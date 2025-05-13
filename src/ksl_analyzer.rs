// ksl_analyzer.rs
// Implements static and dynamic analysis tools for KSL programs, including performance profiling,
// async code analysis, and resource usage tracking.

use crate::ksl_parser::parse;
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_macros::AstNode;
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, Duration};
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};

/// Profiling data for a single instruction
#[derive(Debug)]
struct InstructionProfile {
    count: u64,
    total_time: Duration,
}

/// Profiling data for a function
#[derive(Debug)]
struct FunctionProfile {
    name: String,
    calls: u64,
    total_time: Duration,
    instructions: HashMap<u32, InstructionProfile>,
    is_async: bool,
    async_operations: Vec<String>,
    branch_data: HashMap<u32, BranchProfile>,
}

/// Analysis rules for async code
#[derive(Debug)]
struct AsyncAnalysisRules {
    /// Maximum number of concurrent async operations allowed
    max_concurrent_ops: usize,
    /// Forbidden async operations in certain contexts
    forbidden_ops: HashSet<String>,
    /// Required error handling for async operations
    require_error_handling: bool,
}

/// Transaction metrics for blockchain operations
#[derive(Debug)]
struct TransactionMetrics {
    /// Transaction latency statistics
    latency: LatencyStats,
    /// Validator throughput metrics
    validator_throughput: ThroughputStats,
    /// Gas usage statistics
    gas_stats: GasStats,
    /// Shard operation metrics
    shard_metrics: ShardMetrics,
}

/// Latency statistics for transactions
#[derive(Debug)]
struct LatencyStats {
    /// Average transaction latency
    avg_latency: Duration,
    /// Minimum transaction latency
    min_latency: Duration,
    /// Maximum transaction latency
    max_latency: Duration,
    /// 95th percentile latency
    p95_latency: Duration,
    /// Transaction count
    tx_count: u64,
}

/// Throughput statistics for validators
#[derive(Debug)]
struct ThroughputStats {
    /// Transactions per second
    tps: f64,
    /// Peak TPS observed
    peak_tps: f64,
    /// Average block time
    avg_block_time: Duration,
    /// Validator count
    validator_count: u32,
}

/// Gas usage statistics
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GasStats {
    /// Average gas per transaction
    pub avg_gas: u64,
    /// Total gas used
    pub total_gas: u64,
    /// Gas limit utilization
    pub gas_utilization: f64,
    /// Gas by operation
    pub gas_by_operation: HashMap<String, u64>,
}

/// Shard operation metrics
#[derive(Debug)]
struct ShardMetrics {
    /// Cross-shard transaction count
    cross_shard_tx_count: u64,
    /// Shard sync latency
    shard_sync_latency: Duration,
    /// Shard count
    shard_count: u32,
}

/// Profile-guided optimization data
#[derive(Debug)]
struct PgoData {
    /// Hot functions for optimization
    hot_functions: HashSet<String>,
    /// Loop unrolling candidates
    unroll_candidates: HashSet<u32>,
    /// Inlining candidates
    inline_candidates: HashSet<String>,
    /// Branch prediction stats
    branch_stats: HashMap<u32, f64>,
}

/// Performance metrics for optimization
#[derive(Debug, Default)]
pub struct PerformanceMetrics {
    /// Functions considered "hot" for optimization
    pub hot_functions: HashSet<String>,
    /// Functions that are good candidates for inlining
    pub inline_candidates: HashSet<String>,
    /// Loops that are good candidates for unrolling
    pub unroll_candidates: HashSet<usize>,
    /// Functions with array operations that can be vectorized
    pub array_operations: HashSet<String>,
}

impl PerformanceMetrics {
    /// Create new performance metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a function has array operations that can be vectorized
    pub fn has_array_operations(&self, function_name: &str) -> bool {
        self.array_operations.contains(function_name)
    }

    /// Record that a function has array operations
    pub fn record_array_operations(&mut self, function_name: String) {
        self.array_operations.insert(function_name);
    }
}

/// Analyzer state with async support
pub struct Analyzer {
    module_system: ModuleSystem,
    profiles: Vec<FunctionProfile>,
    async_rules: AsyncAnalysisRules,
    async_contexts: HashMap<String, Vec<String>>,
}

impl Analyzer {
    /// Creates a new analyzer with default settings
    pub fn new() -> Self {
        Analyzer {
            module_system: ModuleSystem::new(),
            profiles: Vec::new(),
            async_rules: AsyncAnalysisRules {
                max_concurrent_ops: 100,
                forbidden_ops: HashSet::new(),
                require_error_handling: true,
            },
            async_contexts: HashMap::new(),
        }
    }

    /// Analyzes async code patterns in the AST
    fn analyze_async_patterns(&mut self, ast: &[AstNode]) -> Result<(), Vec<KslError>> {
        let mut errors = Vec::new();
        let mut async_stack = Vec::new();

        for node in ast {
            match node {
                AstNode::AsyncBlock { body, .. } => {
                    async_stack.push("block".to_string());
                    self.analyze_async_patterns(body)?;
                    async_stack.pop();
                }
                AstNode::AsyncFnDecl { name, body, .. } => {
                    async_stack.push(name.clone());
                    self.analyze_async_patterns(body)?;
                    async_stack.pop();
                }
                AstNode::AwaitExpr { .. } => {
                    if async_stack.is_empty() {
                        errors.push(KslError::type_error(
                            "await used outside async context".to_string(),
                            SourcePosition::new(1, 1),
                            "E105".to_string()
                        ));
                    }
                }
                _ => {}
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(())
    }

    /// Collects transaction metrics during execution
    fn collect_transaction_metrics(&mut self, vm: &KapraVM) -> TransactionMetrics {
        let mut latencies = Vec::new();
        let mut tps_samples = Vec::new();
        let mut gas_usage = Vec::new();
        let mut cross_shard_txs = 0;
        let mut shard_sync_times = Vec::new();

        // Process VM execution logs
        for (timestamp, event) in vm.execution_log.iter() {
            match event {
                ExecutionEvent::Transaction { latency, gas, is_cross_shard } => {
                    latencies.push(latency);
                    gas_usage.push(gas);
                    if is_cross_shard {
                        cross_shard_txs += 1;
                    }
                }
                ExecutionEvent::Block { tx_count, time } => {
                    let tps = tx_count as f64 / time.as_secs_f64();
                    tps_samples.push(tps);
                }
                ExecutionEvent::ShardSync { latency } => {
                    shard_sync_times.push(latency);
                }
            }
        }

        // Calculate latency statistics
        latencies.sort();
        let tx_count = latencies.len() as u64;
        let avg_latency = if !latencies.is_empty() {
            Duration::from_secs_f64(
                latencies.iter().map(|d| d.as_secs_f64()).sum::<f64>() / latencies.len() as f64
            )
        } else {
            Duration::from_secs(0)
        };
        let min_latency = latencies.first().cloned().unwrap_or_else(|| Duration::from_secs(0));
        let max_latency = latencies.last().cloned().unwrap_or_else(|| Duration::from_secs(0));
        let p95_index = ((latencies.len() as f64 * 0.95) as usize).max(1) - 1;
        let p95_latency = latencies.get(p95_index).cloned().unwrap_or_else(|| Duration::from_secs(0));

        // Calculate throughput statistics
        let tps = if !tps_samples.is_empty() {
            tps_samples.iter().sum::<f64>() / tps_samples.len() as f64
        } else {
            0.0
        };
        let peak_tps = tps_samples.iter().fold(0.0f64, |max, &x| max.max(x));
        let avg_block_time = Duration::from_secs_f64(
            vm.execution_log.iter()
                .filter_map(|(_, event)| {
                    if let ExecutionEvent::Block { time, .. } = event {
                        Some(time.as_secs_f64())
                    } else {
                        None
                    }
                })
                .sum::<f64>() / tps_samples.len().max(1) as f64
        );

        // Calculate gas statistics
        let total_gas = gas_usage.iter().sum();
        let avg_gas = if !gas_usage.is_empty() {
            total_gas / gas_usage.len() as u64
        } else {
            0
        };
        let gas_utilization = total_gas as f64 / (vm.gas_limit as f64 * tps_samples.len() as f64);

        // Calculate shard metrics
        let shard_sync_latency = if !shard_sync_times.is_empty() {
            Duration::from_secs_f64(
                shard_sync_times.iter().map(|d| d.as_secs_f64()).sum::<f64>() / shard_sync_times.len() as f64
            )
        } else {
            Duration::from_secs(0)
        };

        TransactionMetrics {
            latency: LatencyStats {
                avg_latency,
                min_latency,
                max_latency,
                p95_latency,
                tx_count,
            },
            validator_throughput: ThroughputStats {
                tps,
                peak_tps,
                avg_block_time,
                validator_count: vm.validator_count,
            },
            gas_stats: GasStats {
                avg_gas,
                total_gas,
                gas_utilization,
                gas_by_operation: HashMap::new(),
            },
            shard_metrics: ShardMetrics {
                cross_shard_tx_count: cross_shard_txs,
                shard_sync_latency,
                shard_count: vm.shard_count,
            },
        }
    }

    /// Collects PGO data for compiler optimization
    fn collect_pgo_data(&self) -> PgoData {
        let mut pgo_data = PgoData {
            hot_functions: HashSet::new(),
            unroll_candidates: HashSet::new(),
            inline_candidates: HashSet::new(),
            branch_stats: HashMap::new(),
        };

        // Identify hot functions
        for profile in &self.profiles {
            if profile.calls > 1000 || profile.total_time > Duration::from_millis(100) {
                pgo_data.hot_functions.insert(profile.name.clone());
            }

            // Analyze instructions for optimization opportunities
            for (index, instr) in &profile.instructions {
                // Identify loop candidates for unrolling
                if instr.count > 100 {
                    pgo_data.unroll_candidates.insert(*index);
                }

                // Collect branch statistics
                if let Some(branch_taken) = self.get_branch_probability(*index) {
                    pgo_data.branch_stats.insert(*index, branch_taken);
                }
            }

            // Identify inlining candidates
            if profile.calls > 0 && profile.total_time.as_micros() / (profile.calls as u128) < 100 {
                pgo_data.inline_candidates.insert(profile.name.clone());
            }
        }

        pgo_data
    }

    /// Gets branch probability for a given instruction
    fn get_branch_probability(&self, instr_index: u32) -> Option<f64> {
        for profile in &self.profiles {
            if let Some(instr) = profile.instructions.get(&instr_index) {
                if let Some(branch_data) = profile.branch_data.get(&instr_index) {
                    return Some(branch_data.taken as f64 / instr.count as f64);
                }
            }
        }
        None
    }

    /// Analyzes a KSL file for both static and dynamic properties
    pub fn analyze_file(&mut self, file: &PathBuf) -> Result<(), Vec<KslError>> {
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| vec![KslError::type_error(
                "Invalid main file name".to_string(),
                SourcePosition::new(1, 1),
                "E101".to_string()
            )])?;

        // Read source file
        let source = fs::read_to_string(file)
            .map_err(|e| vec![KslError::type_error(e.to_string(), SourcePosition::new(1, 1), "E102".to_string())])?;

        // Parse
        let ast = parse(&source)
            .map_err(|e| vec![KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                SourcePosition::new(1, 1),
                "E103".to_string()
            )])?;

        // Analyze async patterns
        self.analyze_async_patterns(&ast)?;

        // Type-check
        check(&ast)
            .map_err(|errors| errors.into_iter().map(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1), "E105".to_string())).collect::<Vec<KslError>>())?;

        // Compile
        let bytecode = compile(
            &ast,
            "main_module",
            CompileTarget::Bytecode,
            "output.bc",
            &PerformanceMetrics::new(),
            false,
            None
        ).map_err(|errors| errors.into_iter().map(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1), "E104".to_string())).collect())?;

        // Run with profiling
        let mut vm = KapraVM::new_with_profiling(bytecode.clone());
        let start = Instant::now();
        vm.run()
            .map_err(|e| vec![KslError::type_error(
                format!("Runtime error at instruction {}: {}", e.pc, e.message),
                SourcePosition::new(1, 1),
                "E401".to_string()
            )])?;
        let total_duration = start.elapsed();

        // Collect function profiles with async information
        let mut function_profiles = HashMap::new();
        for (fn_index, profile) in vm.function_profiles {
            let fn_name = ast.iter()
                .filter_map(|node| {
                    match node {
                        AstNode::FnDecl { name, .. } => Some(name.clone()),
                        AstNode::AsyncFnDecl { name, .. } => Some(name.clone()),
                        _ => None,
                    }
                })
                .nth(fn_index as usize)
                .unwrap_or(format!("fn_{}", fn_index));

            let is_async = ast.iter()
                .filter_map(|node| {
                    if let AstNode::AsyncFnDecl { name, .. } = node {
                        Some(name.clone())
                    } else {
                        None
                    }
                })
                .any(|name| name == fn_name);

            function_profiles.insert(fn_index, FunctionProfile {
                name: fn_name,
                calls: profile.calls,
                total_time: profile.total_time,
                instructions: profile.instructions,
                is_async,
                async_operations: Vec::new(),
                branch_data: HashMap::new(),
            });
        }

        self.profiles = function_profiles.into_values().collect();

        // Collect transaction metrics
        let tx_metrics = self.collect_transaction_metrics(&vm);

        // Collect PGO data
        let pgo_data = self.collect_pgo_data();

        // Generate report
        println!("Analysis Report for {}", file.display());
        println!("Total execution time: {:.2?}", total_duration);
        println!("Memory usage: {} bytes", vm.memory.values().map(|v| v.len()).sum::<usize>());
        println!("\nFunction Profiles:");
        for profile in &self.profiles {
            println!(
                "{}: {} calls, {:.2?} ({:.2}% of total){}",
                profile.name,
                profile.calls,
                profile.total_time,
                (profile.total_time.as_secs_f64() / total_duration.as_secs_f64()) * 100.0,
                if profile.is_async { " [ASYNC]" } else { "" }
            );
            if profile.is_async {
                println!("  Async Operations:");
                for op in &profile.async_operations {
                    println!("    - {}", op);
                }
            }
            println!("  Top Instructions:");
            let mut instrs: Vec<_> = profile.instructions.iter().collect();
            instrs.sort_by(|a, b| b.1.total_time.cmp(&a.1.total_time));
            for (index, instr) in instrs.iter().take(3) {
                let op = bytecode.instructions[**index as usize].opcode;
                println!(
                    "    0x{:04x}: {:?} ({} calls, {:.2?})",
                    index, op, instr.count, instr.total_time
                );
            }
        }

        println!("\nTransaction Metrics:");
        println!("Latency Statistics:");
        println!("  Average: {:.2?}", tx_metrics.latency.avg_latency);
        println!("  Min: {:.2?}", tx_metrics.latency.min_latency);
        println!("  Max: {:.2?}", tx_metrics.latency.max_latency);
        println!("  P95: {:.2?}", tx_metrics.latency.p95_latency);
        println!("  Transaction Count: {}", tx_metrics.latency.tx_count);

        println!("\nValidator Throughput:");
        println!("  TPS: {:.2}", tx_metrics.validator_throughput.tps);
        println!("  Peak TPS: {:.2}", tx_metrics.validator_throughput.peak_tps);
        println!("  Average Block Time: {:.2?}", tx_metrics.validator_throughput.avg_block_time);
        println!("  Validator Count: {}", tx_metrics.validator_throughput.validator_count);

        println!("\nGas Statistics:");
        println!("  Average Gas: {}", tx_metrics.gas_stats.avg_gas);
        println!("  Total Gas: {}", tx_metrics.gas_stats.total_gas);
        println!("  Gas Utilization: {:.2}%", tx_metrics.gas_stats.gas_utilization * 100.0);

        println!("\nShard Metrics:");
        println!("  Cross-shard Transactions: {}", tx_metrics.shard_metrics.cross_shard_tx_count);
        println!("  Shard Sync Latency: {:.2?}", tx_metrics.shard_metrics.shard_sync_latency);
        println!("  Shard Count: {}", tx_metrics.shard_metrics.shard_count);

        println!("\nPGO Data:");
        println!("  Hot Functions: {}", pgo_data.hot_functions.len());
        println!("  Loop Unrolling Candidates: {}", pgo_data.unroll_candidates.len());
        println!("  Inlining Candidates: {}", pgo_data.inline_candidates.len());
        println!("  Branch Statistics: {} entries", pgo_data.branch_stats.len());

        // Feed PGO data to compiler
        if let Some(compiler) = self.module_system.get_compiler() {
            compiler.update_pgo_data(pgo_data);
        }

        Ok(())
    }
}

// Public API to analyze a KSL file
pub fn analyze(file: &PathBuf) -> Result<(), Vec<KslError>> {
    let mut analyzer = Analyzer::new();
    analyzer.analyze_file(file)
}

// Add the missing ExecutionEvent type
/// Events during execution for performance analysis
#[derive(Debug)]
pub enum ExecutionEvent {
    /// Transaction execution event
    Transaction {
        /// Transaction processing latency
        latency: Duration,
        /// Gas used during execution
        gas: u64,
        /// Whether the transaction spans multiple shards
        is_cross_shard: bool,
    },
    /// Block production event
    Block {
        /// Number of transactions in the block
        tx_count: u64,
        /// Time taken to process the block
        time: Duration,
    },
    /// Shard synchronization event
    ShardSync {
        /// Shard sync latency
        latency: Duration,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_analyze_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn compute() { let x: u32 = 42; let y: u32 = x + x; }"
        ).unwrap();

        let result = analyze(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
        let analyzer = Analyzer::new();
        assert!(!analyzer.profiles.is_empty());
        assert!(analyzer.profiles.iter().any(|p| p.name == "compute"));
    }

    #[test]
    fn test_analyze_async() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "async fn fetch_data() { let data = await http.get(\"https://example.com\"); }"
        ).unwrap();

        let result = analyze(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
        let analyzer = Analyzer::new();
        assert!(analyzer.profiles.iter().any(|p| p.name == "fetch_data" && p.is_async));
    }

    #[test]
    fn test_analyze_empty_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "").unwrap();

        let result = analyze(&temp_file.path().to_path_buf());
        assert!(result.is_ok()); // Empty file is valid but no profiles
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Type {
    // Primitive types
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    // Complex types
    String,
    Array(Box<Type>, u32), // e.g., array<u8, 32>
    Struct {
        name: String,
        fields: Vec<(String, Type)>, // (field_name, type)
    },
    Enum {
        name: String,
        variants: Vec<(String, Option<Type>)>, // (variant_name, optional payload type)
    },
    Option(Box<Type>), // e.g., option<u32>
    Result {
        ok: Box<Type>,
        err: Box<Type>,
    }, // e.g., result<string, error>
    Tuple(Vec<Type>), // e.g., (u32, f32)
    Void, // For functions with no return value
    Generic {
        name: String,
        constraints: Vec<Type>, // e.g., T: U32 | F32
    },
    Generated {
        schema: String, // e.g., schema name for JSON/Protobuf
    },
    // Networking types
    Function {
        params: Vec<Type>,
        return_type: Box<Type>,
    }, // e.g., function<u32, string>
    Error, // For error handling
    Socket, // For network sockets
    HttpRequest, // For HTTP requests
    HttpResponse, // For HTTP responses
    Bool,
    ZkProof(ZkProofType),
    Signature(SignatureType),
    // Data blob type
    DataBlob {
        element_type: Box<Type>,
        size: usize,
        alignment: usize,
    },
    Blockchain(BlockchainType),
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Type::U8 => write!(f, "u8"),
            Type::U16 => write!(f, "u16"),
            Type::U32 => write!(f, "u32"),
            Type::U64 => write!(f, "u64"),
            Type::I8 => write!(f, "i8"),
            Type::I16 => write!(f, "i16"),
            Type::I32 => write!(f, "i32"),
            Type::I64 => write!(f, "i64"),
            Type::F32 => write!(f, "f32"),
            Type::F64 => write!(f, "f64"),
            Type::String => write!(f, "string"),
            Type::Array(t, s) => write!(f, "array<{}, {}>", t, s),
            Type::Struct { name, fields } => {
                write!(f, "struct {} {{ ", name)?;
                for (i, (field_name, field_type)) in fields.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", field_name, field_type)?;
                }
                write!(f, " }}")
            }
            Type::Enum { name, variants } => {
                write!(f, "enum {} {{ ", name)?;
                for (i, (variant_name, payload_type)) in variants.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", variant_name)?;
                    if let Some(t) = payload_type {
                        write!(f, "({})", t)?;
                    }
                }
                write!(f, " }}")
            }
            Type::Option(t) => write!(f, "option<{}>", t),
            Type::Result { ok, err } => write!(f, "result<{}, {}>", ok, err),
            Type::Tuple(types) => {
                write!(f, "(")?;
                for (i, t) in types.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", t)?;
                }
                write!(f, ")")
            }
            Type::Void => write!(f, "void"),
            Type::Generic { name, constraints } => {
                write!(f, "{}", name)?;
                if !constraints.is_empty() {
                    write!(f, ": ")?;
                    for (i, c) in constraints.iter().enumerate() {
                        if i > 0 {
                            write!(f, " | ")?;
                        }
                        write!(f, "{}", c)?;
                    }
                }
                Ok(())
            }
            Type::Generated { schema } => write!(f, "generated<{}>", schema),
            Type::Function { params, return_type } => {
                write!(f, "function<")?;
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", p)?;
                }
                write!(f, "> -> {}", return_type)
            }
            Type::Error => write!(f, "error"),
            Type::Socket => write!(f, "socket"),
            Type::HttpRequest => write!(f, "http_request"),
            Type::HttpResponse => write!(f, "http_response"),
            Type::Bool => write!(f, "bool"),
            Type::ZkProof(t) => write!(f, "zk_proof<{}>", t),
            Type::Signature(t) => write!(f, "signature<{}>", t),
            Type::DataBlob { element_type, size, alignment } => {
                write!(f, "data_blob<{}, {}, {}>", element_type, size, alignment)
            }
            Type::Blockchain(t) => write!(f, "blockchain<{}>", t),
        }
    }
}

impl Type {
    pub fn satisfies_constraint(&self, constraint: &Type) -> bool {
        match (self, constraint) {
            (Type::U8, Type::U16) | (Type::U8, Type::U32) | (Type::U8, Type::U64) |
            (Type::U16, Type::U32) | (Type::U16, Type::U64) |
            (Type::U32, Type::U64) |
            (Type::I8, Type::I16) | (Type::I8, Type::I32) | (Type::I8, Type::I64) |
            (Type::I16, Type::I32) | (Type::I16, Type::I64) |
            (Type::I32, Type::I64) |
            (Type::F32, Type::F64) => true,
            (Type::Array(inner1, size1), Type::Array(inner2, size2)) => {
                size1 == size2 && inner1.satisfies_constraint(inner2)
            }
            (Type::Struct { name: name1, fields: fields1 }, Type::Struct { name: name2, fields: fields2 }) => {
                name1 == name2 && fields1.len() == fields2.len() &&
                fields1.iter().zip(fields2.iter()).all(|((name1, type1), (name2, type2))| {
                    name1 == name2 && type1.satisfies_constraint(type2)
                })
            }
            (Type::Enum { name: name1, variants: variants1 }, Type::Enum { name: name2, variants: variants2 }) => {
                name1 == name2 && variants1.len() == variants2.len() &&
                variants1.iter().zip(variants2.iter()).all(|((name1, type1), (name2, type2))| {
                    name1 == name2 && match (type1, type2) {
                        (Some(t1), Some(t2)) => t1.satisfies_constraint(t2),
                        (None, None) => true,
                        _ => false,
                    }
                })
            }
            (Type::Option(inner1), Type::Option(inner2)) => inner1.satisfies_constraint(inner2),
            (Type::Result { ok: ok1, err: err1 }, Type::Result { ok: ok2, err: err2 }) => {
                ok1.satisfies_constraint(ok2) && err1.satisfies_constraint(err2)
            }
            (Type::Tuple(types1), Type::Tuple(types2)) => {
                types1.len() == types2.len() &&
                types1.iter().zip(types2.iter()).all(|(t1, t2)| t1.satisfies_constraint(t2))
            }
            (Type::Generic { name: name1, constraints: constraints1 }, Type::Generic { name: name2, constraints: constraints2 }) => {
                name1 == name2 && constraints1.len() == constraints2.len() &&
                constraints1.iter().zip(constraints2.iter()).all(|(c1, c2)| c1.satisfies_constraint(c2))
            }
            (Type::Generated { schema: schema1 }, Type::Generated { schema: schema2 }) => {
                schema1 == schema2
            }
            (Type::Function { params: params1, return_type: ret1 }, Type::Function { params: params2, return_type: ret2 }) => {
                params1.len() == params2.len() &&
                params1.iter().zip(params2.iter()).all(|(p1, p2)| p1.satisfies_constraint(p2)) &&
                ret1.satisfies_constraint(ret2)
            }
            (Type::ZkProof(proof1), Type::ZkProof(proof2)) => proof1 == proof2,
            (Type::Signature(sig1), Type::Signature(sig2)) => sig1 == sig2,
            (Type::DataBlob { element_type: type1, size: size1, alignment: align1 },
             Type::DataBlob { element_type: type2, size: size2, alignment: align2 }) => {
                type1.satisfies_constraint(type2) && size1 == size2 && align1 == align2
            }
            (Type::Blockchain(block1), Type::Blockchain(block2)) => block1 == block2,
            _ => false,
        }
    }

    pub fn implements_trait(&self, trait_name: &str) -> bool {
        match self {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 |
            Type::I8 | Type::I16 | Type::I32 | Type::I64 |
            Type::F32 | Type::F64 => trait_name == "Numeric",
            Type::String => trait_name == "String",
            Type::Array(_, _) => trait_name == "Collection",
            Type::Struct { .. } => trait_name == "Struct",
            Type::Enum { .. } => trait_name == "Enum",
            Type::Option(_) => trait_name == "Option",
            Type::Result { .. } => trait_name == "Result",
            Type::Tuple(_) => trait_name == "Tuple",
            Type::Void => trait_name == "Void",
            Type::Generic { .. } => trait_name == "Generic",
            Type::Generated { .. } => trait_name == "Generated",
            Type::Function { .. } => trait_name == "Function",
            Type::Error => trait_name == "Error",
            Type::Socket => trait_name == "Socket",
            Type::HttpRequest => trait_name == "HttpRequest",
            Type::HttpResponse => trait_name == "HttpResponse",
            Type::Bool => trait_name == "Bool",
            Type::ZkProof(_) => trait_name == "ZkProof",
            Type::Signature(_) => trait_name == "Signature",
            Type::DataBlob { .. } => trait_name == "DataBlob",
            Type::Blockchain(_) => trait_name == "Blockchain",
        }
    }
}

pub struct TypeSystem;

impl TypeSystem {
    pub fn satisfies_constraint(ty: &Type, constraint: &Type) -> bool {
        ty.satisfies_constraint(constraint)
    }

    pub fn implements_trait(ty: &Type, trait_name: &str) -> bool {
        ty.implements_trait(trait_name)
    }
}

impl PartialEq for Type {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Type::U8, Type::U8) => true,
            (Type::U16, Type::U16) => true,
            (Type::U32, Type::U32) => true,
            (Type::U64, Type::U64) => true,
            (Type::I8, Type::I8) => true,
            (Type::I16, Type::I16) => true,
            (Type::I32, Type::I32) => true,
            (Type::I64, Type::I64) => true,
            (Type::F32, Type::F32) => true,
            (Type::F64, Type::F64) => true,
            (Type::String, Type::String) => true,
            (Type::Array(t1, s1), Type::Array(t2, s2)) => t1 == t2 && s1 == s2,
            (Type::Struct { name: n1, fields: f1 }, Type::Struct { name: n2, fields: f2 }) => n1 == n2 && f1 == f2,
            (Type::Enum { name: n1, variants: v1 }, Type::Enum { name: n2, variants: v2 }) => n1 == n2 && v1 == v2,
            (Type::Option(t1), Type::Option(t2)) => t1 == t2,
            (Type::Result { ok: o1, err: e1 }, Type::Result { ok: o2, err: e2 }) => o1 == o2 && e1 == e2,
            (Type::Tuple(t1), Type::Tuple(t2)) => t1 == t2,
            (Type::Void, Type::Void) => true,
            (Type::Generic { name: n1, constraints: c1 }, Type::Generic { name: n2, constraints: c2 }) => n1 == n2 && c1 == c2,
            (Type::Generated { schema: s1 }, Type::Generated { schema: s2 }) => s1 == s2,
            (Type::Function { params: p1, return_type: r1 }, Type::Function { params: p2, return_type: r2 }) => p1 == p2 && r1 == r2,
            (Type::Error, Type::Error) => true,
            (Type::Socket, Type::Socket) => true,
            (Type::HttpRequest, Type::HttpRequest) => true,
            (Type::HttpResponse, Type::HttpResponse) => true,
            (Type::Bool, Type::Bool) => true,
            (Type::ZkProof(t1), Type::ZkProof(t2)) => t1 == t2,
            (Type::Signature(t1), Type::Signature(t2)) => t1 == t2,
            (Type::DataBlob { element_type: t1, size: s1, alignment: a1 }, Type::DataBlob { element_type: t2, size: s2, alignment: a2 }) => t1 == t2 && s1 == s2 && a1 == a2,
            (Type::Blockchain(t1), Type::Blockchain(t2)) => t1 == t2,
            _ => false,
        }
    }
}