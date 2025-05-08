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
use crate::ksl_ast_transform::AstNode;
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, Duration};
use std::collections::{HashMap, HashSet};

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
#[derive(Debug)]
struct GasStats {
    /// Average gas per transaction
    avg_gas: u64,
    /// Total gas used
    total_gas: u64,
    /// Gas limit utilization
    gas_utilization: f64,
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
                    latencies.push(*latency);
                    gas_usage.push(*gas);
                    if *is_cross_shard {
                        cross_shard_txs += 1;
                    }
                }
                ExecutionEvent::Block { tx_count, time } => {
                    let tps = *tx_count as f64 / time.as_secs_f64();
                    tps_samples.push(tps);
                }
                ExecutionEvent::ShardSync { latency } => {
                    shard_sync_times.push(*latency);
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
        let peak_tps = tps_samples.iter().fold(0.0, |max, &x| max.max(x));
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
            if profile.calls > 0 && profile.total_time.as_micros() / profile.calls < 100 {
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
            )])?;

        // Read source file
        let source = fs::read_to_string(file)
            .map_err(|e| vec![KslError::type_error(e.to_string(), SourcePosition::new(1, 1))])?;

        // Parse
        let ast = parse(&source)
            .map_err(|e| vec![KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                SourcePosition::new(1, 1),
            )])?;

        // Analyze async patterns
        self.analyze_async_patterns(&ast)?;

        // Type-check
        check(&ast)
            .map_err(|errors| errors)?;

        // Compile
        let bytecode = compile(&ast)
            .map_err(|errors| errors.into_iter().map(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1))).collect())?;

        // Run with profiling
        let mut vm = KapraVM::new_with_profiling(bytecode.clone());
        let start = Instant::now();
        vm.run()
            .map_err(|e| vec![KslError::type_error(
                format!("Runtime error at instruction {}: {}", e.pc, e.message),
                SourcePosition::new(1, 1),
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
                let op = bytecode.instructions[*index as usize].opcode;
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

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, ksl_module.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::parse;
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode};
}

mod kapra_vm {
    pub use super::{KapraVM, RuntimeError};
}

mod ksl_module {
    pub use super::ModuleSystem;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
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