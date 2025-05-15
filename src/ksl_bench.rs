// ksl_bench.rs
// Implements a benchmarking framework for KSL programs to measure performance.
// Supports async execution, detailed metrics collection, and integration with ksl_benchmark.rs.

use crate::ksl_parser::{parse, AstNode};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::kapra_vm::{KapraVM, run};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_metrics::{MetricsCollector, MetricType, MetricValue, log_metrics};
use crate::ksl_async::{AsyncContext, AsyncCommand};
use crate::ksl_benchmark::{BenchmarkConfig, BenchmarkSuite};
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, Duration};
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use rand::Rng;

/// Detailed benchmark results with metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Name of the benchmark
    pub name: String,
    /// Total execution duration
    pub duration: Duration,
    /// Number of instructions executed
    pub instructions: u64,
    /// Memory usage in bytes
    pub memory_usage: usize,
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Cache hit/miss statistics
    pub cache_stats: CacheStats,
    /// Async operation metrics
    pub async_metrics: AsyncMetrics,
    /// Custom metrics collected during execution
    pub custom_metrics: Vec<MetricValue>,
}

/// Cache statistics for performance analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheStats {
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
    /// Cache hit rate
    pub hit_rate: f64,
}

/// Async operation metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct AsyncMetrics {
    /// Number of async operations
    pub operation_count: u64,
    /// Total time spent in async operations
    pub async_duration: Duration,
    /// Average async operation duration
    pub avg_async_duration: Duration,
    /// Number of concurrent async operations
    pub max_concurrency: u32,
}

/// Benchmark runner with async support and metrics collection
pub struct BenchmarkRunner {
    /// Module system for code execution
    module_system: ModuleSystem,
    /// Collected benchmark results
    results: Vec<BenchmarkResult>,
    /// Metrics collector
    metrics_collector: MetricsCollector,
    /// Async context for command execution
    async_context: Arc<Mutex<AsyncContext>>,
    /// Benchmark configuration
    config: BenchmarkConfig,
}

impl BenchmarkRunner {
    /// Creates a new benchmark runner with the given configuration
    pub fn new(config: BenchmarkConfig) -> Self {
        BenchmarkRunner {
            module_system: ModuleSystem::new(),
            results: Vec::new(),
            metrics_collector: MetricsCollector::new(),
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
            config,
        }
    }

    /// Runs benchmarks in a KSL file with async support
    pub async fn run_benchmarks(&mut self, file: &PathBuf) -> Result<(), Vec<KslError>> {
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
                "PARSE_ERROR".to_string()
            )])?;

        // Type-check
        check(ast.as_slice())
            .map_err(|errors| errors)?;

        // Compile
        let bytecode = compile(ast.as_slice())
            .map_err(|errors| errors.into_iter().map(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1), "COMPILE_ERROR".to_string())).collect())?;

        // Find benchmark functions (functions with #[bench] attribute)
        let bench_functions: Vec<String> = ast.iter()
            .filter_map(|node| {
                if let AstNode::FnDecl { attributes, name, .. } = node {
                    if attributes.iter().any(|attr| attr.name == "bench") {
                        Some(name.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Run each benchmark
        for bench_name in bench_functions {
            let result = self.run_benchmark(&bytecode, &bench_name).await;
            self.results.push(result);
        }

        // Report results
        println!("Benchmark results:");
        for result in &self.results {
            println!(
                "{}: {:.2?} ({} instructions, {} bytes, {:.2}% CPU, {:.2}% cache hit rate)",
                result.name,
                result.duration,
                result.instructions,
                result.memory_usage,
                result.cpu_usage,
                result.cache_stats.hit_rate * 100.0
            );
            println!("Async metrics: {} operations, {:.2?} avg duration, max concurrency: {}",
                result.async_metrics.operation_count,
                result.async_metrics.avg_async_duration,
                result.async_metrics.max_concurrency
            );
        }

        if self.results.is_empty() {
            Err(vec![KslError::type_error(
                "No benchmark functions found".to_string(),
                SourcePosition::new(1, 1),
            )])
        } else {
            Ok(())
        }
    }

    /// Runs a single benchmark with async support and metrics collection
    async fn run_benchmark(&self, bytecode: &KapraBytecode, bench_name: &str) -> BenchmarkResult {
        // Create a modified bytecode that calls the benchmark function
        let mut bench_bytecode = KapraBytecode::new();

        // Find function index
        let fn_index = bytecode.instructions.iter()
            .position(|instr| instr.opcode == KapraOpCode::Call && matches!(&instr.operands[0], Operand::Immediate(data) if String::from_utf8(data.clone()).unwrap_or_default().contains(bench_name)))
            .unwrap_or(0) as u32;

        // Add call to benchmark function
        bench_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Call,
            vec![Operand::Immediate(fn_index.to_le_bytes().to_vec())],
            None,
        ));
        bench_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        // Start metrics collection
        let metrics_collector = MetricsCollector::new();
        metrics_collector.expect("Failed to initialize metrics collector").start_collection();

        // Run benchmark with profiling
        let start = Instant::now();
        let mut vm = KapraVM::new(bench_bytecode.clone());
        let mut instructions = 0;
        let mut async_context = self.async_context.lock().await;
        let result = vm.run_async(&mut async_context).await.map_err(|e| {
            vec![KslError::type_error(
                format!("Runtime error at instruction {}: {}", e.pc, e.message),
                SourcePosition::new(1, 1),
            )]
        });

        // Collect metrics
        let metrics = metrics_collector.stop_collection();
        let cache_stats = metrics_collector.get_cache_stats();
        let async_metrics = metrics_collector.get_async_metrics();

        // Count instructions
        instructions += bytecode.instructions.len() as u64;

        // Estimate memory usage
        let memory_usage = vm.registers.iter().map(|r| r.len()).sum::<usize>() +
                          vm.memory.values().map(|v| v.len()).sum::<usize>();

        BenchmarkResult {
            name: bench_name.to_string(),
            duration: start.elapsed(),
            instructions,
            memory_usage,
            cpu_usage: metrics_collector.get_cpu_usage(),
            cache_stats,
            async_metrics,
            custom_metrics: metrics,
        }
    }
}

/// Public API to run benchmarks with async support
pub async fn run_benchmarks(file: &PathBuf, config: BenchmarkConfig) -> Result<(), Vec<KslError>> {
    let mut runner = BenchmarkRunner::new(config);
    runner.run_benchmarks(file).await
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, ksl_module.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
}

mod kapra_vm {
    pub use super::{KapraVM, run};
}

mod ksl_module {
    pub use super::ModuleSystem;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

mod ksl_metrics {
    pub use super::{MetricsCollector, MetricType, MetricValue, log_metrics};
}

mod ksl_async {
    pub use super::{AsyncContext, AsyncCommand};
}

mod ksl_benchmark {
    pub use super::{BenchmarkConfig, BenchmarkSuite};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_run_benchmark() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[bench]\nfn bench_add() { let x: u32 = 42; let y: u32 = x + x; }"
        ).unwrap();

        let result = run_benchmarks(&temp_file.path().to_path_buf(), BenchmarkConfig::default());
        assert!(result.is_ok());
        let runner = BenchmarkRunner::new(BenchmarkConfig::default());
        assert_eq!(runner.results.len(), 1);
        assert_eq!(runner.results[0].name, "bench_add");
        assert!(runner.results[0].duration.as_nanos() > 0);
        assert!(runner.results[0].instructions > 0);
    }

    #[test]
    fn test_no_benchmarks() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn add() { let x: u32 = 42; let y: u32 = x + x; }"
        ).unwrap();

        let result = run_benchmarks(&temp_file.path().to_path_buf(), BenchmarkConfig::default());
        assert!(result.is_err());
        assert!(result.unwrap_err()[0].to_string().contains("No benchmark functions found"));
    }
}

#[derive(Debug, Clone)]
pub struct Transaction {
    id: u64,
    sender: String,
    receiver: String,
    amount: u64,
    timestamp: u64,
    signature: String,
}

impl Transaction {
    pub fn mock(id: u64) -> Self {
        let mut rng = rand::thread_rng();
        Transaction {
            id,
            sender: format!("0x{:x}", rng.gen::<u64>()),
            receiver: format!("0x{:x}", rng.gen::<u64>()),
            amount: rng.gen_range(1..1000),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: format!("0x{:x}", rng.gen::<u128>()),
        }
    }
}

#[derive(Debug)]
pub struct BlockResult {
    processed_txs: usize,
    failed_txs: usize,
    gas_used: u64,
    block_time: u64,
}

pub struct BenchmarkState {
    total_processed: usize,
    total_failed: usize,
    total_gas: u64,
}

impl BenchmarkState {
    pub fn new() -> Self {
        Self {
            total_processed: 0,
            total_failed: 0,
            total_gas: 0,
        }
    }

    pub fn update(&mut self, result: &BlockResult) {
        self.total_processed += result.processed_txs;
        self.total_failed += result.failed_txs;
        self.total_gas += result.gas_used;
    }
}

pub async fn run_benchmark() {
    let state = Arc::new(Mutex::new(BenchmarkState::new()));
    let tps_targets = [10_000, 25_000, 50_000, 100_000];

    println!("[BENCH] Starting KSL high-TPS benchmark...");
    println!("[BENCH] Testing TPS targets: {:?}", tps_targets);

    for &tps in tps_targets.iter() {
        println!("\n[BENCH] Running benchmark at {} TPS...", tps);
        let txs = generate_mock_transactions(tps);
        
        let start = Instant::now();
        let result = simulate_block(txs).await;
        let duration = start.elapsed();

        // Update benchmark state
        let mut state_guard = state.lock().await;
        state_guard.update(&result);

        // Log metrics
        log_metrics(tps, duration, &result);

        // Print detailed results
        println!("[BENCH] Results for {} TPS:", tps);
        println!("  - Processed transactions: {}", result.processed_txs);
        println!("  - Failed transactions: {}", result.failed_txs);
        println!("  - Gas used: {}", result.gas_used);
        println!("  - Block time: {} ms", result.block_time);
        println!("  - Actual TPS: {:.2}", result.processed_txs as f64 / duration.as_secs_f64());
    }

    // Print final summary
    let final_state = state.lock().await;
    println!("\n[BENCH] Final Summary:");
    println!("  - Total processed transactions: {}", final_state.total_processed);
    println!("  - Total failed transactions: {}", final_state.total_failed);
    println!("  - Total gas used: {}", final_state.total_gas);
}

fn generate_mock_transactions(count: usize) -> Vec<Transaction> {
    (0..count).map(|i| Transaction::mock(i as u64)).collect()
}

async fn simulate_block(transactions: Vec<Transaction>) -> BlockResult {
    let mut processed = 0;
    let mut failed = 0;
    let mut total_gas = 0;
    let start_time = Instant::now();

    // Simulate parallel processing of transactions
    let chunks: Vec<_> = transactions.chunks(1000).collect();
    let mut handles = vec![];

    for chunk in chunks {
        let chunk = chunk.to_vec();
        let handle = tokio::spawn(async move {
            let mut chunk_processed = 0;
            let mut chunk_failed = 0;
            let mut chunk_gas = 0;

            for tx in chunk {
                // Simulate transaction processing
                if rand::random::<f64>() < 0.95 {
                    chunk_processed += 1;
                    chunk_gas += rand::thread_rng().gen_range(1000..10000);
                } else {
                    chunk_failed += 1;
                }
            }

            (chunk_processed, chunk_failed, chunk_gas)
        });
        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        if let Ok((p, f, g)) = handle.await {
            processed += p;
            failed += f;
            total_gas += g;
        }
    }

    let block_time = start_time.elapsed().as_millis() as u64;

    BlockResult {
        processed_txs: processed,
        failed_txs: failed,
        gas_used: total_gas,
        block_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_benchmark() {
        let txs = generate_mock_transactions(1000);
        let result = simulate_block(txs).await;
        
        assert!(result.processed_txs > 0);
        assert!(result.gas_used > 0);
        assert!(result.block_time > 0);
    }

    #[test]
    fn test_transaction_mock() {
        let tx = Transaction::mock(1);
        assert_eq!(tx.id, 1);
        assert!(!tx.sender.is_empty());
        assert!(!tx.receiver.is_empty());
        assert!(tx.amount > 0);
        assert!(tx.timestamp > 0);
        assert!(!tx.signature.is_empty());
    }
}