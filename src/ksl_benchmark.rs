/// ksl_benchmark.rs
/// Provides benchmarking tools to evaluate KSL performance, supporting async execution,
/// new compiler features, and comprehensive metrics collection.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_optimizer::optimize;
use crate::ksl_profile::{ProfileData, run_profile};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_metrics::{MetricsCollector, MetricsConfig};
use crate::ksl_async::{AsyncRuntime, AsyncVM};
use serde_json::json;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

/// Enhanced benchmark configuration with async and metrics support
#[derive(Debug)]
pub struct BenchmarkConfig {
    /// Source file to benchmark
    input_file: PathBuf,
    /// Number of iterations
    iterations: u32,
    /// Output format: "csv" or "json"
    output_format: String,
    /// Optional path for benchmark results
    output_path: Option<PathBuf>,
    /// Whether to apply optimization
    optimize: bool,
    /// Whether to enable async execution
    enable_async: bool,
    /// Metrics configuration
    metrics_config: Option<MetricsConfig>,
}

/// Enhanced benchmark result with async and metrics data
#[derive(Debug)]
pub struct BenchmarkResult {
    /// Total execution time
    total_duration: Duration,
    /// Average time per iteration
    avg_duration: Duration,
    /// Optional profiling data
    profile_data: Option<ProfileData>,
    /// Async execution metrics
    async_metrics: Option<AsyncMetrics>,
    /// Memory usage metrics
    memory_metrics: Option<MemoryMetrics>,
    /// Network operation metrics
    network_metrics: Option<NetworkMetrics>,
}

/// Async execution metrics
#[derive(Debug)]
pub struct AsyncMetrics {
    /// Number of async tasks created
    tasks_created: u32,
    /// Number of tasks completed
    tasks_completed: u32,
    /// Maximum concurrent tasks
    max_concurrent_tasks: u32,
    /// Average task duration
    avg_task_duration: Duration,
}

/// Memory usage metrics
#[derive(Debug)]
pub struct MemoryMetrics {
    /// Peak memory usage in bytes
    peak_memory: usize,
    /// Average memory usage in bytes
    avg_memory: usize,
    /// Number of allocations
    allocation_count: u32,
}

/// Network operation metrics
#[derive(Debug)]
pub struct NetworkMetrics {
    /// Number of network requests
    requests: u32,
    /// Number of responses
    responses: u32,
    /// Total bytes sent
    bytes_sent: u64,
    /// Total bytes received
    bytes_received: u64,
    /// Average latency
    avg_latency: Duration,
    /// Number of errors
    errors: u32,
}

/// Enhanced benchmark tool with async support and metrics integration
pub struct BenchmarkTool {
    config: BenchmarkConfig,
    metrics_collector: Option<MetricsCollector>,
    async_runtime: Option<Arc<RwLock<AsyncRuntime>>>,
}

impl BenchmarkTool {
    /// Create a new benchmark tool with the given configuration
    pub fn new(config: BenchmarkConfig) -> Self {
        let metrics_collector = config.metrics_config.as_ref().map(|mc| MetricsCollector::new(mc.clone()).unwrap());
        let async_runtime = if config.enable_async {
            Some(Arc::new(RwLock::new(AsyncRuntime::new())))
        } else {
            None
        };

        BenchmarkTool {
            config,
            metrics_collector,
            async_runtime,
        }
    }

    /// Run benchmarks with async support and metrics collection
    pub async fn run(&self) -> Result<BenchmarkResult, KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Read and compile source
        let source = fs::read_to_string(&self.config.input_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", self.config.input_file.display(), e),
                pos,
            ))?;
        let ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;
        check(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;
        let mut bytecode = compile(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        // Optimize if specified
        if self.config.optimize {
            optimize(&mut bytecode, 3) // Use highest optimization level
                .map_err(|e| KslError::type_error(format!("Bytecode optimization failed: {}", e), pos))?;
        }

        // Initialize metrics
        let mut async_metrics = AsyncMetrics {
            tasks_created: 0,
            tasks_completed: 0,
            max_concurrent_tasks: 0,
            avg_task_duration: Duration::from_secs(0),
        };
        let mut memory_metrics = MemoryMetrics {
            peak_memory: 0,
            avg_memory: 0,
            allocation_count: 0,
        };
        let mut network_metrics = NetworkMetrics {
            requests: 0,
            responses: 0,
            bytes_sent: 0,
            bytes_received: 0,
            avg_latency: Duration::from_secs(0),
            errors: 0,
        };

        // Run benchmark
        let start = Instant::now();
        let mut total_memory = 0;
        let mut task_durations = Vec::new();
        let mut current_tasks = 0;

        for i in 0..self.config.iterations {
            let mut vm = if self.config.enable_async {
                let runtime = self.async_runtime.as_ref().unwrap().clone();
                KapraVM::new_async(bytecode.clone(), runtime)
            } else {
                KapraVM::new(bytecode.clone())
            };

            // Run with metrics collection
            if let Some(collector) = &self.metrics_collector {
                collector.start_collection();
            }

            let iter_start = Instant::now();
            if self.config.enable_async {
                vm.run_async().await
                    .map_err(|e| KslError::type_error(format!("Async execution error: {}", e), pos))?;
            } else {
                vm.run()
                    .map_err(|e| KslError::type_error(format!("Execution error: {}", e), pos))?;
            }
            let iter_duration = iter_start.elapsed();

            // Update metrics
            if let Some(collector) = &self.metrics_collector {
                let metrics = collector.end_collection();
                
                // Update async metrics
                if self.config.enable_async {
                    async_metrics.tasks_created += metrics.async_tasks_created;
                    async_metrics.tasks_completed += metrics.async_tasks_completed;
                    current_tasks = metrics.current_async_tasks;
                    async_metrics.max_concurrent_tasks = async_metrics.max_concurrent_tasks.max(current_tasks);
                    task_durations.push(iter_duration);
                }

                // Update memory metrics
                let current_memory = metrics.memory_usage;
                total_memory += current_memory;
                memory_metrics.peak_memory = memory_metrics.peak_memory.max(current_memory);
                memory_metrics.allocation_count += metrics.allocation_count;

                // Update network metrics
                network_metrics.requests += metrics.network_requests;
                network_metrics.responses += metrics.network_responses;
                network_metrics.bytes_sent += metrics.network_bytes_sent;
                network_metrics.bytes_received += metrics.network_bytes_received;
                network_metrics.errors += metrics.network_errors;
                if metrics.network_requests > 0 {
                    network_metrics.avg_latency = (network_metrics.avg_latency * i as u32 + metrics.network_latency) / (i as u32 + 1);
                }
            }

            vm.reset(); // Reset VM state for next iteration
        }

        let total_duration = start.elapsed();
        let avg_duration = total_duration / self.config.iterations;

        // Finalize metrics
        memory_metrics.avg_memory = total_memory as usize / self.config.iterations as usize;
        if !task_durations.is_empty() {
            async_metrics.avg_task_duration = task_durations.iter().sum::<Duration>() / task_durations.len() as u32;
        }

        // Collect profiling data
        let profile_data = if self.config.iterations <= 1000 {
            Some(run_profile(&self.config.input_file, None)?)
        } else {
            None
        };

        let result = BenchmarkResult {
            total_duration,
            avg_duration,
            profile_data,
            async_metrics: if self.config.enable_async { Some(async_metrics) } else { None },
            memory_metrics: Some(memory_metrics),
            network_metrics: Some(network_metrics),
        };

        // Export results
        if let Some(output_path) = &self.config.output_path {
            match self.config.output_format.as_str() {
                "csv" => {
                    let mut content = String::new();
                    content.push_str("Total Duration (ms),Average Duration (ns),Peak Memory (bytes),Avg Memory (bytes),Network Requests,Network Errors,Async Tasks,Max Concurrent Tasks\n");
                    content.push_str(&format!(
                        "{},{},{},{},{},{},{},{}\n",
                        result.total_duration.as_millis(),
                        result.avg_duration.as_nanos(),
                        result.memory_metrics.as_ref().map_or(0, |m| m.peak_memory),
                        result.memory_metrics.as_ref().map_or(0, |m| m.avg_memory),
                        result.network_metrics.as_ref().map_or(0, |m| m.requests),
                        result.network_metrics.as_ref().map_or(0, |m| m.errors),
                        result.async_metrics.as_ref().map_or(0, |m| m.tasks_created),
                        result.async_metrics.as_ref().map_or(0, |m| m.max_concurrent_tasks)
                    ));
                    File::create(output_path)
                        .map_err(|e| KslError::type_error(
                            format!("Failed to create output file {}: {}", output_path.display(), e),
                            pos,
                        ))?
                        .write_all(content.as_bytes())
                        .map_err(|e| KslError::type_error(
                            format!("Failed to write output file {}: {}", output_path.display(), e),
                            pos,
                        ))?;
                }
                "json" => {
                    let json_data = json!({
                        "total_duration_ms": result.total_duration.as_millis(),
                        "average_duration_ns": result.avg_duration.as_nanos(),
                        "iterations": self.config.iterations,
                        "profile_data": result.profile_data.as_ref().map(|data| json!({
                            "total_duration_ms": data.total_duration.as_millis(),
                            "call_graph": data.call_graph
                        })),
                        "async_metrics": result.async_metrics.as_ref().map(|m| json!({
                            "tasks_created": m.tasks_created,
                            "tasks_completed": m.tasks_completed,
                            "max_concurrent_tasks": m.max_concurrent_tasks,
                            "avg_task_duration_ms": m.avg_task_duration.as_millis()
                        })),
                        "memory_metrics": result.memory_metrics.as_ref().map(|m| json!({
                            "peak_memory_bytes": m.peak_memory,
                            "avg_memory_bytes": m.avg_memory,
                            "allocation_count": m.allocation_count
                        })),
                        "network_metrics": result.network_metrics.as_ref().map(|m| json!({
                            "requests": m.requests,
                            "responses": m.responses,
                            "bytes_sent": m.bytes_sent,
                            "bytes_received": m.bytes_received,
                            "avg_latency_ms": m.avg_latency.as_millis(),
                            "errors": m.errors
                        }))
                    });
                    File::create(output_path)
                        .map_err(|e| KslError::type_error(
                            format!("Failed to create output file {}: {}", output_path.display(), e),
                            pos,
                        ))?
                        .write_all(serde_json::to_string_pretty(&json_data)?.as_bytes())
                        .map_err(|e| KslError::type_error(
                            format!("Failed to write output file {}: {}", output_path.display(), e),
                            pos,
                        ))?;
                }
                _ => return Err(KslError::type_error(
                    format!("Unsupported output format: {}", self.config.output_format),
                    pos,
                )),
            }
        } else {
            println!(
                "Benchmark Results:\nTotal Duration: {:.2?}\nAverage Duration: {}ns\nIterations: {}\n",
                result.total_duration,
                result.avg_duration.as_nanos(),
                self.config.iterations
            );
            if let Some(async_metrics) = &result.async_metrics {
                println!(
                    "Async Metrics:\nTasks Created: {}\nTasks Completed: {}\nMax Concurrent: {}\nAvg Task Duration: {:.2?}",
                    async_metrics.tasks_created,
                    async_metrics.tasks_completed,
                    async_metrics.max_concurrent_tasks,
                    async_metrics.avg_task_duration
                );
            }
            if let Some(memory_metrics) = &result.memory_metrics {
                println!(
                    "Memory Metrics:\nPeak Memory: {} bytes\nAvg Memory: {} bytes\nAllocations: {}",
                    memory_metrics.peak_memory,
                    memory_metrics.avg_memory,
                    memory_metrics.allocation_count
                );
            }
            if let Some(network_metrics) = &result.network_metrics {
                println!(
                    "Network Metrics:\nRequests: {}\nResponses: {}\nBytes Sent: {}\nBytes Received: {}\nAvg Latency: {:.2?}\nErrors: {}",
                    network_metrics.requests,
                    network_metrics.responses,
                    network_metrics.bytes_sent,
                    network_metrics.bytes_received,
                    network_metrics.avg_latency,
                    network_metrics.errors
                );
            }
            if let Some(profile_data) = &result.profile_data {
                println!("Profiling Data:\nTotal Duration: {:.2?}\nCall Graph: {:?}", profile_data.total_duration, profile_data.call_graph);
            }
        }

        Ok(result)
    }
}

/// Public API to run benchmarks with async support and metrics
pub async fn benchmark(
    input_file: &PathBuf,
    iterations: u32,
    output_format: &str,
    output_path: Option<PathBuf>,
    optimize: bool,
    enable_async: bool,
    metrics_config: Option<MetricsConfig>
) -> Result<BenchmarkResult, KslError> {
    let pos = SourcePosition::new(1, 1);
    if iterations == 0 {
        return Err(KslError::type_error("Iterations must be greater than 0".to_string(), pos));
    }
    if output_format != "csv" && output_format != "json" {
        return Err(KslError::type_error(
            format!("Invalid output format: {}. Use 'csv' or 'json'", output_format),
            pos,
        ));
    }

    let config = BenchmarkConfig {
        input_file: input_file.clone(),
        iterations,
        output_format: output_format.to_string(),
        output_path,
        optimize,
        enable_async,
        metrics_config,
    };
    let tool = BenchmarkTool::new(config);
    tool.run().await
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, kapra_vm.rs, ksl_optimizer.rs, ksl_profile.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod kapra_vm {
    pub use super::{KapraVM, RuntimeError};
}

mod ksl_optimizer {
    pub use super::optimize;
}

mod ksl_profile {
    pub use super::{ProfileData, run_profile};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

mod ksl_metrics {
    pub use super::{MetricsCollector, MetricsConfig};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncVM};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    use tokio;

    #[tokio::test]
    async fn test_benchmark_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "async fn main() {{ let x: u32 = 42; await async_task(); }}\nasync fn async_task() {{ let y: u32 = 21; }}"
        ).unwrap();

        let output_path = temp_dir.path().join("results.json");
        let result = benchmark(
            &input_file,
            100,
            "json",
            Some(output_path.clone()),
            true,
            true,
            Some(MetricsConfig {
                otel_endpoint: None,
                log_path: None,
                trace_enabled: true,
            })
        ).await;
        
        assert!(result.is_ok());
        let result = result.unwrap();

        assert!(result.total_duration > Duration::from_secs(0));
        assert!(result.avg_duration > Duration::from_nanos(0));
        assert!(result.async_metrics.is_some());
        assert!(result.memory_metrics.is_some());
        assert!(result.network_metrics.is_some());

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("\"async_metrics\""));
        assert!(content.contains("\"memory_metrics\""));
        assert!(content.contains("\"network_metrics\""));
    }

    #[tokio::test]
    async fn test_benchmark_sync() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let output_path = temp_dir.path().join("results.csv");
        let result = benchmark(
            &input_file,
            1000,
            "csv",
            Some(output_path.clone()),
            false,
            false,
            None
        ).await;
        
        assert!(result.is_ok());
        let result = result.unwrap();

        assert!(result.total_duration > Duration::from_secs(0));
        assert!(result.avg_duration > Duration::from_nanos(0));
        assert!(result.async_metrics.is_none());
        assert!(result.memory_metrics.is_some());

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("Total Duration (ms),Average Duration (ns)"));
        assert!(content.contains("1000"));
    }

    #[tokio::test]
    async fn test_benchmark_invalid_iterations() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let result = benchmark(&input_file, 0, "csv", None, false, false, None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Iterations must be greater than 0"));
    }

    #[tokio::test]
    async fn test_benchmark_invalid_format() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let result = benchmark(&input_file, 1000, "invalid", None, false, false, None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid output format"));
    }
}
