// ksl_profile.rs
// Extends ksl_analyzer.rs with advanced profiling for rapid performance optimization,
// providing call graph analysis, memory leak detection, and visual flame graphs.
// Supports async profiling and metrics collection for comprehensive performance analysis.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::kapra_vm::{KapraVM, RuntimeError, VmMetrics};
use crate::ksl_metrics::{MetricsCollector, MetricType};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Instant, Duration};
use std::sync::Arc;
use tokio::sync::RwLock;
use inferno::flamegraph::{from_lines, Options as FlamegraphOptions};

/// Profiling data collected during execution
#[derive(Debug, Clone)]
pub struct ProfileData {
    /// Function call graph with timing information
    pub call_graph: HashMap<String, CallNode>,
    /// Memory allocation tracking
    pub memory_allocations: HashMap<usize, MemoryAllocation>,
    /// Total execution time
    pub total_duration: Duration,
    /// Performance metrics collected during execution
    pub metrics: HashMap<String, MetricType>,
}

/// Call graph node for a function
#[derive(Debug, Clone)]
pub struct CallNode {
    /// Function name
    pub name: String,
    /// Call counts to other functions
    pub calls: HashMap<String, u64>,
    /// Total time spent in function
    pub duration: Duration,
    /// Async operation metrics
    pub async_metrics: AsyncMetrics,
}

/// Async operation metrics
#[derive(Debug, Clone, Default)]
pub struct AsyncMetrics {
    /// Number of async operations
    pub operation_count: u64,
    /// Total time spent in async operations
    pub total_async_time: Duration,
    /// Time spent waiting for async operations
    pub wait_time: Duration,
}

/// Memory allocation details
#[derive(Debug, Clone)]
pub struct MemoryAllocation {
    /// Size in bytes
    pub size: usize,
    /// Source line number
    pub line: usize,
    /// Whether allocation was freed
    pub freed: bool,
    /// Allocation timestamp
    pub timestamp: Instant,
}

/// Profiling report summarizing performance
#[derive(Debug)]
pub struct ProfileReport {
    /// Function call graph
    pub call_graph: HashMap<String, CallNode>,
    /// Detected memory leaks
    pub memory_leaks: Vec<MemoryAllocation>,
    /// Total execution time
    pub total_duration: Duration,
    /// Performance metrics summary
    pub metrics_summary: MetricsSummary,
}

/// Performance metrics summary
#[derive(Debug)]
pub struct MetricsSummary {
    /// CPU usage metrics
    pub cpu_metrics: HashMap<String, f64>,
    /// Memory usage metrics
    pub memory_metrics: HashMap<String, f64>,
    /// Async operation metrics
    pub async_metrics: HashMap<String, f64>,
}

impl ProfileReport {
    /// Generate a text-based report with metrics
    pub fn to_string(&self, source: &str) -> String {
        let mut report = format!(
            "Profiling Report:\nTotal Execution Time: {:.2?}\n\nCall Graph:\n",
            self.total_duration
        );

        for (name, node) in &self.call_graph {
            report.push_str(&format!(
                "Function {} (Duration: {:.2?}, Async Time: {:.2?})\n",
                name, node.duration, node.async_metrics.total_async_time
            ));
            for (callee, count) in &node.calls {
                report.push_str(&format!("  -> {}: {} calls\n", callee, count));
            }
        }

        report.push_str("\nMemory Leaks:\n");
        if self.memory_leaks.is_empty() {
            report.push_str("No memory leaks detected.\n");
        } else {
            for alloc in &self.memory_leaks {
                report.push_str(&format!(
                    "Leak: {} bytes at line {} (Allocated at: {:.2?})\n",
                    alloc.size, alloc.line, alloc.timestamp
                ));
            }
        }

        report.push_str("\nMetrics Summary:\n");
        for (name, value) in &self.metrics_summary.cpu_metrics {
            report.push_str(&format!("CPU {}: {:.2}%\n", name, value));
        }
        for (name, value) in &self.metrics_summary.memory_metrics {
            report.push_str(&format!("Memory {}: {:.2} MB\n", name, value));
        }
        for (name, value) in &self.metrics_summary.async_metrics {
            report.push_str(&format!("Async {}: {:.2} ms\n", name, value));
        }

        report
    }

    /// Generate a flame graph with async operation visualization
    pub fn to_flamegraph(&self, output_path: &PathBuf) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut lines = vec![];
        for (name, node) in &self.call_graph {
            let stack = format!("{} {}", name, node.duration.as_nanos());
            lines.push(stack);
            for (callee, count) in &node.calls {
                let stack = format!("{};{} {}", name, callee, count);
                lines.push(stack);
            }
            // Add async operation stacks
            if node.async_metrics.operation_count > 0 {
                let async_stack = format!(
                    "{};async {}",
                    name,
                    node.async_metrics.total_async_time.as_nanos()
                );
                lines.push(async_stack);
            }
        }

        let mut file = File::create(output_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create flamegraph {}: {}", output_path.display(), e),
                pos,
            ))?;
        let options = FlamegraphOptions::default();
        from_lines(&mut options, lines.iter().map(|s| s.as_str()), &mut file)
            .map_err(|e| KslError::type_error(
                format!("Failed to generate flamegraph: {}", e),
                pos,
            ))?;

        Ok(())
    }
}

/// Profiler for collecting and analyzing performance data
pub struct Profiler {
    /// Compiled bytecode
    bytecode: KapraBytecode,
    /// Source code
    source: String,
    /// Instruction to source line mapping
    line_map: HashMap<usize, usize>,
    /// Metrics collector
    metrics_collector: Arc<MetricsCollector>,
    /// Async runtime
    async_runtime: Arc<AsyncRuntime>,
    /// Profiling state
    state: Arc<RwLock<ProfileState>>,
}

/// Profiler state
#[derive(Debug, Clone)]
pub struct ProfileState {
    /// Current call stack
    call_stack: Vec<(String, Instant)>,
    /// Memory allocations
    allocations: HashMap<usize, MemoryAllocation>,
    /// Current allocation ID
    current_alloc_id: usize,
    /// Async operation tracking
    async_ops: HashMap<String, AsyncMetrics>,
}

impl Profiler {
    /// Creates a new profiler instance
    pub fn new(file: &PathBuf) -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1);
        let source = fs::read_to_string(file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", file.display(), e),
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
        let bytecode = compile(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        let line_map = build_line_map(&ast, &bytecode);
        let metrics_collector = Arc::new(MetricsCollector::new());
        let async_runtime = Arc::new(AsyncRuntime::new());
        let state = Arc::new(RwLock::new(ProfileState {
            call_stack: Vec::new(),
            allocations: HashMap::new(),
            current_alloc_id: 0,
            async_ops: HashMap::new(),
        }));

        Ok(Profiler {
            bytecode,
            source,
            line_map,
            metrics_collector,
            async_runtime,
            state,
        })
    }

    /// Collect profiling data asynchronously
    pub async fn collect_profile_async(&self) -> AsyncResult<ProfileData> {
        let mut vm = KapraVM::new_with_profiling(self.bytecode.clone());
        let start = Instant::now();
        self.run_program_with_profiling_async(&mut vm, &self.source).await?;
        let total_duration = start.elapsed();

        let call_graph = vm.get_call_graph();
        let memory_allocations = vm.get_memory_allocations();
        let metrics = self.metrics_collector.get_metrics();

        Ok(ProfileData {
            call_graph,
            memory_allocations,
            total_duration,
            metrics,
        })
    }

    /// Generate profiling report asynchronously
    pub async fn generate_report_async(
        &self,
        data: &ProfileData,
        flamegraph_path: Option<&PathBuf>,
    ) -> AsyncResult<ProfileReport> {
        let mut memory_leaks = vec![];
        for alloc in data.memory_allocations.values() {
            if !alloc.freed {
                memory_leaks.push(alloc.clone());
            }
        }

        let metrics_summary = self.summarize_metrics(&data.metrics).await;

        let report = ProfileReport {
            call_graph: data.call_graph.clone(),
            memory_leaks,
            total_duration: data.total_duration,
            metrics_summary,
        };

        if let Some(path) = flamegraph_path {
            report.to_flamegraph(path)?;
        }

        Ok(report)
    }

    /// Run program with async profiling
    async fn run_program_with_profiling_async(
        &self,
        vm: &mut KapraVM,
        source: &str,
    ) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        let ast = parse(source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;

        // Start metrics collection
        self.metrics_collector.start_collection();

        // Run program with async support
        vm.run_async().await
            .map_err(|e| KslError::type_error(
                format!("Execution error: {}", e),
                pos,
            ))?;

        // Stop metrics collection
        self.metrics_collector.stop_collection();

        Ok(())
    }

    /// Summarize collected metrics
    async fn summarize_metrics(&self, metrics: &HashMap<String, MetricType>) -> MetricsSummary {
        let mut cpu_metrics = HashMap::new();
        let mut memory_metrics = HashMap::new();
        let mut async_metrics = HashMap::new();

        for (name, metric) in metrics {
            match metric {
                MetricType::CpuUsage(value) => {
                    cpu_metrics.insert(name.clone(), *value);
                }
                MetricType::MemoryUsage(value) => {
                    memory_metrics.insert(name.clone(), *value);
                }
                MetricType::AsyncOperation(value) => {
                    async_metrics.insert(name.clone(), *value);
                }
            }
        }

        MetricsSummary {
            cpu_metrics,
            memory_metrics,
            async_metrics,
        }
    }
}

/// Public API to run profiling asynchronously
pub async fn run_profile_async(
    file: &PathBuf,
    flamegraph_path: Option<&PathBuf>,
) -> AsyncResult<ProfileReport> {
    let profiler = Profiler::new(file)?;
    let profile_data = profiler.collect_profile_async().await?;
    profiler.generate_report_async(&profile_data, flamegraph_path).await
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs,
// kapra_vm.rs, ksl_metrics.rs, ksl_async.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ParseError};
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
    pub use super::{KapraVM, RuntimeError, VmMetrics};
}

mod ksl_metrics {
    pub use super::{MetricsCollector, MetricType};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncResult};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_profile_basic_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        fs::write(&input_file, r#"
            fn main() {
                let x = 42;
                println!("Hello, world!");
            }
        "#).unwrap();

        let result = run_profile_async(&input_file, None).await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.call_graph.contains_key("main"));
        assert!(report.memory_leaks.is_empty());
    }

    #[tokio::test]
    async fn test_profile_async_operations() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        fs::write(&input_file, r#"
            async fn main() {
                let result = await http.get("https://example.com");
                println!("Response: {}", result);
            }
        "#).unwrap();

        let result = run_profile_async(&input_file, None).await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.call_graph.contains_key("main"));
        let main_node = report.call_graph.get("main").unwrap();
        assert!(main_node.async_metrics.operation_count > 0);
    }

    #[tokio::test]
    async fn test_profile_metrics() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        fs::write(&input_file, r#"
            fn main() {
                let mut vec = Vec::new();
                for i in 0..1000 {
                    vec.push(i);
                }
            }
        "#).unwrap();

        let result = run_profile_async(&input_file, None).await;
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.metrics_summary.cpu_metrics.is_empty());
        assert!(!report.metrics_summary.memory_metrics.is_empty());
    }
}
