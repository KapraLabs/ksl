// ksl_metrics.rs
// Collects runtime metrics for KSL programs in production, tracking execution time,
// memory usage, and errors with minimal overhead, exporting to Prometheus or logs.

use crate::ksl_parser::{parse, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::KapraBytecode;
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_errors::{KslError, SourcePosition};
use prometheus::{Counter, Gauge, Histogram, Registry, Encoder, TextEncoder};
use actix_web::{web, App, HttpResponse, HttpServer};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Instant, Duration};
use rand::Rng;

// Metrics configuration
#[derive(Debug)]
pub struct MetricsConfig {
    prometheus_port: Option<u16>, // Port for Prometheus endpoint
    log_path: Option<PathBuf>, // Path for metric logs
    trace_enabled: bool, // Enable distributed tracing
}

// Runtime metrics data
#[derive(Debug)]
pub struct MetricsData {
    execution_time: Histogram, // Execution time per function
    memory_usage: Gauge, // Current memory usage in bytes
    error_count: Counter, // Number of runtime errors
    traces: HashMap<String, Duration>, // Trace ID -> duration
}

// Metrics collector
pub struct MetricsCollector {
    config: MetricsConfig,
    registry: Registry,
    data: Mutex<MetricsData>,
}

impl MetricsCollector {
    pub fn new(config: MetricsConfig) -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1);
        let registry = Registry::new();
        let execution_time = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "ksl_execution_time_seconds",
                "Execution time of KSL functions",
            )
            .buckets(vec![0.001, 0.01, 0.1, 1.0, 10.0]),
        ).map_err(|e| KslError::type_error(format!("Failed to create metric: {}", e), pos))?;
        let memory_usage = Gauge::new(
            "ksl_memory_usage_bytes",
            "Memory usage of KSL program",
        ).map_err(|e| KslError::type_error(format!("Failed to create metric: {}", e), pos))?;
        let error_count = Counter::new(
            "ksl_error_count",
            "Number of runtime errors in KSL program",
        ).map_err(|e| KslError::type_error(format!("Failed to create metric: {}", e), pos))?;

        registry.register(Box::new(execution_time.clone()))
            .map_err(|e| KslError::type_error(format!("Failed to register metric: {}", e), pos))?;
        registry.register(Box::new(memory_usage.clone()))
            .map_err(|e| KslError::type_error(format!("Failed to register metric: {}", e), pos))?;
        registry.register(Box::new(error_count.clone()))
            .map_err(|e| KslError::type_error(format!("Failed to register metric: {}", e), pos))?;

        Ok(MetricsCollector {
            config,
            registry,
            data: Mutex::new(MetricsData {
                execution_time,
                memory_usage,
                error_count,
                traces: HashMap::new(),
            }),
        })
    }

    // Collect metrics for a KSL program
    pub fn collect(&self, file: &PathBuf) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Compile program
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

        // Run program with metrics
        let trace_id = if self.config.trace_enabled {
            Some(format!("trace-{}", rand::thread_rng().gen::<u64>()))
        } else {
            None
        };
        let mut vm = KapraVM::new_with_metrics(bytecode);
        let start = Instant::now();
        if let Err(e) = vm.run() {
            self.data.lock().unwrap().error_count.inc();
            self.log_error(&format!("Runtime error: {}", e), trace_id.as_deref());
            return Err(KslError::type_error(format!("Execution error: {}", e), pos));
        }
        let duration = start.elapsed();

        // Update metrics
        let mut data = self.data.lock().unwrap();
        data.execution_time.observe(duration.as_secs_f64());
        data.memory_usage.set(vm.get_memory_usage() as f64);
        if let Some(trace_id) = trace_id {
            data.traces.insert(trace_id.clone(), duration);
            self.log_metric(&format!("Trace {} completed in {:?}", trace_id, duration), Some(&trace_id));
        }

        // Write logs if specified
        if let Some(log_path) = &self.config.log_path {
            let log_content = format!(
                "Execution Time: {:.2?}\nMemory Usage: {} bytes\nErrors: {}\nTraces: {:?}\n",
                duration, vm.get_memory_usage(), data.error_count.get(), data.traces
            );
            fs::write(log_path, log_content)
                .map_err(|e| KslError::type_error(
                    format!("Failed to write logs to {}: {}", log_path.display(), e),
                    pos,
                ))?;
        }

        Ok(())
    }

    // Start Prometheus endpoint
    pub fn start_prometheus(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let port = self.config.prometheus_port.unwrap_or(9000);
        let registry = self.registry.clone();
        HttpServer::new(move || {
            App::new()
                .route("/metrics", web::get().to(move || {
                    let mut buffer = vec![];
                    let encoder = TextEncoder::new();
                    encoder.encode(&registry.gather(), &mut buffer).unwrap();
                    HttpResponse::Ok()
                        .content_type("text/plain; version=0.0.4")
                        .body(buffer)
                }))
        })
        .bind(("127.0.0.1", port))
        .map_err(|e| KslError::type_error(
            format!("Failed to bind Prometheus endpoint to port {}: {}", port, e),
            pos,
        ))?
        .run()
        .map_err(|e| KslError::type_error(
            format!("Prometheus server error: {}", e),
            pos,
        ))?;

        Ok(())
    }

    // Log a metric or error
    fn log_metric(&self, message: &str, trace_id: Option<&str>) {
        let log = match trace_id {
            Some(id) => format!("[{}] {}", id, message),
            None => message.to_string(),
        };
        if let Some(log_path) = &self.config.log_path {
            if let Ok(mut file) = File::options().append(true).open(log_path) {
                writeln!(file, "{}", log).ok();
            }
        }
    }

    fn log_error(&self, message: &str, trace_id: Option<&str>) {
        self.log_metric(&format!("ERROR: {}", message), trace_id);
    }
}

// Extend KapraVM for metrics collection
trait MetricsVM {
    fn new_with_metrics(bytecode: KapraBytecode) -> Self;
    fn get_memory_usage(&self) -> usize;
}

impl MetricsVM for KapraVM {
    fn new_with_metrics(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode);
        vm.metrics_data = Some(MetricsData {
            memory_usage: 0,
        });
        vm
    }

    fn get_memory_usage(&self) -> usize {
        self.metrics_data.as_ref().map(|d| d.memory_usage).unwrap_or(0)
    }
}

// Metrics data structure for KapraVM
struct MetricsData {
    memory_usage: usize,
}

// Public API to collect metrics
pub fn collect_metrics(file: &PathBuf, prometheus_port: Option<u16>, log_path: Option<PathBuf>, trace_enabled: bool) -> Result<(), KslError> {
    let config = MetricsConfig {
        prometheus_port,
        log_path,
        trace_enabled,
    };
    let collector = MetricsCollector::new(config)?;
    
    // Start Prometheus endpoint if specified
    if collector.config.prometheus_port.is_some() {
        std::thread::spawn(move || {
            collector.start_prometheus().unwrap();
        });
    }

    collector.collect(file)
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_bytecode {
    pub use super::KapraBytecode;
}

mod kapra_vm {
    pub use super::{KapraVM, RuntimeError};
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
    fn test_collect_metrics() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { let x: u32 = 42; sha3(\"data\"); }"
        ).unwrap();
        let log_path = temp_file.path().parent().unwrap().join("metrics.log");

        let result = collect_metrics(
            &temp_file.path().to_path_buf(),
            None,
            Some(log_path.clone()),
            true,
        );
        assert!(result.is_ok());
        assert!(log_path.exists());
        let log_content = fs::read_to_string(&log_path).unwrap();
        assert!(log_content.contains("Execution Time"));
        assert!(log_content.contains("Trace trace-"));
    }

    #[test]
    fn test_collect_metrics_error() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { let x: u32 = 42; invalid_function(); }"
        ).unwrap();
        let log_path = temp_file.path().parent().unwrap().join("metrics.log");

        let result = collect_metrics(
            &temp_file.path().to_path_buf(),
            None,
            Some(log_path.clone()),
            true,
        );
        assert!(result.is_err());
        assert!(log_path.exists());
        let log_content = fs::read_to_string(&log_path).unwrap();
        assert!(log_content.contains("ERROR:"));
    }

    #[test]
    fn test_collect_metrics_invalid_file() {
        let invalid_file = PathBuf::from("nonexistent.ksl");
        let result = collect_metrics(&invalid_file, None, None, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}
