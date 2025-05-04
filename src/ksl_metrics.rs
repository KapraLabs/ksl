// ksl_metrics.rs
// Collects runtime metrics for KSL programs in production, tracking execution time,
// memory usage, networking operations, and errors with minimal overhead, exporting
// to OpenTelemetry or logs.

use crate::ksl_parser::{parse, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraOpCode};
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_errors::{KslError, SourcePosition};
use opentelemetry::{
    global,
    metrics::{Counter, Histogram, Meter, Unit, ValueRecorder},
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::{MeterProvider, PeriodicReader},
    runtime::Tokio,
    Resource,
};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Instant, Duration};
use rand::Rng;

/// Configuration for metrics collection
#[derive(Debug)]
pub struct MetricsConfig {
    /// OpenTelemetry endpoint URL
    otel_endpoint: Option<String>,
    /// Path for metric logs
    log_path: Option<PathBuf>,
    /// Enable distributed tracing
    trace_enabled: bool,
}

/// Runtime metrics data
#[derive(Debug)]
pub struct MetricsData {
    /// Execution time per function
    execution_time: Histogram<f64>,
    /// Current memory usage in bytes
    memory_usage: Counter<u64>,
    /// Number of runtime errors
    error_count: Counter<u64>,
    /// HTTP request latency
    http_latency: Histogram<f64>,
    /// TCP connection latency
    tcp_latency: Histogram<f64>,
    /// Async operation latency
    async_latency: Histogram<f64>,
    /// Trace ID -> duration
    traces: HashMap<String, Duration>,
}

/// Metrics collector
pub struct MetricsCollector {
    config: MetricsConfig,
    meter: Meter,
    data: Mutex<MetricsData>,
}

impl MetricsCollector {
    /// Create a new metrics collector with the given configuration
    pub fn new(config: MetricsConfig) -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Initialize OpenTelemetry meter provider
        let meter_provider = if let Some(endpoint) = &config.otel_endpoint {
            let exporter = opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(endpoint);
            
            MeterProvider::builder()
                .with_reader(PeriodicReader::builder(exporter, Tokio).build())
                .with_resource(Resource::new(vec![KeyValue::new("service.name", "ksl")]))
                .build()
        } else {
            MeterProvider::builder()
                .with_reader(PeriodicReader::builder(opentelemetry_stdout::new(), Tokio).build())
                .with_resource(Resource::new(vec![KeyValue::new("service.name", "ksl")]))
                .build()
        };

        let meter = meter_provider.meter("ksl");

        // Create metrics
        let execution_time = meter
            .f64_histogram("ksl.execution.time")
            .with_description("Execution time of KSL functions")
            .with_unit(Unit::new("s"))
            .init();

        let memory_usage = meter
            .u64_counter("ksl.memory.usage")
            .with_description("Memory usage of KSL program")
            .with_unit(Unit::new("bytes"))
            .init();

        let error_count = meter
            .u64_counter("ksl.error.count")
            .with_description("Number of runtime errors in KSL program")
            .init();

        let http_latency = meter
            .f64_histogram("ksl.http.latency")
            .with_description("HTTP request latency")
            .with_unit(Unit::new("s"))
            .init();

        let tcp_latency = meter
            .f64_histogram("ksl.tcp.latency")
            .with_description("TCP connection latency")
            .with_unit(Unit::new("s"))
            .init();

        let async_latency = meter
            .f64_histogram("ksl.async.latency")
            .with_description("Async operation latency")
            .with_unit(Unit::new("s"))
            .init();

        Ok(MetricsCollector {
            config,
            meter,
            data: Mutex::new(MetricsData {
                execution_time,
                memory_usage,
                error_count,
                http_latency,
                tcp_latency,
                async_latency,
                traces: HashMap::new(),
            }),
        })
    }

    /// Collect metrics for a KSL program
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
            self.data.lock().unwrap().error_count.add(1, &[]);
            self.log_error(&format!("Runtime error: {}", e), trace_id.as_deref());
            return Err(KslError::type_error(format!("Execution error: {}", e), pos));
        }
        let duration = start.elapsed();

        // Update metrics
        let mut data = self.data.lock().unwrap();
        data.execution_time.record(duration.as_secs_f64(), &[]);
        data.memory_usage.add(vm.get_memory_usage() as u64, &[]);

        // Track networking and async operations
        for (opcode, latency) in vm.get_operation_latencies() {
            match opcode {
                KapraOpCode::HttpGet | KapraOpCode::HttpPost | KapraOpCode::HttpPut | KapraOpCode::HttpDelete => {
                    data.http_latency.record(latency.as_secs_f64(), &[]);
                }
                KapraOpCode::TcpConnect | KapraOpCode::TcpListen | KapraOpCode::TcpAccept | 
                KapraOpCode::TcpSend | KapraOpCode::TcpReceive => {
                    data.tcp_latency.record(latency.as_secs_f64(), &[]);
                }
                KapraOpCode::AsyncStart | KapraOpCode::AsyncAwait | KapraOpCode::AsyncResolve => {
                    data.async_latency.record(latency.as_secs_f64(), &[]);
                }
                _ => {}
            }
        }

        if let Some(trace_id) = trace_id {
            data.traces.insert(trace_id.clone(), duration);
            self.log_metric(&format!("Trace {} completed in {:?}", trace_id, duration), Some(&trace_id));
        }

        // Write logs if specified
        if let Some(log_path) = &self.config.log_path {
            let log_content = format!(
                "Execution Time: {:.2?}\nMemory Usage: {} bytes\nErrors: {}\nHTTP Latency: {:?}\nTCP Latency: {:?}\nAsync Latency: {:?}\nTraces: {:?}\n",
                duration, vm.get_memory_usage(), data.error_count.get(), 
                data.http_latency.get(), data.tcp_latency.get(), data.async_latency.get(),
                data.traces
            );
            fs::write(log_path, log_content)
                .map_err(|e| KslError::type_error(
                    format!("Failed to write logs to {}: {}", log_path.display(), e),
                    pos,
                ))?;
        }

        Ok(())
    }

    /// Log a metric or error
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
    fn get_operation_latencies(&self) -> Vec<(KapraOpCode, Duration)>;
}

impl MetricsVM for KapraVM {
    fn new_with_metrics(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode);
        vm.metrics_data = Some(MetricsData {
            memory_usage: 0,
            operation_latencies: Vec::new(),
        });
        vm
    }

    fn get_memory_usage(&self) -> usize {
        self.metrics_data.as_ref().map(|d| d.memory_usage).unwrap_or(0)
    }

    fn get_operation_latencies(&self) -> Vec<(KapraOpCode, Duration)> {
        self.metrics_data.as_ref()
            .map(|d| d.operation_latencies.clone())
            .unwrap_or_default()
    }
}

// Metrics data structure for KapraVM
struct MetricsData {
    memory_usage: usize,
    operation_latencies: Vec<(KapraOpCode, Duration)>,
}

// Public API to collect metrics
pub fn collect_metrics(file: &PathBuf, otel_endpoint: Option<String>, log_path: Option<PathBuf>, trace_enabled: bool) -> Result<(), KslError> {
    let config = MetricsConfig {
        otel_endpoint,
        log_path,
        trace_enabled,
    };
    let collector = MetricsCollector::new(config)?;
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
    pub use super::{KapraBytecode, KapraOpCode};
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
        write!(
            temp_file,
            r#"
            fn test_metrics() {{
                print("Hello, World!");
            }}
            "#
        ).unwrap();

        let result = collect_metrics(
            &temp_file.path().to_path_buf(),
            Some("http://localhost:4317".to_string()),
            None,
            false
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_collect_metrics_with_networking() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(
            temp_file,
            r#"
            fn test_networking() {{
                let response = http.get("https://example.com");
                print(response);
                
                let socket = tcp.connect("localhost:8080");
                socket.send("Hello");
                let response = socket.receive();
                print(response);
            }}
            "#
        ).unwrap();

        let result = collect_metrics(
            &temp_file.path().to_path_buf(),
            Some("http://localhost:4317".to_string()),
            None,
            true
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_collect_metrics_with_async() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(
            temp_file,
            r#"
            fn test_async() {{
                async fn fetch_data() {{
                    let response = http.get("https://example.com");
                    return response;
                }}

                let future = fetch_data();
                let result = await future;
                print(result);
            }}
            "#
        ).unwrap();

        let result = collect_metrics(
            &temp_file.path().to_path_buf(),
            Some("http://localhost:4317".to_string()),
            None,
            true
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_collect_metrics_with_logs() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let log_file = NamedTempFile::new().unwrap();
        write!(
            temp_file,
            r#"
            fn test_logs() {{
                print("Hello, World!");
            }}
            "#
        ).unwrap();

        let result = collect_metrics(
            &temp_file.path().to_path_buf(),
            None,
            Some(log_file.path().to_path_buf()),
            false
        );
        assert!(result.is_ok());

        let log_content = fs::read_to_string(log_file.path()).unwrap();
        assert!(log_content.contains("Execution Time"));
        assert!(log_content.contains("Memory Usage"));
        assert!(log_content.contains("Errors"));
    }

    #[test]
    fn test_collect_metrics_error() {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(
            temp_file,
            r#"
            fn test_error() {{
                let x = 1 / 0; // Division by zero
            }}
            "#
        ).unwrap();

        let result = collect_metrics(
            &temp_file.path().to_path_buf(),
            Some("http://localhost:4317".to_string()),
            None,
            false
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_collect_metrics_invalid_file() {
        let invalid_file = PathBuf::from("nonexistent.ksl");
        let result = collect_metrics(
            &invalid_file,
            Some("http://localhost:4317".to_string()),
            None,
            false
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}
