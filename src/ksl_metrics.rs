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
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Instant, Duration};
use rand::Rng;
use chrono::Local;
use serde::{Serialize, Deserialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

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
    metrics: Vec<MetricValue>,
    start_time: i64,
    cache_hits: u64,
    cache_misses: u64,
    async_operations: Vec<Duration>,
    execution_time: Histogram<f64>,
    tx_counter: Counter<u64>,
    failed_tx_counter: Counter<u64>,
    gas_usage: Histogram<f64>,
    proof_gen_time: Histogram<f64>,
    proof_verify_time: Histogram<f64>,
    proof_size: Histogram<f64>,
    proof_success: Counter<u64>,
    proof_failure: Counter<u64>,
    metrics_cache: Arc<RwLock<HashMap<String, BlockResult>>>,
}

impl MetricsCollector {
    /// Create a new metrics collector with the given configuration
    pub fn new(config: MetricsConfig) -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Initialize OpenTelemetry meter provider
        let meter_provider = if let Some(endpoint) = &config.otel_endpoint {
            let exporter = opentelemetry_otlp::MetricExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()?;
            
            MeterProvider::builder()
                .with_reader(PeriodicReader::builder(exporter, Tokio).build())
                .with_resource(Resource::new(vec![KeyValue::new("service.name", "ksl")]))
                .build()
        } else {
            MeterProvider::builder()
                .with_reader(PeriodicReader::builder(opentelemetry_stdout::metrics_exporter(std::io::stdout()), Tokio).build())
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

        let tx_counter = meter
            .u64_counter("transactions_processed")
            .with_description("Number of transactions processed")
            .init();

        let failed_tx_counter = meter
            .u64_counter("transactions_failed")
            .with_description("Number of failed transactions")
            .init();

        let gas_usage = meter
            .f64_histogram("gas_usage")
            .with_description("Gas used per block")
            .init();

        let proof_gen_time = meter
            .f64_histogram("proof_generation_time")
            .with_description("Proof generation time in seconds")
            .with_unit(Unit::new("s"))
            .init();

        let proof_verify_time = meter
            .f64_histogram("proof_verification_time")
            .with_description("Proof verification time in seconds")
            .with_unit(Unit::new("s"))
            .init();

        let proof_size = meter
            .f64_histogram("proof_size")
            .with_description("Proof size in bytes")
            .with_unit(Unit::new("By"))
            .init();

        let proof_success = meter
            .u64_counter("proof_success")
            .with_description("Number of successful proof verifications")
            .init();

        let proof_failure = meter
            .u64_counter("proof_failure")
            .with_description("Number of failed proof verifications")
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
            metrics: Vec::new(),
            start_time: Local::now().timestamp(),
            cache_hits: 0,
            cache_misses: 0,
            async_operations: Vec::new(),
            execution_time,
            tx_counter,
            failed_tx_counter,
            gas_usage,
            proof_gen_time,
            proof_verify_time,
            proof_size,
            proof_success,
            proof_failure,
            metrics_cache: Arc::new(RwLock::new(HashMap::new())),
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
                "METRICS_FILE_READ_ERROR".to_string()
            ))?;
        let ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
                "METRICS_PARSE_ERROR".to_string()
            ))?;
        check(ast.as_slice())
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
                "METRICS_TYPE_ERROR".to_string()
            ))?;
        let bytecode = compile(ast.as_slice())
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
                "METRICS_COMPILE_ERROR".to_string()
            ))?;

        // Run program with metrics
        let trace_id = if self.config.trace_enabled {
            let mut rng = rand::thread_rng();
            Some(format!("trace-{}", rng.next_u64()))
        } else {
            None
        };
        let mut vm = KapraVM::new_with_metrics(bytecode);
        let start = Instant::now();
        if let Err(e) = vm.run() {
            self.data.lock().unwrap().error_count.add(1, &[]);
            self.log_error(&format!("Runtime error: {}", e), trace_id.as_deref());
            return Err(KslError::type_error(format!("Execution error: {}", e), pos, "METRICS_EXECUTION_ERROR".to_string()));
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
                    "METRICS_LOG_WRITE_ERROR".to_string()
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

    pub fn start_collection(&mut self) {
        self.start_time = Local::now().timestamp();
    }

    pub fn stop_collection(&mut self) -> Vec<MetricValue> {
        self.metrics.clone()
    }

    pub fn get_cache_stats(&self) -> CacheStats {
        let total = self.cache_hits + self.cache_misses;
        let hit_rate = if total > 0 {
            self.cache_hits as f64 / total as f64
        } else {
            0.0
        };

        CacheStats {
            hits: self.cache_hits,
            misses: self.cache_misses,
            hit_rate,
        }
    }

    pub fn get_async_metrics(&self) -> AsyncMetrics {
        let operation_count = self.async_operations.len() as u64;
        let total_duration: Duration = self.async_operations.iter().sum();
        let avg_duration = if operation_count > 0 {
            total_duration / operation_count
        } else {
            Duration::from_nanos(0)
        };

        AsyncMetrics {
            operation_count,
            async_duration: total_duration,
            avg_async_duration: avg_duration,
            max_concurrency: 1, // TODO: Implement actual concurrency tracking
        }
    }

    pub fn get_cpu_usage(&self) -> f64 {
        // TODO: Implement actual CPU usage tracking
        0.0
    }

    pub fn log_metrics(&self, result: &BlockResult) {
        // Basic block metrics
        let attributes = [
            KeyValue::new("validator_count", result.validator_count as i64),
            KeyValue::new("kaprekar_ratio", result.kaprekar_ratio),
        ];

        self.execution_time.record(result.block_time.as_secs_f64(), &attributes);
        self.tx_counter.add(result.processed_txs, &attributes);
        self.failed_tx_counter.add(result.failed_txs, &attributes);
        self.gas_usage.record(result.gas_used as f64, &attributes);

        // ZK proof metrics
        if let Some(scheme) = &result.zk_proof_scheme {
            let proof_attributes = [
                KeyValue::new("scheme", scheme.clone()),
                KeyValue::new("size", result.zk_proof_size.unwrap_or(0) as i64),
            ];

            // Record proof generation time
            if let Some(gen_time) = result.zk_proof_gen_time {
                self.proof_gen_time.record(gen_time.as_secs_f64(), &proof_attributes);
            }

            // Record proof verification time
            if let Some(verify_time) = result.zk_proof_verify_time {
                self.proof_verify_time.record(verify_time.as_secs_f64(), &proof_attributes);
            }

            // Record proof size
            if let Some(size) = result.zk_proof_size {
                self.proof_size.record(size as f64, &proof_attributes);
            }

            // Record proof success/failure
            if let Some(valid) = result.zk_proof_valid {
                if valid {
                    self.proof_success.add(1, &proof_attributes);
                } else {
                    self.proof_failure.add(1, &proof_attributes);
                }
            }

            // Log to console
            println!(
                "[ZKP] Scheme: {}, Size: {} bytes, Valid: {}, Gen Time: {:?}, Verify Time: {:?}",
                scheme,
                result.zk_proof_size.unwrap_or(0),
                result.zk_proof_valid.unwrap_or(false),
                result.zk_proof_gen_time.unwrap_or(Duration::from_secs(0)),
                result.zk_proof_verify_time.unwrap_or(Duration::from_secs(0)),
            );
        }

        // Cache the result
        let timestamp = Utc::now().to_rfc3339();
        let mut cache = self.metrics_cache.try_write().unwrap();
        cache.insert(timestamp, result.clone());
    }

    pub async fn export_metrics_to_csv(&self, path: &str) -> std::io::Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        let cache = self.metrics_cache.read().await;
        
        // Write header if file is empty
        if file.metadata()?.len() == 0 {
            writeln!(file, "timestamp,processed_txs,failed_txs,gas_used,block_time,validator_count,kaprekar_ratio,zk_scheme,zk_size,zk_valid,zk_gen_time,zk_verify_time")?;
        }

        // Write metrics
        for (timestamp, result) in cache.iter() {
            writeln!(
                file,
                "{},{},{},{},{},{},{},{},{},{},{},{}",
                timestamp,
                result.processed_txs,
                result.failed_txs,
                result.gas_used,
                result.block_time.as_secs_f64(),
                result.validator_count,
                result.kaprekar_ratio,
                result.zk_proof_scheme.as_deref().unwrap_or(""),
                result.zk_proof_size.unwrap_or(0),
                result.zk_proof_valid.unwrap_or(false),
                result.zk_proof_gen_time.map_or(0.0, |d| d.as_secs_f64()),
                result.zk_proof_verify_time.map_or(0.0, |d| d.as_secs_f64()),
            )?;
        }

        Ok(())
    }

    pub fn get_proof_success_rate(&self, scheme: &str) -> f64 {
        let attributes = &[KeyValue::new("scheme", scheme.to_string())];
        let success = self.proof_success.get_value(attributes);
        let failure = self.proof_failure.get_value(attributes);
        let total = success + failure;
        if total > 0 {
            success as f64 / total as f64
        } else {
            0.0
        }
    }

    pub fn get_avg_proof_size(&self, scheme: &str) -> f64 {
        let attributes = &[KeyValue::new("scheme", scheme.to_string())];
        self.proof_size.get_value(attributes)
    }

    pub fn get_avg_proof_gen_time(&self, scheme: &str) -> Duration {
        let attributes = &[KeyValue::new("scheme", scheme.to_string())];
        Duration::from_secs_f64(self.proof_gen_time.get_value(attributes))
    }

    pub fn get_avg_proof_verify_time(&self, scheme: &str) -> Duration {
        let attributes = &[KeyValue::new("scheme", scheme.to_string())];
        Duration::from_secs_f64(self.proof_verify_time.get_value(attributes))
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
#[derive(Debug)]
pub struct MetricsData {
    pub memory_usage: usize,
    pub operation_latencies: Vec<(KapraOpCode, Duration)>,
}

// Public API to collect metrics
pub fn collect_metrics(file: &PathBuf, otel_endpoint: Option<String>, log_path: Option<PathBuf>, trace_enabled: bool) -> Result<(), KslError> {
    let config = MetricsConfig {
        otel_endpoint,
        log_path,
        trace_enabled,
    };
    let collector = MetricsCollector::new(config)?;
    collector.start_collection();
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResult {
    pub processed_txs: u64,
    pub failed_txs: u64,
    pub gas_used: u64,
    pub block_time: Duration,
    pub validator_count: u32,
    pub kaprekar_ratio: f64,
    pub zk_proof_scheme: Option<String>,
    pub zk_proof_size: Option<usize>,
    pub zk_proof_valid: Option<bool>,
    pub zk_proof_gen_time: Option<Duration>,
    pub zk_proof_verify_time: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    pub name: String,
    pub value: f64,
    pub timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AsyncMetrics {
    pub operation_count: u64,
    pub async_duration: Duration,
    pub avg_async_duration: Duration,
    pub max_concurrency: u32,
}

pub fn log_metrics(tps: usize, duration: Duration, result: &BlockResult) {
    // Console output
    println!(
        "[METRIC] TPS: {:>5}, Duration: {:?}, Processed: {}, Failed: {}, Gas: {}, Validators: {}, Kaprekar Pass: {:.2}%",
        tps,
        duration,
        result.processed_txs,
        result.failed_txs,
        result.gas_used,
        result.validator_count,
        result.kaprekar_ratio * 100.0
    );

    // Export to CSV
    export_metrics_to_csv(tps, duration, result);
}

pub fn export_metrics_to_csv(tps: usize, duration: Duration, result: &BlockResult) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let csv_path = PathBuf::from("benchmark_results.csv");
    let file_exists = csv_path.exists();

    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(csv_path)
        .expect("Failed to open CSV file");

    // Write header if file is new
    if !file_exists {
        writeln!(
            file,
            "Timestamp,TPS,Duration (ms),Processed TXs,Failed TXs,Gas Used,Validator Count,Kaprekar Pass Ratio"
        ).expect("Failed to write CSV header");
    }

    // Write metrics
    writeln!(
        file,
        "{},{},{},{},{},{},{},{}",
        timestamp,
        tps,
        duration.as_millis(),
        result.processed_txs,
        result.failed_txs,
        result.gas_used,
        result.validator_count,
        result.kaprekar_ratio * 100.0
    ).expect("Failed to write metrics to CSV");
}

pub fn export_metrics_to_json(results: &[BlockResult]) -> String {
    serde_json::to_string_pretty(results).unwrap_or_else(|_| "[]".to_string())
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

    #[test]
    fn test_metrics_logging() {
        let result = BlockResult {
            processed_txs: 1000,
            failed_txs: 50,
            gas_used: 50000,
            block_time: Duration::from_millis(100),
            validator_count: 10,
            kaprekar_ratio: 0.95,
            zk_proof_scheme: Some("BLS".to_string()),
            zk_proof_size: Some(96),
            zk_proof_valid: Some(true),
            zk_proof_gen_time: Some(Duration::from_millis(100)),
            zk_proof_verify_time: Some(Duration::from_millis(50)),
        };

        log_metrics(10000, Duration::from_millis(100), &result);

        // Verify CSV file was created
        assert!(PathBuf::from("benchmark_results.csv").exists());

        // Clean up
        fs::remove_file("benchmark_results.csv").ok();
    }

    #[test]
    fn test_metrics_collector() {
        let mut collector = MetricsCollector::new(MetricsConfig {
            otel_endpoint: None,
            log_path: None,
            trace_enabled: false,
        }).unwrap();
        collector.start_collection();

        // Add some test metrics
        collector.metrics.push(MetricValue {
            name: "test_metric".to_string(),
            value: 42.0,
            timestamp: Local::now().timestamp(),
        });

        let metrics = collector.stop_collection();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].name, "test_metric");
        assert_eq!(metrics[0].value, 42.0);
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let collector = MetricsCollector::new(MetricsConfig {
            otel_endpoint: None,
            log_path: None,
            trace_enabled: false,
        }).unwrap();

        let result = BlockResult {
            processed_txs: 100,
            failed_txs: 5,
            gas_used: 1000000,
            block_time: Duration::from_secs(1),
            validator_count: 4,
            kaprekar_ratio: 0.95,
            zk_proof_scheme: Some("BLS".to_string()),
            zk_proof_size: Some(96),
            zk_proof_valid: Some(true),
            zk_proof_gen_time: Some(Duration::from_millis(100)),
            zk_proof_verify_time: Some(Duration::from_millis(50)),
        };

        collector.log_metrics(&result);

        // Test metrics retrieval
        assert_eq!(collector.get_proof_success_rate("BLS"), 1.0);
        assert_eq!(collector.get_avg_proof_size("BLS"), 96.0);
        assert_eq!(collector.get_avg_proof_gen_time("BLS").as_millis(), 100);
        assert_eq!(collector.get_avg_proof_verify_time("BLS").as_millis(), 50);

        // Test CSV export
        collector.export_metrics_to_csv("test_metrics.csv").await.unwrap();
        assert!(std::path::Path::new("test_metrics.csv").exists());
    }

    #[test]
    fn test_block_result_serialization() {
        let result = BlockResult {
            processed_txs: 100,
            failed_txs: 5,
            gas_used: 1000000,
            block_time: Duration::from_secs(1),
            validator_count: 4,
            kaprekar_ratio: 0.95,
            zk_proof_scheme: Some("Dilithium".to_string()),
            zk_proof_size: Some(2420),
            zk_proof_valid: Some(true),
            zk_proof_gen_time: Some(Duration::from_millis(200)),
            zk_proof_verify_time: Some(Duration::from_millis(100)),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: BlockResult = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.zk_proof_scheme, Some("Dilithium".to_string()));
        assert_eq!(deserialized.zk_proof_size, Some(2420));
        assert_eq!(deserialized.zk_proof_valid, Some(true));
    }
}
