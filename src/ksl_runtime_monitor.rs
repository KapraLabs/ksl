// ksl_runtime_monitor.rs
// Runtime monitoring for KSL programs to track behavior and enforce policies

use crate::ksl_metrics::{MetricsCollector, PerformanceMetrics, MemoryMetrics, CacheMetrics};
use crate::kapra_vm::{KapraVM, VmState, VmError};
use crate::ksl_async::{AsyncContext, AsyncCommand};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Represents KSL bytecode (aligned with ksl_bytecode.rs).
#[derive(Debug, Clone)]
pub struct Bytecode {
    /// Bytecode instructions
    instructions: Vec<u8>,
    /// Constants pool
    constants: Vec<Constant>,
}

impl Bytecode {
    /// Creates new bytecode with instructions and constants.
    pub fn new(instructions: Vec<u8>, constants: Vec<Constant>) -> Self {
        Bytecode {
            instructions,
            constants,
        }
    }
}

/// Represents a constant in the bytecode.
#[derive(Debug, Clone)]
pub enum Constant {
    /// String constant
    String(String),
    /// 64-bit unsigned integer constant
    U64(u64),
}

/// Metrics collected during runtime (extends ksl_metrics.rs).
#[derive(Debug, Clone)]
pub struct RuntimeMetrics {
    /// Performance metrics from ksl_metrics.rs
    performance: PerformanceMetrics,
    /// Memory metrics from ksl_metrics.rs
    memory: MemoryMetrics,
    /// Cache metrics from ksl_metrics.rs
    cache: CacheMetrics,
    /// Current stack size in bytes
    stack_size: usize,
    /// Number of instructions executed
    instruction_count: u64,
    /// Execution time in nanoseconds
    execution_time: u64,
}

impl RuntimeMetrics {
    /// Creates new runtime metrics with default values.
    pub fn new() -> Self {
        RuntimeMetrics {
            performance: PerformanceMetrics::new(),
            memory: MemoryMetrics::new(),
            cache: CacheMetrics::new(),
            stack_size: 0,
            instruction_count: 0,
            execution_time: 0,
        }
    }

    /// Records a change in stack size.
    pub fn record_stack_change(&mut self, delta: i32) {
        self.stack_size = (self.stack_size as i32 + delta) as usize;
        self.memory.update_peak_memory(self.stack_size as u64);
    }

    /// Records an instruction execution.
    pub fn record_instruction(&mut self) {
        self.instruction_count += 1;
        self.performance.increment_instruction_count();
    }

    /// Records execution time.
    pub fn record_execution_time(&mut self, time_ns: u64) {
        self.execution_time = time_ns;
        self.performance.update_execution_time(time_ns);
    }

    /// Records cache statistics.
    pub fn record_cache_stats(&mut self, hits: u64, misses: u64) {
        self.cache.update_stats(hits, misses);
    }
}

/// Runtime policies to enforce.
#[derive(Debug, Clone)]
pub struct RuntimePolicies {
    /// Maximum stack size in bytes
    max_stack_size: usize,
    /// Maximum number of instructions
    max_instruction_count: u64,
    /// Maximum execution time in nanoseconds
    max_execution_time: u64,
    /// Maximum memory usage in bytes
    max_memory_usage: u64,
    /// Minimum cache hit ratio
    min_cache_hit_ratio: f64,
}

impl RuntimePolicies {
    /// Creates new runtime policies with default values.
    pub fn new() -> Self {
        RuntimePolicies {
            max_stack_size: 1_048_576, // 1 MB
            max_instruction_count: 1_000_000, // 1 million instructions
            max_execution_time: 10_000_000_000, // 10 seconds in nanoseconds
            max_memory_usage: 100_000_000, // 100 MB
            min_cache_hit_ratio: 0.8, // 80% cache hit ratio
        }
    }

    /// Checks if metrics violate any policies.
    pub fn check(&self, metrics: &RuntimeMetrics) -> Option<String> {
        if metrics.stack_size > self.max_stack_size {
            return Some(format!(
                "Stack size limit exceeded: {} bytes (max: {} bytes)",
                metrics.stack_size, self.max_stack_size
            ));
        }
        if metrics.instruction_count > self.max_instruction_count {
            return Some(format!(
                "Instruction count limit exceeded: {} (max: {})",
                metrics.instruction_count, self.max_instruction_count
            ));
        }
        if metrics.execution_time > self.max_execution_time {
            return Some(format!(
                "Execution time limit exceeded: {} ns (max: {} ns)",
                metrics.execution_time, self.max_execution_time
            ));
        }
        if metrics.memory.peak_memory > self.max_memory_usage {
            return Some(format!(
                "Memory usage limit exceeded: {} bytes (max: {} bytes)",
                metrics.memory.peak_memory, self.max_memory_usage
            ));
        }
        if metrics.cache.hit_ratio() < self.min_cache_hit_ratio {
            return Some(format!(
                "Cache hit ratio below minimum: {:.2} (min: {:.2})",
                metrics.cache.hit_ratio(), self.min_cache_hit_ratio
            ));
        }
        None
    }
}

/// Anomaly detector for runtime behavior.
#[derive(Debug, Clone)]
pub struct AnomalyDetector {
    /// Metrics collector for anomaly detection
    metrics_collector: MetricsCollector,
    /// Async context for anomaly detection
    async_context: Arc<Mutex<AsyncContext>>,
}

impl AnomalyDetector {
    /// Creates a new anomaly detector.
    pub fn new() -> Self {
        AnomalyDetector {
            metrics_collector: MetricsCollector::new(),
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
        }
    }

    /// Detects anomalies in runtime behavior.
    pub async fn detect(&self, metrics: &RuntimeMetrics, package_name: &str) -> Vec<String> {
        let mut anomalies = vec![];

        // Check for async anomalies
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::CheckAnomalies(metrics.clone());
        if let Err(e) = async_ctx.execute_command(command).await {
            anomalies.push(format!("Async anomaly detection failed: {}", e));
        }

        // Check for performance anomalies
        if package_name.contains("blockchain") && metrics.performance.avg_execution_time > 500_000 {
            anomalies.push("Potential anomaly: High execution time in blockchain contract".to_string());
        }
        if package_name.contains("ai") && metrics.memory.peak_memory > 500_000_000 {
            anomalies.push("Potential anomaly: Excessive memory usage in AI inference".to_string());
        }
        if package_name.contains("game") && metrics.cache.hit_ratio() < 0.6 {
            anomalies.push("Potential anomaly: Poor cache performance in game loop".to_string());
        }

        anomalies
    }
}

/// Runtime monitor for KSL programs.
pub struct RuntimeMonitor {
    /// Current runtime metrics
    metrics: RuntimeMetrics,
    /// Runtime policies to enforce
    policies: RuntimePolicies,
    /// Anomaly detector
    anomaly_detector: AnomalyDetector,
    /// Package name for context
    package_name: String,
    /// Detected anomalies
    anomalies: Vec<String>,
    /// Channel for async monitoring
    monitor_tx: mpsc::Sender<RuntimeMetrics>,
}

impl RuntimeMonitor {
    /// Creates a new runtime monitor.
    pub fn new(package_name: &str) -> Self {
        let (monitor_tx, _) = mpsc::channel(100);
        RuntimeMonitor {
            metrics: RuntimeMetrics::new(),
            policies: RuntimePolicies::new(),
            anomaly_detector: AnomalyDetector::new(),
            package_name: package_name.to_string(),
            anomalies: vec![],
            monitor_tx,
        }
    }

    /// Records runtime metrics.
    pub async fn record_metrics(&mut self, metrics: &RuntimeMetrics) {
        self.metrics = metrics.clone();
        let new_anomalies = self.anomaly_detector.detect(&self.metrics, &self.package_name).await;
        self.anomalies.extend(new_anomalies);
        
        // Send metrics through async channel
        if let Err(e) = self.monitor_tx.send(metrics.clone()).await {
            eprintln!("Failed to send metrics: {}", e);
        }
    }

    /// Runs the monitored program.
    pub async fn run(&mut self, bytecode: Bytecode) -> Result<String, KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut vm = KapraVM::new();

        // Execute with monitoring
        vm.execute(&bytecode, self).await?;

        // Generate report
        let mut report = String::new();
        report.push_str("Runtime Monitoring Report\n");
        report.push_str("========================\n");
        report.push_str(&format!("Stack Size: {} bytes\n", self.metrics.stack_size));
        report.push_str(&format!("Instruction Count: {}\n", self.metrics.instruction_count));
        report.push_str(&format!("Execution Time: {} ns\n", self.metrics.execution_time));
        report.push_str(&format!("Memory Usage: {} bytes\n", self.metrics.memory.peak_memory));
        report.push_str(&format!("Cache Hit Ratio: {:.2}\n", self.metrics.cache.hit_ratio()));

        if !self.anomalies.is_empty() {
            report.push_str("\nAnomalies Detected:\n");
            for anomaly in &self.anomalies {
                report.push_str(&format!("- {}\n", anomaly));
            }
        } else {
            report.push_str("\nNo anomalies detected.\n");
        }

        Ok(report)
    }
}

/// CLI integration for runtime monitoring.
pub async fn run_runtime_monitor(file: &str) -> Result<String, KslError> {
    let pos = SourcePosition::new(1, 1);
    
    // Determine package name based on file
    let package_name = match file {
        f if f.contains("blockchain") => "blockchain-project",
        f if f.contains("ai") => "ai-project",
        f if f.contains("game") => "game-project",
        _ => return Err(KslError::type_error(
            format!("Unknown project type for file: {}", file),
            pos,
        )),
    };

    // Create monitor
    let mut monitor = RuntimeMonitor::new(package_name);

    // Create bytecode based on file
    let mut instructions = vec![];
    let loop_iterations = match package_name {
        "blockchain-project" => 600_000,
        "ai-project" => 50_000,
        "game-project" => 100_000,
        _ => 1_000,
    };

    // Simulate bytecode
    for _ in 0..loop_iterations {
        instructions.push(OPCODE_PUSH);
        instructions.push(OPCODE_PUSH);
        instructions.push(OPCODE_ADD);
        instructions.push(OPCODE_POP);
    }

    let bytecode = Bytecode::new(instructions, vec![]);
    monitor.run(bytecode).await
}

// Simplified opcodes
const OPCODE_PUSH: u8 = 0x01;
const OPCODE_POP: u8 = 0x02;
const OPCODE_ADD: u8 = 0x03;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collection() {
        let bytecode = Bytecode::new(vec![OPCODE_PUSH, OPCODE_PUSH, OPCODE_ADD], vec![]);
        let mut monitor = RuntimeMonitor::new("test-project");
        let result = monitor.run(bytecode);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("Stack Size: 8 bytes")); // 1 value left on stack
        assert!(report.contains("Instruction Count: 3"));
        assert!(report.contains("Execution Time: 3 ns"));
    }

    #[test]
    fn test_policy_violation() {
        let mut instructions = vec![];
        for _ in 0..1_000_001 {
            instructions.push(OPCODE_PUSH);
        }
        let bytecode = Bytecode::new(instructions, vec![]);
        let mut monitor = RuntimeMonitor::new("test-project");
        let result = monitor.run(bytecode);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Instruction count limit exceeded"));
    }

    #[test]
    fn test_anomaly_detection_blockchain() {
        let result = run_runtime_monitor("blockchain.ksl");
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("High execution time in blockchain contract"));
    }

    #[test]
    fn test_anomaly_detection_ai() {
        let result = run_runtime_monitor("ai.ksl");
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("Excessive memory usage in AI inference"));
    }

    #[test]
    fn test_anomaly_detection_game() {
        let result = run_runtime_monitor("game.ksl");
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("Poor cache performance in game loop"));
    }

    #[test]
    fn test_invalid_file() {
        let result = run_runtime_monitor("invalid.ksl");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown project type"));
    }
}