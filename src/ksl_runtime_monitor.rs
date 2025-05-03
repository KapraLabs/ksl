// ksl_runtime_monitor.rs
// Runtime monitoring for KSL programs to track behavior and enforce policies

use std::collections::HashMap;

/// Represents KSL bytecode (aligned with ksl_bytecode.rs).
#[derive(Debug, Clone)]
pub struct Bytecode {
    instructions: Vec<u8>, // Simplified representation of bytecode instructions
    constants: Vec<Constant>, // Constants pool
}

impl Bytecode {
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
    String(String),
    U64(u64),
}

/// Metrics collected during runtime (extends ksl_metrics.rs).
#[derive(Debug, Clone)]
pub struct RuntimeMetrics {
    stack_size: usize, // Current stack size in bytes
    instruction_count: u64, // Number of instructions executed
    execution_time: u64, // Simulated execution time (in arbitrary units)
}

impl RuntimeMetrics {
    pub fn new() -> Self {
        RuntimeMetrics {
            stack_size: 0,
            instruction_count: 0,
            execution_time: 0,
        }
    }

    pub fn record_stack_change(&mut self, delta: i32) {
        self.stack_size = (self.stack_size as i32 + delta) as usize;
    }

    pub fn record_instruction(&mut self) {
        self.instruction_count += 1;
        self.execution_time += 1; // Simulate time increment
    }
}

/// Runtime policies to enforce.
#[derive(Debug, Clone)]
pub struct RuntimePolicies {
    max_stack_size: usize, // Maximum stack size in bytes
    max_instruction_count: u64, // Maximum number of instructions
    max_execution_time: u64, // Maximum execution time (in arbitrary units)
}

impl RuntimePolicies {
    pub fn new() -> Self {
        RuntimePolicies {
            max_stack_size: 1_048_576, // 1 MB
            max_instruction_count: 1_000_000, // 1 million instructions
            max_execution_time: 10_000, // Arbitrary units (simulating 10 seconds)
        }
    }

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
                "Execution time limit exceeded: {} (max: {})",
                metrics.execution_time, self.max_execution_time
            ));
        }
        None
    }
}

/// Anomaly detector (aligned with ksl_security.rs).
#[derive(Debug, Clone)]
pub struct AnomalyDetector {
    // Placeholder for anomaly detection configuration
}

impl AnomalyDetector {
    pub fn new() -> Self {
        AnomalyDetector {}
    }

    pub fn detect(&self, metrics: &RuntimeMetrics, package_name: &str) -> Vec<String> {
        let mut anomalies = vec![];
        // Simplified anomaly detection
        if package_name.contains("blockchain") && metrics.instruction_count > 500_000 {
            anomalies.push("Potential anomaly: High instruction count in blockchain contract execution".to_string());
        }
        if package_name.contains("ai") && metrics.stack_size > 500_000 {
            anomalies.push("Potential anomaly: Excessive stack usage in AI inference".to_string());
        }
        if package_name.contains("game") && metrics.execution_time > 5_000 {
            anomalies.push("Potential anomaly: Long execution time in game server loop".to_string());
        }
        anomalies
    }
}

/// Represents the Kapra VM with monitoring hooks (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>, // Simplified stack
    metrics: RuntimeMetrics, // Metrics being monitored
    policies: RuntimePolicies, // Policies to enforce
}

impl KapraVM {
    pub fn new() -> Self {
        KapraVM {
            stack: vec![],
            metrics: RuntimeMetrics::new(),
            policies: RuntimePolicies::new(),
        }
    }

    pub fn execute(&mut self, bytecode: &Bytecode, monitor: &mut RuntimeMonitor) -> Result<(), String> {
        for &instr in bytecode.instructions.iter() {
            // Update metrics
            self.metrics.record_instruction();
            monitor.record_metrics(&self.metrics);

            // Check policies
            if let Some(violation) = self.policies.check(&self.metrics) {
                return Err(format!("Policy violation: {}", violation));
            }

            // Execute the instruction
            match instr {
                OPCODE_PUSH => {
                    self.stack.push(42); // Dummy value
                    self.metrics.record_stack_change(8); // 8 bytes per u64
                }
                OPCODE_POP => {
                    if self.stack.pop().is_none() {
                        return Err("Stack underflow".to_string());
                    }
                    self.metrics.record_stack_change(-8);
                }
                OPCODE_ADD => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for ADD".to_string());
                    }
                    let a = self.stack.pop().unwrap();
                    let b = self.stack.pop().unwrap();
                    self.stack.push(a + b);
                    self.metrics.record_stack_change(-8); // Popped 2, pushed 1
                }
                _ => {} // Other opcodes
            }
        }
        Ok(())
    }
}

/// Runtime monitor for KSL programs.
pub struct RuntimeMonitor {
    metrics: RuntimeMetrics,
    policies: RuntimePolicies,
    anomaly_detector: AnomalyDetector,
    package_name: String, // Simplified package name for anomaly detection
    anomalies: Vec<String>,
}

impl RuntimeMonitor {
    pub fn new(package_name: &str) -> Self {
        RuntimeMonitor {
            metrics: RuntimeMetrics::new(),
            policies: RuntimePolicies::new(),
            anomaly_detector: AnomalyDetector::new(),
            package_name: package_name.to_string(),
            anomalies: vec![],
        }
    }

    pub fn record_metrics(&mut self, metrics: &RuntimeMetrics) {
        self.metrics = metrics.clone();
        let new_anomalies = self.anomaly_detector.detect(&self.metrics, &self.package_name);
        self.anomalies.extend(new_anomalies);
    }

    pub fn run(&mut self, bytecode: Bytecode) -> Result<String, String> {
        let mut vm = KapraVM::new();
        vm.execute(&bytecode, self)?;

        // Generate report
        let mut report = String::new();
        report.push_str("Runtime Monitoring Report\n");
        report.push_str("========================\n");
        report.push_str(&format!("Stack Size: {} bytes\n", self.metrics.stack_size));
        report.push_str(&format!("Instruction Count: {}\n", self.metrics.instruction_count));
        report.push_str(&format!("Execution Time: {} units\n", self.metrics.execution_time));

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

/// CLI integration for `ksl runtime-monitor <file>` (used by ksl_cli.rs).
pub fn run_runtime_monitor(file: &str) -> Result<String, String> {
    // Determine package name based on file (simplified)
    let package_name = match file {
        f if f.contains("blockchain") => "blockchain-project",
        f if f.contains("ai") => "ai-project",
        f if f.contains("game") => "game-project",
        _ => return Err(format!("Unknown project type for file: {}", file)),
    };

    // Create a bytecode based on the file (simplified for testing)
    let mut instructions = vec![];
    let loop_iterations = match package_name {
        "blockchain-project" => 600_000, // High instruction count
        "ai-project" => 50_000,         // High stack usage
        "game-project" => 100_000,      // Long execution time
        _ => 1_000,
    };

    // Simulate a loop: push, push, add, pop
    for _ in 0..loop_iterations {
        instructions.push(OPCODE_PUSH); // Push value
        instructions.push(OPCODE_PUSH); // Push another value
        instructions.push(OPCODE_ADD);  // Add them
        instructions.push(OPCODE_POP);  // Pop result
    }

    let bytecode = Bytecode::new(instructions, vec![]);

    // Run the monitor
    let mut monitor = RuntimeMonitor::new(package_name);
    monitor.run(bytecode)
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
        assert!(report.contains("Execution Time: 3 units"));
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
        assert!(report.contains("High instruction count in blockchain contract execution"));
    }

    #[test]
    fn test_anomaly_detection_ai() {
        let result = run_runtime_monitor("ai.ksl");
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("Excessive stack usage in AI inference"));
    }

    #[test]
    fn test_anomaly_detection_game() {
        let result = run_runtime_monitor("game.ksl");
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("Long execution time in game server loop"));
    }

    #[test]
    fn test_invalid_file() {
        let result = run_runtime_monitor("invalid.ksl");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown project type"));
    }
}