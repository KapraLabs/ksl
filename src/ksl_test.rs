// ksl_test.rs
// Implements a testing framework for KSL programs.
// 
// The test framework provides:
// - Support for synchronous and asynchronous test cases
// - Networking test capabilities (HTTP, TCP, etc.)
// - Test result metrics including networking statistics
// - Integration with the new program's testing framework
// 
// Usage:
//   run_tests(file) -> Runs all tests in the specified file
//   Test functions should be named with "test_" prefix
//   Async tests should be marked with "async" keyword
//   Networking tests can use http.get, http.post, etc.
// 
// Example:
//   async fn test_http_get() {
//     let response = http.get("http://example.com");
//     assert(response.status == 200);
//   }

use crate::ksl_parser::parse;
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::KapraBytecode;
use crate::kapra_vm::run;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs;
use std::time::Duration;

// Test result type
#[derive(Debug, PartialEq)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub error: Option<String>,
    pub duration: Duration,
    pub network_metrics: Option<NetworkMetrics>,
    pub async_metrics: Option<AsyncMetrics>,
}

// Network metrics for test results
#[derive(Debug, PartialEq)]
pub struct NetworkMetrics {
    pub requests: u32,
    pub responses: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub avg_latency: Duration,
    pub errors: u32,
}

// Async metrics for test results
#[derive(Debug, PartialEq)]
pub struct AsyncMetrics {
    pub tasks_created: u32,
    pub tasks_completed: u32,
    pub max_concurrent_tasks: u32,
    pub avg_task_duration: Duration,
}

// Test runner state
pub struct TestRunner {
    results: Vec<TestResult>,
    network_state: Option<NetworkState>,
    async_state: Option<AsyncState>,
}

// Network state for test runner
#[derive(Debug)]
struct NetworkState {
    requests: u32,
    responses: u32,
    bytes_sent: u64,
    bytes_received: u64,
    latencies: Vec<Duration>,
    errors: u32,
}

// Async state for test runner
#[derive(Debug)]
struct AsyncState {
    tasks_created: u32,
    tasks_completed: u32,
    current_tasks: u32,
    max_concurrent_tasks: u32,
    task_durations: Vec<Duration>,
}

impl TestRunner {
    pub fn new() -> Self {
        TestRunner {
            results: Vec::new(),
            network_state: Some(NetworkState {
                requests: 0,
                responses: 0,
                bytes_sent: 0,
                bytes_received: 0,
                latencies: Vec::new(),
                errors: 0,
            }),
            async_state: Some(AsyncState {
                tasks_created: 0,
                tasks_completed: 0,
                current_tasks: 0,
                max_concurrent_tasks: 0,
                task_durations: Vec::new(),
            }),
        }
    }

    // Run tests in a KSL file
    pub fn run_tests(&mut self, file: &std::path::PathBuf) -> Result<(), String> {
        // Read source file
        let source = fs::read_to_string(file)
            .map_err(|e| format!("Failed to read file {}: {}", file.display(), e))?;

        // Parse
        let ast = parse(&source)
            .map_err(|e| format!("Parse error at position {}: {}", e.position, e.message))?;

        // Type-check
        check(&ast)
            .map_err(|errors| {
                errors
                    .into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;

        // Compile
        let bytecode = compile(&ast)
            .map_err(|errors| {
                errors
                    .into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;

        // Find test functions
        let test_functions: Vec<(String, bool)> = ast.iter()
            .filter_map(|node| {
                if let crate::ksl_parser::AstNode::FnDecl { name, is_async, .. } = node {
                    if name.starts_with("test_") {
                        Some((name.clone(), *is_async))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Run each test function
        for (test_name, is_async) in test_functions {
            let start_time = std::time::Instant::now();
            let result = self.run_test(&bytecode, &test_name, is_async);
            let duration = start_time.elapsed();
            
            let mut result = result;
            result.duration = duration;
            
            // Add network metrics if available
            if let Some(net_state) = &self.network_state {
                if net_state.requests > 0 {
                    result.network_metrics = Some(NetworkMetrics {
                        requests: net_state.requests,
                        responses: net_state.responses,
                        bytes_sent: net_state.bytes_sent,
                        bytes_received: net_state.bytes_received,
                        avg_latency: if !net_state.latencies.is_empty() {
                            net_state.latencies.iter().sum::<Duration>() / net_state.latencies.len() as u32
                        } else {
                            Duration::from_secs(0)
                        },
                        errors: net_state.errors,
                    });
                }
            }

            // Add async metrics if available
            if let Some(async_state) = &self.async_state {
                if async_state.tasks_created > 0 {
                    result.async_metrics = Some(AsyncMetrics {
                        tasks_created: async_state.tasks_created,
                        tasks_completed: async_state.tasks_completed,
                        max_concurrent_tasks: async_state.max_concurrent_tasks,
                        avg_task_duration: if !async_state.task_durations.is_empty() {
                            async_state.task_durations.iter().sum::<Duration>() / async_state.task_durations.len() as u32
                        } else {
                            Duration::from_secs(0)
                        },
                    });
                }
            }

            self.results.push(result);
            
            // Reset state for next test
            if let Some(net_state) = &mut self.network_state {
                net_state.requests = 0;
                net_state.responses = 0;
                net_state.bytes_sent = 0;
                net_state.bytes_received = 0;
                net_state.latencies.clear();
                net_state.errors = 0;
            }
            if let Some(async_state) = &mut self.async_state {
                async_state.tasks_created = 0;
                async_state.tasks_completed = 0;
                async_state.current_tasks = 0;
                async_state.max_concurrent_tasks = 0;
                async_state.task_durations.clear();
            }
        }

        // Report results
        let passed = self.results.iter().filter(|r| r.passed).count();
        let total = self.results.len();
        println!("Test results: {} passed, {} failed", passed, total - passed);
        for result in &self.results {
            if result.passed {
                println!("✓ {}: Passed ({}ms)", result.name, result.duration.as_millis());
                if let Some(net_metrics) = &result.network_metrics {
                    println!("  Network: {} requests, {} errors, avg latency {}ms",
                        net_metrics.requests,
                        net_metrics.errors,
                        net_metrics.avg_latency.as_millis());
                }
                if let Some(async_metrics) = &result.async_metrics {
                    println!("  Async: {} tasks, max concurrent {}, avg duration {}ms",
                        async_metrics.tasks_created,
                        async_metrics.max_concurrent_tasks,
                        async_metrics.avg_task_duration.as_millis());
                }
            } else {
                println!("✗ {}: Failed - {}", result.name, result.error.as_ref().unwrap_or(&"Unknown error".to_string()));
            }
        }

        if passed == total {
            Ok(())
        } else {
            Err(format!("{} test(s) failed", total - passed))
        }
    }

    // Run a single test function
    fn run_test(&self, bytecode: &KapraBytecode, test_name: &str, is_async: bool) -> TestResult {
        // Create a modified bytecode that calls the test function
        let mut test_bytecode = KapraBytecode::new();
        
        // Find function index
        let fn_index = bytecode.instructions.iter()
            .position(|instr| instr.opcode == KapraOpCode::Call && matches!(&instr.operands[0], Operand::Immediate(data) if String::from_utf8(data.clone()).unwrap_or_default().contains(test_name)))
            .unwrap_or(0) as u32;

        // Add call to test function
        test_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Call,
            vec![Operand::Immediate(fn_index.to_le_bytes().to_vec())],
            None,
        ));

        // For async tests, add await instruction
        if is_async {
            test_bytecode.add_instruction(KapraInstruction::new(
                KapraOpCode::Await,
                vec![],
                None,
            ));
        }

        test_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        // Run the test
        match run(test_bytecode) {
            Ok(()) => TestResult {
                name: test_name.to_string(),
                passed: true,
                error: None,
                duration: Duration::from_secs(0),
                network_metrics: None,
                async_metrics: None,
            },
            Err(e) => TestResult {
                name: test_name.to_string(),
                passed: false,
                error: Some(format!("Runtime error at instruction {}: {}", e.pc, e.message)),
                duration: Duration::from_secs(0),
                network_metrics: None,
                async_metrics: None,
            },
        }
    }
}

// Public API to run tests
pub fn run_tests(file: &std::path::PathBuf) -> Result<(), String> {
    let mut runner = TestRunner::new();
    runner.run_tests(file)
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, and ksl_errors.rs are in the same crate
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
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
}

mod kapra_vm {
    pub use super::run;
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
    fn test_run_passing_test() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test_add() { let x: u32 = 42; assert(x == 42); }"
        ).unwrap();

        let result = run_tests(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_failing_test() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test_add() { let x: u32 = 42; assert(x == 43); }"
        ).unwrap();

        let result = run_tests(&temp_file.path().to_path_buf());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("test(s) failed"));
    }

    #[test]
    fn test_run_multiple_tests() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test_one() { let x: u32 = 1; assert(x == 1); }\n\
             fn test_two() { let y: u32 = 2; assert(y == 3); }"
        ).unwrap();

        let result = run_tests(&temp_file.path().to_path_buf());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("1 test(s) failed"));
    }

    #[test]
    fn test_async_test() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "async fn test_async() { let x: u32 = 42; await sleep(100); assert(x == 42); }"
        ).unwrap();

        let result = run_tests(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
    }

    #[test]
    fn test_network_test() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test_http() { let response = http.get(\"http://example.com\"); assert(response.status == 200); }"
        ).unwrap();

        let result = run_tests(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
    }

    #[test]
    fn test_async_network_test() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "async fn test_async_http() { let response = await http.get(\"http://example.com\"); assert(response.status == 200); }"
        ).unwrap();

        let result = run_tests(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
    }

    #[test]
    fn test_network_metrics() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test_http_metrics() { 
                let response1 = http.get(\"http://example.com\");
                let response2 = http.get(\"http://example.com\");
                assert(response1.status == 200);
                assert(response2.status == 200);
            }"
        ).unwrap();

        let mut runner = TestRunner::new();
        let result = runner.run_tests(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
        
        let test_result = runner.results.first().unwrap();
        assert!(test_result.passed);
        assert!(test_result.network_metrics.is_some());
        let metrics = test_result.network_metrics.as_ref().unwrap();
        assert_eq!(metrics.requests, 2);
        assert_eq!(metrics.responses, 2);
        assert!(metrics.bytes_received > 0);
    }

    #[test]
    fn test_async_metrics() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "async fn test_async_metrics() { 
                let task1 = async { sleep(100); };
                let task2 = async { sleep(100); };
                await task1;
                await task2;
            }"
        ).unwrap();

        let mut runner = TestRunner::new();
        let result = runner.run_tests(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
        
        let test_result = runner.results.first().unwrap();
        assert!(test_result.passed);
        assert!(test_result.async_metrics.is_some());
        let metrics = test_result.async_metrics.as_ref().unwrap();
        assert_eq!(metrics.tasks_created, 2);
        assert_eq!(metrics.tasks_completed, 2);
        assert!(metrics.avg_task_duration > Duration::from_millis(0));
    }
}