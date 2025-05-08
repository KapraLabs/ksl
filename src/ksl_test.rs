// ksl_test.rs
// Implements a testing framework for KSL programs.
// 
// The test framework provides:
// - Support for synchronous and asynchronous test cases
// - Networking test capabilities (HTTP, TCP, etc.)
// - Test result metrics including networking statistics
// - Integration with the new program's testing framework
// - Cross-target testing (LLVM/WASM/VM)
// - Snapshot testing with golden outputs
// - Tag-based test filtering
// - Gas usage benchmarking
// - Parallel test execution
// - Watch mode for development
// 
// Usage:
//   run_tests(file) -> Runs all tests in the specified file
//   Test functions should be named with "test_" prefix
//   Async tests should be marked with "async" keyword
//   Networking tests can use http.get, http.post, etc.
//   Validator tests should use #[test_validator] attribute
//   Tests can be tagged with #[test(category = "shard")]
// 
// Example:
//   #[test_validator]
//   async fn test_http_get() {
//     let response = http.get("http://example.com");
//     assert(response.status == 200);
//   }

use crate::ksl_parser::parse;
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, CompileTarget};
use crate::kapra_vm::run;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_analyzer::{Analyzer, GasStats};
use crate::ksl_validator_keys::{ValidatorKeys, Signature};
use std::fs;
use std::time::{Duration, SystemTime};
use std::path::{Path, PathBuf};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use notify::{Watcher, RecursiveMode, Event};
use futures::future::join_all;
use regex;

// Test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    /// Target compilation mode (VM, WASM, LLVM)
    pub target: CompileTarget,
    /// Test categories to run
    pub categories: Vec<String>,
    /// Whether to run tests in parallel
    pub parallel: bool,
    /// Whether to watch for file changes
    pub watch: bool,
    /// Snapshot directory for golden tests
    pub snapshot_dir: Option<PathBuf>,
    /// Whether to update snapshots
    pub update_snapshots: bool,
    /// Whether to measure gas usage
    pub measure_gas: bool,
    /// Output directory for test results
    pub output_dir: Option<PathBuf>,
}

// Test result type
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub error: Option<String>,
    pub duration: Duration,
    pub network_metrics: Option<NetworkMetrics>,
    pub async_metrics: Option<AsyncMetrics>,
    pub gas_metrics: Option<GasMetrics>,
    pub target: CompileTarget,
    pub category: Option<String>,
    pub snapshot_diff: Option<SnapshotDiff>,
}

// Network metrics for test results
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub requests: u32,
    pub responses: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub avg_latency: Duration,
    pub errors: u32,
}

// Async metrics for test results
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AsyncMetrics {
    pub tasks_created: u32,
    pub tasks_completed: u32,
    pub max_concurrent_tasks: u32,
    pub avg_task_duration: Duration,
}

// Gas metrics for test results
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct GasMetrics {
    pub total_gas: u64,
    pub max_gas: u64,
    pub avg_gas: u64,
    pub gas_by_operation: HashMap<String, u64>,
}

// Snapshot diff for test results
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotDiff {
    pub expected: String,
    pub actual: String,
    pub diff: String,
}

// Test group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestGroup {
    pub name: String,
    pub description: Option<String>,
    pub dependencies: Vec<String>,
    pub timeout: Option<Duration>,
}

// Test summary for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSummary {
    pub timestamp: SystemTime,
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub skipped_tests: usize,
    pub duration: Duration,
    pub test_results: Vec<TestResult>,
    pub test_groups: HashMap<String, TestGroup>,
    pub resource_metrics: Option<ResourceMetrics>,
}

// Test runner state
pub struct TestRunner {
    config: TestConfig,
    results: Vec<TestResult>,
    network_state: Option<NetworkState>,
    async_state: Option<AsyncState>,
    analyzer: Option<Arc<Analyzer>>,
    validator_keys: Option<Arc<ValidatorKeys>>,
    watcher: Option<notify::FsEventWatcher>,
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
    pub fn new(config: TestConfig) -> Self {
        let analyzer = if config.measure_gas {
            Some(Arc::new(Analyzer::new()))
        } else {
            None
        };

        let validator_keys = if config.categories.contains(&"validator".to_string()) {
            Some(Arc::new(ValidatorKeys::new()))
        } else {
            None
        };

        TestRunner {
            config,
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
            analyzer,
            validator_keys,
            watcher: None,
        }
    }

    // Run tests in a KSL file
    pub async fn run_tests(&mut self, file: &PathBuf) -> Result<(), String> {
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

        // Find test functions
        let test_functions: Vec<(String, bool, Option<String>, bool)> = ast.iter()
            .filter_map(|node| {
                if let crate::ksl_parser::AstNode::FnDecl { name, is_async, attrs, .. } = node {
                    if name.starts_with("test_") {
                        let category = attrs.iter()
                            .find_map(|attr| {
                                if let crate::ksl_parser::Attr::Test { category } = attr {
                                    Some(category.clone())
                                } else {
                                    None
                                }
                            });
                        let is_validator = attrs.iter()
                            .any(|attr| matches!(attr, crate::ksl_parser::Attr::TestValidator));
                        Some((name.clone(), *is_async, category, is_validator))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Filter tests by category
        let test_functions: Vec<_> = test_functions.into_iter()
            .filter(|(_, _, category, _)| {
                category.as_ref().map_or(true, |cat| self.config.categories.contains(cat))
            })
            .collect();

        // Run tests
        if self.config.parallel {
            self.run_tests_parallel(&ast, &test_functions).await?;
        } else {
            self.run_tests_sequential(&ast, &test_functions).await?;
        }

        // Start watcher if enabled
        if self.config.watch {
            self.start_watcher(file)?;
        }

        // Report results
        self.report_results()?;

        Ok(())
    }

    // Run tests in parallel
    async fn run_tests_parallel(
        &mut self,
        ast: &[crate::ksl_parser::AstNode],
        test_functions: &[(String, bool, Option<String>, bool)],
    ) -> Result<(), String> {
        let mut futures = Vec::new();
        for (test_name, is_async, category, is_validator) in test_functions {
            let ast = ast.to_vec();
            let test_name = test_name.clone();
            let category = category.clone();
            let future = self.run_test_async(&ast, &test_name, *is_async, category, *is_validator);
            futures.push(future);
        }
        let results = join_all(futures).await;
        self.results.extend(results.into_iter().flatten());
        Ok(())
    }

    // Run tests sequentially
    async fn run_tests_sequential(
        &mut self,
        ast: &[crate::ksl_parser::AstNode],
        test_functions: &[(String, bool, Option<String>, bool)],
    ) -> Result<(), String> {
        for (test_name, is_async, category, is_validator) in test_functions {
            let results = self.run_test_async(ast, test_name, *is_async, category.clone(), *is_validator).await?;
            self.results.extend(results);
        }
        Ok(())
    }

    // Run a single test asynchronously
    async fn run_test_async(
        &self,
        ast: &[crate::ksl_parser::AstNode],
        test_name: &str,
        is_async: bool,
        category: Option<String>,
        is_validator: bool,
    ) -> Result<Vec<TestResult>, String> {
        let mut results = Vec::new();
            let start_time = std::time::Instant::now();

        // Run test for each target
        for target in &[CompileTarget::VM, CompileTarget::WASM, CompileTarget::LLVM] {
            if *target == self.config.target {
                // Compile for target
                let bytecode = compile(ast)
                    .map_err(|errors| {
                        errors
                            .into_iter()
                            .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                            .collect::<Vec<_>>()
                            .join("\n")
                    })?;

                // Run test
                let result = self.run_test(&bytecode, test_name, is_async, category.clone(), is_validator).await;
            let duration = start_time.elapsed();
            
            let mut result = result;
            result.duration = duration;
                result.target = *target;
            
                // Add metrics
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

                if let Some(analyzer) = &self.analyzer {
                    if let Some(gas_stats) = analyzer.get_gas_stats() {
                        result.gas_metrics = Some(GasMetrics {
                            total_gas: gas_stats.total_gas,
                            max_gas: gas_stats.max_gas,
                            avg_gas: gas_stats.avg_gas,
                            gas_by_operation: gas_stats.gas_by_operation.clone(),
                        });
                    }
                }

                // Check snapshot if enabled
                if let Some(snapshot_dir) = &self.config.snapshot_dir {
                    let snapshot_path = snapshot_dir.join(format!("{}.json", test_name));
                    if snapshot_path.exists() {
                        let expected = fs::read_to_string(&snapshot_path)
                            .map_err(|e| format!("Failed to read snapshot: {}", e))?;
                        let actual = serde_json::to_string_pretty(&result)
                            .map_err(|e| format!("Failed to serialize result: {}", e))?;
                        
                        if expected != actual {
                            if self.config.update_snapshots {
                                fs::write(&snapshot_path, &actual)
                                    .map_err(|e| format!("Failed to update snapshot: {}", e))?;
                            } else {
                                result.snapshot_diff = Some(SnapshotDiff {
                                    expected,
                                    actual,
                                    diff: self.compute_diff(&expected, &actual),
                                });
                                result.passed = false;
                            }
                        }
                    } else if self.config.update_snapshots {
                        fs::write(&snapshot_path, serde_json::to_string_pretty(&result)?)
                            .map_err(|e| format!("Failed to write snapshot: {}", e))?;
                    }
                }

                results.push(result);
            }
        }

        Ok(results)
    }

    // Start file watcher with complete callback
    fn start_watcher(&mut self, file: &PathBuf) -> Result<(), String> {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = notify::watcher(tx, Duration::from_secs(1))
            .map_err(|e| format!("Failed to create watcher: {}", e))?;

        watcher.watch(file, RecursiveMode::NonRecursive)
            .map_err(|e| format!("Failed to watch file: {}", e))?;

        self.watcher = Some(watcher);

        // Clone necessary data for the watcher thread
        let file = file.clone();
        let config = self.config.clone();
        let analyzer = self.analyzer.clone();
        let validator_keys = self.validator_keys.clone();

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new()
                .expect("Failed to create runtime for file watcher");

            for event in rx {
                if let Event::NoticeWrite(_) = event {
                    println!("File changed, rerunning tests...");
                    
                    // Create new test runner
                    let mut runner = TestRunner {
                        config: config.clone(),
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
                        analyzer: analyzer.clone(),
                        validator_keys: validator_keys.clone(),
                        watcher: None,
                    };

                    // Run tests in the async runtime
                    runtime.block_on(async {
                        if let Err(e) = runner.run_tests(&file).await {
                            eprintln!("Error rerunning tests: {}", e);
                        }
                    });
                }
            }
        });

        Ok(())
    }

    // Compute real diff between expected and actual output
    fn compute_diff(&self, expected: &str, actual: &str) -> String {
        let mut diff = String::new();
        
        // Try to parse as JSON first
        if let (Ok(expected_json), Ok(actual_json)) = (
            serde_json::from_str::<serde_json::Value>(expected),
            serde_json::from_str::<serde_json::Value>(actual)
        ) {
            // Use serde_json's pretty printing for JSON diffs
            let expected_pretty = serde_json::to_string_pretty(&expected_json)
                .unwrap_or_else(|_| expected.to_string());
            let actual_pretty = serde_json::to_string_pretty(&actual_json)
                .unwrap_or_else(|_| actual.to_string());
            
            // Use similar crate for JSON diffing
            let changes = similar::TextDiff::from_lines(&expected_pretty, &actual_pretty);
            diff.push_str(&changes.unified_diff().context(3));
        } else {
            // Fall back to text diffing
            let changes = similar::TextDiff::from_lines(expected, actual);
            diff.push_str(&changes.unified_diff().context(3));
        }
        
        diff
    }

    // Generate and save test summary
    fn save_test_summary(&self) -> Result<(), String> {
        let summary = TestSummary {
            timestamp: SystemTime::now(),
            total_tests: self.results.len(),
            passed_tests: self.results.iter().filter(|r| r.passed).count(),
            failed_tests: self.results.iter().filter(|r| !r.passed).count(),
            skipped_tests: 0, // TODO: Implement test skipping
            duration: self.results.iter()
                .map(|r| r.duration)
                .sum(),
            test_results: self.results.clone(),
            test_groups: self.collect_test_groups()?,
            resource_metrics: self.collect_resource_metrics().ok(),
        };

        // Save to JSON file
        let summary_path = self.config.output_dir.as_ref()
            .map(|dir| dir.join("test_report.json"))
            .unwrap_or_else(|| PathBuf::from("test_report.json"));

        let content = serde_json::to_string_pretty(&summary)
            .map_err(|e| format!("Failed to serialize test summary: {}", e))?;

        fs::write(&summary_path, content)
            .map_err(|e| format!("Failed to write test summary: {}", e))?;

        Ok(())
    }

    // Collect test groups from test files
    fn collect_test_groups(&self) -> Result<HashMap<String, TestGroup>, String> {
        let mut groups = HashMap::new();

        // Parse test files for group declarations
        for result in &self.results {
            if let Some(group_info) = self.parse_test_group(&result.name)? {
                groups.insert(group_info.name.clone(), group_info);
            }
        }

        Ok(groups)
    }

    // Parse test group declaration from file
    fn parse_test_group(&self, file_name: &str) -> Result<Option<TestGroup>, String> {
        let source = fs::read_to_string(file_name)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        // Look for test group declaration
        if let Some(caps) = regex::Regex::new(r"\[test_group:\s*\"([^\"]+)\"\]")
            .map_err(|e| format!("Failed to create regex: {}", e))?
            .captures(&source)
        {
            let group_name = caps[1].to_string();
            
            // Parse group metadata
            let description = regex::Regex::new(r"description:\s*\"([^\"]+)\"")
                .ok()
                .and_then(|re| re.captures(&source))
                .map(|caps| caps[1].to_string());

            let dependencies = regex::Regex::new(r"dependencies:\s*\[([^\]]+)\]")
                .ok()
                .and_then(|re| re.captures(&source))
                .map(|caps| caps[1].split(',')
                    .map(|s| s.trim().to_string())
                    .collect())
                .unwrap_or_default();

            let timeout = regex::Regex::new(r"timeout:\s*(\d+)")
                .ok()
                .and_then(|re| re.captures(&source))
                .map(|caps| Duration::from_secs(caps[1].parse().unwrap_or(30)));

            Ok(Some(TestGroup {
                name: group_name,
                description,
                dependencies,
                timeout,
            }))
        } else {
            Ok(None)
        }
    }

    // Report test results with enhanced output
    fn report_results(&self) -> Result<(), String> {
        let passed = self.results.iter().filter(|r| r.passed).count();
        let total = self.results.len();
        println!("Test results: {} passed, {} failed", passed, total - passed);

        // Group results by test group
        let mut group_results: HashMap<String, Vec<&TestResult>> = HashMap::new();
        for result in &self.results {
            if let Some(group) = self.parse_test_group(&result.name).ok().flatten() {
                group_results.entry(group.name)
                    .or_default()
                    .push(result);
            }
        }

        // Print results by group
        for (group_name, results) in group_results {
            println!("\nTest Group: {}", group_name);
            for result in results {
            if result.passed {
                    println!("✓ {} ({:?}): Passed ({}ms)", 
                        result.name, 
                        result.target, 
                        result.duration.as_millis());
                    
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

                    if let Some(gas_metrics) = &result.gas_metrics {
                        println!("  Gas: total {}, max {}, avg {}",
                            gas_metrics.total_gas,
                            gas_metrics.max_gas,
                            gas_metrics.avg_gas);
                    }
            } else {
                    println!("✗ {} ({:?}): Failed - {}", 
                        result.name, 
                        result.target,
                        result.error.as_ref().unwrap_or(&"Unknown error".to_string()));

                    if let Some(diff) = &result.snapshot_diff {
                        println!("  Snapshot diff:\n{}", diff.diff);
                    }
                }
            }
        }

        // Save test summary
        self.save_test_summary()?;

        if passed == total {
            Ok(())
        } else {
            Err(format!("{} test(s) failed", total - passed))
        }
    }
}

// Public API to run tests
pub async fn run_tests(file: &PathBuf, config: TestConfig) -> Result<(), String> {
    let mut runner = TestRunner::new(config);
    runner.run_tests(file).await
}

// Public API to run tests synchronously
pub fn run_tests_sync(file: &PathBuf, config: TestConfig) -> Result<(), String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create runtime: {}", e))?;
    runtime.block_on(run_tests(file, config))
}

// Module imports
mod ksl_parser {
    pub use super::{parse, AstNode, Attr};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_bytecode {
    pub use super::{KapraBytecode, CompileTarget};
}

mod kapra_vm {
    pub use super::run;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

mod ksl_analyzer {
    pub use super::{Analyzer, GasStats};
}

mod ksl_validator_keys {
    pub use super::{ValidatorKeys, Signature};
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

        let config = TestConfig {
            target: CompileTarget::VM,
            categories: vec![],
            parallel: false,
            watch: false,
            snapshot_dir: None,
            update_snapshots: false,
            measure_gas: false,
            output_dir: None,
        };

        let result = run_tests_sync(&temp_file.path().to_path_buf(), config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_failing_test() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test_add() { let x: u32 = 42; assert(x == 43); }"
        ).unwrap();

        let config = TestConfig {
            target: CompileTarget::VM,
            categories: vec![],
            parallel: false,
            watch: false,
            snapshot_dir: None,
            update_snapshots: false,
            measure_gas: false,
            output_dir: None,
        };

        let result = run_tests_sync(&temp_file.path().to_path_buf(), config);
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

        let config = TestConfig {
            target: CompileTarget::VM,
            categories: vec![],
            parallel: false,
            watch: false,
            snapshot_dir: None,
            update_snapshots: false,
            measure_gas: false,
            output_dir: None,
        };

        let result = run_tests_sync(&temp_file.path().to_path_buf(), config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("1 test(s) failed"));
    }

    #[tokio::test]
    async fn test_async_test() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "async fn test_async() { let x: u32 = 42; assert(x == 42); }"
        ).unwrap();

        let config = TestConfig {
            target: CompileTarget::VM,
            categories: vec![],
            parallel: false,
            watch: false,
            snapshot_dir: None,
            update_snapshots: false,
            measure_gas: false,
            output_dir: None,
        };

        let result = run_tests(&temp_file.path().to_path_buf(), config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_validator_test() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[test_validator]\n\
             fn test_validator() { let x: u32 = 42; assert(x == 42); }"
        ).unwrap();

        let config = TestConfig {
            target: CompileTarget::VM,
            categories: vec!["validator".to_string()],
            parallel: false,
            watch: false,
            snapshot_dir: None,
            update_snapshots: false,
            measure_gas: false,
            output_dir: None,
        };

        let result = run_tests_sync(&temp_file.path().to_path_buf(), config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_snapshot_test() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test_snapshot() { let x: u32 = 42; assert(x == 42); }"
        ).unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let config = TestConfig {
            target: CompileTarget::VM,
            categories: vec![],
            parallel: false,
            watch: false,
            snapshot_dir: Some(temp_dir.path().to_path_buf()),
            update_snapshots: true,
            measure_gas: false,
            output_dir: None,
        };

        let result = run_tests_sync(&temp_file.path().to_path_buf(), config);
        assert!(result.is_ok());
        assert!(temp_dir.path().join("test_snapshot.json").exists());
    }

    #[test]
    fn test_gas_benchmark() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test_gas() { let x: u32 = 42; assert(x == 42); }"
        ).unwrap();

        let config = TestConfig {
            target: CompileTarget::VM,
            categories: vec![],
            parallel: false,
            watch: false,
            snapshot_dir: None,
            update_snapshots: false,
            measure_gas: true,
            output_dir: None,
        };

        let result = run_tests_sync(&temp_file.path().to_path_buf(), config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_diff() {
        let runner = TestRunner::new(TestConfig {
            target: CompileTarget::VM,
            categories: vec![],
            parallel: false,
            watch: false,
            snapshot_dir: None,
            update_snapshots: false,
            measure_gas: false,
            output_dir: None,
        });

        let expected = r#"{"name": "test", "value": 42}"#;
        let actual = r#"{"name": "test", "value": 43}"#;
        let diff = runner.compute_diff(expected, actual);
        assert!(diff.contains("value"));
        assert!(diff.contains("42"));
        assert!(diff.contains("43"));
    }

    #[test]
    fn test_test_group() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "[test_group: \"contracts\"]\n\
             description: \"Contract tests\"\n\
             dependencies: [\"ksl_contract\", \"ksl_validator\"]\n\
             timeout: 30\n\
             \n\
             fn test_contract() { let x: u32 = 42; assert(x == 42); }"
        ).unwrap();

        let config = TestConfig {
            target: CompileTarget::VM,
            categories: vec![],
            parallel: false,
            watch: false,
            snapshot_dir: None,
            update_snapshots: false,
            measure_gas: false,
            output_dir: None,
        };

        let mut runner = TestRunner::new(config);
        let group = runner.parse_test_group(temp_file.path().to_str().unwrap())
            .unwrap()
            .unwrap();

        assert_eq!(group.name, "contracts");
        assert_eq!(group.description, Some("Contract tests".to_string()));
        assert_eq!(group.dependencies, vec!["ksl_contract", "ksl_validator"]);
        assert_eq!(group.timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_save_test_summary() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test_add() { let x: u32 = 42; assert(x == 42); }"
        ).unwrap();

        let config = TestConfig {
            target: CompileTarget::VM,
            categories: vec![],
            parallel: false,
            watch: false,
            snapshot_dir: None,
            update_snapshots: false,
            measure_gas: false,
            output_dir: None,
        };

        let mut runner = TestRunner::new(config);
        runner.run_tests(&temp_file.path().to_path_buf()).unwrap();
        
        let summary_path = PathBuf::from("test_report.json");
        assert!(summary_path.exists());
        
        let content = fs::read_to_string(&summary_path).unwrap();
        let summary: TestSummary = serde_json::from_str(&content).unwrap();
        
        assert_eq!(summary.total_tests, 1);
        assert_eq!(summary.passed_tests, 1);
        assert_eq!(summary.failed_tests, 0);
    }
}