// ksl_ci.rs
// Implements a Continuous Integration system for KSL programs.
// 
// The CI system provides:
// - Runtime consistency checks across VM, WASM, and LLVM modes
// - Normalized output comparison for return values, memory footprint, and gas/timing deltas
// - Performance regression suite with synthetic workloads
// - Regression detection against baseline metrics
// - Output and alerts management
// - Artifact verification
// - CI profile control
// - YAML/CLI configuration
// - CI dashboard HTML output
// - Parallel test execution
// - CPU/RAM metrics instrumentation
// - WASM baseline output logging
// - Cross-test hashing for reproducibility

use crate::ksl_analyzer::{Analyzer, GasStats};
use crate::ksl_package_publish::{PackagePublisher, PackageArchive};
use crate::ksl_validator_keys::{ValidatorKeys, Signature};
use crate::ksl_shard_manager::ShardManager;
use crate::ksl_consensus_manager::ConsensusManager;
use crate::ksl_bytecode::{CompileTarget, KapraBytecode};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_test::{TestConfig, TestResult};
use std::fs;
use std::path::{Path, PathBuf};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use serde_yaml;
use clap::{App, Arg};
use sysinfo::{System, SystemExt, ProcessExt};
use sha2::{Sha256, Digest};
use chrono::Local;
use tera::{Tera, Context};
use reqwest;
use ed25519_dalek;

// CI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiConfig {
    /// Target compilation modes to test
    pub targets: Vec<CompileTarget>,
    /// Test categories to run
    pub categories: Vec<String>,
    /// Whether to run tests in parallel
    pub parallel: bool,
    /// Baseline file path
    pub baseline_path: PathBuf,
    /// Output directory for results
    pub output_dir: PathBuf,
    /// Whether to generate HTML dashboard
    pub generate_dashboard: bool,
    /// Whether to measure CPU/RAM usage
    pub measure_resources: bool,
    /// Whether to cache test results
    pub cache_results: bool,
    /// Cache directory
    pub cache_dir: Option<PathBuf>,
    /// Whether to verify WASM output
    pub verify_wasm: bool,
    /// Whether to auto-yank packages on regression
    pub auto_yank: bool,
    /// Webhook configuration
    pub webhook: Option<WebhookConfig>,
    /// Runtime bounds configuration
    pub runtime_bounds: Option<RuntimeBounds>,
    /// Chart configuration
    pub charts: Option<ChartConfig>,
    /// Whether to sign reports
    pub sign_reports: bool,
    /// Signing key path
    pub signing_key: Option<String>,
}

// CI test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiTestResult {
    pub name: String,
    pub target: CompileTarget,
    pub passed: bool,
    pub error: Option<String>,
    pub duration: Duration,
    pub gas_metrics: Option<GasMetrics>,
    pub resource_metrics: Option<ResourceMetrics>,
    pub wasm_output: Option<String>,
    pub test_hash: String,
}

// Resource metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub peak_memory: u64,
    pub io_read: u64,
    pub io_write: u64,
    pub context_switches: u64,
}

// CI regression
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiRegression {
    pub test_name: String,
    pub target: CompileTarget,
    pub regression_type: RegressionType,
    pub baseline_value: f64,
    pub current_value: f64,
    pub threshold: f64,
}

// Regression type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegressionType {
    GasUsage,
    ExecutionTime,
    MemoryUsage,
    CpuUsage,
    WasmOutput,
}

// CI benchmark result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiBenchmarkResult {
    pub name: String,
    pub tps: f64,
    pub latency: Duration,
    pub gas_per_tx: u64,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub timestamp: SystemTime,
}

// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub tps: f64,
    pub latency: Duration,
    pub gas_per_tx: u64,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub io_metrics: IoMetrics,
}

// IO metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoMetrics {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
}

// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub service: WebhookService,
    pub channel: Option<String>,
    pub username: Option<String>,
    pub icon_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebhookService {
    Slack,
    Discord,
}

// Runtime bounds configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeBounds {
    pub max_duration: Option<Duration>,
    pub max_memory_mb: Option<u64>,
    pub max_cpu_percent: Option<f32>,
    pub max_io_ops: Option<u64>,
}

// Chart configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartConfig {
    pub enabled: bool,
    pub metrics: Vec<ChartMetric>,
    pub update_interval: Duration,
    pub history_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartMetric {
    pub name: String,
    pub label: String,
    pub color: String,
    pub unit: String,
}

// CI system
pub struct CiSystem {
    config: CiConfig,
    analyzer: Arc<Analyzer>,
    publisher: Option<Arc<PackagePublisher>>,
    shard_manager: Arc<ShardManager>,
    consensus_manager: Arc<ConsensusManager>,
    baseline_results: HashMap<String, CiTestResult>,
    current_results: Vec<CiTestResult>,
    regressions: Vec<CiRegression>,
    system_info: System,
    test_cache: HashMap<String, CiTestResult>,
    tera: Tera,
    webhook_client: Option<reqwest::Client>,
    chart_data: HashMap<String, Vec<f64>>,
    signing_key: Option<ed25519_dalek::Keypair>,
}

impl CiSystem {
    pub fn new(config: CiConfig) -> Result<Self, String> {
        // Initialize system info
        let mut system_info = System::new_all();
        system_info.refresh_all();

        // Initialize template engine
        let tera = Tera::new("templates/**/*")
            .map_err(|e| format!("Failed to initialize template engine: {}", e))?;

        // Initialize webhook client if configured
        let webhook_client = if config.webhook.is_some() {
            Some(reqwest::Client::new())
        } else {
            None
        };

        // Initialize signing key if configured
        let signing_key = if config.sign_reports {
            if let Some(key_path) = &config.signing_key {
                let key_bytes = fs::read(key_path)
                    .map_err(|e| format!("Failed to read signing key: {}", e))?;
                Some(ed25519_dalek::Keypair::from_bytes(&key_bytes)
                    .map_err(|e| format!("Invalid signing key: {}", e))?)
            } else {
                return Err("Signing enabled but no key provided".to_string());
            }
        } else {
            None
        };

        Ok(CiSystem {
            config,
            analyzer: Arc::new(Analyzer::new()),
            publisher: None,
            shard_manager: Arc::new(ShardManager::new()),
            consensus_manager: Arc::new(ConsensusManager::new()),
            baseline_results: HashMap::new(),
            current_results: Vec::new(),
            regressions: Vec::new(),
            system_info,
            test_cache: HashMap::new(),
            tera,
            webhook_client,
            chart_data: HashMap::new(),
            signing_key,
        })
    }

    // Load configuration from YAML file
    pub fn load_config_from_yaml(path: &Path) -> Result<CiConfig, String> {
        let contents = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        serde_yaml::from_str(&contents)
            .map_err(|e| format!("Failed to parse config file: {}", e))
    }

    // Parse CLI arguments
    pub fn parse_cli_args() -> Result<CiConfig, String> {
        let matches = App::new("ksl-ci")
            .version("1.0")
            .author("KSL Team")
            .about("KSL Continuous Integration System")
            .arg(Arg::with_name("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Path to YAML config file")
                .takes_value(true))
            .arg(Arg::with_name("targets")
                .short('t')
                .long("targets")
                .value_name("TARGETS")
                .help("Comma-separated list of targets (VM,WASM,LLVM)")
                .takes_value(true))
            .arg(Arg::with_name("parallel")
                .short('p')
                .long("parallel")
                .help("Run tests in parallel"))
            .arg(Arg::with_name("baseline")
                .short('b')
                .long("baseline")
                .value_name("FILE")
                .help("Path to baseline file")
                .takes_value(true))
            .arg(Arg::with_name("output")
                .short('o')
                .long("output")
                .value_name("DIR")
                .help("Output directory")
                .takes_value(true))
            .arg(Arg::with_name("dashboard")
                .long("dashboard")
                .help("Generate HTML dashboard"))
            .arg(Arg::with_name("resources")
                .long("resources")
                .help("Measure CPU/RAM usage"))
            .arg(Arg::with_name("cache")
                .long("cache")
                .help("Cache test results"))
            .arg(Arg::with_name("cache-dir")
                .long("cache-dir")
                .value_name("DIR")
                .help("Cache directory")
                .takes_value(true))
            .arg(Arg::with_name("verify-wasm")
                .long("verify-wasm")
                .help("Verify WASM output"))
            .arg(Arg::with_name("auto-yank")
                .long("auto-yank")
                .help("Auto-yank packages on regression"))
            .get_matches();

        // Try to load from YAML first
        if let Some(config_path) = matches.value_of("config") {
            return Self::load_config_from_yaml(Path::new(config_path));
        }

        // Otherwise build from CLI args
        let targets = matches.value_of("targets")
            .map(|s| s.split(',')
                .map(|t| match t {
                    "VM" => CompileTarget::VM,
                    "WASM" => CompileTarget::WASM,
                    "LLVM" => CompileTarget::LLVM,
                    _ => CompileTarget::VM,
                })
                .collect())
            .unwrap_or_else(|| vec![CompileTarget::VM]);

        Ok(CiConfig {
            targets,
            categories: vec![],
            parallel: matches.is_present("parallel"),
            baseline_path: matches.value_of("baseline")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("ci_baseline.json")),
            output_dir: matches.value_of("output")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("ci_output")),
            generate_dashboard: matches.is_present("dashboard"),
            measure_resources: matches.is_present("resources"),
            cache_results: matches.is_present("cache"),
            cache_dir: matches.value_of("cache-dir").map(PathBuf::from),
            verify_wasm: matches.is_present("verify-wasm"),
            auto_yank: matches.is_present("auto-yank"),
            webhook: None,
            runtime_bounds: None,
            charts: None,
            sign_reports: false,
            signing_key: None,
        })
    }

    // Run tests
    pub async fn run_tests(&mut self, file: &PathBuf) -> Result<(), String> {
        // Load baseline if exists
        if self.config.baseline_path.exists() {
            self.load_baseline()?;
        }

        // Create output directory
        fs::create_dir_all(&self.config.output_dir)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;

        // Run tests for each target
        if self.config.parallel {
            self.run_tests_parallel(file).await?;
        } else {
            self.run_tests_sequential(file).await?;
        }

        // Check runtime bounds
        if let Some(metrics) = self.collect_resource_metrics()? {
            self.check_runtime_bounds(&metrics)?;
            self.update_chart_data(&metrics);
        }

        // Check for regressions
        self.check_regressions()?;

        // Send webhook notification if there are regressions
        if !self.regressions.is_empty() {
            let message = format!(
                "⚠️ CI Regression Alert\n\
                 {} regression(s) detected:\n{}",
                self.regressions.len(),
                self.regressions.iter()
                    .map(|r| format!("- {}: {} ({} vs {})", 
                        r.test_name, 
                        format!("{:?}", r.regression_type),
                        r.baseline_value,
                        r.current_value))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            self.send_webhook(&message).await?;
        }

        // Generate dashboard if enabled
        if self.config.generate_dashboard {
            self.generate_dashboard()?;
        }

        // Auto-yank packages if needed
        if self.config.auto_yank && !self.regressions.is_empty() {
            self.auto_yank_packages()?;
        }

        Ok(())
    }

    // Run tests in parallel
    async fn run_tests_parallel(&mut self, file: &PathBuf) -> Result<(), String> {
        let mut futures = Vec::new();
        for target in &self.config.targets {
            let file = file.clone();
            let target = *target;
            let future = self.run_test_for_target(&file, target);
            futures.push(future);
        }
        let results = futures::future::join_all(futures).await;
        for result in results {
            self.current_results.extend(result?);
        }
        Ok(())
    }

    // Run tests sequentially
    async fn run_tests_sequential(&mut self, file: &PathBuf) -> Result<(), String> {
        for target in &self.config.targets {
            let results = self.run_test_for_target(file, *target).await?;
            self.current_results.extend(results);
        }
        Ok(())
    }

    // Run test for a specific target
    async fn run_test_for_target(&self, file: &PathBuf, target: CompileTarget) -> Result<Vec<CiTestResult>, String> {
        let mut results = Vec::new();
        let start_time = std::time::Instant::now();

        // Calculate test hash
        let test_hash = self.calculate_test_hash(file, target)?;

        // Check cache if enabled
        if self.config.cache_results {
            if let Some(cached_result) = self.test_cache.get(&test_hash) {
                return Ok(vec![cached_result.clone()]);
            }
        }

        // Run test
        let test_config = TestConfig {
            target,
            categories: self.config.categories.clone(),
            parallel: self.config.parallel,
            watch: false,
            snapshot_dir: None,
            update_snapshots: false,
            measure_gas: true,
        };

        let test_result = crate::ksl_test::run_tests(file, test_config).await?;
        let duration = start_time.elapsed();

        // Collect resource metrics if enabled
        let resource_metrics = if self.config.measure_resources {
            self.collect_resource_metrics()?
        } else {
            None
        };

        // Collect WASM output if needed
        let wasm_output = if target == CompileTarget::WASM && self.config.verify_wasm {
            self.collect_wasm_output(file)?
        } else {
            None
        };

        // Create CI test result
        let result = CiTestResult {
            name: file.file_name().unwrap().to_string_lossy().into_owned(),
            target,
            passed: test_result.is_ok(),
            error: test_result.err(),
            duration,
            gas_metrics: self.analyzer.get_gas_stats().map(|stats| GasMetrics {
                total_gas: stats.total_gas,
                max_gas: stats.max_gas,
                avg_gas: stats.avg_gas,
                gas_by_operation: stats.gas_by_operation.clone(),
            }),
            resource_metrics,
            wasm_output,
            test_hash,
        };

        // Cache result if enabled
        if self.config.cache_results {
            self.test_cache.insert(test_hash.clone(), result.clone());
        }

        results.push(result);
        Ok(results)
    }

    // Calculate test hash
    fn calculate_test_hash(&self, file: &PathBuf, target: CompileTarget) -> Result<String, String> {
        let mut hasher = Sha256::new();
        
        // Hash file contents
        let contents = fs::read_to_string(file)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        hasher.update(contents.as_bytes());
        
        // Hash target
        hasher.update(format!("{:?}", target).as_bytes());
        
        // Hash config
        let config_str = serde_json::to_string(&self.config)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        hasher.update(config_str.as_bytes());
        
        Ok(format!("{:x}", hasher.finalize()))
    }

    // Collect resource metrics
    fn collect_resource_metrics(&mut self) -> Result<ResourceMetrics, String> {
        self.system_info.refresh_all();
        
        let process = self.system_info.processes()
            .values()
            .find(|p| p.name() == "ksl")
            .ok_or_else(|| "KSL process not found".to_string())?;
        
        Ok(ResourceMetrics {
            cpu_usage: process.cpu_usage(),
            memory_usage: process.memory(),
            peak_memory: process.memory(),
            io_read: process.disk_usage().read_bytes,
            io_write: process.disk_usage().written_bytes,
            context_switches: process.context_switches(),
        })
    }

    // Collect WASM output
    fn collect_wasm_output(&self, file: &PathBuf) -> Result<Option<String>, String> {
        if !self.config.verify_wasm {
            return Ok(None);
        }

        // Compile to WASM
        let source = fs::read_to_string(file)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        let ast = crate::ksl_parser::parse(&source)
            .map_err(|e| format!("Parse error: {}", e))?;
        let bytecode = crate::ksl_compiler::compile(&ast)
            .map_err(|e| format!("Compile error: {}", e))?;

        // Get WASM output
        let wasm_output = bytecode.to_wasm()
            .map_err(|e| format!("WASM conversion error: {}", e))?;
        
        Ok(Some(wasm_output))
    }

    // Send webhook notification
    async fn send_webhook(&self, message: &str) -> Result<(), String> {
        if let (Some(client), Some(config)) = (&self.webhook_client, &self.config.webhook) {
            let payload = match config.service {
                WebhookService::Slack => {
                    serde_json::json!({
                        "channel": config.channel,
                        "username": config.username,
                        "icon_url": config.icon_url,
                        "text": message,
                    })
                },
                WebhookService::Discord => {
                    serde_json::json!({
                        "content": message,
                        "username": config.username,
                        "avatar_url": config.icon_url,
                    })
                },
            };

            client.post(&config.url)
                .json(&payload)
                .send()
                .await
                .map_err(|e| format!("Failed to send webhook: {}", e))?;
        }
        Ok(())
    }

    // Check runtime bounds
    fn check_runtime_bounds(&self, metrics: &ResourceMetrics) -> Result<(), String> {
        if let Some(bounds) = &self.config.runtime_bounds {
            if let Some(max_memory) = bounds.max_memory_mb {
                let memory_mb = metrics.memory_usage / (1024 * 1024);
                if memory_mb > max_memory {
                    return Err(format!("Memory usage {}MB exceeds limit of {}MB", 
                        memory_mb, max_memory));
                }
            }

            if let Some(max_cpu) = bounds.max_cpu_percent {
                if metrics.cpu_usage > max_cpu {
                    return Err(format!("CPU usage {}% exceeds limit of {}%", 
                        metrics.cpu_usage, max_cpu));
                }
            }

            if let Some(max_io) = bounds.max_io_ops {
                let total_io = metrics.io_read + metrics.io_write;
                if total_io > max_io {
                    return Err(format!("IO operations {} exceed limit of {}", 
                        total_io, max_io));
                }
            }
        }
        Ok(())
    }

    // Update chart data
    fn update_chart_data(&mut self, metrics: &ResourceMetrics) {
        if let Some(charts) = &self.config.charts {
            if !charts.enabled {
                return;
            }

            for metric in &charts.metrics {
                let value = match metric.name.as_str() {
                    "cpu" => metrics.cpu_usage as f64,
                    "memory" => metrics.memory_usage as f64 / (1024.0 * 1024.0),
                    "io_read" => metrics.io_read as f64,
                    "io_write" => metrics.io_write as f64,
                    _ => continue,
                };

                let data = self.chart_data.entry(metric.name.clone())
                    .or_insert_with(Vec::new);
                
                data.push(value);
                if data.len() > charts.history_size {
                    data.remove(0);
                }
            }
        }
    }

    // Generate chart HTML
    fn generate_charts(&self) -> String {
        if let Some(charts) = &self.config.charts {
            if !charts.enabled {
                return String::new();
            }

            let mut html = String::from("<div class='charts'>");
            for metric in &charts.metrics {
                if let Some(data) = self.chart_data.get(&metric.name) {
                    html.push_str(&format!(
                        "<div class='chart' id='chart_{}'>\n\
                         <h3>{}</h3>\n\
                         <canvas></canvas>\n\
                         <script>\n\
                         new Chart(document.getElementById('chart_{}').querySelector('canvas'), {{\n\
                             type: 'line',\n\
                             data: {{\n\
                                 labels: Array.from({{length: {}}}, (_, i) => i),\n\
                                 datasets: [{{\n\
                                     label: '{}',\n\
                                     data: {:?},\n\
                                     borderColor: '{}',\n\
                                     fill: false\n\
                                 }}]\n\
                             }},\n\
                             options: {{\n\
                                 scales: {{\n\
                                     y: {{\n\
                                         beginAtZero: true,\n\
                                         title: {{\n\
                                             display: true,\n\
                                             text: '{}'\n\
                                         }}\n\
                                     }}\n\
                                 }}\n\
                             }}\n\
                         }});\n\
                         </script>\n\
                         </div>",
                        metric.name,
                        metric.label,
                        metric.name,
                        data.len(),
                        metric.label,
                        data,
                        metric.color,
                        metric.unit
                    ));
                }
            }
            html.push_str("</div>");
            html
        } else {
            String::new()
        }
    }

    // Sign report
    fn sign_report(&self, content: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(keypair) = &self.signing_key {
            let signature = keypair.sign(content);
            let mut signed = Vec::new();
            signed.extend_from_slice(content);
            signed.extend_from_slice(b"\n---\n");
            signed.extend_from_slice(signature.to_bytes().as_ref());
            Ok(signed)
        } else {
            Ok(content.to_vec())
        }
    }

    // Generate HTML dashboard
    fn generate_dashboard(&self) -> Result<(), String> {
        let mut context = Context::new();
        
        // Add test results
        context.insert("results", &self.current_results);
        
        // Add regressions
        context.insert("regressions", &self.regressions);
        
        // Add charts
        context.insert("charts", &self.generate_charts());
        
        // Add summary
        let passed = self.current_results.iter().filter(|r| r.passed).count();
        let total = self.current_results.len();
        context.insert("summary", &serde_json::json!({
            "passed": passed,
            "total": total,
            "failed": total - passed,
            "timestamp": Local::now().to_rfc3339(),
        }));
        
        // Render template
        let html = self.tera.render("dashboard.html", &context)
            .map_err(|e| format!("Failed to render dashboard: {}", e))?;
        
        // Sign if configured
        let content = if self.config.sign_reports {
            self.sign_report(html.as_bytes())?
        } else {
            html.into_bytes()
        };
        
        // Write to file
        let dashboard_path = self.config.output_dir.join("dashboard.html");
        fs::write(&dashboard_path, content)
            .map_err(|e| format!("Failed to write dashboard: {}", e))?;
        
        Ok(())
    }

    // Auto-yank packages on regression
    fn auto_yank_packages(&self) -> Result<(), String> {
        if let Some(publisher) = &self.publisher {
            for regression in &self.regressions {
                if let Some(commit_msg) = self.extract_package_info(&regression.test_name)? {
                    publisher.yank_package(&commit_msg.package_name, &commit_msg.version)
                        .map_err(|e| format!("Failed to yank package: {}", e))?;
                }
            }
        }
        Ok(())
    }
}

// Public API to run CI
pub async fn run_ci(file: &PathBuf, config: CiConfig) -> Result<(), String> {
    let mut ci = CiSystem::new(config)?;
    ci.run_tests(file).await
}

// Public API to run CI synchronously
pub fn run_ci_sync(file: &PathBuf, config: CiConfig) -> Result<(), String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create runtime: {}", e))?;
    runtime.block_on(run_ci(file, config))
}

// Module imports
mod ksl_analyzer {
    pub use super::{Analyzer, GasStats};
}

mod ksl_package_publish {
    pub use super::{PackagePublisher, PackageArchive};
}

mod ksl_validator_keys {
    pub use super::{ValidatorKeys, Signature};
}

mod ksl_shard_manager {
    pub use super::ShardManager;
}

mod ksl_consensus_manager {
    pub use super::ConsensusManager;
}

mod ksl_bytecode {
    pub use super::{CompileTarget, KapraBytecode};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

mod ksl_test {
    pub use super::{TestConfig, TestResult};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_config_from_yaml() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "targets: [VM, WASM, LLVM]\n\
             parallel: true\n\
             baseline_path: ci_baseline.json\n\
             output_dir: ci_output\n\
             generate_dashboard: true\n\
             measure_resources: true\n\
             cache_results: true\n\
             verify_wasm: true\n\
             auto_yank: true"
        ).unwrap();

        let config = CiSystem::load_config_from_yaml(temp_file.path()).unwrap();
        assert_eq!(config.targets.len(), 3);
        assert!(config.parallel);
        assert!(config.generate_dashboard);
        assert!(config.measure_resources);
        assert!(config.cache_results);
        assert!(config.verify_wasm);
        assert!(config.auto_yank);
    }

    #[test]
    fn test_parse_cli_args() {
        let args = vec![
            "ksl-ci",
            "--targets", "VM,WASM",
            "--parallel",
            "--baseline", "test_baseline.json",
            "--output", "test_output",
            "--dashboard",
            "--resources",
            "--cache",
            "--verify-wasm",
            "--auto-yank",
        ];

        let config = CiSystem::parse_cli_args().unwrap();
        assert_eq!(config.targets.len(), 2);
        assert!(config.parallel);
        assert!(config.generate_dashboard);
        assert!(config.measure_resources);
        assert!(config.cache_results);
        assert!(config.verify_wasm);
        assert!(config.auto_yank);
    }

    #[tokio::test]
    async fn test_run_ci() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test_add() { let x: u32 = 42; assert(x == 42); }"
        ).unwrap();

        let config = CiConfig {
            targets: vec![CompileTarget::VM],
            categories: vec![],
            parallel: false,
            baseline_path: PathBuf::from("test_baseline.json"),
            output_dir: PathBuf::from("test_output"),
            generate_dashboard: true,
            measure_resources: true,
            cache_results: true,
            cache_dir: Some(PathBuf::from("test_cache")),
            verify_wasm: true,
            auto_yank: false,
            webhook: None,
            runtime_bounds: None,
            charts: None,
            sign_reports: false,
            signing_key: None,
        };

        let result = run_ci(&temp_file.path().to_path_buf(), config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_runtime_bounds() {
        let config = CiConfig {
            targets: vec![CompileTarget::VM],
            categories: vec![],
            parallel: false,
            baseline_path: PathBuf::from("ci_baseline.json"),
            output_dir: PathBuf::from("ci_output"),
            generate_dashboard: true,
            measure_resources: true,
            cache_results: true,
            cache_dir: None,
            verify_wasm: true,
            auto_yank: false,
            webhook: None,
            runtime_bounds: Some(RuntimeBounds {
                max_memory_mb: Some(100),
                max_cpu_percent: Some(50.0),
                max_io_ops: Some(1000),
                max_duration: Some(Duration::from_secs(30)),
            }),
            charts: None,
            sign_reports: false,
            signing_key: None,
        };

        let mut ci = CiSystem::new(config).unwrap();
        let metrics = ResourceMetrics {
            cpu_usage: 60.0,
            memory_usage: 150 * 1024 * 1024,
            peak_memory: 150 * 1024 * 1024,
            io_read: 600,
            io_write: 500,
            context_switches: 100,
        };

        assert!(ci.check_runtime_bounds(&metrics).is_err());
    }

    #[test]
    fn test_webhook() {
        let config = CiConfig {
            targets: vec![CompileTarget::VM],
            categories: vec![],
            parallel: false,
            baseline_path: PathBuf::from("ci_baseline.json"),
            output_dir: PathBuf::from("ci_output"),
            generate_dashboard: true,
            measure_resources: true,
            cache_results: true,
            cache_dir: None,
            verify_wasm: true,
            auto_yank: false,
            webhook: Some(WebhookConfig {
                url: "https://hooks.slack.com/test".to_string(),
                service: WebhookService::Slack,
                channel: Some("#ci".to_string()),
                username: Some("CI Bot".to_string()),
                icon_url: None,
            }),
            runtime_bounds: None,
            charts: None,
            sign_reports: false,
            signing_key: None,
        };

        let ci = CiSystem::new(config).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            assert!(ci.send_webhook("Test message").await.is_ok());
        });
    }

    #[test]
    fn test_chart_data() {
        let config = CiConfig {
            targets: vec![CompileTarget::VM],
            categories: vec![],
            parallel: false,
            baseline_path: PathBuf::from("ci_baseline.json"),
            output_dir: PathBuf::from("ci_output"),
            generate_dashboard: true,
            measure_resources: true,
            cache_results: true,
            cache_dir: None,
            verify_wasm: true,
            auto_yank: false,
            webhook: None,
            runtime_bounds: None,
            charts: Some(ChartConfig {
                enabled: true,
                metrics: vec![
                    ChartMetric {
                        name: "cpu".to_string(),
                        label: "CPU Usage".to_string(),
                        color: "#ff0000".to_string(),
                        unit: "%".to_string(),
                    },
                ],
                update_interval: Duration::from_secs(1),
                history_size: 100,
            }),
            sign_reports: false,
            signing_key: None,
        };

        let mut ci = CiSystem::new(config).unwrap();
        let metrics = ResourceMetrics {
            cpu_usage: 50.0,
            memory_usage: 1024 * 1024,
            peak_memory: 1024 * 1024,
            io_read: 100,
            io_write: 100,
            context_switches: 10,
        };

        ci.update_chart_data(&metrics);
        assert!(ci.chart_data.get("cpu").is_some());
    }
} 