/// ksl_fuzzer.rs
/// Implements a comprehensive fuzzing framework for KSL programs.
/// 
/// Features:
/// - Targeted fuzzing for contracts, validators, sharding, and consensus
/// - Corpus management and input shrinking
/// - Crash logging and reproducibility
/// - CI integration
/// - Optional features like symbolic fuzzing and coverage tracking

use crate::ksl_parser::{parse, AstNode};
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, CompileTarget};
use crate::ksl_contract::{ContractAbi, ContractFunction};
use crate::ksl_validator_keys::{ValidatorKeys, Signature};
use crate::ksl_shard_manager::ShardManager;
use crate::ksl_consensus_manager::ConsensusManager;
use crate::ksl_analyzer::{Analyzer, GasStats};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_macros::{MacroDef, MacroKind};
use std::fs;
use std::path::{Path, PathBuf};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use proptest::prelude::*;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{TestRunner, TestCaseResult};
use z3::{Context, Solver};
use rayon::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};
use backtrace::Backtrace;
use regex;
use chrono::{Local};
use tera::{Context as TeraContext, Tera};
use reqwest;
use serde_json;
use libloading;
use seccompiler;
use nix;
use rlimit;
use humantime;
use crate::kapra_vm::{KapraVM, KapraInstruction, KapraOpCode, Operand};
use crate::ksl_kapra_consensus::{KapraVM as ConsensusVM, Bytecode, Constant};
use crate::ksl_types::{Type, TypeError};
use rand::{thread_rng, Rng};
use std::panic;
use log;
use env_logger;
use clap;

/// Fuzzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerConfig {
    /// Target domain to fuzz
    pub domain: FuzzDomain,
    /// Number of test cases to generate
    pub num_cases: usize,
    /// Whether to run in parallel
    pub parallel: bool,
    /// Whether to use symbolic execution
    pub symbolic: bool,
    /// Whether to track coverage
    pub track_coverage: bool,
    /// Corpus directory
    pub corpus_dir: PathBuf,
    /// Shrunk directory
    pub shrunk_dir: PathBuf,
    /// Whether to replay a specific case
    pub replay: Option<PathBuf>,
    /// Timeout per test case
    pub timeout: Duration,
    /// Custom mutators to use
    pub mutators: Vec<String>,
    /// Output directory
    pub output_dir: PathBuf,
}

/// Fuzzing domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FuzzDomain {
    Contract {
        abi: ContractAbi,
        storage: bool,
        modifiers: bool,
    },
    Validator {
        keys: ValidatorKeys,
        segments: bool,
    },
    Sharding {
        cross_shard: bool,
        timing: bool,
    },
    Consensus {
        forks: bool,
        votes: bool,
    },
}

/// Fuzzer result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerResult {
    pub pass_rate: f64,
    pub total_cases: usize,
    pub failures: usize,
    pub high_risk: usize,
    pub crashes: Vec<CrashInfo>,
    pub coverage: Option<CoverageInfo>,
    pub duration: Duration,
    pub timestamp: SystemTime,
}

/// Crash information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashInfo {
    pub input: String,
    pub stack_trace: String,
    pub seed: u64,
    pub ast_diff: Option<String>,
    pub module: String,
    pub severity: CrashSeverity,
    pub shrunk_input: Option<String>,
}

/// Crash severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrashSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Coverage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageInfo {
    pub bytecode_coverage: f64,
    pub llvm_coverage: f64,
    pub uncovered_blocks: Vec<String>,
    pub hot_paths: Vec<String>,
}

/// ABI mutator trait for custom contract mutation
pub trait AbiMutator: Send + Sync {
    fn mutate(&self, abi: &mut ContractAbi) -> Result<(), String>;
    fn name(&self) -> &str;
}

/// ABI mutator registry
#[derive(Default)]
pub struct AbiMutatorRegistry {
    mutators: HashMap<String, Box<dyn AbiMutator>>,
}

impl AbiMutatorRegistry {
    pub fn new() -> Self {
        Self {
            mutators: HashMap::new(),
        }
    }

    pub fn register(&mut self, mutator: Box<dyn AbiMutator>) {
        self.mutators.insert(mutator.name().to_string(), mutator);
    }

    pub fn get(&self, name: &str) -> Option<&dyn AbiMutator> {
        self.mutators.get(name).map(|m| m.as_ref())
    }
}

/// Coverage trend data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageTrend {
    pub timestamp: SystemTime,
    pub bytecode_coverage: f64,
    pub llvm_coverage: f64,
    pub uncovered_blocks: Vec<String>,
    pub hot_paths: Vec<String>,
    pub git_commit: String,
}

/// Coverage trend tracker
pub struct CoverageTrendTracker {
    trends: Vec<CoverageTrend>,
    output_dir: PathBuf,
    tera: Tera,
}

impl CoverageTrendTracker {
    pub fn new(output_dir: PathBuf) -> Self {
        Self {
            trends: Vec::new(),
            output_dir,
            tera: Tera::new("templates/**/*").unwrap(),
        }
    }

    pub fn add_trend(&mut self, trend: CoverageTrend) -> Result<(), String> {
        self.trends.push(trend);
        self.save_trends()?;
        Ok(())
    }

    pub fn save_trends(&self) -> Result<(), String> {
        let trends_path = self.output_dir.join("coverage_trends.json");
        fs::write(&trends_path, serde_json::to_string_pretty(&self.trends)?)
            .map_err(|e| format!("Failed to save coverage trends: {}", e))?;
        Ok(())
    }

    pub fn generate_trend_report(&self) -> Result<(), String> {
        let mut context = TeraContext::new();
        context.insert("trends", &self.trends);
        
        let html = self.tera.render("coverage_trend.html", &context)
            .map_err(|e| format!("Failed to render trend report: {}", e))?;
        
        let report_path = self.output_dir.join("coverage_trend.html");
        fs::write(&report_path, html)
            .map_err(|e| format!("Failed to write trend report: {}", e))?;
        
        Ok(())
    }
}

/// Sharding message injector
pub struct ShardingMessageInjector {
    testnet_nodes: Vec<String>,
    message_queue: Arc<RwLock<Vec<Vec<u8>>>>,
}

impl ShardingMessageInjector {
    pub fn new(testnet_nodes: Vec<String>) -> Self {
        Self {
            testnet_nodes,
            message_queue: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn inject_message(&self, message: Vec<u8>) -> Result<(), String> {
        let mut queue = self.message_queue.write().await;
        queue.push(message);
        Ok(())
    }

    pub async fn process_queue(&self) -> Result<(), String> {
        let mut queue = self.message_queue.write().await;
        while let Some(message) = queue.pop() {
            for node in &self.testnet_nodes {
                // TODO: Implement actual message injection to testnet nodes
                println!("Injecting message to node: {}", node);
            }
        }
        Ok(())
    }
}

/// Fuzzer state
pub struct Fuzzer {
    config: FuzzerConfig,
    corpus: HashMap<String, Vec<u8>>,
    crashes: Vec<CrashInfo>,
    coverage: Option<CoverageInfo>,
    analyzer: Arc<Analyzer>,
    shard_manager: Arc<ShardManager>,
    consensus_manager: Arc<ConsensusManager>,
    solver: Option<Solver>,
    progress: ProgressBar,
    tera: Tera,
}

impl Fuzzer {
    pub fn new(config: FuzzerConfig) -> Result<Self, String> {
        // Create directories
        fs::create_dir_all(&config.corpus_dir)
            .map_err(|e| format!("Failed to create corpus directory: {}", e))?;
        fs::create_dir_all(&config.shrunk_dir)
            .map_err(|e| format!("Failed to create shrunk directory: {}", e))?;

        // Initialize Z3 solver if symbolic execution is enabled
        let solver = if config.symbolic {
            let ctx = Context::new();
            Some(Solver::new(&ctx))
        } else {
            None
        };

        // Initialize progress bar
        let progress = ProgressBar::new(config.num_cases as u64);
        progress.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
            .progress_chars("##-"));

        // Initialize Tera template engine
        let tera = Tera::new("templates/**/*").map_err(|e| format!("Failed to create Tera: {}", e))?;

        Ok(Fuzzer {
            config,
            corpus: HashMap::new(),
            crashes: Vec::new(),
            coverage: None,
            analyzer: Arc::new(Analyzer::new()),
            shard_manager: Arc::new(ShardManager::new()),
            consensus_manager: Arc::new(ConsensusManager::new()),
            solver,
            progress,
            tera,
        })
    }

    /// Run fuzzer
    pub async fn run(&mut self) -> Result<FuzzerResult, String> {
        if let Some(replay) = &self.config.replay {
            return self.replay_crash(replay).await;
        }

        let start_time = SystemTime::now();
        let mut failures = 0;
        let mut high_risk = 0;

        // Run fuzzer based on domain
        match &self.config.domain {
            FuzzDomain::Contract { abi, storage, modifiers } => {
                self.fuzz_contract(abi, *storage, *modifiers).await?;
            },
            FuzzDomain::Validator { keys, segments } => {
                self.fuzz_validator(keys, *segments).await?;
            },
            FuzzDomain::Sharding { cross_shard, timing } => {
                self.fuzz_sharding(*cross_shard, *timing).await?;
            },
            FuzzDomain::Consensus { forks, votes } => {
                self.fuzz_consensus(*forks, *votes).await?;
            },
        }

        // Calculate results
        let duration = start_time.elapsed().unwrap();
        let pass_rate = 1.0 - (failures as f64 / self.config.num_cases as f64);

        Ok(FuzzerResult {
            pass_rate,
            total_cases: self.config.num_cases,
            failures,
            high_risk,
            crashes: self.crashes.clone(),
            coverage: self.coverage.clone(),
            duration,
            timestamp: SystemTime::now(),
        })
    }

    /// Fuzz contract domain
    async fn fuzz_contract(&mut self, abi: &ContractAbi, storage: bool, modifiers: bool) -> Result<(), String> {
        let mut runner = TestRunner::new(ProptestConfig::default());
        
        for function in &abi.functions {
            // Generate ABI inputs
            let input_strategy = self.generate_abi_inputs(function)?;
            
            // Run test cases
            for _ in 0..self.config.num_cases {
                let input = input_strategy.new_tree(&mut runner)
                    .map_err(|e| format!("Failed to generate input: {}", e))?
                    .current();

                // Fuzz storage if enabled
                if storage {
                    self.fuzz_storage(&input).await?;
                }

                // Fuzz modifiers if enabled
                if modifiers {
                    self.fuzz_modifiers(function, &input).await?;
                }

                // Run test case
                if let Err(e) = self.run_test_case(&input).await {
                    self.handle_crash(&input, e, "contract").await?;
                    failures += 1;
                    if self.is_high_risk(&e) {
                        high_risk += 1;
                    }
                }

                self.progress.inc(1);
            }
        }

        Ok(())
    }

    /// Fuzz validator domain
    async fn fuzz_validator(&mut self, keys: &ValidatorKeys, segments: bool) -> Result<(), String> {
        let mut runner = TestRunner::new(ProptestConfig::default());
        
        // Generate malformed signatures
        let signature_strategy = self.generate_malformed_signatures(keys)?;
        
        // Run test cases
        for _ in 0..self.config.num_cases {
            let signature = signature_strategy.new_tree(&mut runner)
                .map_err(|e| format!("Failed to generate signature: {}", e))?
                .current();

            // Fuzz segments if enabled
            if segments {
                self.fuzz_segments(&signature).await?;
            }

            // Run test case
            if let Err(e) = self.run_test_case(&signature).await {
                self.handle_crash(&signature, e, "validator").await?;
                failures += 1;
                if self.is_high_risk(&e) {
                    high_risk += 1;
                }
            }

            self.progress.inc(1);
        }

        Ok(())
    }

    /// Fuzz sharding domain
    async fn fuzz_sharding(&mut self, cross_shard: bool, timing: bool) -> Result<(), String> {
        let mut runner = TestRunner::new(ProptestConfig::default());
        
        // Generate cross-shard messages
        let message_strategy = self.generate_cross_shard_messages()?;
        
        // Run test cases
        for _ in 0..self.config.num_cases {
            let message = message_strategy.new_tree(&mut runner)
                .map_err(|e| format!("Failed to generate message: {}", e))?
                .current();

            // Fuzz timing if enabled
            if timing {
                self.fuzz_timing(&message).await?;
            }

            // Run test case
            if let Err(e) = self.run_test_case(&message).await {
                self.handle_crash(&message, e, "sharding").await?;
                failures += 1;
                if self.is_high_risk(&e) {
                    high_risk += 1;
                }
            }

            self.progress.inc(1);
        }

        Ok(())
    }

    /// Fuzz consensus domain
    async fn fuzz_consensus(&mut self, forks: bool, votes: bool) -> Result<(), String> {
        let mut runner = TestRunner::new(ProptestConfig::default());
        
        // Generate consensus scenarios
        let scenario_strategy = self.generate_consensus_scenarios()?;
        
        // Run test cases
        for _ in 0..self.config.num_cases {
            let scenario = scenario_strategy.new_tree(&mut runner)
                .map_err(|e| format!("Failed to generate scenario: {}", e))?
                .current();

            // Fuzz forks if enabled
            if forks {
                self.fuzz_forks(&scenario).await?;
            }

            // Fuzz votes if enabled
            if votes {
                self.fuzz_votes(&scenario).await?;
            }

            // Run test case
            if let Err(e) = self.run_test_case(&scenario).await {
                self.handle_crash(&scenario, e, "consensus").await?;
                failures += 1;
                if self.is_high_risk(&e) {
                    high_risk += 1;
                }
            }

            self.progress.inc(1);
        }

        Ok(())
    }

    /// Generate ABI inputs
    fn generate_abi_inputs(&self, function: &ContractFunction) -> Result<Box<dyn Strategy<Value = Vec<u8>>>, String> {
        let mut strategies = Vec::new();
        
        for param in &function.parameters {
            let strategy = match param.typ.as_str() {
                "u8" => any::<u8>().prop_map(|v| v.to_le_bytes().to_vec()).boxed(),
                "u32" => any::<u32>().prop_map(|v| v.to_le_bytes().to_vec()).boxed(),
                "u64" => any::<u64>().prop_map(|v| v.to_le_bytes().to_vec()).boxed(),
                "string" => any::<String>().prop_map(|v| v.into_bytes()).boxed(),
                "bool" => any::<bool>().prop_map(|v| vec![v as u8]).boxed(),
                _ => return Err(format!("Unsupported type: {}", param.typ)),
            };
            strategies.push(strategy);
        }
        
        Ok(Just(vec![]).prop_flat_map(move |_| {
            strategies.clone().prop_map(|values| {
                values.into_iter().flatten().collect()
            })
        }).boxed())
    }

    /// Generate malformed signatures
    fn generate_malformed_signatures(&self, keys: &ValidatorKeys) -> Result<Box<dyn Strategy<Value = Vec<u8>>>, String> {
        Ok(any::<[u8; 64]>()
            .prop_map(|mut sig| {
                // Corrupt signature bytes
                sig[0] ^= 0xFF;
                sig[32] ^= 0xFF;
                sig.to_vec()
            })
            .boxed())
    }

    /// Generate cross-shard messages
    fn generate_cross_shard_messages(&self) -> Result<Box<dyn Strategy<Value = Vec<u8>>>, String> {
        Ok(any::<[u8; 32]>()
            .prop_map(|mut msg| {
                // Corrupt message bytes
                msg[0] ^= 0xFF;
                msg[16] ^= 0xFF;
                msg.to_vec()
            })
            .boxed())
    }

    /// Generate consensus scenarios
    fn generate_consensus_scenarios(&self) -> Result<Box<dyn Strategy<Value = Vec<u8>>>, String> {
        Ok(any::<[u8; 128]>()
            .prop_map(|mut scenario| {
                // Corrupt scenario bytes
                scenario[0] ^= 0xFF;
                scenario[64] ^= 0xFF;
                scenario.to_vec()
            })
            .boxed())
    }

    /// Handle crash
    async fn handle_crash(&mut self, input: &[u8], error: String, module: &str) -> Result<(), String> {
        // Generate stack trace
        let backtrace = Backtrace::new();
        let stack_trace = format!("{:?}", backtrace);

        // Generate AST diff if applicable
        let ast_diff = if let Ok(source) = String::from_utf8(input.to_vec()) {
            if let Ok(ast) = parse(&source) {
                Some(format!("{:?}", ast))
            } else {
                None
            }
        } else {
            None
        };

        // Generate random seed for reproducibility
        let seed = rand::random();

        // Save crash info
        let crash = CrashInfo {
            input: hex::encode(input),
            stack_trace,
            seed,
            ast_diff,
            module: module.to_string(),
            severity: self.determine_severity(&error),
            shrunk_input: None,
        };

        // Log crash details
        log::error!(
            "Crash detected in module '{}'\nSeverity: {:?}\nSeed: {}\nInput: {}\nError: {}\n",
            module,
            crash.severity,
            crash.seed,
            crash.input,
            error
        );

        // Save to corpus
        let corpus_path = self.config.corpus_dir.join(format!(
            "crash_{}_{:016x}.json",
            self.crashes.len(),
            seed
        ));
        fs::write(&corpus_path, serde_json::to_string_pretty(&crash)?)
            .map_err(|e| format!("Failed to save crash: {}", e))?;

        // Attempt to shrink input
        if let Some(shrunk) = self.shrink_input(input).await? {
            crash.shrunk_input = Some(hex::encode(&shrunk));
            
            // Save shrunk input
            let shrunk_path = self.config.shrunk_dir.join(format!(
                "reduced_{}_{:016x}.json",
                self.crashes.len(),
                seed
            ));
            fs::write(&shrunk_path, serde_json::to_string_pretty(&crash)?)
                .map_err(|e| format!("Failed to save shrunk input: {}", e))?;

            log::info!("Shrunk input saved to {}", shrunk_path.display());
        }

        self.crashes.push(crash);
        Ok(())
    }

    /// Determine crash severity
    fn determine_severity(&self, error: &str) -> CrashSeverity {
        if error.contains("panic") || error.contains("assertion failed") {
            CrashSeverity::Critical
        } else if error.contains("overflow") || error.contains("underflow") {
            CrashSeverity::High
        } else if error.contains("invalid") || error.contains("failed") {
            CrashSeverity::Medium
        } else {
            CrashSeverity::Low
        }
    }

    /// Shrink input
    async fn shrink_input(&self, input: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let mut runner = TestRunner::new(ProptestConfig::default());
        let strategy = Just(input.to_vec()).boxed();
        
        if let Ok(mut tree) = strategy.new_tree(&mut runner) {
            while tree.simplify() {
                let current = tree.current();
                if self.run_test_case(&current).await.is_ok() {
                    return Ok(Some(current));
                }
            }
        }
        
        Ok(None)
    }

    /// Replay crash
    async fn replay_crash(&self, path: &Path) -> Result<FuzzerResult, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read crash file: {}", e))?;
        
        let crash: CrashInfo = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse crash file: {}", e))?;
        
        let input = hex::decode(&crash.input)
            .map_err(|e| format!("Failed to decode input: {}", e))?;
        
        if let Err(e) = self.run_test_case(&input).await {
            println!("Crash reproduced!");
            println!("Error: {}", e);
            println!("Stack trace:\n{}", crash.stack_trace);
            if let Some(diff) = crash.ast_diff {
                println!("AST diff:\n{}", diff);
            }
        } else {
            println!("Crash not reproduced!");
        }
        
        Ok(FuzzerResult {
            pass_rate: 0.0,
            total_cases: 1,
            failures: 1,
            high_risk: if self.is_high_risk(&crash.stack_trace) { 1 } else { 0 },
            crashes: vec![crash],
            coverage: None,
            duration: Duration::from_secs(0),
            timestamp: SystemTime::now(),
        })
    }

    /// Run test case
    async fn run_test_case(&self, input: &[u8]) -> Result<(), String> {
        // Run with timeout
        tokio::time::timeout(self.config.timeout, async {
            match &self.config.domain {
                FuzzDomain::Contract { .. } => self.run_contract_test(input).await,
                FuzzDomain::Validator { .. } => self.run_validator_test(input).await,
                FuzzDomain::Sharding { .. } => self.run_sharding_test(input).await,
                FuzzDomain::Consensus { .. } => self.run_consensus_test(input).await,
            }
        }).await
        .map_err(|_| "Test case timed out".to_string())?
    }

    /// Run contract test
    async fn run_contract_test(&self, input: &[u8]) -> Result<(), String> {
        // TODO: Implement contract test execution
            Ok(())
    }

    /// Run validator test
    async fn run_validator_test(&self, input: &[u8]) -> Result<(), String> {
        // TODO: Implement validator test execution
        Ok(())
    }

    /// Run sharding test
    async fn run_sharding_test(&self, input: &[u8]) -> Result<(), String> {
        // TODO: Implement sharding test execution
        Ok(())
    }

    /// Run consensus test
    async fn run_consensus_test(&self, input: &[u8]) -> Result<(), String> {
        // TODO: Implement consensus test execution
        Ok(())
    }

    /// Check if error is high risk
    fn is_high_risk(&self, error: &str) -> bool {
        error.contains("panic") || 
        error.contains("assertion failed") || 
        error.contains("overflow") || 
        error.contains("underflow")
    }

    /// Generate coverage HTML report
    pub fn generate_coverage_html(&self) -> Result<(), String> {
        if let Some(coverage) = &self.coverage {
            let mut context = TeraContext::new();
            
            // Add coverage data
            context.insert("bytecode_coverage", &coverage.bytecode_coverage);
            context.insert("llvm_coverage", &coverage.llvm_coverage);
            context.insert("uncovered_blocks", &coverage.uncovered_blocks);
            context.insert("hot_paths", &coverage.hot_paths);
            
            // Add timestamp
            context.insert("timestamp", &Local::now().to_rfc3339());
            
            // Render template
            let html = self.tera.render("coverage.html", &context)
                .map_err(|e| format!("Failed to render coverage report: {}", e))?;
            
            // Write to file
            let coverage_path = self.config.output_dir.join("coverage.html");
            fs::write(&coverage_path, html)
                .map_err(|e| format!("Failed to write coverage report: {}", e))?;
        }
        Ok(())
    }

    /// Generate crash explorer HTML
    pub fn generate_crash_explorer(&self) -> Result<(), String> {
        let mut context = TeraContext::new();
        
        // Add crash data
        context.insert("crashes", &self.crashes);
        context.insert("total_crashes", &self.crashes.len());
        
        // Group crashes by severity
        let mut by_severity: HashMap<&str, Vec<&CrashInfo>> = HashMap::new();
        for crash in &self.crashes {
            let severity = match crash.severity {
                CrashSeverity::Critical => "critical",
                CrashSeverity::High => "high",
                CrashSeverity::Medium => "medium",
                CrashSeverity::Low => "low",
            };
            by_severity.entry(severity).or_default().push(crash);
        }
        context.insert("by_severity", &by_severity);
        
        // Add timestamp
        context.insert("timestamp", &Local::now().to_rfc3339());
        
        // Render template
        let html = self.tera.render("crash_explorer.html", &context)
            .map_err(|e| format!("Failed to render crash explorer: {}", e))?;
        
        // Write to file
        let explorer_path = self.config.output_dir.join("crash_explorer.html");
        fs::write(&explorer_path, html)
            .map_err(|e| format!("Failed to write crash explorer: {}", e))?;
        
        Ok(())
    }

    /// Replay crash with expected panic pattern
    pub async fn replay_with_pattern(&self, path: &Path, expected_pattern: &str) -> Result<bool, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read crash file: {}", e))?;
        
        let crash: CrashInfo = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse crash file: {}", e))?;
        
        let input = hex::decode(&crash.input)
            .map_err(|e| format!("Failed to decode input: {}", e))?;
        
        match self.run_test_case(&input).await {
            Ok(_) => Ok(false), // No panic occurred
            Err(e) => {
                // Check if error matches expected pattern
                let matches = regex::Regex::new(expected_pattern)
                    .map_err(|e| format!("Invalid pattern: {}", e))?
                    .is_match(&e);
                
                if matches {
                    println!("✅ Panic pattern matched as expected");
                } else {
                    println!("❌ Panic pattern did not match");
                    println!("Expected: {}", expected_pattern);
                    println!("Got: {}", e);
                }
                
                Ok(matches)
            }
        }
    }

    /// Run parallelized fuzz loops
    async fn run_parallel_fuzz(&mut self) -> Result<(), String> {
        let num_threads = rayon::current_num_threads();
        let chunk_size = self.config.num_cases / num_threads;

        match &self.config.domain {
            FuzzDomain::Contract { abi, storage, modifiers } => {
                let abi = abi.clone();
                let results: Vec<Result<(), String>> = (0..num_threads)
                    .into_par_iter()
                    .map(|i| {
                        let start = i * chunk_size;
                        let end = if i == num_threads - 1 {
                            self.config.num_cases
                        } else {
                            (i + 1) * chunk_size
                        };
                        
                        let mut local_fuzzer = Fuzzer::new(self.config.clone())?;
                        local_fuzzer.fuzz_contract_range(&abi, *storage, *modifiers, start, end)
                    })
                    .collect();
                
                for result in results {
                    result?;
                }
            },
            FuzzDomain::Validator { keys, segments } => {
                let keys = keys.clone();
                let results: Vec<Result<(), String>> = (0..num_threads)
                    .into_par_iter()
                    .map(|i| {
                        let start = i * chunk_size;
                        let end = if i == num_threads - 1 {
                            self.config.num_cases
                        } else {
                            (i + 1) * chunk_size
                        };
                        
                        let mut local_fuzzer = Fuzzer::new(self.config.clone())?;
                        local_fuzzer.fuzz_validator_range(&keys, *segments, start, end)
                    })
                    .collect();
                
                for result in results {
                    result?;
                }
            },
            FuzzDomain::Sharding { cross_shard, timing } => {
                let results: Vec<Result<(), String>> = (0..num_threads)
                    .into_par_iter()
                    .map(|i| {
                        let start = i * chunk_size;
                        let end = if i == num_threads - 1 {
                            self.config.num_cases
                        } else {
                            (i + 1) * chunk_size
                        };
                        
                        let mut local_fuzzer = Fuzzer::new(self.config.clone())?;
                        local_fuzzer.fuzz_sharding_range(*cross_shard, *timing, start, end)
                    })
                    .collect();
                
                for result in results {
                    result?;
                }
            },
            FuzzDomain::Consensus { forks, votes } => {
                let results: Vec<Result<(), String>> = (0..num_threads)
                    .into_par_iter()
                    .map(|i| {
                        let start = i * chunk_size;
                        let end = if i == num_threads - 1 {
                            self.config.num_cases
        } else {
                            (i + 1) * chunk_size
                        };
                        
                        let mut local_fuzzer = Fuzzer::new(self.config.clone())?;
                        local_fuzzer.fuzz_consensus_range(*forks, *votes, start, end)
                    })
                    .collect();
                
                for result in results {
                    result?;
                }
            },
        }

        Ok(())
    }

    /// Fuzz contract range
    async fn fuzz_contract_range(&mut self, abi: &ContractAbi, storage: bool, modifiers: bool, start: usize, end: usize) -> Result<(), String> {
        let mut runner = TestRunner::new(ProptestConfig::default());
        
        for function in &abi.functions {
            let input_strategy = self.generate_abi_inputs(function)?;
            
            for _ in start..end {
                let input = input_strategy.new_tree(&mut runner)
                    .map_err(|e| format!("Failed to generate input: {}", e))?
                    .current();

                if storage {
                    self.fuzz_storage(&input).await?;
                }

                if modifiers {
                    self.fuzz_modifiers(function, &input).await?;
                }

                if let Err(e) = self.run_test_case(&input).await {
                    self.handle_crash(&input, e, "contract").await?;
                }

                self.progress.inc(1);
            }
        }

        Ok(())
    }

    /// Fuzz validator range
    async fn fuzz_validator_range(&mut self, keys: &ValidatorKeys, segments: bool, start: usize, end: usize) -> Result<(), String> {
        let mut runner = TestRunner::new(ProptestConfig::default());
        let signature_strategy = self.generate_malformed_signatures(keys)?;
        
        for _ in start..end {
            let signature = signature_strategy.new_tree(&mut runner)
                .map_err(|e| format!("Failed to generate signature: {}", e))?
                .current();

            if segments {
                self.fuzz_segments(&signature).await?;
            }

            if let Err(e) = self.run_test_case(&signature).await {
                self.handle_crash(&signature, e, "validator").await?;
            }

            self.progress.inc(1);
        }

        Ok(())
    }

    /// Fuzz sharding range
    async fn fuzz_sharding_range(&mut self, cross_shard: bool, timing: bool, start: usize, end: usize) -> Result<(), String> {
        let mut runner = TestRunner::new(ProptestConfig::default());
        let message_strategy = self.generate_cross_shard_messages()?;
        
        for _ in start..end {
            let message = message_strategy.new_tree(&mut runner)
                .map_err(|e| format!("Failed to generate message: {}", e))?
                .current();

            if timing {
                self.fuzz_timing(&message).await?;
            }

            if let Err(e) = self.run_test_case(&message).await {
                self.handle_crash(&message, e, "sharding").await?;
            }

            self.progress.inc(1);
        }

        Ok(())
    }

    /// Fuzz consensus range
    async fn fuzz_consensus_range(&mut self, forks: bool, votes: bool, start: usize, end: usize) -> Result<(), String> {
        let mut runner = TestRunner::new(ProptestConfig::default());
        let scenario_strategy = self.generate_consensus_scenarios()?;
        
        for _ in start..end {
            let scenario = scenario_strategy.new_tree(&mut runner)
                .map_err(|e| format!("Failed to generate scenario: {}", e))?
                .current();

            if forks {
                self.fuzz_forks(&scenario).await?;
            }

            if votes {
                self.fuzz_votes(&scenario).await?;
            }

            if let Err(e) = self.run_test_case(&scenario).await {
                self.handle_crash(&scenario, e, "consensus").await?;
            }

            self.progress.inc(1);
        }

        Ok(())
    }

    /// Send webhook alert for new crash
    async fn send_crash_alert(&self, crash: &CrashInfo, webhook_config: &WebhookConfig) -> Result<(), String> {
        let client = reqwest::Client::new();
        
        let payload = match webhook_config.service {
            WebhookService::Discord => {
                json!({
                    "content": format!(
                        "🚨 New crash detected!\nModule: {}\nSeverity: {:?}\nStack trace:\n```\n{}\n```",
                        crash.module,
                        crash.severity,
                        crash.stack_trace
                    ),
                    "username": webhook_config.username.as_deref().unwrap_or("KSL Fuzzer"),
                    "avatar_url": webhook_config.icon_url,
                })
            },
            WebhookService::Slack => {
                json!({
                    "text": format!(
                        "🚨 New crash detected!\nModule: {}\nSeverity: {:?}\nStack trace:\n```\n{}\n```",
                        crash.module,
                        crash.severity,
                        crash.stack_trace
                    ),
                    "username": webhook_config.username.as_deref().unwrap_or("KSL Fuzzer"),
                    "icon_url": webhook_config.icon_url,
                })
            },
            WebhookService::Custom => {
                json!({
                    "crash": crash,
                    "timestamp": SystemTime::now(),
                })
            },
        };

        client.post(&webhook_config.url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to send webhook: {}", e))?;

        Ok(())
    }

    /// Load external ABI mutator plugin
    fn load_mutator_plugin(&mut self, plugin_path: &Path) -> Result<(), String> {
        unsafe {
            let lib = libloading::Library::new(plugin_path)
                .map_err(|e| format!("Failed to load plugin: {}", e))?;
            
            let mutator_ctor: libloading::Symbol<unsafe extern "C" fn() -> Box<dyn AbiMutator>> = lib
                .get(b"create_mutator")
                .map_err(|e| format!("Failed to get mutator constructor: {}", e))?;
            
            let mutator = mutator_ctor();
            self.mutator_registry.register(mutator);
            
            Ok(())
        }
    }

    /// Apply safety sandbox
    fn apply_sandbox(&self, config: &SandboxConfig) -> Result<(), String> {
        if config.seccomp {
            // Apply seccomp filters
            seccompiler::apply_filter(&self.get_seccomp_filter())
                .map_err(|e| format!("Failed to apply seccomp filter: {}", e))?;
        }

        if let Some(chroot) = &config.chroot {
            // Apply chroot
            nix::unistd::chroot(chroot)
                .map_err(|e| format!("Failed to apply chroot: {}", e))?;
        }

        // Apply resource limits
        if let Some(max_memory) = config.resource_limits.max_memory {
            rlimit::setrlimit(rlimit::Resource::AS, max_memory as u64, max_memory as u64)
                .map_err(|e| format!("Failed to set memory limit: {}", e))?;
        }

        if let Some(max_cpu_time) = config.resource_limits.max_cpu_time {
            rlimit::setrlimit(rlimit::Resource::CPU, max_cpu_time.as_secs(), max_cpu_time.as_secs())
                .map_err(|e| format!("Failed to set CPU time limit: {}", e))?;
        }

        if let Some(max_file_size) = config.resource_limits.max_file_size {
            rlimit::setrlimit(rlimit::Resource::FSIZE, max_file_size as u64, max_file_size as u64)
                .map_err(|e| format!("Failed to set file size limit: {}", e))?;
        }

        if let Some(max_files) = config.resource_limits.max_files {
            rlimit::setrlimit(rlimit::Resource::NOFILE, max_files as u64, max_files as u64)
                .map_err(|e| format!("Failed to set file limit: {}", e))?;
        }

        if !config.network_access {
            // Block network access
            seccompiler::apply_filter(&self.get_network_filter())
                .map_err(|e| format!("Failed to block network access: {}", e))?;
        }

        Ok(())
    }

    /// Generate seccomp filter
    fn get_seccomp_filter(&self) -> Vec<u8> {
        // TODO: Implement proper seccomp filter generation
        vec![]
    }

    /// Generate network filter
    fn get_network_filter(&self) -> Vec<u8> {
        // TODO: Implement proper network filter generation
        vec![]
    }

    /// Generate trend report
    fn generate_trend_report(&self, command: &TrendReportCommand) -> Result<(), String> {
        let mut context = TeraContext::new();
        
        // Filter trends by time range
        let trends = if let Some(range) = &command.time_range {
            self.filter_trends_by_time(range)?
        } else {
            self.trends.clone()
        };
        
        context.insert("trends", &trends);
        context.insert("metrics", &command.metrics);
        
        // Generate report based on format
        match command.output_format.as_str() {
            "html" => {
                let html = self.tera.render("trend_report.html", &context)
                    .map_err(|e| format!("Failed to render trend report: {}", e))?;
                
                let report_path = self.config.output_dir.join("trend_report.html");
                fs::write(&report_path, html)
                    .map_err(|e| format!("Failed to write trend report: {}", e))?;
            },
            "json" => {
                let json = serde_json::to_string_pretty(&trends)
                    .map_err(|e| format!("Failed to serialize trends: {}", e))?;
                
                let report_path = self.config.output_dir.join("trend_report.json");
                fs::write(&report_path, json)
                    .map_err(|e| format!("Failed to write trend report: {}", e))?;
            },
            _ => return Err("Unsupported output format".to_string()),
        }
        
        Ok(())
    }

    /// Filter trends by time range
    fn filter_trends_by_time(&self, range: &str) -> Result<Vec<CoverageTrend>, String> {
        let now = SystemTime::now();
        let duration = humantime::parse_duration(range)
            .map_err(|e| format!("Invalid time range: {}", e))?;
        
        let cutoff = now - duration;
        
        Ok(self.trends.iter()
            .filter(|t| t.timestamp >= cutoff)
            .cloned()
            .collect())
    }

    /// Browse corpus
    fn browse_corpus(&self, command: &CorpusBrowserCommand) -> Result<(), String> {
        let mut context = TeraContext::new();
        
        // Load corpus data
        let corpus = self.load_corpus()?;
        
        // Apply filters
        let filtered = if let Some(filter) = &command.filter {
            self.filter_corpus(&corpus, filter)?
        } else {
            corpus
        };
        
        // Apply sorting
        let sorted = if let Some(sort_by) = &command.sort_by {
            self.sort_corpus(&filtered, sort_by)?
        } else {
            filtered
        };
        
        context.insert("corpus", &sorted);
        context.insert("view_type", &command.view_type);
        
        // Generate browser view
        let html = self.tera.render("corpus_browser.html", &context)
            .map_err(|e| format!("Failed to render corpus browser: {}", e))?;
        
        let browser_path = self.config.output_dir.join("corpus_browser.html");
        fs::write(&browser_path, html)
            .map_err(|e| format!("Failed to write corpus browser: {}", e))?;
        
        Ok(())
    }

    /// Load corpus data
    fn load_corpus(&self) -> Result<Vec<CrashInfo>, String> {
        let mut corpus = Vec::new();
        
        for entry in fs::read_dir(&self.config.corpus_dir)
            .map_err(|e| format!("Failed to read corpus directory: {}", e))? {
            let entry = entry.map_err(|e| format!("Failed to read corpus entry: {}", e))?;
            let path = entry.path();
            
            if path.extension().map_or(false, |ext| ext == "json") {
                let content = fs::read_to_string(&path)
                    .map_err(|e| format!("Failed to read corpus file: {}", e))?;
                
                let crash: CrashInfo = serde_json::from_str(&content)
                    .map_err(|e| format!("Failed to parse corpus file: {}", e))?;
                
                corpus.push(crash);
            }
        }
        
        Ok(corpus)
    }

    /// Filter corpus
    fn filter_corpus(&self, corpus: &[CrashInfo], filter: &str) -> Result<Vec<CrashInfo>, String> {
        Ok(corpus.iter()
            .filter(|c| {
                c.module.contains(filter) ||
                c.stack_trace.contains(filter) ||
                format!("{:?}", c.severity).contains(filter)
            })
            .cloned()
            .collect())
    }

    /// Sort corpus
    fn sort_corpus(&self, corpus: &[CrashInfo], sort_by: &str) -> Result<Vec<CrashInfo>, String> {
        let mut sorted = corpus.to_vec();
        
        match sort_by {
            "severity" => {
                sorted.sort_by(|a, b| b.severity.cmp(&a.severity));
            },
            "module" => {
                sorted.sort_by(|a, b| a.module.cmp(&b.module));
            },
            "timestamp" => {
                sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            },
            _ => return Err(format!("Invalid sort field: {}", sort_by)),
        }
        
        Ok(sorted)
    }
}

/// Public API to run fuzzer
pub async fn run_fuzzer(config: FuzzerConfig) -> Result<FuzzerResult, String> {
    let mut fuzzer = Fuzzer::new(config)?;
    fuzzer.run().await
}

/// Public API to run fuzzer synchronously
pub fn run_fuzzer_sync(config: FuzzerConfig) -> Result<FuzzerResult, String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create runtime: {}", e))?;
    runtime.block_on(run_fuzzer(config))
}

/// CLI wrapper for fuzzer
pub fn run_fuzzer_cli() -> Result<(), String> {
    let matches = clap::App::new("ksl-fuzz")
        .version("1.0")
        .author("KSL Team")
        .about("KSL Fuzzing Framework")
        .arg(clap::Arg::with_name("domain")
            .short('d')
            .long("domain")
            .value_name("DOMAIN")
            .help("Fuzzing domain (contract, validator, sharding, consensus)")
            .required(true)
            .takes_value(true))
        .arg(clap::Arg::with_name("cases")
            .short('c')
            .long("cases")
            .value_name("NUM")
            .help("Number of test cases")
            .default_value("1000")
            .takes_value(true))
        .arg(clap::Arg::with_name("parallel")
            .short('p')
            .long("parallel")
            .help("Run tests in parallel"))
        .arg(clap::Arg::with_name("symbolic")
            .long("symbolic")
            .help("Use symbolic execution"))
        .arg(clap::Arg::with_name("coverage")
            .long("coverage")
            .help("Track coverage"))
        .arg(clap::Arg::with_name("replay")
            .long("replay")
            .value_name("FILE")
            .help("Replay specific crash file")
            .takes_value(true))
        .arg(clap::Arg::with_name("pattern")
            .long("pattern")
            .value_name("PATTERN")
            .help("Expected panic pattern for replay")
            .takes_value(true))
        .arg(clap::Arg::with_name("output")
            .short('o')
            .long("output")
            .value_name("DIR")
            .help("Output directory")
            .default_value("fuzz_output")
            .takes_value(true))
        .arg(clap::Arg::with_name("log-level")
            .long("log-level")
            .value_name("LEVEL")
            .help("Log level (debug, info, warn, error)")
            .default_value("info")
            .takes_value(true))
        .arg(clap::Arg::with_name("shrink")
            .long("shrink")
            .help("Enable input shrinking"))
        .arg(clap::Arg::with_name("save-all")
            .long("save-all")
            .help("Save all inputs, not just failing ones"))
        .get_matches();

    // Set up logging
    let log_level = match matches.value_of("log-level").unwrap() {
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();

    // Parse domain
    let domain = match matches.value_of("domain").unwrap() {
        "contract" => FuzzDomain::Contract {
            abi: ContractAbi::default(),
            storage: true,
            modifiers: true,
        },
        "validator" => FuzzDomain::Validator {
            keys: ValidatorKeys::new(),
            segments: true,
        },
        "sharding" => FuzzDomain::Sharding {
            cross_shard: true,
            timing: true,
        },
        "consensus" => FuzzDomain::Consensus {
            forks: true,
            votes: true,
        },
        _ => return Err("Invalid domain".to_string()),
    };

    // Create output directories
    let output_dir = PathBuf::from(matches.value_of("output").unwrap());
    let corpus_dir = output_dir.join("corpus");
    let shrunk_dir = output_dir.join("shrunk");
    let coverage_dir = output_dir.join("coverage");

    fs::create_dir_all(&output_dir)?;
    fs::create_dir_all(&corpus_dir)?;
    fs::create_dir_all(&shrunk_dir)?;
    fs::create_dir_all(&coverage_dir)?;

    // Create config
    let config = FuzzerConfig {
        domain,
        num_cases: matches.value_of("cases")
            .unwrap()
            .parse()
            .map_err(|e| format!("Invalid number of cases: {}", e))?,
        parallel: matches.is_present("parallel"),
        symbolic: matches.is_present("symbolic"),
        track_coverage: matches.is_present("coverage"),
        corpus_dir,
        shrunk_dir,
        replay: matches.value_of("replay").map(PathBuf::from),
        timeout: Duration::from_secs(30),
        mutators: vec![],
        output_dir: coverage_dir,
    };

    // Run fuzzer
    log::info!("Starting fuzzer with {} test cases", config.num_cases);
    let start_time = Instant::now();
    let result = run_fuzzer_sync(config.clone())?;
    let duration = start_time.elapsed();

    // Log results
    log::info!("Fuzzing completed in {:.2}s", duration.as_secs_f64());
    log::info!("Pass rate: {:.2}%", result.pass_rate * 100.0);
    log::info!("Total cases: {}", result.total_cases);
    log::info!("Failures: {}", result.failures);
    log::info!("High risk issues: {}", result.high_risk);

    // Generate reports
    let mut fuzzer = Fuzzer::new(config)?;
    
    if result.coverage.is_some() {
        log::info!("Generating coverage report...");
        fuzzer.generate_coverage_html()?;
    }

    log::info!("Generating crash explorer...");
    fuzzer.generate_crash_explorer()?;

    // Check replay pattern if specified
    if let (Some(replay), Some(pattern)) = (matches.value_of("replay"), matches.value_of("pattern")) {
        log::info!("Replaying crash with pattern...");
        let matches = fuzzer.replay_with_pattern(Path::new(replay), pattern).await?;
        if !matches {
            return Err("Panic pattern did not match".to_string());
        }
    }

    Ok(())
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub service: WebhookService,
    pub channel: Option<String>,
    pub username: Option<String>,
    pub icon_url: Option<String>,
}

/// Webhook service type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebhookService {
    Discord,
    Slack,
    Custom,
}

/// Safety sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub seccomp: bool,
    pub chroot: Option<PathBuf>,
    pub resource_limits: ResourceLimits,
    pub network_access: bool,
}

/// Resource limits for sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory: Option<usize>,
    pub max_cpu_time: Option<Duration>,
    pub max_file_size: Option<usize>,
    pub max_files: Option<usize>,
}

/// CLI subcommand for trend report
#[derive(Debug, Clone)]
pub struct TrendReportCommand {
    pub output_format: String,
    pub time_range: Option<String>,
    pub metrics: Vec<String>,
}

/// CLI subcommand for corpus browser
#[derive(Debug, Clone)]
pub struct CorpusBrowserCommand {
    pub view_type: String,
    pub filter: Option<String>,
    pub sort_by: Option<String>,
}

/// Maximum iterations for a single fuzzing run
const MAX_ITERATIONS: usize = 10_000;

/// Maximum instructions per bytecode
const MAX_INSTRUCTIONS: usize = 50;

/// Maximum gas limit for VM execution
const MAX_GAS: u64 = 5000;

/// Fuzz the VM runtime with random bytecode
pub fn fuzz_vm_runtime(iterations: usize) -> FuzzStats {
    let mut stats = FuzzStats::default();
    let start = Instant::now();

    for i in 0..iterations.min(MAX_ITERATIONS) {
        let bytecode = random_vm_bytecode();
        let mut vm = KapraVM::new(bytecode, None, Some(MAX_GAS));
        
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            vm.run(false, false)
        }));

        match result {
            Ok(run_result) => {
                match run_result {
                    Ok(_) => stats.successes += 1,
                    Err(e) => {
                        stats.runtime_errors += 1;
                        eprintln!("⚠️ VM runtime error on iteration {}: {:?}", i, e);
                    }
                }
            }
            Err(_) => {
                stats.panics += 1;
                eprintln!("💥 Panic in VM runtime on iteration {}", i);
            }
        }

        // Check gas usage
        if let Some(gas_used) = vm.get_gas_used() {
            stats.total_gas += gas_used;
            stats.max_gas = stats.max_gas.max(gas_used);
        }
    }

    stats.duration = start.elapsed();
    stats
}

/// Generate random VM bytecode
fn random_vm_bytecode() -> KapraBytecode {
    let mut rng = thread_rng();
    let mut bytecode = KapraBytecode::new();
    
    // Available opcodes for fuzzing
    let opcodes = [
        // Arithmetic
        KapraOpCode::Add,
        KapraOpCode::Sub,
        KapraOpCode::Mul,
        KapraOpCode::Div,
        // Cryptographic
        KapraOpCode::Sha3,
        KapraOpCode::BLSVerify,
        KapraOpCode::DilithiumVerify,
        KapraOpCode::Ed25519Verify,
        KapraOpCode::MerkleVerify,
        // Control flow
        KapraOpCode::Jump,
        KapraOpCode::JumpIf,
        KapraOpCode::Call,
        KapraOpCode::Return,
        KapraOpCode::Halt,
    ];

    let num_instructions = rng.gen_range(5..MAX_INSTRUCTIONS);
    
    for _ in 0..num_instructions {
        let opcode = opcodes[rng.gen_range(0..opcodes.len())].clone();
        
        let instr = match opcode {
            // Arithmetic operations
            KapraOpCode::Add | KapraOpCode::Sub | KapraOpCode::Mul | KapraOpCode::Div => {
                KapraInstruction::new(
                    opcode,
                    vec![
                        Operand::Register(rng.gen_range(0..8)),
                        Operand::Register(rng.gen_range(0..8)),
                        Operand::Register(rng.gen_range(0..8)),
                    ],
                    Some(Type::U32),
                )
            }

            // Cryptographic operations
            KapraOpCode::Sha3 => {
                KapraInstruction::new(
                    opcode,
                    vec![
                        Operand::Register(rng.gen_range(0..8)),
                        Operand::Register(rng.gen_range(0..8)),
                    ],
                    Some(Type::Array(Box::new(Type::U8), 32)),
                )
            }

            KapraOpCode::BLSVerify => {
                KapraInstruction::new(
                    opcode,
                    vec![
                        Operand::Register(rng.gen_range(0..8)), // pubkey
                        Operand::Register(rng.gen_range(0..8)), // signature
                        Operand::Register(rng.gen_range(0..8)), // message
                    ],
                    Some(Type::Bool),
                )
            }

            KapraOpCode::DilithiumVerify | KapraOpCode::Ed25519Verify => {
                KapraInstruction::new(
                    opcode,
                    vec![
                        Operand::Register(rng.gen_range(0..8)), // pubkey
                        Operand::Register(rng.gen_range(0..8)), // signature
                        Operand::Register(rng.gen_range(0..8)), // message
                    ],
                    Some(Type::Bool),
                )
            }

            // Control flow
            KapraOpCode::Jump => {
                KapraInstruction::new(
                    opcode,
                    vec![Operand::Immediate(rng.gen_range(0..num_instructions as u64))],
                    None,
                )
            }

            KapraOpCode::JumpIf => {
                KapraInstruction::new(
                    opcode,
                    vec![
                        Operand::Register(rng.gen_range(0..8)),
                        Operand::Immediate(rng.gen_range(0..num_instructions as u64)),
                    ],
                    None,
                )
            }

            KapraOpCode::Call => {
                KapraInstruction::new(
                    opcode,
                    vec![
                        Operand::Immediate(rng.gen_range(0..num_instructions as u64)),
                        Operand::Register(rng.gen_range(0..8)),
                    ],
                    None,
                )
            }

            // Simple operations
            _ => KapraInstruction::new(opcode, vec![], None),
        };

        bytecode.add_instruction(instr);
    }

    // Always end with Halt
    bytecode.add_instruction(KapraInstruction::new(KapraOpCode::Halt, vec![], None));
    
    bytecode
}

/// Fuzz the consensus runtime with random bytecode
pub fn fuzz_consensus_runtime(iterations: usize) -> FuzzStats {
    let mut stats = FuzzStats::default();
    let start = Instant::now();

    for i in 0..iterations.min(MAX_ITERATIONS) {
        let bytecode = random_consensus_bytecode();
        let mut vm = ConsensusVM::new(8, 1000, false); // 8 shards, low threshold

        let result = panic::catch_unwind(|| vm.execute(&bytecode));
        
        match result {
            Ok(exec_result) => {
                match exec_result {
                    Ok(_) => stats.successes += 1,
                    Err(e) => {
                        stats.runtime_errors += 1;
                        eprintln!("⚠️ Consensus error on iteration {}: {:?}", i, e);
                    }
                }
            }
            Err(_) => {
                stats.panics += 1;
                eprintln!("🧨 Consensus panic on iteration {}", i);
            }
        }
    }

    stats.duration = start.elapsed();
    stats
}

/// Generate random consensus bytecode
fn random_consensus_bytecode() -> Bytecode {
    let mut rng = thread_rng();
    
    // Generate random constants
    let mut constants = vec![
        Constant::Array32([1u8; 32]), // seed
        Constant::Array32([2u8; 32]), // key
    ];

    // Add some random array constants
    for _ in 0..rng.gen_range(1..5) {
        let mut arr = [0u8; 32];
        rng.fill(&mut arr[..]);
        constants.push(Constant::Array32(arr));
    }

    // Basic consensus operations
    let mut instructions = vec![
        0x05, 0x00, // PUSH 0 (seed)
        0x05, 0x01, // PUSH 1 (key)
        0x01,       // VRF_GENERATE
        0x02,       // LEADER_ELECT
    ];

    // Add some random operations
    for _ in 0..rng.gen_range(5..15) {
        instructions.extend_from_slice(&[
            0x05, rng.gen_range(0..constants.len()) as u8, // PUSH random constant
            rng.gen_range(0x01..0x08), // Random operation
        ]);
    }

    // End with validation
    instructions.extend_from_slice(&[
        0x07, // FAIL_IF_FALSE
    ]);

    Bytecode::new(instructions, constants)
}

/// Statistics for fuzzing runs
#[derive(Debug, Default)]
pub struct FuzzStats {
    /// Number of successful executions
    pub successes: usize,
    /// Number of runtime errors
    pub runtime_errors: usize,
    /// Number of panics
    pub panics: usize,
    /// Total gas used
    pub total_gas: u64,
    /// Maximum gas used in a single execution
    pub max_gas: u64,
    /// Duration of the fuzzing run
    pub duration: Duration,
}

impl FuzzStats {
    /// Get average gas usage
    pub fn avg_gas(&self) -> f64 {
        if self.successes > 0 {
            self.total_gas as f64 / self.successes as f64
        } else {
            0.0
        }
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.successes + self.runtime_errors + self.panics;
        if total > 0 {
            self.successes as f64 / total as f64
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_contract_fuzzing() {
        let config = FuzzerConfig {
            domain: FuzzDomain::Contract {
                abi: ContractAbi {
                    name: "TestContract".to_string(),
                    functions: vec![
                        ContractFunction {
                            name: "test".to_string(),
                            parameters: vec![
                                ContractParameter {
                                    name: "x".to_string(),
                                    typ: "u32".to_string(),
                                },
                            ],
                            returns: "bool".to_string(),
                        },
                    ],
                },
                storage: true,
                modifiers: true,
            },
            num_cases: 100,
            parallel: false,
            symbolic: false,
            track_coverage: true,
            corpus_dir: PathBuf::from("fuzz_corpus"),
            shrunk_dir: PathBuf::from("shrunk"),
            replay: None,
            timeout: Duration::from_secs(1),
            mutators: vec![],
            output_dir: PathBuf::from("fuzz_output"),
        };

        let result = run_fuzzer_sync(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validator_fuzzing() {
        let config = FuzzerConfig {
            domain: FuzzDomain::Validator {
                keys: ValidatorKeys::new(),
                segments: true,
            },
            num_cases: 100,
            parallel: false,
            symbolic: false,
            track_coverage: true,
            corpus_dir: PathBuf::from("fuzz_corpus"),
            shrunk_dir: PathBuf::from("shrunk"),
            replay: None,
            timeout: Duration::from_secs(1),
            mutators: vec![],
            output_dir: PathBuf::from("fuzz_output"),
        };

        let result = run_fuzzer_sync(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sharding_fuzzing() {
        let config = FuzzerConfig {
            domain: FuzzDomain::Sharding {
                cross_shard: true,
                timing: true,
            },
            num_cases: 100,
            parallel: false,
            symbolic: false,
            track_coverage: true,
            corpus_dir: PathBuf::from("fuzz_corpus"),
            shrunk_dir: PathBuf::from("shrunk"),
            replay: None,
            timeout: Duration::from_secs(1),
            mutators: vec![],
            output_dir: PathBuf::from("fuzz_output"),
        };

        let result = run_fuzzer_sync(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_consensus_fuzzing() {
        let config = FuzzerConfig {
            domain: FuzzDomain::Consensus {
                forks: true,
                votes: true,
            },
            num_cases: 100,
            parallel: false,
            symbolic: false,
            track_coverage: true,
            corpus_dir: PathBuf::from("fuzz_corpus"),
            shrunk_dir: PathBuf::from("shrunk"),
            replay: None,
            timeout: Duration::from_secs(1),
            mutators: vec![],
            output_dir: PathBuf::from("fuzz_output"),
        };

        let result = run_fuzzer_sync(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_crash_replay() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            r#"{{"input": "deadbeef", "stack_trace": "test", "seed": 42, "module": "test", "severity": "High"}}"#
        ).unwrap();

        let config = FuzzerConfig {
            domain: FuzzDomain::Contract {
                abi: ContractAbi {
                    name: "TestContract".to_string(),
                    functions: vec![],
                },
                storage: false,
                modifiers: false,
            },
            num_cases: 1,
            parallel: false,
            symbolic: false,
            track_coverage: false,
            corpus_dir: PathBuf::from("fuzz_corpus"),
            shrunk_dir: PathBuf::from("shrunk"),
            replay: Some(temp_file.path().to_path_buf()),
            timeout: Duration::from_secs(1),
            mutators: vec![],
            output_dir: PathBuf::from("fuzz_output"),
        };

        let result = run_fuzzer_sync(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_coverage_html() {
        let config = FuzzerConfig {
            domain: FuzzDomain::Contract {
                abi: ContractAbi::default(),
                storage: false,
                modifiers: false,
            },
            num_cases: 1,
            parallel: false,
            symbolic: false,
            track_coverage: true,
            corpus_dir: PathBuf::from("fuzz_corpus"),
            shrunk_dir: PathBuf::from("shrunk"),
            replay: None,
            timeout: Duration::from_secs(1),
            mutators: vec![],
            output_dir: PathBuf::from("fuzz_output"),
        };

        let mut fuzzer = Fuzzer::new(config).unwrap();
        fuzzer.coverage = Some(CoverageInfo {
            bytecode_coverage: 0.85,
            llvm_coverage: 0.90,
            uncovered_blocks: vec!["block1".to_string()],
            hot_paths: vec!["path1".to_string()],
        });

        assert!(fuzzer.generate_coverage_html().is_ok());
    }

    #[test]
    fn test_crash_explorer() {
        let config = FuzzerConfig {
            domain: FuzzDomain::Contract {
                abi: ContractAbi::default(),
                storage: false,
                modifiers: false,
            },
            num_cases: 1,
            parallel: false,
            symbolic: false,
            track_coverage: false,
            corpus_dir: PathBuf::from("fuzz_corpus"),
            shrunk_dir: PathBuf::from("shrunk"),
            replay: None,
            timeout: Duration::from_secs(1),
            mutators: vec![],
            output_dir: PathBuf::from("fuzz_output"),
        };

        let mut fuzzer = Fuzzer::new(config).unwrap();
        fuzzer.crashes = vec![
            CrashInfo {
                input: "test".to_string(),
                stack_trace: "trace".to_string(),
                seed: 42,
                ast_diff: None,
                module: "test".to_string(),
                severity: CrashSeverity::High,
                shrunk_input: None,
            }
        ];

        assert!(fuzzer.generate_crash_explorer().is_ok());
    }

    #[test]
    fn test_replay_pattern() {
        let config = FuzzerConfig {
            domain: FuzzDomain::Contract {
                abi: ContractAbi::default(),
                storage: false,
                modifiers: false,
            },
            num_cases: 1,
            parallel: false,
            symbolic: false,
            track_coverage: false,
            corpus_dir: PathBuf::from("fuzz_corpus"),
            shrunk_dir: PathBuf::from("shrunk"),
            replay: None,
            timeout: Duration::from_secs(1),
            mutators: vec![],
            output_dir: PathBuf::from("fuzz_output"),
        };

        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            r#"{{"input": "deadbeef", "stack_trace": "panic: test", "seed": 42, "module": "test", "severity": "High"}}"#
        ).unwrap();

        let fuzzer = Fuzzer::new(config).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(fuzzer.replay_with_pattern(temp_file.path(), "panic: test"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_abi_mutator_registry() {
        struct TestMutator;
        impl AbiMutator for TestMutator {
            fn mutate(&self, abi: &mut ContractAbi) -> Result<(), String> {
                abi.name = "Mutated".to_string();
                Ok(())
            }
            fn name(&self) -> &str {
                "test_mutator"
            }
        }

        let mut registry = AbiMutatorRegistry::new();
        registry.register(Box::new(TestMutator));

        let mutator = registry.get("test_mutator").unwrap();
        let mut abi = ContractAbi::default();
        mutator.mutate(&mut abi).unwrap();
        assert_eq!(abi.name, "Mutated");
    }

    #[test]
    fn test_coverage_trend_tracker() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut tracker = CoverageTrendTracker::new(temp_dir.path().to_path_buf());

        let trend = CoverageTrend {
            timestamp: SystemTime::now(),
            bytecode_coverage: 0.85,
            llvm_coverage: 0.90,
            uncovered_blocks: vec!["block1".to_string()],
            hot_paths: vec!["path1".to_string()],
            git_commit: "abc123".to_string(),
        };

        tracker.add_trend(trend).unwrap();
        assert!(temp_dir.path().join("coverage_trends.json").exists());
    }

    #[tokio::test]
    async fn test_sharding_message_injector() {
        let injector = ShardingMessageInjector::new(vec!["node1".to_string(), "node2".to_string()]);
        injector.inject_message(vec![1, 2, 3]).await.unwrap();
        injector.process_queue().await.unwrap();
    }

    #[tokio::test]
    async fn test_webhook_alert() {
        let fuzzer = Fuzzer::new(FuzzerConfig::default()).unwrap();
        let webhook_config = WebhookConfig {
            url: "https://discord.com/api/webhooks/test".to_string(),
            service: WebhookService::Discord,
            channel: Some("fuzzer-alerts".to_string()),
            username: Some("KSL Fuzzer".to_string()),
            icon_url: Some("https://example.com/icon.png".to_string()),
        };

        let crash = CrashInfo {
            input: "test".to_string(),
            stack_trace: "test trace".to_string(),
            seed: 42,
            ast_diff: None,
            module: "test".to_string(),
            severity: CrashSeverity::High,
            shrunk_input: None,
        };

        // Note: This test will fail if the webhook URL is not valid
        let result = fuzzer.send_crash_alert(&crash, &webhook_config).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_sandbox() {
        let fuzzer = Fuzzer::new(FuzzerConfig::default()).unwrap();
        let sandbox_config = SandboxConfig {
            seccomp: true,
            chroot: Some(PathBuf::from("/tmp")),
            resource_limits: ResourceLimits {
                max_memory: Some(1024 * 1024 * 1024), // 1GB
                max_cpu_time: Some(Duration::from_secs(60)),
                max_file_size: Some(1024 * 1024), // 1MB
                max_files: Some(100),
            },
            network_access: false,
        };

        // Note: This test requires root privileges
        let result = fuzzer.apply_sandbox(&sandbox_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_trend_report() {
        let fuzzer = Fuzzer::new(FuzzerConfig::default()).unwrap();
        let command = TrendReportCommand {
            output_format: "json".to_string(),
            time_range: Some("1d".to_string()),
            metrics: vec!["bytecode_coverage".to_string(), "llvm_coverage".to_string()],
        };

        let result = fuzzer.generate_trend_report(&command);
        assert!(result.is_ok());
    }

    #[test]
    fn test_corpus_browser() {
        let fuzzer = Fuzzer::new(FuzzerConfig::default()).unwrap();
        let command = CorpusBrowserCommand {
            view_type: "table".to_string(),
            filter: Some("test".to_string()),
            sort_by: Some("severity".to_string()),
        };

        let result = fuzzer.browse_corpus(&command);
        assert!(result.is_ok());
    }
}