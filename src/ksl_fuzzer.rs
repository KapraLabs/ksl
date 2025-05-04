/// ksl_fuzzer.rs
/// Implements fuzz testing to ensure KSL compiler and VM robustness, supporting async execution,
/// new language features, and comprehensive test integration.

use crate::ksl_parser::{parse, AstNode, TypeAnnotation};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_types::Type;
use crate::ksl_test::{TestRunner, TestResult};
use crate::ksl_async::{AsyncRuntime, AsyncVM};
use rand::{Rng, rngs::StdRng, SeedableRng};
use std::fs;
use std::path::PathBuf;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

/// Enhanced fuzz test result with async and network metrics
#[derive(Debug)]
pub struct FuzzResult {
    /// Function being tested
    pub function: String,
    /// Test inputs
    pub inputs: Vec<Vec<u8>>,
    /// Error message if test failed
    pub error: String,
    /// Async execution metrics
    pub async_metrics: Option<AsyncMetrics>,
    /// Network operation metrics
    pub network_metrics: Option<NetworkMetrics>,
}

/// Async execution metrics for fuzzing
#[derive(Debug)]
pub struct AsyncMetrics {
    /// Number of async tasks created
    pub tasks_created: u32,
    /// Number of tasks completed
    pub tasks_completed: u32,
    /// Maximum concurrent tasks
    pub max_concurrent_tasks: u32,
    /// Task durations
    pub task_durations: Vec<std::time::Duration>,
}

/// Network operation metrics for fuzzing
#[derive(Debug)]
pub struct NetworkMetrics {
    /// Number of network requests
    pub requests: u32,
    /// Number of responses
    pub responses: u32,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Network latencies
    pub latencies: Vec<std::time::Duration>,
    /// Number of errors
    pub errors: u32,
}

/// Enhanced fuzzer configuration
#[derive(Debug)]
pub struct FuzzerConfig {
    /// Random number generator seed
    pub seed: Option<u64>,
    /// Number of iterations per function
    pub iterations: usize,
    /// Whether to enable async fuzzing
    pub enable_async: bool,
    /// Whether to fuzz network operations
    pub fuzz_network: bool,
    /// Maximum async tasks per test
    pub max_async_tasks: u32,
    /// Network timeout duration
    pub network_timeout: std::time::Duration,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        FuzzerConfig {
            seed: None,
            iterations: 100,
            enable_async: false,
            fuzz_network: false,
            max_async_tasks: 10,
            network_timeout: std::time::Duration::from_secs(5),
        }
    }
}

/// Enhanced fuzzer with async support and test integration
pub struct Fuzzer {
    config: FuzzerConfig,
    module_system: ModuleSystem,
    results: Vec<FuzzResult>,
    rng: StdRng,
    test_runner: Option<TestRunner>,
    async_runtime: Option<Arc<RwLock<AsyncRuntime>>>,
}

impl Fuzzer {
    /// Create a new fuzzer with the given configuration
    pub fn new(config: FuzzerConfig) -> Self {
        let rng = match config.seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };
        let async_runtime = if config.enable_async {
            Some(Arc::new(RwLock::new(AsyncRuntime::new())))
        } else {
            None
        };
        Fuzzer {
            config,
            module_system: ModuleSystem::new(),
            results: Vec::new(),
            rng,
            test_runner: Some(TestRunner::new()),
            async_runtime,
        }
    }

    /// Run fuzz tests on a KSL file with async support
    pub async fn fuzz_file(&mut self, file: &PathBuf) -> Result<(), Vec<KslError>> {
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| vec![KslError::type_error(
                "Invalid main file name".to_string(),
                SourcePosition::new(1, 1),
            )])?;

        // Read source file
        let source = fs::read_to_string(file)
            .map_err(|e| vec![KslError::type_error(e.to_string(), SourcePosition::new(1, 1))])?;

        // Parse
        let ast = parse(&source)
            .map_err(|e| vec![KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                SourcePosition::new(1, 1),
            )])?;

        // Type-check
        check(&ast)
            .map_err(|errors| errors)?;

        // Compile
        let bytecode = compile(&ast)
            .map_err(|errors| errors.into_iter().map(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1))).collect())?;

        // Find fuzzable functions (functions with #[fuzz] attribute)
        let fuzz_functions: Vec<(String, Vec<TypeAnnotation>, bool)> = ast.iter()
            .filter_map(|node| {
                match node {
                    AstNode::FnDecl { attributes, name, params, .. } => {
                        if attributes.iter().any(|attr| attr.name == "fuzz") {
                            Some((name.clone(), params.iter().map(|(_, t)| t.clone()).collect(), false))
                        } else {
                            None
                        }
                    }
                    AstNode::AsyncFnDecl { attributes, name, params, .. } => {
                        if attributes.iter().any(|attr| attr.name == "fuzz") {
                            Some((name.clone(), params.iter().map(|(_, t)| t.clone()).collect(), true))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            })
            .collect();

        // Run fuzz tests
        for (fn_name, param_types, is_async) in fuzz_functions {
            for _ in 0..self.config.iterations {
                let result = if is_async && self.config.enable_async {
                    self.fuzz_async_function(&bytecode, &fn_name, &param_types).await
                } else {
                    self.fuzz_function(&bytecode, &fn_name, &param_types)
                };
                if let Some(result) = result {
                    self.results.push(result);
                }
            }
        }

        // Report results
        println!("Fuzz Test Results for {} ({} iterations per function):", file.display(), self.config.iterations);
        if self.results.is_empty() {
            println!("No issues found");
        } else {
            println!("Found {} issues:", self.results.len());
            for result in &self.results {
                println!(
                    "{}: Failed with inputs {:?}, error: {}",
                    result.function, result.inputs, result.error
                );
                if let Some(async_metrics) = &result.async_metrics {
                    println!(
                        "  Async Metrics: {} tasks created, {} completed, {} max concurrent",
                        async_metrics.tasks_created,
                        async_metrics.tasks_completed,
                        async_metrics.max_concurrent_tasks
                    );
                }
                if let Some(network_metrics) = &result.network_metrics {
                    println!(
                        "  Network Metrics: {} requests, {} responses, {} bytes sent/received, {} errors",
                        network_metrics.requests,
                        network_metrics.responses,
                        network_metrics.bytes_sent + network_metrics.bytes_received,
                        network_metrics.errors
                    );
                }
            }
        }

        if self.results.is_empty() {
            Ok(())
        } else {
            Err(self.results.iter().map(|r| KslError::type_error(
                format!("Fuzz failure in {}: {}", r.function, r.error),
                SourcePosition::new(1, 1),
            )).collect())
        }
    }

    /// Fuzz an async function
    async fn fuzz_async_function(&mut self, bytecode: &KapraBytecode, fn_name: &str, param_types: &[TypeAnnotation]) -> Option<FuzzResult> {
        // Generate random inputs
        let inputs: Vec<Vec<u8>> = param_types.iter().map(|ty| self.generate_input(ty)).collect();

        // Create bytecode to call the function with inputs
        let mut fuzz_bytecode = KapraBytecode::new();
        let mut registers = vec![];
        for (i, input) in inputs.iter().enumerate() {
            let reg = i as u8;
            registers.push(reg);
            fuzz_bytecode.add_instruction(KapraInstruction::new(
                KapraOpCode::Mov,
                vec![
                    Operand::Register(reg),
                    Operand::Immediate(input.clone()),
                ],
                Some(self.type_annotation_to_type(param_types[i].clone())),
            ));
        }

        // Find function index
        let fn_index = bytecode.instructions.iter()
            .position(|instr| instr.opcode == KapraOpCode::AsyncCall && matches!(&instr.operands[0], Operand::Immediate(data) if String::from_utf8(data.clone()).unwrap_or_default().contains(fn_name)))
            .unwrap_or(0) as u32;

        // Add async call to function
        fuzz_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::AsyncCall,
            vec![Operand::Immediate(fn_index.to_le_bytes().to_vec())],
            None,
        ));
        fuzz_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        // Run with async support and collect metrics
        let runtime = self.async_runtime.as_ref().unwrap().clone();
        let mut vm = KapraVM::new_async(fuzz_bytecode, runtime);
        let mut async_metrics = AsyncMetrics {
            tasks_created: 0,
            tasks_completed: 0,
            max_concurrent_tasks: 0,
            task_durations: Vec::new(),
        };
        let mut network_metrics = NetworkMetrics {
            requests: 0,
            responses: 0,
            bytes_sent: 0,
            bytes_received: 0,
            latencies: Vec::new(),
            errors: 0,
        };

        match vm.run_async().await {
            Ok(_) => None,
            Err(e) => {
                // Collect metrics from VM
                if let Some(metrics) = vm.get_async_metrics() {
                    async_metrics.tasks_created = metrics.tasks_created;
                    async_metrics.tasks_completed = metrics.tasks_completed;
                    async_metrics.max_concurrent_tasks = metrics.max_concurrent_tasks;
                    async_metrics.task_durations = metrics.task_durations;
                }
                if let Some(metrics) = vm.get_network_metrics() {
                    network_metrics.requests = metrics.requests;
                    network_metrics.responses = metrics.responses;
                    network_metrics.bytes_sent = metrics.bytes_sent;
                    network_metrics.bytes_received = metrics.bytes_received;
                    network_metrics.latencies = metrics.latencies;
                    network_metrics.errors = metrics.errors;
                }

                Some(FuzzResult {
                    function: fn_name.to_string(),
                    inputs,
                    error: format!("Runtime error at instruction {}: {}", e.pc, e.message),
                    async_metrics: Some(async_metrics),
                    network_metrics: if self.config.fuzz_network { Some(network_metrics) } else { None },
                })
            }
        }
    }

    /// Fuzz a synchronous function
    fn fuzz_function(&mut self, bytecode: &KapraBytecode, fn_name: &str, param_types: &[TypeAnnotation]) -> Option<FuzzResult> {
        // Generate random inputs
        let inputs: Vec<Vec<u8>> = param_types.iter().map(|ty| self.generate_input(ty)).collect();

        // Create bytecode to call the function with inputs
        let mut fuzz_bytecode = KapraBytecode::new();
        let mut registers = vec![];
        for (i, input) in inputs.iter().enumerate() {
            let reg = i as u8;
            registers.push(reg);
            fuzz_bytecode.add_instruction(KapraInstruction::new(
                KapraOpCode::Mov,
                vec![
                    Operand::Register(reg),
                    Operand::Immediate(input.clone()),
                ],
                Some(self.type_annotation_to_type(param_types[i].clone())),
            ));
        }

        // Find function index
        let fn_index = bytecode.instructions.iter()
            .position(|instr| instr.opcode == KapraOpCode::Call && matches!(&instr.operands[0], Operand::Immediate(data) if String::from_utf8(data.clone()).unwrap_or_default().contains(fn_name)))
            .unwrap_or(0) as u32;

        // Add call to function
        fuzz_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Call,
            vec![Operand::Immediate(fn_index.to_le_bytes().to_vec())],
            None,
        ));
        fuzz_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        // Run and collect metrics
        let mut vm = KapraVM::new(fuzz_bytecode);
        let mut network_metrics = if self.config.fuzz_network {
            Some(NetworkMetrics {
                requests: 0,
                responses: 0,
                bytes_sent: 0,
                bytes_received: 0,
                latencies: Vec::new(),
                errors: 0,
            })
        } else {
            None
        };

        match vm.run() {
            Ok(_) => None,
            Err(e) => {
                // Collect network metrics if enabled
                if let Some(metrics) = network_metrics.as_mut() {
                    if let Some(vm_metrics) = vm.get_network_metrics() {
                        metrics.requests = vm_metrics.requests;
                        metrics.responses = vm_metrics.responses;
                        metrics.bytes_sent = vm_metrics.bytes_sent;
                        metrics.bytes_received = vm_metrics.bytes_received;
                        metrics.latencies = vm_metrics.latencies;
                        metrics.errors = vm_metrics.errors;
                    }
                }

                Some(FuzzResult {
                    function: fn_name.to_string(),
                    inputs,
                    error: format!("Runtime error at instruction {}: {}", e.pc, e.message),
                    async_metrics: None,
                    network_metrics,
                })
            }
        }
    }

    /// Generate random input for a type
    fn generate_input(&mut self, ty: &TypeAnnotation) -> Vec<u8> {
        match ty {
            TypeAnnotation::Simple(name) => match name.as_str() {
                "u32" => {
                    let value: u32 = self.rng.gen();
                    value.to_le_bytes().to_vec()
                }
                "f32" => {
                    let value: f32 = self.rng.gen_range(-1000.0..1000.0);
                    value.to_le_bytes().to_vec()
                }
                "f64" => {
                    let value: f64 = self.rng.gen_range(-1000.0..1000.0);
                    value.to_le_bytes().to_vec()
                }
                "bool" => {
                    let value: bool = self.rng.gen();
                    (value as u32).to_le_bytes().to_vec()
                }
                "string" => {
                    let len = self.rng.gen_range(0..100);
                    let chars: String = (0..len)
                        .map(|_| self.rng.gen_range(b'a'..=b'z') as char)
                        .collect();
                    chars.into_bytes()
                }
                _ => vec![], // Unsupported type
            },
            TypeAnnotation::Array { element, size } => match element.as_str() {
                "u8" => {
                    let len = *size as usize;
                    let mut bytes = vec![0; len];
                    self.rng.fill_bytes(&mut bytes);
                    bytes
                }
                "u32" => {
                    let len = *size as usize;
                    let values: Vec<u32> = (0..len).map(|_| self.rng.gen()).collect();
                    values.iter().flat_map(|v| v.to_le_bytes().to_vec()).collect()
                }
                "f32" => {
                    let len = *size as usize;
                    let values: Vec<f32> = (0..len).map(|_| self.rng.gen_range(-1000.0..1000.0)).collect();
                    values.iter().flat_map(|v| v.to_le_bytes().to_vec()).collect()
                }
                _ => vec![], // Unsupported type
            },
            _ => vec![], // Unsupported type
        }
    }

    /// Convert TypeAnnotation to Type
    fn type_annotation_to_type(&self, annot: TypeAnnotation) -> Type {
        match annot {
            TypeAnnotation::Simple(name) => match name.as_str() {
                "u32" => Type::U32,
                "f32" => Type::F32,
                "f64" => Type::F64,
                "bool" => Type::Bool,
                "string" => Type::String,
                _ => Type::Void,
            },
            TypeAnnotation::Array { element, size } => match element.as_str() {
                "u8" => Type::Array(Box::new(Type::U8), size),
                "u32" => Type::Array(Box::new(Type::U32), size),
                "f32" => Type::Array(Box::new(Type::F32), size),
                _ => Type::Void,
            },
            _ => Type::Void,
        }
    }
}

/// Public API to fuzz a KSL file with async support
pub async fn fuzz(
    file: &PathBuf,
    config: Option<FuzzerConfig>
) -> Result<(), Vec<KslError>> {
    let config = config.unwrap_or_default();
    let mut fuzzer = Fuzzer::new(config);
    fuzzer.fuzz_file(file).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio;

    #[tokio::test]
    async fn test_fuzz_async_function() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[fuzz]\nasync fn test_async(x: u32) {{ if x == 0 {{ panic!(); }} await async_task(x); }}\nasync fn async_task(x: u32) {{ if x > 1000 {{ panic!(); }} }}"
        ).unwrap();

        let config = FuzzerConfig {
            iterations: 100,
            enable_async: true,
            fuzz_network: false,
            ..Default::default()
        };

        let result = fuzz(&temp_file.path().to_path_buf(), Some(config)).await;
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(!errors.is_empty());
        assert!(errors[0].to_string().contains("test_async"));
    }

    #[tokio::test]
    async fn test_fuzz_network_function() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[fuzz]\nfn test_network(url: string) {{ let response = http_get(url); if response.status != 200 {{ panic!(); }} }}"
        ).unwrap();

        let config = FuzzerConfig {
            iterations: 50,
            enable_async: false,
            fuzz_network: true,
            ..Default::default()
        };

        let result = fuzz(&temp_file.path().to_path_buf(), Some(config)).await;
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(!errors.is_empty());
        assert!(errors[0].to_string().contains("test_network"));
    }

    #[tokio::test]
    async fn test_fuzz_no_functions() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn add(x: u32, y: u32): u32 {{ x + y }}"
        ).unwrap();

        let result = fuzz(&temp_file.path().to_path_buf(), None).await;
        assert!(result.is_ok());
    }
}