// ksl_bench.rs
// Implements a benchmarking framework for KSL programs to measure performance.

use crate::ksl_parser::{parse, AstNode};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::kapra_vm::{KapraVM, run};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, Duration};

// Benchmark result representation
#[derive(Debug)]
pub struct BenchmarkResult {
    pub name: String,
    pub duration: Duration,
    pub instructions: u64,
    pub memory_usage: usize, // Bytes allocated
}

// Benchmark runner state
pub struct BenchmarkRunner {
    module_system: ModuleSystem,
    results: Vec<BenchmarkResult>,
}

impl BenchmarkRunner {
    pub fn new() -> Self {
        BenchmarkRunner {
            module_system: ModuleSystem::new(),
            results: Vec::new(),
        }
    }

    // Run benchmarks in a KSL file
    pub fn run_benchmarks(&mut self, file: &PathBuf) -> Result<(), Vec<KslError>> {
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

        // Find benchmark functions (functions with #[bench] attribute)
        let bench_functions: Vec<String> = ast.iter()
            .filter_map(|node| {
                if let AstNode::FnDecl { attributes, name, .. } = node {
                    if attributes.iter().any(|attr| attr.name == "bench") {
                        Some(name.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Run each benchmark
        for bench_name in bench_functions {
            let result = self.run_benchmark(&bytecode, &bench_name);
            self.results.push(result);
        }

        // Report results
        println!("Benchmark results:");
        for result in &self.results {
            println!(
                "{}: {:.2?} ({} instructions, {} bytes)",
                result.name,
                result.duration,
                result.instructions,
                result.memory_usage
            );
        }

        if self.results.is_empty() {
            Err(vec![KslError::type_error(
                "No benchmark functions found".to_string(),
                SourcePosition::new(1, 1),
            )])
        } else {
            Ok(())
        }
    }

    // Run a single benchmark
    fn run_benchmark(&self, bytecode: &KapraBytecode, bench_name: &str) -> BenchmarkResult {
        // Create a modified bytecode that calls the benchmark function
        let mut bench_bytecode = KapraBytecode::new();

        // Find function index (simplified: assume function exists)
        let fn_index = bytecode.instructions.iter()
            .position(|instr| instr.opcode == KapraOpCode::Call && matches!(&instr.operands[0], Operand::Immediate(data) if String::from_utf8(data.clone()).unwrap_or_default().contains(bench_name)))
            .unwrap_or(0) as u32;

        // Add call to benchmark function
        bench_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Call,
            vec![Operand::Immediate(fn_index.to_le_bytes().to_vec())],
            None,
        ));
        bench_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        // Run benchmark with profiling
        let start = Instant::now();
        let mut vm = KapraVM::new(bench_bytecode.clone());
        let mut instructions = 0;
        let result = vm.run().map_err(|e| {
            vec![KslError::type_error(
                format!("Runtime error at instruction {}: {}", e.pc, e.message),
                SourcePosition::new(1, 1),
            )]
        });

        // Count instructions (simplified: assumes single run)
        instructions += bytecode.instructions.len() as u64;

        // Estimate memory usage (simplified: register and memory size)
        let memory_usage = vm.registers.iter().map(|r| r.len()).sum::<usize>() +
                          vm.memory.values().map(|v| v.len()).sum::<usize>();

        BenchmarkResult {
            name: bench_name.to_string(),
            duration: start.elapsed(),
            instructions,
            memory_usage,
        }
    }
}

// Public API to run benchmarks
pub fn run_benchmarks(file: &PathBuf) -> Result<(), Vec<KslError>> {
    let mut runner = BenchmarkRunner::new();
    runner.run_benchmarks(file)
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, ksl_module.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode};
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
    pub use super::{KapraVM, run};
}

mod ksl_module {
    pub use super::ModuleSystem;
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
    fn test_run_benchmark() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[bench]\nfn bench_add() { let x: u32 = 42; let y: u32 = x + x; }"
        ).unwrap();

        let result = run_benchmarks(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
        let runner = BenchmarkRunner::new();
        assert_eq!(runner.results.len(), 1);
        assert_eq!(runner.results[0].name, "bench_add");
        assert!(runner.results[0].duration.as_nanos() > 0);
        assert!(runner.results[0].instructions > 0);
    }

    #[test]
    fn test_no_benchmarks() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn add() { let x: u32 = 42; let y: u32 = x + x; }"
        ).unwrap();

        let result = run_benchmarks(&temp_file.path().to_path_buf());
        assert!(result.is_err());
        assert!(result.unwrap_err()[0].to_string().contains("No benchmark functions found"));
    }
}