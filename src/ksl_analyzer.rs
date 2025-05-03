// ksl_analyzer.rs
// Implements a dynamic analysis tool to profile KSL programs for performance and resource usage.

use crate::ksl_parser::parse;
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, Duration};
use std::collections::HashMap;

// Profiling data for a single instruction
#[derive(Debug)]
struct InstructionProfile {
    count: u64,
    total_time: Duration,
}

// Profiling data for a function
#[derive(Debug)]
struct FunctionProfile {
    name: String,
    calls: u64,
    total_time: Duration,
    instructions: HashMap<u32, InstructionProfile>,
}

// Analyzer state
pub struct Analyzer {
    module_system: ModuleSystem,
    profiles: Vec<FunctionProfile>,
}

impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            module_system: ModuleSystem::new(),
            profiles: Vec::new(),
        }
    }

    // Analyze a KSL file
    pub fn analyze_file(&mut self, file: &PathBuf) -> Result<(), Vec<KslError>> {
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

        // Run with profiling
        let mut vm = KapraVM::new_with_profiling(bytecode.clone());
        let start = Instant::now();
        vm.run()
            .map_err(|e| vec![KslError::type_error(
                format!("Runtime error at instruction {}: {}", e.pc, e.message),
                SourcePosition::new(1, 1),
            )])?;
        let total_duration = start.elapsed();

        // Collect function profiles
        let mut function_profiles = HashMap::new();
        for (fn_index, profile) in vm.function_profiles {
            let fn_name = ast.iter()
                .filter_map(|node| {
                    if let AstNode::FnDecl { name, .. } = node {
                        Some(name.clone())
                    } else {
                        None
                    }
                })
                .nth(fn_index as usize)
                .unwrap_or(format!("fn_{}", fn_index));
            function_profiles.insert(fn_index, FunctionProfile {
                name: fn_name,
                calls: profile.calls,
                total_time: profile.total_time,
                instructions: profile.instructions,
            });
        }

        self.profiles = function_profiles.into_values().collect();

        // Generate report
        println!("Analysis Report for {}", file.display());
        println!("Total execution time: {:.2?}", total_duration);
        println!("Memory usage: {} bytes", vm.memory.values().map(|v| v.len()).sum::<usize>());
        println!("\nFunction Profiles:");
        for profile in &self.profiles {
            println!(
                "{}: {} calls, {:.2?} ({:.2}% of total)",
                profile.name,
                profile.calls,
                profile.total_time,
                (profile.total_time.as_secs_f64() / total_duration.as_secs_f64()) * 100.0
            );
            println!("  Top Instructions:");
            let mut instrs: Vec<_> = profile.instructions.iter().collect();
            instrs.sort_by(|a, b| b.1.total_time.cmp(&a.1.total_time));
            for (index, instr) in instrs.iter().take(3) {
                let op = bytecode.instructions[*index as usize].opcode;
                println!(
                    "    0x{:04x}: {:?} ({} calls, {:.2?})",
                    index, op, instr.count, instr.total_time
                );
            }
        }

        Ok(())
    }
}

// Public API to analyze a KSL file
pub fn analyze(file: &PathBuf) -> Result<(), Vec<KslError>> {
    let mut analyzer = Analyzer::new();
    analyzer.analyze_file(file)
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, ksl_module.rs, and ksl_errors.rs are in the same crate
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
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode};
}

mod kapra_vm {
    pub use super::{KapraVM, RuntimeError};
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
    fn test_analyze_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn compute() { let x: u32 = 42; let y: u32 = x + x; }"
        ).unwrap();

        let result = analyze(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
        let analyzer = Analyzer::new();
        assert!(!analyzer.profiles.is_empty());
        assert!(analyzer.profiles.iter().any(|p| p.name == "compute"));
    }

    #[test]
    fn test_analyze_empty_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "").unwrap();

        let result = analyze(&temp_file.path().to_path_buf());
        assert!(result.is_ok()); // Empty file is valid but no profiles
    }
}