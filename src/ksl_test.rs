// ksl_test.rs
// Implements a testing framework for KSL programs.

use crate::ksl_parser::parse;
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::KapraBytecode;
use crate::kapra_vm::run;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs;

// Test result type
#[derive(Debug, PartialEq)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub error: Option<String>,
}

// Test runner state
pub struct TestRunner {
    results: Vec<TestResult>,
}

impl TestRunner {
    pub fn new() -> Self {
        TestRunner {
            results: Vec::new(),
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

        // Find test functions (simplified: functions starting with "test_")
        let test_functions: Vec<String> = ast.iter()
            .filter_map(|node| {
                if let crate::ksl_parser::AstNode::FnDecl { name, .. } = node {
                    if name.starts_with("test_") {
                        Some(name.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Run each test function
        for test_name in test_functions {
            let result = self.run_test(&bytecode, &test_name);
            self.results.push(result);
        }

        // Report results
        let passed = self.results.iter().filter(|r| r.passed).count();
        let total = self.results.len();
        println!("Test results: {} passed, {} failed", passed, total - passed);
        for result in &self.results {
            if result.passed {
                println!("✓ {}: Passed", result.name);
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
    fn run_test(&self, bytecode: &KapraBytecode, test_name: &str) -> TestResult {
        // Create a modified bytecode that calls the test function
        let mut test_bytecode = KapraBytecode::new();
        
        // Find function index (simplified: assume function exists)
        let fn_index = bytecode.instructions.iter()
            .position(|instr| instr.opcode == KapraOpCode::Call && matches!(&instr.operands[0], Operand::Immediate(data) if String::from_utf8(data.clone()).unwrap_or_default().contains(test_name)))
            .unwrap_or(0) as u32;

        // Add call to test function
        test_bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Call,
            vec![Operand::Immediate(fn_index.to_le_bytes().to_vec())],
            None,
        ));
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
            },
            Err(e) => TestResult {
                name: test_name.to_string(),
                passed: false,
                error: Some(format!("Runtime error at instruction {}: {}", e.pc, e.message)),
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
}