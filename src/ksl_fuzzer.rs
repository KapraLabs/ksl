// ksl_fuzzer.rs
// Implements a fuzz testing framework for KSL programs to detect edge cases and improve robustness.

use crate::ksl_parser::{parse, AstNode, TypeAnnotation};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::kapra_vm::run;
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_types::Type;
use rand::{Rng, rngs::StdRng, SeedableRng};
use std::fs;
use std::path::PathBuf;
use std::collections::HashMap;

// Fuzz test result
#[derive(Debug)]
pub struct FuzzResult {
    pub function: String,
    pub inputs: Vec<Vec<u8>>,
    pub error: String,
}

// Fuzzer state
pub struct Fuzzer {
    module_system: ModuleSystem,
    results: Vec<FuzzResult>,
    rng: StdRng,
}

impl Fuzzer {
    pub fn new(seed: Option<u64>) -> Self {
        let rng = match seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => StdRng::from_entropy(),
        };
        Fuzzer {
            module_system: ModuleSystem::new(),
            results: Vec::new(),
            rng,
        }
    }

    // Run fuzz tests on a KSL file
    pub fn fuzz_file(&mut self, file: &PathBuf, iterations: usize) -> Result<(), Vec<KslError>> {
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
        let fuzz_functions: Vec<(String, Vec<TypeAnnotation>)> = ast.iter()
            .filter_map(|node| {
                if let AstNode::FnDecl { attributes, name, params, .. } = node {
                    if attributes.iter().any(|attr| attr.name == "fuzz") {
                        Some((name.clone(), params.iter().map(|(_, t)| t.clone()).collect()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Run fuzz tests
        for (fn_name, param_types) in fuzz_functions {
            for _ in 0..iterations {
                let result = self.fuzz_function(&bytecode, &fn_name, &param_types);
                if let Some(result) = result {
                    self.results.push(result);
                }
            }
        }

        // Report results
        println!("Fuzz Test Results for {} ({} iterations per function):", file.display(), iterations);
        if self.results.is_empty() {
            println!("No issues found");
        } else {
            println!("Found {} issues:", self.results.len());
            for result in &self.results {
                println!(
                    "{}: Failed with inputs {:?}, error: {}",
                    result.function, result.inputs, result.error
                );
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

    // Fuzz a single function
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

        // Find function index (simplified: assume function exists)
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

        // Run and check for errors
        match run(fuzz_bytecode) {
            Ok(_) => None,
            Err(e) => Some(FuzzResult {
                function: fn_name.to_string(),
                inputs,
                error: format!("Runtime error at instruction {}: {}", e.pc, e.message),
            }),
        }
    }

    // Generate random input for a type
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
            TypeAnnotation::Array { element, size } if element == "u8" => {
                let len = *size as usize;
                let mut bytes = vec![0; len];
                self.rng.fill_bytes(&mut bytes);
                bytes
            }
            _ => vec![], // Unsupported type
        }
    }

    // Convert TypeAnnotation to Type (simplified)
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
            TypeAnnotation::Array { element, size } if element == "u8" => Type::Array(Box::new(Type::U8), size),
            _ => Type::Void,
        }
    }
}

// Public API to fuzz a KSL file
pub fn fuzz(file: &PathBuf, iterations: Option<usize>, seed: Option<u64>) -> Result<(), Vec<KslError>> {
    let mut fuzzer = Fuzzer::new(seed);
    fuzzer.fuzz_file(file, iterations.unwrap_or(100))
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, ksl_module.rs, ksl_types.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, TypeAnnotation};
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

mod ksl_module {
    pub use super::ModuleSystem;
}

mod ksl_types {
    pub use super::Type;
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
    fn test_fuzz_function() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[fuzz]\nfn test_div(x: u32, y: u32): u32 { if y == 0 { assert(false); } x / y; }"
        ).unwrap();

        let result = fuzz(&temp_file.path().to_path_buf(), Some(100), Some(42));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(!errors.is_empty());
        assert!(errors[0].to_string().contains("test_div"));
    }

    #[test]
    fn test_fuzz_no_functions() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "fn add(x: u32, y: u32): u32 { x + y; }").unwrap();

        let result = fuzz(&temp_file.path().to_path_buf(), Some(100), None);
        assert!(result.is_ok());
    }
}