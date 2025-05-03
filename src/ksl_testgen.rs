// ksl_testgen.rs
// Automatically generates unit tests for KSL code, analyzing functions to produce
// #[test]-annotated test cases with edge cases and property-based testing.

use crate::ksl_parser::{parse, AstNode, TypeAnnotation, ParseError};
use crate::ksl_errors::{KslError, SourcePosition};
use rand::Rng;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

// Test generator configuration
#[derive(Debug)]
pub struct TestGenConfig {
    input_file: PathBuf, // Source file to analyze
    output_dir: PathBuf, // Directory for generated tests
}

// Test generator
pub struct TestGen {
    config: TestGenConfig,
}

impl TestGen {
    pub fn new(config: TestGenConfig) -> Self {
        TestGen { config }
    }

    // Generate unit tests for a KSL source file
    pub fn generate_tests(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Read and parse source
        let source = fs::read_to_string(&self.config.input_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", self.config.input_file.display(), e),
                pos,
            ))?;
        let ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;

        // Create output directory
        fs::create_dir_all(&self.config.output_dir)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output directory {}: {}", self.config.output_dir.display(), e),
                pos,
            ))?;

        // Generate tests for each function
        for node in &ast {
            if let AstNode::FnDecl { name, params, return_type, .. } = node {
                self.generate_test_for_function(name, params, return_type)?;
            }
        }

        Ok(())
    }

    // Generate a test file for a specific function
    fn generate_test_for_function(&self, name: &str, params: &[(String, TypeAnnotation)], return_type: &TypeAnnotation) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut test_code = String::new();

        // Basic test
        test_code.push_str(&format!("#[test]\nfn test_{}() {{\n", name));
        let mut args = vec![];
        for (param_name, param_type) in params {
            let arg = match param_type {
                TypeAnnotation::Simple(typ) => match typ.as_str() {
                    "u32" => "42",
                    "f64" => "3.14",
                    "bool" => "true",
                    "string" => "\"test\"",
                    _ => return Err(KslError::type_error(
                        format!("Unsupported parameter type: {}", typ),
                        pos,
                    )),
                },
                TypeAnnotation::Array { element, size } => {
                    match element.as_str() {
                        "u8" => &format!("[0; {}]", size),
                        _ => return Err(KslError::type_error(
                            format!("Unsupported array element type: {}", element),
                            pos,
                        )),
                    }
                }
                _ => return Err(KslError::type_error(
                    "Unsupported parameter type".to_string(),
                    pos,
                )),
            };
            test_code.push_str(&format!("    let {} = {};\n", param_name, arg));
            args.push(param_name.to_string());
        }
        test_code.push_str(&format!("    let result = {}({});\n", name, args.join(", ")));
        test_code.push_str("    // Add assertions here\n");
        test_code.push_str("}\n\n");

        // Edge case test
        test_code.push_str(&format!("#[test]\nfn test_{}_edge_cases() {{\n", name));
        let mut edge_args = vec![];
        for (param_name, param_type) in params {
            let edge_arg = match param_type {
                TypeAnnotation::Simple(typ) => match typ.as_str() {
                    "u32" => "0", // Edge case: zero
                    "f64" => "0.0",
                    "bool" => "false",
                    "string" => "\"\"",
                    _ => return Err(KslError::type_error(
                        format!("Unsupported parameter type: {}", typ),
                        pos,
                    )),
                },
                TypeAnnotation::Array { element, size } => {
                    match element.as_str() {
                        "u8" => &format!("[255; {}]", size), // Edge case: max value
                        _ => return Err(KslError::type_error(
                            format!("Unsupported array element type: {}", element),
                            pos,
                        )),
                    }
                }
                _ => return Err(KslError::type_error(
                    "Unsupported parameter type".to_string(),
                    pos,
                )),
            };
            test_code.push_str(&format!("    let {} = {};\n", param_name, edge_arg));
            edge_args.push(param_name.to_string());
        }
        test_code.push_str(&format!("    let result = {}({});\n", name, edge_args.join(", ")));
        test_code.push_str("    // Add assertions here\n");
        test_code.push_str("}\n\n");

        // Property-based test
        test_code.push_str(&format!("#[test]\nfn test_{}_property() {{\n", name));
        let mut rand_args = vec![];
        for (param_name, param_type) in params {
            let rand_arg = match param_type {
                TypeAnnotation::Simple(typ) => match typ.as_str() {
                    "u32" => {
                        let val = rand::thread_rng().gen_range(0..1000);
                        format!("{}", val)
                    }
                    "f64" => {
                        let val = rand::thread_rng().gen_range(0.0..1000.0);
                        format!("{}", val)
                    }
                    "bool" => {
                        let val = rand::thread_rng().gen::<bool>();
                        format!("{}", val)
                    }
                    "string" => {
                        let val: String = rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric)
                            .take(10)
                            .map(char::from)
                            .collect();
                        format!("\"{}\"", val)
                    }
                    _ => return Err(KslError::type_error(
                        format!("Unsupported parameter type: {}", typ),
                        pos,
                    )),
                },
                TypeAnnotation::Array { element, size } => {
                    match element.as_str() {
                        "u8" => {
                            let vals: Vec<u8> = (0..*size).map(|_| rand::thread_rng().gen()).collect();
                            format!("[{}; {}]", vals.iter().map(|v| v.to_string()).collect::<Vec<String>>().join(", "), size)
                        }
                        _ => return Err(KslError::type_error(
                            format!("Unsupported array element type: {}", element),
                            pos,
                        )),
                    }
                }
                _ => return Err(KslError::type_error(
                    "Unsupported parameter type".to_string(),
                    pos,
                )),
            };
            test_code.push_str(&format!("    let {} = {};\n", param_name, rand_arg));
            rand_args.push(param_name.to_string());
        }
        test_code.push_str(&format!("    let result = {}({});\n", name, rand_args.join(", ")));
        test_code.push_str("    // Add assertions here\n");
        test_code.push_str("}\n");

        // Write test file
        let output_path = self.config.output_dir.join(format!("test_{}.ksl", name));
        File::create(&output_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create test file {}: {}", output_path.display(), e),
                pos,
            ))?
            .write_all(test_code.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write test file {}: {}", output_path.display(), e),
                pos,
            ))?;

        Ok(())
    }
}

// Public API to generate tests
pub fn generate_tests(input_file: &PathBuf, output_dir: PathBuf) -> Result<(), KslError> {
    let config = TestGenConfig {
        input_file: input_file.clone(),
        output_dir,
    };
    let testgen = TestGen::new(config);
    testgen.generate_tests()
}

// Assume ksl_parser.rs and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, TypeAnnotation, ParseError};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_generate_tests() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn add(x: u32, y: u32): u32 {{ x + y }}\nfn divide(a: f64, b: f64): f64 {{ a / b }}"
        ).unwrap();

        let output_dir = temp_dir.path().join("tests");
        let result = generate_tests(&input_file, output_dir.clone());
        assert!(result.is_ok());

        // Check add tests
        let add_test_file = output_dir.join("test_add.ksl");
        let content = fs::read_to_string(&add_test_file).unwrap();
        assert!(content.contains("#[test]\nfn test_add()"));
        assert!(content.contains("let x = 42;\n    let y = 42;"));
        assert!(content.contains("#[test]\nfn test_add_edge_cases()"));
        assert!(content.contains("let x = 0;\n    let y = 0;"));
        assert!(content.contains("#[test]\nfn test_add_property()"));

        // Check divide tests
        let divide_test_file = output_dir.join("test_divide.ksl");
        let content = fs::read_to_string(&divide_test_file).unwrap();
        assert!(content.contains("#[test]\nfn test_divide()"));
        assert!(content.contains("let a = 3.14;\n    let b = 3.14;"));
        assert!(content.contains("#[test]\nfn test_divide_edge_cases()"));
        assert!(content.contains("let a = 0.0;\n    let b = 0.0;"));
        assert!(content.contains("#[test]\nfn test_divide_property()"));
    }

    #[test]
    fn test_generate_tests_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("nonexistent.ksl");
        let output_dir = temp_dir.path().join("tests");

        let result = generate_tests(&input_file, output_dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }

    #[test]
    fn test_generate_tests_unsupported_type() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn unsupported(x: invalid_type): u32 {{ 0 }}"
        ).unwrap();

        let output_dir = temp_dir.path().join("tests");
        let result = generate_tests(&input_file, output_dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported parameter type"));
    }
}
