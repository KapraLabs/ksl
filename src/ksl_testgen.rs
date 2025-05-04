/// ksl_testgen.rs
/// Automatically generates unit tests for KSL code, analyzing functions to produce
/// #[test]-annotated test cases with edge cases, property-based testing, and async tests.
/// Supports advanced type system features and async test generation.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_types::{Type, TypeSystem, TypeConstraint, TypeInfo};
use crate::ksl_test::{TestRunner, TestCase, TestResult, TestSuite};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for test generation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestGenConfig {
    /// Source file to analyze
    pub input_file: PathBuf,
    /// Directory for generated tests
    pub output_dir: PathBuf,
    /// Maximum number of test cases per function
    pub max_test_cases: usize,
    /// Whether to generate async tests
    pub generate_async: bool,
    /// Type system constraints
    pub type_constraints: Vec<TypeConstraint>,
}

/// Test generation state
#[derive(Debug)]
struct TestGenState {
    /// Type system for type checking
    type_system: Arc<TypeSystem>,
    /// Test runner for executing tests
    test_runner: Arc<TestRunner>,
    /// Async runtime for async tests
    async_runtime: Arc<AsyncRuntime>,
    /// Generated test suites
    test_suites: Vec<TestSuite>,
}

/// Test generator with async support
pub struct TestGen {
    /// Generator configuration
    config: TestGenConfig,
    /// Generator state
    state: Arc<RwLock<TestGenState>>,
}

impl TestGen {
    /// Creates a new test generator instance
    pub fn new(config: TestGenConfig) -> Result<Self, KslError> {
        let state = TestGenState {
            type_system: Arc::new(TypeSystem::new(config.type_constraints.clone())?),
            test_runner: Arc::new(TestRunner::new()),
            async_runtime: Arc::new(AsyncRuntime::new()),
            test_suites: Vec::new(),
        };

        Ok(TestGen {
            config,
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// Generates tests asynchronously
    pub async fn generate_tests_async(&self) -> AsyncResult<()> {
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
            match node {
                AstNode::FnDecl { name, params, return_type, is_async, .. } => {
                    self.generate_function_tests(name, params, return_type, *is_async).await?;
                }
                _ => continue,
            }
        }

        // Write test suites
        let state = self.state.read().await;
        for suite in &state.test_suites {
            self.write_test_suite(suite).await?;
        }

        Ok(())
    }

    /// Generates tests for a specific function
    async fn generate_function_tests(
        &self,
        name: &str,
        params: &[(String, Type)],
        return_type: &Type,
        is_async: bool,
    ) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        let mut test_suite = TestSuite::new(name.to_string());

        // Get type information
        let state = self.state.read().await;
        let type_info = state.type_system.get_type_info(return_type)
            .map_err(|e| KslError::type_error(format!("Type error: {}", e), pos))?;

        // Generate standard test cases
        test_suite.add_test(self.generate_basic_test(name, params, return_type, is_async)?);
        test_suite.add_test(self.generate_edge_case_test(name, params, return_type, is_async)?);
        test_suite.add_test(self.generate_property_test(name, params, return_type, is_async)?);

        // Generate async test cases if needed
        if is_async || self.config.generate_async {
            test_suite.add_test(self.generate_async_test(name, params, return_type)?);
            test_suite.add_test(self.generate_concurrent_test(name, params, return_type)?);
        }

        // Add type-specific tests
        match type_info {
            TypeInfo::Numeric { .. } => {
                test_suite.add_test(self.generate_numeric_test(name, params, return_type)?);
            }
            TypeInfo::Array { .. } => {
                test_suite.add_test(self.generate_array_test(name, params, return_type)?);
            }
            TypeInfo::Result { .. } => {
                test_suite.add_test(self.generate_error_test(name, params, return_type)?);
            }
            _ => {}
        }

        // Store test suite
        let mut state = self.state.write().await;
        state.test_suites.push(test_suite);

        Ok(())
    }

    /// Generates a basic test case
    fn generate_basic_test(
        &self,
        name: &str,
        params: &[(String, Type)],
        return_type: &Type,
        is_async: bool,
    ) -> Result<TestCase, KslError> {
        let mut test = TestCase::new(format!("test_{}_basic", name));
        test.is_async = is_async;

        // Generate test code
        let mut code = String::new();
        if is_async {
            code.push_str("#[tokio::test]\nasync ");
        } else {
            code.push_str("#[test]\n");
        }
        code.push_str(&format!("fn test_{}_basic() {{\n", name));

        // Add parameter initialization
        for (param_name, param_type) in params {
            let value = self.generate_default_value(param_type)?;
            code.push_str(&format!("    let {} = {};\n", param_name, value));
        }

        // Add function call
        let args = params.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>().join(", ");
        if is_async {
            code.push_str(&format!("    let result = {name}({args}).await;\n"));
        } else {
            code.push_str(&format!("    let result = {name}({args});\n"));
        }

        // Add assertions
        code.push_str("    assert!(result.is_ok());\n");
        code.push_str("}\n");

        test.code = code;
        Ok(test)
    }

    /// Generates an async test case
    fn generate_async_test(
        &self,
        name: &str,
        params: &[(String, Type)],
        return_type: &Type,
    ) -> Result<TestCase, KslError> {
        let mut test = TestCase::new(format!("test_{}_async", name));
        test.is_async = true;

        // Generate test code
        let mut code = String::new();
        code.push_str("#[tokio::test]\n");
        code.push_str(&format!("async fn test_{}_async() {{\n", name));

        // Add concurrent parameter initialization
        code.push_str("    let (");
        let param_names: Vec<_> = params.iter().map(|(name, _)| name).collect();
        code.push_str(&param_names.join(", "));
        code.push_str(") = tokio::join!(\n");
        for (name, typ) in params {
            let value = self.generate_async_value(typ)?;
            code.push_str(&format!("        async {{ {} }},\n", value));
        }
        code.push_str("    );\n\n");

        // Add function call
        let args = param_names.join(", ");
        code.push_str(&format!("    let result = {name}({args}).await;\n"));

        // Add assertions
        code.push_str("    assert!(result.is_ok());\n");
        code.push_str("}\n");

        test.code = code;
        Ok(test)
    }

    /// Generates a concurrent test case
    fn generate_concurrent_test(
        &self,
        name: &str,
        params: &[(String, Type)],
        return_type: &Type,
    ) -> Result<TestCase, KslError> {
        let mut test = TestCase::new(format!("test_{}_concurrent", name));
        test.is_async = true;

        // Generate test code
        let mut code = String::new();
        code.push_str("#[tokio::test]\n");
        code.push_str(&format!("async fn test_{}_concurrent() {{\n", name));
        code.push_str("    let mut handles = Vec::new();\n\n");

        // Spawn multiple concurrent calls
        code.push_str("    for _ in 0..10 {\n");
        for (param_name, param_type) in params {
            let value = self.generate_default_value(param_type)?;
            code.push_str(&format!("        let {} = {};\n", param_name, value));
        }
        let args = params.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>().join(", ");
        code.push_str(&format!("        let handle = tokio::spawn(async move {{\n"));
        code.push_str(&format!("            {name}({args}).await\n"));
        code.push_str("        });\n");
        code.push_str("        handles.push(handle);\n");
        code.push_str("    }\n\n");

        // Wait for all calls to complete
        code.push_str("    for handle in handles {\n");
        code.push_str("        let result = handle.await.unwrap();\n");
        code.push_str("        assert!(result.is_ok());\n");
        code.push_str("    }\n");
        code.push_str("}\n");

        test.code = code;
        Ok(test)
    }

    /// Writes a test suite to a file
    async fn write_test_suite(&self, suite: &TestSuite) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        let output_path = self.config.output_dir.join(format!("test_{}.rs", suite.name));
        
        let mut code = String::new();
        code.push_str("// Generated by KSL Test Generator\n\n");
        code.push_str("use super::*;\n\n");

        for test in &suite.tests {
            code.push_str(&test.code);
            code.push_str("\n");
        }

        fs::write(&output_path, code)
            .map_err(|e| KslError::type_error(
                format!("Failed to write test file {}: {}", output_path.display(), e),
                pos,
            ))?;

        Ok(())
    }

    /// Generates a default value for a type
    fn generate_default_value(&self, typ: &Type) -> Result<String, KslError> {
        match typ {
            Type::U32 => Ok("42".to_string()),
            Type::F64 => Ok("3.14".to_string()),
            Type::Bool => Ok("true".to_string()),
            Type::String => Ok("\"test\".to_string()".to_string()),
            Type::Array(element_type, size) => {
                let default = self.generate_default_value(element_type)?;
                Ok(format!("vec![{}; {}]", default, size))
            }
            Type::Result(ok_type, err_type) => {
                let ok_value = self.generate_default_value(ok_type)?;
                Ok(format!("Ok({})", ok_value))
            }
            _ => Err(KslError::type_error(
                format!("Unsupported type for default value: {:?}", typ),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Generates an async value for a type
    fn generate_async_value(&self, typ: &Type) -> Result<String, KslError> {
        match typ {
            Type::U32 => Ok("42".to_string()),
            Type::F64 => Ok("3.14".to_string()),
            Type::Bool => Ok("true".to_string()),
            Type::String => Ok("\"test\".to_string()".to_string()),
            Type::Array(element_type, size) => {
                let default = self.generate_async_value(element_type)?;
                Ok(format!("vec![{}; {}]", default, size))
            }
            Type::Result(ok_type, err_type) => {
                let ok_value = self.generate_async_value(ok_type)?;
                Ok(format!("Ok({})", ok_value))
            }
            _ => Err(KslError::type_error(
                format!("Unsupported type for async value: {:?}", typ),
                SourcePosition::new(1, 1),
            )),
        }
    }
}

/// Public API to generate tests asynchronously
pub async fn generate_tests_async(config: TestGenConfig) -> AsyncResult<()> {
    let generator = TestGen::new(config)?;
    generator.generate_tests_async().await
}

// Module imports
mod ksl_parser {
    pub use super::{parse, AstNode, ParseError};
}

mod ksl_types {
    pub use super::{Type, TypeSystem, TypeConstraint, TypeInfo};
}

mod ksl_test {
    pub use super::{TestRunner, TestCase, TestResult, TestSuite};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncResult};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_generate_async_tests() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_dir = temp_dir.path().join("tests");

        // Create test input file
        fs::write(&input_file, r#"
            async fn test_function(x: u32) -> Result<u32, String> {
                Ok(x + 1)
            }
        "#).unwrap();

        let config = TestGenConfig {
            input_file,
            output_dir,
            max_test_cases: 10,
            generate_async: true,
            type_constraints: vec![],
        };

        let result = generate_tests_async(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_concurrent_tests() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_dir = temp_dir.path().join("tests");

        // Create test input file
        fs::write(&input_file, r#"
            async fn concurrent_function(x: u32, y: u32) -> Result<u32, String> {
                Ok(x + y)
            }
        "#).unwrap();

        let config = TestGenConfig {
            input_file,
            output_dir,
            max_test_cases: 10,
            generate_async: true,
            type_constraints: vec![],
        };

        let result = generate_tests_async(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_type_specific_tests() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_dir = temp_dir.path().join("tests");

        // Create test input file
        fs::write(&input_file, r#"
            fn array_function(arr: [u8; 10]) -> Result<u32, String> {
                Ok(arr.len() as u32)
            }
        "#).unwrap();

        let config = TestGenConfig {
            input_file,
            output_dir,
            max_test_cases: 10,
            generate_async: false,
            type_constraints: vec![],
        };

        let result = generate_tests_async(config).await;
        assert!(result.is_ok());
    }
}
