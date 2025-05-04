/// ksl_transpiler.rs
/// Transpiles KSL code to other languages like Rust, Python, or JavaScript,
/// enabling cross-platform use through AST transformation and async code generation.
/// Supports advanced language features and async/await patterns.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_ast_transform::{transform, TransformRule, AstTransformer};
use crate::ksl_compiler::{compile, CompileConfig, CompileTarget};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Supported transpilation targets
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum TranspileTarget {
    /// Rust with async/await support
    Rust,
    /// Python with asyncio
    Python,
    /// JavaScript with Promises
    JavaScript,
    /// TypeScript with async/await
    TypeScript,
}

/// Configuration for transpilation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TranspilerConfig {
    /// Source KSL file
    pub input_file: PathBuf,
    /// Output file (e.g., output.rs, output.py)
    pub output_file: PathBuf,
    /// Target language
    pub target: TranspileTarget,
    /// Whether to generate async code
    pub generate_async: bool,
    /// AST transformation rules
    pub transform_rules: Vec<TransformRule>,
    /// Compiler configuration
    pub compile_config: CompileConfig,
}

/// Transpiler state
#[derive(Debug)]
struct TranspilerState {
    /// AST transformer
    transformer: Arc<AstTransformer>,
    /// Async runtime
    async_runtime: Arc<AsyncRuntime>,
    /// Generated code cache
    code_cache: std::collections::HashMap<String, String>,
}

/// Transpiler with async support
pub struct Transpiler {
    /// Transpiler configuration
    config: TranspilerConfig,
    /// Transpiler state
    state: Arc<RwLock<TranspilerState>>,
}

impl Transpiler {
    /// Creates a new transpiler instance
    pub fn new(config: TranspilerConfig) -> Result<Self, KslError> {
        let state = TranspilerState {
            transformer: Arc::new(AstTransformer::new(config.transform_rules.clone())?),
            async_runtime: Arc::new(AsyncRuntime::new()),
            code_cache: std::collections::HashMap::new(),
        };

        Ok(Transpiler {
            config,
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// Transpiles code asynchronously
    pub async fn transpile_async(&self) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        
        // Read and parse source
        let source = fs::read_to_string(&self.config.input_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", self.config.input_file.display(), e),
                pos,
            ))?;
        let mut ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;

        // Transform AST
        let state = self.state.read().await;
        ast = state.transformer.transform_async(&ast).await?;

        // Compile with target-specific config
        let compile_config = CompileConfig {
            target: match self.config.target {
                TranspileTarget::Rust => CompileTarget::Rust,
                TranspileTarget::Python => CompileTarget::Python,
                TranspileTarget::JavaScript => CompileTarget::JavaScript,
                TranspileTarget::TypeScript => CompileTarget::TypeScript,
            },
            ..self.config.compile_config.clone()
        };
        let bytecode = compile(&ast, &compile_config)?;

        // Generate target code
        let output_code = match self.config.target {
            TranspileTarget::Rust => self.transpile_to_rust_async(&ast).await?,
            TranspileTarget::Python => self.transpile_to_python_async(&ast).await?,
            TranspileTarget::JavaScript => self.transpile_to_js_async(&ast).await?,
            TranspileTarget::TypeScript => self.transpile_to_ts_async(&ast).await?,
        };

        // Write output
        fs::write(&self.config.output_file, output_code)
            .map_err(|e| KslError::type_error(
                format!("Failed to write output file {}: {}", self.config.output_file.display(), e),
                pos,
            ))?;

        Ok(())
    }

    /// Transpiles to Rust asynchronously
    async fn transpile_to_rust_async(&self, ast: &[AstNode]) -> AsyncResult<String> {
        let mut code = String::new();
        code.push_str("// Generated Rust code from KSL\n\n");
        code.push_str("use tokio;\n");
        code.push_str("use std::sync::Arc;\n\n");

        for node in ast {
            match node {
                AstNode::FnDecl { name, params, return_type, body, is_async, .. } => {
                    // Add async marker if needed
                    if *is_async || self.config.generate_async {
                        code.push_str("#[tokio::main]\n");
                        code.push_str("pub async ");
                    } else {
                        code.push_str("pub ");
                    }

                    // Function signature
                    code.push_str(&format!("fn {}(", name));
                    let param_strings: Vec<String> = params.iter()
                        .map(|(name, typ)| format!("{}: {}", name, self.type_to_rust(typ)?))
                        .collect();
                    code.push_str(&param_strings.join(", "));
                    code.push_str(&format!(") -> {} {{\n", self.type_to_rust(return_type)?));

                    // Function body
                    code.push_str(&self.transpile_rust_body_async(body).await?);
                    code.push_str("}\n\n");
                }
                _ => continue,
            }
        }

        Ok(code)
    }

    /// Transpiles to Python asynchronously
    async fn transpile_to_python_async(&self, ast: &[AstNode]) -> AsyncResult<String> {
        let mut code = String::new();
        code.push_str("# Generated Python code from KSL\n\n");
        code.push_str("import asyncio\n");
        code.push_str("from typing import Optional, List, Dict\n\n");

        for node in ast {
            match node {
                AstNode::FnDecl { name, params, body, is_async, .. } => {
                    // Add async marker if needed
                    if *is_async || self.config.generate_async {
                        code.push_str("async ");
                    }

                    // Function signature
                    code.push_str(&format!("def {}(", name));
                    let param_strings: Vec<String> = params.iter()
                        .map(|(name, typ)| format!("{}: {}", name, self.type_to_python(typ)?))
                        .collect();
                    code.push_str(&param_strings.join(", "));
                    code.push_str("):\n");

                    // Function body
                    code.push_str(&self.transpile_python_body_async(body).await?);
                    code.push_str("\n");
                }
                _ => continue,
            }
        }

        Ok(code)
    }

    /// Transpiles to JavaScript asynchronously
    async fn transpile_to_js_async(&self, ast: &[AstNode]) -> AsyncResult<String> {
        let mut code = String::new();
        code.push_str("// Generated JavaScript code from KSL\n\n");

        for node in ast {
            match node {
                AstNode::FnDecl { name, params, body, is_async, .. } => {
                    // Add async marker if needed
                    if *is_async || self.config.generate_async {
                        code.push_str("async ");
                    }

                    // Function signature
                    code.push_str(&format!("function {}(", name));
                    let param_strings: Vec<String> = params.iter()
                        .map(|(name, _)| name.clone())
                        .collect();
                    code.push_str(&param_strings.join(", "));
                    code.push_str(") {\n");

                    // Function body
                    code.push_str(&self.transpile_js_body_async(body).await?);
                    code.push_str("}\n\n");
                }
                _ => continue,
            }
        }

        Ok(code)
    }

    /// Transpiles to TypeScript asynchronously
    async fn transpile_to_ts_async(&self, ast: &[AstNode]) -> AsyncResult<String> {
        let mut code = String::new();
        code.push_str("// Generated TypeScript code from KSL\n\n");

        for node in ast {
            match node {
                AstNode::FnDecl { name, params, return_type, body, is_async, .. } => {
                    // Add async marker if needed
                    if *is_async || self.config.generate_async {
                        code.push_str("async ");
                    }

                    // Function signature
                    code.push_str(&format!("function {}(", name));
                    let param_strings: Vec<String> = params.iter()
                        .map(|(name, typ)| format!("{}: {}", name, self.type_to_ts(typ)?))
                        .collect();
                    code.push_str(&param_strings.join(", "));
                    code.push_str(&format!("): {} {{\n", self.type_to_ts(return_type)?));

                    // Function body
                    code.push_str(&self.transpile_ts_body_async(body).await?);
                    code.push_str("}\n\n");
                }
                _ => continue,
            }
        }

        Ok(code)
    }

    /// Converts KSL type to Rust type
    fn type_to_rust(&self, typ: &Type) -> Result<String, KslError> {
        match typ {
            Type::U32 => Ok("u32".to_string()),
            Type::F64 => Ok("f64".to_string()),
            Type::Bool => Ok("bool".to_string()),
            Type::String => Ok("String".to_string()),
            Type::Array(element_type, size) => {
                let rust_type = self.type_to_rust(element_type)?;
                Ok(format!("[{}; {}]", rust_type, size))
            }
            Type::Result(ok_type, err_type) => {
                let ok_rust = self.type_to_rust(ok_type)?;
                let err_rust = self.type_to_rust(err_type)?;
                Ok(format!("Result<{}, {}>", ok_rust, err_rust))
            }
            _ => Err(KslError::type_error(
                format!("Unsupported type for Rust: {:?}", typ),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Converts KSL type to Python type
    fn type_to_python(&self, typ: &Type) -> Result<String, KslError> {
        match typ {
            Type::U32 => Ok("int".to_string()),
            Type::F64 => Ok("float".to_string()),
            Type::Bool => Ok("bool".to_string()),
            Type::String => Ok("str".to_string()),
            Type::Array(element_type, _) => {
                let py_type = self.type_to_python(element_type)?;
                Ok(format!("List[{}]", py_type))
            }
            Type::Result(ok_type, err_type) => {
                let ok_py = self.type_to_python(ok_type)?;
                let err_py = self.type_to_python(err_type)?;
                Ok(format!("Optional[{}]", ok_py))
            }
            _ => Err(KslError::type_error(
                format!("Unsupported type for Python: {:?}", typ),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Converts KSL type to TypeScript type
    fn type_to_ts(&self, typ: &Type) -> Result<String, KslError> {
        match typ {
            Type::U32 => Ok("number".to_string()),
            Type::F64 => Ok("number".to_string()),
            Type::Bool => Ok("boolean".to_string()),
            Type::String => Ok("string".to_string()),
            Type::Array(element_type, _) => {
                let ts_type = self.type_to_ts(element_type)?;
                Ok(format!("{}[]", ts_type))
            }
            Type::Result(ok_type, err_type) => {
                let ok_ts = self.type_to_ts(ok_type)?;
                let err_ts = self.type_to_ts(err_type)?;
                Ok(format!("Promise<{}>", ok_ts))
            }
            _ => Err(KslError::type_error(
                format!("Unsupported type for TypeScript: {:?}", typ),
                SourcePosition::new(1, 1),
            )),
        }
    }
}

/// Public API to transpile code asynchronously
pub async fn transpile_async(config: TranspilerConfig) -> AsyncResult<()> {
    let transpiler = Transpiler::new(config)?;
    transpiler.transpile_async().await
}

// Module imports
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, ParseError};
}

mod ksl_ast_transform {
    pub use super::{transform, TransformRule, AstTransformer};
}

mod ksl_compiler {
    pub use super::{compile, CompileConfig, CompileTarget};
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
    async fn test_transpile_rust_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_file = temp_dir.path().join("output.rs");

        // Create test input file
        fs::write(&input_file, r#"
            async fn test_function(x: u32) -> Result<u32, String> {
                Ok(x + 1)
            }
        "#).unwrap();

        let config = TranspilerConfig {
            input_file,
            output_file,
            target: TranspileTarget::Rust,
            generate_async: true,
            transform_rules: vec![],
            compile_config: CompileConfig::default(),
        };

        let result = transpile_async(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_transpile_python_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_file = temp_dir.path().join("output.py");

        // Create test input file
        fs::write(&input_file, r#"
            async fn process_data(data: Array<u8>) -> Result<u32, String> {
                Ok(data.len())
            }
        "#).unwrap();

        let config = TranspilerConfig {
            input_file,
            output_file,
            target: TranspileTarget::Python,
            generate_async: true,
            transform_rules: vec![],
            compile_config: CompileConfig::default(),
        };

        let result = transpile_async(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_transpile_typescript_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let output_file = temp_dir.path().join("output.ts");

        // Create test input file
        fs::write(&input_file, r#"
            async fn fetch_data(url: String) -> Result<String, String> {
                Ok("data")
            }
        "#).unwrap();

        let config = TranspilerConfig {
            input_file,
            output_file,
            target: TranspileTarget::TypeScript,
            generate_async: true,
            transform_rules: vec![],
            compile_config: CompileConfig::default(),
        };

        let result = transpile_async(config).await;
        assert!(result.is_ok());
    }
}
