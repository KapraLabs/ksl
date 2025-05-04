// ksl_bind.rs
// Implements a Foreign Function Interface (FFI) binding generator for KSL programs.

//! Binding management for KSL variables and functions.
//! 
//! This module handles the binding of KSL variables and functions, which is critical for semantic analysis.
//! It supports both synchronous and asynchronous binding operations, and integrates with the analyzer
//! for type checking and validation.
//! 
//! # Binding Rules
//! 
//! The binding system follows these rules:
//! 1. Variables must be declared before use
//! 2. Functions can be forward-declared
//! 3. Types must be compatible in assignments
//! 4. Async functions must be marked with `async` keyword
//! 5. Extern functions must have compatible signatures
//! 
//! # Example
//! ```ksl
//! // Variable binding
//! let x: u32 = 42;
//! 
//! // Function binding
//! fn add(a: u32, b: u32): u32 {
//!     return a + b;
//! }
//! 
//! // Async function binding
//! async fn fetch_data(): string {
//!     // async implementation
//! }
//! ```

use crate::ksl_parser::{AstNode, TypeAnnotation};
use crate::ksl_ast_transform::{TransformedAstNode, AsyncNode};
use crate::ksl_analyzer::{Analyzer, AnalysisResult};
use crate::ksl_types::Type;
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::collections::HashMap;
use async_trait::async_trait;
use tokio::fs as tokio_fs;
use tokio::io::AsyncWriteExt;

/// Binding output types
#[derive(Debug)]
pub enum BindingType {
    CHeader, // Generate C header file (.h)
    RustModule, // Generate Rust module (.rs)
}

/// Binding generator state
pub struct BindingGenerator {
    module_system: ModuleSystem,
    bindings: Vec<String>,
    analyzer: Analyzer,
    symbol_table: HashMap<String, Type>,
}

impl BindingGenerator {
    /// Creates a new BindingGenerator instance
    pub fn new() -> Self {
        BindingGenerator {
            module_system: ModuleSystem::new(),
            bindings: Vec::new(),
            analyzer: Analyzer::new(),
            symbol_table: HashMap::new(),
        }
    }

    /// Generates bindings for a KSL file
    pub fn generate_bindings(&mut self, file: &PathBuf, output: &PathBuf, binding_type: BindingType) -> Result<(), KslError> {
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KslError::type_error(
                "Invalid main file name".to_string(),
                SourcePosition::new(1, 1),
            ))?;

        // Load modules
        self.module_system.load_module(main_module_name, file)?;

        // Generate bindings
        self.bindings.clear();
        let ast = self.module_system.link(main_module_name)?;
        
        // Analyze AST
        let analysis_result = self.analyzer.analyze(&ast)?;
        if !analysis_result.is_valid() {
            return Err(KslError::type_error(
                "AST analysis failed".to_string(),
                SourcePosition::new(1, 1),
            ));
        }

        // Generate bindings for each node
        for node in &ast {
            self.generate_node_binding(node, &binding_type)?;
        }

        // Write bindings to output file
        fs::create_dir_all(output.parent().unwrap_or(output))
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let output_file = match binding_type {
            BindingType::CHeader => output.join(format!("{}.h", main_module_name)),
            BindingType::RustModule => output.join(format!("{}.rs", main_module_name)),
        };
        let mut file = File::create(&output_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let binding_content = self.bindings.join("\n");
        file.write_all(binding_content.as_bytes())
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        Ok(())
    }

    /// Generates binding for an AST node
    fn generate_node_binding(&mut self, node: &AstNode, binding_type: &BindingType) -> Result<(), KslError> {
        match node {
            AstNode::FnDecl { attributes, name, params, return_type, .. } => {
                if attributes.iter().any(|attr| attr.name == "extern") {
                    match binding_type {
                        BindingType::CHeader => {
                            let c_return = self.type_to_c(return_type)?;
                            let c_params = params.iter()
                                .map(|(p_name, p_type)| Ok(format!("{} {}", self.type_to_c(p_type)?, p_name)))
                                .collect::<Result<Vec<_>, KslError>>()?
                                .join(", ");
                            self.bindings.push(format!(
                                "{} {}({});",
                                c_return, name, c_params
                            ));
                        }
                        BindingType::RustModule => {
                            let rust_return = self.type_to_rust(return_type)?;
                            let rust_params = params.iter()
                                .map(|(p_name, p_type)| Ok(format!("{}: {}", p_name, self.type_to_rust(p_type)?)))
                                .collect::<Result<Vec<_>, KslError>>()?
                                .join(", ");
                            self.bindings.push(format!(
                                "extern \"C\" fn {}({}) -> {};",
                                name, rust_params, rust_return
                            ));
                        }
                    }
                }
            }
            AstNode::ExternDecl { name, type_annot } => {
                if let Some(annot) = type_annot {
                    match binding_type {
                        BindingType::CHeader => {
                            let c_return = self.type_to_c(annot)?;
                            self.bindings.push(format!(
                                "{} {}();",
                                c_return, name
                            ));
                        }
                        BindingType::RustModule => {
                            let rust_return = self.type_to_rust(annot)?;
                            self.bindings.push(format!(
                                "extern \"C\" fn {}() -> {};",
                                name, rust_return
                            ));
                        }
                    }
                }
            }
            AstNode::AsyncFnDecl { attributes, name, params, return_type, .. } => {
                if attributes.iter().any(|attr| attr.name == "extern") {
                    match binding_type {
                        BindingType::CHeader => {
                            let c_return = self.type_to_c(return_type)?;
                            let c_params = params.iter()
                                .map(|(p_name, p_type)| Ok(format!("{} {}", self.type_to_c(p_type)?, p_name)))
                                .collect::<Result<Vec<_>, KslError>>()?
                                .join(", ");
                            self.bindings.push(format!(
                                "{} {}({});",
                                c_return, name, c_params
                            ));
                        }
                        BindingType::RustModule => {
                            let rust_return = self.type_to_rust(return_type)?;
                            let rust_params = params.iter()
                                .map(|(p_name, p_type)| Ok(format!("{}: {}", p_name, self.type_to_rust(p_type)?)))
                                .collect::<Result<Vec<_>, KslError>>()?
                                .join(", ");
                            self.bindings.push(format!(
                                "extern \"C\" async fn {}({}) -> {};",
                                name, rust_params, rust_return
                            ));
                        }
                    }
                }
            }
            _ => {} // Ignore other nodes
        }
        Ok(())
    }

    /// Converts KSL TypeAnnotation to C type
    fn type_to_c(&self, annot: &TypeAnnotation) -> Result<String, KslError> {
        match annot {
            TypeAnnotation::Simple(name) => match name.as_str() {
                "u32" => Ok("uint32_t".to_string()),
                "f32" => Ok("float".to_string()),
                "f64" => Ok("double".to_string()),
                "bool" => Ok("bool".to_string()),
                "string" => Ok("const char*".to_string()),
                "void" => Ok("void".to_string()),
                _ => Err(KslError::type_error(
                    format!("Unsupported type for C binding: {}", name),
                    SourcePosition::new(1, 1),
                )),
            },
            TypeAnnotation::Array { element, size } if element == "u8" => {
                Ok(format!("uint8_t[{}]", size))
            }
            _ => Err(KslError::type_error(
                "Unsupported type annotation for C binding".to_string(),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Converts KSL TypeAnnotation to Rust type
    fn type_to_rust(&self, annot: &TypeAnnotation) -> Result<String, KslError> {
        match annot {
            TypeAnnotation::Simple(name) => match name.as_str() {
                "u32" => Ok("u32".to_string()),
                "f32" => Ok("f32".to_string()),
                "f64" => Ok("f64".to_string()),
                "bool" => Ok("bool".to_string()),
                "string" => Ok("*const c_char".to_string()),
                "void" => Ok("()".to_string()),
                _ => Err(KslError::type_error(
                    format!("Unsupported type for Rust binding: {}", name),
                    SourcePosition::new(1, 1),
                )),
            },
            TypeAnnotation::Array { element, size } if element == "u8" => {
                Ok(format!("[u8; {}]", size))
            }
            _ => Err(KslError::type_error(
                "Unsupported type annotation for Rust binding".to_string(),
                SourcePosition::new(1, 1),
            )),
        }
    }
}

#[async_trait]
pub trait AsyncBindingGenerator {
    async fn generate_bindings_async(&mut self, file: &PathBuf, output: &PathBuf, binding_type: BindingType) -> Result<(), KslError>;
}

#[async_trait]
impl AsyncBindingGenerator for BindingGenerator {
    /// Asynchronously generates bindings for a KSL file
    async fn generate_bindings_async(&mut self, file: &PathBuf, output: &PathBuf, binding_type: BindingType) -> Result<(), KslError> {
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KslError::type_error(
                "Invalid main file name".to_string(),
                SourcePosition::new(1, 1),
            ))?;

        // Load modules
        self.module_system.load_module(main_module_name, file)?;

        // Generate bindings
        self.bindings.clear();
        let ast = self.module_system.link(main_module_name)?;
        
        // Analyze AST
        let analysis_result = self.analyzer.analyze(&ast)?;
        if !analysis_result.is_valid() {
            return Err(KslError::type_error(
                "AST analysis failed".to_string(),
                SourcePosition::new(1, 1),
            ));
        }

        // Generate bindings for each node
        for node in &ast {
            self.generate_node_binding(node, &binding_type)?;
        }

        // Write bindings to output file asynchronously
        tokio_fs::create_dir_all(output.parent().unwrap_or(output))
            .await
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let output_file = match binding_type {
            BindingType::CHeader => output.join(format!("{}.h", main_module_name)),
            BindingType::RustModule => output.join(format!("{}.rs", main_module_name)),
        };
        let mut file = tokio_fs::File::create(&output_file)
            .await
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let binding_content = self.bindings.join("\n");
        file.write_all(binding_content.as_bytes())
            .await
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        Ok(())
    }
}

// Public API to manage bindings
pub fn generate_bindings(file: &PathBuf, output: &PathBuf, binding_type: BindingType) -> Result<(), KslError> {
    let mut generator = BindingGenerator::new();
    generator.generate_bindings(file, output, binding_type)
}

pub async fn generate_bindings_async(file: &PathBuf, output: &PathBuf, binding_type: BindingType) -> Result<(), KslError> {
    let mut generator = BindingGenerator::new();
    generator.generate_bindings_async(file, output, binding_type).await
}

// Assume ksl_parser.rs, ksl_types.rs, ksl_module.rs, ksl_analyzer.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{AstNode, TypeAnnotation};
}

mod ksl_ast_transform {
    pub use super::{TransformedAstNode, AsyncNode};
}

mod ksl_analyzer {
    pub use super::{Analyzer, AnalysisResult};
}

mod ksl_types {
    pub use super::Type;
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
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_c_bindings() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[extern]\nfn compute(x: u32): u32 { x + 1; }\nextern fn external() -> u32;"
        ).unwrap();

        let output_dir = temp_file.path().parent().unwrap().join("bindings");
        let result = generate_bindings(&temp_file.path().to_path_buf(), &output_dir, BindingType::CHeader);
        assert!(result.is_ok());

        let binding_file = output_dir.join(format!("{}.h", temp_file.path().file_stem().unwrap().to_str().unwrap()));
        let mut contents = String::new();
        File::open(&binding_file).unwrap().read_to_string(&mut contents).unwrap();
        assert!(contents.contains("uint32_t compute(uint32_t x);"));
        assert!(contents.contains("uint32_t external();"));
    }

    #[test]
    fn test_generate_rust_bindings() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[extern]\nfn compute(x: u32): u32 { x + 1; }\nextern fn external() -> u32;"
        ).unwrap();

        let output_dir = temp_file.path().parent().unwrap().join("bindings");
        let result = generate_bindings(&temp_file.path().to_path_buf(), &output_dir, BindingType::RustModule);
        assert!(result.is_ok());

        let binding_file = output_dir.join(format!("{}.rs", temp_file.path().file_stem().unwrap().to_str().unwrap()));
        let mut contents = String::new();
        File::open(&binding_file).unwrap().read_to_string(&mut contents).unwrap();
        assert!(contents.contains("extern \"C\" fn compute(x: u32) -> u32;"));
        assert!(contents.contains("extern \"C\" fn external() -> u32;"));
    }

    #[tokio::test]
    async fn test_generate_async_bindings() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[extern]\nasync fn fetch_data(): string { return \"data\"; }"
        ).unwrap();

        let output_dir = temp_file.path().parent().unwrap().join("bindings");
        let result = generate_bindings_async(&temp_file.path().to_path_buf(), &output_dir, BindingType::RustModule).await;
        assert!(result.is_ok());

        let binding_file = output_dir.join(format!("{}.rs", temp_file.path().file_stem().unwrap().to_str().unwrap()));
        let mut contents = String::new();
        File::open(&binding_file).unwrap().read_to_string(&mut contents).unwrap();
        assert!(contents.contains("extern \"C\" async fn fetch_data() -> *const c_char;"));
    }
}