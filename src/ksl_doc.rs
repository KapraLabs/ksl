// ksl_doc.rs
// Implements documentation generation for KSL programs and standard library.
// Supports async code documentation and integration with ksl_docgen.rs.

use crate::ksl_parser::{AstNode, TypeAnnotation, DocComment};
use crate::ksl_types::Type;
use crate::ksl_ast::Expr;
use crate::ksl_module::{ModuleSystem, load_and_link};
use crate::ksl_stdlib::StdLib;
use crate::ksl_stdlib_crypto::CryptoStdLib;
use crate::ksl_stdlib_math::MathStdLib;
use crate::ksl_stdlib_io::IOStdLib;
use crate::ksl_stdlib_net::NetStdLib;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_docgen::{DocGen, DocItem, DocParam, DocReturn};
use crate::ksl_async::AsyncRuntime;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

/// Documentation generator state with async support
pub struct DocGenerator {
    module_system: ModuleSystem,
    stdlib: StdLib,
    crypto_stdlib: CryptoStdLib,
    math_stdlib: MathStdLib,
    io_stdlib: IOStdLib,
    net_stdlib: NetStdLib,
    async_runtime: Arc<RwLock<AsyncRuntime>>,
}

impl DocGenerator {
    /// Creates a new documentation generator with async support
    pub fn new() -> Self {
        DocGenerator {
            module_system: ModuleSystem::new(),
            stdlib: StdLib::new(),
            crypto_stdlib: CryptoStdLib::new(),
            math_stdlib: MathStdLib::new(),
            io_stdlib: IOStdLib::new(),
            net_stdlib: NetStdLib::new(),
            async_runtime: Arc::new(RwLock::new(AsyncRuntime::new())),
        }
    }

    /// Generates documentation for a KSL file with async support
    pub async fn generate_for_file_async(&mut self, file: &PathBuf, output: &PathBuf) -> Result<(), KslError> {
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KslError::type_error(
                "Invalid main file name".to_string(),
                SourcePosition::new(1, 1),
            ))?;

        // Load and link modules asynchronously
        self.module_system.load_module_async(main_module_name, file).await?;
        let ast = self.module_system.link(main_module_name)?;

        // Generate Markdown
        let mut markdown = String::new();
        markdown.push_str(&format!("# Module {}\n\n", main_module_name));

        for node in &ast {
            self.document_node(&mut markdown, node, 2)?;
        }

        // Write to output file
        fs::create_dir_all(output.parent().unwrap_or(output))
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let output_file = output.join(format!("{}.md", main_module_name));
        let mut file = File::create(&output_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        file.write_all(markdown.as_bytes())
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Generate JSON documentation
        let doc_items = self.generate_doc_items(&ast)?;
        let docgen = DocGen::new(main_module_name.to_string(), output.clone());
        docgen.generate(&doc_items)?;

        Ok(())
    }

    /// Generates documentation for the standard library with async support
    pub async fn generate_for_std_async(&self, output: &PathBuf) -> Result<(), KslError> {
        fs::create_dir_all(output)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Generate Markdown for stdlib
        let mut markdown = String::new();
        markdown.push_str("# Standard Library\n\n");

        // Crypto functions
        markdown.push_str("## Module std::crypto\n\n");
        for func in &self.crypto_stdlib.functions {
            self.document_std_function(&mut markdown, func, 3)?;
        }

        // Math functions
        markdown.push_str("## Module std::math\n\n");
        for func in &self.math_stdlib.functions {
            self.document_std_function(&mut markdown, func, 3)?;
        }

        // IO functions
        markdown.push_str("## Module std::io\n\n");
        for func in &self.io_stdlib.functions {
            self.document_std_function(&mut markdown, func, 3)?;
        }

        // Network functions
        markdown.push_str("## Module std::net\n\n");
        for func in &self.net_stdlib.functions {
            self.document_std_function(&mut markdown, func, 3)?;
        }

        // Write to output file
        let output_file = output.join("std.md");
        let mut file = File::create(&output_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        file.write_all(markdown.as_bytes())
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Generate JSON documentation
        let doc_items = self.generate_std_doc_items()?;
        let docgen = DocGen::new("std".to_string(), output.clone());
        docgen.generate(&doc_items)?;

        Ok(())
    }

    // Document an AST node with new syntax support
    fn document_node(&self, markdown: &mut String, node: &AstNode, heading_level: usize) -> Result<(), KslError> {
        match node {
            AstNode::AsyncFnDecl { doc, name, params, return_type, .. } => {
                markdown.push_str(&format!("{} Async Function {}\n\n", "#".repeat(heading_level), name));
                if let Some(doc) = doc {
                    markdown.push_str(&format!("{}\n\n", doc.text));
                }
                markdown.push_str("**Parameters**:\n");
                if params.is_empty() {
                    markdown.push_str("- None\n");
                } else {
                    for (param_name, param_type) in params {
                        markdown.push_str(&format!("- `{}`: {}\n", param_name, self.format_type(param_type)));
                    }
                }
                markdown.push_str("\n**Returns**: ");
                markdown.push_str(&self.format_type(return_type));
                markdown.push_str("\n\n**Async**: Yes\n\n");
            }
            AstNode::Network { op_type, endpoint, headers, data } => {
                markdown.push_str(&format!("{} Network Operation {}\n\n", "#".repeat(heading_level), op_type));
                markdown.push_str("**Endpoint**: ");
                self.format_expr(markdown, endpoint);
                markdown.push_str("\n");
                if let Some(h) = headers {
                    markdown.push_str("**Headers**: ");
                    self.format_expr(markdown, h);
                    markdown.push_str("\n");
                }
                if let Some(d) = data {
                    markdown.push_str("**Data**: ");
                    self.format_expr(markdown, d);
                    markdown.push_str("\n");
                }
                markdown.push_str("\n");
            }
            AstNode::FnDecl { doc, name, params, return_type, .. } => {
                markdown.push_str(&format!("{} Function {}\n\n", "#".repeat(heading_level), name));
                if let Some(doc) = doc {
                    markdown.push_str(&format!("{}\n\n", doc.text));
                }
                markdown.push_str("**Parameters**:\n");
                if params.is_empty() {
                    markdown.push_str("- None\n");
                } else {
                    for (param_name, param_type) in params {
                        markdown.push_str(&format!("- `{}`: {}\n", param_name, self.format_type(param_type)));
                    }
                }
                markdown.push_str("\n**Returns**: ");
                markdown.push_str(&self.format_type(return_type));
                markdown.push_str("\n\n");
            }
            AstNode::VarDecl { doc, name, type_annot, is_mutable, .. } => {
                markdown.push_str(&format!("{} Variable {}\n\n", "#".repeat(heading_level), name));
                if let Some(doc) = doc {
                    markdown.push_str(&format!("{}\n\n", doc.text));
                }
                markdown.push_str(&format!("**Type**: {}\n", type_annot.as_ref().map(|t| self.format_type(t)).unwrap_or("Unknown".to_string())));
                markdown.push_str(&format!("**Mutable**: {}\n\n", is_mutable));
            }
            AstNode::ModuleDecl { name } => {
                markdown.push_str(&format!("{} Module {}\n\n", "#".repeat(heading_level - 1), name));
                if let Some(module) = self.module_system.modules.get(name) {
                    for node in &module.ast {
                        self.document_node(markdown, node, heading_level + 1)?;
                    }
                }
            }
            _ => {} // Ignore other nodes (e.g., Import, ExternDecl)
        }
        Ok(())
    }

    // Generate documentation items for AST nodes
    fn generate_doc_items(&self, ast: &[AstNode]) -> Result<Vec<DocItem>, KslError> {
        let mut items = Vec::new();
        for node in ast {
            match node {
                AstNode::AsyncFnDecl { doc, name, params, return_type, .. } => {
                    items.push(DocItem {
                        name: name.clone(),
                        description: doc.as_ref().map(|d| d.text.clone()).unwrap_or_default(),
                        params: params.iter().map(|(name, ty)| DocParam {
                            name: name.clone(),
                            ty: self.format_type(ty),
                            description: String::new(), // TODO: Extract from doc comments
                        }).collect(),
                        returns: DocReturn {
                            ty: self.format_type(return_type),
                            description: String::new(), // TODO: Extract from doc comments
                        },
                        is_async: true,
                    });
                }
                AstNode::Network { op_type, endpoint, .. } => {
                    items.push(DocItem {
                        name: format!("network.{}", op_type),
                        description: format!("Network operation: {}", op_type),
                        params: vec![DocParam {
                            name: "endpoint".to_string(),
                            ty: "string".to_string(),
                            description: "Network endpoint".to_string(),
                        }],
                        returns: DocReturn {
                            ty: "result<string, error>".to_string(),
                            description: "Network operation result".to_string(),
                        },
                        is_async: true,
                    });
                }
                AstNode::FnDecl { doc, name, params, return_type, .. } => {
                    items.push(DocItem {
                        name: name.clone(),
                        description: doc.as_ref().map(|d| d.text.clone()).unwrap_or_default(),
                        params: params.iter().map(|(name, ty)| DocParam {
                            name: name.clone(),
                            ty: self.format_type(ty),
                            description: String::new(), // TODO: Extract from doc comments
                        }).collect(),
                        returns: DocReturn {
                            ty: self.format_type(return_type),
                            description: String::new(), // TODO: Extract from doc comments
                        },
                        is_async: false,
                    });
                }
                AstNode::VarDecl { doc, name, type_annot, is_mutable, .. } => {
                    items.push(DocItem {
                        name: name.clone(),
                        description: doc.as_ref().map(|d| d.text.clone()).unwrap_or_default(),
                        params: vec![DocParam {
                            name: name.clone(),
                            ty: self.format_type(type_annot),
                            description: String::new(),
                        }],
                        returns: DocReturn {
                            ty: self.format_type(type_annot),
                            description: String::new(),
                        },
                        is_async: false,
                    });
                }
                AstNode::ModuleDecl { name } => {
                    items.push(DocItem {
                        name: name.clone(),
                        description: String::new(), // TODO: Add descriptions
                        params: Vec::new(),
                        returns: DocReturn {
                            ty: String::new(),
                            description: String::new(),
                        },
                        is_async: false,
                    });
                }
                _ => {}
            }
        }
        Ok(items)
    }

    // Generate documentation items for standard library
    fn generate_std_doc_items(&self) -> Result<Vec<DocItem>, KslError> {
        let mut items = Vec::new();
        
        // Add crypto functions
        for func in &self.crypto_stdlib.functions {
            items.push(DocItem {
                name: func.get_name().to_string(),
                description: String::new(), // TODO: Add descriptions
                params: func.get_params().iter().map(|ty| DocParam {
                    name: String::new(),
                    ty: self.format_type_raw(ty),
                    description: String::new(),
                }).collect(),
                returns: DocReturn {
                    ty: self.format_type_raw(func.get_return_type()),
                    description: String::new(),
                },
                is_async: false,
            });
        }

        // Add network functions
        for func in &self.net_stdlib.functions {
            items.push(DocItem {
                name: func.get_name().to_string(),
                description: String::new(), // TODO: Add descriptions
                params: func.get_params().iter().map(|ty| DocParam {
                    name: String::new(),
                    ty: self.format_type_raw(ty),
                    description: String::new(),
                }).collect(),
                returns: DocReturn {
                    ty: self.format_type_raw(func.get_return_type()),
                    description: String::new(),
                },
                is_async: true,
            });
        }

        Ok(items)
    }

    // Document a standard library function
    fn document_std_function(
        &self,
        markdown: &mut String,
        func: &dyn StdLibFunctionTrait,
        heading_level: usize,
    ) -> Result<(), KslError> {
        markdown.push_str(&format!("{} Function {}\n\n", "#".repeat(heading_level), func.get_name()));
        // Placeholder: Add doc comments when available in stdlib
        markdown.push_str("Documentation not available.\n\n");
        markdown.push_str("**Parameters**:\n");
        if func.get_params().is_empty() {
            markdown.push_str("- None\n");
        } else {
            for param_type in func.get_params() {
                markdown.push_str(&format!("- `{}`\n", self.format_type_raw(param_type)));
            }
        }
        markdown.push_str("\n**Returns**: ");
        markdown.push_str(&self.format_type_raw(func.get_return_type()));
        markdown.push_str("\n\n");
        Ok(())
    }

    // Format a TypeAnnotation for display
    fn format_type(&self, annot: &TypeAnnotation) -> String {
        match annot {
            TypeAnnotation::Simple(name) => name.clone(),
            TypeAnnotation::Array { element, size } => format!("array<{}, {}>", element, size),
            TypeAnnotation::Result { success, error } => format!("result<{}, {}>", success, error),
        }
    }

    // Format a Type for display
    fn format_type_raw(&self, ty: &Type) -> String {
        match ty {
            Type::U8 => "u8".to_string(),
            Type::U32 => "u32".to_string(),
            Type::F32 => "f 0x17f32".to_string(),
            Type::F64 => "f64".to_string(),
            Type::Bool => "bool".to_string(),
            Type::String => "string".to_string(),
            Type::Void => "void".to_string(),
            Type::Array(inner, size) => format!("array<{}, {}>", self.format_type_raw(inner), size),
            Type::Result(success, error) => format!("result<{}, {}>", self.format_type_raw(success), self.format_type_raw(error)),
            Type::Function(params, ret) => {
                let param_types = params.iter().map(|p| self.format_type_raw(p)).collect::<Vec<_>>().join(", ");
                format!("({}) -> {}", param_types, self.format_type_raw(ret))
            }
        }
    }

    // Placeholder for format_expr method
    fn format_expr(&self, markdown: &mut String, expr: &Expr) {
        // Implementation needed
    }
}

// Trait for standard library functions
pub trait StdLibFunctionTrait {
    fn get_name(&self) -> &'static str;
    fn get_params(&self) -> &[Type];
    fn get_return_type(&self) -> &Type;
}

impl StdLibFunctionTrait for crate::ksl_stdlib::StdLibFunction {
    fn get_name(&self) -> &'static str { self.name }
    fn get_params(&self) -> &[Type] { &self.params }
    fn get_return_type(&self) -> &Type { &self.return_type }
}

impl StdLibFunctionTrait for crate::ksl_stdlib_crypto::CryptoStdLibFunction {
    fn get_name(&self) -> &'static str { self.name }
    fn get_params(&self) -> &[Type] { &self.params }
    fn get_return_type(&self) -> &Type { &self.return_type }
}

impl StdLibFunctionTrait for crate::ksl_stdlib_math::MathStdLibFunction {
    fn get_name(&self) -> &'static str { self.name }
    fn get_params(&self) -> &[Type] { &self.params }
    fn get_return_type(&self) -> &Type { &self.return_type }
}

impl StdLibFunctionTrait for crate::ksl_stdlib_io::IOStdLibFunction {
    fn get_name(&self) -> &'static str { self.name }
    fn get_params(&self) -> &[Type] { &self.params }
    fn get_return_type(&self) -> &Type { &self.return_type }
}

// Public API to generate documentation with async support
pub async fn generate_async(file: Option<&PathBuf>, std: bool, output: Option<&PathBuf>) -> Result<(), KslError> {
    let mut generator = DocGenerator::new();
    let output_dir = output.unwrap_or_else(|| PathBuf::from("docs"));

    if std {
        generator.generate_for_std_async(&output_dir).await?;
    } else if let Some(file) = file {
        generator.generate_for_file_async(file, &output_dir).await?;
    } else {
        return Err(KslError::type_error(
            "Either --file or --std must be specified".to_string(),
            SourcePosition::new(1, 1),
        ));
    }

    Ok(())
}

// Assume ksl_parser.rs, ksl_module.rs, ksl_stdlib.rs, ksl_stdlib_crypto.rs, ksl_stdlib_math.rs, ksl_stdlib_io.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{AstNode, TypeAnnotation};
}

mod ksl_module {
    pub use super::{ModuleSystem, load_and_link};
}

mod ksl_stdlib {
    pub use super::StdLib;
}

mod ksl_stdlib_crypto {
    pub use super::CryptoStdLib;
}

mod ksl_stdlib_math {
    pub use super::MathStdLib;
}

mod ksl_stdlib_io {
    pub use super::IOStdLib;
}

mod ksl_stdlib_net {
    pub use super::NetStdLib;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::runtime::Runtime;

    #[tokio::test]
    async fn test_generate_for_file_async() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "async fn fetch(url: string): result<string, error> {{ let data = await http.get(url); }}"
        ).unwrap();

        let result = generate_async(Some(&temp_file.path().to_path_buf()), false, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_generate_for_std_async() {
        let result = generate_async(None, true, None).await;
        assert!(result.is_ok());
    }
}