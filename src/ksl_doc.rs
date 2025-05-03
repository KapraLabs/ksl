// ksl_doc.rs
// Implements documentation generation for KSL programs and standard library.

use crate::ksl_parser::{AstNode, TypeAnnotation};
use crate::ksl_module::{ModuleSystem, load_and_link};
use crate::ksl_stdlib::StdLib;
use crate::ksl_stdlib_crypto::CryptoStdLib;
use crate::ksl_stdlib_math::MathStdLib;
use crate::ksl_stdlib_io::IOStdLib;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

// Documentation generator state
pub struct DocGenerator {
    module_system: ModuleSystem,
    stdlib: StdLib,
    crypto_stdlib: CryptoStdLib,
    math_stdlib: MathStdLib,
    io_stdlib: IOStdLib,
}

impl DocGenerator {
    pub fn new() -> Self {
        DocGenerator {
            module_system: ModuleSystem::new(),
            stdlib: StdLib::new(),
            crypto_stdlib: CryptoStdLib::new(),
            math_stdlib: MathStdLib::new(),
            io_stdlib: IOStdLib::new(),
        }
    }

    // Generate documentation for a KSL file
    pub fn generate_for_file(&mut self, file: &PathBuf, output: &PathBuf) -> Result<(), KslError> {
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KslError::type_error(
                "Invalid main file name".to_string(),
                SourcePosition::new(1, 1),
            ))?;

        // Load and link modules
        self.module_system.load_module(main_module_name, file)?;
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

        Ok(())
    }

    // Generate documentation for the standard library
    pub fn generate_for_std(&self, output: &PathBuf) -> Result<(), KslError> {
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

        // Write to output file
        let output_file = output.join("std.md");
        let mut file = File::create(&output_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        file.write_all(markdown.as_bytes())
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        Ok(())
    }

    // Document an AST node
    fn document_node(&self, markdown: &mut String, node: &AstNode, heading_level: usize) -> Result<(), KslError> {
        match node {
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

// Public API to generate documentation
pub fn generate(file: Option<&PathBuf>, std: bool, output: Option<&PathBuf>) -> Result<(), KslError> {
    let mut generator = DocGenerator::new();
    let output_dir = output.unwrap_or_else(|| PathBuf::from("docs"));

    if std {
        generator.generate_for_std(&output_dir)?;
    } else if let Some(file) = file {
        generator.generate_for_file(file, &output_dir)?;
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

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_for_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "/// Validates an NFT.\nfn validate_nft(msg: array<u8, 32>): bool { true }"
        ).unwrap();

        let output_dir = temp_file.path().parent().unwrap().join("docs");
        let result = generate(Some(&temp_file.path().to_path_buf()), false, Some(&output_dir));
        assert!(result.is_ok());

        let doc_file = output_dir.join(format!("{}.md", temp_file.path().file_stem().unwrap().to_str().unwrap()));
        let contents = fs::read_to_string(&doc_file).unwrap();
        assert!(contents.contains("# Module"));
        assert!(contents.contains("## Function validate_nft"));
        assert!(contents.contains("Validates an NFT."));
        assert!(contents.contains("- `msg`: array<u8, 32>"));
        assert!(contents.contains("**Returns**: bool"));
    }

    #[test]
    fn test_generate_for_std() {
        let output_dir = tempdir::TempDir::new("docs").unwrap().into_path();
        let result = generate(None, true, Some(&output_dir));
        assert!(result.is_ok());

        let doc_file = output_dir.join("std.md");
        let contents = fs::read_to_string(&doc_file).unwrap();
        assert!(contents.contains("# Standard Library"));
        assert!(contents.contains("## Module std::crypto"));
        assert!(contents.contains("## Function std::crypto::bls_verify"));
        assert!(contents.contains("## Module std::math"));
        assert!(contents.contains("## Module std::io"));
    }
}