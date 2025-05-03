// ksl_formatter.rs
// Implements an auto-formatting tool for KSL programs to standardize code style.

use crate::ksl_parser::{AstNode, ExprKind, TypeAnnotation, DocComment};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use toml::Value;
use serde::Deserialize;

// Formatter configuration
#[derive(Debug, Deserialize)]
struct FormatConfig {
    indent_size: Option<usize>,
    max_line_length: Option<usize>,
}

// Formatter state
pub struct Formatter {
    module_system: ModuleSystem,
    config: FormatConfig,
    output: String,
    indent_level: usize,
}

impl Formatter {
    pub fn new(config_path: Option<&PathBuf>) -> Self {
        let config = if let Some(path) = config_path {
            let content = fs::read_to_string(path).unwrap_or_default();
            toml::from_str(&content).unwrap_or_else(|_| FormatConfig {
                indent_size: Some(2),
                max_line_length: Some(80),
            })
        } else {
            FormatConfig {
                indent_size: Some(2),
                max_line_length: Some(80),
            }
        };

        Formatter {
            module_system: ModuleSystem::new(),
            config,
            output: String::new(),
            indent_level: 0,
        }
    }

    // Format a KSL file
    pub fn format_file(&mut self, file: &PathBuf) -> Result<(), KslError> {
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KslError::type_error(
                "Invalid main file name".to_string(),
                SourcePosition::new(1, 1),
            ))?;

        // Load and link modules
        self.module_system.load_module(main_module_name, file)?;
        let ast = self.module_system.link(main_module_name)?;

        // Format AST
        self.output.clear();
        for node in &ast {
            self.format_node(node);
            self.output.push('\n');
        }

        // Write formatted code to file
        let mut file = File::create(file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        file.write_all(self.output.as_bytes())
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        Ok(())
    }

    // Format an AST node
    fn format_node(&mut self, node: &AstNode) {
        match node {
            AstNode::VarDecl { doc, is_mutable, name, type_annot, expr } => {
                if let Some(doc) = doc {
                    self.format_doc_comment(doc);
                }
                self.write(&format!(
                    "{}{} {}: {} = ",
                    self.indent(),
                    if *is_mutable { "let" } else { "const" },
                    name,
                    type_annot.as_ref().map(|t| self.format_type(t)).unwrap_or("".to_string())
                ));
                self.format_expr(expr);
                self.output.push(';');
            }
            AstNode::FnDecl { doc, name, params, return_type, body } => {
                if let Some(doc) = doc {
                    self.format_doc_comment(doc);
                }
                self.write(&format!(
                    "{}fn {}({}): {} {{",
                    self.indent(),
                    name,
                    params.iter().map(|(n, t)| format!("{}: {}", n, self.format_type(t))).collect::<Vec<_>>().join(", "),
                    self.format_type(return_type)
                ));
                self.indent_level += 1;
                for node in body {
                    self.output.push('\n');
                    self.format_node(node);
                }
                self.indent_level -= 1;
                self.output.push('\n');
                self.write("}");
            }
            AstNode::ModuleDecl { doc, name } => {
                if let Some(doc) = doc {
                    self.format_doc_comment(doc);
                }
                self.write(&format!("{}mod {};", self.indent(), name));
            }
            AstNode::Import { path, item } => {
                self.write(&format!("{}import {}::{};", self.indent(), path.join("::"), item));
            }
            AstNode::If { condition, then_branch, else_branch } => {
                self.write(&format!("{}if ", self.indent()));
                self.format_expr(condition);
                self.output.push_str(" {");
                self.indent_level += 1;
                for node in then_branch {
                    self.output.push('\n');
                    self.format_node(node);
                }
                self.indent_level -= 1;
                self.output.push('\n');
                self.write("}");
                if let Some(else_nodes) = else_branch {
                    self.output.push_str(" else {");
                    self.indent_level += 1;
                    for node in else_nodes {
                        self.output.push('\n');
                        self.format_node(node);
                    }
                    self.indent_level -= 1;
                    self.output.push('\n');
                    self.write("}");
                }
            }
            AstNode::Expr { kind } => {
                self.format_expr(&AstNode::Expr { kind: kind.clone() });
                self.output.push(';');
            }
            _ => {} // Ignore other nodes
        }
    }

    // Format an expression
    fn format_expr(&mut self, expr: &AstNode) {
        match expr {
            AstNode::Expr { kind } => match kind {
                ExprKind::Ident(name) => {
                    self.output.push_str(name);
                }
                ExprKind::Number(num) => {
                    self.output.push_str(num);
                }
                ExprKind::String(s) => {
                    self.output.push_str(&format!("\"{}\"", s));
                }
                ExprKind::BinaryOp { op, left, right } => {
                    self.format_expr(left);
                    self.output.push_str(&format!(" {} ", op));
                    self.format_expr(right);
                }
                ExprKind::Call { name, args } => {
                    self.output.push_str(name);
                    self.output.push('(');
                    for (i, arg) in args.iter().enumerate() {
                        if i > 0 {
                            self.output.push_str(", ");
                        }
                        self.format_expr(arg);
                    }
                    self.output.push(')');
                }
            }
            _ => {}
        }
    }

    // Format a doc comment
    fn format_doc_comment(&mut self, doc: &DocComment) {
        for line in doc.text.lines() {
            self.write(&format!("/// {}", line.trim()));
            self.output.push('\n');
        }
    }

    // Format a TypeAnnotation
    fn format_type(&self, annot: &TypeAnnotation) -> String {
        match annot {
            TypeAnnotation::Simple(name) => name.clone(),
            TypeAnnotation::Array { element, size } => format!("array<{}, {}>", element, size),
            TypeAnnotation::Result { success, error } => format!("result<{}, {}>", success, error),
        }
    }

    // Generate indentation
    fn indent(&self) -> String {
        " ".repeat(self.indent_level * self.config.indent_size.unwrap_or(2))
    }

    // Write to output buffer
    fn write(&mut self, text: &str) {
        self.output.push_str(text);
    }
}

// Public API to format a KSL file
pub fn format(file: &PathBuf, config: Option<&PathBuf>) -> Result<(), KslError> {
    let mut formatter = Formatter::new(config);
    formatter.format_file(file)
}

// Assume ksl_parser.rs, ksl_module.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{AstNode, ExprKind, TypeAnnotation, DocComment};
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
    fn test_format_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn add(x:u32,y:u32):u32{x+y;}///Test\nlet x: u32=42;"
        ).unwrap();

        let result = format(&temp_file.path().to_path_buf(), None);
        assert!(result.is_ok());

        let mut formatted_content = String::new();
        File::open(&temp_file.path())
            .unwrap()
            .read_to_string(&mut formatted_content)
            .unwrap();
        
        let expected = "fn add(x: u32, y: u32): u32 {\n  x + y;\n}\n\n/// Test\nlet x: u32 = 42;\n";
        assert_eq!(formatted_content, expected);
    }

    #[test]
    fn test_format_with_module() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "mod utils;import utils::add;fn main(){let x=add(1,2);}"
        ).unwrap();

        let mut utils_file = NamedTempFile::new().unwrap();
        writeln!(
            utils_file,
            "fn add(x: u32, y: u32): u32 { x + y; }"
        ).unwrap();
        let utils_path = utils_file.path().to_path_buf();
        let utils_dir = utils_path.parent().unwrap().to_path_buf();
        let utils_name = utils_path.file_stem().unwrap().to_str().unwrap();
        fs::rename(&utils_path, utils_dir.join(format!("{}.ksl", utils_name))).unwrap();

        let result = format(&temp_file.path().to_path_buf(), None);
        assert!(result.is_ok());

        let mut formatted_content = String::new();
        File::open(&temp_file.path())
            .unwrap()
            .read_to_string(&mut formatted_content)
            .unwrap();
        
        let expected = "mod utils;\nimport utils::add;\n\nfn main() {\n  let x: u32 = add(1, 2);\n}\n";
        assert_eq!(formatted_content, expected);
    }
}