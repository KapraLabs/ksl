// ksl_formatter.rs
// Implements an auto-formatting tool for KSL programs to standardize code style.
// Supports async code formatting, custom rules, and CLI integration.

use crate::ksl_parser::{AstNode, ExprKind, TypeAnnotation, DocComment};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_cli::CliOptions;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use toml::Value;
use serde::Deserialize;
use std::collections::HashMap;

/// Formatter configuration with support for custom rules
#[derive(Debug, Deserialize)]
pub struct FormatConfig {
    /// Number of spaces per indentation level
    indent_size: Option<usize>,
    /// Maximum line length before wrapping
    max_line_length: Option<usize>,
    /// Whether to align function parameters
    align_parameters: Option<bool>,
    /// Whether to align match arms
    align_match_arms: Option<bool>,
    /// Whether to add spaces around binary operators
    spaces_around_operators: Option<bool>,
    /// Whether to add spaces after commas
    spaces_after_commas: Option<bool>,
    /// Whether to add spaces after colons
    spaces_after_colons: Option<bool>,
    /// Custom formatting rules
    custom_rules: Option<HashMap<String, String>>,
}

/// Formatter state with CLI integration
pub struct Formatter {
    module_system: ModuleSystem,
    config: FormatConfig,
    output: String,
    indent_level: usize,
    cli_options: Option<CliOptions>,
}

impl Formatter {
    /// Creates a new formatter with the specified configuration
    pub fn new(config_path: Option<&PathBuf>, cli_options: Option<CliOptions>) -> Self {
        let config = if let Some(path) = config_path {
            let content = fs::read_to_string(path).unwrap_or_default();
            toml::from_str(&content).unwrap_or_else(|_| FormatConfig {
                indent_size: Some(2),
                max_line_length: Some(80),
                align_parameters: Some(true),
                align_match_arms: Some(true),
                spaces_around_operators: Some(true),
                spaces_after_commas: Some(true),
                spaces_after_colons: Some(true),
                custom_rules: None,
            })
        } else {
            FormatConfig {
                indent_size: Some(2),
                max_line_length: Some(80),
                align_parameters: Some(true),
                align_match_arms: Some(true),
                spaces_around_operators: Some(true),
                spaces_after_commas: Some(true),
                spaces_after_colons: Some(true),
                custom_rules: None,
            }
        };

        Formatter {
            module_system: ModuleSystem::new(),
            config,
            output: String::new(),
            indent_level: 0,
            cli_options,
        }
    }

    /// Formats a KSL file with CLI options support
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

        // Apply custom rules if specified
        if let Some(rules) = &self.config.custom_rules {
            self.apply_custom_rules(rules);
        }

        // Write formatted code to file
        let mut file = File::create(file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        file.write_all(self.output.as_bytes())
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        Ok(())
    }

    // Format an AST node with new syntax support
    fn format_node(&mut self, node: &AstNode) {
        match node {
            AstNode::AsyncFnDecl { doc, name, params, return_type, body } => {
                if let Some(doc) = doc {
                    self.format_doc_comment(doc);
                }
                self.write(&format!(
                    "{}async fn {}({}): {} {{",
                    self.indent(),
                    name,
                    self.format_params(params),
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
            AstNode::AwaitExpr { expr } => {
                self.write(&format!("{}await ", self.indent()));
                self.format_expr(expr);
                self.output.push(';');
            }
            AstNode::Network { op_type, endpoint, headers, data } => {
                self.write(&format!("{}network.{}(", self.indent(), op_type));
                self.format_expr(endpoint);
                if let Some(h) = headers {
                    self.output.push_str(", ");
                    self.format_expr(h);
                }
                if let Some(d) = data {
                    self.output.push_str(", ");
                    self.format_expr(d);
                }
                self.output.push_str(");");
            }
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

    // Format parameters with alignment support
    fn format_params(&self, params: &[(String, TypeAnnotation)]) -> String {
        if self.config.align_parameters.unwrap_or(false) {
            let max_name_len = params.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
            params.iter()
                .map(|(name, ty)| format!("{:<width$}: {}", name, self.format_type(ty), width = max_name_len))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            params.iter()
                .map(|(name, ty)| format!("{}: {}", name, self.format_type(ty)))
                .collect::<Vec<_>>()
                .join(", ")
        }
    }

    // Format an expression with new syntax support
    fn format_expr(&mut self, expr: &AstNode) {
        match expr {
            AstNode::Expr { kind } => match kind {
                ExprKind::AsyncCall { name, args } => {
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
                ExprKind::BinaryOp { op, left, right } => {
                    self.format_expr(left);
                    if self.config.spaces_around_operators.unwrap_or(false) {
                        self.output.push_str(&format!(" {} ", op));
                    } else {
                        self.output.push_str(op);
                    }
                    self.format_expr(right);
                }
                ExprKind::Ident(name) => {
                    self.output.push_str(name);
                }
                ExprKind::Number(num) => {
                    self.output.push_str(num);
                }
                ExprKind::String(s) => {
                    self.output.push_str(&format!("\"{}\"", s));
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

    // Apply custom formatting rules
    fn apply_custom_rules(&mut self, rules: &HashMap<String, String>) {
        for (pattern, replacement) in rules {
            self.output = self.output.replace(pattern, replacement);
        }
    }
}

/// Public API to format a KSL file with CLI options
pub fn format(file: &PathBuf, config: Option<&PathBuf>, cli_options: Option<CliOptions>) -> Result<(), KslError> {
    let mut formatter = Formatter::new(config, cli_options);
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

mod ksl_cli {
    pub use super::CliOptions;
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

        let result = format(&temp_file.path().to_path_buf(), None, None);
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

        let result = format(&temp_file.path().to_path_buf(), None, None);
        assert!(result.is_ok());

        let mut formatted_content = String::new();
        File::open(&temp_file.path())
            .unwrap()
            .read_to_string(&mut formatted_content)
            .unwrap();
        
        let expected = "mod utils;\nimport utils::add;\n\nfn main() {\n  let x: u32 = add(1, 2);\n}\n";
        assert_eq!(formatted_content, expected);
    }

    #[test]
    fn test_format_async() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "async fn fetch(url:string):result<string,error>{let data=await http.get(url);}"
        ).unwrap();

        let result = format(&temp_file.path().to_path_buf(), None, None);
        assert!(result.is_ok());
        let mut content = String::new();
        temp_file.read_to_string(&mut content).unwrap();
        assert!(content.contains("async fn fetch"));
        assert!(content.contains("await http.get"));
    }

    #[test]
    fn test_format_network() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test(){let response=network.get(\"url\",{\"header\":\"value\"});}"
        ).unwrap();

        let result = format(&temp_file.path().to_path_buf(), None, None);
        assert!(result.is_ok());
        let mut content = String::new();
        temp_file.read_to_string(&mut content).unwrap();
        assert!(content.contains("network.get"));
    }

    #[test]
    fn test_custom_rules() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test(){let x=42;}"
        ).unwrap();

        let mut custom_rules = HashMap::new();
        custom_rules.insert("let".to_string(), "const".to_string());
        let config = FormatConfig {
            indent_size: Some(2),
            max_line_length: Some(80),
            align_parameters: Some(true),
            align_match_arms: Some(true),
            spaces_around_operators: Some(true),
            spaces_after_commas: Some(true),
            spaces_after_colons: Some(true),
            custom_rules: Some(custom_rules),
        };

        let result = format(&temp_file.path().to_path_buf(), None, None);
        assert!(result.is_ok());
        let mut content = String::new();
        temp_file.read_to_string(&mut content).unwrap();
        assert!(content.contains("const x = 42"));
    }
}