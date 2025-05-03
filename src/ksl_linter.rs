// ksl_linter.rs
// Implements a static analysis tool (linter) for KSL programs to enforce coding standards and detect errors.

use crate::ksl_parser::{AstNode, ExprKind, TypeAnnotation};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use toml::Value;
use serde::Deserialize;

// Lint rule configuration
#[derive(Debug, Deserialize)]
struct LintConfig {
    max_line_length: Option<usize>,
    enforce_snake_case: Option<bool>,
    warn_unused_variables: Option<bool>,
    require_result_handling: Option<bool>,
}

// Lint issue representation
#[derive(Debug)]
pub struct LintIssue {
    pub message: String,
    pub position: SourcePosition,
}

// Linter state
pub struct Linter {
    module_system: ModuleSystem,
    config: LintConfig,
    issues: Vec<LintIssue>,
    used_variables: HashSet<String>,
}

impl Linter {
    pub fn new(config_path: Option<&PathBuf>) -> Self {
        let config = if let Some(path) = config_path {
            let content = fs::read_to_string(path).unwrap_or_default();
            toml::from_str(&content).unwrap_or_else(|_| LintConfig {
                max_line_length: Some(80),
                enforce_snake_case: Some(true),
                warn_unused_variables: Some(true),
                require_result_handling: Some(true),
            })
        } else {
            LintConfig {
                max_line_length: Some(80),
                enforce_snake_case: Some(true),
                warn_unused_variables: Some(true),
                require_result_handling: Some(true),
            }
        };

        Linter {
            module_system: ModuleSystem::new(),
            config,
            issues: Vec::new(),
            used_variables: HashSet::new(),
        }
    }

    // Run the linter on a KSL file
    pub fn lint_file(&mut self, file: &PathBuf) -> Result<(), Vec<LintIssue>> {
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| vec![LintIssue {
                message: "Invalid main file name".to_string(),
                position: SourcePosition::new(1, 1),
            }])?;

        // Load and link modules
        self.module_system.load_module(main_module_name, file)
            .map_err(|e| vec![LintIssue {
                message: e.to_string(),
                position: SourcePosition::new(1, 1),
            }])?;
        let ast = self.module_system.link(main_module_name)
            .map_err(|e| vec![LintIssue {
                message: e.to_string(),
                position: SourcePosition::new(1, 1),
            }])?;

        // Run lint checks
        for node in &ast {
            self.lint_node(node, SourcePosition::new(1, 1));
        }

        if self.issues.is_empty() {
            Ok(())
        } else {
            Err(self.issues.clone())
        }
    }

    // Lint a single AST node
    fn lint_node(&mut self, node: &AstNode, pos: SourcePosition) {
        match node {
            AstNode::VarDecl { name, type_annot, expr, is_mutable, .. } => {
                self.lint_variable_name(name, pos);
                if let Some(annot) = type_annot {
                    if self.config.require_result_handling.unwrap_or(false) && matches!(annot, TypeAnnotation::Result { .. }) {
                        self.check_result_handling(expr, pos);
                    }
                }
                if self.config.warn_unused_variables.unwrap_or(false) {
                    self.used_variables.insert(name.clone());
                }
                self.lint_expr(expr, pos);
            }
            AstNode::FnDecl { name, params, body, .. } => {
                self.lint_function_name(name, pos);
                for (param_name, _) in params {
                    self.lint_variable_name(param_name, pos);
                    if self.config.warn_unused_variables.unwrap_or(false) {
                        self.used_variables.insert(param_name.clone());
                    }
                }
                for node in body {
                    self.lint_node(node, pos);
                }
            }
            AstNode::ModuleDecl { name, .. } => {
                self.lint_module_name(name, pos);
            }
            AstNode::If { condition, then_branch, else_branch, .. } => {
                self.lint_expr(condition, pos);
                for node in then_branch {
                    self.lint_node(node, pos);
                }
                if let Some(else_nodes) = else_branch {
                    for node in else_nodes {
                        self.lint_node(node, pos);
                    }
                }
            }
            AstNode::Expr { kind } => {
                self.lint_expr(&AstNode::Expr { kind: kind.clone() }, pos);
            }
            _ => {} // Ignore other nodes (e.g., Import, ExternDecl)
        }
    }

    // Lint an expression
    fn lint_expr(&mut self, expr: &AstNode, pos: SourcePosition) {
        match expr {
            AstNode::Expr { kind } => match kind {
                ExprKind::Ident(name) => {
                    if self.config.warn_unused_variables.unwrap_or(false) {
                        self.used_variables.insert(name.clone());
                    }
                }
                ExprKind::BinaryOp { left, right, .. } => {
                    self.lint_expr(left, pos);
                    self.lint_expr(right, pos);
                }
                ExprKind::Call { name, args } => {
                    for arg in args {
                        self.lint_expr(arg, pos);
                    }
                }
                _ => {}
            }
            _ => {}
        }
    }

    // Check variable naming (snake_case)
    fn lint_variable_name(&mut self, name: &str, pos: SourcePosition) {
        if self.config.enforce_snake_case.unwrap_or(false) {
            let is_snake_case = name.chars().all(|c| c.is_lowercase() || c == '_' || c.is_digit(10))
                && !name.contains("__");
            if !is_snake_case {
                self.issues.push(LintIssue {
                    message: format!("Variable name '{}' should be snake_case", name),
                    position: pos,
                });
            }
        }
    }

    // Check function naming (snake_case)
    fn lint_function_name(&mut self, name: &str, pos: SourcePosition) {
        if self.config.enforce_snake_case.unwrap_or(false) {
            let is_snake_case = name.chars().all(|c| c.is_lowercase() || c == '_' || c.is_digit(10))
                && !name.contains("__");
            if !is_snake_case {
                self.issues.push(LintIssue {
                    message: format!("Function name '{}' should be snake_case", name),
                    position: pos,
                });
            }
        }
    }

    // Check module naming (snake_case)
    fn lint_module_name(&mut self, name: &str, pos: SourcePosition) {
        if self.config.enforce_snake_case.unwrap_or(false) {
            let is_snake_case = name.chars().all(|c| c.is_lowercase() || c == '_' || c.is_digit(10))
                && !name.contains("__");
            if !is_snake_case {
                self.issues.push(LintIssue {
                    message: format!("Module name '{}' should be snake_case", name),
                    position: pos,
                });
            }
        }
    }

    // Check for unhandled result types
    fn check_result_handling(&mut self, expr: &AstNode, pos: SourcePosition) {
        match expr {
            AstNode::Expr { kind: ExprKind::Call { name, .. } } => {
                if name == "http.get" || name == "device.sensor" {
                    self.issues.push(LintIssue {
                        message: format!("Result type from '{}' must be handled (e.g., with match)", name),
                        position: pos,
                    });
                }
            }
            _ => {}
        }
    }
}

// Public API to lint a KSL file
pub fn lint(file: &PathBuf, config: Option<&PathBuf>) -> Result<(), Vec<LintIssue>> {
    let mut linter = Linter::new(config);
    linter.lint_file(file)
}

// Assume ksl_parser.rs, ksl_module.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{AstNode, ExprKind, TypeAnnotation};
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
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_lint_snake_case() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn CamelCase() { let NotSnakeCase: u32 = 42; }"
        ).unwrap();

        let result = lint(&temp_file.path().to_path_buf(), None);
        assert!(result.is_err());
        let issues = result.unwrap_err();
        assert_eq!(issues.len(), 2);
        assert!(issues.iter().any(|i| i.message.contains("Function name 'CamelCase' should be snake_case")));
        assert!(issues.iter().any(|i| i.message.contains("Variable name 'NotSnakeCase' should be snake_case")));
    }

    #[test]
    fn test_lint_unused_variable() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test() { let unused: u32 = 42; let used: u32 = 43; let x = used + 1; }"
        ).unwrap();

        let result = lint(&temp_file.path().to_path_buf(), None);
        assert!(result.is_err());
        let issues = result.unwrap_err();
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("Variable 'unused' is declared but never used"));
    }

    #[test]
    fn test_lint_result_handling() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test() { let data: result<string, error> = http.get(\"url\"); }"
        ).unwrap();

        let result = lint(&temp_file.path().to_path_buf(), None);
        assert!(result.is_err());
        let issues = result.unwrap_err();
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("Result type from 'http.get' must be handled"));
    }
}