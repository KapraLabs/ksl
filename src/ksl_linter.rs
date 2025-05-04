// ksl_linter.rs
// Implements a static analysis tool (linter) for KSL programs to enforce coding standards and detect errors.
// Supports async code analysis, networking operations, and enhanced error checking.

use crate::ksl_parser::{AstNode, ExprKind, TypeAnnotation};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_analyzer::Analyzer;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use toml::Value;
use serde::Deserialize;

/// Lint rule configuration with support for async and networking features
#[derive(Debug, Deserialize)]
struct LintConfig {
    /// Maximum line length in characters
    max_line_length: Option<usize>,
    /// Enforce snake_case naming convention
    enforce_snake_case: Option<bool>,
    /// Warn about unused variables
    warn_unused_variables: Option<bool>,
    /// Require handling of Result types
    require_result_handling: Option<bool>,
    /// Maximum number of concurrent async operations
    max_concurrent_async: Option<usize>,
    /// Require error handling for async operations
    require_async_error_handling: Option<bool>,
    /// Enforce network operation timeouts
    enforce_network_timeouts: Option<bool>,
}

/// Lint issue representation with severity level
#[derive(Debug)]
pub struct LintIssue {
    /// The error or warning message
    pub message: String,
    /// Source position of the issue
    pub position: SourcePosition,
    /// Severity level of the issue
    pub severity: LintSeverity,
}

/// Severity levels for lint issues
#[derive(Debug, PartialEq)]
pub enum LintSeverity {
    /// Warning that doesn't prevent compilation
    Warning,
    /// Error that should be fixed
    Error,
}

/// Linter state with analyzer integration
pub struct Linter {
    module_system: ModuleSystem,
    analyzer: Analyzer,
    config: LintConfig,
    issues: Vec<LintIssue>,
    used_variables: HashSet<String>,
    async_contexts: Vec<String>,
}

impl Linter {
    /// Creates a new linter with the specified configuration
    pub fn new(config_path: Option<&PathBuf>) -> Self {
        let config = if let Some(path) = config_path {
            let content = fs::read_to_string(path).unwrap_or_default();
            toml::from_str(&content).unwrap_or_else(|_| LintConfig {
                max_line_length: Some(80),
                enforce_snake_case: Some(true),
                warn_unused_variables: Some(true),
                require_result_handling: Some(true),
                max_concurrent_async: Some(100),
                require_async_error_handling: Some(true),
                enforce_network_timeouts: Some(true),
            })
        } else {
            LintConfig {
                max_line_length: Some(80),
                enforce_snake_case: Some(true),
                warn_unused_variables: Some(true),
                require_result_handling: Some(true),
                max_concurrent_async: Some(100),
                require_async_error_handling: Some(true),
                enforce_network_timeouts: Some(true),
            }
        };

        Linter {
            module_system: ModuleSystem::new(),
            analyzer: Analyzer::new(),
            config,
            issues: Vec::new(),
            used_variables: HashSet::new(),
            async_contexts: Vec::new(),
        }
    }

    /// Runs the linter on a KSL file with analyzer integration
    pub fn lint_file(&mut self, file: &PathBuf) -> Result<(), Vec<LintIssue>> {
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| vec![LintIssue {
                message: "Invalid main file name".to_string(),
                position: SourcePosition::new(1, 1),
                severity: LintSeverity::Error,
            }])?;

        // Load and link modules
        self.module_system.load_module(main_module_name, file)
            .map_err(|e| vec![LintIssue {
                message: e.to_string(),
                position: SourcePosition::new(1, 1),
                severity: LintSeverity::Error,
            }])?;
        let ast = self.module_system.link(main_module_name)
            .map_err(|e| vec![LintIssue {
                message: e.to_string(),
                position: SourcePosition::new(1, 1),
                severity: LintSeverity::Error,
            }])?;

        // Run analyzer checks
        if let Err(errors) = self.analyzer.analyze_async_patterns(&ast) {
            for error in errors {
                self.issues.push(LintIssue {
                    message: error.to_string(),
                    position: error.position,
                    severity: LintSeverity::Error,
                });
            }
        }

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

    // Lint a single AST node with async support
    fn lint_node(&mut self, node: &AstNode, pos: SourcePosition) {
        match node {
            AstNode::AsyncFnDecl { name, params, body, .. } => {
                self.lint_function_name(name, pos);
                self.async_contexts.push(name.clone());
                for (param_name, _) in params {
                    self.lint_variable_name(param_name, pos);
                    if self.config.warn_unused_variables.unwrap_or(false) {
                        self.used_variables.insert(param_name.clone());
                    }
                }
                for node in body {
                    self.lint_node(node, pos);
                }
                self.async_contexts.pop();
            }
            AstNode::AwaitExpr { expr, .. } => {
                if self.async_contexts.is_empty() {
                    self.issues.push(LintIssue {
                        message: "await used outside async context".to_string(),
                        position: pos,
                        severity: LintSeverity::Error,
                    });
                }
                self.lint_expr(expr, pos);
            }
            AstNode::Network { op_type, endpoint, headers, data, .. } => {
                self.lint_expr(endpoint, pos);
                if let Some(h) = headers {
                    self.lint_expr(h, pos);
                }
                if let Some(d) = data {
                    self.lint_expr(d, pos);
                }
                if self.config.enforce_network_timeouts.unwrap_or(false) {
                    self.issues.push(LintIssue {
                        message: format!("Network operation '{}' should specify timeout", op_type),
                        position: pos,
                        severity: LintSeverity::Warning,
                    });
                }
            }
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

    // Lint an expression with async support
    fn lint_expr(&mut self, expr: &AstNode, pos: SourcePosition) {
        match expr {
            AstNode::Expr { kind } => match kind {
                ExprKind::AsyncCall { name, args } => {
                    if self.config.require_async_error_handling.unwrap_or(false) {
                        self.issues.push(LintIssue {
                            message: format!("Async call '{}' should handle errors", name),
                            position: pos,
                            severity: LintSeverity::Warning,
                        });
                    }
                    for arg in args {
                        self.lint_expr(arg, pos);
                    }
                }
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
                    severity: LintSeverity::Error,
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
                    severity: LintSeverity::Error,
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
                    severity: LintSeverity::Error,
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
                        severity: LintSeverity::Error,
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

    #[test]
    fn test_lint_async_context() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn test() { let x = await http.get(\"url\"); }"
        ).unwrap();

        let result = lint(&temp_file.path().to_path_buf(), None);
        assert!(result.is_err());
        let issues = result.unwrap_err();
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("await used outside async context"));
    }

    #[test]
    fn test_lint_network_timeout() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "async fn test() { let x = await http.get(\"url\"); }"
        ).unwrap();

        let result = lint(&temp_file.path().to_path_buf(), None);
        assert!(result.is_err());
        let issues = result.unwrap_err();
        assert!(issues.iter().any(|i| i.message.contains("should specify timeout")));
    }

    #[test]
    fn test_lint_async_error_handling() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "async fn test() { let x = await http.get(\"url\"); }"
        ).unwrap();

        let result = lint(&temp_file.path().to_path_buf(), None);
        assert!(result.is_err());
        let issues = result.unwrap_err();
        assert!(issues.iter().any(|i| i.message.contains("should handle errors")));
    }
}