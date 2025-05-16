// ksl_refactor.rs
// Provides automated refactoring tools for KSL code, supporting operations like
// rename, extract function, and inline variable with validation.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError, TypeAnnotation};
use crate::ksl_checker::check;
use crate::ksl_ast_transform::transform;
use crate::ksl_analyzer::{Analyzer, AnalysisResult};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_async::{AsyncContext, AsyncCommand};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::{HashMap, HashSet};

/// Configuration for KSL code refactoring.
#[derive(Debug)]
pub struct RefactorConfig {
    /// Source KSL file to refactor
    input_file: PathBuf,
    /// Optional output file (defaults to input_file)
    output_file: Option<PathBuf>,
    /// Refactoring rule to apply (e.g., "rename", "extract", "inline")
    rule: String,
    /// For rename: old identifier name
    old_name: Option<String>,
    /// For rename: new identifier name
    new_name: Option<String>,
    /// Optional path for refactor report
    report_path: Option<PathBuf>,
    /// Whether to enable async processing
    enable_async: bool,
}

/// Represents a single refactoring change
#[derive(Clone)]
struct RefactorChange {
    /// Description of the change
    description: String,
    /// Location in source code
    position: SourcePosition,
    /// Whether the change requires async processing
    requires_async: bool,
}

/// Handles automated refactoring of KSL code with async support.
pub struct RefactorTool {
    /// Refactoring configuration
    config: RefactorConfig,
    /// List of changes made during refactoring
    changes: Vec<RefactorChange>,
    /// Async context for processing
    async_context: Arc<Mutex<AsyncContext>>,
    /// Code analyzer for validation
    analyzer: Arc<Mutex<Analyzer>>,
}

impl RefactorTool {
    /// Creates a new refactoring tool with the given configuration.
    pub fn new(config: RefactorConfig) -> Self {
        RefactorTool {
            config,
            changes: Vec::new(),
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
            analyzer: Arc::new(Mutex::new(Analyzer::new())),
        }
    }

    /// Applies refactoring to the KSL source asynchronously.
    pub async fn refactor(&mut self) -> Result<Vec<RefactorChange>, KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Read and parse source
        let source = fs::read_to_string(&self.config.input_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", self.config.input_file.display(), e),
                pos,
                "REFACTOR_READ_ERROR".to_string()
            ))?;
        
        let mut ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
                "REFACTOR_PARSE_ERROR".to_string()
            ))?;

        // Analyze code before refactoring
        let mut analyzer = self.analyzer.lock().await;
        let analysis = analyzer.analyze_file(&ast)
            .map_err(|e| KslError::type_error(
                format!("Analysis failed: {}", e),
                pos,
                "REFACTOR_ANALYSIS_ERROR".to_string()
            ))?;

        // Apply refactoring
        match self.config.rule.as_str() {
            "rename" => {
                let old_name = self.config.old_name.as_ref()
                    .ok_or_else(|| KslError::type_error("Missing old_name for rename".to_string(), pos, "E301".to_string()))?;
                let new_name = self.config.new_name.as_ref()
                    .ok_or_else(|| KslError::type_error("Missing new_name for rename".to_string(), pos, "E302".to_string()))?;
                self.rename(&mut ast, old_name, new_name).await?;
            }
            "extract" => self.extract_function(&mut ast).await?,
            "inline" => self.inline_variable(&mut ast).await?,
            _ => return Err(KslError::type_error(
                format!("Unsupported refactoring rule: {}", self.config.rule),
                pos,
                "REFACTOR_UNKNOWN_RULE".to_string()
            )),
        }

        // Validate refactored code
        check(&ast[..])
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
                "REFACTOR_TYPE_ERROR".to_string()
            ))?;

        // Analyze code after refactoring
        let post_analysis = analyzer.analyze_file(&ast)
            .map_err(|e| KslError::type_error(
                format!("Post-refactoring analysis failed: {}", e),
                pos,
                "REFACTOR_POST_ANALYSIS_ERROR".to_string()
            ))?;

        // Compare analysis results
        self.compare_analyses(&analysis, &post_analysis)?;

        // Serialize AST back to source code
        let transformed_source = ast_to_source(&ast);

        // Write transformed code
        let output_path = self.config.output_file.clone().unwrap_or(self.config.input_file.clone());
        File::create(&output_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output file {}: {}", output_path.display(), e),
                pos,
                "REFACTOR_OUTPUT_ERROR".to_string()
            ))?
            .write_all(transformed_source.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write output file {}: {}", output_path.display(), e),
                pos,
                "REFACTOR_WRITE_ERROR".to_string()
            ))?;

        // Generate report
        if let Some(report_path) = &self.config.report_path {
            let report_content = self.generate_report();
            File::create(report_path)
                .map_err(|e| KslError::type_error(
                    format!("Failed to create report file {}: {}", report_path.display(), e),
                    pos,
                    "REFACTOR_REPORT_CREATE_ERROR".to_string()
                ))?
                .write_all(report_content.as_bytes())
                .map_err(|e| KslError::type_error(
                    format!("Failed to write report file {}: {}", report_path.display(), e),
                    pos,
                    "REFACTOR_REPORT_WRITE_ERROR".to_string()
                ))?;
        } else {
            println!("{}", self.generate_report());
        }

        Ok(self.changes.clone())
    }

    /// Renames an identifier with async support.
    async fn rename(&mut self, ast: &mut Vec<AstNode>, old_name: &str, new_name: &str) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Check for async functions
        let is_async = self.contains_async_function(ast);
        if is_async && self.config.enable_async {
            let mut async_ctx = self.async_context.lock().await;
            let command = AsyncCommand::RenameIdentifier(old_name.to_string(), new_name.to_string());
            async_ctx.execute_command(command).await?;
        }

        for node in ast.iter_mut() {
            match node {
                AstNode::FnDecl { name, body, attributes, .. } => {
                    if name == old_name {
                        *name = new_name.to_string();
                        self.changes.push(RefactorChange {
                            description: format!("Renamed function {} to {}", old_name, new_name),
                            position: pos,
                            requires_async: is_async,
                        });
                    }
                    self.rename_in_body(body, old_name, new_name).await?;
                }
                AstNode::VarDecl { name, expr, .. } => {
                    if name == old_name {
                        *name = new_name.to_string();
                        self.changes.push(RefactorChange {
                            description: format!("Renamed variable {} to {}", old_name, new_name),
                            position: pos,
                            requires_async: is_async,
                        });
                    }
                    self.rename_in_expr(expr, old_name, new_name).await?;
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    self.rename_in_expr(condition, old_name, new_name).await?;
                    self.rename_in_body(then_branch, old_name, new_name).await?;
                    if let Some(else_branch) = else_branch {
                        self.rename_in_body(else_branch, old_name, new_name).await?;
                    }
                }
                AstNode::Match { expr, arms } => {
                    self.rename_in_expr(expr, old_name, new_name).await?;
                    for arm in arms {
                        self.rename_in_body(&mut arm.body, old_name, new_name).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Renames identifiers in a body with async support.
    async fn rename_in_body(&self, body: &mut Vec<AstNode>, old_name: &str, new_name: &str) -> Result<(), KslError> {
        for node in body.iter_mut() {
            match node {
                AstNode::VarDecl { name, expr, .. } => {
                    if name == old_name {
                        *name = new_name.to_string();
                    }
                    self.rename_in_expr(expr, old_name, new_name).await?;
                }
                AstNode::Expr { kind } => {
                    self.rename_in_expr(&mut AstNode::Expr { kind: kind.clone() }, old_name, new_name).await?;
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    self.rename_in_expr(condition, old_name, new_name).await?;
                    self.rename_in_body(then_branch, old_name, new_name).await?;
                    if let Some(else_branch) = else_branch {
                        self.rename_in_body(else_branch, old_name, new_name).await?;
                    }
                }
                AstNode::Match { expr, arms } => {
                    self.rename_in_expr(expr, old_name, new_name).await?;
                    for arm in arms {
                        self.rename_in_body(&mut arm.body, old_name, new_name).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Renames identifiers in an expression with async support.
    async fn rename_in_expr(&self, expr: &mut AstNode, old_name: &str, new_name: &str) -> Result<(), KslError> {
        match expr {
            AstNode::Expr { kind } => match kind {
                ExprKind::Ident(name) if name == old_name => {
                    *kind = ExprKind::Ident(new_name.to_string());
                }
                ExprKind::BinaryOp { left, right, .. } => {
                    self.rename_in_expr(left, old_name, new_name).await?;
                    self.rename_in_expr(right, old_name, new_name).await?;
                }
                ExprKind::Call { args, .. } => {
                    for arg in args {
                        self.rename_in_expr(arg, old_name, new_name).await?;
                    }
                }
                _ => {}
            },
            _ => {}
        }
        Ok(())
    }

    /// Extracts an expression into a function with async support.
    async fn extract_function(&mut self, ast: &mut Vec<AstNode>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut new_ast = Vec::new();
        let mut extracted = false;

        // Check for async functions
        let is_async = self.contains_async_function(ast);
        if is_async && self.config.enable_async {
            let mut async_ctx = self.async_context.lock().await;
            let command = AsyncCommand::ExtractFunction;
            async_ctx.execute_command(command).await?;
        }

        for node in ast.iter() {
            match node {
                AstNode::FnDecl { name, params, return_type, body, attributes, .. } => {
                    let mut new_body = Vec::new();
                    for (i, stmt) in body.iter().enumerate() {
                        if let AstNode::Expr { kind: ExprKind::BinaryOp { op, left, right } } = stmt {
                            if !extracted {
                                let new_func_name = format!("extracted_{}", i);
                                let new_func = AstNode::FnDecl {
                                    doc: None,
                                    name: new_func_name.clone(),
                                    params: vec![],
                                    return_type: TypeAnnotation::Simple("u32".to_string()),
                                    body: vec![AstNode::Expr {
                                        kind: ExprKind::BinaryOp {
                                            op: op.clone(),
                                            left: left.clone(),
                                            right: right.clone(),
                                        },
                                    }],
                                    attributes: if is_async { vec!["async".to_string()] } else { vec![] },
                                };
                                new_ast.push(new_func);
                                self.changes.push(RefactorChange {
                                    description: format!("Extracted expression into function {}", new_func_name),
                                    position: pos,
                                    requires_async: is_async,
                                });
                                extracted = true;
                            }
                        }
                        new_body.push(stmt.clone());
                    }
                    new_ast.push(AstNode::FnDecl {
                        doc: None,
                        name: name.clone(),
                        params: params.clone(),
                        return_type: return_type.clone(),
                        body: new_body,
                        attributes: attributes.clone(),
                    });
                }
                _ => new_ast.push(node.clone()),
            }
        }

        *ast = new_ast;
        Ok(())
    }

    /// Inlines a variable with async support.
    async fn inline_variable(&mut self, ast: &mut Vec<AstNode>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut new_ast = Vec::new();

        // Check for async functions
        let is_async = self.contains_async_function(ast);
        if is_async && self.config.enable_async {
            let mut async_ctx = self.async_context.lock().await;
            let command = AsyncCommand::InlineVariable;
            async_ctx.execute_command(command).await?;
        }

        for node in ast.iter() {
            match node {
                AstNode::FnDecl { name, params, return_type, body, attributes, .. } => {
                    let mut new_body = Vec::new();
                    for stmt in body.iter() {
                        if let AstNode::VarDecl { name: var_name, expr, .. } = stmt {
                            self.changes.push(RefactorChange {
                                description: format!("Inlined variable {}", var_name),
                                position: pos,
                                requires_async: is_async,
                            });
                            self.inline_in_body(&mut new_body, var_name, expr)?;
                        } else {
                            new_body.push(stmt.clone());
                        }
                    }
                    new_ast.push(AstNode::FnDecl {
                        doc: None,
                        name: name.clone(),
                        params: params.clone(),
                        return_type: return_type.clone(),
                        body: new_body,
                        attributes: attributes.clone(),
                    });
                }
                _ => new_ast.push(node.clone()),
            }
        }

        *ast = new_ast;
        Ok(())
    }

    /// Checks if the AST contains any async functions.
    fn contains_async_function(&self, ast: &[AstNode]) -> bool {
        for node in ast {
            match node {
                AstNode::FnDecl { attributes, .. } => {
                    if attributes.iter().any(|attr| attr == "async") {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Compares pre and post-refactoring analysis results.
    fn compare_analyses(&self, pre: &AnalysisResult, post: &AnalysisResult) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        
        // Check for performance regressions
        if post.performance_metrics.avg_execution_time > pre.performance_metrics.avg_execution_time {
            return Err(KslError::type_error(
                "Refactoring caused performance regression".to_string(),
                pos,
                "REFACTOR_PERFORMANCE_REGRESSION".to_string()
            ));
        }

        // Check for memory usage changes
        if post.memory_metrics.peak_memory > pre.memory_metrics.peak_memory {
            return Err(KslError::type_error(
                "Refactoring increased memory usage".to_string(),
                pos,
                "REFACTOR_MEMORY_USAGE_INCREASE".to_string()
            ));
        }

        Ok(())
    }

    /// Generates a detailed refactoring report.
    fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!("KSL Refactoring Report\n=================\n\n"));
        if self.changes.is_empty() {
            report.push_str("No changes made.\n");
        } else {
            report.push_str(&format!("Applied {} changes:\n\n", self.changes.len()));
            for (i, change) in self.changes.iter().enumerate() {
                report.push_str(&format!(
                    "Change {}: {}\n  Position: {}\n  Async: {}\n\n",
                    i + 1,
                    change.description,
                    change.position,
                    change.requires_async
                ));
            }
        }
        report
    }

    /// Helper function to inline variables within a body of statements
    fn inline_in_body(&mut self, new_body: &mut Vec<AstNode>, var_name: &str, expr: &AstNode) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        
        for i in 0..new_body.len() {
            match &mut new_body[i] {
                AstNode::Expr { kind: ExprKind::Ident(name) } if name == var_name => {
                    // Replace variable reference with inlined expression
                    new_body[i] = expr.clone();
                }
                AstNode::Expr { kind } => {
                    // Recursively process expressions
                    match kind {
                        ExprKind::BinaryOp { left, right, .. } => {
                            self.inline_in_expr(left, var_name, expr)?;
                            self.inline_in_expr(right, var_name, expr)?;
                        }
                        ExprKind::Call { args, .. } => {
                            for arg in args {
                                self.inline_in_expr(arg, var_name, expr)?;
                            }
                        }
                        _ => {}
                    }
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    self.inline_in_expr(condition, var_name, expr)?;
                    self.inline_in_body(then_branch, var_name, expr)?;
                    if let Some(else_branch) = else_branch {
                        self.inline_in_body(else_branch, var_name, expr)?;
                    }
                }
                _ => {}
            }
        }
        
        Ok(())
    }
    
    /// Helper function to inline variables within an expression
    fn inline_in_expr(&mut self, node: &mut AstNode, var_name: &str, expr: &AstNode) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        
        match node {
            AstNode::Expr { kind: ExprKind::Ident(name) } if name == var_name => {
                *node = expr.clone();
            }
            AstNode::Expr { kind } => {
                match kind {
                    ExprKind::BinaryOp { left, right, .. } => {
                        self.inline_in_expr(left, var_name, expr)?;
                        self.inline_in_expr(right, var_name, expr)?;
                    }
                    ExprKind::Call { args, .. } => {
                        for arg in args {
                            self.inline_in_expr(arg, var_name, expr)?;
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        
        Ok(())
    }
}

// Convert AST back to source code (simplified)
fn ast_to_source(ast: &[AstNode]) -> String {
    let mut source = String::new();
    for node in ast {
        match node {
            AstNode::FnDecl { doc, name, params, return_type, body, attributes } => {
                if let Some(doc) = doc {
                    source.push_str(&format!("/// {}\n", doc.text));
                }
                for attr in attributes {
                    source.push_str(&format!("#[{}]\n", attr.name));
                }
                source.push_str(&format!("fn {}(", name));
                let param_strings: Vec<String> = params.iter()
                    .map(|(name, typ)| format!("{}: {}", name, format_type(typ)))
                    .collect();
                source.push_str(param_strings.join(", "));
                source.push_str(&format!("): {} {{\n", format_type(return_type)));
                source.push_str(&ast_to_source(body));
                source.push_str("}\n\n");
            }
            AstNode::VarDecl { name, type_annot, expr, is_mutable, .. } => {
                source.push_str(&format!(
                    "    let {}{} = {};\n",
                    if *is_mutable { "mut " } else { "" },
                    name,
                    expr_to_source(expr)
                ));
            }
            AstNode::Expr { kind } => {
                source.push_str(&format!("    {};\n", expr_to_source(&AstNode::Expr { kind: kind.clone() })));
            }
            _ => {}
        }
    }
    source
}

// Format a type annotation
fn format_type(typ: &TypeAnnotation) -> String {
    match typ {
        TypeAnnotation::Simple(name) => name.clone(),
        TypeAnnotation::Array { element, size } => format!("array<{}, {}>", element, size),
        TypeAnnotation::Result { success, error } => format!("result<{}, {}>", success, error),
    }
}

// Convert expression to source code (simplified)
fn expr_to_source(expr: &AstNode) -> String {
    match expr {
        AstNode::Expr { kind } => match kind {
            ExprKind::Ident(name) => name.clone(),
            ExprKind::Number(num) => num.clone(),
            ExprKind::String(s) => format!("\"{}\"", s),
            ExprKind::BinaryOp { op, left, right } => format!(
                "({} {} {})",
                expr_to_source(left),
                op,
                expr_to_source(right)
            ),
            ExprKind::Call { name, args } => {
                let arg_strings: Vec<String> = args.iter().map(expr_to_source).collect();
                format!("{}({})", name, arg_strings.join(", "))
            }
            _ => "".to_string(),
        },
        _ => "".to_string(),
    }
}

// Public API to refactor KSL code
pub fn refactor(input_file: &PathBuf, output_file: Option<PathBuf>, rule: &str, old_name: Option<String>, new_name: Option<String>, report_path: Option<PathBuf>, enable_async: bool) -> Result<Vec<RefactorChange>, KslError> {
    let config = RefactorConfig {
        input_file: input_file.clone(),
        output_file,
        rule: rule.to_string(),
        old_name,
        new_name,
        report_path,
        enable_async,
    };
    let mut tool = RefactorTool::new(config);
    tool.refactor().await
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_ast_transform.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_ast_transform {
    pub use super::transform;
}

mod ksl_analyzer {
    pub use super::{Analyzer, AnalysisResult};
}

mod ksl_async {
    pub use super::{AsyncContext, AsyncCommand};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

/*
---

### 6. `ksl_doc_lsp.rs`

This file integrates `ksl_docgen.rs` with `ksl_lsp.rs` to provide in-IDE documentation via LSP, supporting hover and completion with cached documentation and cross-references.

<xaiArtifact artifact_id="c74f6e1a-3857-46d4-b266-74a9b40f6f0c" artifact_version_id="9977979c-8d6a-4fa1-a122-43ceea72cd12" title="ksl_doc_lsp.rs" contentType="text/rust">
```rust
// ksl_doc_lsp.rs
*/

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_refactor_rename() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; let y = x + 1; }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let changes = refactor(&input_file, None, "rename", Some("x".to_string()), Some("z".to_string()), Some(report_path.clone()), true).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].description, "Renamed variable x to z");

        let content = fs::read_to_string(&input_file).unwrap();
        assert!(content.contains("let z: u32 = 42;"));
        assert!(content.contains("let y = z + 1;"));

        let report = fs::read_to_string(&report_path).unwrap();
        assert!(report.contains("Renamed variable x to z"));
    }

    #[test]
    fn test_refactor_extract() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let result = 10 + 20; }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let changes = refactor(&input_file, None, "extract", None, None, Some(report_path.clone()), true).unwrap();
        assert_eq!(changes.len(), 1);
        assert!(changes[0].description.contains("Extracted expression into function"));

        let content = fs::read_to_string(&input_file).unwrap();
        assert!(content.contains("fn extracted_0(): u32 {"));
        assert!(content.contains("10 + 20;"));
        assert!(content.contains("extracted_0();"));

        let report = fs::read_to_string(&report_path).unwrap();
        assert!(report.contains("Extracted expression into function"));
    }

    #[test]
    fn test_refactor_inline() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; let y = x + 1; }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let changes = refactor(&input_file, None, "inline", None, None, Some(report_path.clone()), true).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].description, "Inlined variable x");

        let content = fs::read_to_string(&input_file).unwrap();
        assert!(content.contains("let y = 42 + 1;"));
        assert!(!content.contains("let x: u32 = 42;"));

        let report = fs::read_to_string(&report_path).unwrap();
        assert!(report.contains("Inlined variable x"));
    }

    #[test]
    fn test_refactor_invalid_rule() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let result = refactor(&input_file, None, "invalid", None, None, Some(report_path), true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported refactoring rule"));
    }

    #[test]
    fn test_refactor_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("nonexistent.ksl");
        let report_path = temp_dir.path().join("report.txt");

        let result = refactor(&input_file, None, "rename", Some("x".to_string()), Some("y".to_string()), Some(report_path), true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}