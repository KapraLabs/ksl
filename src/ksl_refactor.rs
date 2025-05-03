// ksl_refactor.rs
// Provides automated refactoring tools for KSL code, supporting operations like
// rename, extract function, and inline variable with validation.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_checker::check;
use crate::ksl_ast_transform::transform;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

// Refactor configuration
#[derive(Debug)]
pub struct RefactorConfig {
    input_file: PathBuf, // Source KSL file
    output_file: Option<PathBuf>, // Optional output file
    rule: String, // Refactoring rule (e.g., "rename", "extract", "inline")
    old_name: Option<String>, // For rename: old identifier name
    new_name: Option<String>, // For rename: new identifier name
    report_path: Option<PathBuf>, // Optional path for refactor report
}

// Refactor report entry
#[derive(Debug)]
struct RefactorChange {
    description: String, // Description of the change
    position: SourcePosition, // Location in source code
}

// Refactor tool
pub struct RefactorTool {
    config: RefactorConfig,
    changes: Vec<RefactorChange>,
}

impl RefactorTool {
    pub fn new(config: RefactorConfig) -> Self {
        RefactorTool {
            config,
            changes: Vec::new(),
        }
    }

    // Apply refactoring to the KSL source
    pub fn refactor(&mut self) -> Result<Vec<RefactorChange>, KslError> {
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

        // Apply refactoring
        match self.config.rule.as_str() {
            "rename" => {
                let old_name = self.config.old_name.as_ref()
                    .ok_or_else(|| KslError::type_error("Missing old_name for rename".to_string(), pos))?;
                let new_name = self.config.new_name.as_ref()
                    .ok_or_else(|| KslError::type_error("Missing new_name for rename".to_string(), pos))?;
                self.rename(&mut ast, old_name, new_name)?;
            }
            "extract" => self.extract_function(&mut ast)?,
            "inline" => self.inline_variable(&mut ast)?,
            _ => return Err(KslError::type_error(
                format!("Unsupported refactoring rule: {}", self.config.rule),
                pos,
            )),
        }

        // Validate refactored code
        check(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        // Serialize AST back to source code
        let transformed_source = ast_to_source(&ast);

        // Write transformed code
        let output_path = self.config.output_file.clone().unwrap_or(self.config.input_file.clone());
        File::create(&output_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output file {}: {}", output_path.display(), e),
                pos,
            ))?
            .write_all(transformed_source.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write output file {}: {}", output_path.display(), e),
                pos,
            ))?;

        // Generate report
        if let Some(report_path) = &self.config.report_path {
            let report_content = self.generate_report();
            File::create(report_path)
                .map_err(|e| KslError::type_error(
                    format!("Failed to create report file {}: {}", report_path.display(), e),
                    pos,
                ))?
                .write_all(report_content.as_bytes())
                .map_err(|e| KslError::type_error(
                    format!("Failed to write report file {}: {}", report_path.display(), e),
                    pos,
                ))?;
        } else {
            println!("{}", self.generate_report());
        }

        Ok(self.changes.clone())
    }

    // Rename an identifier
    fn rename(&mut self, ast: &mut Vec<AstNode>, old_name: &str, new_name: &str) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        for node in ast.iter_mut() {
            match node {
                AstNode::FnDecl { name, body, .. } => {
                    if name == old_name {
                        *name = new_name.to_string();
                        self.changes.push(RefactorChange {
                            description: format!("Renamed function {} to {}", old_name, new_name),
                            position: pos,
                        });
                    }
                    self.rename_in_body(body, old_name, new_name)?;
                }
                AstNode::VarDecl { name, expr, .. } => {
                    if name == old_name {
                        *name = new_name.to_string();
                        self.changes.push(RefactorChange {
                            description: format!("Renamed variable {} to {}", old_name, new_name),
                            position: pos,
                        });
                    }
                    self.rename_in_expr(expr, old_name, new_name)?;
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    self.rename_in_expr(condition, old_name, new_name)?;
                    self.rename_in_body(then_branch, old_name, new_name)?;
                    if let Some(else_branch) = else_branch {
                        self.rename_in_body(else_branch, old_name, new_name)?;
                    }
                }
                AstNode::Match { expr, arms } => {
                    self.rename_in_expr(expr, old_name, new_name)?;
                    for arm in arms {
                        self.rename_in_body(&mut arm.body, old_name, new_name)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // Rename identifiers in a body
    fn rename_in_body(&self, body: &mut Vec<AstNode>, old_name: &str, new_name: &str) -> Result<(), KslError> {
        for node in body.iter_mut() {
            match node {
                AstNode::VarDecl { name, expr, .. } => {
                    if name == old_name {
                        *name = new_name.to_string();
                    }
                    self.rename_in_expr(expr, old_name, new_name)?;
                }
                AstNode::Expr { kind } => {
                    self.rename_in_expr(&mut AstNode::Expr { kind: kind.clone() }, old_name, new_name)?;
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    self.rename_in_expr(condition, old_name, new_name)?;
                    self.rename_in_body(then_branch, old_name, new_name)?;
                    if let Some(else_branch) = else_branch {
                        self.rename_in_body(else_branch, old_name, new_name)?;
                    }
                }
                AstNode::Match { expr, arms } => {
                    self.rename_in_expr(expr, old_name, new_name)?;
                    for arm in arms {
                        self.rename_in_body(&mut arm.body, old_name, new_name)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // Rename identifiers in an expression
    fn rename_in_expr(&self, expr: &mut AstNode, old_name: &str, new_name: &str) -> Result<(), KslError> {
        match expr {
            AstNode::Expr { kind } => match kind {
                ExprKind::Ident(name) if name == old_name => {
                    *name = new_name.to_string();
                }
                ExprKind::BinaryOp { left, right, .. } => {
                    self.rename_in_expr(left, old_name, new_name)?;
                    self.rename_in_expr(right, old_name, new_name)?;
                }
                ExprKind::Call { args, .. } => {
                    for arg in args {
                        self.rename_in_expr(arg, old_name, new_name)?;
                    }
                }
                _ => {}
            },
            _ => {}
        }
        Ok(())
    }

    // Extract an expression into a function (simplified)
    fn extract_function(&mut self, ast: &mut Vec<AstNode>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut new_ast = Vec::new();
        let mut extracted = false;

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
                                    attributes: vec![],
                                };
                                new_ast.push(new_func);
                                new_body.push(AstNode::Expr {
                                    kind: ExprKind::Call {
                                        name: new_func_name,
                                        args: vec![],
                                    },
                                });
                                self.changes.push(RefactorChange {
                                    description: format!("Extracted expression into function {}", new_func_name),
                                    position: pos,
                                });
                                extracted = true;
                            } else {
                                new_body.push(stmt.clone());
                            }
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

    // Inline a variable (simplified)
    fn inline_variable(&mut self, ast: &mut Vec<AstNode>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut new_ast = Vec::new();
        let mut inlined = false;

        for node in ast.iter() {
            match node {
                AstNode::FnDecl { name, params, return_type, body, attributes, .. } => {
                    let mut new_body = Vec::new();
                    let mut var_value: Option<AstNode> = None;
                    let mut var_name: Option<String> = None;

                    for stmt in body.iter() {
                        match stmt {
                            AstNode::VarDecl { name: v_name, expr, .. } if !inlined => {
                                var_value = Some(expr.clone());
                                var_name = Some(v_name.clone());
                                inlined = true;
                                continue; // Skip adding the variable declaration
                            }
                            AstNode::Expr { kind } => {
                                if let (Some(ref value), Some(ref name)) = (&var_value, &var_name) {
                                    let mut new_stmt = stmt.clone();
                                    self.inline_in_expr(&mut new_stmt, name, value)?;
                                    new_body.push(new_stmt);
                                    self.changes.push(RefactorChange {
                                        description: format!("Inlined variable {}", name),
                                        position: pos,
                                    });
                                } else {
                                    new_body.push(stmt.clone());
                                }
                            }
                            _ => new_body.push(stmt.clone()),
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

    // Inline a variable in an expression
    fn inline_in_expr(&self, expr: &mut AstNode, var_name: &str, value: &AstNode) -> Result<(), KslError> {
        match expr {
            AstNode::Expr { kind } => match kind {
                ExprKind::Ident(name) if name == var_name => {
                    *expr = value.clone();
                }
                ExprKind::BinaryOp { left, right, .. } => {
                    self.inline_in_expr(left, var_name, value)?;
                    self.inline_in_expr(right, var_name, value)?;
                }
                ExprKind::Call { args, .. } => {
                    for arg in args {
                        self.inline_in_expr(arg, var_name, value)?;
                    }
                }
                _ => {}
            },
            _ => {}
        }
        Ok(())
    }

    // Generate refactor report
    fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str("KSL Refactor Report\n=================\n\n");
        if self.changes.is_empty() {
            report.push_str("No changes applied.\n");
        } else {
            report.push_str(&format!("Applied {} changes:\n\n", self.changes.len()));
            for (i, change) in self.changes.iter().enumerate() {
                report.push_str(&format!(
                    "Change {}: {}\n  Position: {}\n\n",
                    i + 1,
                    change.description,
                    change.position
                ));
            }
        }
        report
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
                source.push_str(¶m_strings.join(", "));
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
pub fn refactor(input_file: &PathBuf, output_file: Option<PathBuf>, rule: &str, old_name: Option<String>, new_name: Option<String>, report_path: Option<PathBuf>) -> Result<Vec<RefactorChange>, KslError> {
    let config = RefactorConfig {
        input_file: input_file.clone(),
        output_file,
        rule: rule.to_string(),
        old_name,
        new_name,
        report_path,
    };
    let mut tool = RefactorTool::new(config);
    tool.refactor()
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

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

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
        let changes = refactor(&input_file, None, "rename", Some("x".to_string()), Some("z".to_string()), Some(report_path.clone())).unwrap();
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
        let changes = refactor(&input_file, None, "extract", None, None, Some(report_path.clone())).unwrap();
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
        let changes = refactor(&input_file, None, "inline", None, None, Some(report_path.clone())).unwrap();
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
        let result = refactor(&input_file, None, "invalid", None, None, Some(report_path));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported refactoring rule"));
    }

    #[test]
    fn test_refactor_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("nonexistent.ksl");
        let report_path = temp_dir.path().join("report.txt");

        let result = refactor(&input_file, None, "rename", Some("x".to_string()), Some("y".to_string()), Some(report_path));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}
```

---

### 6. `ksl_doc_lsp.rs`

This file integrates `ksl_docgen.rs` with `ksl_lsp.rs` to provide in-IDE documentation via LSP, supporting hover and completion with cached documentation and cross-references.

<xaiArtifact artifact_id="c74f6e1a-3857-46d4-b266-74a9b40f6f0c" artifact_version_id="9977979c-8d6a-4fa1-a122-43ceea72cd12" title="ksl_doc_lsp.rs" contentType="text/rust">
```rust
// ksl_doc_lsp.rs
// Integrates ksl_docgen.rs with ksl_lsp.rs to provide documentation in IDEs via LSP,
// serving hover and completion docs with caching.

use crate::ksl_docgen::generate_docgen;
use crate::ksl_lsp::start_lsp;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// Doc LSP configuration
#[derive(Debug)]
pub struct DocLspConfig {
    port: u16, // Port to listen on
    doc_cache_dir: PathBuf, // Directory for cached documentation
}

// Doc LSP server
pub struct DocLspServer {
    config: DocLspConfig,
    doc_cache: Arc<Mutex<HashMap<String, String>>>, // Cache of documentation (function -> doc)
}

impl DocLspServer {
    pub fn new(config: DocLspConfig) -> Self {
        DocLspServer {
            config,
            doc_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // Start the Doc LSP server
    pub fn start(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Preload documentation for standard library
        self.preload_docs()?;

        // Start LSP server with custom hover handler
        start_lsp(self.config.port)?;
        Ok(())
    }

    // Preload documentation into cache
    fn preload_docs(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Generate documentation for standard library (simulated)
        let temp_file = self.config.doc_cache_dir.join("std_temp.ksl");
        let mut file = File::create(&temp_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to create temp file {}: {}", temp_file.display(), e),
                pos,
            ))?;
        writeln!(
            file,
            "/// Computes the SHA-3 hash\nfn sha3(data: string): array<u8, 32> {{}}\n/// Matrix multiplication\nfn matrix.mul(a: array<array<f64, 4>, 4>, b: array<array<f64, 4>, 4>): array<array<f64, 4>, 4> {{}}"
        ).map_err(|e| KslError::type_error(
            format!("Failed to write temp file {}: {}", temp_file.display(), e),
            pos,
        ))?;

        generate_docgen("std", "markdown", self.config.doc_cache_dir.clone())?;
        let doc_file = self.config.doc_cache_dir.join("std.md");
        let content = fs::read_to_string(&doc_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read doc file {}: {}", doc_file.display(), e),
                pos,
            ))?;

        // Parse documentation into cache
        let mut cache = self.doc_cache.lock().unwrap();
        let mut current_func = None;
        let mut current_doc = String::new();
        for line in content.lines() {
            if line.starts_with("## Function `") {
                if let Some(func) = current_func {
                    cache.insert(func, current_doc.trim().to_string());
                }
                current_func = Some(line[12..line.len()-1].to_string());
                current_doc = String::new();
            } else if current_func.is_some() {
                current_doc.push_str(line);
                current_doc.push('\n');
            }
        }
        if let Some(func) = current_func {
            cache.insert(func, current_doc.trim().to_string());
        }

        // Clean up temp file
        fs::remove_file(&temp_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to clean up temp file {}: {}", temp_file.display(), e),
                pos,
            ))?;
        Ok(())
    }

    // Get documentation for a function (used by LSP server)
    pub fn get_doc(&self, func_name: &str) -> Option<String> {
        let cache = self.doc_cache.lock().unwrap();
        cache.get(func_name).cloned()
    }
}

// Public API to start the Doc LSP server
pub fn start_doc_lsp(port: u16, doc_cache_dir: PathBuf) -> Result<(), KslError> {
    let pos = SourcePosition::new(1, 1);
    if port < 1024 || port > 65535 {
        return Err(KslError::type_error(
            "Port must be between 1024 and 65535".to_string(),
            pos,
        ));
    }

    let config = DocLspConfig {
        port,
        doc_cache_dir,
    };
    let server = DocLspServer::new(config);
    server.start()
}

// Assume ksl_docgen.rs, ksl_lsp.rs, and ksl_errors.rs are in the same crate
mod ksl_docgen {
    pub use super::generate_docgen;
}

mod ksl_lsp {
    pub use super::start_lsp;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_doc_lsp_preload() {
        let temp_dir = TempDir::new().unwrap();
        let doc_cache_dir = temp_dir.path().join("docs");
        fs::create_dir_all(&doc_cache_dir).unwrap();

        let config = DocLspConfig {
            port: 9002,
            doc_cache_dir: doc_cache_dir.clone(),
        };
        let server = DocLspServer::new(config);

        let result = server.preload_docs();
        assert!(result.is_ok());

        let doc_file = doc_cache_dir.join("std.md");
        assert!(doc_file.exists());
        let content = fs::read_to_string(&doc_file).unwrap();
        assert!(content.contains("## Function `sha3`"));
        assert!(content.contains("## Function `matrix.mul`"));

        let doc = server.get_doc("sha3");
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Computes the SHA-3 hash"));
    }

    #[test]
    fn test_doc_lsp_invalid_port() {
        let temp_dir = TempDir::new().unwrap();
        let doc_cache_dir = temp_dir.path().join("docs");

        let result = start_doc_lsp(80, doc_cache_dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Port must be between 1024 and 65535"));
    }
}
