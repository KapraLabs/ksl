// ksl_migrate.rs
// Supports migration of KSL code between versions or platforms, detecting deprecated
// features and updating code to the latest version with a migration report.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_checker::check;
use crate::ksl_doc::{StdLibFunctionTrait};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::collections::VecDeque;

// Migration configuration
#[derive(Debug)]
pub struct MigrationConfig {
    input_file: PathBuf, // Source file to migrate
    output_file: Option<PathBuf>, // Optional output file (defaults to input_file)
    target_version: String, // Target KSL version (e.g., "2.0")
    report_path: Option<PathBuf>, // Optional path for migration report
}

// Migration report entry
#[derive(Debug)]
struct MigrationChange {
    description: String, // Description of the change
    position: SourcePosition, // Location in source code
    remediation: String, // Details of what was changed
}

// Migrator for KSL code
pub struct Migrator {
    config: MigrationConfig,
    changes: Vec<MigrationChange>,
}

impl Migrator {
    pub fn new(config: MigrationConfig) -> Self {
        Migrator {
            config,
            changes: Vec::new(),
        }
    }

    // Migrate a KSL source file to the target version
    pub fn migrate(&mut self) -> Result<Vec<MigrationChange>, KslError> {
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

        // Apply migration transformations
        match self.config.target_version.as_str() {
            "2.0" => {
                self.migrate_to_2_0(&mut ast)?;
            }
            _ => return Err(KslError::type_error(
                format!("Unsupported target version: {}", self.config.target_version),
                pos,
            )),
        }

        // Validate transformed AST
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

        // Generate migration report
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

    // Migrate to KSL version 2.0
    fn migrate_to_2_0(&mut self, ast: &mut Vec<AstNode>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut new_ast = Vec::new();
        for node in ast.iter() {
            match node {
                AstNode::FnDecl { doc, name, params, return_type, body, attributes } => {
                    let mut new_body = Vec::new();
                    self.transform_body(body, &mut new_body)?;
                    new_ast.push(AstNode::FnDecl {
                        doc: doc.clone(),
                        name: name.clone(),
                        params: params.clone(),
                        return_type: return_type.clone(),
                        body: new_body,
                        attributes: attributes.clone(),
                    });
                }
                AstNode::Match { expr, arms } => {
                    let mut new_arms = Vec::new();
                    for arm in arms {
                        let mut new_body = Vec::new();
                        self.transform_body(&arm.body, &mut new_body)?;
                        new_arms.push(arm.clone_with_body(new_body));
                    }
                    new_ast.push(AstNode::Match {
                        expr: expr.clone(),
                        arms: new_arms,
                    });
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    let mut new_then = Vec::new();
                    self.transform_body(then_branch, &mut new_then)?;
                    let mut new_else = None;
                    if let Some(else_branch) = else_branch {
                        let mut new_else_branch = Vec::new();
                        self.transform_body(else_branch, &mut new_else_branch)?;
                        new_else = Some(new_else_branch);
                    }
                    new_ast.push(AstNode::If {
                        condition: condition.clone(),
                        then_branch: new_then,
                        else_branch: new_else,
                    });
                }
                _ => new_ast.push(node.clone()),
            }
        }

        // Check for deprecated array syntax (placeholder: no change needed in this case)
        for node in ast.iter() {
            if let AstNode::VarDecl { type_annot, .. } = node {
                if let Some(TypeAnnotation::Array { element, size }) = type_annot {
                    if element.contains('[') {
                        self.changes.push(MigrationChange {
                            description: "Deprecated array syntax".to_string(),
                            position: pos,
                            remediation: "Update array syntax to array<element, size> format".to_string(),
                        });
                    }
                }
            }
        }

        *ast = new_ast;
        Ok(())
    }

    // Transform a block of statements
    fn transform_body(&mut self, body: &[AstNode], new_body: &mut Vec<AstNode>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        for node in body {
            match node {
                AstNode::Expr { kind: ExprKind::Call { name, .. } } if name == "time.now" => {
                    self.changes.push(MigrationChange {
                        description: "Deprecated API: time.now".to_string(),
                        position: pos,
                        remediation: "time.now is removed in version 2.0; use a static timestamp or external time source".to_string(),
                    });
                    new_body.push(AstNode::Expr {
                        kind: ExprKind::Number("0".to_string()),
                    });
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    let mut new_then = Vec::new();
                    self.transform_body(then_branch, &mut new_then)?;
                    let mut new_else = None;
                    if let Some(else_branch) = else_branch {
                        let mut new_else_branch = Vec::new();
                        self.transform_body(else_branch, &mut new_else_branch)?;
                        new_else = Some(new_else_branch);
                    }
                    new_body.push(AstNode::If {
                        condition: condition.clone(),
                        then_branch: new_then,
                        else_branch: new_else,
                    });
                }
                AstNode::Match { expr, arms } => {
                    let mut new_arms = Vec::new();
                    for arm in arms {
                        let mut new_arm_body = Vec::new();
                        self.transform_body(&arm.body, &mut new_arm_body)?;
                        new_arms.push(arm.clone_with_body(new_arm_body));
                    }
                    new_body.push(AstNode::Match {
                        expr: expr.clone(),
                        arms: new_arms,
                    });
                }
                _ => new_body.push(node.clone()),
            }
        }
        Ok(())
    }

    // Generate migration report
    fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!("KSL Migration Report (to version {})\n=================\n\n", self.config.target_version));
        if self.changes.is_empty() {
            report.push_str("No changes required.\n");
        } else {
            report.push_str(&format!("Applied {} changes:\n\n", self.changes.len()));
            for (i, change) in self.changes.iter().enumerate() {
                report.push_str(&format!(
                    "Change {}: {}\n  Position: {}\n  Remediation: {}\n\n",
                    i + 1,
                    change.description,
                    change.position,
                    change.remediation
                ));
            }
            report.push_str("Note: Deprecated features are documented in the KSL API docs (see ksl_doc.rs).\n");
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
                source.push_str(&param_strings.join(", "));
                source.push_str(&format!("): {} {{\n", format_type(return_type)));
                source.push_str(&ast_to_source(body));
                source.push_str("}\n\n");
            }
            AstNode::VarDecl { name, type_annot, expr, is_mutable, .. } => {
                source.push_str(&format!("    let {}{} = {};\n", if *is_mutable { "mut " } else { "" }, name, expr_to_source(expr)));
            }
            AstNode::If { condition, then_branch, else_branch } => {
                source.push_str(&format!("    if {} {{\n", expr_to_source(condition)));
                source.push_str(&ast_to_source(then_branch));
                if let Some(else_branch) = else_branch {
                    source.push_str("    } else {\n");
                    source.push_str(&ast_to_source(else_branch));
                }
                source.push_str("    }\n");
            }
            AstNode::Match { expr, arms } => {
                source.push_str(&format!("    match {} in ", expr_to_source(expr)));
                let arm_strings: Vec<String> = arms.iter()
                    .map(|arm| {
                        let mut arm_str = String::new();
                        arm_str.push_str(&match &arm.pattern {
                            ExprKind::Range { start, end } => format!(
                                "{}..{}",
                                expr_to_source(start),
                                expr_to_source(end)
                            ),
                            ExprKind::Number(n) => n.clone(),
                            ExprKind::Ident(i) => i.clone(),
                            _ => "".to_string(),
                        });
                        if let Some(var) = &arm.var {
                            arm_str.push_str(&format!(" {{ let {} = ", var));
                        } else {
                            arm_str.push_str(" {{ ");
                        }
                        arm_str.push_str(&ast_to_source(&arm.body));
                        arm_str.push_str(" }}");
                        arm_str
                    })
                    .collect();
                source.push_str(&arm_strings.join(" "));
                source.push_str("\n");
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
fn format_type(annot: &TypeAnnotation) -> String {
    match annot {
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
            ExprKind::Range { start, end } => format!(
                "{}..{}",
                expr_to_source(start),
                expr_to_source(end)
            ),
        },
        _ => String::new(),
    }
}

// Public API to migrate KSL code
pub fn migrate(input_file: &PathBuf, output_file: Option<PathBuf>, target_version: &str, report_path: Option<PathBuf>) -> Result<Vec<MigrationChange>, KslError> {
    let config = MigrationConfig {
        input_file: input_file.clone(),
        output_file,
        target_version: target_version.to_string(),
        report_path,
    };
    let mut migrator = Migrator::new(config);
    migrator.migrate()
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_doc.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_doc {
    pub use super::StdLibFunctionTrait;
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
    fn test_migrate_deprecated_api() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let t: u64 = time.now(); }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let changes = migrate(&input_file, None, "2.0", Some(report_path.clone())).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].description, "Deprecated API: time.now");

        let content = fs::read_to_string(&input_file).unwrap();
        assert!(content.contains("let t: u64 = 0;"));
        assert!(!content.contains("time.now"));

        let report = fs::read_to_string(&report_path).unwrap();
        assert!(report.contains("Deprecated API: time.now"));
        assert!(report.contains("time.now is removed in version 2.0"));
    }

    #[test]
    fn test_migrate_no_changes() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let changes = migrate(&input_file, None, "2.0", Some(report_path.clone())).unwrap();
        assert!(changes.is_empty());

        let report = fs::read_to_string(&report_path).unwrap();
        assert!(report.contains("No changes required"));
    }

    #[test]
    fn test_migrate_invalid_version() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let result = migrate(&input_file, None, "3.0", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported target version"));
    }

    #[test]
    fn test_migrate_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("nonexistent.ksl");

        let result = migrate(&input_file, None, "2.0", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}
