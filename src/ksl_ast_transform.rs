// ksl_ast_transform.rs
// Enables AST transformations for advanced code generation and optimization,
// supporting function inlining, loop unrolling, async/await transformation,
// and networking operation optimization.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_checker::check;
use crate::ksl_plugin::{PluginSystem, KslPlugin};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::collections::HashMap;

/// Configuration for AST transformations.
#[derive(Debug)]
pub struct TransformConfig {
    /// Source file to transform
    input_file: PathBuf,
    /// Optional output file (defaults to input_file)
    output_file: Option<PathBuf>,
    /// Transformation rule (e.g., "inline", "unroll", "async", "network")
    rule: String,
    /// Optional plugin for custom transformation
    plugin_name: Option<String>,
    /// Maximum number of iterations for loop unrolling
    max_unroll_iterations: u32,
    /// Whether to preserve networking state during transformation
    preserve_networking: bool,
}

/// AST transformer that handles various code transformations.
pub struct AstTransformer {
    config: TransformConfig,
    plugin_system: PluginSystem,
}

impl AstTransformer {
    /// Creates a new AST transformer with the given configuration.
    pub fn new(config: TransformConfig) -> Self {
        AstTransformer {
            config,
            plugin_system: PluginSystem::new(),
        }
    }

    /// Transforms a KSL source file according to the configured rules.
    pub fn transform(&mut self) -> Result<(), KslError> {
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

        // Apply transformation
        if let Some(plugin_name) = &self.config.plugin_name {
            // Use plugin for custom transformation
            self.plugin_system.run_plugin(
                plugin_name,
                "transform",
                &self.config.input_file,
                &[self.config.rule.clone()],
            )?;
        } else {
            // Apply built-in transformation
            match self.config.rule.as_str() {
                "inline" => self.inline_functions(&mut ast)?,
                "unroll" => self.unroll_loops(&mut ast)?,
                "async" => self.transform_async(&mut ast)?,
                "network" => self.optimize_networking(&mut ast)?,
                _ => return Err(KslError::type_error(
                    format!("Unknown transformation rule: {}", self.config.rule),
                    pos,
                )),
            }
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

        Ok(())
    }

    /// Inlines function calls in the AST.
    fn inline_functions(&self, ast: &mut Vec<AstNode>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut functions = HashMap::new();
        for node in ast.iter() {
            if let AstNode::FnDecl { name, params, body, .. } = node {
                functions.insert(name.clone(), (params.clone(), body.clone()));
            }
        }

        let mut new_ast = Vec::new();
        for node in ast.iter() {
            match node {
                AstNode::Expr { kind: ExprKind::Call { name, args } } => {
                    if let Some((params, body)) = functions.get(name) {
                        if params.len() != args.len() {
                            return Err(KslError::type_error(
                                format!("Function {} expects {} arguments, got {}", name, params.len(), args.len()),
                                pos,
                            ));
                        }
                        // Create a new block with variable declarations for arguments
                        let mut inline_block = Vec::new();
                        for ((param_name, _), arg) in params.iter().zip(args) {
                            inline_block.push(AstNode::VarDecl {
                                doc: None,
                                name: param_name.clone(),
                                type_annot: None,
                                expr: Box::new(arg.clone()),
                                is_mutable: false,
                            });
                        }
                        inline_block.extend(body.clone());
                        new_ast.extend(inline_block);
                    } else {
                        new_ast.push(node.clone());
                    }
                }
                _ => new_ast.push(node.clone()),
            }
        }

        *ast = new_ast;
        Ok(())
    }

    /// Unrolls loops in the AST up to the configured maximum iterations.
    fn unroll_loops(&self, ast: &mut Vec<AstNode>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut new_ast = Vec::new();
        for node in ast.iter() {
            match node {
                AstNode::Match { expr, arms } => {
                    let mut unrolled = Vec::new();
                    for arm in arms {
                        let (start, end) = match &arm.pattern {
                            ExprKind::Range { start, end } => {
                                if let (ExprKind::Number(start), ExprKind::Number(end)) = (&start.kind, &end.kind) {
                                    (start.parse::<u32>().unwrap_or(0), end.parse::<u32>().unwrap_or(0))
                                } else {
                                    return Err(KslError::type_error(
                                        "Range bounds must be numeric literals".to_string(),
                                        pos,
                                    ));
                                }
                            }
                            _ => {
                                unrolled.push(AstNode::Match {
                                    expr: expr.clone(),
                                    arms: arms.clone(),
                                });
                                continue;
                            }
                        };

                        let var_name = match &arm.var {
                            Some(name) => name.clone(),
                            None => return Err(KslError::type_error(
                                "Range match requires a variable".to_string(),
                                pos,
                            )),
                        };

                        // Unroll the loop up to max_unroll_iterations
                        for i in start..end.min(start + self.config.max_unroll_iterations) {
                            let mut new_body = arm.body.clone();
                            // Replace variable with literal
                            for node in new_body.iter_mut() {
                                if let AstNode::Expr { kind: ExprKind::Ident(ref name) } = node {
                                    if name == &var_name {
                                        *node = AstNode::Expr {
                                            kind: ExprKind::Number(i.to_string()),
                                        };
                                    }
                                }
                            }
                            unrolled.extend(new_body);
                        }
                    }
                    new_ast.extend(unrolled);
                }
                _ => new_ast.push(node.clone()),
            }
        }

        *ast = new_ast;
        Ok(())
    }

    /// Transforms async/await code into a state machine.
    fn transform_async(&self, ast: &mut Vec<AstNode>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut new_ast = Vec::new();

        for node in ast.iter() {
            match node {
                AstNode::AsyncFnDecl { name, params, body, .. } => {
                    // Transform async function into a state machine
                    let mut state_machine = Vec::new();
                    let mut state = 0;

                    for stmt in body {
                        match stmt {
                            AstNode::Await { expr, .. } => {
                                // Add state transition
                                state_machine.push(AstNode::StateTransition {
                                    from_state: state,
                                    to_state: state + 1,
                                    condition: expr.clone(),
                                });
                                state += 1;
                            }
                            _ => state_machine.push(stmt.clone()),
                        }
                    }

                    // Add the transformed function to the new AST
                    new_ast.push(AstNode::FnDecl {
                        doc: None,
                        name: name.clone(),
                        params: params.clone(),
                        return_type: None,
                        body: state_machine,
                        is_async: false,
                    });
                }
                _ => new_ast.push(node.clone()),
            }
        }

        *ast = new_ast;
        Ok(())
    }

    /// Optimizes networking operations in the AST.
    fn optimize_networking(&self, ast: &mut Vec<AstNode>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut new_ast = Vec::new();

        for node in ast.iter() {
            match node {
                AstNode::Expr { kind: ExprKind::Network { op_type, endpoint, headers, data } } => {
                    if self.config.preserve_networking {
                        // Preserve networking state
                        new_ast.push(node.clone());
                    } else {
                        // Optimize networking operation
                        match op_type {
                            NetworkOpType::HttpGet | NetworkOpType::HttpPost => {
                                // Combine multiple HTTP requests to the same endpoint
                                if let Some(prev_node) = new_ast.last() {
                                    if let AstNode::Expr { kind: ExprKind::Network { op_type: prev_op_type, endpoint: prev_endpoint, .. } } = prev_node {
                                        if prev_endpoint == endpoint && 
                                           (prev_op_type == NetworkOpType::HttpGet || prev_op_type == NetworkOpType::HttpPost) {
                                            // Skip duplicate request
                                            continue;
                                        }
                                    }
                                }
                            }
                            NetworkOpType::TcpConnect => {
                                // Preserve TCP connections
                                new_ast.push(node.clone());
                            }
                            _ => new_ast.push(node.clone()),
                        }
                    }
                }
                _ => new_ast.push(node.clone()),
            }
        }

        *ast = new_ast;
        Ok(())
    }
}

// Convert AST back to source code (simplified)
fn ast_to_source(ast: &[AstNode]) -> String {
    let mut source = String::new();
    for node in ast {
        match node {
            AstNode::FnDecl { doc, name, params, return_type, body, .. } => {
                if let Some(doc) = doc {
                    source.push_str(&format!("/// {}\n", doc.text));
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

// Public API to transform KSL code
pub fn transform(input_file: &PathBuf, output_file: Option<PathBuf>, rule: &str, plugin_name: Option<String>) -> Result<(), KslError> {
    let config = TransformConfig {
        input_file: input_file.clone(),
        output_file,
        rule: rule.to_string(),
        plugin_name,
        max_unroll_iterations: 5,
        preserve_networking: true,
    };
    let mut transformer = AstTransformer::new(config);
    transformer.transform()
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_plugin.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_plugin {
    pub use super::{PluginSystem, KslPlugin};
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
    fn test_transform_inline() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn add(x: u32, y: u32): u32 {{ x + y }}\nfn main() {{ let result = add(10, 20); }}"
        ).unwrap();

        let result = transform(&input_file, None, "inline", None);
        assert!(result.is_ok());

        let content = fs::read_to_string(&input_file).unwrap();
        assert!(content.contains("let x = 10;"));
        assert!(content.contains("let y = 20;"));
        assert!(content.contains("let result = x + y;"));
        assert!(!content.contains("add(10, 20)"));
    }

    #[test]
    fn test_transform_unroll() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ match i in 0..3 {{ let x = i + 1; }} }}"
        ).unwrap();

        let result = transform(&input_file, None, "unroll", None);
        assert!(result.is_ok());

        let content = fs::read_to_string(&input_file).unwrap();
        assert!(content.contains("let x = 0 + 1;"));
        assert!(content.contains("let x = 1 + 1;"));
        assert!(content.contains("let x = 2 + 1;"));
        assert!(!content.contains("match i in 0..3"));
    }

    #[test]
    fn test_transform_invalid_rule() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(file, "fn main() {{}}").unwrap();

        let result = transform(&input_file, None, "invalid", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown transformation rule"));
    }

    #[test]
    fn test_transform_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("nonexistent.ksl");

        let result = transform(&input_file, None, "inline", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}
