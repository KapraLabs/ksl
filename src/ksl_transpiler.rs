// ksl_transpiler.rs
// Transpiles KSL code to other languages like Rust or Python for broader compatibility,
// converting the AST to target language syntax.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_checker::check;
use crate::ksl_ast_transform::transform;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

// Transpiler configuration
#[derive(Debug)]
pub struct TranspilerConfig {
    input_file: PathBuf, // Source KSL file
    output_file: PathBuf, // Output file (e.g., output.rs or output.py)
    target: String, // Target language: "rust" or "python"
}

// Transpiler
pub struct Transpiler {
    config: TranspilerConfig,
}

impl Transpiler {
    pub fn new(config: TranspilerConfig) -> Self {
        Transpiler { config }
    }

    // Transpile KSL code to the target language
    pub fn transpile(&self) -> Result<(), KslError> {
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

        // Validate source
        check(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        // Apply transformations if needed (e.g., inline functions)
        transform(&self.config.input_file, None, "inline", None)?;

        // Transpile to target language
        let output_code = match self.config.target.as_str() {
            "rust" => self.transpile_to_rust(&ast)?,
            "python" => self.transpile_to_python(&ast)?,
            _ => return Err(KslError::type_error(
                format!("Unsupported target language: {}", self.config.target),
                pos,
            )),
        };

        // Write output code
        File::create(&self.config.output_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output file {}: {}", self.config.output_file.display(), e),
                pos,
            ))?
            .write_all(output_code.as_bytes())
            .map_err(|e| KslError::type_error(
                format!("Failed to write output file {}: {}", self.config.output_file.display(), e),
                pos,
            ))?;

        Ok(())
    }

    // Transpile KSL AST to Rust
    fn transpile_to_rust(&self, ast: &[AstNode]) -> Result<String, KslError> {
        let mut rust_code = String::new();
        rust_code.push_str("// Generated Rust code from KSL\n\n");

        for node in ast {
            match node {
                AstNode::FnDecl { name, params, return_type, body, .. } => {
                    rust_code.push_str(&format!("fn {}(", name));
                    let param_strings: Vec<String> = params.iter()
                        .map(|(name, typ)| format!("{}: {}", name, ksl_type_to_rust(typ)))
                        .collect();
                    rust_code.push_str(&param_strings.join(", "));
                    rust_code.push_str(&format!(") -> {} {{\n", ksl_type_to_rust(return_type)));
                    rust_code.push_str(&self.transpile_rust_body(body));
                    rust_code.push_str("}\n\n");
                }
                AstNode::VarDecl { name, type_annot, expr, is_mutable, .. } => {
                    rust_code.push_str(&format!(
                        "    let {}{}: {} = {};\n",
                        if *is_mutable { "mut " } else { "" },
                        name,
                        type_annot.as_ref().map(ksl_type_to_rust).unwrap_or("".to_string()),
                        expr_to_rust(expr)
                    ));
                }
                _ => {}
            }
        }

        Ok(rust_code)
    }

    // Transpile KSL body to Rust
    fn transpile_rust_body(&self, body: &[AstNode]) -> String {
        let mut rust_code = String::new();
        for node in body {
            match node {
                AstNode::VarDecl { name, type_annot, expr, is_mutable, .. } => {
                    rust_code.push_str(&format!(
                        "    let {}{}: {} = {};\n",
                        if *is_mutable { "mut " } else { "" },
                        name,
                        type_annot.as_ref().map(ksl_type_to_rust).unwrap_or("".to_string()),
                        expr_to_rust(expr)
                    ));
                }
                AstNode::Expr { kind } => {
                    rust_code.push_str(&format!("    {};\n", expr_to_rust(&AstNode::Expr { kind: kind.clone() })));
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    rust_code.push_str(&format!("    if {} {{\n", expr_to_rust(condition)));
                    rust_code.push_str(&self.transpile_rust_body(then_branch));
                    if let Some(else_branch) = else_branch {
                        rust_code.push_str("    } else {\n");
                        rust_code.push_str(&self.transpile_rust_body(else_branch));
                    }
                    rust_code.push_str("    }\n");
                }
                _ => {}
            }
        }
        rust_code
    }

    // Transpile KSL AST to Python
    fn transpile_to_python(&self, ast: &[AstNode]) -> Result<String, KslError> {
        let mut python_code = String::new();
        python_code.push_str("# Generated Python code from KSL\n\n");

        for node in ast {
            match node {
                AstNode::FnDecl { name, params, return_type, body, .. } => {
                    python_code.push_str(&format!("def {}(", name));
                    let param_strings: Vec<String> = params.iter()
                        .map(|(name, _)| name.clone())
                        .collect();
                    python_code.push_str(&param_strings.join(", "));
                    python_code.push_str("):\n");
                    python_code.push_str(&self.transpile_python_body(body));
                    python_code.push_str("\n");
                }
                AstNode::VarDecl { name, expr, .. } => {
                    python_code.push_str(&format!("    {} = {}\n", name, expr_to_python(expr)));
                }
                _ => {}
            }
        }

        Ok(python_code)
    }

    // Transpile KSL body to Python
    fn transpile_python_body(&self, body: &[AstNode]) -> String {
        let mut python_code = String::new();
        for node in body {
            match node {
                AstNode::VarDecl { name, expr, .. } => {
                    python_code.push_str(&format!("    {} = {}\n", name, expr_to_python(expr)));
                }
                AstNode::Expr { kind } => {
                    python_code.push_str(&format!("    {}\n", expr_to_python(&AstNode::Expr { kind: kind.clone() })));
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    python_code.push_str(&format!("    if {}:\n", expr_to_python(condition)));
                    python_code.push_str(&self.transpile_python_body(then_branch));
                    if let Some(else_branch) = else_branch {
                        python_code.push_str("    else:\n");
                        python_code.push_str(&self.transpile_python_body(else_branch));
                    }
                }
                _ => {}
            }
        }
        python_code
    }
}

// Convert KSL type to Rust type
fn ksl_type_to_rust(typ: &TypeAnnotation) -> String {
    match typ {
        TypeAnnotation::Simple(name) => match name.as_str() {
            "u32" => "u32".to_string(),
            "f64" => "f64".to_string(),
            "bool" => "bool".to_string(),
            "string" => "String".to_string(),
            _ => name.clone(),
        },
        TypeAnnotation::Array { element, size } => {
            format!("[{}; {}]", element, size)
        }
        TypeAnnotation::Result { success, .. } => {
            format!("Result<{}, ()>", success)
        }
    }
}

// Convert KSL expression to Rust
fn expr_to_rust(expr: &AstNode) -> String {
    match expr {
        AstNode::Expr { kind } => match kind {
            ExprKind::Ident(name) => name.clone(),
            ExprKind::Number(num) => num.clone(),
            ExprKind::String(s) => format!("String::from(\"{}\")", s),
            ExprKind::BinaryOp { op, left, right } => format!(
                "({} {} {})",
                expr_to_rust(left),
                op,
                expr_to_rust(right)
            ),
            ExprKind::Call { name, args } => {
                let arg_strings: Vec<String> = args.iter().map(expr_to_rust).collect();
                format!("{}({})", name, arg_strings.join(", "))
            }
            _ => "".to_string(),
        },
        _ => "".to_string(),
    }
}

// Convert KSL expression to Python
fn expr_to_python(expr: &AstNode) -> String {
    match expr {
        AstNode::Expr { kind } => match kind {
            ExprKind::Ident(name) => name.clone(),
            ExprKind::Number(num) => num.clone(),
            ExprKind::String(s) => format!("\"{}\"", s),
            ExprKind::BinaryOp { op, left, right } => format!(
                "({} {} {})",
                expr_to_python(left),
                op,
                expr_to_python(right)
            ),
            ExprKind::Call { name, args } => {
                let arg_strings: Vec<String> = args.iter().map(expr_to_python).collect();
                format!("{}({})", name, arg_strings.join(", "))
            }
            _ => "".to_string(),
        },
        _ => "".to_string(),
    }
}

// Public API to transpile KSL code
pub fn transpile(input_file: &PathBuf, output_file: PathBuf, target: &str) -> Result<(), KslError> {
    let pos = SourcePosition::new(1, 1);
    if target != "rust" && target != "python" {
        return Err(KslError::type_error(
            format!("Unsupported target language: {}. Use 'rust' or 'python'", target),
            pos,
        ));
    }

    let config = TranspilerConfig {
        input_file: input_file.clone(),
        output_file,
        target: target.to_string(),
    };
    let transpiler = Transpiler::new(config);
    transpiler.transpile()
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
    fn test_transpile_rust() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn add(x: u32, y: u32): u32 {{ x + y }}\nfn main() {{ let result = add(10, 20); }}"
        ).unwrap();

        let output_file = temp_dir.path().join("output.rs");
        let result = transpile(&input_file, output_file.clone(), "rust");
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("fn add(x: u32, y: u32) -> u32 {"));
        assert!(content.contains("let result:  = add(10, 20);"));
    }

    #[test]
    fn test_transpile_python() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn add(x: u32, y: u32): u32 {{ x + y }}\nfn main() {{ let result = add(10, 20); }}"
        ).unwrap();

        let output_file = temp_dir.path().join("output.py");
        let result = transpile(&input_file, output_file.clone(), "python");
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("def add(x, y):"));
        assert!(content.contains("result = add(10, 20)"));
    }

    #[test]
    fn test_transpile_invalid_target() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let output_file = temp_dir.path().join("output.rs");
        let result = transpile(&input_file, output_file, "invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported target language"));
    }

    #[test]
    fn test_transpile_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("nonexistent.ksl");
        let output_file = temp_dir.path().join("output.rs");

        let result = transpile(&input_file, output_file, "rust");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}
