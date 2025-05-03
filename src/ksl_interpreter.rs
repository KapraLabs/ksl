// ksl_interpreter.rs
// Lightweight interpreter for KSL, optimized for rapid prototyping by directly
// interpreting AST, supporting basic types and secure execution in low-resource environments.

use crate::ksl_parser::{parse, AstNode, ExprKind, TypeAnnotation, ParseError};
use crate::ksl_checker::check;
use crate::ksl_sandbox::run_sandbox;
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

// Runtime value types
#[derive(Debug, Clone)]
pub enum Value {
    U32(u32),
    F64(f64),
    Bool(bool),
    String(String),
    Array(Vec<Value>, u32), // Values, size
    Void,
}

// Runtime environment for variables and functions
#[derive(Debug)]
struct Environment {
    variables: HashMap<String, Value>,
    functions: HashMap<String, (Vec<(String, TypeAnnotation)>, TypeAnnotation, Vec<AstNode>)>,
}

// KSL interpreter
pub struct Interpreter {
    env: Environment,
}

impl Interpreter {
    pub fn new() -> Self {
        Interpreter {
            env: Environment {
                variables: HashMap::new(),
                functions: HashMap::new(),
            },
        }
    }

    // Interpret a KSL program from a file
    pub fn interpret(&mut self, file: &PathBuf) -> Result<Value, KslError> {
        let pos = SourcePosition::new(1, 1);
        // Read and parse source
        let source = fs::read_to_string(file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", file.display(), e),
                pos,
            ))?;
        let ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;

        // Type-check
        check(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        // Run in sandbox
        run_sandbox(file)
            .map_err(|e| KslError::type_error(
                e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
                pos,
            ))?;

        // Populate function definitions
        for node in &ast {
            if let AstNode::FnDecl { name, params, return_type, body, .. } = node {
                self.env.functions.insert(
                    name.clone(),
                    (params.clone(), return_type.clone(), body.clone()),
                );
            }
        }

        // Execute main function
        if let Some((params, return_type, body)) = self.env.functions.get("main").cloned() {
            if !params.is_empty() {
                return Err(KslError::type_error(
                    "Main function must have no parameters".to_string(),
                    pos,
                ));
            }
            self.execute_block(&body)
        } else {
            Err(KslError::type_error(
                "No main function found".to_string(),
                pos,
            ))
        }
    }

    // Execute a block of statements
    fn execute_block(&mut self, block: &[AstNode]) -> Result<Value, KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut result = Value::Void;
        for node in block {
            result = match node {
                AstNode::VarDecl { name, expr, .. } => {
                    let value = self.evaluate_expr(expr)?;
                    self.env.variables.insert(name.clone(), value);
                    Value::Void
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    let cond_value = self.evaluate_expr(condition)?;
                    if let Value::Bool(true) = cond_value {
                        self.execute_block(then_branch)?
                    } else if let Some(else_branch) = else_branch {
                        self.execute_block(else_branch)?
                    } else {
                        Value::Void
                    }
                }
                AstNode::Expr { kind } => self.evaluate_expr(&AstNode::Expr { kind: kind.clone() })?,
                _ => return Err(KslError::type_error(
                    "Unsupported statement in interpreter".to_string(),
                    pos,
                )),
            };
        }
        Ok(result)
    }

    // Evaluate an expression
    fn evaluate_expr(&self, expr: &AstNode) -> Result<Value, KslError> {
        let pos = SourcePosition::new(1, 1);
        match expr {
            AstNode::Expr { kind } => match kind {
                ExprKind::Ident(name) => self.env.variables.get(name)
                    .cloned()
                    .ok_or_else(|| KslError::type_error(
                        format!("Undefined variable: {}", name),
                        pos,
                    )),
                ExprKind::Number(num) => {
                    if num.contains('.') {
                        num.parse::<f64>()
                            .map(Value::F64)
                            .map_err(|_| KslError::type_error(
                                format!("Invalid float: {}", num),
                                pos,
                            ))
                    } else {
                        num.parse::<u32>()
                            .map(Value::U32)
                            .map_err(|_| KslError::type_error(
                                format!("Invalid integer: {}", num),
                                pos,
                            ))
                    }
                }
                ExprKind::String(s) => Ok(Value::String(s.clone())),
                ExprKind::BinaryOp { op, left, right } => {
                    let left_val = self.evaluate_expr(left)?;
                    let right_val = self.evaluate_expr(right)?;
                    match (op.as_str(), &left_val, &right_val) {
                        ("+", Value::U32(l), Value::U32(r)) => Ok(Value::U32(l + r)),
                        ("+", Value::F64(l), Value::F64(r)) => Ok(Value::F64(l + r)),
                        ("-", Value::U32(l), Value::U32(r)) => Ok(Value::U32(l - r)),
                        ("-", Value::F64(l), Value::F64(r)) => Ok(Value::F64(l - r)),
                        ("==", Value::U32(l), Value::U32(r)) => Ok(Value::Bool(l == r)),
                        ("==", Value::F64(l), Value::F64(r)) => Ok(Value::Bool(l == r)),
                        ("==", Value::Bool(l), Value::Bool(r)) => Ok(Value::Bool(l == r)),
                        (">", Value::U32(l), Value::U32(r)) => Ok(Value::Bool(l > r)),
                        (">", Value::F64(l), Value::F64(r)) => Ok(Value::Bool(l > r)),
                        _ => Err(KslError::type_error(
                            format!("Unsupported operation: {} on {:?} and {:?}", op, left_val, right_val),
                            pos,
                        )),
                    }
                }
                ExprKind::Call { name, args } => {
                    if let Some((params, return_type, body)) = self.env.functions.get(name).cloned() {
                        if params.len() != args.len() {
                            return Err(KslError::type_error(
                                format!("Expected {} arguments, got {}", params.len(), args.len()),
                                pos,
                            ));
                        }
                        let mut local_env = Environment {
                            variables: HashMap::new(),
                            functions: self.env.functions.clone(),
                        };
                        for ((param_name, _), arg) in params.iter().zip(args) {
                            let arg_value = self.evaluate_expr(arg)?;
                            local_env.variables.insert(param_name.clone(), arg_value);
                        }
                        let mut local_interpreter = Interpreter { env: local_env };
                        local_interpreter.execute_block(&body)
                    } else {
                        Err(KslError::type_error(
                            format!("Undefined function: {}", name),
                            pos,
                        ))
                    }
                }
            },
            _ => Err(KslError::type_error(
                "Expected expression".to_string(),
                pos,
            )),
        }
    }
}

// Public API to interpret a KSL program
pub fn interpret(file: &PathBuf) -> Result<Value, KslError> {
    let mut interpreter = Interpreter::new();
    interpreter.interpret(file)
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_sandbox.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, TypeAnnotation, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_sandbox {
    pub use super::run_sandbox;
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
    fn test_interpret_basic() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main(): u32 { let x: u32 = 42; x + 8 }"
        ).unwrap();

        let result = interpret(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Value::U32(50));
    }

    #[test]
    fn test_interpret_if() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main(): u32 { let x: u32 = 10; if x > 5 { 1 } else { 0 } }"
        ).unwrap();

        let result = interpret(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Value::U32(1));
    }

    #[test]
    fn test_interpret_function_call() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn add(x: u32, y: u32): u32 { x + y }\nfn main(): u32 { add(20, 30) }"
        ).unwrap();

        let result = interpret(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Value::U32(50));
    }

    #[test]
    fn test_interpret_invalid_file() {
        let invalid_file = PathBuf::from("nonexistent.ksl");
        let result = interpret(&invalid_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }

    #[test]
    fn test_interpret_no_main() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "fn not_main() { let x: u32 = 42; }").unwrap();

        let result = interpret(&temp_file.path().to_path_buf());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No main function found"));
    }
}