// ksl_interpreter.rs
// Lightweight interpreter for KSL, optimized for rapid prototyping by directly
// interpreting AST, supporting basic types and secure execution in low-resource environments.
// Supports async interpretation and new AST transformations.

use crate::ksl_parser::{parse, AstNode, ExprKind, TypeAnnotation, ParseError};
use crate::ksl_ast_transform::{TransformContext, TransformError};
use crate::ksl_checker::check;
use crate::ksl_sandbox::{Sandbox, SandboxPolicy, run_sandbox_async};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Runtime value types supported by the interpreter
#[derive(Debug, Clone)]
pub enum Value {
    /// 32-bit unsigned integer
    U32(u32),
    /// 64-bit floating point number
    F64(f64),
    /// Boolean value
    Bool(bool),
    /// String value
    String(String),
    /// Array with fixed size
    Array(Vec<Value>, u32),
    /// Async operation result
    Async(AsyncResult<Value>),
    /// Void value (no return)
    Void,
}

/// Runtime environment for variables and functions
#[derive(Debug, Clone)]
pub struct Environment {
    /// Variable bindings
    pub variables: HashMap<String, Value>,
    /// Function definitions
    pub functions: HashMap<String, (Vec<(String, TypeAnnotation)>, TypeAnnotation, Vec<AstNode>)>,
    /// Async runtime state
    pub async_state: AsyncState,
}

/// Async runtime state
#[derive(Debug, Clone, Default)]
pub struct AsyncState {
    /// Current async operation count
    pub operation_count: u64,
    /// Total async operation time
    pub total_async_time: std::time::Duration,
    /// Pending async operations
    pub pending_ops: HashMap<String, AsyncResult<Value>>,
}

/// KSL interpreter with async support
pub struct Interpreter {
    /// Runtime environment
    env: Arc<RwLock<Environment>>,
    /// Async runtime
    async_runtime: Arc<AsyncRuntime>,
    /// AST transformation context
    transform_ctx: Arc<TransformContext>,
}

impl Interpreter {
    /// Creates a new interpreter instance
    pub fn new() -> Self {
        Interpreter {
            env: Arc::new(RwLock::new(Environment {
                variables: HashMap::new(),
                functions: HashMap::new(),
                async_state: AsyncState::default(),
            })),
            async_runtime: Arc::new(AsyncRuntime::new()),
            transform_ctx: Arc::new(TransformContext::new()),
        }
    }

    /// Interpret a KSL program from a file asynchronously
    pub async fn interpret_async(&self, file: &PathBuf) -> AsyncResult<Value> {
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

        // Transform AST
        let transformed_ast = self.transform_ctx.transform(&ast)
            .map_err(|e| KslError::type_error(
                format!("AST transformation error: {}", e),
                pos,
            ))?;

        // Type-check
        check(&transformed_ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        // Run in sandbox
        let mut sandbox = Sandbox::new(SandboxPolicy::default());
        sandbox.run_sandbox_async(file).await
            .map_err(|e| KslError::type_error(
                e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
                pos,
            ))?;

        // Populate function definitions
        let mut env = self.env.write().await;
        for node in &transformed_ast {
            if let AstNode::FnDecl { name, params, return_type, body, .. } = node {
                env.functions.insert(
                    name.clone(),
                    (params.clone(), return_type.clone(), body.clone()),
                );
            }
        }

        // Execute main function
        if let Some((params, return_type, body)) = env.functions.get("main").cloned() {
            if !params.is_empty() {
                return Err(KslError::type_error(
                    "Main function must have no parameters".to_string(),
                    pos,
                ));
            }
            self.execute_block_async(&body).await
        } else {
            Err(KslError::type_error(
                "No main function found".to_string(),
                pos,
            ))
        }
    }

    /// Execute a block of statements asynchronously
    async fn execute_block_async(&self, block: &[AstNode]) -> AsyncResult<Value> {
        let pos = SourcePosition::new(1, 1);
        let mut result = Value::Void;
        for node in block {
            result = match node {
                AstNode::VarDecl { name, expr, .. } => {
                    let value = self.evaluate_expr_async(expr).await?;
                    let mut env = self.env.write().await;
                    env.variables.insert(name.clone(), value);
                    Value::Void
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    let cond_value = self.evaluate_expr_async(condition).await?;
                    if let Value::Bool(true) = cond_value {
                        self.execute_block_async(then_branch).await?
                    } else if let Some(else_branch) = else_branch {
                        self.execute_block_async(else_branch).await?
                    } else {
                        Value::Void
                    }
                }
                AstNode::Expr { kind } => {
                    self.evaluate_expr_async(&AstNode::Expr { kind: kind.clone() }).await?
                }
                AstNode::AsyncBlock { body } => {
                    let result = self.execute_block_async(body).await?;
                    Value::Async(Ok(result))
                }
                _ => return Err(KslError::type_error(
                    "Unsupported statement in interpreter".to_string(),
                    pos,
                )),
            };
        }
        Ok(result)
    }

    /// Evaluate an expression asynchronously
    async fn evaluate_expr_async(&self, expr: &AstNode) -> AsyncResult<Value> {
        let pos = SourcePosition::new(1, 1);
        match expr {
            AstNode::Expr { kind } => match kind {
                ExprKind::Ident(name) => {
                    let env = self.env.read().await;
                    env.variables.get(name)
                        .cloned()
                        .ok_or_else(|| KslError::type_error(
                            format!("Undefined variable: {}", name),
                            pos,
                        ))
                }
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
                    let left_val = self.evaluate_expr_async(left).await?;
                    let right_val = self.evaluate_expr_async(right).await?;
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
                    let env = self.env.read().await;
                    if let Some((params, return_type, body)) = env.functions.get(name).cloned() {
                        if params.len() != args.len() {
                            return Err(KslError::type_error(
                                format!("Expected {} arguments, got {}", params.len(), args.len()),
                                pos,
                            ));
                        }
                        let mut local_env = Environment {
                            variables: HashMap::new(),
                            functions: env.functions.clone(),
                            async_state: AsyncState::default(),
                        };
                        for ((param_name, _), arg) in params.iter().zip(args) {
                            let arg_value = self.evaluate_expr_async(arg).await?;
                            local_env.variables.insert(param_name.clone(), arg_value);
                        }
                        let local_interpreter = Interpreter {
                            env: Arc::new(RwLock::new(local_env)),
                            async_runtime: self.async_runtime.clone(),
                            transform_ctx: self.transform_ctx.clone(),
                        };
                        local_interpreter.execute_block_async(&body).await
                    } else {
                        Err(KslError::type_error(
                            format!("Undefined function: {}", name),
                            pos,
                        ))
                    }
                }
                ExprKind::AsyncCall { name, args } => {
                    let mut env = self.env.write().await;
                    env.async_state.operation_count += 1;
                    let start = std::time::Instant::now();
                    let result = self.evaluate_expr_async(&AstNode::Expr {
                        kind: ExprKind::Call { name: name.clone(), args: args.clone() },
                    }).await;
                    env.async_state.total_async_time += start.elapsed();
                    result
                }
            },
            _ => Err(KslError::type_error(
                "Expected expression".to_string(),
                pos,
            )),
        }
    }
}

/// Public API to interpret a KSL program asynchronously
pub async fn interpret_async(file: &PathBuf) -> AsyncResult<Value> {
    let interpreter = Interpreter::new();
    interpreter.interpret_async(file).await
}

// Assume ksl_parser.rs, ksl_ast_transform.rs, ksl_checker.rs, ksl_sandbox.rs,
// ksl_async.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, TypeAnnotation, ParseError};
}

mod ksl_ast_transform {
    pub use super::{TransformContext, TransformError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_sandbox {
    pub use super::{Sandbox, SandboxPolicy, run_sandbox_async};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncResult};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_interpret_basic_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        fs::write(&input_file, r#"
            fn main() {
                let x = 42;
                println!("Hello, world!");
            }
        "#).unwrap();

        let result = interpret_async(&input_file).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_interpret_async_operations() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        fs::write(&input_file, r#"
            async fn main() {
                let result = await http.get("https://example.com");
                println!("Response: {}", result);
            }
        "#).unwrap();

        let result = interpret_async(&input_file).await;
        assert!(result.is_ok());
        if let Value::Async(Ok(_)) = result.unwrap() {
            // Async operation completed successfully
        } else {
            panic!("Expected async value");
        }
    }

    #[tokio::test]
    async fn test_interpret_ast_transform() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        fs::write(&input_file, r#"
            fn main() {
                let x = 42;
                let y = x + 1;
                println!("Result: {}", y);
            }
        "#).unwrap();

        let result = interpret_async(&input_file).await;
        assert!(result.is_ok());
    }
}