// ksl_async.rs
// Adds asynchronous programming support to KSL, introducing async/await syntax
// and supporting async I/O operations.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_stdlib_io::{HttpGet};
use crate::ksl_stdlib_net::{HttpPost};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use std::time::Duration;
use reqwest::Client;
use tokio::runtime::Runtime;

/// Async configuration
/// @struct AsyncConfig
/// @field input_file Source KSL file
/// @field output_file Optional output file
#[derive(Debug)]
pub struct AsyncConfig {
    input_file: PathBuf,
    output_file: Option<PathBuf>,
}

/// Async runtime state
/// @struct AsyncRuntime
/// @field runtime Tokio runtime
/// @field tasks Map of task IDs to their join handles
#[derive(Clone)]
pub struct AsyncRuntime {
    runtime: Arc<Runtime>,
    tasks: Arc<Mutex<Vec<(String, JoinHandle<Result<(), RuntimeError>>)>>>,
    client: Arc<Client>,
}

impl AsyncRuntime {
    /// Creates a new async runtime
    /// @returns A new `AsyncRuntime` instance
    pub fn new() -> Self {
        AsyncRuntime {
            runtime: Arc::new(Runtime::new().unwrap()),
            tasks: Arc::new(Mutex::new(Vec::new())),
            client: Arc::new(Client::new()),
        }
    }

    /// Schedules an async task
    /// @param task_id Unique identifier for the task
    /// @param vm Virtual machine instance to run
    pub async fn schedule_task(&self, task_id: String, vm: KapraVM) {
        let mut tasks = self.tasks.lock().await;
        let handle = self.runtime.spawn(async move {
            vm.run_with_async().await
        });
        tasks.push((task_id, handle));
    }

    /// Polls for task completion
    /// @returns `Ok(())` if all tasks complete successfully, or `Err` with a `KslError`
    pub async fn poll(&self) -> Result<(), KslError> {
        let mut tasks = self.tasks.lock().await;
        let mut i = 0;
        while i < tasks.len() {
            let (task_id, handle) = &tasks[i];
            if handle.is_finished() {
                match handle.await {
                    Ok(Ok(())) => {
                        println!("Task {} completed successfully", task_id);
                        tasks.remove(i);
                    }
                    Ok(Err(e)) => return Err(KslError::type_error(
                        format!("Task {} failed: {}", task_id, e),
                        SourcePosition::new(1, 1),
                    )),
                    Err(e) => return Err(KslError::type_error(
                        format!("Task {} panicked: {}", task_id, e),
                        SourcePosition::new(1, 1),
                    )),
                }
            } else {
                i += 1;
            }
        }
        Ok(())
    }

    /// Executes an HTTP GET request
    /// @param url The URL to fetch
    /// @returns The response body as a string
    pub async fn http_get(&self, url: &str) -> Result<String, KslError> {
        let response = self.client.get(url)
            .send()
            .await
            .map_err(|e| KslError::type_error(
                format!("HTTP GET failed: {}", e),
                SourcePosition::new(1, 1),
            ))?;
        let body = response.text()
            .await
            .map_err(|e| KslError::type_error(
                format!("Failed to read response: {}", e),
                SourcePosition::new(1, 1),
            ))?;
        Ok(body)
    }

    /// Executes an HTTP POST request
    /// @param url The URL to post to
    /// @param data The data to post
    /// @returns The response body as a string
    pub async fn http_post(&self, url: &str, data: &str) -> Result<String, KslError> {
        let response = self.client.post(url)
            .body(data.to_string())
            .send()
            .await
            .map_err(|e| KslError::type_error(
                format!("HTTP POST failed: {}", e),
                SourcePosition::new(1, 1),
            ))?;
        let body = response.text()
            .await
            .map_err(|e| KslError::type_error(
                format!("Failed to read response: {}", e),
                SourcePosition::new(1, 1),
            ))?;
        Ok(body)
    }

    /// Executes a contract bytecode
    /// @param contract_id The contract ID
    /// @param bytecode The bytecode to execute
    /// @returns Whether the execution succeeded
    pub async fn execute_contract(&self, contract_id: [u8; 32], bytecode: &Bytecode) -> AsyncResult<bool> {
        // Create a new VM instance for the contract
        let mut vm = KapraVM::new_with_contract(contract_id);
        
        // Execute the bytecode
        vm.execute(bytecode)
            .map_err(|e| KslError::runtime(
                format!("Contract execution failed: {}", e),
                0,
                "E401".to_string()
            ))
    }
}

/// Async compiler and executor
/// @struct AsyncProcessor
/// @field config Async configuration
/// @field runtime Async runtime
pub struct AsyncProcessor {
    config: AsyncConfig,
    runtime: AsyncRuntime,
}

impl AsyncProcessor {
    /// Creates a new async processor
    /// @param config Async configuration
    /// @returns A new `AsyncProcessor` instance
    pub fn new(config: AsyncConfig) -> Self {
        AsyncProcessor {
            config,
            runtime: AsyncRuntime::new(),
        }
    }

    /// Compiles and executes async KSL code
    /// @returns `Ok(())` if processing succeeds, or `Err` with a `KslError`
    pub async fn process(&mut self) -> Result<(), KslError> {
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

        // Transform async/await syntax
        self.transform_async(&mut ast)?;

        // Compile to bytecode
        let bytecode = compile(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        // Execute with async runtime
        let mut vm = KapraVM::new_with_async(bytecode);
        vm.run_with_async(&self.runtime).await?;

        // Poll for async task completion
        self.runtime.poll().await?;

        // Optionally write transformed code
        if let Some(output_path) = &self.config.output_file {
            let transformed_source = ast_to_source(&ast);
            File::create(output_path)
                .map_err(|e| KslError::type_error(
                    format!("Failed to create output file {}: {}", output_path.display(), e),
                    pos,
                ))?
                .write_all(transformed_source.as_bytes())
                .map_err(|e| KslError::type_error(
                    format!("Failed to write output file {}: {}", output_path.display(), e),
                    pos,
                ))?;
        }

        Ok(())
    }

    /// Transforms async/await syntax
    /// @param ast Abstract syntax tree to transform
    /// @returns `Ok(())` if transformation succeeds, or `Err` with a `KslError`
    fn transform_async(&self, ast: &mut Vec<AstNode>) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut new_ast = Vec::new();
        for node in ast.iter() {
            match node {
                AstNode::FnDecl { name, params, return_type, body, attributes } => {
                    if attributes.iter().any(|attr| attr.name == "async") {
                        let mut new_body = Vec::new();
                        self.transform_async_body(body, &mut new_body, name)?;
                        new_ast.push(AstNode::FnDecl {
                            doc: None,
                            name: name.clone(),
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: new_body,
                            attributes: attributes.clone(),
                        });
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

    /// Transforms async body
    /// @param body Original function body
    /// @param new_body Transformed function body
    /// @param task_name Name of the task
    /// @returns `Ok(())` if transformation succeeds, or `Err` with a `KslError`
    fn transform_async_body(&self, body: &[AstNode], new_body: &mut Vec<AstNode>, task_name: &str) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        for node in body {
            match node {
                AstNode::Expr { kind: ExprKind::AsyncCall { name, args } } => {
                    let task_id = format!("task_{}_{}", task_name, new_body.len());
                    match name.as_str() {
                        "http.get" => {
                            if args.len() != 1 {
                                return Err(KslError::type_error(
                                    "http.get expects 1 argument".to_string(),
                                    pos,
                                ));
                            }
                            new_body.push(AstNode::Expr {
                                kind: ExprKind::Call {
                                    name: "http_get".to_string(),
                                    args: args.clone(),
                                },
                            });
                        }
                        "http.post" => {
                            if args.len() != 2 {
                                return Err(KslError::type_error(
                                    "http.post expects 2 arguments".to_string(),
                                    pos,
                                ));
                            }
                            new_body.push(AstNode::Expr {
                                kind: ExprKind::Call {
                                    name: "http_post".to_string(),
                                    args: args.clone(),
                                },
                            });
                        }
                        _ => {
                            new_body.push(AstNode::Expr {
                                kind: ExprKind::Call {
                                    name: "schedule_task".to_string(),
                                    args: vec![
                                        AstNode::Expr { kind: ExprKind::String(task_id.clone()) },
                                        AstNode::Expr { kind: ExprKind::AsyncCall { name: name.clone(), args: args.clone() } },
                                    ],
                                },
                            });
                        }
                    }
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    let mut new_then = Vec::new();
                    self.transform_async_body(then_branch, &mut new_then, task_name)?;
                    let mut new_else = None;
                    if let Some(else_branch) = else_branch {
                        let mut new_else_branch = Vec::new();
                        self.transform_async_body(else_branch, &mut new_else_branch, task_name)?;
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
                        self.transform_async_body(&arm.body, &mut new_arm_body, task_name)?;
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
}

/// Converts AST back to source code
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
                source.push_str(&format!("    let {}{} = {};\n", if *is_mutable { "mut " } else { "" }, name, expr_to_source(expr)));
            }
            AstNode::Expr { kind } => {
                source.push_str(&format!("    {};\n", expr_to_source(&AstNode::Expr { kind: kind.clone() })));
            }
            _ => {}
        }
    }
    source
}

/// Formats a type annotation as a string
pub fn format_type(typ: &TypeAnnotation) -> String {
    match typ {
        TypeAnnotation::Simple(name) => name.clone(),
        TypeAnnotation::Array { element, size } => format!("array<{}, {}>", element, size),
        TypeAnnotation::Result { success, error } => format!("result<{}, {}>", success, error),
    }
}

/// Converts an expression to source code
fn expr_to_source(expr: &AstNode) -> String {
    match expr {
        AstNode::Expr { kind } => match kind {
            ExprKind::Call { name, args } => {
                let arg_strings: Vec<String> = args.iter()
                    .map(|arg| expr_to_source(arg))
                    .collect();
                format!("{}({})", name, arg_strings.join(", "))
            }
            ExprKind::String(s) => format!("\"{}\"", s),
            ExprKind::Number(n) => n.to_string(),
            ExprKind::Bool(b) => b.to_string(),
            _ => "".to_string(),
        },
        _ => "".to_string(),
    }
}

/// Trait for async virtual machine support
pub trait AsyncVM {
    /// Creates a new VM instance with async support
    fn new_with_async(bytecode: KapraBytecode) -> Self;
    /// Checks if an async operation is pending
    fn is_async_pending(&self) -> bool;
    /// Completes an async operation
    fn complete_async(&mut self);
    /// Runs the VM with async support
    async fn run_with_async(&mut self, runtime: &AsyncRuntime) -> Result<(), RuntimeError>;
}

impl AsyncVM for KapraVM {
    fn new_with_async(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode);
        vm.async_state = Some(AsyncState { pending: false });
        vm
    }

    fn is_async_pending(&self) -> bool {
        self.async_state.as_ref().map(|s| s.pending).unwrap_or(false)
    }

    fn complete_async(&mut self) {
        if let Some(state) = &mut self.async_state {
            state.pending = false;
        }
    }

    async fn run_with_async(&mut self, runtime: &AsyncRuntime) -> Result<(), RuntimeError> {
        while let Some(opcode) = self.next_opcode() {
            match opcode {
                Opcode::HttpGet => {
                    let url = self.pop_string()?;
                    self.async_state.as_mut().unwrap().pending = true;
                    runtime.schedule_task(format!("http_get_{}", self.pc), self.clone()).await;
                    return Ok(());
                }
                Opcode::HttpPost => {
                    let url = self.pop_string()?;
                    let data = self.pop_string()?;
                    self.async_state.as_mut().unwrap().pending = true;
                    runtime.schedule_task(format!("http_post_{}", self.pc), self.clone()).await;
                    return Ok(());
                }
                _ => self.execute_instruction(opcode)?,
            }
        }
        Ok(())
    }
}

/// Async state for the virtual machine
struct AsyncState {
    pending: bool,
}

/// Public API to process async KSL code
/// @param input_file Input KSL file
/// @param output_file Optional output file
/// @returns `Ok(())` if processing succeeds, or `Err` with a `KslError`
pub async fn process_async(input_file: &PathBuf, output_file: Option<PathBuf>) -> Result<(), KslError> {
    let config = AsyncConfig {
        input_file: input_file.clone(),
        output_file,
    };
    let mut processor = AsyncProcessor::new(config);
    processor.process().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[tokio::test]
    async fn test_process_async() {
        let temp_dir = std::env::temp_dir();
        let input_file = temp_dir.join("test.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            r#"#[async]
fn fetch_data() {{
    let response = http.get("https://example.com");
    let post_response = http.post("https://example.com", "data");
}}"#
        ).unwrap();

        let output_file = temp_dir.join("test_transformed.ksl");
        let result = process_async(&input_file, Some(output_file)).await;
        assert!(result.is_ok());

        let transformed = fs::read_to_string(output_file).unwrap();
        assert!(transformed.contains("schedule_task"));
        assert!(transformed.contains("http.get"));
        assert!(transformed.contains("http.post"));
    }

    #[tokio::test]
    async fn test_process_async_no_async() {
        let temp_dir = std::env::temp_dir();
        let input_file = temp_dir.join("test.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            r#"fn main() {{
    let x = 1;
}}"#
        ).unwrap();

        let output_file = temp_dir.join("test_transformed.ksl");
        let result = process_async(&input_file, Some(output_file)).await;
        assert!(result.is_ok());

        let transformed = fs::read_to_string(output_file).unwrap();
        assert!(!transformed.contains("schedule_task"));
    }

    #[tokio::test]
    async fn test_process_async_invalid_file() {
        let temp_dir = std::env::temp_dir();
        let input_file = temp_dir.join("nonexistent.ksl");
        let result = process_async(&input_file, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_http_operations() {
        let runtime = AsyncRuntime::new();
        
        // Test HTTP GET
        let response = runtime.http_get("https://httpbin.org/get").await;
        assert!(response.is_ok());
        let body = response.unwrap();
        assert!(body.contains("httpbin.org"));

        // Test HTTP POST
        let response = runtime.http_post("https://httpbin.org/post", "test data").await;
        assert!(response.is_ok());
        let body = response.unwrap();
        assert!(body.contains("test data"));
    }

    #[tokio::test]
    async fn test_async_task_completion() {
        let runtime = AsyncRuntime::new();
        let mut vm = KapraVM::new_with_async(vec![]);
        
        // Schedule a task
        runtime.schedule_task("test_task".to_string(), vm).await;
        
        // Poll for completion
        let result = runtime.poll().await;
        assert!(result.is_ok());
    }
}

