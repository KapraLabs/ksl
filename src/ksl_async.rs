// ksl_async.rs
// Adds asynchronous programming support to KSL, introducing async/await syntax
// and supporting async I/O operations.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_stdlib_io::{HttpGet};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Async configuration
#[derive(Debug)]
pub struct AsyncConfig {
    input_file: PathBuf, // Source KSL file
    output_file: Option<PathBuf>, // Optional output file
}

// Async runtime state
#[derive(Clone)]
pub struct AsyncRuntime {
    pending_tasks: Arc<Mutex<Vec<(String, Arc<Mutex<KapraVM>>)>>> // (Task ID, VM instance)
}

impl AsyncRuntime {
    pub fn new() -> Self {
        AsyncRuntime {
            pending_tasks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    // Schedule an async task
    pub fn schedule_task(&self, task_id: String, vm: KapraVM) {
        let mut tasks = self.pending_tasks.lock().unwrap();
        tasks.push((task_id, Arc::new(Mutex::new(vm))));
    }

    // Poll for task completion (simplified)
    pub fn poll(&self) -> Result<(), KslError> {
        let mut tasks = self.pending_tasks.lock().unwrap();
        let mut i = 0;
        while i < tasks.len() {
            let (task_id, vm) = tasks[i].clone();
            let mut vm = vm.lock().unwrap();
            if vm.is_async_pending() {
                // Simulate async I/O completion
                thread::sleep(Duration::from_millis(100));
                vm.complete_async();
                vm.run()?;
                tasks.remove(i);
                println!("Task {} completed", task_id);
            } else {
                i += 1;
            }
        }
        Ok(())
    }
}

// Async compiler and executor
pub struct AsyncProcessor {
    config: AsyncConfig,
    runtime: AsyncRuntime,
}

impl AsyncProcessor {
    pub fn new(config: AsyncConfig) -> Self {
        AsyncProcessor {
            config,
            runtime: AsyncRuntime::new(),
        }
    }

    // Compile and execute async KSL code
    pub fn process(&mut self) -> Result<(), KslError> {
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

        // Transform async/await syntax (simplified: add task scheduling)
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
        vm.run_with_async(&self.runtime)?;

        // Poll for async task completion
        self.runtime.poll()?;

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

    // Transform async/await syntax (simplified)
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

    // Transform async body (simplified: schedule async calls as tasks)
    fn transform_async_body(&self, body: &[AstNode], new_body: &mut Vec<AstNode>, task_name: &str) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        for node in body {
            match node {
                AstNode::Expr { kind: ExprKind::Call { name, args } } if name == "http.get" => {
                    let task_id = format!("task_{}_{}", task_name, new_body.len());
                    new_body.push(AstNode::Expr {
                        kind: ExprKind::Call {
                            name: "schedule_task".to_string(),
                            args: vec![
                                AstNode::Expr { kind: ExprKind::String(task_id.clone()) },
                                AstNode::Expr { kind: ExprKind::Call { name: name.clone(), args: args.clone() } },
                            ],
                        },
                    });
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

// Extend KapraVM for async support
trait AsyncVM {
    fn new_with_async(bytecode: KapraBytecode) -> Self;
    fn is_async_pending(&self) -> bool;
    fn complete_async(&mut self);
    fn run_with_async(&mut self, runtime: &AsyncRuntime) -> Result<(), RuntimeError>;
}

impl AsyncVM for KapraVM {
    fn new_with_async(bytecode: KapraBytecode) -> Self {
        let mut vm = KapraVM::new(bytecode);
        vm.async_state = Some(AsyncState {
            pending: false,
        });
        vm
    }

    fn is_async_pending(&self) -> bool {
        self.async_state.as_ref().map(|state| state.pending).unwrap_or(false)
    }

    fn complete_async(&mut self) {
        if let Some(state) = &mut self.async_state {
            state.pending = false;
        }
    }

    fn run_with_async(&mut self, runtime: &AsyncRuntime) -> Result<(), RuntimeError> {
        for instr in &self.bytecode.instructions {
            if let KapraInstruction { opcode: KapraOpCode::Call, operands, .. } = instr {
                if let Some(Operand::Immediate(name)) = operands.get(0) {
                    if name == "http.get" {
                        self.async_state.as_mut().unwrap().pending = true;
                        runtime.schedule_task(format!("http_get_{}", self.pc), self.clone());
                        return Ok(());
                    }
                }
            }
            self.execute_instruction(instr)?;
        }
        Ok(())
    }
}

// Async state for KapraVM
struct AsyncState {
    pending: bool,
}

// Public API to process async KSL code
pub fn process_async(input_file: &PathBuf, output_file: Option<PathBuf>) -> Result<(), KslError> {
    let config = AsyncConfig {
        input_file: input_file.clone(),
        output_file,
    };
    let mut processor = AsyncProcessor::new(config);
    processor.process()
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, kapra_vm.rs, ksl_stdlib_io.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod kapra_vm {
    pub use super::{KapraVM, RuntimeError, KapraBytecode, KapraInstruction, KapraOpCode, Operand};
}

mod ksl_stdlib_io {
    pub use super::HttpGet;
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
    fn test_process_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "#[async]\nfn fetch() {{ http.get(\"url\"); }}\nfn main() {{ fetch(); }}"
        ).unwrap();

        let output_file = temp_dir.path().join("output.ksl");
        let result = process_async(&input_file, Some(output_file.clone()));
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("schedule_task"));
    }

    #[test]
    fn test_process_async_no_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let output_file = temp_dir.path().join("output.ksl");
        let result = process_async(&input_file, Some(output_file.clone()));
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("let x: u32 = 42;"));
    }

    #[test]
    fn test_process_async_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("nonexistent.ksl");
        let output_file = temp_dir.path().join("output.ksl");

        let result = process_async(&input_file, Some(output_file));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}

