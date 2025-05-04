/// ksl_repl.rs
/// Implements an interactive Read-Eval-Print Loop (REPL) for KSL programs.
/// 
/// Key Features:
/// - Interactive command-line interface for KSL development
/// - Support for all KSL language features including async/await
/// - Integration with compiler and debugger
/// - Comprehensive error handling and reporting
/// 
/// Usage:
/// ```ksl
/// // Start the REPL
/// let repl = Repl::new();
/// repl.run()?;
/// 
/// // Example commands:
/// ksl> let x: u32 = 42;
/// ksl> fn add(a: u32, b: u32): u32 { a + b; }
/// ksl> #[async] fn fetch() { let data = http.get("https://example.com"); }
/// ksl> :debug // Enter debug mode
/// ksl> :quit // Exit REPL
/// ```

use crate::ksl_parser::{parse, AstNode, ExprKind};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::kapra_vm::{KapraVM, run};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_async::{AsyncRuntime, AsyncProcessor};
use crate::ksl_debug::{Debugger, DebugCommand};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::collections::HashMap;
use std::path::PathBuf;
use std::fs::File;
use std::io::Write;
use tokio::runtime::Runtime;

/// REPL state
pub struct Repl {
    module_system: ModuleSystem,
    vm: KapraVM,
    bytecode: KapraBytecode,
    variables: HashMap<String, u8>, // Variable name to register
    functions: HashMap<String, u32>, // Function name to instruction index
    async_runtime: AsyncRuntime,
    debugger: Option<Debugger>,
    is_debug_mode: bool,
}

impl Repl {
    /// Creates a new REPL instance
    pub fn new() -> Self {
        let bytecode = KapraBytecode::new();
        let vm = KapraVM::new(bytecode.clone());
        Repl {
            module_system: ModuleSystem::new(),
            vm,
            bytecode,
            variables: HashMap::new(),
            functions: HashMap::new(),
            async_runtime: AsyncRuntime::new(),
            debugger: None,
            is_debug_mode: false,
        }
    }

    /// Starts the REPL
    pub fn run(&mut self) -> Result<(), String> {
        let mut rl = Editor::<()>::new();
        println!("KSL REPL (type :help for commands)");

        loop {
            let readline = rl.readline("ksl> ");
            match readline {
                Ok(line) => {
                    rl.add_history_entry(line.as_str());
                    if line.trim().starts_with(':') {
                        match self.handle_command(&line.trim()[1..]) {
                            Ok(should_continue) => if !should_continue { break; },
                            Err(e) => println!("Error: {}", e),
                        }
                        continue;
                    }
                    match self.process_input(&line) {
                        Ok(result) => {
                            if let Some(value) = result {
                                println!("=> {}", value);
                            }
                        }
                        Err(e) => println!("Error: {}", e),
                    }
                }
                Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
                Err(err) => return Err(format!("Readline error: {}", err)),
            }
        }

        Ok(())
    }

    /// Handles REPL commands
    fn handle_command(&mut self, command: &str) -> Result<bool, String> {
        match command {
            "quit" | "exit" => Ok(false),
            "help" => {
                println!("Available commands:");
                println!("  :help - Show this help message");
                println!("  :quit - Exit the REPL");
                println!("  :reset - Reset REPL state");
                println!("  :debug - Enter debug mode");
                println!("  :async - Show async tasks");
                println!("  :vars - Show variables");
                println!("  :funcs - Show functions");
                Ok(true)
            }
            "reset" => {
                *self = Self::new();
                println!("REPL state reset");
                Ok(true)
            }
            "debug" => {
                self.is_debug_mode = true;
                self.debugger = Some(Debugger::new(&PathBuf::from("repl.ksl"))?);
                println!("Debug mode enabled");
                Ok(true)
            }
            "async" => {
                let tasks = self.async_runtime.tasks.lock().await;
                println!("Active async tasks:");
                for (id, handle) in &*tasks {
                    println!("  {}: {}", id, if handle.is_finished() { "completed" } else { "running" });
                }
                Ok(true)
            }
            "vars" => {
                println!("Variables:");
                for (name, reg) in &self.variables {
                    println!("  {}: {:?}", name, self.vm.registers[*reg as usize]);
                }
                Ok(true)
            }
            "funcs" => {
                println!("Functions:");
                for (name, index) in &self.functions {
                    println!("  {}: instruction {}", name, index);
                }
                Ok(true)
            }
            _ => Err(format!("Unknown command: {}", command)),
        }
    }

    /// Processes a single input line
    fn process_input(&mut self, input: &str) -> Result<Option<String>, String> {
        // Create temporary file for the input
        let temp_file = PathBuf::from("repl_temp.ksl");
        File::create(&temp_file)
            .map_err(|e| e.to_string())?
            .write_all(input.as_bytes())
            .map_err(|e| e.to_string())?;

        // Parse input
        let ast = parse(input)
            .map_err(|e| format!("Parse error at position {}: {}", e.position, e.message))?;

        // Type-check
        check(&ast)
            .map_err(|errors| errors.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"))?;

        // Handle async functions
        if ast.iter().any(|node| matches!(node, AstNode::AsyncFnDecl { .. })) {
            let processor = AsyncProcessor::new(AsyncConfig {
                input_file: temp_file.clone(),
                output_file: None,
            });
            processor.process().await
                .map_err(|e| e.to_string())?;
            return Ok(None);
        }

        // Compile
        let new_bytecode = compile(&ast)
            .map_err(|errors| errors.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"))?;

        // Update state
        for node in &ast {
            match node {
                AstNode::VarDecl { name, .. } => {
                    if let Some(reg) = self.variables.get(name) {
                        self.variables.insert(name.clone(), *reg);
                    } else {
                        let reg = self.vm.next_register().ok_or("No free registers")?;
                        self.variables.insert(name.clone(), reg);
                    }
                }
                AstNode::FnDecl { name, .. } => {
                    let fn_index = self.bytecode.instructions.len() as u32;
                    self.functions.insert(name.clone(), fn_index);
                }
                AstNode::Import { path, item } => {
                    self.module_system.resolve_import(path, item)
                        .map_err(|e| e.to_string())?;
                }
                _ => {}
            }
        }

        // Merge bytecode
        self.bytecode.instructions.extend(new_bytecode.instructions);
        self.vm = KapraVM::new(self.bytecode.clone());

        // Execute
        let result = run(self.bytecode.clone())
            .map_err(|e| format!("Runtime error at instruction {}: {}", e.pc, e.message))?;

        // Get result for expressions
        let output = if let Some(AstNode::Expr { .. }) = ast.last() {
            let last_reg = self.vm.registers.iter().rposition(|r| !r.is_empty())
                .map(|i| i as u8);
            if let Some(reg) = last_reg {
                let value = &self.vm.registers[reg as usize];
                Some(format!("{:?}", value)) // Simplified: format as byte array
            } else {
                None
            }
        } else {
            None
        };

        Ok(output)
    }
}

/// Public API to start the REPL
pub fn start_repl() -> Result<(), String> {
    let mut repl = Repl::new();
    repl.run()
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, ksl_module.rs, ksl_errors.rs, ksl_async.rs, and ksl_debug.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
}

mod kapra_vm {
    pub use super::{KapraVM, run};
}

mod ksl_module {
    pub use super::ModuleSystem;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncProcessor, AsyncConfig};
}

mod ksl_debug {
    pub use super::{Debugger, DebugCommand};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repl_expression() {
        let mut repl = Repl::new();
        let result = repl.process_input("42 + 1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("[43, 0, 0, 0]".to_string())); // u32: 43 in LE bytes
    }

    #[test]
    fn test_repl_variable() {
        let mut repl = Repl::new();
        let result = repl.process_input("let x: u32 = 42;");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        let result = repl.process_input("x");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("[42, 0, 0, 0]".to_string()));
    }

    #[test]
    fn test_repl_function() {
        let mut repl = Repl::new();
        let result = repl.process_input("fn add(x: u32, y: u32): u32 { x + y; }");
        assert!(result.is_ok());
        let result = repl.process_input("add(1, 2)");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("[3, 0, 0, 0]".to_string()));
    }

    #[tokio::test]
    async fn test_repl_async() {
        let mut repl = Repl::new();
        let result = repl.process_input("#[async] fn fetch() { let data = http.get(\"https://example.com\"); }");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}