// ksl_repl.rs
// Implements an interactive Read-Eval-Print Loop (REPL) for KSL programs.

use crate::ksl_parser::{parse, AstNode};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::kapra_vm::{KapraVM, run};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::collections::HashMap;

// REPL state
pub struct Repl {
    module_system: ModuleSystem,
    vm: KapraVM,
    bytecode: KapraBytecode,
    variables: HashMap<String, u8>, // Variable name to register
    functions: HashMap<String, u32>, // Function name to instruction index
}

impl Repl {
    pub fn new() -> Self {
        let bytecode = KapraBytecode::new();
        let vm = KapraVM::new(bytecode.clone());
        Repl {
            module_system: ModuleSystem::new(),
            vm,
            bytecode,
            variables: HashMap::new(),
            functions: HashMap::new(),
        }
    }

    // Start the REPL
    pub fn run(&mut self) -> Result<(), String> {
        let mut rl = Editor::<()>::new();
        println!("KSL REPL (type :quit to exit, :reset to clear state)");

        loop {
            let readline = rl.readline("ksl> ");
            match readline {
                Ok(line) => {
                    rl.add_history_entry(line.as_str());
                    if line.trim() == ":quit" {
                        break;
                    } else if line.trim() == ":reset" {
                        *self = Self::new();
                        println!("REPL state reset");
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

    // Process a single input line
    fn process_input(&mut self, input: &str) -> Result<Option<String>, String> {
        // Parse input
        let ast = parse(input)
            .map_err(|e| format!("Parse error at position {}: {}", e.position, e.message))?;

        // Type-check
        check(&ast)
            .map_err(|errors| errors.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"))?;

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

// Public API to start the REPL
pub fn start_repl() -> Result<(), String> {
    let mut repl = Repl::new();
    repl.run()
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, ksl_module.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode};
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
}