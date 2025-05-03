// ksl_debug.rs
// Implements a debugging framework for KSL programs.

use crate::ksl_parser::parse;
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs;
use std::io::{self, Write};
use std::collections::HashSet;

// Debug command enum
#[derive(Debug, PartialEq)]
enum DebugCommand {
    Break(u32), // Set breakpoint at instruction index
    Step, // Execute one instruction
    Continue, // Run until breakpoint or end
    Print(String), // Print register (e.g., "r0") or memory (e.g., "mem 0x100")
    Quit, // Exit debugger
}

// Debugger state
pub struct Debugger {
    vm: KapraVM, // VM instance for execution
    bytecode: KapraBytecode, // Program bytecode
    breakpoints: HashSet<u32>, // Instruction indices for breakpoints
    running: bool, // Debugger loop control
}

impl Debugger {
    pub fn new(file: &std::path::PathBuf) -> Result<Self, String> {
        // Read source file
        let source = fs::read_to_string(file)
            .map_err(|e| format!("Failed to read file {}: {}", file.display(), e))?;

        // Parse
        let ast = parse(&source)
            .map_err(|e| format!("Parse error at position {}: {}", e.position, e.message))?;

        // Type-check
        check(&ast)
            .map_err(|errors| {
                errors
                    .into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;

        // Compile
        let bytecode = compile(&ast)
            .map_err(|errors| {
                errors
                    .into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;

        // Initialize VM
        let vm = KapraVM::new(bytecode.clone());

        Ok(Debugger {
            vm,
            bytecode,
            breakpoints: HashSet::new(),
            running: true,
        })
    }

    // Start the debugging session
    pub fn run(&mut self) -> Result<(), String> {
        println!("KSL Debugger started. Commands: break <index>, step, continue, print <rN/mem addr>, quit");
        while self.running {
            self.print_state();
            match self.read_command() {
                Ok(command) => self.execute_command(command)?,
                Err(e) => println!("Error: {}", e),
            }
        }
        Ok(())
    }

    // Read and parse a debug command
    fn read_command(&self) -> Result<DebugCommand, String> {
        print!("(ksl-dbg) ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        let input = input.trim();

        if input == "quit" {
            return Ok(DebugCommand::Quit);
        } else if input == "step" {
            return Ok(DebugCommand::Step);
        } else if input == "continue" {
            return Ok(DebugCommand::Continue);
        } else if input.starts_with("break ") {
            let parts: Vec<&str> = input.split_whitespace().collect();
            if parts.len() != 2 {
                return Err("Invalid break command: use 'break <index>'".to_string());
            }
            let index = parts[1].parse::<u32>().map_err(|e| format!("Invalid index: {}", e))?;
            return Ok(DebugCommand::Break(index));
        } else if input.starts_with("print ") {
            let parts: Vec<&str> = input.split_whitespace().collect();
            if parts.len() != 2 {
                return Err("Invalid print command: use 'print <rN/mem addr>'".to_string());
            }
            return Ok(DebugCommand::Print(parts[1].to_string()));
        }

        Err("Unknown command".to_string())
    }

    // Execute a debug command
    fn execute_command(&mut self, command: DebugCommand) -> Result<(), String> {
        match command {
            DebugCommand::Break(index) => {
                if index as usize >= self.bytecode.instructions.len() {
                    return Err(format!("Invalid breakpoint index: {}", index));
                }
                self.breakpoints.insert(index);
                println!("Breakpoint set at instruction 0x{:04x}", index);
            }
            DebugCommand::Step => {
                if self.vm.halted || self.vm.pc >= self.bytecode.instructions.len() {
                    return Err("Program has halted".to_string());
                }
                let instruction = &self.bytecode.instructions[self.vm.pc];
                self.vm.execute_instruction(instruction)
                    .map_err(|e| format!("Runtime error at instruction {}: {}", e.pc, e.message))?;
                self.vm.pc += 1;
            }
            DebugCommand::Continue => {
                while !self.vm.halted && self.vm.pc < self.bytecode.instructions.len() {
                    if self.breakpoints.contains(&(self.vm.pc as u32)) {
                        println!("Hit breakpoint at instruction 0x{:04x}", self.vm.pc);
                        break;
                    }
                    let instruction = &self.bytecode.instructions[self.vm.pc];
                    self.vm.execute_instruction(instruction)
                        .map_err(|e| format!("Runtime error at instruction {}: {}", e.pc, e.message))?;
                    self.vm.pc += 1;
                }
            }
            DebugCommand::Print(target) => {
                if target.starts_with("r") {
                    let reg_num = target[1..].parse::<u8>().map_err(|e| format!("Invalid register: {}", e))?;
                    if reg_num >= 16 {
                        return Err("Register index out of range".to_string());
                    }
                    let value = &self.vm.registers[reg_num as usize];
                    println!("r{} = {:?}", reg_num, value);
                } else if target.starts_with("mem ") {
                    let addr = target[4..].parse::<u64>().map_err(|e| format!("Invalid memory address: {}", e))?;
                    let value = self.vm.memory.get(&addr).unwrap_or(&vec![]);
                    println!("mem[0x{:x}] = {:?}", addr, value);
                } else {
                    return Err("Invalid print target: use 'rN' or 'mem addr'".to_string());
                }
            }
            DebugCommand::Quit => {
                self.running = false;
            }
        }
        Ok(())
    }

    // Print current VM state
    fn print_state(&self) {
        if self.vm.pc < self.bytecode.instructions.len() {
            let instr = &self.bytecode.instructions[self.vm.pc];
            println!("PC: 0x{:04x}, Instruction: {:?}", self.vm.pc, instr.opcode);
            for (i, op) in instr.operands.iter().enumerate() {
                println!("  Operand {}: {:?}", i, op);
            }
        } else {
            println!("PC: 0x{:04x}, Program halted", self.vm.pc);
        }
        println!("Registers:");
        for i in 0..16 {
            if !self.vm.registers[i].is_empty() {
                println!("  r{} = {:?}", i, self.vm.registers[i]);
            }
        }
        if !self.vm.memory.is_empty() {
            println!("Memory:");
            for (addr, value) in &self.vm.memory {
                println!("  0x{:x} = {:?}", addr, value);
            }
        }
        if !self.breakpoints.is_empty() {
            println!("Breakpoints: {:?}", self.breakpoints);
        }
    }
}

// Public API to start debugging
pub fn debug(file: &std::path::PathBuf) -> Result<(), String> {
    let mut debugger = Debugger::new(file)?;
    debugger.run()
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::parse;
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
    pub use super::{KapraVM, RuntimeError};
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
    fn test_debugger_init() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { let x: u32 = 42; let y: u32 = x + x; }"
        ).unwrap();

        let debugger = Debugger::new(&temp_file.path().to_path_buf());
        assert!(debugger.is_ok());
        let debugger = debugger.unwrap();
        assert_eq!(debugger.bytecode.instructions.len(), 4); // Mov, Add, Mov, Halt
    }

    #[test]
    fn test_breakpoint_and_step() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { let x: u32 = 42; let y: u32 = x + x; }"
        ).unwrap();

        let mut debugger = Debugger::new(&temp_file.path().to_path_buf()).unwrap();
        debugger.execute_command(DebugCommand::Break(1)).unwrap();
        debugger.execute_command(DebugCommand::Step).unwrap();
        assert_eq!(debugger.vm.pc, 1);
        debugger.execute_command(DebugCommand::Continue).unwrap();
        assert_eq!(debugger.vm.pc, 1); // Stopped at breakpoint
    }

    #[test]
    fn test_print_register() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { let x: u32 = 42; }"
        ).unwrap();

        let mut debugger = Debugger::new(&temp_file.path().to_path_buf()).unwrap();
        debugger.execute_command(DebugCommand::Step).unwrap();
        // Capture stdout for testing print
        let mut output = Vec::new();
        {
            let mut stdout = io::BufWriter::new(&mut output);
            writeln!(stdout, "r0 = {:?}", debugger.vm.registers[0]).unwrap();
        }
        let expected = format!("r0 = {:?}\n", 42u32.to_le_bytes().to_vec());
        debugger.execute_command(DebugCommand::Print("r0".to_string())).unwrap();
        // Note: Actual stdout testing requires redirecting; simplified here
        assert_eq!(debugger.vm.registers[0], 42u32.to_le_bytes().to_vec());
    }
}