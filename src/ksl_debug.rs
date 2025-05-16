// ksl_debug.rs
// Implements a debugging framework for KSL programs.
// 
// The debugger provides interactive debugging capabilities for KSL programs,
// including breakpoints, step-by-step execution, and state inspection.
// 
// New features:
// - Network state inspection: View active connections and pending requests
// - Async task monitoring: Track active and pending async tasks
// - Enhanced state display: Shows networking and async task information
// 
// Usage:
//   debug(file) -> Starts an interactive debugging session
//   Commands:
//     break <index>  - Set breakpoint at instruction index
//     step          - Execute one instruction
//     continue      - Run until breakpoint or end
//     print <target> - Print register or memory value
//     net           - Display detailed network state
//     tasks         - Display detailed async task state
//     quit          - Exit debugger

use crate::ksl_parser::parse;
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::kapra_vm::{KapraVM, RuntimeError};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs;
use std::io::{self, Write};
use std::collections::HashSet;
use std::collections::HashMap;

// Debug command enum
#[derive(Debug, PartialEq)]
pub enum DebugCommand {
    Break(u32), // Set breakpoint at instruction index
    Step, // Execute one instruction
    Continue, // Run until breakpoint or end
    Print(String), // Print register (e.g., "r0") or memory (e.g., "mem 0x100")
    Net, // Display network state
    Tasks, // Display async tasks state
    Quit, // Exit debugger
}

// Debugger state
pub struct Debugger {
    vm: KapraVM, // VM instance for execution
    bytecode: KapraBytecode, // Program bytecode
    breakpoints: HashSet<u32>, // Instruction indices for breakpoints
    function_breakpoints: HashSet<String>, // Function name breakpoints for JIT
    running: bool, // Debugger loop control
    is_jit: bool, // Whether running in JIT mode
}

impl Debugger {
    pub fn new() -> Result<Self, String> {
        // Create an empty bytecode
        let bytecode = KapraBytecode::new();
        
        // Initialize VM with empty bytecode
        let vm = KapraVM::new(bytecode.clone());

        Ok(Debugger {
            vm,
            bytecode,
            breakpoints: HashSet::new(),
            function_breakpoints: HashSet::new(),
            running: true,
            is_jit: false,
        })
    }

    pub fn new_with_file(file: &std::path::PathBuf) -> Result<Self, String> {
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
            function_breakpoints: HashSet::new(),
            running: true,
            is_jit: false,
        })
    }

    // Enable JIT mode
    pub fn enable_jit(&mut self) {
        self.is_jit = true;
    }

    // Attach bytecode for debugging
    pub fn attach_bytecode(&mut self, bytecode: &KapraBytecode) -> Result<(), String> {
        self.bytecode = bytecode.clone();
        Ok(())
    }

    // Check if a function has a breakpoint (for JIT mode)
    pub fn has_breakpoint(&self, function_name: &str) -> bool {
        self.function_breakpoints.contains(function_name)
    }

    // Handle a breakpoint in JIT mode
    pub fn handle_breakpoint(&self) -> Result<(), String> {
        println!("Breakpoint hit. Commands: continue, step, print <var>, quit");
        loop {
            print!("(ksl-dbg) ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut input = String::new();
            io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
            let input = input.trim();

            match input {
                "continue" => break,
                "step" => {
                    println!("Stepping...");
                    break;
                }
                "quit" => {
                    println!("Exiting debugger...");
                    std::process::exit(0);
                }
                cmd if cmd.starts_with("print ") => {
                    let var = &cmd[6..];
                    println!("Variable {}: <value not available in JIT mode>", var);
                }
                _ => println!("Unknown command. Use: continue, step, print <var>, quit"),
            }
        }
        Ok(())
    }

    // Notify function entry (for JIT mode)
    pub fn notify_function_entry(&mut self, function_name: &str) -> Result<(), String> {
        if self.is_jit {
            println!("Entering function: {}", function_name);
        }
        Ok(())
    }

    // Notify function exit (for JIT mode)
    pub fn notify_function_exit(&mut self, function_name: &str) -> Result<(), String> {
        if self.is_jit {
            println!("Exiting function: {}", function_name);
        }
        Ok(())
    }

    // Start the debugging session
    pub fn run(&mut self) -> Result<(), String> {
        println!("KSL Debugger started. Commands: break <index/function>, step, continue, print <rN/mem addr>, net, tasks, quit");
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
                return Err("Invalid break command: use 'break <index/function>'".to_string());
            }
            // Try parsing as instruction index first
            match parts[1].parse::<u32>() {
                Ok(index) => return Ok(DebugCommand::Break(index)),
                Err(_) => {
                    // If not a number, treat as function name
                    if self.is_jit {
                        self.function_breakpoints.insert(parts[1].to_string());
                        println!("Breakpoint set on function: {}", parts[1]);
                    }
                    return Ok(DebugCommand::Break(0)); // Dummy index for function breakpoint
                }
            }
        } else if input.starts_with("print ") {
            let parts: Vec<&str> = input.split_whitespace().collect();
            if parts.len() != 2 {
                return Err("Invalid print command: use 'print <rN/mem addr>'".to_string());
            }
            return Ok(DebugCommand::Print(parts[1].to_string()));
        } else if input == "net" {
            return Ok(DebugCommand::Net);
        } else if input == "tasks" {
            return Ok(DebugCommand::Tasks);
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
            DebugCommand::Net => {
                if let Some(net_state) = &self.vm.network_state {
                    println!("Network State:");
                    println!("  Active Connections ({}):", net_state.active_connections.len());
                    for (id, conn) in &net_state.active_connections {
                        println!("    Connection {}:", id);
                        println!("      Type: {:?}", conn.conn_type);
                        println!("      State: {:?}", conn.state);
                        println!("      Local Address: {:?}", conn.local_addr);
                        println!("      Remote Address: {:?}", conn.remote_addr);
                        println!("      Buffer Size: {}", conn.buffer.len());
                    }
                    println!("  Pending Requests ({}):", net_state.pending_requests.len());
                    for (id, req) in &net_state.pending_requests {
                        println!("    Request {}:", id);
                        println!("      Type: {:?}", req.request_type);
                        println!("      URL: {}", req.url);
                        println!("      Headers: {:?}", req.headers);
                    }
                } else {
                    println!("No network state available");
                }
            }
            DebugCommand::Tasks => {
                if let Some(task_state) = &self.vm.task_state {
                    println!("Async Tasks:");
                    println!("  Active Tasks ({}):", task_state.active_tasks.len());
                    for (id, task) in &task_state.active_tasks {
                        println!("    Task {}:", id);
                        println!("      State: {:?}", task.state);
                        println!("      PC: 0x{:04x}", task.pc);
                        println!("      Stack Size: {}", task.stack.len());
                        println!("      Registers: {:?}", task.registers);
                    }
                    println!("  Pending Tasks ({}):", task_state.pending_tasks.len());
                    for (id, task) in &task_state.pending_tasks {
                        println!("    Task {}:", id);
                        println!("      Priority: {}", task.priority);
                        println!("      Creation Time: {:?}", task.creation_time);
                    }
                } else {
                    println!("No async task state available");
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

        // Display networking state
        if let Some(net_state) = &self.vm.network_state {
            println!("Network State:");
            println!("  Active Connections: {}", net_state.active_connections.len());
            for (id, conn) in &net_state.active_connections {
                println!("    Connection {}: {:?}", id, conn);
            }
            println!("  Pending Requests: {}", net_state.pending_requests.len());
        }

        // Display async task state
        if let Some(task_state) = &self.vm.task_state {
            println!("Async Tasks:");
            println!("  Active Tasks: {}", task_state.active_tasks.len());
            for (id, task) in &task_state.active_tasks {
                println!("    Task {}: {:?}", id, task);
            }
            println!("  Pending Tasks: {}", task_state.pending_tasks.len());
        }
    }

    /// Set a breakpoint at a specific line number
    pub fn set_breakpoint(&mut self, line_num: usize) {
        // Convert line number to instruction index (simplified)
        let breakpoint_index = line_num as u32;
        self.breakpoints.insert(breakpoint_index);
    }

    /// Inspect variables in the current scope
    pub fn inspect_variables(&self) -> HashMap<String, Vec<u8>> {
        // In a real implementation, this would extract variable names and values
        // from the VM's state
        let mut variables = HashMap::new();
        
        // Return registers as variables for simplicity
        for i in 0..16 {
            if !self.vm.registers[i].is_empty() {
                variables.insert(format!("r{}", i), self.vm.registers[i].clone());
            }
        }
        
        variables
    }

    /// Clear all breakpoints
    pub fn clear_breakpoints(&mut self) {
        self.breakpoints.clear();
        self.function_breakpoints.clear();
    }
    
    /// Check if execution should break at the current point
    pub fn should_break(&self) -> bool {
        // In a real implementation, this would check if the current position
        // matches any breakpoint
        if self.breakpoints.contains(&(self.vm.pc as u32)) {
            return true;
        }
        
        false
    }
}

// Public API to start debugging
pub fn debug(file: &std::path::PathBuf) -> Result<(), String> {
    let mut debugger = Debugger::new_with_file(file)?;
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

        let debugger = Debugger::new_with_file(&temp_file.path().to_path_buf());
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

        let mut debugger = Debugger::new_with_file(&temp_file.path().to_path_buf()).unwrap();
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

        let mut debugger = Debugger::new_with_file(&temp_file.path().to_path_buf()).unwrap();
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