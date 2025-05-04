// ksl_dev_tools.rs
// Developer tools for debugging, profiling, and visualization in KSL

use crate::ksl_debug::{Debugger, Breakpoint, Watchpoint, DebugState};
use crate::ksl_async::{AsyncContext, AsyncCommand};
use crate::ksl_cli::{CliCommand, CliInterface};
use crate::ksl_errors::{KslError, ErrorType};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Represents KSL bytecode (aligned with ksl_bytecode.rs).
#[derive(Debug, Clone)]
pub struct Bytecode {
    instructions: Vec<u8>,
    constants: Vec<Constant>,
}

impl Bytecode {
    pub fn new(instructions: Vec<u8>, constants: Vec<Constant>) -> Self {
        Bytecode {
            instructions,
            constants,
        }
    }

    pub fn extend(&mut self, other: Bytecode) {
        self.instructions.extend(other.instructions);
        self.constants.extend(other.constants);
    }
}

/// Represents a constant in the bytecode.
#[derive(Debug, Clone)]
pub enum Constant {
    U64(u64),
    ArrayU8(usize, Vec<u8>),   // e.g., array<u8, 32>
    ArrayU64(usize, Vec<u64>), // e.g., array<u64, 3>
}

/// Represents an AST node (aligned with ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    DebugBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., message)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the debug block
    },
    ProfileBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., task)
        return_type: Type,           // Return type (array<u64, 3>)
        body: Vec<AstNode>,          // Body of the profile block
    },
    VisualizeBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., data)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the visualize block
    },
    Call {
        name: String,
        args: Vec<AstNode>,
    },
    LiteralU64(u64),
    LiteralArrayU8(usize, Vec<u8>),
    LiteralArrayU64(usize, Vec<u64>),
}

/// Represents a type (aligned with ksl_types.rs).
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Bool,
    U64,
    ArrayU8(usize),  // e.g., array<u8, 32>
    ArrayU64(usize), // e.g., array<u64, 3>
}

/// Runtime metrics (aligned with ksl_runtime_monitor.rs).
#[derive(Debug, Clone)]
pub struct RuntimeMetrics {
    instruction_count: u64,
    execution_time: u64, // Simulated time in arbitrary units
    gas_usage: u64,      // Simulated gas usage
}

impl RuntimeMetrics {
    pub fn new() -> Self {
        RuntimeMetrics {
            instruction_count: 0,
            execution_time: 0,
            gas_usage: 0,
        }
    }

    pub fn record_instruction(&mut self) {
        self.instruction_count += 1;
        self.execution_time += 1; // Increment time per instruction
        self.gas_usage += 1;      // Increment gas per instruction
    }
}

/// Developer tools runtime for KSL.
#[derive(Debug, Clone)]
pub struct DevToolsRuntime {
    is_embedded: bool,
    metrics: RuntimeMetrics,
    debugger: Arc<Mutex<Debugger>>,
    async_context: Arc<Mutex<AsyncContext>>,
    cli_interface: Arc<Mutex<CliInterface>>,
}

impl DevToolsRuntime {
    /// Creates a new developer tools runtime with debugging, async, and CLI support.
    pub fn new(is_embedded: bool) -> Self {
        DevToolsRuntime {
            is_embedded,
            metrics: RuntimeMetrics::new(),
            debugger: Arc::new(Mutex::new(Debugger::new())),
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
            cli_interface: Arc::new(Mutex::new(CliInterface::new())),
        }
    }

    /// Log a message with async support and CLI integration.
    pub async fn log(&self, message: &Vec<u8>) -> Result<bool, KslError> {
        let mut cli = self.cli_interface.lock().await;
        cli.execute_command(CliCommand::Log(message.clone()))
            .await
            .map_err(|e| KslError::new(ErrorType::RuntimeError, e.to_string()))
    }

    /// Set a breakpoint with debugging support.
    pub async fn breakpoint(&self, bp: Breakpoint) -> Result<bool, KslError> {
        let mut debugger = self.debugger.lock().await;
        debugger.set_breakpoint(bp)
            .map_err(|e| KslError::new(ErrorType::DebugError, e.to_string()))
    }

    /// Measure performance metrics for a task with async support.
    pub async fn measure(&self, task: &Vec<u8>) -> Result<Vec<u64>, KslError> {
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::Measure(task.clone());
        async_ctx.execute_command(command)
            .await
            .map_err(|e| KslError::new(ErrorType::AsyncError, e.to_string()))
    }

    /// Generate a visualization with async support.
    pub async fn generate_diagram(&self, data: &Vec<u64>) -> Result<bool, KslError> {
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::Visualize(data.clone());
        async_ctx.execute_command(command)
            .await
            .map_err(|e| KslError::new(ErrorType::AsyncError, e.to_string()))
    }

    /// Get current debug state.
    pub async fn get_debug_state(&self) -> Result<DebugState, KslError> {
        let debugger = self.debugger.lock().await;
        debugger.get_state()
            .map_err(|e| KslError::new(ErrorType::DebugError, e.to_string()))
    }

    /// Add a watchpoint for variable monitoring.
    pub async fn add_watchpoint(&self, wp: Watchpoint) -> Result<bool, KslError> {
        let mut debugger = self.debugger.lock().await;
        debugger.add_watchpoint(wp)
            .map_err(|e| KslError::new(ErrorType::DebugError, e.to_string()))
    }
}

/// Kapra VM with developer tools support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    dev_tools_runtime: DevToolsRuntime,
    async_tasks: Vec<AsyncTask>,
}

impl KapraVM {
    pub fn new(is_embedded: bool) -> Self {
        KapraVM {
            stack: vec![],
            dev_tools_runtime: DevToolsRuntime::new(is_embedded),
            async_tasks: vec![],
        }
    }

    pub async fn execute(&mut self, bytecode: &Bytecode) -> Result<Vec<u64>, KslError> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            self.dev_tools_runtime.metrics.record_instruction();

            match instr {
                OPCODE_LOG => {
                    if self.stack.len() < 1 {
                        return Err(KslError::new(ErrorType::StackUnderflow, "Not enough values on stack for LOG".to_string()));
                    }
                    let message_idx = self.stack.pop().unwrap() as usize;
                    let message = match &bytecode.constants[message_idx] {
                        Constant::ArrayU8(_, data) => data,
                        _ => return Err(KslError::new(ErrorType::TypeError, "Invalid type for LOG message".to_string())),
                    };
                    let success = self.dev_tools_runtime.log(message).await?;
                    self.stack.push(success as u64);
                }
                OPCODE_BREAKPOINT => {
                    let bp = Breakpoint::new(ip as u64);
                    let success = self.dev_tools_runtime.breakpoint(bp).await?;
                    self.stack.push(success as u64);
                }
                OPCODE_MEASURE => {
                    if self.stack.len() < 1 {
                        return Err(KslError::new(ErrorType::StackUnderflow, "Not enough values on stack for MEASURE".to_string()));
                    }
                    let task_idx = self.stack.pop().unwrap() as usize;
                    let task = match &bytecode.constants[task_idx] {
                        Constant::ArrayU8(_, data) => data,
                        _ => return Err(KslError::new(ErrorType::TypeError, "Invalid type for MEASURE task".to_string())),
                    };
                    let metrics = self.dev_tools_runtime.measure(task).await?;
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::ArrayU64(metrics.len(), metrics));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_GENERATE_DIAGRAM => {
                    if self.stack.len() < 1 {
                        return Err(KslError::new(ErrorType::StackUnderflow, "Not enough values on stack for GENERATE_DIAGRAM".to_string()));
                    }
                    let data_idx = self.stack.pop().unwrap() as usize;
                    let data = match &bytecode.constants[data_idx] {
                        Constant::ArrayU64(_, data) => data,
                        _ => return Err(KslError::new(ErrorType::TypeError, "Invalid type for GENERATE_DIAGRAM data".to_string())),
                    };
                    let success = self.dev_tools_runtime.generate_diagram(data).await?;
                    self.stack.push(success as u64);
                }
                OPCODE_PUSH => {
                    if ip >= bytecode.instructions.len() {
                        return Err(KslError::new(ErrorType::InvalidInstruction, "Incomplete PUSH instruction".to_string()));
                    }
                    let value = bytecode.instructions[ip] as u64;
                    ip += 1;
                    self.stack.push(value);
                }
                OPCODE_FAIL => {
                    return Err(KslError::new(ErrorType::RuntimeError, "Developer tools operation failed".to_string()));
                }
                _ => return Err(KslError::new(ErrorType::InvalidInstruction, format!("Unsupported opcode: {}", instr))),
            }
        }

        if self.stack.len() != 1 {
            return Err(KslError::new(ErrorType::StackError, "Developer tools block must return exactly one value".to_string()));
        }
        match &bytecode.constants.last() {
            Some(Constant::ArrayU64(_, data)) => Ok(data.clone()),
            _ => Ok(vec![self.stack[0]]),
        }
    }
}

/// Represents an async task (aligned with ksl_async.rs).
#[derive(Debug, Clone)]
pub enum AsyncTask {
    Debug(DebugState),
    Profile(Vec<u64>),
    Visualize(bool),
}

/// Developer tools compiler for KSL.
pub struct DevToolsCompiler {
    is_embedded: bool,
}

impl DevToolsCompiler {
    pub fn new(is_embedded: bool) -> Self {
        DevToolsCompiler { is_embedded }
    }

    /// Compile a developer tools block into bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, String> {
        match node {
            AstNode::DebugBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 1 {
                    return Err("Debug block must have exactly 1 parameter: message".to_string());
                }
                if params[0].0 != "message" || !matches!(params[0].1, Type::ArrayU8(32)) {
                    return Err("Parameter must be 'message: array<u8, 32]'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("Debug block must return bool".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            AstNode::ProfileBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 1 {
                    return Err("Profile block must have exactly 1 parameter: task".to_string());
                }
                if params[0].0 != "task" || !matches!(params[0].1, Type::ArrayU8(32)) {
                    return Err("Parameter must be 'task: array<u8, 32]'".to_string());
                }
                if !matches!(return_type, Type::ArrayU64(3)) {
                    return Err("Profile block must return array<u64, 3>".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            AstNode::VisualizeBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 1 {
                    return Err("Visualize block must have exactly 1 parameter: data".to_string());
                }
                if params[0].0 != "data" || !matches!(params[0].1, Type::ArrayU64(4)) {
                    return Err("Parameter must be 'data: array<u64, 4]'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("Visualize block must return bool".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            _ => Err("Only developer tools blocks can be compiled at the top level".to_string()),
        }
    }

    fn compile_stmt(&self, stmt: &AstNode) -> Result<Bytecode, String> {
        match stmt {
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                match name.as_str() {
                    "log" => {
                        bytecode.instructions.push(OPCODE_LOG);
                    }
                    "breakpoint" => {
                        bytecode.instructions.push(OPCODE_BREAKPOINT);
                    }
                    "measure" => {
                        bytecode.instructions.push(OPCODE_MEASURE);
                    }
                    "generate_diagram" => {
                        bytecode.instructions.push(OPCODE_GENERATE_DIAGRAM);
                    }
                    _ => return Err(format!("Unsupported function in developer tools block: {}", name)),
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported statement in developer tools block".to_string()),
        }
    }

    fn compile_expr(&self, expr: &AstNode) -> Result<Bytecode, String> {
        match expr {
            AstNode::LiteralU64(val) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::U64(*val));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArrayU8(size, data) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::ArrayU8(*size, data.clone()));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArrayU64(size, data) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::ArrayU64(*size, data.clone()));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                if name == "log" {
                    bytecode.instructions.push(OPCODE_LOG);
                } else if name == "breakpoint" {
                    bytecode.instructions.push(OPCODE_BREAKPOINT);
                } else if name == "measure" {
                    bytecode.instructions.push(OPCODE_MEASURE);
                } else if name == "generate_diagram" {
                    bytecode.instructions.push(OPCODE_GENERATE_DIAGRAM);
                } else {
                    return Err(format!("Unsupported expression in developer tools block: {}", name));
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported expression in developer tools block".to_string()),
        }
    }
}

const OPCODE_LOG: u8 = 0x01;
const OPCODE_BREAKPOINT: u8 = 0x02;
const OPCODE_MEASURE: u8 = 0x03;
const OPCODE_GENERATE_DIAGRAM: u8 = 0x04;
const OPCODE_PUSH: u8 = 0x05;
const OPCODE_FAIL: u8 = 0x06;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_block_compilation() {
        let debug_node = AstNode::DebugBlock {
            params: vec![("message".to_string(), Type::ArrayU8(32))],
            return_type: Type::Bool,
            body: vec![
                AstNode::Call {
                    name: "log".to_string(),
                    args: vec![AstNode::LiteralArrayU8(32, vec![1; 32])],
                },
                AstNode::Call {
                    name: "breakpoint".to_string(),
                    args: vec![],
                },
            ],
        };

        let compiler = DevToolsCompiler::new(false);
        let bytecode = compiler.compile(&debug_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_LOG));
        assert!(bytecode.instructions.contains(&OPCODE_BREAKPOINT));
    }

    #[test]
    fn test_profile_block_compilation() {
        let profile_node = AstNode::ProfileBlock {
            params: vec![("task".to_string(), Type::ArrayU8(32))],
            return_type: Type::ArrayU64(3),
            body: vec![
                AstNode::Call {
                    name: "measure".to_string(),
                    args: vec![AstNode::LiteralArrayU8(32, vec![1; 32])],
                },
            ],
        };

        let compiler = DevToolsCompiler::new(false);
        let bytecode = compiler.compile(&profile_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_MEASURE));
    }

    #[test]
    fn test_visualize_block_compilation() {
        let visualize_node = AstNode::VisualizeBlock {
            params: vec![("data".to_string(), Type::ArrayU64(4))],
            return_type: Type::Bool,
            body: vec![
                AstNode::Call {
                    name: "generate_diagram".to_string(),
                    args: vec![AstNode::LiteralArrayU64(4, vec![1, 2, 3, 4])],
                },
            ],
        };

        let compiler = DevToolsCompiler::new(false);
        let bytecode = compiler.compile(&visualize_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_GENERATE_DIAGRAM));
    }

    #[test]
    fn test_debug_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::ArrayU8(32, vec![1; 32]), // message
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push message
            OPCODE_LOG,               // Log message
            OPCODE_BREAKPOINT,        // Set breakpoint
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![1]); // Success
    }

    #[test]
    fn test_profile_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::ArrayU8(32, vec![1; 32]), // task
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push task
            OPCODE_MEASURE,           // Measure performance
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        let metrics = result.unwrap();
        assert_eq!(metrics.len(), 3); // [gas_usage, instruction_count, execution_time]
        assert_eq!(metrics[0], 320); // Simulated gas usage (32 * 10)
    }

    #[test]
    fn test_visualize_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::ArrayU64(4, vec![1, 2, 3, 4]), // data
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push data
            OPCODE_GENERATE_DIAGRAM,  // Generate diagram
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![1]); // Success
    }

    #[test]
    fn test_invalid_debug_params() {
        let debug_node = AstNode::DebugBlock {
            params: vec![],
            return_type: Type::Bool,
            body: vec![],
        };

        let compiler = DevToolsCompiler::new(false);
        let result = compiler.compile(&debug_node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must have exactly 1 parameter"));
    }
}