// ksl_kapra_shard.rs
// Language-level sharding primitives for Kapra Chain

use std::collections::HashMap;

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
    String(String),
    U64(u64),
    Array32([u8; 32]),
}

/// Represents an AST node (aligned with ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    ShardBlock {
        input: String,       // Input parameter name (e.g., "account")
        input_type: Type,    // Input type (e.g., array<u8, 32>)
        return_type: Type,   // Return type (e.g., u32)
        body: Vec<AstNode>,  // Body of the shard block
    },
    Call {
        name: String,
        args: Vec<AstNode>,
    },
    Let {
        name: String,
        ty: Type,
        value: Box<AstNode>,
    },
    LiteralU32(u32),
    LiteralArray32([u8; 32]),
}

/// Represents a type (aligned with ksl_types.rs).
#[derive(Debug, Clone)]
pub enum Type {
    U32,
    ArrayU8(usize), // e.g., array<u8, 32>
}

/// Sharding runtime for Kapra Chain (integrates with ksl_stdlib_net.rs).
#[derive(Debug, Clone)]
pub struct ShardRuntime {
    shard_count: u32, // Total number of shards (configurable)
    route_cache: HashMap<[u8; 32], u32>, // Cache for shard_route results
}

impl ShardRuntime {
    pub fn new(shard_count: u32) -> Self {
        ShardRuntime {
            shard_count,
            route_cache: HashMap::new(),
        }
    }

    /// Route an account to a shard (simulates shard_route).
    pub fn shard_route(&mut self, account: &[u8; 32]) -> u32 {
        if let Some(shard_id) = self.route_cache.get(account) {
            return *shard_id;
        }

        // Simplified routing: hash the account and mod by shard count
        let hash = account.iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        let shard_id = hash % self.shard_count;
        self.route_cache.insert(*account, shard_id);
        shard_id
    }

    /// Send a message to a shard (simulates shard_send).
    pub fn shard_send(&self, shard_id: u32, message: &[u8; 32]) -> bool {
        // Validate shard ID
        if shard_id >= self.shard_count {
            return false;
        }

        // Simulate sending (in reality, this would use net.udp_send or similar)
        true
    }
}

/// Kapra VM with sharding support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    shard_runtime: ShardRuntime,
    async_tasks: Vec<AsyncTask>,
}

impl KapraVM {
    pub fn new(shard_count: u32) -> Self {
        KapraVM {
            stack: vec![],
            shard_runtime: ShardRuntime::new(shard_count),
            async_tasks: vec![],
        }
    }

    pub fn execute(&mut self, bytecode: &Bytecode) -> Result<(), String> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            match instr {
                OPCODE_SHARD_ROUTE => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for SHARD_ROUTE".to_string());
                    }
                    let account_idx = self.stack.pop().unwrap() as usize;
                    if account_idx >= bytecode.constants.len() {
                        return Err("Invalid constant index for SHARD_ROUTE".to_string());
                    }
                    let account = match &bytecode.constants[account_idx] {
                        Constant::Array32(arr) => arr,
                        _ => return Err("Invalid type for SHARD_ROUTE argument".to_string()),
                    };
                    let shard_id = self.shard_runtime.shard_route(account);
                    self.stack.push(shard_id as u64);
                }
                OPCODE_SHARD_SEND => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for SHARD_SEND".to_string());
                    }
                    let msg_idx = self.stack.pop().unwrap() as usize;
                    let shard_id = self.stack.pop().unwrap() as u32;
                    if msg_idx >= bytecode.constants.len() {
                        return Err("Invalid constant index for SHARD_SEND".to_string());
                    }
                    let message = match &bytecode.constants[msg_idx] {
                        Constant::Array32(arr) => arr,
                        _ => return Err("Invalid type for SHARD_SEND argument".to_string()),
                    };
                    let success = self.shard_runtime.shard_send(shard_id, message);
                    self.stack.push(success as u64);

                    // Schedule the async task (simplified)
                    self.async_tasks.push(AsyncTask::ShardSend(shard_id, *message));
                }
                OPCODE_PUSH => {
                    if ip >= bytecode.instructions.len() {
                        return Err("Incomplete PUSH instruction".to_string());
                    }
                    let value = bytecode.instructions[ip] as u64;
                    ip += 1;
                    self.stack.push(value);
                }
                OPCODE_POP => {
                    if self.stack.is_empty() {
                        return Err("Stack underflow".to_string());
                    }
                    self.stack.pop();
                }
                _ => return Err(format!("Unsupported opcode: {}", instr)),
            }
        }
        Ok(())
    }
}

/// Represents an async task (aligned with ksl_async.rs).
#[derive(Debug, Clone)]
pub enum AsyncTask {
    ShardSend(u32, [u8; 32]),
}

/// Compiler for shard blocks.
pub struct ShardCompiler {
    shard_count: u32,
}

impl ShardCompiler {
    pub fn new(shard_count: u32) -> Self {
        ShardCompiler { shard_count }
    }

    /// Compile a shard block into bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, String> {
        match node {
            AstNode::ShardBlock {
                input,
                input_type,
                return_type,
                body,
            } => {
                // Validate input and return types
                if !matches!(input_type, Type::ArrayU8(32)) {
                    return Err("Shard block input must be array<u8, 32>".to_string());
                }
                if !matches!(return_type, Type::U32) {
                    return Err("Shard block must return u32".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt, input)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            _ => Err("Only shard blocks can be compiled at the top level".to_string()),
        }
    }

    fn compile_stmt(&self, stmt: &AstNode, input_param: &str) -> Result<Bytecode, String> {
        match stmt {
            AstNode::Let { name, ty, value } => {
                let value_bytecode = self.compile_expr(value.as_ref(), input_param)?;
                let mut bytecode = value_bytecode;

                // Add the variable to the constants (simplified)
                if let AstNode::Call { name: call_name, .. } = value.as_ref() {
                    if call_name == "shard_route" {
                        bytecode.instructions.push(OPCODE_SHARD_ROUTE);
                    } else if call_name == "shard_send" {
                        bytecode.instructions.push(OPCODE_SHARD_SEND);
                    }
                }

                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg, input_param)?;
                    bytecode.extend(arg_bytecode);
                }
                if name == "shard_route" {
                    bytecode.instructions.push(OPCODE_SHARD_ROUTE);
                } else if name == "shard_send" {
                    bytecode.instructions.push(OPCODE_SHARD_SEND);
                } else {
                    return Err(format!("Unsupported function in shard block: {}", name));
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported statement in shard block".to_string()),
        }
    }

    fn compile_expr(&self, expr: &AstNode, input_param: &str) -> Result<Bytecode, String> {
        match expr {
            AstNode::LiteralU32(val) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, *val as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArray32(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array32(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg, input_param)?;
                    bytecode.extend(arg_bytecode);
                }
                if name == input_param {
                    // Reference to the input parameter (e.g., account)
                    Ok(bytecode)
                } else {
                    Err(format!("Unsupported expression in shard block: {}", name))
                }
            }
            _ => Err("Unsupported expression in shard block".to_string()),
        }
    }
}

/// Example usage in KSL (for reference):
/// shard (account: array<u8, 32]) -> u32 {
///     let shard_id: u32 = shard_route(account);
///     shard_send(shard_id, account);
///     shard_id
/// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_block_compilation() {
        let shard_node = AstNode::ShardBlock {
            input: "account".to_string(),
            input_type: Type::ArrayU8(32),
            return_type: Type::U32,
            body: vec![
                AstNode::Let {
                    name: "shard_id".to_string(),
                    ty: Type::U32,
                    value: Box::new(AstNode::Call {
                        name: "shard_route".to_string(),
                        args: vec![AstNode::LiteralArray32([1; 32])],
                    }),
                },
                AstNode::Call {
                    name: "shard_send".to_string(),
                    args: vec![
                        AstNode::LiteralU32(0), // Shard ID (simplified)
                        AstNode::LiteralArray32([1; 32]),
                    ],
                },
            ],
        };

        let compiler = ShardCompiler::new(1000);
        let bytecode = compiler.compile(&shard_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_SHARD_ROUTE));
        assert!(bytecode.instructions.contains(&OPCODE_SHARD_SEND));
    }

    #[test]
    fn test_shard_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.push(Constant::Array32([1; 32]));
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push account (constant index 0)
            OPCODE_SHARD_ROUTE,       // Route to shard
            OPCODE_PUSH, 0,           // Push message (constant index 0)
            OPCODE_SHARD_SEND,        // Send to shard
        ]);

        let mut vm = KapraVM::new(1000);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert_eq!(vm.stack.len(), 1); // Success flag from shard_send
        assert_eq!(vm.stack[0], 1); // shard_send returned true
    }

    #[test]
    fn test_invalid_shard_id() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.push(Constant::Array32([1; 32]));
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 1000,        // Invalid shard ID
            OPCODE_PUSH, 0,           // Message (constant index 0)
            OPCODE_SHARD_SEND,        // Send to shard
        ]);

        let mut vm = KapraVM::new(1000);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert_eq!(vm.stack[0], 0); // shard_send returned false due to invalid shard ID
    }

    #[test]
    fn test_shard_route_caching() {
        let mut shard_runtime = ShardRuntime::new(1000);
        let account = [1; 32];
        let shard_id1 = shard_runtime.shard_route(&account);
        let shard_id2 = shard_runtime.shard_route(&account);
        assert_eq!(shard_id1, shard_id2); // Should use cached value
        assert_eq!(shard_runtime.route_cache.len(), 1);
    }
}