// ksl_kapra_consensus.rs
// Language-level consensus primitives for Kapra Chain

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
    ConsensusBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., validator_id, seed)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the consensus block
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
    LiteralU64(u64),
    LiteralArray32([u8; 32]),
}

/// Represents a type (aligned with ksl_types.rs).
#[derive(Debug, Clone)]
pub enum Type {
    Bool,
    U64,
    ArrayU8(usize), // e.g., array<u8, 32>
}

/// Fixed-size array (aligned with ksl_kapra_crypto.rs).
#[derive(Debug, Clone)]
pub struct FixedArray<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> FixedArray<N> {
    pub fn new(data: [u8; N]) -> Self {
        FixedArray { data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

/// Crypto module (aligned with ksl_kapra_crypto.rs).
#[derive(Debug, Clone)]
pub struct KapraCrypto {
    is_embedded: bool,
}

impl KapraCrypto {
    pub fn new(is_embedded: bool) -> Self {
        KapraCrypto { is_embedded }
    }

    pub fn vrf_generate(&self, seed: &FixedArray<32>, key: &FixedArray<32>) -> FixedArray<32> {
        let mut output = [0u8; 32];
        if self.is_embedded {
            for i in 0..32 {
                output[i] = seed.as_slice()[i] ^ key.as_slice()[i];
            }
        } else {
            let seed_hash = self.simple_hash(seed.as_slice());
            let key_hash = self.simple_hash(key.as_slice());
            let combined = seed_hash.wrapping_add(key_hash);
            for i in 0..32 {
                output[i] = (combined >> (i % 32)) as u8;
            }
        }
        FixedArray::new(output)
    }

    fn simple_hash(&self, data: &[u8]) -> u32 {
        data.iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32))
    }
}

/// Sharding runtime (aligned with ksl_kapra_shard.rs).
#[derive(Debug, Clone)]
pub struct ShardRuntime {
    shard_count: u32,
}

impl ShardRuntime {
    pub fn new(shard_count: u32) -> Self {
        ShardRuntime { shard_count }
    }

    pub fn shard_route(&self, account: &[u8; 32]) -> u32 {
        let hash = account.iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        hash % self.shard_count
    }

    pub fn shard_send(&self, shard_id: u32, message: &[u8; 32]) -> bool {
        if shard_id >= self.shard_count {
            return false;
        }
        true
    }
}

/// Consensus runtime for Kapra Chain.
#[derive(Debug, Clone)]
pub struct ConsensusRuntime {
    threshold: u64, // Threshold for leader election (simplified)
}

impl ConsensusRuntime {
    pub fn new(threshold: u64) -> Self {
        ConsensusRuntime { threshold }
    }

    pub fn is_leader(&self, vrf_output: &[u8; 32]) -> bool {
        let value = vrf_output.iter().fold(0u64, |acc, &x| acc.wrapping_add(x as u64));
        value < self.threshold
    }

    pub fn propose_block(&self, shard_id: u32) -> bool {
        // Simplified: Always succeed if shard_id is valid
        shard_id != u32::MAX
    }
}

/// Kapra VM with consensus support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    crypto: KapraCrypto,
    shard_runtime: ShardRuntime,
    consensus_runtime: ConsensusRuntime,
    async_tasks: Vec<AsyncTask>,
}

impl KapraVM {
    pub fn new(shard_count: u32, threshold: u64, is_embedded: bool) -> Self {
        KapraVM {
            stack: vec![],
            crypto: KapraCrypto::new(is_embedded),
            shard_runtime: ShardRuntime::new(shard_count),
            consensus_runtime: ConsensusRuntime::new(threshold),
            async_tasks: vec![],
        }
    }

    pub fn execute(&mut self, bytecode: &Bytecode) -> Result<bool, String> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            match instr {
                OPCODE_VRF_GENERATE => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for VRF_GENERATE".to_string());
                    }
                    let key_idx = self.stack.pop().unwrap() as usize;
                    let seed_idx = self.stack.pop().unwrap() as usize;
                    let seed = match &bytecode.constants[seed_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for VRF_GENERATE seed".to_string()),
                    };
                    let key = match &bytecode.constants[key_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for VRF_GENERATE key".to_string()),
                    };
                    let vrf_output = self.crypto.vrf_generate(&seed, &key);
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array32(vrf_output.data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_LEADER_ELECT => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for LEADER_ELECT".to_string());
                    }
                    let vrf_idx = self.stack.pop().unwrap() as usize;
                    let vrf_output = match &bytecode.constants[vrf_idx] {
                        Constant::Array32(arr) => arr,
                        _ => return Err("Invalid type for LEADER_ELECT argument".to_string()),
                    };
                    let is_leader = self.consensus_runtime.is_leader(vrf_output);
                    self.stack.push(is_leader as u64);
                }
                OPCODE_PROPOSE_BLOCK => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for PROPOSE_BLOCK".to_string());
                    }
                    let shard_id = self.stack.pop().unwrap() as u32;
                    let success = self.consensus_runtime.propose_block(shard_id);
                    self.stack.push(success as u64);
                }
                OPCODE_SHARD => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for SHARD".to_string());
                    }
                    let account_idx = self.stack.pop().unwrap() as usize;
                    let account = match &bytecode.constants[account_idx] {
                        Constant::Array32(arr) => arr,
                        _ => return Err("Invalid type for SHARD argument".to_string()),
                    };
                    let shard_id = self.shard_runtime.shard_route(account);
                    let success = self.shard_runtime.shard_send(shard_id, account);
                    self.async_tasks.push(AsyncTask::ShardSend(shard_id, *account));
                    self.stack.push(shard_id as u64);
                    self.stack.push(success as u64);
                }
                OPCODE_PUSH => {
                    if ip >= bytecode.instructions.len() {
                        return Err("Incomplete PUSH instruction".to_string());
                    }
                    let value = bytecode.instructions[ip] as u64;
                    ip += 1;
                    self.stack.push(value);
                }
                OPCODE_FAIL => {
                    return Err("Consensus failed".to_string());
                }
                _ => return Err(format!("Unsupported opcode: {}", instr)),
            }
        }

        if self.stack.len() != 1 {
            return Err("Consensus block must return exactly one boolean value".to_string());
        }
        Ok(self.stack[0] != 0)
    }
}

/// Represents an async task (aligned with ksl_async.rs).
#[derive(Debug, Clone)]
pub enum AsyncTask {
    ShardSend(u32, [u8; 32]),
}

/// Consensus compiler for Kapra Chain.
pub struct ConsensusCompiler {
    shard_count: u32,
    threshold: u64,
    is_embedded: bool,
}

impl ConsensusCompiler {
    pub fn new(shard_count: u32, threshold: u64, is_embedded: bool) -> Self {
        ConsensusCompiler {
            shard_count,
            threshold,
            is_embedded,
        }
    }

    /// Compile a consensus block into bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, String> {
        match node {
            AstNode::ConsensusBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 2 {
                    return Err("Consensus block must have exactly 2 parameters: validator_id, seed".to_string());
                }
                if params[0].0 != "validator_id" || !matches!(params[0].1, Type::U64) {
                    return Err("First parameter must be 'validator_id: u64'".to_string());
                }
                if params[1].0 != "seed" || !matches!(params[1].1, Type::ArrayU8(32)) {
                    return Err("Second parameter must be 'seed: array<u8, 32>'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("Consensus block must return bool".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            _ => Err("Only consensus blocks can be compiled at the top level".to_string()),
        }
    }

    fn compile_stmt(&self, stmt: &AstNode) -> Result<Bytecode, String> {
        match stmt {
            AstNode::Let { name, ty, value } => {
                let value_bytecode = self.compile_expr(value.as_ref())?;
                let mut bytecode = value_bytecode;

                if let AstNode::Call { name: call_name, .. } = value.as_ref() {
                    if call_name == "vrf_generate" {
                        bytecode.instructions.push(OPCODE_VRF_GENERATE);
                    }
                }

                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                match name.as_str() {
                    "vrf_generate" => {
                        bytecode.instructions.push(OPCODE_VRF_GENERATE);
                    }
                    "elect_leader" => {
                        bytecode.instructions.push(OPCODE_LEADER_ELECT);
                        // Add fail if not elected (simplified)
                        bytecode.instructions.push(OPCODE_FAIL_IF_FALSE);
                    }
                    "propose_block" => {
                        bytecode.instructions.push(OPCODE_PROPOSE_BLOCK);
                    }
                    "shard" => {
                        bytecode.instructions.push(OPCODE_SHARD);
                    }
                    _ => return Err(format!("Unsupported function in consensus block: {}", name)),
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported statement in consensus block".to_string()),
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
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                if name == "vrf_generate" {
                    bytecode.instructions.push(OPCODE_VRF_GENERATE);
                } else {
                    return Err(format!("Unsupported expression in consensus block: {}", name));
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported expression in consensus block".to_string()),
        }
    }
}

const OPCODE_VRF_GENERATE: u8 = 0x01;
const OPCODE_LEADER_ELECT: u8 = 0x02;
const OPCODE_PROPOSE_BLOCK: u8 = 0x03;
const OPCODE_SHARD: u8 = 0x04;
const OPCODE_PUSH: u8 = 0x05;
const OPCODE_FAIL: u8 = 0x06;
const OPCODE_FAIL_IF_FALSE: u8 = 0x07;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_block_compilation() {
        let consensus_node = AstNode::ConsensusBlock {
            params: vec![
                ("validator_id".to_string(), Type::U64),
                ("seed".to_string(), Type::ArrayU8(32)),
            ],
            return_type: Type::Bool,
            body: vec![
                AstNode::Let {
                    name: "vrf_output".to_string(),
                    ty: Type::ArrayU8(32),
                    value: Box::new(AstNode::Call {
                        name: "vrf_generate".to_string(),
                        args: vec![
                            AstNode::LiteralArray32([1; 32]), // seed
                            AstNode::LiteralArray32([2; 32]), // key
                        ],
                    }),
                },
                AstNode::Call {
                    name: "elect_leader".to_string(),
                    args: vec![AstNode::LiteralArray32([1; 32])],
                },
                AstNode::Call {
                    name: "propose_block".to_string(),
                    args: vec![AstNode::LiteralU64(0)],
                },
                AstNode::Call {
                    name: "shard".to_string(),
                    args: vec![AstNode::LiteralArray32([1; 32])],
                },
            ],
        };

        let compiler = ConsensusCompiler::new(1000, 100, false);
        let bytecode = compiler.compile(&consensus_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_VRF_GENERATE));
        assert!(bytecode.instructions.contains(&OPCODE_LEADER_ELECT));
        assert!(bytecode.instructions.contains(&OPCODE_PROPOSE_BLOCK));
        assert!(bytecode.instructions.contains(&OPCODE_SHARD));
    }

    #[test]
    fn test_consensus_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array32([1; 32]), // seed
            Constant::Array32([2; 32]), // key
            Constant::Array32([3; 32]), // vrf_output
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push seed
            OPCODE_PUSH, 1,           // Push key
            OPCODE_VRF_GENERATE,      // Generate VRF
            OPCODE_LEADER_ELECT,      // Elect leader
            OPCODE_FAIL_IF_FALSE,     // Fail if not elected
            OPCODE_PUSH, 0,           // Push shard_id (simplified)
            OPCODE_PROPOSE_BLOCK,     // Propose block
            OPCODE_PUSH, 2,           // Push vrf_output (account)
            OPCODE_SHARD,             // Shard operation
        ]);

        let mut vm = KapraVM::new(1000, 1000, false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_consensus_not_leader() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array32([255; 32]), // seed
            Constant::Array32([255; 32]), // key
            Constant::Array32([255; 32]), // vrf_output (will exceed threshold)
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,
            OPCODE_PUSH, 1,
            OPCODE_VRF_GENERATE,
            OPCODE_LEADER_ELECT,
            OPCODE_FAIL_IF_FALSE,
        ]);

        let mut vm = KapraVM::new(1000, 100, false);
        let result = vm.execute(&bytecode);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Consensus failed"));
    }

    #[test]
    fn test_consensus_invalid_params() {
        let consensus_node = AstNode::ConsensusBlock {
            params: vec![("validator_id".to_string(), Type::U64)],
            return_type: Type::Bool,
            body: vec![],
        };

        let compiler = ConsensusCompiler::new(1000, 100, false);
        let result = compiler.compile(&consensus_node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must have exactly 2 parameters"));
    }
}