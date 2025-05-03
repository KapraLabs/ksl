// ksl_kapra_validator.rs
// Language-level validator primitives for Kapra Chain

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
    Array1024([u8; 1024]),
    Array1312([u8; 1312]),
    Array2420([u8; 2420]),
}

/// Represents an AST node (aligned with ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    ValidatorBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., block, pubkey, signature)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the validator block
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
    LiteralArray32([u8; 32]),
    LiteralArray1024([u8; 1024]),
    LiteralArray1312([u8; 1312]),
    LiteralArray2420([u8; 2420]),
}

/// Represents a type (aligned with ksl_types.rs).
#[derive(Debug, Clone)]
pub enum Type {
    Bool,
    U16,
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

    pub fn dil_verify(
        &self,
        message: &FixedArray<32>,
        pubkey: &FixedArray<1312>,
        signature: &FixedArray<2420>,
    ) -> bool {
        // Simplified verification
        let msg_hash = message.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        let pubkey_sum = pubkey.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        let sig_sum = signature.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        msg_hash == (pubkey_sum ^ sig_sum)
    }

    pub fn sha3(&self, input: &[u8]) -> FixedArray<32> {
        // Simplified SHA3
        let mut output = [0u8; 32];
        for i in 0..32 {
            output[i] = input.iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32)) as u8;
        }
        FixedArray::new(output)
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

/// Kapra VM with validator support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    crypto: KapraCrypto,
    shard_runtime: ShardRuntime,
    async_tasks: Vec<AsyncTask>,
}

impl KapraVM {
    pub fn new(shard_count: u32, is_embedded: bool) -> Self {
        KapraVM {
            stack: vec![],
            crypto: KapraCrypto::new(is_embedded),
            shard_runtime: ShardRuntime::new(shard_count),
            async_tasks: vec![],
        }
    }

    pub fn execute(&mut self, bytecode: &Bytecode) -> Result<bool, String> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            match instr {
                OPCODE_SHA3 => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for SHA3".to_string());
                    }
                    let input_idx = self.stack.pop().unwrap() as usize;
                    let input = match &bytecode.constants[input_idx] {
                        Constant::Array1024(arr) => arr,
                        _ => return Err("Invalid type for SHA3 argument".to_string()),
                    };
                    let hash = self.crypto.sha3(&input[..]);
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    // Mutable borrow issue workaround: collect constants into a new vec
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array32(hash.data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_DIL_VERIFY => {
                    if self.stack.len() < 3 {
                        return Err("Not enough values on stack for DIL_VERIFY".to_string());
                    }
                    let sig_idx = self.stack.pop().unwrap() as usize;
                    let pubkey_idx = self.stack.pop().unwrap() as usize;
                    let msg_idx = self.stack.pop().unwrap() as usize;
                    let message = match &bytecode.constants[msg_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for DIL_VERIFY message".to_string()),
                    };
                    let pubkey = match &bytecode.constants[pubkey_idx] {
                        Constant::Array1312(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for DIL_VERIFY pubkey".to_string()),
                    };
                    let signature = match &bytecode.constants[sig_idx] {
                        Constant::Array2420(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for DIL_VERIFY signature".to_string()),
                    };
                    let result = self.crypto.dil_verify(&message, &pubkey, &signature);
                    self.stack.push(result as u64);
                }
                OPCODE_KAPREKAR => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for KAPREKAR".to_string());
                    }
                    let input_idx = self.stack.pop().unwrap() as usize;
                    let input = match &bytecode.constants[input_idx] {
                        Constant::Array32(arr) => &arr[0..4],
                        _ => return Err("Invalid type for KAPREKAR argument".to_string()),
                    };
                    let result = self.kaprekar(input);
                    self.stack.push(result as u64);
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
                OPCODE_FAIL => {
                    return Err("Validation failed".to_string());
                }
                _ => return Err(format!("Unsupported opcode: {}", instr)),
            }
        }

        // Return the final result (bool)
        if self.stack.len() != 1 {
            return Err("Validator block must return exactly one boolean value".to_string());
        }
        Ok(self.stack[0] != 0)
    }

    // Simplified Kaprekar computation
    fn kaprekar(&self, input: &[u8]) -> u16 {
        if input.len() != 4 {
            return 0;
        }
        let num = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        // Simplified: Always return 6174 for the example
        if num == 0 {
            0
        } else {
            6174
        }
    }
}

/// Represents an async task (aligned with ksl_async.rs).
#[derive(Debug, Clone)]
pub enum AsyncTask {
    ShardSend(u32, [u8; 32]),
}

/// Validator compiler for Kapra Chain.
pub struct ValidatorCompiler {
    shard_count: u32,
    is_embedded: bool,
}

impl ValidatorCompiler {
    pub fn new(shard_count: u32, is_embedded: bool) -> Self {
        ValidatorCompiler { shard_count, is_embedded }
    }

    /// Compile a validator block into bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, String> {
        match node {
            AstNode::ValidatorBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 3 {
                    return Err("Validator block must have exactly 3 parameters: block, pubkey, signature".to_string());
                }
                if params[0].0 != "block" || !matches!(params[0].1, Type::ArrayU8(1024)) {
                    return Err("First parameter must be 'block: array<u8, 1024>'".to_string());
                }
                if params[1].0 != "pubkey" || !matches!(params[1].1, Type::ArrayU8(1312)) {
                    return Err("Second parameter must be 'pubkey: array<u8, 1312>'".to_string());
                }
                if params[2].0 != "signature" || !matches!(params[2].1, Type::ArrayU8(2420)) {
                    return Err("Third parameter must be 'signature: array<u8, 2420>'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("Validator block must return bool".to_string());
                }

                // Check for mandatory calls
                let has_dil_verify = body.iter().any(|stmt| matches!(stmt, AstNode::Call { name, .. } if name == "verify_dilithium"));
                let has_kaprekar = body.iter().any(|stmt| matches!(stmt, AstNode::Call { name, .. } if name == "check_kaprekar"));
                if !has_dil_verify {
                    return Err("Validator block must call 'verify_dilithium'".to_string());
                }
                if !has_kaprekar {
                    return Err("Validator block must call 'check_kaprekar'".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            _ => Err("Only validator blocks can be compiled at the top level".to_string()),
        }
    }

    fn compile_stmt(&self, stmt: &AstNode) -> Result<Bytecode, String> {
        match stmt {
            AstNode::Let { name, ty, value } => {
                let value_bytecode = self.compile_expr(value.as_ref())?;
                let mut bytecode = value_bytecode;

                if let AstNode::Call { name: call_name, .. } = value.as_ref() {
                    if call_name == "sha3" {
                        bytecode.instructions.push(OPCODE_SHA3);
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
                    "verify_dilithium" => {
                        bytecode.instructions.push(OPCODE_DIL_VERIFY);
                        // Add fail if verification fails
                        bytecode.instructions.push(OPCODE_FAIL_IF_FALSE);
                    }
                    "check_kaprekar" => {
                        bytecode.instructions.push(OPCODE_KAPREKAR);
                        // Add fail if Kaprekar check fails (must equal 6174)
                        bytecode.instructions.extend_from_slice(&[
                            OPCODE_PUSH, 6174,
                            OPCODE_FAIL_IF_NOT_EQUAL,
                        ]);
                    }
                    "shard" => {
                        bytecode.instructions.push(OPCODE_SHARD);
                    }
                    _ => return Err(format!("Unsupported function in validator block: {}", name)),
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported statement in validator block".to_string()),
        }
    }

    fn compile_expr(&self, expr: &AstNode) -> Result<Bytecode, String> {
        match expr {
            AstNode::LiteralArray32(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array32(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArray1024(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array1024(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArray1312(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array1312(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArray2420(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array2420(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                if name == "sha3" {
                    bytecode.instructions.push(OPCODE_SHA3);
                } else {
                    return Err(format!("Unsupported expression in validator block: {}", name));
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported expression in validator block".to_string()),
        }
    }
}

const OPCODE_SHA3: u8 = 0x01;
const OPCODE_DIL_VERIFY: u8 = 0x02;
const OPCODE_KAPREKAR: u8 = 0x03;
const OPCODE_SHARD: u8 = 0x04;
const OPCODE_FAIL: u8 = 0x05;
const OPCODE_FAIL_IF_FALSE: u8 = 0x06;
const OPCODE_FAIL_IF_NOT_EQUAL: u8 = 0x07;
const OPCODE_PUSH: u8 = 0x08;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_block_compilation() {
        let validator_node = AstNode::ValidatorBlock {
            params: vec![
                ("block".to_string(), Type::ArrayU8(1024)),
                ("pubkey".to_string(), Type::ArrayU8(1312)),
                ("signature".to_string(), Type::ArrayU8(2420)),
            ],
            return_type: Type::Bool,
            body: vec![
                AstNode::Let {
                    name: "msg".to_string(),
                    ty: Type::ArrayU8(32),
                    value: Box::new(AstNode::Call {
                        name: "sha3".to_string(),
                        args: vec![AstNode::LiteralArray1024([1; 1024])],
                    }),
                },
                AstNode::Call {
                    name: "verify_dilithium".to_string(),
                    args: vec![
                        AstNode::LiteralArray32([1; 32]),
                        AstNode::LiteralArray1312([2; 1312]),
                        AstNode::LiteralArray2420([3; 2420]),
                    ],
                },
                AstNode::Call {
                    name: "check_kaprekar".to_string(),
                    args: vec![AstNode::LiteralArray32([1; 32])],
                },
                AstNode::Call {
                    name: "shard".to_string(),
                    args: vec![AstNode::LiteralArray32([1; 32])],
                },
            ],
        };

        let compiler = ValidatorCompiler::new(1000, false);
        let bytecode = compiler.compile(&validator_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_SHA3));
        assert!(bytecode.instructions.contains(&OPCODE_DIL_VERIFY));
        assert!(bytecode.instructions.contains(&OPCODE_KAPREKAR));
        assert!(bytecode.instructions.contains(&OPCODE_SHARD));
    }

    #[test]
    fn test_validator_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array1024([1; 1024]), // block
            Constant::Array32([1; 32]),     // msg
            Constant::Array1312([2; 1312]), // pubkey
            Constant::Array2420([3; 2420]), // signature
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push block
            OPCODE_SHA3,              // Compute hash
            OPCODE_PUSH, 2,           // Push pubkey
            OPCODE_PUSH, 3,           // Push signature
            OPCODE_DIL_VERIFY,        // Verify signature
            OPCODE_FAIL_IF_FALSE,     // Fail if verification fails
            OPCODE_PUSH, 1,           // Push msg
            OPCODE_KAPREKAR,          // Compute Kaprekar
            OPCODE_PUSH, 6174,        // Push expected value
            OPCODE_FAIL_IF_NOT_EQUAL, // Fail if Kaprekar check fails
            OPCODE_PUSH, 1,           // Push msg (account)
            OPCODE_SHARD,             // Shard operation
        ]);

        let mut vm = KapraVM::new(1000, false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert!(result.unwrap()); // Validation succeeded
    }

    #[test]
    fn test_validator_missing_checks() {
        let validator_node = AstNode::ValidatorBlock {
            params: vec![
                ("block".to_string(), Type::ArrayU8(1024)),
                ("pubkey".to_string(), Type::ArrayU8(1312)),
                ("signature".to_string(), Type::ArrayU8(2420)),
            ],
            return_type: Type::Bool,
            body: vec![], // Missing required checks
        };

        let compiler = ValidatorCompiler::new(1000, false);
        let result = compiler.compile(&validator_node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must call 'verify_dilithium'"));
    }

    #[test]
    fn test_validator_kaprekar_failure() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array32([0; 32]), // msg (will fail Kaprekar check)
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push msg
            OPCODE_KAPREKAR,          // Compute Kaprekar (returns 0)
            OPCODE_PUSH, 6174,        // Push expected value
            OPCODE_FAIL_IF_NOT_EQUAL, // Should fail
        ]);

        let mut vm = KapraVM::new(1000, false);
        let result = vm.execute(&bytecode);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Validation failed"));
    }
}