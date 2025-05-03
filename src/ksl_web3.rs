// ksl_web3.rs
// Web3-specific primitives for Kapra Chain

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
    Array32([u8; 32]),
}

/// Represents an AST node (aligned with ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    DidBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., identity, credential)
        return_type: Type,           // Return type (array<u8, 32])
        body: Vec<AstNode>,          // Body of the DID block
    },
    OracleBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., url)
        return_type: Type,           // Return type (array<u8, 32])
        body: Vec<AstNode>,          // Body of the oracle block
    },
    CrossChainBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., chain_id, message)
        return_type: Type,           // Return type (bool)
        body: Vec<AstNode>,          // Body of the cross-chain block
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
    LiteralString(String),
    LiteralArray32([u8; 32]),
    LiteralU32(u32),
}

/// Represents a type (aligned with ksl_types.rs).
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Bool,
    U32,
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

    pub fn sha3(&self, input: &[u8]) -> FixedArray<32> {
        let mut output = [0u8; 32];
        for i in 0..32 {
            output[i] = input.iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32)) as u8;
        }
        FixedArray::new(output)
    }
}

/// Web3 runtime for Kapra Chain.
#[derive(Debug, Clone)]
pub struct Web3Runtime {
    is_embedded: bool,
}

impl Web3Runtime {
    pub fn new(is_embedded: bool) -> Self {
        Web3Runtime { is_embedded }
    }

    /// Create a decentralized identity.
    pub fn create_did(&self, identity: &FixedArray<32>, credential: &FixedArray<32>) -> FixedArray<32> {
        let mut did = [0u8; 32];
        for i in 0..32 {
            did[i] = identity.as_slice()[i] ^ credential.as_slice()[i];
        }
        FixedArray::new(did)
    }

    /// Verify a decentralized identity.
    pub fn verify_did(&self, did: &FixedArray<32>, credential: &FixedArray<32>) -> bool {
        let expected = credential.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        let did_sum = did.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        expected == did_sum
    }

    /// Fetch off-chain data via an oracle (simplified for demo).
    pub fn fetch_oracle_data(&self, url: &str) -> FixedArray<32> {
        // Simulated oracle data (in reality, this would use http.get from ksl_stdlib_net.rs)
        let mut data = [0u8; 32];
        let hash = url.as_bytes().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        for i in 0..32 {
            data[i] = (hash >> (i % 32)) as u8;
        }
        FixedArray::new(data)
    }

    /// Send a cross-chain message (simplified for demo).
    pub fn send_cross_chain(&self, chain_id: u32, message: &FixedArray<32>) -> bool {
        // Simulated cross-chain messaging (in reality, this would use net.udp_send from ksl_stdlib_net.rs)
        chain_id != u32::MAX
    }
}

/// Kapra VM with Web3 support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    crypto: KapraCrypto,
    web3_runtime: Web3Runtime,
    async_tasks: Vec<AsyncTask>,
}

impl KapraVM {
    pub fn new(is_embedded: bool) -> Self {
        KapraVM {
            stack: vec![],
            crypto: KapraCrypto::new(is_embedded),
            web3_runtime: Web3Runtime::new(is_embedded),
            async_tasks: vec![],
        }
    }

    pub fn execute(&mut self, bytecode: &Bytecode) -> Result<FixedArray<32>, String> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            match instr {
                OPCODE_CREATE_DID => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for CREATE_DID".to_string());
                    }
                    let credential_idx = self.stack.pop().unwrap() as usize;
                    let identity_idx = self.stack.pop().unwrap() as usize;
                    let identity = match &bytecode.constants[identity_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for CREATE_DID identity".to_string()),
                    };
                    let credential = match &bytecode.constants[credential_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for CREATE_DID credential".to_string()),
                    };
                    let did = self.web3_runtime.create_did(&identity, &credential);
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array32(did.data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_VERIFY_DID => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for VERIFY_DID".to_string());
                    }
                    let credential_idx = self.stack.pop().unwrap() as usize;
                    let did_idx = self.stack.pop().unwrap() as usize;
                    let did = match &bytecode.constants[did_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for VERIFY_DID did".to_string()),
                    };
                    let credential = match &bytecode.constants[credential_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for VERIFY_DID credential".to_string()),
                    };
                    let valid = self.web3_runtime.verify_did(&did, &credential);
                    self.stack.push(valid as u64);
                }
                OPCODE_FETCH_ORACLE => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for FETCH_ORACLE".to_string());
                    }
                    let url_idx = self.stack.pop().unwrap() as usize;
                    let url = match &bytecode.constants[url_idx] {
                        Constant::String(s) => s,
                        _ => return Err("Invalid type for FETCH_ORACLE url".to_string()),
                    };
                    let data = self.web3_runtime.fetch_oracle_data(url);
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array32(data.data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_CROSS_CHAIN => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for CROSS_CHAIN".to_string());
                    }
                    let message_idx = self.stack.pop().unwrap() as usize;
                    let chain_id = self.stack.pop().unwrap() as u32;
                    let message = match &bytecode.constants[message_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err("Invalid type for CROSS_CHAIN message".to_string()),
                    };
                    let success = self.web3_runtime.send_cross_chain(chain_id, &message);
                    self.async_tasks.push(AsyncTask::CrossChainSend(chain_id, message.data));
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
                    return Err("Web3 operation failed".to_string());
                }
                _ => return Err(format!("Unsupported opcode: {}", instr)),
            }
        }

        if self.stack.len() != 1 {
            return Err("Web3 block must return exactly one value".to_string());
        }
        let result_idx = self.stack.pop().unwrap() as usize;
        match &bytecode.constants[result_idx] {
            Constant::Array32(arr) => Ok(FixedArray::new(*arr)),
            _ => Err("Invalid return type for Web3 block".to_string()),
        }
    }
}

/// Represents an async task (aligned with ksl_async.rs).
#[derive(Debug, Clone)]
pub enum AsyncTask {
    CrossChainSend(u32, [u8; 32]),
}

/// Web3 compiler for Kapra Chain.
pub struct Web3Compiler {
    is_embedded: bool,
}

impl Web3Compiler {
    pub fn new(is_embedded: bool) -> Self {
        Web3Compiler { is_embedded }
    }

    /// Compile a Web3 block into bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, String> {
        match node {
            AstNode::DidBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 2 {
                    return Err("DID block must have exactly 2 parameters: identity, credential".to_string());
                }
                if params[0].0 != "identity" || !matches!(params[0].1, Type::ArrayU8(32)) {
                    return Err("First parameter must be 'identity: array<u8, 32]'".to_string());
                }
                if params[1].0 != "credential" || !matches!(params[1].1, Type::ArrayU8(32)) {
                    return Err("Second parameter must be 'credential: array<u8, 32]'".to_string());
                }
                if !matches!(return_type, Type::ArrayU8(32)) {
                    return Err("DID block must return array<u8, 32]".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            AstNode::OracleBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 1 {
                    return Err("Oracle block must have exactly 1 parameter: url".to_string());
                }
                if params[0].0 != "url" || !matches!(params[0].1, Type::ArrayU8(_)) {
                    return Err("Parameter must be 'url: array<u8, N>'".to_string());
                }
                if !matches!(return_type, Type::ArrayU8(32)) {
                    return Err("Oracle block must return array<u8, 32]".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            AstNode::CrossChainBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 2 {
                    return Err("CrossChain block must have exactly 2 parameters: chain_id, message".to_string());
                }
                if params[0].0 != "chain_id" || !matches!(params[0].1, Type::U32) {
                    return Err("First parameter must be 'chain_id: u32'".to_string());
                }
                if params[1].0 != "message" || !matches!(params[1].1, Type::ArrayU8(32)) {
                    return Err("Second parameter must be 'message: array<u8, 32]'".to_string());
                }
                if !matches!(return_type, Type::Bool) {
                    return Err("CrossChain block must return bool".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            _ => Err("Only Web3 blocks can be compiled at the top level".to_string()),
        }
    }

    fn compile_stmt(&self, stmt: &AstNode) -> Result<Bytecode, String> {
        match stmt {
            AstNode::Let { name, ty, value } => {
                let value_bytecode = self.compile_expr(value.as_ref())?;
                let mut bytecode = value_bytecode;

                if let AstNode::Call { name: call_name, .. } = value.as_ref() {
                    if call_name == "create_did" {
                        bytecode.instructions.push(OPCODE_CREATE_DID);
                    } else if call_name == "verify_did" {
                        bytecode.instructions.push(OPCODE_VERIFY_DID);
                    } else if call_name == "fetch_oracle_data" {
                        bytecode.instructions.push(OPCODE_FETCH_ORACLE);
                    } else if call_name == "send_cross_chain" {
                        bytecode.instructions.push(OPCODE_CROSS_CHAIN);
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
                    "create_did" => {
                        bytecode.instructions.push(OPCODE_CREATE_DID);
                    }
                    "verify_did" => {
                        bytecode.instructions.push(OPCODE_VERIFY_DID);
                        bytecode.instructions.push(OPCODE_FAIL_IF_FALSE);
                    }
                    "fetch_oracle_data" => {
                        bytecode.instructions.push(OPCODE_FETCH_ORACLE);
                    }
                    "send_cross_chain" => {
                        bytecode.instructions.push(OPCODE_CROSS_CHAIN);
                    }
                    _ => return Err(format!("Unsupported function in Web3 block: {}", name)),
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported statement in Web3 block".to_string()),
        }
    }

    fn compile_expr(&self, expr: &AstNode) -> Result<Bytecode, String> {
        match expr {
            AstNode::LiteralString(s) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::String(s.clone()));
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
            AstNode::LiteralU32(val) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, *val as u8]);
                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                if name == "create_did" {
                    bytecode.instructions.push(OPCODE_CREATE_DID);
                } else if name == "verify_did" {
                    bytecode.instructions.push(OPCODE_VERIFY_DID);
                } else if name == "fetch_oracle_data" {
                    bytecode.instructions.push(OPCODE_FETCH_ORACLE);
                } else if name == "send_cross_chain" {
                    bytecode.instructions.push(OPCODE_CROSS_CHAIN);
                } else {
                    return Err(format!("Unsupported expression in Web3 block: {}", name));
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported expression in Web3 block".to_string()),
        }
    }
}

const OPCODE_CREATE_DID: u8 = 0x01;
const OPCODE_VERIFY_DID: u8 = 0x02;
const OPCODE_FETCH_ORACLE: u8 = 0x03;
const OPCODE_CROSS_CHAIN: u8 = 0x04;
const OPCODE_PUSH: u8 = 0x05;
const OPCODE_FAIL: u8 = 0x06;
const OPCODE_FAIL_IF_FALSE: u8 = 0x07;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_block_compilation() {
        let did_node = AstNode::DidBlock {
            params: vec![
                ("identity".to_string(), Type::ArrayU8(32)),
                ("credential".to_string(), Type::ArrayU8(32)),
            ],
            return_type: Type::ArrayU8(32),
            body: vec![
                AstNode::Let {
                    name: "did".to_string(),
                    ty: Type::ArrayU8(32),
                    value: Box::new(AstNode::Call {
                        name: "create_did".to_string(),
                        args: vec![
                            AstNode::LiteralArray32([1; 32]),
                            AstNode::LiteralArray32([2; 32]),
                        ],
                    }),
                },
                AstNode::Call {
                    name: "verify_did".to_string(),
                    args: vec![
                        AstNode::LiteralArray32([3; 32]),
                        AstNode::LiteralArray32([2; 32]),
                    ],
                },
            ],
        };

        let compiler = Web3Compiler::new(false);
        let bytecode = compiler.compile(&did_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_CREATE_DID));
        assert!(bytecode.instructions.contains(&OPCODE_VERIFY_DID));
    }

    #[test]
    fn test_oracle_block_compilation() {
        let oracle_node = AstNode::OracleBlock {
            params: vec![("url".to_string(), Type::ArrayU8(32))],
            return_type: Type::ArrayU8(32),
            body: vec![
                AstNode::Let {
                    name: "data".to_string(),
                    ty: Type::ArrayU8(32),
                    value: Box::new(AstNode::Call {
                        name: "fetch_oracle_data".to_string(),
                        args: vec![AstNode::LiteralString("https://price-feed".to_string())],
                    }),
                },
            ],
        };

        let compiler = Web3Compiler::new(false);
        let bytecode = compiler.compile(&oracle_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_FETCH_ORACLE));
    }

    #[test]
    fn test_cross_chain_block_compilation() {
        let cross_chain_node = AstNode::CrossChainBlock {
            params: vec![
                ("chain_id".to_string(), Type::U32),
                ("message".to_string(), Type::ArrayU8(32)),
            ],
            return_type: Type::Bool,
            body: vec![
                AstNode::Call {
                    name: "send_cross_chain".to_string(),
                    args: vec![
                        AstNode::LiteralU32(1),
                        AstNode::LiteralArray32([1; 32]),
                    ],
                },
            ],
        };

        let compiler = Web3Compiler::new(false);
        let bytecode = compiler.compile(&cross_chain_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_CROSS_CHAIN));
    }

    #[test]
    fn test_did_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array32([1; 32]), // identity
            Constant::Array32([2; 32]), // credential
            Constant::Array32([3; 32]), // did
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push identity
            OPCODE_PUSH, 1,           // Push credential
            OPCODE_CREATE_DID,        // Create DID
            OPCODE_PUSH, 1,           // Push credential
            OPCODE_VERIFY_DID,        // Verify DID
            OPCODE_FAIL_IF_FALSE,     // Fail if verification fails
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        let did = result.unwrap();
        assert_eq!(did.as_slice()[0], 1 ^ 2); // Simplified DID check
    }

    #[test]
    fn test_oracle_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::String("https://price-feed".to_string()),
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push url
            OPCODE_FETCH_ORACLE,      // Fetch oracle data
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.as_slice().len(), 32);
    }

    #[test]
    fn test_cross_chain_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array32([1; 32]), // message
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 1,           // Push chain_id
            OPCODE_PUSH, 0,           // Push message
            OPCODE_CROSS_CHAIN,       // Send cross-chain message
        ]);

        let mut vm = KapraVM::new(false);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        assert_eq!(vm.async_tasks.len(), 1);
    }

    #[test]
    fn test_invalid_did_params() {
        let did_node = AstNode::DidBlock {
            params: vec![("identity".to_string(), Type::ArrayU8(32))],
            return_type: Type::ArrayU8(32),
            body: vec![],
        };

        let compiler = Web3Compiler::new(false);
        let result = compiler.compile(&did_node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must have exactly 2 parameters"));
    }
}