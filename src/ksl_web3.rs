// ksl_web3.rs
// Web3-specific primitives for Kapra Chain

use crate::ksl_contract::{Contract, ContractState, ContractEvent};
use crate::ksl_stdlib_net::{Networking, HttpRequest, HttpResponse};
use crate::ksl_async::{AsyncContext, AsyncCommand};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Represents KSL bytecode with Web3 support (aligned with ksl_bytecode.rs).
#[derive(Debug, Clone)]
pub struct Bytecode {
    /// Bytecode instructions
    instructions: Vec<u8>,
    /// Constants pool
    constants: Vec<Constant>,
    /// Contract state
    contract_state: Option<ContractState>,
}

impl Bytecode {
    /// Creates new bytecode with instructions and constants.
    pub fn new(instructions: Vec<u8>, constants: Vec<Constant>) -> Self {
        Bytecode {
            instructions,
            constants,
            contract_state: None,
        }
    }

    /// Extends bytecode with additional instructions and constants.
    pub fn extend(&mut self, other: Bytecode) {
        self.instructions.extend(other.instructions);
        self.constants.extend(other.constants);
    }

    /// Sets the contract state for the bytecode.
    pub fn set_contract_state(&mut self, state: ContractState) {
        self.contract_state = Some(state);
    }
}

/// Represents a constant in the bytecode.
#[derive(Debug, Clone)]
pub enum Constant {
    /// String constant
    String(String),
    /// 32-byte array constant
    Array32([u8; 32]),
    /// Contract event constant
    ContractEvent(ContractEvent),
}

/// Represents an AST node with Web3 support (aligned with ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    /// DID block for decentralized identity
    DidBlock {
        /// Parameters (e.g., identity, credential)
        params: Vec<(String, Type)>,
        /// Return type (array<u8, 32])
        return_type: Type,
        /// Body of the DID block
        body: Vec<AstNode>,
    },
    /// Oracle block for off-chain data
    OracleBlock {
        /// Parameters (e.g., url)
        params: Vec<(String, Type)>,
        /// Return type (array<u8, 32])
        return_type: Type,
        /// Body of the oracle block
        body: Vec<AstNode>,
    },
    /// Cross-chain block for interoperability
    CrossChainBlock {
        /// Parameters (e.g., chain_id, message)
        params: Vec<(String, Type)>,
        /// Return type (bool)
        return_type: Type,
        /// Body of the cross-chain block
        body: Vec<AstNode>,
    },
    /// Contract block for smart contract functionality
    ContractBlock {
        /// Contract name
        name: String,
        /// Contract state
        state: ContractState,
        /// Contract events
        events: Vec<ContractEvent>,
        /// Contract methods
        methods: Vec<AstNode>,
    },
    /// Call expression
    Call {
        /// Function name
        name: String,
        /// Arguments
        args: Vec<AstNode>,
    },
    /// Variable declaration
    Let {
        /// Variable name
        name: String,
        /// Variable type
        ty: Type,
        /// Variable value
        value: Box<AstNode>,
    },
    /// String literal
    LiteralString(String),
    /// 32-byte array literal
    LiteralArray32([u8; 32]),
    /// 32-bit unsigned integer literal
    LiteralU32(u32),
    /// Contract event literal
    LiteralContractEvent(ContractEvent),
}

/// Represents a type with Web3 support (aligned with ksl_types.rs).
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    /// Boolean type
    Bool,
    /// 32-bit unsigned integer type
    U32,
    /// Fixed-size array of u8
    ArrayU8(usize),
    /// Contract type
    Contract(String),
    /// Event type
    Event(String),
}

/// Fixed-size array for cryptographic operations (aligned with ksl_kapra_crypto.rs).
#[derive(Debug, Clone)]
pub struct FixedArray<const N: usize> {
    /// Array data
    data: [u8; N],
}

impl<const N: usize> FixedArray<N> {
    /// Creates a new fixed-size array.
    pub fn new(data: [u8; N]) -> Self {
        FixedArray { data }
    }

    /// Returns the array as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

/// Web3 runtime for Kapra Chain with async support.
#[derive(Debug, Clone)]
pub struct Web3Runtime {
    /// Whether running in embedded mode
    is_embedded: bool,
    /// Async context for Web3 operations
    async_context: Arc<Mutex<AsyncContext>>,
    /// Networking module for Web3 operations
    networking: Networking,
}

impl Web3Runtime {
    /// Creates a new Web3 runtime.
    pub fn new(is_embedded: bool) -> Self {
        Web3Runtime {
            is_embedded,
            async_context: Arc::new(Mutex::new(AsyncContext::new())),
            networking: Networking::new(),
        }
    }

    /// Creates a decentralized identity asynchronously.
    pub async fn create_did(&self, identity: &FixedArray<32>, credential: &FixedArray<32>) -> Result<FixedArray<32>, KslError> {
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::CreateDid(identity.clone(), credential.clone());
        if let Err(e) = async_ctx.execute_command(command).await {
            return Err(KslError::web3_error(
                format!("Failed to create DID: {}", e),
                SourcePosition::new(1, 1),
            ));
        }

        let mut did = [0u8; 32];
        for i in 0..32 {
            did[i] = identity.as_slice()[i] ^ credential.as_slice()[i];
        }
        Ok(FixedArray::new(did))
    }

    /// Verifies a decentralized identity asynchronously.
    pub async fn verify_did(&self, did: &FixedArray<32>, credential: &FixedArray<32>) -> Result<bool, KslError> {
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::VerifyDid(did.clone(), credential.clone());
        if let Err(e) = async_ctx.execute_command(command).await {
            return Err(KslError::web3_error(
                format!("Failed to verify DID: {}", e),
                SourcePosition::new(1, 1),
            ));
        }

        let expected = credential.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        let did_sum = did.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        Ok(expected == did_sum)
    }

    /// Fetches off-chain data via an oracle asynchronously.
    pub async fn fetch_oracle_data(&self, url: &str) -> Result<FixedArray<32>, KslError> {
        let request = HttpRequest::new(url.to_string());
        let response = self.networking.http_get(request).await?;
        
        if response.status_code != 200 {
            return Err(KslError::web3_error(
                format!("Oracle request failed with status {}", response.status_code),
                SourcePosition::new(1, 1),
            ));
        }

        let mut data = [0u8; 32];
        let hash = response.body.iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
        for i in 0..32 {
            data[i] = (hash >> (i % 32)) as u8;
        }
        Ok(FixedArray::new(data))
    }

    /// Sends a cross-chain message asynchronously.
    pub async fn send_cross_chain(&self, chain_id: u32, message: &FixedArray<32>) -> Result<bool, KslError> {
        let mut async_ctx = self.async_context.lock().await;
        let command = AsyncCommand::SendCrossChain(chain_id, message.clone());
        if let Err(e) = async_ctx.execute_command(command).await {
            return Err(KslError::web3_error(
                format!("Failed to send cross-chain message: {}", e),
                SourcePosition::new(1, 1),
            ));
        }

        Ok(chain_id != u32::MAX)
    }
}

/// Kapra VM with Web3 and async support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    /// Execution stack
    stack: Vec<u64>,
    /// Web3 runtime
    web3_runtime: Web3Runtime,
    /// Async tasks
    async_tasks: Vec<AsyncTask>,
    /// Contract state
    contract_state: Option<ContractState>,
}

impl KapraVM {
    /// Creates a new Kapra VM with Web3 support.
    pub fn new(is_embedded: bool) -> Self {
        KapraVM {
            stack: vec![],
            web3_runtime: Web3Runtime::new(is_embedded),
            async_tasks: vec![],
            contract_state: None,
        }
    }

    /// Executes bytecode with Web3 support asynchronously.
    pub async fn execute(&mut self, bytecode: &Bytecode) -> Result<FixedArray<32>, KslError> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            match instr {
                OPCODE_CREATE_DID => {
                    if self.stack.len() < 2 {
                        return Err(KslError::web3_error(
                            "Not enough values on stack for CREATE_DID".to_string(),
                            SourcePosition::new(1, 1),
                        ));
                    }
                    let credential_idx = self.stack.pop().unwrap() as usize;
                    let identity_idx = self.stack.pop().unwrap() as usize;
                    let identity = match &bytecode.constants[identity_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err(KslError::web3_error(
                            "Invalid type for CREATE_DID identity".to_string(),
                            SourcePosition::new(1, 1),
                        )),
                    };
                    let credential = match &bytecode.constants[credential_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err(KslError::web3_error(
                            "Invalid type for CREATE_DID credential".to_string(),
                            SourcePosition::new(1, 1),
                        )),
                    };
                    let did = self.web3_runtime.create_did(&identity, &credential).await?;
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array32(did.data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_VERIFY_DID => {
                    if self.stack.len() < 2 {
                        return Err(KslError::web3_error(
                            "Not enough values on stack for VERIFY_DID".to_string(),
                            SourcePosition::new(1, 1),
                        ));
                    }
                    let credential_idx = self.stack.pop().unwrap() as usize;
                    let did_idx = self.stack.pop().unwrap() as usize;
                    let did = match &bytecode.constants[did_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err(KslError::web3_error(
                            "Invalid type for VERIFY_DID did".to_string(),
                            SourcePosition::new(1, 1),
                        )),
                    };
                    let credential = match &bytecode.constants[credential_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err(KslError::web3_error(
                            "Invalid type for VERIFY_DID credential".to_string(),
                            SourcePosition::new(1, 1),
                        )),
                    };
                    let valid = self.web3_runtime.verify_did(&did, &credential).await?;
                    self.stack.push(valid as u64);
                }
                OPCODE_FETCH_ORACLE => {
                    if self.stack.len() < 1 {
                        return Err(KslError::web3_error(
                            "Not enough values on stack for FETCH_ORACLE".to_string(),
                            SourcePosition::new(1, 1),
                        ));
                    }
                    let url_idx = self.stack.pop().unwrap() as usize;
                    let url = match &bytecode.constants[url_idx] {
                        Constant::String(s) => s,
                        _ => return Err(KslError::web3_error(
                            "Invalid type for FETCH_ORACLE url".to_string(),
                            SourcePosition::new(1, 1),
                        )),
                    };
                    let data = self.web3_runtime.fetch_oracle_data(url).await?;
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array32(data.data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_CROSS_CHAIN => {
                    if self.stack.len() < 2 {
                        return Err(KslError::web3_error(
                            "Not enough values on stack for CROSS_CHAIN".to_string(),
                            SourcePosition::new(1, 1),
                        ));
                    }
                    let message_idx = self.stack.pop().unwrap() as usize;
                    let chain_id = self.stack.pop().unwrap() as u32;
                    let message = match &bytecode.constants[message_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err(KslError::web3_error(
                            "Invalid type for CROSS_CHAIN message".to_string(),
                            SourcePosition::new(1, 1),
                        )),
                    };
                    let success = self.web3_runtime.send_cross_chain(chain_id, &message).await?;
                    self.async_tasks.push(AsyncTask::CrossChainSend(chain_id, message.data));
                    self.stack.push(success as u64);
                }
                _ => {
                    return Err(KslError::web3_error(
                        format!("Unknown opcode: {}", instr),
                        SourcePosition::new(1, 1),
                    ));
                }
            }
        }

        Ok(FixedArray::new([0u8; 32]))
    }
}

/// Async tasks for Web3 operations.
#[derive(Debug)]
pub enum AsyncTask {
    /// Cross-chain message sending task
    CrossChainSend(u32, [u8; 32]),
    /// Contract event emission task
    ContractEvent(ContractEvent),
}

/// Web3 compiler for generating bytecode (aligned with ksl_compiler.rs).
pub struct Web3Compiler {
    /// Whether running in embedded mode
    is_embedded: bool,
    /// Contract state for compilation
    contract_state: Option<ContractState>,
}

impl Web3Compiler {
    /// Creates a new Web3 compiler.
    pub fn new(is_embedded: bool) -> Self {
        Web3Compiler {
            is_embedded,
            contract_state: None,
        }
    }

    /// Sets the contract state for compilation.
    pub fn set_contract_state(&mut self, state: ContractState) {
        self.contract_state = Some(state);
    }

    /// Compiles an AST node to bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, KslError> {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        self.compile_node(node, &mut bytecode)?;
        if let Some(state) = &self.contract_state {
            bytecode.set_contract_state(state.clone());
        }
        Ok(bytecode)
    }

    /// Compiles a single AST node.
    fn compile_node(&self, node: &AstNode, bytecode: &mut Bytecode) -> Result<(), KslError> {
        match node {
            AstNode::DidBlock { params, body, .. } => {
                // Compile DID block
                for param in params {
                    bytecode.instructions.push(OPCODE_PUSH);
                    bytecode.constants.push(Constant::String(param.0.clone()));
                }
                for node in body {
                    self.compile_node(node, bytecode)?;
                }
                bytecode.instructions.push(OPCODE_CREATE_DID);
            }
            AstNode::OracleBlock { params, body, .. } => {
                // Compile oracle block
                for param in params {
                    bytecode.instructions.push(OPCODE_PUSH);
                    bytecode.constants.push(Constant::String(param.0.clone()));
                }
                for node in body {
                    self.compile_node(node, bytecode)?;
                }
                bytecode.instructions.push(OPCODE_FETCH_ORACLE);
            }
            AstNode::CrossChainBlock { params, body, .. } => {
                // Compile cross-chain block
                for param in params {
                    bytecode.instructions.push(OPCODE_PUSH);
                    bytecode.constants.push(Constant::String(param.0.clone()));
                }
                for node in body {
                    self.compile_node(node, bytecode)?;
                }
                bytecode.instructions.push(OPCODE_CROSS_CHAIN);
            }
            AstNode::ContractBlock { name, state, events, methods, .. } => {
                // Compile contract block
                bytecode.set_contract_state(state.clone());
                for event in events {
                    bytecode.constants.push(Constant::ContractEvent(event.clone()));
                }
                for method in methods {
                    self.compile_node(method, bytecode)?;
                }
            }
            _ => {
                return Err(KslError::web3_error(
                    format!("Unsupported node type: {:?}", node),
                    SourcePosition::new(1, 1),
                ));
            }
        }
        Ok(())
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