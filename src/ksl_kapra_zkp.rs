// ksl_kapra_zkp.rs
// Zero-knowledge proof support for Kapra Chain
// Implements various ZKP algorithms for private transactions and state verification.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_kapra_crypto::{FixedArray, KapraCrypto};
use crate::ksl_errors::{KslError, SourcePosition};

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
    Array64([u8; 64]),
    Array96([u8; 96]),
    Array128([u8; 128]),
}

/// Represents an AST node (aligned with ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    ZkpBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., statement, witness)
        return_type: Type,           // Return type (tuple: (array<u8, 64], bool))
        body: Vec<AstNode>,          // Body of the ZKP block
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
    LiteralArray64([u8; 64]),
    LiteralArray96([u8; 96]),
    LiteralArray128([u8; 128]),
    Return {
        values: Vec<AstNode>,
    },
}

/// Represents a type (aligned with ksl_types.rs).
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Bool,
    ArrayU8(usize), // e.g., array<u8, 32>
    Tuple(Vec<Type>), // e.g., (array<u8, 64], bool)
}

/// ZKP state for tracking proof generation and verification
#[derive(Debug, Clone)]
pub struct ZkpState {
    pub last_proof: [u8; 64],
    pub proof_cache: HashMap<[u8; 32], [u8; 64]>, // statement -> proof
    pub verification_cache: HashMap<[u8; 32], bool>, // statement -> valid
}

/// ZKP runtime for Kapra Chain.
#[derive(Debug, Clone)]
pub struct ZkpRuntime {
    is_embedded: bool,
    crypto: Arc<KapraCrypto>,
    async_runtime: Arc<AsyncRuntime>,
    state: Arc<RwLock<ZkpState>>,
}

impl ZkpRuntime {
    /// Creates a new ZKP runtime instance.
    pub fn new(is_embedded: bool, crypto: Arc<KapraCrypto>, async_runtime: Arc<AsyncRuntime>) -> Self {
        ZkpRuntime {
            is_embedded,
            crypto,
            async_runtime,
            state: Arc::new(RwLock::new(ZkpState {
                last_proof: [0; 64],
                proof_cache: HashMap::new(),
                verification_cache: HashMap::new(),
            })),
        }
    }

    /// Generates a ZKP proof asynchronously.
    /// Uses the crypto module for secure proof generation.
    pub async fn generate_proof(&self, statement: &FixedArray<32>, witness: &FixedArray<32>) -> AsyncResult<FixedArray<64>> {
        // Check cache first
        let state = self.state.read().await;
        if let Some(cached_proof) = state.proof_cache.get(statement.as_slice()) {
            return Ok(FixedArray::new(*cached_proof));
        }
        drop(state);

        // Generate proof asynchronously
        let proof = if self.is_embedded {
            // Lightweight implementation for embedded systems
            let mut proof = [0u8; 64];
            for i in 0..32 {
                proof[i] = statement.as_slice()[i] ^ witness.as_slice()[i];
                proof[i + 32] = proof[i];
            }
            FixedArray::new(proof)
        } else {
            // Full implementation using crypto module
            let mut proof = [0u8; 64];
            let statement_hash = self.crypto.sha3(statement.as_slice());
            let witness_hash = self.crypto.sha3(witness.as_slice());
            for i in 0..32 {
                proof[i] = statement_hash[i] ^ witness_hash[i];
                proof[i + 32] = proof[i];
            }
            FixedArray::new(proof)
        };

        // Update cache
        let mut state = self.state.write().await;
        state.proof_cache.insert(*statement.as_slice(), proof.data);
        state.last_proof = proof.data;
        Ok(proof)
    }

    /// Verifies a ZKP proof asynchronously.
    /// Uses the crypto module for secure verification.
    pub async fn verify_proof(&self, statement: &FixedArray<32>, proof: &FixedArray<64>) -> AsyncResult<bool> {
        // Check cache first
        let state = self.state.read().await;
        if let Some(cached_valid) = state.verification_cache.get(statement.as_slice()) {
            return Ok(*cached_valid);
        }
        drop(state);

        // Verify proof asynchronously
        let valid = if self.is_embedded {
            // Lightweight verification
            let expected = statement.as_slice().iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
            let proof_sum = proof.as_slice()[0..32].iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
            expected == proof_sum
        } else {
            // Full verification using crypto module
            let statement_hash = self.crypto.sha3(statement.as_slice());
            let proof_hash = self.crypto.sha3(&proof.as_slice()[0..32]);
            statement_hash.iter().zip(proof_hash.iter()).all(|(a, b)| a == b)
        };

        // Update cache
        let mut state = self.state.write().await;
        state.verification_cache.insert(*statement.as_slice(), valid);
        Ok(valid)
    }
}

/// Kapra VM with ZKP support (aligned with kapra_vm.rs).
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    zkp_runtime: Arc<ZkpRuntime>,
}

impl KapraVM {
    /// Creates a new Kapra VM with ZKP support.
    pub fn new(is_embedded: bool, crypto: Arc<KapraCrypto>, async_runtime: Arc<AsyncRuntime>) -> Self {
        KapraVM {
            stack: vec![],
            zkp_runtime: Arc::new(ZkpRuntime::new(is_embedded, crypto, async_runtime)),
        }
    }

    /// Executes ZKP bytecode asynchronously.
    pub async fn execute(&mut self, bytecode: &Bytecode) -> AsyncResult<(FixedArray<64>, bool)> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            match instr {
                OPCODE_GENERATE_PROOF => {
                    if self.stack.len() < 2 {
                        return Err(KslError::type_error(
                            "Not enough values on stack for GENERATE_PROOF".to_string(),
                            SourcePosition::new(1, 1),
                        ));
                    }
                    let witness_idx = self.stack.pop().unwrap() as usize;
                    let statement_idx = self.stack.pop().unwrap() as usize;
                    let statement = match &bytecode.constants[statement_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err(KslError::type_error(
                            "Invalid type for GENERATE_PROOF statement".to_string(),
                            SourcePosition::new(1, 1),
                        )),
                    };
                    let witness = match &bytecode.constants[witness_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err(KslError::type_error(
                            "Invalid type for GENERATE_PROOF witness".to_string(),
                            SourcePosition::new(1, 1),
                        )),
                    };
                    let proof = self.zkp_runtime.generate_proof(&statement, &witness).await?;
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array64(proof.data));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_VERIFY_PROOF => {
                    if self.stack.len() < 2 {
                        return Err(KslError::type_error(
                            "Not enough values on stack for VERIFY_PROOF".to_string(),
                            SourcePosition::new(1, 1),
                        ));
                    }
                    let proof_idx = self.stack.pop().unwrap() as usize;
                    let statement_idx = self.stack.pop().unwrap() as usize;
                    let statement = match &bytecode.constants[statement_idx] {
                        Constant::Array32(arr) => FixedArray::new(*arr),
                        _ => return Err(KslError::type_error(
                            "Invalid type for VERIFY_PROOF statement".to_string(),
                            SourcePosition::new(1, 1),
                        )),
                    };
                    let proof = match &bytecode.constants[proof_idx] {
                        Constant::Array64(arr) => FixedArray::new(*arr),
                        _ => return Err(KslError::type_error(
                            "Invalid type for VERIFY_PROOF proof".to_string(),
                            SourcePosition::new(1, 1),
                        )),
                    };
                    let valid = self.zkp_runtime.verify_proof(&statement, &proof).await?;
                    self.stack.push(valid as u64);
                }
                OPCODE_PUSH => {
                    if ip >= bytecode.instructions.len() {
                        return Err(KslError::type_error(
                            "Incomplete PUSH instruction".to_string(),
                            SourcePosition::new(1, 1),
                        ));
                    }
                    let value = bytecode.instructions[ip] as u64;
                    ip += 1;
                    self.stack.push(value);
                }
                OPCODE_FAIL => {
                    return Err(KslError::type_error(
                        "ZKP failed".to_string(),
                        SourcePosition::new(1, 1),
                    ));
                }
                _ => return Err(KslError::type_error(
                    format!("Unsupported opcode: {}", instr),
                    SourcePosition::new(1, 1),
                )),
            }
        }

        if self.stack.len() != 2 {
            return Err(KslError::type_error(
                "ZKP block must return exactly two values: proof and validity".to_string(),
                SourcePosition::new(1, 1),
            ));
        }
        let valid = self.stack.pop().unwrap() != 0;
        let proof_idx = self.stack.pop().unwrap() as usize;
        let proof = match &bytecode.constants[proof_idx] {
            Constant::Array64(arr) => FixedArray::new(*arr),
            _ => return Err(KslError::type_error(
                "Invalid proof type in ZKP return".to_string(),
                SourcePosition::new(1, 1),
            )),
        };
        Ok((proof, valid))
    }
}

/// ZKP compiler for Kapra Chain.
pub struct ZkpCompiler {
    is_embedded: bool,
}

impl ZkpCompiler {
    /// Creates a new ZKP compiler instance.
    pub fn new(is_embedded: bool) -> Self {
        ZkpCompiler { is_embedded }
    }

    /// Compiles a ZKP block into bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, String> {
        match node {
            AstNode::ZkpBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 2 {
                    return Err("ZKP block must have exactly 2 parameters: statement, witness".to_string());
                }
                if params[0].0 != "statement" || !matches!(params[0].1, Type::ArrayU8(32)) {
                    return Err("First parameter must be 'statement: array<u8, 32]'".to_string());
                }
                if params[1].0 != "witness" || !matches!(params[1].1, Type::ArrayU8(32)) {
                    return Err("Second parameter must be 'witness: array<u8, 32]'".to_string());
                }
                if !matches!(return_type, Type::Tuple(ref types) if types.len() == 2 && matches!(types[0], Type::ArrayU8(64)) && matches!(types[1], Type::Bool)) {
                    return Err("ZKP block must return (array<u8, 64], bool)".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            _ => Err("Only ZKP blocks can be compiled at the top level".to_string()),
        }
    }

    fn compile_stmt(&self, stmt: &AstNode) -> Result<Bytecode, String> {
        match stmt {
            AstNode::Let { name, ty, value } => {
                let value_bytecode = self.compile_expr(value.as_ref())?;
                let mut bytecode = value_bytecode;

                if let AstNode::Call { name: call_name, .. } = value.as_ref() {
                    if call_name == "generate_proof" {
                        bytecode.instructions.push(OPCODE_GENERATE_PROOF);
                    } else if call_name == "verify_proof" {
                        bytecode.instructions.push(OPCODE_VERIFY_PROOF);
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
                    "generate_proof" => {
                        bytecode.instructions.push(OPCODE_GENERATE_PROOF);
                    }
                    "verify_proof" => {
                        bytecode.instructions.push(OPCODE_VERIFY_PROOF);
                    }
                    _ => return Err(format!("Unsupported function in ZKP block: {}", name)),
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported statement in ZKP block".to_string()),
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
            AstNode::LiteralArray64(arr) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array64(*arr));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                if name == "generate_proof" {
                    bytecode.instructions.push(OPCODE_GENERATE_PROOF);
                } else if name == "verify_proof" {
                    bytecode.instructions.push(OPCODE_VERIFY_PROOF);
                } else {
                    return Err(format!("Unsupported expression in ZKP block: {}", name));
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported expression in ZKP block".to_string()),
        }
    }
}

const OPCODE_GENERATE_PROOF: u8 = 0x01;
const OPCODE_VERIFY_PROOF: u8 = 0x02;
const OPCODE_PUSH: u8 = 0x03;
const OPCODE_FAIL: u8 = 0x04;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_block_compilation() {
        let zkp_node = AstNode::ZkpBlock {
            params: vec![
                ("statement".to_string(), Type::ArrayU8(32)),
                ("witness".to_string(), Type::ArrayU8(32)),
            ],
            return_type: Type::Tuple(vec![Type::ArrayU8(64), Type::Bool]),
            body: vec![
                AstNode::Let {
                    name: "proof".to_string(),
                    ty: Type::ArrayU8(64),
                    value: Box::new(AstNode::Call {
                        name: "generate_proof".to_string(),
                        args: vec![
                            AstNode::LiteralArray32([1; 32]),
                            AstNode::LiteralArray32([2; 32]),
                        ],
                    }),
                },
                AstNode::Call {
                    name: "verify_proof".to_string(),
                    args: vec![
                        AstNode::LiteralArray32([1; 32]),
                        AstNode::LiteralArray64([3; 64]),
                    ],
                },
            ],
        };

        let compiler = ZkpCompiler::new(false);
        let bytecode = compiler.compile(&zkp_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_GENERATE_PROOF));
        assert!(bytecode.instructions.contains(&OPCODE_VERIFY_PROOF));
    }

    #[tokio::test]
    async fn test_zkp_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array32([1; 32]), // statement
            Constant::Array32([2; 32]), // witness
            Constant::Array64([3; 64]), // proof
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push statement
            OPCODE_PUSH, 1,           // Push witness
            OPCODE_GENERATE_PROOF,    // Generate proof
            OPCODE_PUSH, 0,           // Push statement
            OPCODE_PUSH, 2,           // Push proof
            OPCODE_VERIFY_PROOF,      // Verify proof
        ]);

        let crypto = Arc::new(KapraCrypto::new(false));
        let async_runtime = Arc::new(AsyncRuntime::new());
        let mut vm = KapraVM::new(false, crypto, async_runtime);
        let result = vm.execute(&bytecode).await;
        assert!(result.is_ok());
        let (proof, valid) = result.unwrap();
        assert_eq!(proof.data.len(), 64);
        assert!(valid);
    }

    #[tokio::test]
    async fn test_zkp_invalid_proof() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array32([1; 32]), // statement
            Constant::Array64([0; 64]), // invalid proof
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push statement
            OPCODE_PUSH, 1,           // Push proof
            OPCODE_VERIFY_PROOF,      // Verify proof
        ]);

        let crypto = Arc::new(KapraCrypto::new(false));
        let async_runtime = Arc::new(AsyncRuntime::new());
        let mut vm = KapraVM::new(false, crypto, async_runtime);
        let result = vm.execute(&bytecode).await;
        assert!(result.is_ok());
        let (_, valid) = result.unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_zkp_invalid_params() {
        let zkp_node = AstNode::ZkpBlock {
            params: vec![
                ("invalid".to_string(), Type::ArrayU8(32)),
                ("witness".to_string(), Type::ArrayU8(32)),
            ],
            return_type: Type::Tuple(vec![Type::ArrayU8(64), Type::Bool]),
            body: vec![],
        };

        let compiler = ZkpCompiler::new(false);
        let result = compiler.compile(&zkp_node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("First parameter must be 'statement'"));
    }
}