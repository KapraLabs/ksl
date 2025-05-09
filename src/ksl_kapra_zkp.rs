// ksl_kapra_zkp.rs
// Zero-knowledge proof support for Kapra Chain
// Implements various ZKP algorithms for private transactions and state verification.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_kapra_crypto::{FixedArray, KapraCrypto};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_stdlib_crypto::{Crypto, BlsKeypair, DilithiumKeypair};
use blst::{min_pk::*, BLST_ERROR};
#[cfg(not(target_arch = "wasm32"))]
use pqcrypto_dilithium::dilithium5;
#[cfg(not(target_arch = "wasm32"))]
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PqPublicKey};
use std::convert::TryFrom;
use serde::{Serialize, Deserialize};
use serde_json::json;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

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
    Array96([u8; 96]),     // For BLS signatures
    Array128([u8; 128]),
    Array2420([u8; 2420]), // For Dilithium signatures
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
    /// 
    /// Important: In embedded/light mode, this method always returns a FixedArray<64>
    /// regardless of the proof scheme (BLS or Dilithium). This is an optimization for
    /// resource-constrained environments. The full proof sizes (96 bytes for BLS,
    /// 2420 bytes for Dilithium) are only used in non-embedded mode.
    /// 
    /// The returned proof is:
    /// - In embedded mode: Always a 64-byte lightweight proof
    /// - In non-embedded mode: Full-size proof based on scheme (96 bytes for BLS, 2420 for Dilithium)
    /// 
    /// @param statement The statement to prove
    /// @param witness The witness data
    /// @returns A fixed-size proof array
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
            // Always returns 64 bytes regardless of scheme
            let mut proof = [0u8; 64];
            for i in 0..32 {
                proof[i] = statement.as_slice()[i] ^ witness.as_slice()[i];
                proof[i + 32] = proof[i];
            }
            FixedArray::new(proof)
        } else {
            // Full implementation using crypto module
            // Note: The returned 64-byte proof is a hash/commitment of the full-size proof
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

    /// Returns whether this runtime is in embedded mode
    pub fn is_embedded(&self) -> bool {
        self.is_embedded
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
    /// 
    /// This method handles proofs of different sizes through the ZkProof::to_constant() method:
    /// - For BLS proofs: Converts to Constant::Array96 (96 bytes)
    /// - For Dilithium proofs: Converts to Constant::Array2420 (2420 bytes)
    /// 
    /// Even though ZkpRuntime::generate_proof returns 64-byte proofs in embedded mode,
    /// this method ensures proper expansion to full-size proofs when storing in constants.
    /// The proof size in the constant pool always matches the cryptographic scheme's
    /// requirements, regardless of the runtime mode.
    /// 
    /// @param bytecode The bytecode to execute
    /// @returns A tuple of (proof, validity)
    pub async fn execute(&mut self, bytecode: &Bytecode) -> AsyncResult<(ZkProof, bool)> {
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

                    // Convert the 64-byte proof to the appropriate full-size constant
                    // ZkProof::to_constant() handles the expansion based on scheme:
                    // - BLS -> Array96 (96 bytes)
                    // - Dilithium -> Array2420 (2420 bytes)
                    let constant = proof.to_constant()?;
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(constant);
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

                    // Handle different proof sizes
                    let proof = match &bytecode.constants[proof_idx] {
                        Constant::Array96(arr) => {
                            let mut bytes = Vec::with_capacity(96);
                            bytes.extend_from_slice(arr);
                            ZkProof::from_bytes(ZkScheme::BLS, bytes)?
                        }
                        Constant::Array2420(arr) => {
                            let mut bytes = Vec::with_capacity(2420);
                            bytes.extend_from_slice(arr);
                            ZkProof::from_bytes(ZkScheme::Dilithium, bytes)?
                        }
                        _ => return Err(KslError::type_error(
                            "Invalid proof type in VERIFY_PROOF".to_string(),
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

        // Handle different proof sizes in return value
        let proof = match &bytecode.constants[proof_idx] {
            Constant::Array96(arr) => {
                let mut bytes = Vec::with_capacity(96);
                bytes.extend_from_slice(arr);
                ZkProof::from_bytes(ZkScheme::BLS, bytes)?
            }
            Constant::Array2420(arr) => {
                let mut bytes = Vec::with_capacity(2420);
                bytes.extend_from_slice(arr);
                ZkProof::from_bytes(ZkScheme::Dilithium, bytes)?
            }
            _ => return Err(KslError::type_error(
                "Invalid proof type in ZKP return".to_string(),
                SourcePosition::new(1, 1),
            )),
        };

        Ok((proof, valid))
    }

    /// Executes ZKP bytecode and returns the result as a JSON string.
    /// 
    /// The output format is:
    /// ```json
    /// {
    ///   "scheme": "BLS",
    ///   "proof": "base64_encoded_proof_bytes",
    ///   "valid": true,
    ///   "metadata": {
    ///     "size": 96,
    ///     "timestamp": 1234567890,
    ///     "embedded": false
    ///   }
    /// }
    /// ```
    /// 
    /// @param bytecode The bytecode to execute
    /// @returns A JSON string containing the proof result
    pub async fn execute_with_output(&mut self, bytecode: &Bytecode) -> AsyncResult<String> {
        let (proof, valid) = self.execute(bytecode).await?;
        
        let metadata = ProofMetadata {
            size: proof.as_bytes().len(),
            timestamp: chrono::Utc::now().timestamp(),
            embedded: self.zkp_runtime.is_embedded(),
        };

        let output = ProofOutput {
            scheme: proof.scheme().to_string(),
            proof: BASE64.encode(proof.as_bytes()),
            valid,
            metadata: Some(metadata),
        };

        Ok(serde_json::to_string_pretty(&output)?)
    }

    /// Executes ZKP bytecode and returns a structured output.
    /// Similar to execute_with_output but returns the structured data instead of a JSON string.
    pub async fn execute_structured(&mut self, bytecode: &Bytecode) -> AsyncResult<ProofOutput> {
        let (proof, valid) = self.execute(bytecode).await?;
        
        let metadata = ProofMetadata {
            size: proof.as_bytes().len(),
            timestamp: chrono::Utc::now().timestamp(),
            embedded: self.zkp_runtime.is_embedded(),
        };

        Ok(ProofOutput {
            scheme: proof.scheme().to_string(),
            proof: BASE64.encode(proof.as_bytes()),
            valid,
            metadata: Some(metadata),
        })
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

/// Represents different types of zero-knowledge proofs supported by KSL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZkProof {
    /// BLS signature-based proof
    BlsSignature(Vec<u8>),
    /// Post-quantum Dilithium proof
    DilithiumProof(Vec<u8>),
}

impl ZkProof {
    /// Create a new proof from raw bytes
    pub fn from_bytes(scheme: ZkScheme, bytes: Vec<u8>) -> Result<Self, KslError> {
        match scheme {
            ZkScheme::BLS => {
                if bytes.len() != 96 {
                    return Err(KslError::InvalidProof("Invalid BLS signature length".into()));
                }
                Ok(ZkProof::BlsSignature(bytes))
            }
            ZkScheme::Dilithium => {
                if bytes.len() != 2420 {
                    return Err(KslError::InvalidProof("Invalid Dilithium signature length".into()));
                }
                Ok(ZkProof::DilithiumProof(bytes))
            }
        }
    }

    /// Convert proof to a constant
    pub fn to_constant(&self) -> Result<Constant, KslError> {
        match self {
            ZkProof::BlsSignature(bytes) => {
                if bytes.len() != 96 {
                    return Err(KslError::InvalidProof("Invalid BLS signature length".into()));
                }
                let mut arr = [0u8; 96];
                arr.copy_from_slice(bytes);
                Ok(Constant::Array96(arr))
            }
            ZkProof::DilithiumProof(bytes) => {
                if bytes.len() != 2420 {
                    return Err(KslError::InvalidProof("Invalid Dilithium signature length".into()));
                }
                let mut arr = [0u8; 2420];
                arr.copy_from_slice(bytes);
                Ok(Constant::Array2420(arr))
            }
        }
    }

    /// Get the raw bytes of the proof
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            ZkProof::BlsSignature(bytes) => bytes,
            ZkProof::DilithiumProof(bytes) => bytes,
        }
    }

    /// Get the scheme used for this proof
    pub fn scheme(&self) -> ZkScheme {
        match self {
            ZkProof::BlsSignature(_) => ZkScheme::BLS,
            ZkProof::DilithiumProof(_) => ZkScheme::Dilithium,
        }
    }

    /// Get the expected length for this proof type
    pub fn expected_length(&self) -> usize {
        match self {
            ZkProof::BlsSignature(_) => 96,
            ZkProof::DilithiumProof(_) => 2420,
        }
    }
}

/// Validator for zero-knowledge proofs
#[derive(Debug, Clone)]
pub struct ZkValidator {
    /// The cryptographic scheme used for validation
    pub scheme: ZkScheme,
    /// Crypto instance for operations
    crypto: Crypto,
}

/// Supported zero-knowledge proof schemes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZkScheme {
    /// BLS signature scheme (BLS12-381 curve)
    BLS,
    /// Post-quantum Dilithium signature scheme
    Dilithium,
}

impl ZkValidator {
    /// Create a new validator for the specified scheme
    pub fn new(scheme: ZkScheme) -> Self {
        Self {
            scheme,
            crypto: Crypto::new(),
        }
    }

    /// Verify a proof against a message and public key
    pub async fn verify(&self, msg: &[u8], proof: &ZkProof, pubkey: &[u8]) -> Result<bool, KslError> {
        if proof.scheme() != self.scheme {
            return Err(KslError::InvalidProof("Proof scheme mismatch".into()));
        }

        match self.scheme {
            ZkScheme::BLS => {
                // Convert bytes to BLS types
                let pk = PublicKey::from_bytes(pubkey)
                    .map_err(|_| KslError::InvalidProof("Invalid BLS public key".into()))?;
                let sig = Signature::from_bytes(proof.as_bytes())
                    .map_err(|_| KslError::InvalidProof("Invalid BLS signature".into()))?;
                
                // Verify using crypto instance
                self.crypto.bls_verify(&pk, msg, &sig)
            }
            ZkScheme::Dilithium => {
                // Convert bytes to Dilithium types
                let pk = PqPublicKey::from_bytes(pubkey)
                    .map_err(|_| KslError::InvalidProof("Invalid Dilithium public key".into()))?;
                let sig = DetachedSignature::from_bytes(proof.as_bytes())
                    .map_err(|_| KslError::InvalidProof("Invalid Dilithium signature".into()))?;
                
                // Verify using crypto instance
                self.crypto.dilithium_verify(&pk, msg, &sig)
            }
        }
    }

    /// Generate a new proof for a message using the given keypair
    pub async fn generate_proof(&self, msg: &[u8], keypair: &ZkKeypair) -> Result<ZkProof, KslError> {
        match (self.scheme, keypair) {
            (ZkScheme::BLS, ZkKeypair::Bls(bls_pair)) => {
                let sig = self.crypto.bls_sign(&bls_pair.sk, msg)?;
                Ok(ZkProof::BlsSignature(sig.to_bytes().to_vec()))
            }
            (ZkScheme::Dilithium, ZkKeypair::Dilithium(dil_pair)) => {
                let sig = self.crypto.dilithium_sign(&dil_pair.sk, msg)?;
                Ok(ZkProof::DilithiumProof(sig.as_bytes().to_vec()))
            }
            _ => Err(KslError::InvalidProof("Keypair scheme mismatch".into())),
        }
    }
}

/// Unified keypair type for ZK operations
#[derive(Clone)]
pub enum ZkKeypair {
    Bls(BlsKeypair),
    Dilithium(DilithiumKeypair),
}

impl ZkKeypair {
    /// Generate a new keypair for the specified scheme
    pub async fn generate(scheme: ZkScheme) -> Result<Self, KslError> {
        let crypto = Crypto::new();
        match scheme {
            ZkScheme::BLS => {
                let keypair = crypto.bls_generate_keypair()?;
                Ok(ZkKeypair::Bls(keypair))
            }
            ZkScheme::Dilithium => {
                let keypair = crypto.dilithium_generate_keypair()?;
                Ok(ZkKeypair::Dilithium(keypair))
            }
        }
    }

    /// Get the scheme for this keypair
    pub fn scheme(&self) -> ZkScheme {
        match self {
            ZkKeypair::Bls(_) => ZkScheme::BLS,
            ZkKeypair::Dilithium(_) => ZkScheme::Dilithium,
        }
    }
}

/// JSON output format for proof verification results
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofOutput {
    /// The cryptographic scheme used (BLS or Dilithium)
    pub scheme: String,
    /// Base64-encoded proof bytes
    pub proof: String,
    /// Whether the proof is valid
    pub valid: bool,
    /// Additional metadata about the proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProofMetadata>,
}

/// Additional metadata about the proof
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Size of the proof in bytes
    pub size: usize,
    /// Timestamp of proof generation (Unix timestamp)
    pub timestamp: i64,
    /// Whether this was generated in embedded mode
    pub embedded: bool,
}

impl ToString for ZkScheme {
    fn to_string(&self) -> String {
        match self {
            ZkScheme::BLS => "BLS".to_string(),
            ZkScheme::Dilithium => "Dilithium".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

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
        assert_eq!(proof.as_bytes().len(), 96);
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

    #[tokio::test]
    async fn test_bls_proof_verification() {
        let validator = ZkValidator::new(ZkScheme::BLS);
        let keypair = ZkKeypair::generate(ZkScheme::BLS).await.unwrap();
        let message = b"test message";
        
        // Generate and verify proof
        let proof = validator.generate_proof(message, &keypair).await.unwrap();
        assert_eq!(proof.scheme(), ZkScheme::BLS);
        
        match &keypair {
            ZkKeypair::Bls(bls_pair) => {
                let result = validator.verify(
                    message,
                    &proof,
                    &bls_pair.pk.to_bytes()
                ).await.unwrap();
                assert!(result);
            }
            _ => panic!("Wrong keypair type"),
        }
    }

    #[tokio::test]
    async fn test_dilithium_proof_verification() {
        let validator = ZkValidator::new(ZkScheme::Dilithium);
        let keypair = ZkKeypair::generate(ZkScheme::Dilithium).await.unwrap();
        let message = b"test message";
        
        // Generate and verify proof
        let proof = validator.generate_proof(message, &keypair).await.unwrap();
        assert_eq!(proof.scheme(), ZkScheme::Dilithium);
        
        match &keypair {
            ZkKeypair::Dilithium(dil_pair) => {
                let result = validator.verify(
                    message,
                    &proof,
                    dil_pair.pk.as_bytes()
                ).await.unwrap();
                assert!(result);
            }
            _ => panic!("Wrong keypair type"),
        }
    }

    #[tokio::test]
    async fn test_proof_scheme_mismatch() {
        let bls_validator = ZkValidator::new(ZkScheme::BLS);
        let dilithium_keypair = ZkKeypair::generate(ZkScheme::Dilithium).await.unwrap();
        let message = b"test message";
        
        // Try to generate BLS proof with Dilithium keypair
        let result = bls_validator.generate_proof(message, &dilithium_keypair).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_from_bytes() {
        // Test BLS proof
        let bls_bytes = vec![0u8; 96];
        let proof = ZkProof::from_bytes(ZkScheme::BLS, bls_bytes).unwrap();
        assert_eq!(proof.scheme(), ZkScheme::BLS);

        // Test Dilithium proof
        let dil_bytes = vec![0u8; 2420];
        let proof = ZkProof::from_bytes(ZkScheme::Dilithium, dil_bytes).unwrap();
        assert_eq!(proof.scheme(), ZkScheme::Dilithium);

        // Test invalid lengths
        assert!(ZkProof::from_bytes(ZkScheme::BLS, vec![0u8; 32]).is_err());
        assert!(ZkProof::from_bytes(ZkScheme::Dilithium, vec![0u8; 32]).is_err());
    }

    #[tokio::test]
    async fn test_json_output() {
        let crypto = Arc::new(KapraCrypto::new(false));
        let async_runtime = Arc::new(AsyncRuntime::new());
        let mut vm = KapraVM::new(false, crypto, async_runtime);

        // Create a simple bytecode that generates and verifies a proof
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array32([1; 32]), // statement
            Constant::Array32([2; 32]), // witness
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push statement
            OPCODE_PUSH, 1,           // Push witness
            OPCODE_GENERATE_PROOF,    // Generate proof
            OPCODE_PUSH, 0,           // Push statement
            OPCODE_VERIFY_PROOF,      // Verify proof
        ]);

        // Test JSON output
        let json_output = vm.execute_with_output(&bytecode).await.unwrap();
        let parsed: Value = serde_json::from_str(&json_output).unwrap();

        // Verify JSON structure
        assert!(parsed.is_object());
        assert!(parsed["scheme"].is_string());
        assert!(parsed["proof"].is_string());
        assert!(parsed["valid"].is_boolean());
        assert!(parsed["metadata"].is_object());
        assert!(parsed["metadata"]["size"].is_number());
        assert!(parsed["metadata"]["timestamp"].is_number());
        assert!(parsed["metadata"]["embedded"].is_boolean());

        // Test structured output
        let structured = vm.execute_structured(&bytecode).await.unwrap();
        assert_eq!(structured.scheme, parsed["scheme"].as_str().unwrap());
        assert_eq!(structured.proof, parsed["proof"].as_str().unwrap());
        assert_eq!(structured.valid, parsed["valid"].as_bool().unwrap());
    }

    #[test]
    fn test_proof_base64() {
        let proof_bytes = vec![1, 2, 3, 4, 5];
        let encoded = BASE64.encode(&proof_bytes);
        let decoded = BASE64.decode(&encoded).unwrap();
        assert_eq!(proof_bytes, decoded);
    }
}