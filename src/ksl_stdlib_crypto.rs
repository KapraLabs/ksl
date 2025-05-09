// ksl_stdlib_crypto.rs
// Implements cryptographic functions for KSL standard library, optimized for NFT use cases.
// Provides both synchronous and asynchronous cryptographic operations.

use crate::ksl_types::{Type, TypeError};
use crate::ksl_bytecode::{KapraOpCode, Operand, KapraInstruction};
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use rand::Rng;
use sha3::{Digest, Keccak256};
use ed25519_dalek::{
    Keypair as EdKeypair,
    PublicKey as EdPublicKey,
    SecretKey as EdSecretKey,
    Signature as EdSignature,
    Verifier,
};
use blst::{
    min_pk::{
        SecretKey as BlsSecretKey,
        PublicKey as BlsPublicKey,
        Signature as BlsSignature,
    },
    BLST_ERROR,
};
#[cfg(not(target_arch = "wasm32"))]
use pqcrypto_dilithium::dilithium5;

#[cfg(not(target_arch = "wasm32"))]
use pqcrypto_traits::sign::{
    DetachedSignature as DilithiumSignature,
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
};

/// Cryptographic function signature with async support
#[derive(Debug, PartialEq, Clone)]
pub struct CryptoStdLibFunction {
    pub name: &'static str,
    pub params: Vec<Type>,
    pub return_type: Type,
    pub opcode: Option<KapraOpCode>, // None for native implementations
    pub is_async: bool, // Whether the function is asynchronous
}

/// Cryptographic standard library registry
pub struct CryptoStdLib {
    functions: Vec<CryptoStdLibFunction>,
}

impl CryptoStdLib {
    pub fn new() -> Self {
        let functions = vec![
            // Hashing functions
            CryptoStdLibFunction {
                name: "sha256",
                params: vec![Type::Array(Box::new(Type::U8), 0)], // Variable-length input
                return_type: Type::Array(Box::new(Type::U8), 32), // 32-byte hash
                opcode: Some(KapraOpCode::Sha256),
                is_async: false,
            },
            CryptoStdLibFunction {
                name: "sha3_256",
                params: vec![Type::Array(Box::new(Type::U8), 0)], // Variable-length input
                return_type: Type::Array(Box::new(Type::U8), 32), // 32-byte hash
                opcode: Some(KapraOpCode::Sha3_256),
                is_async: false,
            },
            CryptoStdLibFunction {
                name: "blake2b",
                params: vec![
                    Type::Array(Box::new(Type::U8), 0), // Input data
                    Type::Array(Box::new(Type::U8), 0), // Optional key
                ],
                return_type: Type::Array(Box::new(Type::U8), 64), // 64-byte hash
                opcode: Some(KapraOpCode::Blake2b),
                is_async: false,
            },
            // Async hashing functions
            CryptoStdLibFunction {
                name: "async_sha256",
                params: vec![Type::Array(Box::new(Type::U8), 0)],
                return_type: Type::Array(Box::new(Type::U8), 32),
                opcode: Some(KapraOpCode::AsyncSha256),
                is_async: true,
            },
            CryptoStdLibFunction {
                name: "async_sha3_256",
                params: vec![Type::Array(Box::new(Type::U8), 0)],
                return_type: Type::Array(Box::new(Type::U8), 32),
                opcode: Some(KapraOpCode::AsyncSha3_256),
                is_async: true,
            },
            // Existing verification functions
            CryptoStdLibFunction {
                name: "bls_verify",
                params: vec![
                    Type::Array(Box::new(Type::U8), 32), // Message
                    Type::Array(Box::new(Type::U8), 48), // Public key
                    Type::Array(Box::new(Type::U8), 96), // Signature
                ],
                return_type: Type::U32, // Boolean as u32
                opcode: Some(KapraOpCode::BlsVerify),
                is_async: false,
            },
            CryptoStdLibFunction {
                name: "dil_verify",
                params: vec![
                    Type::Array(Box::new(Type::U8), 32), // Message
                    Type::Array(Box::new(Type::U8), 1312), // Public key
                    Type::Array(Box::new(Type::U8), 2420), // Signature
                ],
                return_type: Type::U32, // Boolean as u32
                opcode: Some(KapraOpCode::DilithiumVerify),
                is_async: false,
            },
            CryptoStdLibFunction {
                name: "merkle_verify",
                params: vec![
                    Type::Array(Box::new(Type::U8), 32), // Root
                    Type::Array(Box::new(Type::U8), 0), // Variable-length proof
                ],
                return_type: Type::U32, // Boolean as u32
                opcode: Some(KapraOpCode::MerkleVerify),
                is_async: false,
            },
        ];
        CryptoStdLib { functions }
    }

    /// Example usage:
    /// ```ksl
    /// // Synchronous hashing
    /// let hash = sha256(data);
    /// let hash3 = sha3_256(data);
    /// let blake_hash = blake2b(data, key);
    /// 
    /// // Asynchronous hashing
    /// let hash = await async_sha256(data);
    /// let hash3 = await async_sha3_256(data);
    /// 
    /// // Verification
    /// let valid = bls_verify(msg, pubkey, sig);
    /// let valid = dil_verify(msg, pubkey, sig);
    /// let valid = merkle_verify(root, proof);
    /// ```
    pub fn get_function(&self, name: &str) -> Option<&CryptoStdLibFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    // Validate function call (used by type checker)
    pub fn validate_call(
        &self,
        name: &str,
        arg_types: &[Type],
        position: SourcePosition,
    ) -> Result<Type, KslError> {
        let func = self.get_function(name).ok_or_else(|| KslError::type_error(
            format!("Undefined cryptographic function: {}", name),
            position,
        ))?;
        if arg_types.len() != func.params.len() {
            return Err(KslError::type_error(
                format!(
                    "Expected {} arguments, got {}",
                    func.params.len(),
                    arg_types.len()
                ),
                position,
            ));
        }
        for (expected, actual) in func.params.iter().zip(arg_types) {
            if expected != actual {
                return Err(KslError::type_error(
                    format!("Argument type mismatch: expected {:?}, got {:?}", expected, actual),
                    position,
                ));
            }
        }
        Ok(func.return_type.clone())
    }

    // Generate bytecode for function call (used by compiler)
    pub fn emit_call(
        &self,
        name: &str,
        arg_regs: &[u8],
        dst_reg: u8,
    ) -> Result<Vec<KapraInstruction>, KslError> {
        let func = self.get_function(name).ok_or_else(|| KslError::type_error(
            format!("Undefined cryptographic function: {}", name),
            SourcePosition::new(1, 1), // Simplified
        ))?;
        if arg_regs.len() != func.params.len() {
            return Err(KslError::type_error(
                format!(
                    "Expected {} arguments, got {}",
                    func.params.len(),
                    arg_regs.len()
                ),
                SourcePosition::new(1, 1),
            ));
        }

        match func.opcode {
            Some(opcode) => {
                let mut operands = vec![Operand::Register(dst_reg)];
                operands.extend(arg_regs.iter().map(|&r| Operand::Register(r)));
                Ok(vec![KapraInstruction::new(
                    opcode,
                    operands,
                    Some(func.return_type.clone()),
                )])
            }
            None => Err(KslError::type_error(
                format!("No implementation for {}", name),
                SourcePosition::new(1, 1),
            )),
        }
    }
}

/// BLS12-381 keypair
#[derive(Clone)]
pub struct BlsKeypair {
    pub sk: BlsSecretKey,
    pub pk: BlsPublicKey,
}

/// Dilithium keypair
#[derive(Clone)]
pub struct DilithiumKeypair {
    pub sk: DilithiumSecretKey,
    pub pk: DilithiumPublicKey,
}

/// Ed25519 keypair
#[derive(Clone)]
pub struct Ed25519Keypair {
    pub sk: EdSecretKey,
    pub pk: EdPublicKey,
}

/// Crypto operations for KSL
pub struct Crypto {
    /// Cache of Ed25519 public keys
    ed25519_cache: Arc<RwLock<HashMap<[u8; 32], EdPublicKey>>>,
    /// BLS keypairs
    bls_keys: Arc<RwLock<HashMap<[u8; 32], BlsKeypair>>>,
    /// Dilithium keypairs
    dilithium_keys: Arc<RwLock<HashMap<[u8; 32], DilithiumKeypair>>>,
}

impl Crypto {
    pub fn new() -> Self {
        Self {
            ed25519_cache: Arc::new(RwLock::new(HashMap::new())),
            bls_keys: Arc::new(RwLock::new(HashMap::new())),
            dilithium_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate Ed25519 keypair
    pub fn generate_ed25519_keypair(&self) -> Result<Ed25519Keypair, KslError> {
        let mut rng = rand::thread_rng();
        let keypair = EdKeypair::generate(&mut rng);
        Ok(Ed25519Keypair {
            sk: keypair.secret,
            pk: keypair.public,
        })
    }

    /// Generate BLS12-381 keypair
    pub fn bls_generate_keypair(&self) -> Result<BlsKeypair, KslError> {
        let ikm = b"kapra-bls-key"; // TODO: Replace with proper entropy source
        let sk = BlsSecretKey::key_gen(ikm);
        let pk = sk.sk_to_pk();
        Ok(BlsKeypair { sk, pk })
    }

    /// Generate Dilithium keypair
    pub fn dilithium_generate_keypair(&self) -> Result<DilithiumKeypair, KslError> {
        let (pk, sk) = dilithium5::keypair();
        Ok(DilithiumKeypair { sk, pk })
    }

    /// Sign message with Ed25519
    pub fn ed25519_sign(&self, sk: &EdSecretKey, message: &[u8]) -> Result<EdSignature, KslError> {
        let keypair = EdKeypair {
            secret: *sk,
            public: EdPublicKey::from(sk),
        };
        Ok(keypair.sign(message))
    }

    /// Sign message with BLS12-381
    pub fn bls_sign(&self, sk: &BlsSecretKey, message: &[u8]) -> Result<BlsSignature, KslError> {
        Ok(sk.sign(message, b"", &[]))
    }

    /// Sign message with Dilithium
    #[cfg(not(target_arch = "wasm32"))]
    pub fn dilithium_sign(&self, sk: &DilithiumSecretKey, message: &[u8]) -> Result<DilithiumSignature, KslError> {
        Ok(dilithium5::sign_detached(message, sk))
    }

    /// Verify Ed25519 signature
    pub fn ed25519_verify(&self, pk: &EdPublicKey, message: &[u8], sig: &EdSignature) -> Result<bool, KslError> {
        Ok(pk.verify(message, sig).is_ok())
    }

    /// Verify BLS12-381 signature
    pub fn bls_verify(&self, pk: &BlsPublicKey, message: &[u8], sig: &BlsSignature) -> Result<bool, KslError> {
        Ok(sig.verify(true, message, b"", &[], pk, true) == BLST_ERROR::BLST_SUCCESS)
    }

    /// Verify Dilithium signature
    pub fn dilithium_verify(&self, pk: &DilithiumPublicKey, message: &[u8], sig: &DilithiumSignature) -> Result<bool, KslError> {
        Ok(dilithium5::verify_detached(sig, message, pk).is_ok())
    }

    /// Hash data using Keccak-256
    pub fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Cache an Ed25519 public key
    pub async fn cache_ed25519_key(&self, id: [u8; 32], pk: EdPublicKey) {
        let mut cache = self.ed25519_cache.write().await;
        cache.insert(id, pk);
    }

    /// Get cached Ed25519 public key
    pub async fn get_cached_ed25519_key(&self, id: &[u8; 32]) -> Option<EdPublicKey> {
        let cache = self.ed25519_cache.read().await;
        cache.get(id).copied()
    }

    /// Cache a BLS keypair
    pub async fn cache_bls_keypair(&self, id: [u8; 32], keypair: BlsKeypair) {
        let mut keys = self.bls_keys.write().await;
        keys.insert(id, keypair);
    }

    /// Get cached BLS keypair
    pub async fn get_cached_bls_keypair(&self, id: &[u8; 32]) -> Option<BlsKeypair> {
        let keys = self.bls_keys.read().await;
        keys.get(id).cloned()
    }

    /// Cache a Dilithium keypair
    pub async fn cache_dilithium_keypair(&self, id: [u8; 32], keypair: DilithiumKeypair) {
        let mut keys = self.dilithium_keys.write().await;
        keys.insert(id, keypair);
    }

    /// Get cached Dilithium keypair
    pub async fn get_cached_dilithium_keypair(&self, id: &[u8; 32]) -> Option<DilithiumKeypair> {
        let keys = self.dilithium_keys.read().await;
        keys.get(id).cloned()
    }
}

// Assume ksl_types.rs, ksl_bytecode.rs, and ksl_errors.rs are in the same crate
mod ksl_types {
    pub use super::{Type, TypeError};
}

mod ksl_bytecode {
    pub use super::{KapraOpCode, Operand, KapraInstruction};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_function() {
        let stdlib = CryptoStdLib::new();
        
        // Test hashing functions
        let func = stdlib.get_function("sha256").unwrap();
        assert_eq!(func.name, "sha256");
        assert_eq!(func.params.len(), 1);
        assert_eq!(func.return_type, Type::Array(Box::new(Type::U8), 32));
        assert_eq!(func.is_async, false);

        let func = stdlib.get_function("async_sha256").unwrap();
        assert_eq!(func.name, "async_sha256");
        assert_eq!(func.is_async, true);

        // Test existing verification functions
        let func = stdlib.get_function("bls_verify").unwrap();
        assert_eq!(func.name, "bls_verify");
        assert_eq!(func.params.len(), 3);
        assert_eq!(func.return_type, Type::U32);
        assert_eq!(func.is_async, false);

        let func = stdlib.get_function("dil_verify").unwrap();
        assert_eq!(func.name, "dil_verify");
        assert_eq!(func.params.len(), 3);
        assert_eq!(func.params[1], Type::Array(Box::new(Type::U8), 1312));
        assert_eq!(func.is_async, false);

        let func = stdlib.get_function("merkle_verify").unwrap();
        assert_eq!(func.name, "merkle_verify");
        assert_eq!(func.params.len(), 2);
        assert_eq!(func.params[0], Type::Array(Box::new(Type::U8), 32));
        assert_eq!(func.is_async, false);
    }

    #[test]
    fn test_validate_call() {
        let stdlib = CryptoStdLib::new();
        let pos = SourcePosition::new(1, 1);
        assert_eq!(
            stdlib.validate_call("bls_verify", &[
                Type::Array(Box::new(Type::U8), 32),
                Type::Array(Box::new(Type::U8), 48),
                Type::Array(Box::new(Type::U8), 96),
            ], pos),
            Ok(Type::U32)
        );
        assert!(stdlib.validate_call("bls_verify", &[Type::U32], pos).is_err());
        assert!(stdlib.validate_call("unknown", &[], pos).is_err());
    }

    #[test]
    fn test_emit_call() {
        let stdlib = CryptoStdLib::new();
        let instructions = stdlib.emit_call("bls_verify", &[1, 2, 3], 0).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, KapraOpCode::BlsVerify);
        assert_eq!(
            instructions[0].operands,
            vec![
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
                Operand::Register(3),
            ]
        );
        assert_eq!(instructions[0].type_info, Some(Type::U32));
    }

    #[tokio::test]
    async fn test_ed25519_operations() {
        let crypto = Crypto::new();
        let keypair = crypto.generate_ed25519_keypair().unwrap();
        let message = b"test message";
        let sig = crypto.ed25519_sign(&keypair.sk, message).unwrap();
        assert!(crypto.ed25519_verify(&keypair.pk, message, &sig).unwrap());
    }

    #[tokio::test]
    async fn test_bls_operations() {
        let crypto = Crypto::new();
        let keypair = crypto.bls_generate_keypair().unwrap();
        let message = b"test message";
        let sig = crypto.bls_sign(&keypair.sk, message).unwrap();
        assert!(crypto.bls_verify(&keypair.pk, message, &sig).unwrap());
    }

    #[tokio::test]
    async fn test_dilithium_operations() {
        let crypto = Crypto::new();
        let keypair = crypto.dilithium_generate_keypair().unwrap();
        let message = b"test message";
        let sig = crypto.dilithium_sign(&keypair.sk, message).unwrap();
        assert!(crypto.dilithium_verify(&keypair.pk, message, &sig).unwrap());
    }

    #[tokio::test]
    async fn test_key_caching() {
        let crypto = Crypto::new();
        let keypair = crypto.generate_ed25519_keypair().unwrap();
        let id = [1u8; 32];
        
        crypto.cache_ed25519_key(id, keypair.pk).await;
        let cached_pk = crypto.get_cached_ed25519_key(&id).await;
        assert!(cached_pk.is_some());
    }

    #[tokio::test]
    async fn test_bls_key_caching() {
        let crypto = Crypto::new();
        let keypair = crypto.bls_generate_keypair().unwrap();
        let id = [1u8; 32];
        
        crypto.cache_bls_keypair(id, keypair.clone()).await;
        let cached_keypair = crypto.get_cached_bls_keypair(&id).await;
        assert!(cached_keypair.is_some());
    }

    #[tokio::test]
    async fn test_dilithium_key_caching() {
        let crypto = Crypto::new();
        let keypair = crypto.dilithium_generate_keypair().unwrap();
        let id = [1u8; 32];
        
        crypto.cache_dilithium_keypair(id, keypair.clone()).await;
        let cached_keypair = crypto.get_cached_dilithium_keypair(&id).await;
        assert!(cached_keypair.is_some());
    }
}