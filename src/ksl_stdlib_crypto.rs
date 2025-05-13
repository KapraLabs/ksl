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
    Signer,
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

use itertools::Itertools;

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

/// Built-in validation functions for KSL blockchain
pub mod validation {
    use crate::ksl_types::{BlockHeader, Transaction, ValidatorInfo};
    use sha3::{Digest, Keccak256};
    use std::collections::{HashSet, HashMap};

    /// Checks if a number is Kaprekar stable
    /// @param num The number to check
    /// @returns bool indicating if the number is Kaprekar stable
    pub fn kaprekar_valid(num: u64) -> bool {
        let mut n = num;
        let mut seen = std::collections::HashSet::new();
        
        while !seen.contains(&n) {
            seen.insert(n);
            let digits: Vec<u8> = n.to_string().chars()
                .map(|c| c.to_digit(10).unwrap() as u8)
                .collect();
            
            let ascending: u64 = digits.iter()
                .sorted()
                .fold(0u64, |acc, &d| acc * 10 + d as u64);
            
            let descending: u64 = digits.iter()
                .sorted_by(|a, b| b.cmp(a))
                .fold(0u64, |acc, &d| acc * 10 + d as u64);
            
            n = descending - ascending;
            if n == 0 || n == num {
                return true;
            }
        }
        false
    }

    /// Validates block hash modulo difficulty
    /// @param hash The block hash to check
    /// @param difficulty The difficulty target
    /// @returns bool indicating if the hash meets the difficulty requirement
    pub fn modulo_check(hash: u64, difficulty: u64) -> bool {
        hash % difficulty == 0
    }

    /// Computes SHA3 hash of input data
    /// @param input The input data to hash
    /// @returns The computed hash as a byte array
    pub fn sha3(input: &[u8]) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }

    /// Verifies a BLS signature
    /// @param message The message that was signed
    /// @param signature The signature to verify
    /// @param public_key The public key to verify against
    /// @returns bool indicating if the signature is valid
    pub fn bls_verify(_message: &[u8], _signature: &[u8], _public_key: &[u8]) -> bool {
        // TODO: Implement actual BLS verification
        // This is a placeholder that should be replaced with actual BLS implementation
        false
    }

    /// Verifies an Ed25519 signature
    /// @param message The message that was signed
    /// @param signature The signature to verify
    /// @param public_key The public key to verify against
    /// @returns bool indicating if the signature is valid
    pub fn ed25519_verify(_message: &[u8], _signature: &[u8], _public_key: &[u8]) -> bool {
        // TODO: Implement actual Ed25519 verification
        // This is a placeholder that should be replaced with actual Ed25519 implementation
        false
    }

    /// Verifies a Merkle proof for a given leaf and root
    /// @param leaf The leaf hash to verify
    /// @param root The expected root hash
    /// @param proof The array of sibling hashes in the proof path
    /// @param index The index of the leaf in the tree (0-based)
    /// @returns bool indicating if the proof is valid
    pub fn merkle_verify(leaf: &[u8], root: &[u8], proof: &[Vec<u8>], index: u64) -> bool {
        let mut hash = leaf.to_vec();
        let mut current_index = index;

        for sibling in proof {
            let (left, right) = if current_index % 2 == 0 {
                (&hash, sibling)
            } else {
                (sibling, &hash)
            };

            let mut hasher = Keccak256::new();
            hasher.update(left);
            hasher.update(right);
            hash = hasher.finalize().to_vec();
            current_index /= 2;
        }

        hash == root
    }

    /// Computes the Merkle root for a list of transactions
    /// @param transactions The list of transactions to compute the root for
    /// @returns The computed Merkle root
    pub fn compute_merkle_root(transactions: &[Transaction]) -> Vec<u8> {
        if transactions.is_empty() {
            return vec![0; 32];
        }

        let mut leaves: Vec<Vec<u8>> = transactions.iter()
            .map(|tx| {
                let mut hasher = Keccak256::new();
                hasher.update(&tx.sender);
                hasher.update(&tx.recipient);
                hasher.update(&tx.amount.to_be_bytes());
                hasher.update(&tx.nonce.to_be_bytes());
                hasher.update(&tx.signature);
                hasher.update(&tx.data);
                hasher.finalize().to_vec()
            })
            .collect();

        // Pad to power of 2
        while leaves.len() & (leaves.len() - 1) != 0 {
            leaves.push(vec![0; 32]);
        }

        let mut current = leaves;
        while current.len() > 1 {
            let mut next = Vec::new();
            for i in (0..current.len()).step_by(2) {
                let mut hasher = Keccak256::new();
                hasher.update(&current[i]);
                hasher.update(&current[i + 1]);
                next.push(hasher.finalize().to_vec());
            }
            current = next;
        }

        current[0].clone()
    }

    /// Generates a Merkle proof for a transaction at a given index
    /// @param transactions The list of transactions
    /// @param index The index of the transaction to generate a proof for
    /// @returns A tuple containing the proof and the root
    pub fn generate_merkle_proof(transactions: &[Transaction], index: u64) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut leaves: Vec<Vec<u8>> = transactions.iter()
            .map(|tx| {
                let mut hasher = Keccak256::new();
                hasher.update(&tx.sender);
                hasher.update(&tx.recipient);
                hasher.update(&tx.amount.to_be_bytes());
                hasher.update(&tx.nonce.to_be_bytes());
                hasher.update(&tx.signature);
                hasher.update(&tx.data);
                hasher.finalize().to_vec()
            })
            .collect();

        // Pad to power of 2
        while leaves.len() & (leaves.len() - 1) != 0 {
            leaves.push(vec![0; 32]);
        }

        let mut proof = Vec::new();
        let mut current_index = index;
        let mut current = leaves;

        while current.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current.len() as u64 {
                proof.push(current[sibling_index as usize].clone());
            }

            let mut next = Vec::new();
            for i in (0..current.len()).step_by(2) {
                let mut hasher = Keccak256::new();
                hasher.update(&current[i]);
                hasher.update(&current[i + 1]);
                next.push(hasher.finalize().to_vec());
            }
            current = next;
            current_index /= 2;
        }

        (proof, current[0].clone())
    }

    /// Represents a cross-shard Merkle proof
    #[derive(Debug, Clone)]
    pub struct CrossShardProof {
        pub source_shard: u16,
        pub target_shard: u16,
        pub transaction_proof: Vec<Vec<u8>>,
        pub shard_proof: Vec<Vec<u8>>,
        pub transaction_index: u64,
        pub shard_index: u64,
    }

    /// Computes the shard Merkle root for a list of transaction roots
    /// @param shard_roots The list of transaction roots per shard
    /// @returns The computed shard Merkle root
    pub fn compute_shard_root(shard_roots: &[(u16, Vec<u8>)]) -> Vec<u8> {
        if shard_roots.is_empty() {
            return vec![0; 32];
        }

        // Sort by shard ID to ensure consistent ordering
        let mut sorted_roots = shard_roots.to_vec();
        sorted_roots.sort_by_key(|(shard_id, _)| *shard_id);

        let mut leaves: Vec<Vec<u8>> = sorted_roots.iter()
            .map(|(_, root)| root.clone())
            .collect();

        // Pad to power of 2
        while leaves.len() & (leaves.len() - 1) != 0 {
            leaves.push(vec![0; 32]);
        }

        let mut current = leaves;
        while current.len() > 1 {
            let mut next = Vec::new();
            for i in (0..current.len()).step_by(2) {
                let mut hasher = Keccak256::new();
                hasher.update(&current[i]);
                hasher.update(&current[i + 1]);
                next.push(hasher.finalize().to_vec());
            }
            current = next;
        }

        current[0].clone()
    }

    /// Generates a cross-shard Merkle proof
    /// @param transactions The list of transactions in the source shard
    /// @param shard_roots The list of transaction roots per shard
    /// @param tx_index The index of the transaction in its shard
    /// @param source_shard The source shard ID
    /// @param target_shard The target shard ID
    /// @returns A CrossShardProof containing both transaction and shard proofs
    pub fn generate_cross_shard_proof(
        transactions: &[Transaction],
        shard_roots: &[(u16, Vec<u8>)],
        tx_index: u64,
        source_shard: u16,
        target_shard: u16,
    ) -> CrossShardProof {
        // Generate transaction proof
        let (tx_proof, _) = generate_merkle_proof(transactions, tx_index);

        // Find shard index
        let shard_index = shard_roots.iter()
            .position(|(shard_id, _)| *shard_id == source_shard)
            .unwrap_or(0) as u64;

        // Generate shard proof
        let mut sorted_roots = shard_roots.to_vec();
        sorted_roots.sort_by_key(|(shard_id, _)| *shard_id);
        let shard_leaves: Vec<Vec<u8>> = sorted_roots.iter()
            .map(|(_, root)| root.clone())
            .collect();

        let mut shard_proof = Vec::new();
        let mut current_index = shard_index;
        let mut current = shard_leaves;

        while current.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current.len() as u64 {
                shard_proof.push(current[sibling_index as usize].clone());
            }

            let mut next = Vec::new();
            for i in (0..current.len()).step_by(2) {
                let mut hasher = Keccak256::new();
                hasher.update(&current[i]);
                hasher.update(&current[i + 1]);
                next.push(hasher.finalize().to_vec());
            }
            current = next;
            current_index /= 2;
        }

        CrossShardProof {
            source_shard,
            target_shard,
            transaction_proof: tx_proof,
            shard_proof,
            transaction_index: tx_index,
            shard_index,
        }
    }

    /// Verifies a cross-shard Merkle proof
    /// @param tx The transaction to verify
    /// @param proof The cross-shard proof
    /// @param shard_root The root of the shard Merkle tree
    /// @returns bool indicating if the proof is valid
    pub fn verify_cross_shard_proof(
        tx: &Transaction,
        proof: &CrossShardProof,
        shard_root: &[u8],
    ) -> bool {
        // Compute transaction hash
        let mut hasher = Keccak256::new();
        hasher.update(&tx.sender);
        hasher.update(&tx.recipient);
        hasher.update(&tx.amount.to_be_bytes());
        hasher.update(&tx.nonce.to_be_bytes());
        hasher.update(&tx.signature);
        hasher.update(&tx.data);
        let tx_hash = hasher.finalize().to_vec();

        // Verify transaction proof
        let mut current_hash = tx_hash.clone();
        let mut current_index = proof.transaction_index;

        for sibling in &proof.transaction_proof {
            let (left, right) = if current_index % 2 == 0 {
                (&current_hash, sibling)
            } else {
                (sibling, &current_hash)
            };

            let mut hasher = Keccak256::new();
            hasher.update(left);
            hasher.update(right);
            current_hash = hasher.finalize().to_vec();
            current_index /= 2;
        }

        // Verify shard proof
        let mut current_hash = current_hash;
        let mut current_index = proof.shard_index;

        for sibling in &proof.shard_proof {
            let (left, right) = if current_index % 2 == 0 {
                (&current_hash, sibling)
            } else {
                (sibling, &current_hash)
            };

            let mut hasher = Keccak256::new();
            hasher.update(left);
            hasher.update(right);
            current_hash = hasher.finalize().to_vec();
            current_index /= 2;
        }

        current_hash == shard_root
    }
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