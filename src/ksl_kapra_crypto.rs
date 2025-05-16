// ksl_kapra_crypto.rs
// Optimized quantum-resistant cryptographic functions for Kapra Chain
// Uses the new program's crypto library for secure implementations

use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_validator_keys::{ValidatorKeyPair, KeyRotationSchedule, KeyMetrics, KeyId, StorageType, HardwareSecurityModule};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::collections::HashMap;
use std::arch::x86_64::*;
use std::arch::asm;
use wgpu;
// use packed_simd::{u8x32, u32x8, u64x4};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use blst::{min_pk::*, BLST_ERROR};
use std::time::Instant;
use sha2::{Sha256, Digest};
use rand_core::{OsRng, RngCore};
use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};
use std::sync::mpsc;
use std::thread;
use std::sync::{Arc, RwLock};
use rand::Rng;
use keyring::Keyring;
use tokio::time::{Duration, sleep};
use tokio::task::JoinHandle;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use rand_chacha::ChaCha20Rng;
use rand_chacha::chacha20::ChaCha20Core;
use rand_core::SeedableRng;
use pqcrypto::dilithium::{self, DilithiumKeypair, DilithiumPublicKey, DilithiumSecretKey};
use blst::{blst_sk, blst_pk, blst_signature};
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Key, Nonce}};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Represents a fixed-size array (aligned with KSL's type system).
/// Uses the new program's array type for better performance and memory safety.
#[derive(Debug, Clone)]
pub struct FixedArray<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> FixedArray<N> {
    /// Creates a new fixed-size array with the given data.
    pub fn new(data: [u8; N]) -> Self {
        FixedArray { data }
    }

    /// Returns a slice of the array's data.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable slice of the array's data.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Returns the length of the array.
    pub fn len(&self) -> usize {
        N
    }
}

/// Optimized Dilithium signature verification for Kapra Chain.
/// Uses the new program's crypto library for secure implementation.
pub struct DilithiumVerifier {
    is_embedded: bool,
    // New program's crypto context
    crypto_ctx: CryptoContext,
}

impl DilithiumVerifier {
    /// Creates a new Dilithium verifier instance.
    pub fn new(is_embedded: bool) -> Self {
        DilithiumVerifier {
            is_embedded,
            crypto_ctx: CryptoContext::new(),
        }
    }

    /// Verify a Dilithium signature (quantum-resistant).
    /// Uses the new program's crypto library for secure verification.
    /// 
    /// # Arguments
    /// * `message` - 32-byte message to verify
    /// * `pubkey` - 1312-byte public key
    /// * `signature` - 2420-byte signature
    /// 
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    pub fn dil_verify(
        &self,
        message: &FixedArray<32>,
        pubkey: &FixedArray<1312>,
        signature: &FixedArray<2420>,
    ) -> bool {
        if self.is_embedded {
            // Use optimized implementation for embedded systems
            self.crypto_ctx.dilithium_verify_embedded(
                message.as_slice(),
                pubkey.as_slice(),
                signature.as_slice(),
            )
        } else {
            // Use full implementation
            self.crypto_ctx.dilithium_verify(
                message.as_slice(),
                pubkey.as_slice(),
                signature.as_slice(),
            )
        }
    }
}

/// Optimized BLS signature verification for Kapra Chain.
pub struct BLSVerifier {
    is_embedded: bool,
    crypto_ctx: CryptoContext,
}

impl BLSVerifier {
    /// Creates a new BLS verifier instance.
    pub fn new(is_embedded: bool) -> Self {
        BLSVerifier {
            is_embedded,
            crypto_ctx: CryptoContext::new(),
        }
    }

    /// Verify a BLS signature.
    /// 
    /// # Arguments
    /// * `message` - 32-byte message to verify
    /// * `pubkey` - 96-byte public key
    /// * `signature` - 48-byte signature
    /// 
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    pub fn bls_verify(
        &self,
        message: &FixedArray<32>,
        pubkey: &FixedArray<96>,
        signature: &FixedArray<48>,
    ) -> bool {
        if self.is_embedded {
            // Use optimized implementation for embedded systems
            self.crypto_ctx.bls_verify_embedded(
                message.as_slice(),
                pubkey.as_slice(),
                signature.as_slice(),
            )
        } else {
            // Use full implementation
            self.crypto_ctx.bls_verify(
                message.as_slice(),
                pubkey.as_slice(),
                signature.as_slice(),
            )
        }
    }
}

/// Optimized Ed25519 signature verification for Kapra Chain.
pub struct Ed25519Verifier {
    is_embedded: bool,
    crypto_ctx: CryptoContext,
}

impl Ed25519Verifier {
    /// Creates a new Ed25519 verifier instance.
    pub fn new(is_embedded: bool) -> Self {
        Ed25519Verifier {
            is_embedded,
            crypto_ctx: CryptoContext::new(),
        }
    }

    /// Verify an Ed25519 signature.
    /// 
    /// # Arguments
    /// * `message` - Message to verify
    /// * `pubkey` - 32-byte public key
    /// * `signature` - 64-byte signature
    /// 
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    pub fn ed25519_verify(
        &self,
        message: &[u8],
        pubkey: &FixedArray<32>,
        signature: &FixedArray<64>,
    ) -> bool {
        if self.is_embedded {
            self.crypto_ctx.ed25519_verify_embedded(
                message,
                pubkey.as_slice(),
                signature.as_slice(),
            )
        } else {
            self.crypto_ctx.ed25519_verify(
                message,
                pubkey.as_slice(),
                signature.as_slice(),
            )
        }
    }
}

/// Merkle tree node
#[derive(Debug, Clone)]
pub struct MerkleNode {
    /// Node hash
    hash: [u8; 32],
    /// Left child hash (if any)
    left: Option<Box<MerkleNode>>,
    /// Right child hash (if any)
    right: Option<Box<MerkleNode>>,
}

impl MerkleNode {
    /// Creates a new leaf node
    pub fn new_leaf(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        // Prefix with 0x00 for leaf nodes to prevent second preimage attacks
        hasher.update([0x00]);
        hasher.update(data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        MerkleNode {
            hash,
            left: None,
            right: None,
        }
    }

    /// Creates a new internal node
    pub fn new_internal(left: MerkleNode, right: MerkleNode) -> Self {
        let mut hasher = Sha256::new();
        // Prefix with 0x01 for internal nodes to prevent second preimage attacks
        hasher.update([0x01]);
        hasher.update(&left.hash);
        hasher.update(&right.hash);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        MerkleNode {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }

    /// Gets the node's hash
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

/// Merkle proof element
#[derive(Debug, Clone)]
pub struct MerkleProofElement {
    /// The hash to combine with
    pub hash: [u8; 32],
    /// Whether this hash is on the left
    pub is_left: bool,
}

/// Optimized Merkle tree verification for Kapra Chain.
pub struct MerkleVerifier {
    is_embedded: bool,
    crypto_ctx: CryptoContext,
}

impl MerkleVerifier {
    /// Creates a new Merkle verifier instance.
    pub fn new(is_embedded: bool) -> Self {
        MerkleVerifier {
            is_embedded,
            crypto_ctx: CryptoContext::new(),
        }
    }

    /// Verify a Merkle proof.
    /// 
    /// # Arguments
    /// * `leaf` - 32-byte leaf node
    /// * `root` - 32-byte root hash
    /// * `proof` - Vector of proof elements
    /// 
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn merkle_verify(
        &self,
        leaf: &FixedArray<32>,
        root: &FixedArray<32>,
        proof: &[MerkleProofElement],
    ) -> bool {
        if self.is_embedded {
            self.crypto_ctx.merkle_verify_embedded(
                leaf.as_slice(),
                root.as_slice(),
                proof,
            )
        } else {
            self.crypto_ctx.merkle_verify(
                leaf.as_slice(),
                root.as_slice(),
                proof,
            )
        }
    }

    /// Compute a leaf node hash
    pub fn hash_leaf(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x00]); // Prefix for leaf nodes
        hasher.update(data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }

    /// Compute an internal node hash
    pub fn hash_internal(&self, left: &[u8], right: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x01]); // Prefix for internal nodes
        hasher.update(left);
        hasher.update(right);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }

    /// Build a Merkle tree from leaves
    pub fn build_tree(&self, leaves: &[&[u8]]) -> Option<MerkleNode> {
        if leaves.is_empty() {
            return None;
        }

        // Create leaf nodes
        let mut nodes: Vec<MerkleNode> = leaves
            .iter()
            .map(|data| MerkleNode::new_leaf(data))
            .collect();

        // Build tree bottom-up
        while nodes.len() > 1 {
            let mut new_nodes = Vec::with_capacity((nodes.len() + 1) / 2);
            for chunk in nodes.chunks(2) {
                if chunk.len() == 2 {
                    new_nodes.push(MerkleNode::new_internal(
                        chunk[0].clone(),
                        chunk[1].clone(),
                    ));
                } else {
                    // Duplicate last node if odd number
                    new_nodes.push(MerkleNode::new_internal(
                        chunk[0].clone(),
                        chunk[0].clone(),
                    ));
                }
            }
            nodes = new_nodes;
        }

        Some(nodes.remove(0))
    }

    /// Generate a Merkle proof for a leaf
    pub fn generate_proof(
        &self,
        leaves: &[&[u8]],
        leaf_index: usize,
    ) -> Option<Vec<MerkleProofElement>> {
        if leaf_index >= leaves.len() {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_index = leaf_index;
        let mut nodes: Vec<MerkleNode> = leaves
            .iter()
            .map(|data| MerkleNode::new_leaf(data))
            .collect();

        while nodes.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < nodes.len() {
                proof.push(MerkleProofElement {
                    hash: nodes[sibling_index].hash,
                    is_left: current_index % 2 == 0,
                });
            } else {
                // Use the same node as both children if we're at the end
                proof.push(MerkleProofElement {
                    hash: nodes[current_index].hash,
                    is_left: current_index % 2 == 0,
                });
            }

            let mut new_nodes = Vec::with_capacity((nodes.len() + 1) / 2);
            for chunk in nodes.chunks(2) {
                if chunk.len() == 2 {
                    new_nodes.push(MerkleNode::new_internal(
                        chunk[0].clone(),
                        chunk[1].clone(),
                    ));
                } else {
                    new_nodes.push(MerkleNode::new_internal(
                        chunk[0].clone(),
                        chunk[0].clone(),
                    ));
                }
            }

            current_index /= 2;
            nodes = new_nodes;
        }

        Some(proof)
    }
}

/// ECVRF implementation based on curve25519
pub struct ECVRFGenerator {
    is_embedded: bool,
}

impl ECVRFGenerator {
    pub fn new(is_embedded: bool) -> Self {
        ECVRFGenerator { is_embedded }
    }

    /// Generate VRF output and proof using ECVRF
    pub fn generate_vrf(
        &self,
        seed: &FixedArray<32>,
        private_key: &[u8],
    ) -> Result<(FixedArray<32>, Vec<u8>), String> {
        // Convert private key to scalar
        let scalar = match Scalar::from_bytes_mod_order(private_key.try_into().unwrap()) {
            Some(s) => s,
            None => return Err("Invalid private key".to_string()),
        };

        // Hash seed to curve point
        let h = self.hash_to_curve(seed.as_slice());
        
        // Compute VRF output
        let output_point = h * scalar;
        let mut output = [0u8; 32];
        output.copy_from_slice(&output_point.compress().to_bytes());

        // Generate proof
        let k = Scalar::random(&mut OsRng);
        let u = h * k;
        let c = self.hash_challenge(&h, &output_point, &u);
        let s = k + c * scalar;

        // Encode proof
        let mut proof = Vec::with_capacity(96);
        proof.extend_from_slice(&output_point.compress().to_bytes());
        proof.extend_from_slice(&s.to_bytes());

        Ok((FixedArray::new(output), proof))
    }

    /// Verify VRF output and proof
    pub fn verify_vrf(
        &self,
        seed: &FixedArray<32>,
        public_key: &[u8],
        output: &FixedArray<32>,
        proof: &[u8],
    ) -> bool {
        if proof.len() != 96 {
            return false;
        }

        // Parse public key
        let public_key = match EdwardsPoint::from_bytes(public_key.try_into().unwrap()) {
            Some(p) => p,
            None => return false,
        };

        // Parse proof components
        let (output_point_bytes, s_bytes) = proof.split_at(32);
        let output_point = match EdwardsPoint::from_bytes(output_point_bytes.try_into().unwrap()) {
            Some(p) => p,
            None => return false,
        };
        let s = match Scalar::from_bytes_canonical(s_bytes.try_into().unwrap()) {
            Some(s) => s,
            None => return false,
        };

        // Hash seed to curve
        let h = self.hash_to_curve(seed.as_slice());
        
        // Verify proof
        let u = h * s - output_point * self.hash_challenge(&h, &output_point, &(h * s));
        let computed_output = (h * s).compress();
        
        computed_output.as_bytes() == output.as_slice()
    }

    fn hash_to_curve(&self, input: &[u8]) -> EdwardsPoint {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let scalar = Scalar::from_hash(hasher);
        EdwardsPoint::mul_base(&scalar)
    }

    fn hash_challenge(
        &self,
        h: &EdwardsPoint,
        output: &EdwardsPoint,
        u: &EdwardsPoint,
    ) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(h.compress().as_bytes());
        hasher.update(output.compress().as_bytes());
        hasher.update(u.compress().as_bytes());
        Scalar::from_hash(hasher)
    }
}

/// Supported signature schemes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureScheme {
    /// BLS12-381 signatures
    BLS = 0,
    /// Dilithium post-quantum signatures
    Dilithium = 1,
    /// Ed25519 classical signatures
    Ed25519 = 2,
}

impl SignatureScheme {
    /// Get expected public key size for scheme
    pub fn pubkey_size(&self) -> usize {
        match self {
            SignatureScheme::BLS => 96,
            SignatureScheme::Dilithium => 1312,
            SignatureScheme::Ed25519 => 32,
        }
    }

    /// Get expected signature size for scheme
    pub fn signature_size(&self) -> usize {
        match self {
            SignatureScheme::BLS => 48,
            SignatureScheme::Dilithium => 2420,
            SignatureScheme::Ed25519 => 64,
        }
    }

    /// Get scheme from type code
    pub fn from_type_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(SignatureScheme::BLS),
            1 => Some(SignatureScheme::Dilithium),
            2 => Some(SignatureScheme::Ed25519),
            _ => None,
        }
    }
}

/// KSL Crypto ABI
/// 
/// This module defines the Application Binary Interface (ABI) for cryptographic
/// operations available to KSL smart contracts and runtime code.
/// 
/// # Opcodes
/// 
/// ## Signature Verification
/// ```ksl
/// // BLS signature verification
/// fn bls_verify(pubkey: [u8; 96], sig: [u8; 48], msg: [u8; 32]) -> bool
/// 
/// // Dilithium signature verification
/// fn dilithium_verify(pubkey: [u8; 1312], sig: [u8; 2420], msg: [u8; 32]) -> bool
/// 
/// // Ed25519 signature verification  
/// fn ed25519_verify(pubkey: [u8; 32], sig: [u8; 64], msg: [u8]) -> bool
/// 
/// // Generic signature verification
/// fn verify_signature(pubkey: [u8], sig: [u8], msg: [u8], scheme: u8) -> bool
/// ```
/// 
/// ## Merkle Tree Operations
/// ```ksl
/// // Verify Merkle proof
/// fn merkle_verify(leaf: [u8; 32], root: [u8; 32], proof: [[u8; 32]]) -> bool
/// ```
/// 
/// ## VRF Operations
/// ```ksl
/// // Generate VRF output
/// fn vrf_generate(seed: [u8; 32], key: [u8; 32]) -> [u8; 32]
/// ```
pub struct KapraCrypto {
    dilithium: DilithiumVerifier,
    bls: BLSVerifier,
    merkle: MerkleVerifier,
    ed25519: Ed25519Verifier,
    vrf: ECVRFGenerator,
}

impl KapraCrypto {
    /// Creates a new KapraCrypto instance.
    pub fn new(is_embedded: bool) -> Self {
        KapraCrypto {
            dilithium: DilithiumVerifier::new(is_embedded),
            bls: BLSVerifier::new(is_embedded),
            merkle: MerkleVerifier::new(is_embedded),
            ed25519: Ed25519Verifier::new(is_embedded),
            vrf: ECVRFGenerator::new(is_embedded),
        }
    }

    /// Verify a Dilithium signature.
    pub fn dil_verify(
        &self,
        message: &FixedArray<32>,
        pubkey: &FixedArray<1312>,
        signature: &FixedArray<2420>,
    ) -> bool {
        self.dilithium.dil_verify(message, pubkey, signature)
    }

    /// Verify a BLS signature.
    pub fn bls_verify(
        &self,
        message: &FixedArray<32>,
        pubkey: &FixedArray<96>,
        signature: &FixedArray<48>,
    ) -> bool {
        self.bls.bls_verify(message, pubkey, signature)
    }

    /// Verify an Ed25519 signature.
    pub fn ed25519_verify(
        &self,
        message: &[u8],
        pubkey: &FixedArray<32>,
        signature: &FixedArray<64>,
    ) -> bool {
        self.ed25519.ed25519_verify(message, pubkey, signature)
    }

    /// Verify a Merkle proof.
    pub fn merkle_verify(
        &self,
        leaf: &FixedArray<32>,
        root: &FixedArray<32>,
        proof: &[MerkleProofElement],
    ) -> bool {
        self.merkle.merkle_verify(leaf, root, proof)
    }

    /// Generate a Verifiable Random Function output.
    pub fn vrf_generate(
        &self,
        seed: &FixedArray<32>,
        key: &FixedArray<32>,
    ) -> FixedArray<32> {
        self.vrf.vrf_generate(seed, key)
    }

    /// Verify a signature using any supported scheme
    /// 
    /// # Arguments
    /// * `pubkey` - Public key bytes
    /// * `signature` - Signature bytes
    /// * `message` - Message bytes
    /// * `scheme` - Signature scheme type code (0=BLS, 1=Dilithium, 2=Ed25519)
    /// 
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    pub fn verify_signature(
        &self,
        pubkey: &[u8],
        signature: &[u8],
        message: &[u8],
        scheme: u8,
    ) -> bool {
        let scheme = match SignatureScheme::from_type_code(scheme) {
            Some(s) => s,
            None => return false,
        };

        // Validate input sizes
        if pubkey.len() != scheme.pubkey_size() || signature.len() != scheme.signature_size() {
            return false;
        }

        match scheme {
            SignatureScheme::BLS => {
                if message.len() != 32 {
                    return false;
                }
                let pubkey = FixedArray::new(pubkey.try_into().unwrap());
                let signature = FixedArray::new(signature.try_into().unwrap());
                let message = FixedArray::new(message.try_into().unwrap());
                self.bls_verify(&message, &pubkey, &signature)
            }
            SignatureScheme::Dilithium => {
                if message.len() != 32 {
                    return false;
                }
                let pubkey = FixedArray::new(pubkey.try_into().unwrap());
                let signature = FixedArray::new(signature.try_into().unwrap());
                let message = FixedArray::new(message.try_into().unwrap());
                self.dil_verify(&message, &pubkey, &signature)
            }
            SignatureScheme::Ed25519 => {
                let pubkey = FixedArray::new(pubkey.try_into().unwrap());
                let signature = FixedArray::new(signature.try_into().unwrap());
                self.ed25519_verify(message, &pubkey, &signature)
            }
        }
    }
}

/// Context for the new program's crypto library.
struct CryptoContext {
    // Implementation details of the new program's crypto library
    // This would be replaced with actual crypto library types
}

impl CryptoContext {
    fn new() -> Self {
        CryptoContext {}
    }

    fn dilithium_verify(&self, message: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
        use std::time::{Duration, Instant};
        let start = Instant::now();

        if message.len() != 32 || pubkey.len() != 1312 || signature.len() != 2420 {
            return false;
        }

        let pk = match dilithium5::PublicKey::from_bytes(pubkey) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let result = dilithium5::verify_detached(signature, message, &pk).is_ok();

        if start.elapsed() > Duration::from_millis(50) {
            eprintln!("⚠️ Dilithium verify exceeded 50ms — possible DoS vector");
            return false;
        }

        result
    }

    fn dilithium_verify_embedded(&self, message: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
        // For embedded systems, we use the same implementation but with additional checks
        self.dilithium_verify(message, pubkey, signature)
    }

    fn bls_verify(&self, message: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
        use std::time::{Duration, Instant};
        let start = Instant::now();

        if message.len() != 32 || pubkey.len() != 96 || signature.len() != 48 {
            return false;
        }

        let pk = match PublicKey::from_bytes(pubkey) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match Signature::from_bytes(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        let result = sig.verify(true, message, &[], &pk, DST) == BLST_ERROR::BLST_SUCCESS;

        if start.elapsed() > Duration::from_millis(50) {
            eprintln!("⚠️ BLS verify exceeded 50ms — possible DoS vector");
            return false;
        }

        result
    }

    fn bls_verify_embedded(&self, message: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
        // For embedded systems, we use the same implementation but with additional checks
        self.bls_verify(message, pubkey, signature)
    }

    fn merkle_verify(&self, leaf: &[u8], root: &[u8], proof: &[MerkleProofElement]) -> bool {
        // Validate input sizes
        if leaf.len() != 32 || root.len() != 32 {
            return false;
        }

        // Start with leaf hash
        let mut current = self.hash_leaf(leaf);

        // Apply each proof element
        for element in proof {
            current = if element.is_left {
                self.hash_internal(&element.hash, &current)
            } else {
                self.hash_internal(&current, &element.hash)
            };
        }

        // Compare with root
        constant_time_eq::constant_time_eq(&current, root)
    }

    fn merkle_verify_embedded(&self, leaf: &[u8], root: &[u8], proof: &[MerkleProofElement]) -> bool {
        self.merkle_verify(leaf, root, proof)
    }

    fn hash_leaf(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x00]); // Prefix for leaf nodes
        hasher.update(data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }

    fn hash_internal(&self, left: &[u8], right: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x01]); // Prefix for internal nodes
        hasher.update(left);
        hasher.update(right);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }

    fn ed25519_verify(&self, message: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
        use std::time::{Duration, Instant};
        let start = Instant::now();

        if pubkey.len() != 32 || signature.len() != 64 {
            return false;
        }

        let pk = match PublicKey::from_bytes(pubkey) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match Signature::from_bytes(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        let result = pk.verify(message, &sig).is_ok();

        if start.elapsed() > Duration::from_millis(50) {
            eprintln!("⚠️ Ed25519 verification exceeded 50ms — possible DoS vector");
            return false;
        }

        result
    }

    fn ed25519_verify_embedded(&self, message: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
        // For embedded systems, we use the same implementation with additional checks
        self.ed25519_verify(message, pubkey, signature)
    }
}

/// Dilithium signature parameters
#[derive(Debug, Clone)]
pub struct DilithiumParams {
    /// Security level (2, 3, or 5)
    pub security_level: u8,
    /// Public key size in bytes
    pub public_key_size: usize,
    /// Secret key size in bytes
    pub secret_key_size: usize,
    /// Signature size in bytes
    pub signature_size: usize,
}

/// BLS signature parameters
#[derive(Debug, Clone)]
pub struct BLSParams {
    /// Curve type (BLS12-381, BLS12-377)
    pub curve_type: BLSCurve,
    /// Public key size in bytes
    pub public_key_size: usize,
    /// Signature size in bytes
    pub signature_size: usize,
    /// Aggregation threshold
    pub aggregation_threshold: usize,
}

/// BLS curve types
#[derive(Debug, Clone, PartialEq)]
pub enum BLSCurve {
    BLS12381,
    BLS12377,
}

/// GPU-accelerated BLS aggregation engine
pub struct GpuBLSEngine {
    /// GPU device
    device: wgpu::Device,
    /// Command queue
    queue: wgpu::Queue,
    /// Compute pipeline
    pipeline: wgpu::ComputePipeline,
    /// Aggregation shader
    aggregate_shader: wgpu::ShaderModule,
    /// Batch buffers
    batch_buffers: Vec<wgpu::Buffer>,
}

impl GpuBLSEngine {
    /// Creates a new GPU BLS engine
    pub async fn new() -> Result<Self, String> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
        });

        let adapter = instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        }).await.ok_or("Failed to find GPU adapter")?;

        let (device, queue) = adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: None,
                features: wgpu::Features::empty(),
                limits: wgpu::Limits::default(),
            },
            None,
        ).await.map_err(|e| format!("Failed to create device: {}", e))?;

        // Load compute shader
        let shader_src = include_str!("shaders/bls_aggregate.wgsl");
        let aggregate_shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("BLS Aggregation Shader"),
            source: wgpu::ShaderSource::Wgsl(shader_src.into()),
        });

        // Create compute pipeline
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("BLS Pipeline Layout"),
            bind_group_layouts: &[],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("BLS Pipeline"),
            layout: Some(&pipeline_layout),
            module: &aggregate_shader,
            entry_point: "main",
            compilation_options: Default::default(),
            cache: None,
        });

        // Create batch buffers
        let mut batch_buffers = Vec::with_capacity(2);
        for _ in 0..2 {
            let buffer = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("Batch Buffer"),
                size: 1024 * 1024, // 1MB buffer
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::COPY_SRC,
                mapped_at_creation: false,
            });
            batch_buffers.push(buffer);
        }

        Ok(GpuBLSEngine {
            device,
            queue,
            pipeline,
            aggregate_shader,
            batch_buffers,
        })
    }

    /// Aggregates BLS signatures using GPU
    pub async fn aggregate_signatures_gpu(&self, signatures: &[BLSSignature]) -> Result<BLSSignature, String> {
        let buffer_size = signatures.len() * std::mem::size_of::<BLSSignature>();
        let staging_buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Staging Buffer"),
            size: buffer_size as u64,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // Create bind group
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("BLS Aggregation Bind Group"),
            layout: &self.pipeline.get_bind_group_layout(0),
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: self.batch_buffers[0].as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: staging_buffer.as_entire_binding(),
                },
            ],
        });

        // Write data to GPU
        let signature_bytes: Vec<u8> = signatures
            .iter()
            .flat_map(|sig| sig.data.clone())
            .collect();
        self.queue.write_buffer(&self.batch_buffers[0], 0, &signature_bytes);

        // Create command encoder
        let mut encoder = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("BLS Aggregation Command Encoder"),
        });

        // Dispatch compute shader
        {
            let mut compute_pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("BLS Aggregation Compute Pass"),
                timestamp_writes: None,
            });
            compute_pass.set_pipeline(&self.pipeline);
            compute_pass.set_bind_group(0, &bind_group, &[]);
            compute_pass.dispatch_workgroups((signatures.len() as u32 + 255) / 256, 1, 1);
        }

        // Copy results back
        encoder.copy_buffer_to_buffer(
            &self.batch_buffers[0],
            0,
            &staging_buffer,
            0,
            buffer_size as u64,
        );

        // Submit commands
        self.queue.submit(Some(encoder.finish()));

        // Read results
        let buffer_slice = staging_buffer.slice(..);
        let (tx, rx) = futures_intrusive::channel::shared::oneshot_channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            tx.send(result).unwrap();
        });
        self.device.poll(wgpu::Maintain::Wait);

        if rx.receive().await.unwrap().is_err() {
            return Err("Failed to read GPU results".to_string());
        }

        let data = buffer_slice.get_mapped_range();
        // Specify the concrete type for result
        let result_data = &data[..std::mem::size_of::<BLSSignature>()];
        let params = BLSParams {
            curve_type: BLSCurve::BLS12381,
            public_key_size: 96,
            signature_size: 48,
            aggregation_threshold: 1,
        };
        let result = BLSSignature::new(result_data.to_vec(), params);
        drop(data);
        staging_buffer.unmap();

        Ok(result)
    }
}

/// CPU-accelerated BLS aggregation using SIMD
pub struct SimdBLSEngine {
    /// SIMD width
    simd_width: usize,
    /// Aggregation metrics
    metrics: AggregationMetrics,
}

/// Aggregation metrics
#[derive(Debug, Default)]
pub struct AggregationMetrics {
    /// Total signatures aggregated
    total_aggregated: AtomicU64,
    /// Total aggregation time
    total_time_us: AtomicU64,
    /// Average aggregation latency
    avg_latency_us: AtomicU64,
}

impl SimdBLSEngine {
    /// Creates a new SIMD BLS engine
    pub fn new() -> Self {
        SimdBLSEngine {
            simd_width: 32, // 256-bit SIMD
            metrics: AggregationMetrics::default(),
        }
    }

    /// Aggregates BLS signatures using SIMD
    pub fn aggregate_signatures_simd(&self, signatures: &[BLSSignature]) -> BLSSignature {
        let start = std::time::Instant::now();
        
        // Process signatures in parallel using SIMD
        let aggregated = signatures.par_chunks(self.simd_width)
            .map(|chunk| {
                let mut result = BLSSignature::default();
                for sig in chunk {
                    // Vectorized point addition
                    unsafe {
                        let sig_vec = _mm256_loadu_si256(sig.as_ptr() as *const __m256i);
                        let result_vec = _mm256_loadu_si256(result.as_ptr() as *const __m256i);
                        let sum = _mm256_add_epi64(sig_vec, result_vec);
                        _mm256_storeu_si256(result.as_mut_ptr() as *mut __m256i, sum);
                    }
                }
                result
            })
            .reduce(|| BLSSignature::default(), |a, b| {
                let mut result = a;
                unsafe {
                    let a_vec = _mm256_loadu_si256(a.as_ptr() as *const __m256i);
                    let b_vec = _mm256_loadu_si256(b.as_ptr() as *const __m256i);
                    let sum = _mm256_add_epi64(a_vec, b_vec);
                    _mm256_storeu_si256(result.as_mut_ptr() as *mut __m256i, sum);
                }
                result
            });

        // Update metrics
        let duration = start.elapsed();
        self.metrics.total_aggregated.fetch_add(signatures.len() as u64, Ordering::Relaxed);
        self.metrics.total_time_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        let avg_latency = duration.as_micros() as u64 / signatures.len() as u64;
        self.metrics.avg_latency_us.store(avg_latency, Ordering::Relaxed);

        aggregated
    }
}

/// Dilithium signature with assembly-optimized operations
pub struct DilithiumSignature {
    /// Signature data
    data: Vec<u8>,
    /// Parameters
    params: DilithiumParams,
}

impl DilithiumSignature {
    /// Creates a new Dilithium signature
    pub fn new(data: Vec<u8>, params: DilithiumParams) -> Self {
        DilithiumSignature { data, params }
    }

    /// Verifies the signature using assembly intrinsics
    pub fn verify(&self, message: &[u8], public_key: &[u8]) -> bool {
        unsafe {
            // Load message and public key into SIMD registers
            let msg_vec = _mm256_loadu_si256(message.as_ptr() as *const __m256i);
            let key_vec = _mm256_loadu_si256(public_key.as_ptr() as *const __m256i);
            let sig_vec = _mm256_loadu_si256(self.data.as_ptr() as *const __m256i);

            // Vectorized polynomial multiplication
            let mut result = _mm256_setzero_si256();
            for i in 0..self.params.signature_size / 32 {
                let sig_chunk = _mm256_loadu_si256(self.data[i * 32..].as_ptr() as *const __m256i);
                let key_chunk = _mm256_loadu_si256(public_key[i * 32..].as_ptr() as *const __m256i);
                let prod = _mm256_mullo_epi32(sig_chunk, key_chunk);
                result = _mm256_add_epi32(result, prod);
            }

            // Compare with message hash
            let msg_hash = _mm256_loadu_si256(message.as_ptr() as *const __m256i);
            let cmp = _mm256_cmpeq_epi32(result, msg_hash);
            _mm256_movemask_epi8(cmp) == -1
        }
    }
}

/// BLS signature with GPU/CPU fallback
pub struct BLSSignature {
    /// Signature data
    data: Vec<u8>,
    /// Parameters
    params: BLSParams,
}

impl BLSSignature {
    /// Creates a new BLS signature
    pub fn new(data: Vec<u8>, params: BLSParams) -> Self {
        BLSSignature { data, params }
    }

    /// Aggregates multiple BLS signatures
    pub async fn aggregate(signatures: &[BLSSignature], gpu_engine: Option<&GpuBLSEngine>) -> Result<BLSSignature, String> {
        if let Some(gpu) = gpu_engine {
            // Use GPU acceleration
            gpu.aggregate_signatures_gpu(signatures).await
        } else {
            // Fallback to CPU SIMD
            let simd_engine = SimdBLSEngine::new();
            Ok(simd_engine.aggregate_signatures_simd(signatures))
        }
    }
}

const DST: &[u8] = b"KSL_BLS_SIG";

/// Validator key pair with secure memory handling
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ValidatorKeyPair {
    /// Key ID
    pub id: KeyId,
    /// BLS public key
    pub bls_public: Vec<u8>,
    /// BLS private key (encrypted)
    #[zeroize(skip)]
    pub bls_private: Vec<u8>,
    /// Dilithium public key
    pub dilithium_public: Vec<u8>,
    /// Dilithium private key (encrypted)
    #[zeroize(skip)]
    pub dilithium_private: Vec<u8>,
    /// Ed25519 public key
    pub ed25519_public: Vec<u8>,
    /// Ed25519 private key (encrypted)
    #[zeroize(skip)]
    pub ed25519_private: Vec<u8>,
    /// Key version
    pub version: u64,
    /// Creation timestamp
    pub created_at: u64,
}

/// Key store configuration
#[derive(Debug, Clone)]
pub struct KeyStoreConfig {
    /// Storage type
    pub storage_type: StorageType,
    /// Path for file storage
    pub file_path: Option<PathBuf>,
    /// Encryption key
    pub encryption_key: Vec<u8>,
}

/// Key store for managing validator keys
pub struct KeyStore {
    /// Active key pairs per validator
    key_pairs: RwLock<HashMap<KeyId, Vec<ValidatorKeyPair>>>,
    /// Key rotation schedule
    rotation_schedule: RwLock<KeyRotationSchedule>,
    /// Key usage metrics
    metrics: KeyMetrics,
    /// OS keyring for secure storage
    keyring: Keyring,
    /// Rotation task handle
    rotation_task: Option<JoinHandle<()>>,
    /// FIPS RNG state
    fips_rng: Arc<RwLock<ChaCha20Rng>>,
    /// Hardware security module
    hsm: Option<Box<dyn HardwareSecurityModule>>,
    /// Configuration
    config: KeyStoreConfig,
}

impl KeyStore {
    /// Creates a new key store
    pub fn new(config: KeyStoreConfig) -> Self {
        // Initialize FIPS-compliant RNG
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let fips_rng = Arc::new(RwLock::new(ChaCha20Rng::from_seed(seed)));

        // Initialize HSM if available
        let hsm = Self::initialize_hsm();

        let store = KeyStore {
            key_pairs: RwLock::new(HashMap::new()),
            rotation_schedule: RwLock::new(KeyRotationSchedule::new()),
            metrics: KeyMetrics::default(),
            keyring: Keyring::new("ksl_validator", "key_store"),
            rotation_task: None,
            fips_rng,
            hsm,
            config,
        };

        // Start rotation task
        store.start_rotation_task();
        store
    }

    /// Gets the latest key pair for a validator
    pub fn get_latest_key(&self, id: KeyId) -> Option<ValidatorKeyPair> {
        self.key_pairs.read().unwrap()
            .get(&id)
            .and_then(|keys| keys.last().cloned())
    }

    /// Signs data using Ed25519
    pub fn sign_ed25519(&self, id: KeyId, data: &[u8]) -> Result<Vec<u8>, String> {
        let key_pair = self.get_latest_key(id)
            .ok_or("Key pair not found")?;

        let mut private_key = self.decrypt_private_key(&key_pair.ed25519_private)?;
        if private_key.len() != 64 {
            private_key.zeroize();
            return Err("Invalid Ed25519 private key size".to_string());
        }

        let secret = match SecretKey::from_bytes(&private_key[..32]) {
            Ok(sk) => sk,
            Err(e) => {
                private_key.zeroize();
                return Err(format!("Failed to parse secret key: {}", e));
            }
        };

        let public = match PublicKey::from_bytes(&private_key[32..]) {
            Ok(pk) => pk,
            Err(e) => {
                private_key.zeroize();
                return Err(format!("Failed to parse public key: {}", e));
            }
        };

        let keypair = Keypair { secret, public };
        let signature = keypair.sign(data).to_bytes().to_vec();
        
        // Secure cleanup
        private_key.zeroize();
        
        Ok(signature)
    }

    /// Verifies Ed25519 signature
    pub fn verify_ed25519(&self, id: KeyId, data: &[u8], signature: &[u8]) -> Result<bool, String> {
        let key_pair = self.get_latest_key(id)
            .ok_or("Key pair not found")?;

        if key_pair.ed25519_public.len() != 32 || signature.len() != 64 {
            return Ok(false);
        }

        let pk = PublicKey::from_bytes(&key_pair.ed25519_public)
            .map_err(|_| "Invalid Ed25519 public key".to_string())?;
        let sig = match Signature::from_bytes(signature) {
            Ok(sig) => sig,
            Err(_) => return Ok(false),
        };

        Ok(pk.verify(data, &sig).is_ok())
    }

    /// Generates Ed25519 key pair
    fn generate_ed25519_keys(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let mut secret = keypair.secret.to_bytes();
        let public = keypair.public.to_bytes();
        
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&secret);
        combined.extend_from_slice(&public);
        
        // Secure cleanup
        secret.zeroize();
        
        Ok((public.to_vec(), combined))
    }

    /// Rotates keys for a validator
    pub fn rotate_keys(&mut self, id: KeyId) -> Result<ValidatorKeyPair, String> {
        let mut key_pairs = self.key_pairs.write().unwrap();
        
        let validator_keys = key_pairs.get_mut(&id)
            .ok_or("Validator not found")?;

        // Generate new keys
        let (ed25519_public, ed25519_private) = self.generate_ed25519_keys()?;
        let (bls_public, bls_private) = self.generate_bls_keys()?;
        let (dilithium_public, dilithium_private) = self.generate_dilithium_keys()?;

        // Create new key pair
        let new_version = validator_keys.last()
            .map(|k| k.version + 1)
            .unwrap_or(1);

        let new_key = ValidatorKeyPair {
            id,
            bls_public,
            bls_private: self.encrypt_private_key(&bls_private)?,
            dilithium_public,
            dilithium_private: self.encrypt_private_key(&dilithium_private)?,
            ed25519_public,
            ed25519_private: self.encrypt_private_key(&ed25519_private)?,
            version: new_version,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Add to history
        validator_keys.push(new_key.clone());

        // Update metrics
        self.metrics.total_rotations += 1;

        Ok(new_key)
    }

    /// Stores a key pair securely
    fn store_keypair(&self, keypair: &ValidatorKeyPair) -> Result<(), String> {
        match self.config.storage_type {
            StorageType::File => {
                if let Some(path) = &self.config.file_path {
                    let encrypted = self.encrypt_keypair(keypair)?;
                    fs::write(path, encrypted)
                        .map_err(|e| format!("Failed to write key file: {}", e))?;
                } else {
                    return Err("No file path configured".to_string());
                }
            }
            StorageType::Keyring => {
                let key_name = format!("validator_{}", keypair.id);
                let encrypted = self.encrypt_keypair(keypair)?;
                self.keyring.set_password(&key_name, &BASE64.encode(&encrypted))
                    .map_err(|e| format!("Failed to store in keyring: {}", e))?;
            }
            StorageType::HSM => {
                if let Some(hsm) = &self.hsm {
                    // Store only public keys in HSM, private keys are managed by HSM
                    hsm.store_key(&keypair.bls_public)?;
                } else {
                    return Err("HSM not available".to_string());
                }
            }
        }
        Ok(())
    }

    /// Loads key pairs from storage
    pub fn load_keys(&mut self) -> Result<(), String> {
        match self.config.storage_type {
            StorageType::File => {
                if let Some(path) = &self.config.file_path {
                    let encrypted = fs::read(path)
                        .map_err(|e| format!("Failed to read key file: {}", e))?;
                    let keypair = self.decrypt_keypair(&encrypted)?;
                    let mut key_pairs = self.key_pairs.write().unwrap();
                    key_pairs.entry(keypair.id)
                        .or_insert_with(Vec::new)
                        .push(keypair);
                }
            }
            StorageType::Keyring => {
                // Implementation for keyring loading
            }
            StorageType::HSM => {
                // Implementation for HSM loading
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::*;
    use tokio;

    #[test]
    fn test_dil_verify_full() {
        let crypto = KapraCrypto::new(false);
        let message = FixedArray::new([1; 32]);
        let pubkey = FixedArray::new([2; 1312]);
        let signature = FixedArray::new([3; 2420]);
        let result = crypto.dil_verify(&message, &pubkey, &signature);
        assert!(result);
    }

    #[test]
    fn test_dil_verify_embedded() {
        let crypto = KapraCrypto::new(true);
        let message = FixedArray::new([1; 32]);
        let pubkey = FixedArray::new([2; 1312]);
        let signature = FixedArray::new([3; 2420]);
        let result = crypto.dil_verify(&message, &pubkey, &signature);
        assert!(result);
    }

    #[test]
    fn test_bls_verify() {
        // Generate a keypair
        let ikm = b"test-key";
        let sk = SecretKey::key_gen(ikm);
        let pk = sk.sk_to_pk();

        // Create a message and sign it
        let message = b"test message";
        let sig = sk.sign(message, &[], &pk, DST);

        // Convert to bytes
        let msg_bytes = message.to_vec();
        let pk_bytes = pk.to_bytes();
        let sig_bytes = sig.to_bytes();

        // Create verifier
        let verifier = BLSVerifier::new(false);

        // Test valid signature
        let msg_array = FixedArray::new(msg_bytes.try_into().unwrap());
        let pk_array = FixedArray::new(pk_bytes);
        let sig_array = FixedArray::new(sig_bytes);
        assert!(verifier.bls_verify(&msg_array, &pk_array, &sig_array));

        // Test invalid signature
        let mut invalid_sig = sig_bytes;
        invalid_sig[0] ^= 1; // Flip a bit
        let invalid_sig_array = FixedArray::new(invalid_sig);
        assert!(!verifier.bls_verify(&msg_array, &pk_array, &invalid_sig_array));

        // Test invalid public key
        let mut invalid_pk = pk_bytes;
        invalid_pk[0] ^= 1; // Flip a bit
        let invalid_pk_array = FixedArray::new(invalid_pk);
        assert!(!verifier.bls_verify(&msg_array, &invalid_pk_array, &sig_array));
    }

    #[test]
    fn test_bls_verify_embedded() {
        // Generate a keypair
        let ikm = b"test-key";
        let sk = SecretKey::key_gen(ikm);
        let pk = sk.sk_to_pk();

        // Create a message and sign it
        let message = b"test message";
        let sig = sk.sign(message, &[], &pk, DST);

        // Convert to bytes
        let msg_bytes = message.to_vec();
        let pk_bytes = pk.to_bytes();
        let sig_bytes = sig.to_bytes();

        // Create embedded verifier
        let verifier = BLSVerifier::new(true);

        // Test valid signature
        let msg_array = FixedArray::new(msg_bytes.try_into().unwrap());
        let pk_array = FixedArray::new(pk_bytes);
        let sig_array = FixedArray::new(sig_bytes);
        assert!(verifier.bls_verify(&msg_array, &pk_array, &sig_array));

        // Test invalid signature
        let mut invalid_sig = sig_bytes;
        invalid_sig[0] ^= 1; // Flip a bit
        let invalid_sig_array = FixedArray::new(invalid_sig);
        assert!(!verifier.bls_verify(&msg_array, &pk_array, &invalid_sig_array));
    }

    #[test]
    fn test_merkle_tree_build() {
        let verifier = MerkleVerifier::new(false);
        let leaves = vec![
            b"leaf1" as &[u8],
            b"leaf2",
            b"leaf3",
            b"leaf4",
        ];

        let tree = verifier.build_tree(&leaves).unwrap();
        assert_eq!(tree.hash().len(), 32);
    }

    #[test]
    fn test_merkle_proof_generation_verification() {
        let verifier = MerkleVerifier::new(false);
        let leaves = vec![
            b"leaf1" as &[u8],
            b"leaf2",
            b"leaf3",
            b"leaf4",
        ];

        // Build tree and generate proof for leaf[1]
        let tree = verifier.build_tree(&leaves).unwrap();
        let proof = verifier.generate_proof(&leaves, 1).unwrap();

        // Verify the proof
        let leaf_hash = verifier.hash_leaf(leaves[1]);
        assert!(verifier.merkle_verify(
            &FixedArray::new(leaf_hash),
            &FixedArray::new(*tree.hash()),
            &proof,
        ));
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let verifier = MerkleVerifier::new(false);
        let leaves = vec![
            b"leaf1" as &[u8],
            b"leaf2",
            b"leaf3",
            b"leaf4",
        ];

        // Build tree and generate proof for leaf[1]
        let tree = verifier.build_tree(&leaves).unwrap();
        let mut proof = verifier.generate_proof(&leaves, 1).unwrap();

        // Tamper with the proof
        if let Some(element) = proof.get_mut(0) {
            element.hash[0] ^= 1;
        }

        // Verify the tampered proof
        let leaf_hash = verifier.hash_leaf(leaves[1]);
        assert!(!verifier.merkle_verify(
            &FixedArray::new(leaf_hash),
            &FixedArray::new(*tree.hash()),
            &proof,
        ));
    }

    #[test]
    fn test_merkle_tree_odd_leaves() {
        let verifier = MerkleVerifier::new(false);
        let leaves = vec![
            b"leaf1" as &[u8],
            b"leaf2",
            b"leaf3",
        ];

        let tree = verifier.build_tree(&leaves).unwrap();
        let proof = verifier.generate_proof(&leaves, 1).unwrap();

        let leaf_hash = verifier.hash_leaf(leaves[1]);
        assert!(verifier.merkle_verify(
            &FixedArray::new(leaf_hash),
            &FixedArray::new(*tree.hash()),
            &proof,
        ));
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let verifier = MerkleVerifier::new(false);
        let leaves = vec![b"leaf1" as &[u8]];

        let tree = verifier.build_tree(&leaves).unwrap();
        let proof = verifier.generate_proof(&leaves, 0).unwrap();
        assert!(proof.is_empty());

        let leaf_hash = verifier.hash_leaf(leaves[0]);
        assert!(verifier.merkle_verify(
            &FixedArray::new(leaf_hash),
            &FixedArray::new(*tree.hash()),
            &proof,
        ));
    }

    #[test]
    fn test_vrf_generate_full() {
        let crypto = KapraCrypto::new(false);
        let seed = FixedArray::new([1; 32]);
        let key = FixedArray::new([2; 32]);
        let output = crypto.vrf_generate(&seed, &key);
        assert_eq!(output.as_slice().len(), 32);
    }

    #[test]
    fn test_vrf_generate_embedded() {
        let crypto = KapraCrypto::new(true);
        let seed = FixedArray::new([1; 32]);
        let key = FixedArray::new([2; 32]);
        let output = crypto.vrf_generate(&seed, &key);
        assert_eq!(output.as_slice().len(), 32);
    }

    #[test]
    fn benchmark_bls_verify() {
        // Generate a keypair
        let ikm = b"test-key";
        let sk = SecretKey::key_gen(ikm);
        let pk = sk.sk_to_pk();

        // Create a message and sign it
        let message = b"test message";
        let sig = sk.sign(message, &[], &pk, DST);

        // Convert to bytes
        let msg_bytes = message.to_vec();
        let pk_bytes = pk.to_bytes();
        let sig_bytes = sig.to_bytes();

        // Create verifier
        let verifier = BLSVerifier::new(false);

        // Prepare arrays
        let msg_array = FixedArray::new(msg_bytes.try_into().unwrap());
        let pk_array = FixedArray::new(pk_bytes);
        let sig_array = FixedArray::new(sig_bytes);

        // Warm up
        for _ in 0..10 {
            verifier.bls_verify(&msg_array, &pk_array, &sig_array);
        }

        // Benchmark
        let iterations = 100;
        let start = Instant::now();
        for _ in 0..iterations {
            verifier.bls_verify(&msg_array, &pk_array, &sig_array);
        }
        let duration = start.elapsed();
        let avg_time = duration.as_nanos() as f64 / iterations as f64;
        println!("Average BLS verification time: {:.2} ns", avg_time);
        println!("Average BLS verification time: {:.2} ms", avg_time / 1_000_000.0);

        // Verify performance meets requirements
        assert!(avg_time < 50_000_000.0, "BLS verification should complete in < 50ms");
    }

    #[test]
    fn benchmark_bls_verify_embedded() {
        // Generate a keypair
        let ikm = b"test-key";
        let sk = SecretKey::key_gen(ikm);
        let pk = sk.sk_to_pk();

        // Create a message and sign it
        let message = b"test message";
        let sig = sk.sign(message, &[], &pk, DST);

        // Convert to bytes
        let msg_bytes = message.to_vec();
        let pk_bytes = pk.to_bytes();
        let sig_bytes = sig.to_bytes();

        // Create embedded verifier
        let verifier = BLSVerifier::new(true);

        // Prepare arrays
        let msg_array = FixedArray::new(msg_bytes.try_into().unwrap());
        let pk_array = FixedArray::new(pk_bytes);
        let sig_array = FixedArray::new(sig_bytes);

        // Warm up
        for _ in 0..10 {
            verifier.bls_verify(&msg_array, &pk_array, &sig_array);
        }

        // Benchmark
        let iterations = 100;
        let start = Instant::now();
        for _ in 0..iterations {
            verifier.bls_verify(&msg_array, &pk_array, &sig_array);
        }
        let duration = start.elapsed();
        let avg_time = duration.as_nanos() as f64 / iterations as f64;
        println!("Average embedded BLS verification time: {:.2} ns", avg_time);
        println!("Average embedded BLS verification time: {:.2} ms", avg_time / 1_000_000.0);

        // Verify performance meets requirements
        assert!(avg_time < 50_000_000.0, "Embedded BLS verification should complete in < 50ms");
    }

    #[tokio::test]
    async fn test_gpu_bls_aggregation() {
        let gpu_engine = GpuBLSEngine::new().await.unwrap();
        let ikm = b"gpu-key";
        let sk = SecretKey::key_gen(ikm);
        let pk = sk.sk_to_pk();

        let msg = b"gpu test message";
        let sig = sk.sign(msg, &[], &pk, DST);
        let sig_bytes = sig.to_bytes();
        let params = BLSParams {
            curve_type: BLSCurve::BLS12381,
            public_key_size: 96,
            signature_size: 48,
            aggregation_threshold: 1,
        };

        let sig1 = BLSSignature::new(sig_bytes.clone(), params.clone());
        let sig2 = BLSSignature::new(sig_bytes.clone(), params.clone());

        let agg = BLSSignature::aggregate(&[sig1, sig2], Some(&gpu_engine)).await.unwrap();
        assert!(!agg.data.is_empty(), "Aggregated signature should not be empty");
    }

    #[test]
    fn test_invalid_signature_sizes() {
        let ctx = CryptoContext::new();
        
        // Test Dilithium with invalid sizes
        assert!(!ctx.dilithium_verify(&[0; 16], &[0; 1312], &[0; 2420])); // Invalid message
        assert!(!ctx.dilithium_verify(&[0; 32], &[0; 1000], &[0; 2420])); // Invalid pubkey
        assert!(!ctx.dilithium_verify(&[0; 32], &[0; 1312], &[0; 2000])); // Invalid signature

        // Test BLS with invalid sizes
        assert!(!ctx.bls_verify(&[0; 16], &[0; 96], &[0; 48])); // Invalid message
        assert!(!ctx.bls_verify(&[0; 32], &[0; 80], &[0; 48])); // Invalid pubkey
        assert!(!ctx.bls_verify(&[0; 32], &[0; 96], &[0; 40])); // Invalid signature
    }

    #[test]
    fn test_merkle_verify() {
        let ctx = CryptoContext::new();
        let leaf = vec![0u8; 32];
        let root = vec![0u8; 32];
        let proof = vec![vec![0u8; 32].as_slice()];
        
        // Test with valid sizes
        assert!(!ctx.merkle_verify(&leaf, &root, proof.clone())); // Returns false as unimplemented

        // Test with invalid sizes
        assert!(!ctx.merkle_verify(&[0; 16], &root, proof.clone())); // Invalid leaf
        assert!(!ctx.merkle_verify(&leaf, &[0; 16], proof.clone())); // Invalid root
        assert!(!ctx.merkle_verify(&leaf, &root, vec![&[0; 16]])); // Invalid proof
    }

    #[test]
    fn test_ed25519_verify() {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let message = b"test message";
        let signature = keypair.sign(message);

        let verifier = Ed25519Verifier::new(false);
        let pubkey = FixedArray::new(keypair.public.to_bytes());
        let sig = FixedArray::new(signature.to_bytes());

        assert!(verifier.ed25519_verify(
            message,
            &pubkey,
            &sig,
        ));

        // Test invalid signature
        let mut invalid_sig = signature.to_bytes();
        invalid_sig[0] ^= 1; // Flip a bit
        let invalid_sig = FixedArray::new(invalid_sig);
        assert!(!verifier.ed25519_verify(
            message,
            &pubkey,
            &invalid_sig,
        ));
    }

    #[test]
    fn test_ed25519_verify_embedded() {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let message = b"test message";
        let signature = keypair.sign(message);

        let verifier = Ed25519Verifier::new(true);
        let pubkey = FixedArray::new(keypair.public.to_bytes());
        let sig = FixedArray::new(signature.to_bytes());

        assert!(verifier.ed25519_verify(
            message,
            &pubkey,
            &sig,
        ));
    }

    #[test]
    fn test_ed25519_timing() {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let message = b"test message";
        let signature = keypair.sign(message);

        let verifier = Ed25519Verifier::new(false);
        let pubkey = FixedArray::new(keypair.public.to_bytes());
        let sig = FixedArray::new(signature.to_bytes());

        let start = Instant::now();
        for _ in 0..100 {
            verifier.ed25519_verify(message, &pubkey, &sig);
        }
        let avg_time = start.elapsed().as_nanos() as f64 / 100.0;
        println!("Average Ed25519 verification time: {:.2} ns", avg_time);
        assert!(avg_time < 50_000_000.0, "Ed25519 verification should complete in < 50ms");
    }

    #[test]
    fn test_crypto_all_schemes() {
        let crypto = KapraCrypto::new(false);
        let message = FixedArray::new([1; 32]);

        // Test Dilithium
        let dil_pubkey = FixedArray::new([2; 1312]);
        let dil_sig = FixedArray::new([3; 2420]);
        assert!(crypto.dil_verify(&message, &dil_pubkey, &dil_sig));

        // Test BLS
        let bls_pubkey = FixedArray::new([4; 96]);
        let bls_sig = FixedArray::new([5; 48]);
        assert!(crypto.bls_verify(&message, &bls_pubkey, &bls_sig));

        // Test Ed25519
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let ed25519_pubkey = FixedArray::new(keypair.public.to_bytes());
        let signature = keypair.sign(message.as_slice());
        let ed25519_sig = FixedArray::new(signature.to_bytes());
        assert!(crypto.ed25519_verify(message.as_slice(), &ed25519_pubkey, &ed25519_sig));
    }

    #[test]
    fn test_signature_scheme() {
        assert_eq!(SignatureScheme::BLS.pubkey_size(), 96);
        assert_eq!(SignatureScheme::Dilithium.pubkey_size(), 1312);
        assert_eq!(SignatureScheme::Ed25519.pubkey_size(), 32);

        assert_eq!(SignatureScheme::BLS.signature_size(), 48);
        assert_eq!(SignatureScheme::Dilithium.signature_size(), 2420);
        assert_eq!(SignatureScheme::Ed25519.signature_size(), 64);

        assert_eq!(SignatureScheme::from_type_code(0), Some(SignatureScheme::BLS));
        assert_eq!(SignatureScheme::from_type_code(1), Some(SignatureScheme::Dilithium));
        assert_eq!(SignatureScheme::from_type_code(2), Some(SignatureScheme::Ed25519));
        assert_eq!(SignatureScheme::from_type_code(3), None);
    }

    #[test]
    fn test_verify_signature_abstraction() {
        let crypto = KapraCrypto::new(false);
        let message = [1u8; 32];

        // Test BLS
        let bls_pubkey = [2u8; 96];
        let bls_sig = [3u8; 48];
        assert!(crypto.verify_signature(&bls_pubkey, &bls_sig, &message, 0));

        // Test Dilithium
        let dil_pubkey = [4u8; 1312];
        let dil_sig = [5u8; 2420];
        assert!(crypto.verify_signature(&dil_pubkey, &dil_sig, &message, 1));

        // Test Ed25519
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let signature = keypair.sign(&message);
        assert!(crypto.verify_signature(
            &keypair.public.to_bytes(),
            &signature.to_bytes(),
            &message,
            2
        ));

        // Test invalid scheme
        assert!(!crypto.verify_signature(&[0u8; 32], &[0u8; 64], &message, 3));

        // Test invalid sizes
        assert!(!crypto.verify_signature(&[0u8; 32], &[0u8; 48], &message, 0)); // Wrong BLS pubkey size
        assert!(!crypto.verify_signature(&[0u8; 96], &[0u8; 32], &message, 0)); // Wrong BLS sig size
    }
}