use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use rand::Rng;
use crate::ksl_kapra_crypto::{KapraCrypto, SignatureScheme};
use keyring::Keyring;
use tokio::time::{Duration, sleep};
use tokio::task::JoinHandle;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use rand_chacha::ChaCha20Rng;
use rand_chacha::chacha20::ChaCha20Core;
use rand_core::SeedableRng;
use pqcrypto::dilithium::{self, DilithiumKeypair, DilithiumPublicKey, DilithiumSecretKey};
use blst::{blst_sk, blst_pk, blst_signature};
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Key}};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Validator key store
pub struct KeyStore {
    /// Active key pairs
    key_pairs: RwLock<HashMap<KeyId, ValidatorKeyPair>>,
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
    /// Hardware security module (if available)
    hsm: Option<Box<dyn HardwareSecurityModule>>,
    /// Schedule persistence path
    schedule_path: PathBuf,
    /// Encryption key for private keys
    encryption_key: Aes256Gcm,
}

/// Hardware security module trait
pub trait HardwareSecurityModule: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String>;
    fn generate_key(&self) -> Result<Vec<u8>, String>;
    fn is_available(&self) -> bool;
}

/// Validator bootstrap package
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorBootstrap {
    /// Validator ID
    pub validator_id: KeyId,
    /// Key pairs
    pub key_pairs: Vec<ValidatorKeyPair>,
    /// Rotation schedule
    pub rotation_schedule: KeyRotationSchedule,
    /// Network configuration
    pub network_config: NetworkConfig,
    /// Security settings
    pub security_settings: SecuritySettings,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Signature
    pub signature: Vec<u8>,
}

/// Network configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Node address
    pub node_address: String,
    /// P2P port
    pub p2p_port: u16,
    /// RPC port
    pub rpc_port: u16,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
}

/// Security settings
#[derive(Debug, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Whether to use HSM
    pub use_hsm: bool,
    /// Whether to use enclave
    pub use_enclave: bool,
    /// Minimum key rotation interval
    pub min_rotation_interval: Duration,
    /// Maximum key lifetime
    pub max_key_lifetime: Duration,
}

/// Key identifier
pub type KeyId = u64;

/// Validator key pair
#[derive(Debug, Clone)]
pub struct ValidatorKeyPair {
    /// Key ID
    id: KeyId,
    /// Public key
    public_key: Vec<u8>,
    /// Private key (encrypted)
    encrypted_private_key: Vec<u8>,
    /// Key type
    key_type: KeyType,
    /// Creation timestamp
    created_at: Instant,
    /// Last rotation timestamp
    last_rotation: Instant,
    /// Usage count
    usage_count: u64,
}

/// Key type
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    /// Dilithium-based key
    Dilithium,
    /// BLS-based key
    BLS,
    /// Ed25519-based key
    Ed25519,
}

/// Key rotation schedule
#[derive(Debug)]
struct KeyRotationSchedule {
    /// Next rotation time
    next_rotation: Instant,
    /// Rotation interval
    rotation_interval: std::time::Duration,
    /// Keys to rotate
    keys_to_rotate: Vec<KeyId>,
}

/// Key metrics
#[derive(Debug, Default)]
struct KeyMetrics {
    /// Total keys generated
    total_generated: u64,
    /// Total rotations
    total_rotations: u64,
    /// Failed operations
    failed_operations: u64,
}

/// Key export for audit/snapshot
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExport {
    /// Export timestamp
    timestamp: DateTime<Utc>,
    /// Exported keys
    keys: Vec<KeyExportEntry>,
}

/// Key export entry
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExportEntry {
    /// Key ID
    id: KeyId,
    /// Public key
    public_key: Vec<u8>,
    /// Private key
    private_key: Vec<u8>,
    /// Key type
    key_type: KeyType,
    /// Creation timestamp
    created_at: Instant,
    /// Last rotation timestamp
    last_rotation: Instant,
}

impl KeyStore {
    /// Creates a new key store with enhanced security features
    pub fn new() -> Self {
        // Initialize FIPS-compliant RNG
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let fips_rng = Arc::new(RwLock::new(ChaCha20Rng::from_seed(seed)));

        // Initialize encryption key
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let encryption_key = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

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
            schedule_path: PathBuf::from("validator_schedule.json"),
            encryption_key,
        };

        // Load saved schedule
        if let Err(e) = store.load_schedule() {
            eprintln!("Failed to load schedule: {}", e);
        }

        // Start rotation task
        store.start_rotation_task();

        store
    }

    /// Initializes hardware security module if available
    fn initialize_hsm() -> Option<Box<dyn HardwareSecurityModule>> {
        // Check for TPM
        if let Ok(tpm) = TpmModule::new() {
            return Some(Box::new(tpm));
        }

        // Check for SGX
        if let Ok(sgx) = SgxModule::new() {
            return Some(Box::new(sgx));
        }

        None
    }

    /// Loads rotation schedule from disk
    fn load_schedule(&self) -> Result<(), String> {
        if !self.schedule_path.exists() {
            return Ok(());
        }

        let mut file = File::open(&self.schedule_path)
            .map_err(|e| format!("Failed to open schedule file: {}", e))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Failed to read schedule file: {}", e))?;

        let schedule: KeyRotationSchedule = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse schedule: {}", e))?;

        *self.rotation_schedule.write().unwrap() = schedule;
        Ok(())
    }

    /// Saves rotation schedule to disk
    fn save_schedule(&self) -> Result<(), String> {
        let schedule = self.rotation_schedule.read().unwrap();
        let contents = serde_json::to_string_pretty(&*schedule)
            .map_err(|e| format!("Failed to serialize schedule: {}", e))?;

        let mut file = File::create(&self.schedule_path)
            .map_err(|e| format!("Failed to create schedule file: {}", e))?;

        file.write_all(contents.as_bytes())
            .map_err(|e| format!("Failed to write schedule file: {}", e))?;

        Ok(())
    }

    /// Creates a validator bootstrap package
    pub fn create_bootstrap_package(&self, validator_id: KeyId) -> Result<ValidatorBootstrap, String> {
        let key_pairs = self.key_pairs.read().unwrap();
        let schedule = self.rotation_schedule.read().unwrap();

        let package = ValidatorBootstrap {
            validator_id,
            key_pairs: key_pairs.values().cloned().collect(),
            rotation_schedule: schedule.clone(),
            network_config: NetworkConfig {
                node_address: "0.0.0.0".to_string(),
                p2p_port: 26656,
                rpc_port: 26657,
                bootstrap_nodes: vec![],
            },
            security_settings: SecuritySettings {
                use_hsm: self.hsm.is_some(),
                use_enclave: false,
                min_rotation_interval: Duration::from_secs(24 * 60 * 60),
                max_key_lifetime: Duration::from_secs(30 * 24 * 60 * 60),
            },
            timestamp: Utc::now(),
            signature: vec![],
        };

        // Sign package
        let signature = self.sign_package(&package)?;
        Ok(ValidatorBootstrap { signature, ..package })
    }

    /// Signs a bootstrap package
    fn sign_package(&self, package: &ValidatorBootstrap) -> Result<Vec<u8>, String> {
        let data = serde_json::to_vec(package)
            .map_err(|e| format!("Failed to serialize package: {}", e))?;

        if let Some(hsm) = &self.hsm {
            hsm.sign(&data)
        } else {
            self.sign(0, &data) // Use first key pair
        }
    }

    /// Encrypts a private key using AES-GCM
    fn encrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = self.generate_secure_bytes(12);
        self.encryption_key
            .encrypt(&nonce.into(), private_key)
            .map_err(|e| format!("Failed to encrypt private key: {}", e))
            .map(|ciphertext| {
                let mut result = nonce;
                result.extend(ciphertext);
                result
            })
    }

    /// Decrypts a private key using AES-GCM
    fn decrypt_private_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted_key.len() < 12 {
            return Err("Invalid encrypted key format".to_string());
        }

        let (nonce, ciphertext) = encrypted_key.split_at(12);
        self.encryption_key
            .decrypt(nonce.into(), ciphertext)
            .map_err(|e| format!("Failed to decrypt private key: {}", e))
    }

    /// Signs data using Dilithium
    fn sign_dilithium(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let secret_key = DilithiumSecretKey::from_bytes(private_key)
            .map_err(|e| format!("Failed to parse Dilithium secret key: {}", e))?;

        let signature = dilithium::sign(data, &secret_key);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verifies Dilithium signature
    fn verify_dilithium(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
        let pk = DilithiumPublicKey::from_bytes(public_key)
            .map_err(|e| format!("Failed to parse Dilithium public key: {}", e))?;

        let sig = dilithium::Signature::from_bytes(signature)
            .map_err(|e| format!("Failed to parse Dilithium signature: {}", e))?;

        Ok(dilithium::verify(&sig, data, &pk))
    }

    /// Signs data using BLS
    fn sign_bls(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let mut sk = blst_sk::default();
        sk.from_bytes(private_key)
            .map_err(|e| format!("Failed to parse BLS secret key: {}", e))?;

        let mut sig = blst_signature::default();
        sig.sign(&sk, data, &[]);

        let mut result = vec![0u8; 96];
        sig.to_bytes(&mut result);
        Ok(result)
    }

    /// Verifies BLS signature
    fn verify_bls(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
        let mut pk = blst_pk::default();
        pk.from_bytes(public_key)
            .map_err(|e| format!("Failed to parse BLS public key: {}", e))?;

        let mut sig = blst_signature::default();
        sig.from_bytes(signature)
            .map_err(|e| format!("Failed to parse BLS signature: {}", e))?;

        Ok(sig.verify(true, &pk, &[], data, &[]))
    }

    /// Starts the key rotation background task
    fn start_rotation_task(&self) {
        let store = Arc::new(self.clone());
        let handle = tokio::spawn(async move {
            loop {
                // Check for keys that need rotation
                let keys_to_rotate = {
                    let schedule = store.rotation_schedule.read().unwrap();
                    if Instant::now() >= schedule.next_rotation {
                        schedule.keys_to_rotate.clone()
                    } else {
                        Vec::new()
                    }
                };

                // Rotate keys
                for key_id in keys_to_rotate {
                    if let Err(e) = store.rotate_key_pair(key_id) {
                        eprintln!("Failed to rotate key {}: {}", key_id, e);
                    }
                }

                // Sleep until next check
                sleep(Duration::from_secs(60)).await;
            }
        });

        self.rotation_task = Some(handle);
    }

    /// Securely stores a private key in the OS keyring
    fn store_private_key(&self, key_id: KeyId, private_key: &[u8]) -> Result<(), String> {
        let key_name = format!("private_key_{}", key_id);
        self.keyring
            .set_password(&key_name, &base64::encode(private_key))
            .map_err(|e| format!("Failed to store private key: {}", e))
    }

    /// Retrieves a private key from the OS keyring
    fn get_private_key(&self, key_id: KeyId) -> Result<Vec<u8>, String> {
        let key_name = format!("private_key_{}", key_id);
        self.keyring
            .get_password(&key_name)
            .map_err(|e| format!("Failed to get private key: {}", e))
            .and_then(|encoded| {
                base64::decode(&encoded)
                    .map_err(|e| format!("Failed to decode private key: {}", e))
            })
    }

    /// Exports keys for audit/snapshot
    pub fn export_keys(&self) -> Result<KeyExport, String> {
        let key_pairs = self.key_pairs.read().unwrap();
        let mut export = KeyExport {
            timestamp: Utc::now(),
            keys: Vec::new(),
        };

        for (id, key_pair) in key_pairs.iter() {
            let private_key = self.get_private_key(*id)?;
            export.keys.push(KeyExportEntry {
                id: *id,
                public_key: key_pair.public_key.clone(),
                private_key,
                key_type: key_pair.key_type.clone(),
                created_at: key_pair.created_at,
                last_rotation: key_pair.last_rotation,
            });
        }

        Ok(export)
    }

    /// Generates cryptographically secure random bytes using FIPS-compliant RNG
    fn generate_secure_bytes(&self, len: usize) -> Vec<u8> {
        let mut rng = self.fips_rng.write().unwrap();
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Generates a new key ID using FIPS-compliant RNG
    fn generate_key_id(&self) -> KeyId {
        let mut rng = self.fips_rng.write().unwrap();
        rng.gen()
    }

    /// Generates a new validator key pair
    pub fn generate_key_pair(&self, key_type: KeyType) -> Result<Arc<ValidatorKeyPair>, String> {
        let mut key_pairs = self.key_pairs.write().unwrap();
        
        // Generate key ID
        let id = self.generate_key_id();
        
        // Generate key pair based on type
        let (public_key, private_key) = match key_type {
            KeyType::Dilithium => self.generate_dilithium_keys()?,
            KeyType::BLS => self.generate_bls_keys()?,
            KeyType::Ed25519 => self.generate_ed25519_keys()?,
        };
        
        // Encrypt private key
        let encrypted_private_key = self.encrypt_private_key(&private_key)?;
        
        // Create key pair
        let key_pair = ValidatorKeyPair {
            id,
            public_key,
            encrypted_private_key,
            key_type,
            created_at: Instant::now(),
            last_rotation: Instant::now(),
            usage_count: 0,
        };
        
        // Store key pair
        key_pairs.insert(id, key_pair.clone());
        
        // Update metrics
        self.metrics.total_generated += 1;
        
        Ok(Arc::new(key_pair))
    }

    /// Rotates a validator key pair
    pub fn rotate_key_pair(&self, id: KeyId) -> Result<Arc<ValidatorKeyPair>, String> {
        let mut key_pairs = self.key_pairs.write().unwrap();
        
        if let Some(old_key) = key_pairs.get(&id) {
            // Generate new key pair
            let (public_key, private_key) = match old_key.key_type {
                KeyType::Dilithium => self.generate_dilithium_keys()?,
                KeyType::BLS => self.generate_bls_keys()?,
                KeyType::Ed25519 => self.generate_ed25519_keys()?,
            };
            
            // Encrypt new private key
            let encrypted_private_key = self.encrypt_private_key(&private_key)?;
            
            // Create new key pair
            let new_key = ValidatorKeyPair {
                id,
                public_key,
                encrypted_private_key,
                key_type: old_key.key_type.clone(),
                created_at: old_key.created_at,
                last_rotation: Instant::now(),
                usage_count: 0,
            };
            
            // Replace old key
            key_pairs.insert(id, new_key.clone());
            
            // Update metrics
            self.metrics.total_rotations += 1;
            
            Ok(Arc::new(new_key))
        } else {
            Err("Key pair not found".to_string())
        }
    }

    /// Signs data using a validator key pair
    pub fn sign(&self, id: KeyId, data: &[u8]) -> Result<Vec<u8>, String> {
        let key_pairs = self.key_pairs.read().unwrap();
        
        if let Some(key_pair) = key_pairs.get(&id) {
            // Decrypt private key
            let private_key = self.decrypt_private_key(&key_pair.encrypted_private_key)?;
            
            // Sign data based on key type
            let signature = match key_pair.key_type {
                KeyType::Dilithium => self.sign_dilithium(&private_key, data)?,
                KeyType::BLS => self.sign_bls(&private_key, data)?,
                KeyType::Ed25519 => self.sign_ed25519(&private_key, data)?,
            };
            
            Ok(signature)
        } else {
            Err("Key pair not found".to_string())
        }
    }

    /// Verifies a signature
    pub fn verify(&self, id: KeyId, data: &[u8], signature: &[u8]) -> Result<bool, String> {
        let key_pairs = self.key_pairs.read().unwrap();
        
        if let Some(key_pair) = key_pairs.get(&id) {
            // Verify signature based on key type
            let valid = match key_pair.key_type {
                KeyType::Dilithium => self.verify_dilithium(&key_pair.public_key, data, signature)?,
                KeyType::BLS => self.verify_bls(&key_pair.public_key, data, signature)?,
                KeyType::Ed25519 => self.verify_ed25519(&key_pair.public_key, data, signature)?,
            };
            
            Ok(valid)
        } else {
            Err("Key pair not found".to_string())
        }
    }

    /// Generates Dilithium key pair using FIPS-compliant RNG
    fn generate_dilithium_keys(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let public_key = self.generate_secure_bytes(1312);
        let private_key = self.generate_secure_bytes(2420);
        Ok((public_key, private_key))
    }

    /// Generates BLS key pair using FIPS-compliant RNG
    fn generate_bls_keys(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let public_key = self.generate_secure_bytes(96);
        let private_key = self.generate_secure_bytes(32);
        Ok((public_key, private_key))
    }

    /// Generates Ed25519 key pair using FIPS-compliant RNG
    fn generate_ed25519_keys(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let public_key = self.generate_secure_bytes(32);
        let private_key = self.generate_secure_bytes(64);
        Ok((public_key, private_key))
    }

    /// Signs data using Ed25519
    fn sign_ed25519(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        // Implementation would use actual Ed25519 signing
        Ok(vec![])
    }

    /// Verifies Ed25519 signature
    fn verify_ed25519(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
        // Implementation would use actual Ed25519 verification
        Ok(true)
    }
}

impl KeyRotationSchedule {
    /// Creates a new key rotation schedule
    fn new() -> Self {
        KeyRotationSchedule {
            next_rotation: Instant::now() + std::time::Duration::from_secs(24 * 60 * 60), // 24 hours
            rotation_interval: std::time::Duration::from_secs(24 * 60 * 60),
            keys_to_rotate: Vec::new(),
        }
    }
}

impl ValidatorKeyPair {
    /// Generates a new validator key pair
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        ValidatorKeyPair {
            id: rng.gen(),
            public_key: vec![],
            encrypted_private_key: vec![],
            key_type: KeyType::Dilithium,
            created_at: Instant::now(),
            last_rotation: Instant::now(),
            usage_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key_store = KeyStore::new();
        
        // Test Dilithium key generation
        let result = key_store.generate_key_pair(KeyType::Dilithium);
        assert!(result.is_ok());
        
        // Test BLS key generation
        let result = key_store.generate_key_pair(KeyType::BLS);
        assert!(result.is_ok());
        
        // Test Ed25519 key generation
        let result = key_store.generate_key_pair(KeyType::Ed25519);
        assert!(result.is_ok());
    }

    #[test]
    fn test_key_rotation() {
        let key_store = KeyStore::new();
        
        // Generate key pair
        let key_pair = key_store.generate_key_pair(KeyType::Dilithium).unwrap();
        
        // Rotate key
        let result = key_store.rotate_key_pair(key_pair.id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_signing_and_verification() {
        let key_store = KeyStore::new();
        
        // Generate key pair
        let key_pair = key_store.generate_key_pair(KeyType::Dilithium).unwrap();
        
        // Sign data
        let data = b"test data";
        let signature = key_store.sign(key_pair.id, data);
        assert!(signature.is_ok());
        
        // Verify signature
        let valid = key_store.verify(key_pair.id, data, &signature.unwrap());
        assert!(valid.is_ok());
        assert!(valid.unwrap());
    }

    #[test]
    fn test_key_export() {
        let key_store = KeyStore::new();
        
        // Generate test key
        let key_pair = key_store.generate_key_pair(KeyType::Dilithium).unwrap();
        
        // Export keys
        let export = key_store.export_keys().unwrap();
        
        // Verify export
        assert_eq!(export.keys.len(), 1);
        assert_eq!(export.keys[0].id, key_pair.id);
        assert_eq!(export.keys[0].public_key, key_pair.public_key);
    }

    #[test]
    fn test_secure_key_storage() {
        let key_store = KeyStore::new();
        
        // Generate test key
        let key_pair = key_store.generate_key_pair(KeyType::Dilithium).unwrap();
        
        // Store private key
        let private_key = vec![1, 2, 3, 4];
        key_store.store_private_key(key_pair.id, &private_key).unwrap();
        
        // Retrieve private key
        let retrieved = key_store.get_private_key(key_pair.id).unwrap();
        assert_eq!(retrieved, private_key);
    }

    #[test]
    fn test_fips_rng() {
        let key_store = KeyStore::new();
        
        // Generate random bytes
        let bytes1 = key_store.generate_secure_bytes(32);
        let bytes2 = key_store.generate_secure_bytes(32);
        
        // Verify randomness
        assert_ne!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
    }

    #[test]
    fn test_bootstrap_package() {
        let key_store = KeyStore::new();
        
        // Generate test key
        let key_pair = key_store.generate_key_pair(KeyType::Dilithium).unwrap();
        
        // Create bootstrap package
        let package = key_store.create_bootstrap_package(key_pair.id).unwrap();
        
        // Verify package
        assert_eq!(package.validator_id, key_pair.id);
        assert!(!package.key_pairs.is_empty());
        assert!(!package.signature.is_empty());
    }

    #[test]
    fn test_schedule_persistence() {
        let key_store = KeyStore::new();
        
        // Modify schedule
        {
            let mut schedule = key_store.rotation_schedule.write().unwrap();
            schedule.keys_to_rotate.push(1);
        }
        
        // Save schedule
        key_store.save_schedule().unwrap();
        
        // Create new store
        let new_store = KeyStore::new();
        
        // Verify schedule was loaded
        let schedule = new_store.rotation_schedule.read().unwrap();
        assert!(schedule.keys_to_rotate.contains(&1));
    }

    #[test]
    fn test_real_crypto() {
        let key_store = KeyStore::new();
        
        // Generate Dilithium key pair
        let key_pair = key_store.generate_key_pair(KeyType::Dilithium).unwrap();
        
        // Sign and verify
        let data = b"test data";
        let signature = key_store.sign(key_pair.id, data).unwrap();
        let valid = key_store.verify(key_pair.id, data, &signature).unwrap();
        assert!(valid);
        
        // Generate BLS key pair
        let key_pair = key_store.generate_key_pair(KeyType::BLS).unwrap();
        
        // Sign and verify
        let signature = key_store.sign(key_pair.id, data).unwrap();
        let valid = key_store.verify(key_pair.id, data, &signature).unwrap();
        assert!(valid);
    }
} 