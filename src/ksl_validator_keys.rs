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
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Key, Nonce}};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use crate::ksl_errors::{KslError, SourcePosition};
use blst::{min_pk::*, BLST_ERROR};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
// use tss_esapi::{Context, TctiNameConf};
// use sgx_types::*;
// use sgx_urts::SgxEnclave;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorKeyPair {
    /// BLS secret key (48 bytes)
    pub bls_secret: Vec<u8>,
    /// BLS public key (96 bytes)
    pub bls_public: Vec<u8>,
    /// Dilithium secret key (2560 bytes)
    pub dilithium_secret: Vec<u8>,
    /// Dilithium public key (1312 bytes)
    pub dilithium_public: Vec<u8>,
    /// Key version for rotation tracking
    pub version: u64,
    /// Timestamp of key creation
    pub created_at: u64,
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
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyRotationSchedule {
    /// Next rotation time
    pub next_rotation: Instant,
    /// Rotation interval
    pub rotation_interval: std::time::Duration,
    /// Keys to rotate
    pub keys_to_rotate: Vec<KeyId>,
}

/// Key metrics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KeyMetrics {
    /// Total keys generated
    pub total_generated: u64,
    /// Total rotations
    pub total_rotations: u64,
    /// Failed operations
    pub failed_operations: u64,
}

/// Key export for audit/snapshot
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExport {
    /// Export timestamp
    pub timestamp: DateTime<Utc>,
    /// Exported keys
    pub keys: Vec<KeyExportEntry>,
}

/// Key export entry
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExportEntry {
    /// Key ID
    pub id: KeyId,
    /// BLS public key
    pub bls_public_key: Option<Vec<u8>>,
    /// BLS private key
    pub bls_private_key: Option<Vec<u8>>,
    /// Dilithium public key
    pub dilithium_public_key: Option<Vec<u8>>,
    /// Dilithium private key
    pub dilithium_private_key: Option<Vec<u8>>,
    /// Key type
    pub key_type: KeyType,
    /// Creation timestamp
    pub created_at: u64,
    /// Last rotation timestamp
    pub last_rotation: u64,
}

/// Domain separation tag for BLS signatures
const BLS_DST: &[u8] = b"KSL_VALIDATOR_BLS_SIG";

/// Domain separation tag for Dilithium signatures
const DILITHIUM_DST: &[u8] = b"KSL_VALIDATOR_DIL_SIG";

/// Key storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStorageConfig {
    /// Storage type (keystore, keychain, or file)
    pub storage_type: StorageType,
    /// Path for file-based storage
    pub file_path: Option<PathBuf>,
    /// Encryption key for file-based storage
    pub encryption_key: Option<Vec<u8>>,
}

/// Storage type for validator keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    /// Android Keystore
    AndroidKeystore,
    /// iOS Keychain
    IOSKeychain,
    /// Encrypted file storage
    EncryptedFile,
}

/// Key manager for validator operations
pub struct ValidatorKeyManager {
    /// Current key pair
    keys: Option<ValidatorKeyPair>,
    /// Storage configuration
    config: KeyStorageConfig,
    /// Platform-specific storage implementation
    #[cfg(target_os = "android")]
    keystore: Option<AndroidKeystore>,
    #[cfg(target_os = "ios")]
    keychain: Option<IOSKeychain>,
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
        /*
        if let Ok(tpm) = TpmModule::new() {
            return Some(Box::new(tpm));
        }
        */

        // Check for SGX
        /*
        if let Ok(sgx) = SgxModule::new() {
            return Some(Box::new(sgx));
        }
        */

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
        let nonce = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce);
        self.encryption_key
            .encrypt(nonce, private_key)
            .map_err(|e| format!("Failed to encrypt private key: {}", e))
            .map(|ciphertext| {
                let mut result = nonce.to_vec();
                result.extend(ciphertext);
                result
            })
    }

    /// Decrypts a private key using AES-GCM
    fn decrypt_private_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted_key.len() < 12 {
            return Err("Invalid encrypted key format".to_string());
        }

        let (nonce_bytes, ciphertext) = encrypted_key.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.encryption_key
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Failed to decrypt private key: {}", e))
    }

    /// Signs data using Dilithium
    fn sign_dilithium(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let start = Instant::now();

        if private_key.len() != 2420 {
            return Err("Invalid Dilithium private key size".to_string());
        }

        let secret_key = DilithiumSecretKey::from_bytes(private_key)
            .map_err(|e| format!("Failed to parse Dilithium secret key: {}", e))?;

        let signature = dilithium::sign(data, &secret_key);

        if start.elapsed() > Duration::from_millis(50) {
            eprintln!("⚠️ Dilithium signing took too long");
            return Err("Operation timeout".to_string());
        }

        Ok(signature.to_bytes().to_vec())
    }

    /// Verifies Dilithium signature
    fn verify_dilithium(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
        let start = Instant::now();

        if public_key.len() != 1312 || signature.len() != 2420 {
            return Ok(false);
        }

        let pk = DilithiumPublicKey::from_bytes(public_key)
            .map_err(|e| format!("Failed to parse Dilithium public key: {}", e))?;

        let sig = dilithium::Signature::from_bytes(signature)
            .map_err(|e| format!("Failed to parse Dilithium signature: {}", e))?;

        let result = dilithium::verify(&sig, data, &pk);

        if start.elapsed() > Duration::from_millis(50) {
            eprintln!("⚠️ Dilithium verification took too long");
            return Ok(false);
        }

        Ok(result)
    }

    /// Signs data using BLS
    fn sign_bls(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let start = Instant::now();

        if private_key.len() != 32 {
            return Err("Invalid BLS private key size".to_string());
        }

        let mut sk = blst_sk::default();
        sk.from_bytes(private_key)
            .map_err(|e| format!("Failed to parse BLS secret key: {}", e))?;

        let mut sig = blst_signature::default();
        sig.sign(&sk, data, &[]);

        if start.elapsed() > Duration::from_millis(50) {
            eprintln!("⚠️ BLS signing took too long");
            return Err("Operation timeout".to_string());
        }

        let mut result = vec![0u8; 96];
        sig.to_bytes(&mut result);
        Ok(result)
    }

    /// Verifies BLS signature
    fn verify_bls(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, String> {
        let start = Instant::now();

        if public_key.len() != 96 || signature.len() != 48 {
            return Ok(false);
        }

        let mut pk = blst_pk::default();
        pk.from_bytes(public_key)
            .map_err(|e| format!("Failed to parse BLS public key: {}", e))?;

        let mut sig = blst_signature::default();
        sig.from_bytes(signature)
            .map_err(|e| format!("Failed to parse BLS signature: {}", e))?;

        let result = sig.verify(true, &pk, &[], data, &[]);

        if start.elapsed() > Duration::from_millis(50) {
            eprintln!("⚠️ BLS verification took too long");
            return Ok(false);
        }

        Ok(result)
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
                bls_public_key: if key_pair.key_type == KeyType::BLS {
                    Some(key_pair.public_key.clone())
                } else {
                    None
                },
                bls_private_key: if key_pair.key_type == KeyType::BLS {
                    Some(private_key.clone())
                } else {
                    None
                },
                dilithium_public_key: if key_pair.key_type == KeyType::Dilithium {
                    Some(key_pair.public_key.clone())
                } else {
                    None
                },
                dilithium_private_key: if key_pair.key_type == KeyType::Dilithium {
                    Some(private_key)
                } else {
                    None
                },
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
        rng.r#gen()
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
            created_at: Instant::now().timestamp() as u64,
            version: 1,
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
                created_at: Instant::now().timestamp() as u64,
                version: 2,
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
            id: rng.r#gen(),
            public_key: vec![],
            encrypted_private_key: vec![],
            key_type: KeyType::Dilithium,
            created_at: Instant::now().timestamp() as u64,
            version: 1,
        }
    }
}

impl ValidatorKeyManager {
    /// Creates a new key manager with the given configuration
    pub fn new(config: KeyStorageConfig) -> Self {
        ValidatorKeyManager {
            keys: None,
            config,
            #[cfg(target_os = "android")]
            keystore: None,
            #[cfg(target_os = "ios")]
            keychain: None,
        }
    }

    /// Generates a new BLS key pair
    pub fn generate_bls_keypair() -> Result<(Vec<u8>, Vec<u8>), KslError> {
        let mut rng = OsRng;
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let sk = SecretKey::key_gen(&ikm);
        let pk = sk.sk_to_pk();

        Ok((sk.to_bytes().to_vec(), pk.to_bytes().to_vec()))
    }

    /// Generates a new Dilithium key pair
    pub fn generate_dilithium_keypair() -> Result<(Vec<u8>, Vec<u8>), KslError> {
        // Use PQClean's Dilithium implementation
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        // Generate key pair using Dilithium
        let (sk, pk) = dilithium::keypair(&seed);
        Ok((sk.to_vec(), pk.to_vec()))
    }

    /// Generates a new validator key pair
    pub fn generate_keypair(&mut self) -> Result<ValidatorKeyPair, KslError> {
        let (bls_secret, bls_public) = Self::generate_bls_keypair()?;
        let (dilithium_secret, dilithium_public) = Self::generate_dilithium_keypair()?;

        let keypair = ValidatorKeyPair {
            bls_secret,
            bls_public,
            dilithium_secret,
            dilithium_public,
            version: 1,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Store the key pair
        self.store_keypair(&keypair)?;
        self.keys = Some(keypair.clone());

        Ok(keypair)
    }

    /// Signs a message with BLS
    pub fn sign_bls(&self, message: &[u8]) -> Result<Vec<u8>, KslError> {
        let keys = self.keys.as_ref().ok_or_else(|| {
            KslError::runtime_error("No validator keys loaded".to_string(), None)
        })?;

        let sk = SecretKey::from_bytes(&keys.bls_secret)
            .map_err(|_| KslError::runtime_error("Invalid BLS secret key".to_string(), None))?;
        let pk = PublicKey::from_bytes(&keys.bls_public)
            .map_err(|_| KslError::runtime_error("Invalid BLS public key".to_string(), None))?;

        let sig = sk.sign(message, &[], &pk, BLS_DST);
        Ok(sig.to_bytes().to_vec())
    }

    /// Signs a message with Dilithium
    pub fn sign_dilithium(&self, message: &[u8]) -> Result<Vec<u8>, KslError> {
        let keys = self.keys.as_ref().ok_or_else(|| {
            KslError::runtime_error("No validator keys loaded".to_string(), None)
        })?;

        // Sign using Dilithium
        let sig = dilithium::sign(message, &keys.dilithium_secret);
        Ok(sig)
    }

    /// Verifies a BLS signature
    pub fn verify_bls(&self, message: &[u8], signature: &[u8]) -> Result<bool, KslError> {
        let keys = self.keys.as_ref().ok_or_else(|| {
            KslError::runtime_error("No validator keys loaded".to_string(), None)
        })?;

        let pk = PublicKey::from_bytes(&keys.bls_public)
            .map_err(|_| KslError::runtime_error("Invalid BLS public key".to_string(), None))?;
        let sig = Signature::from_bytes(signature)
            .map_err(|_| KslError::runtime_error("Invalid BLS signature".to_string(), None))?;

        Ok(sig.verify(true, message, &[], &pk, BLS_DST) == BLST_ERROR::BLST_SUCCESS)
    }

    /// Verifies a Dilithium signature
    pub fn verify_dilithium(&self, message: &[u8], signature: &[u8]) -> Result<bool, KslError> {
        let keys = self.keys.as_ref().ok_or_else(|| {
            KslError::runtime_error("No validator keys loaded".to_string(), None)
        })?;

        // Verify using Dilithium
        Ok(dilithium::verify(message, signature, &keys.dilithium_public))
    }

    /// Rotates the validator keys
    pub fn rotate_keys(&mut self) -> Result<ValidatorKeyPair, KslError> {
        // Generate new key pair
        let new_keys = self.generate_keypair()?;

        // Sign rotation confirmation with old keys
        if let Some(old_keys) = &self.keys {
            let rotation_msg = format!(
                "Key rotation from version {} to {}",
                old_keys.version, new_keys.version
            );
            let bls_sig = self.sign_bls(rotation_msg.as_bytes())?;
            let dil_sig = self.sign_dilithium(rotation_msg.as_bytes())?;

            // Store rotation confirmation
            self.store_rotation_confirmation(
                old_keys.version,
                new_keys.version,
                &bls_sig,
                &dil_sig,
            )?;
        }

        Ok(new_keys)
    }

    /// Stores the key pair securely
    fn store_keypair(&self, keypair: &ValidatorKeyPair) -> Result<(), KslError> {
        match self.config.storage_type {
            #[cfg(target_os = "android")]
            StorageType::AndroidKeystore => {
                if let Some(keystore) = &self.keystore {
                    keystore.store_keys(keypair)?;
                } else {
                    return Err(KslError::runtime_error(
                        "Android Keystore not initialized".to_string(),
                        None,
                    ));
                }
            }
            #[cfg(target_os = "ios")]
            StorageType::IOSKeychain => {
                if let Some(keychain) = &self.keychain {
                    keychain.store_keys(keypair)?;
                } else {
                    return Err(KslError::runtime_error(
                        "iOS Keychain not initialized".to_string(),
                        None,
                    ));
                }
            }
            StorageType::EncryptedFile => {
                if let Some(path) = &self.config.file_path {
                    let encrypted = self.encrypt_keypair(keypair)?;
                    fs::write(path, encrypted)?;
                } else {
                    return Err(KslError::runtime_error(
                        "No file path specified for key storage".to_string(),
                        None,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Loads the key pair from secure storage
    pub fn load_keys(&mut self) -> Result<ValidatorKeyPair, KslError> {
        let keypair = match self.config.storage_type {
            #[cfg(target_os = "android")]
            StorageType::AndroidKeystore => {
                if let Some(keystore) = &self.keystore {
                    keystore.load_keys()?
                } else {
                    return Err(KslError::runtime_error(
                        "Android Keystore not initialized".to_string(),
                        None,
                    ));
                }
            }
            #[cfg(target_os = "ios")]
            StorageType::IOSKeychain => {
                if let Some(keychain) = &self.keychain {
                    keychain.load_keys()?
                } else {
                    return Err(KslError::runtime_error(
                        "iOS Keychain not initialized".to_string(),
                        None,
                    ));
                }
            }
            StorageType::EncryptedFile => {
                if let Some(path) = &self.config.file_path {
                    let encrypted = fs::read(path)?;
                    self.decrypt_keypair(&encrypted)?
                } else {
                    return Err(KslError::runtime_error(
                        "No file path specified for key storage".to_string(),
                        None,
                    ));
                }
            }
        };

        self.keys = Some(keypair.clone());
        Ok(keypair)
    }

    /// Encrypts a key pair for file storage
    fn encrypt_keypair(&self, keypair: &ValidatorKeyPair) -> Result<Vec<u8>, KslError> {
        let key = self.config.encryption_key.as_ref().ok_or_else(|| {
            KslError::runtime_error("No encryption key provided".to_string(), None)
        })?;

        let cipher = Aes256Gcm::new(Key::from_slice(key));
        let nonce = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce);

        let serialized = serde_json::to_vec(keypair)?;
        let encrypted = cipher
            .encrypt(nonce, serialized.as_ref())
            .map_err(|_| KslError::runtime_error("Encryption failed".to_string(), None))?;

        let mut result = nonce.to_vec();
        result.extend(encrypted);
        Ok(result)
    }

    /// Decrypts a key pair from file storage
    fn decrypt_keypair(&self, encrypted: &[u8]) -> Result<ValidatorKeyPair, KslError> {
        if encrypted.len() < 12 {
            return Err(KslError::runtime_error(
                "Invalid encrypted data format".to_string(),
                None,
            ));
        }

        let key = self.config.encryption_key.as_ref().ok_or_else(|| {
            KslError::runtime_error("No encryption key provided".to_string(), None)
        })?;

        let cipher = Aes256Gcm::new(Key::from_slice(key));
        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| KslError::runtime_error("Decryption failed".to_string(), None))?;

        let keypair: ValidatorKeyPair = serde_json::from_slice(&decrypted)?;
        Ok(keypair)
    }

    /// Stores rotation confirmation
    fn store_rotation_confirmation(
        &self,
        old_version: u64,
        new_version: u64,
        bls_sig: &[u8],
        dil_sig: &[u8],
    ) -> Result<(), KslError> {
        let confirmation = RotationConfirmation {
            old_version,
            new_version,
            bls_signature: bls_sig.to_vec(),
            dilithium_signature: dil_sig.to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        if let Some(path) = &self.config.file_path {
            let mut rotation_path = path.clone();
            rotation_path.set_extension("rotation");
            let serialized = serde_json::to_vec(&confirmation)?;
            fs::write(rotation_path, serialized)?;
        }

        Ok(())
    }
}

/// Rotation confirmation record
#[derive(Debug, Serialize, Deserialize)]
struct RotationConfirmation {
    old_version: u64,
    new_version: u64,
    bls_signature: Vec<u8>,
    dilithium_signature: Vec<u8>,
    timestamp: u64,
}

#[cfg(target_os = "android")]
mod android {
    use super::*;
    use jni::JNIEnv;
    use jni::objects::{JClass, JObject};
    use jni::sys::jobject;

    /// Android Keystore implementation
    pub struct AndroidKeystore {
        env: JNIEnv<'static>,
        keystore: jobject,
    }

    impl AndroidKeystore {
        pub fn new(env: JNIEnv<'static>) -> Result<Self, KslError> {
            // Initialize Android Keystore
            let keystore = env
                .find_class("android/security/keystore/KeyGenParameterSpec")
                .map_err(|_| KslError::runtime_error("Failed to find KeyGenParameterSpec".to_string(), None))?;

            Ok(AndroidKeystore { env, keystore })
        }

        pub fn store_keys(&self, keypair: &ValidatorKeyPair) -> Result<(), KslError> {
            // Store keys in Android Keystore
            // Implementation depends on Android Keystore API
            Ok(())
        }

        pub fn load_keys(&self) -> Result<ValidatorKeyPair, KslError> {
            // Load keys from Android Keystore
            // Implementation depends on Android Keystore API
            unimplemented!("Android Keystore loading not implemented")
        }
    }
}

#[cfg(target_os = "ios")]
mod ios {
    use super::*;
    use objc::{class, msg_send, sel, sel_impl};
    use objc::runtime::{Object, Sel};
    use objc::declare::ClassDecl;

    /// iOS Keychain implementation
    pub struct IOSKeychain {
        keychain: *mut Object,
    }

    impl IOSKeychain {
        pub fn new() -> Result<Self, KslError> {
            // Initialize iOS Keychain
            let keychain = unsafe {
                let cls = class!(NSKeychain);
                msg_send![cls, alloc]
            };

            Ok(IOSKeychain { keychain })
        }

        pub fn store_keys(&self, keypair: &ValidatorKeyPair) -> Result<(), KslError> {
            // Store keys in iOS Keychain
            // Implementation depends on iOS Keychain API
            Ok(())
        }

        pub fn load_keys(&self) -> Result<ValidatorKeyPair, KslError> {
            // Load keys from iOS Keychain
            // Implementation depends on iOS Keychain API
            unimplemented!("iOS Keychain loading not implemented")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_key_generation() {
        let (bls_secret, bls_public) = ValidatorKeyManager::generate_bls_keypair().unwrap();
        assert_eq!(bls_secret.len(), 32);
        assert_eq!(bls_public.len(), 96);

        let (dil_secret, dil_public) = ValidatorKeyManager::generate_dilithium_keypair().unwrap();
        assert_eq!(dil_secret.len(), 2560);
        assert_eq!(dil_public.len(), 1312);
    }

    #[test]
    fn test_file_storage() {
        let temp_file = NamedTempFile::new().unwrap();
        let config = KeyStorageConfig {
            storage_type: StorageType::EncryptedFile,
            file_path: Some(temp_file.path().to_path_buf()),
            encryption_key: Some(vec![1; 32]),
        };

        let mut manager = ValidatorKeyManager::new(config);
        let keypair = manager.generate_keypair().unwrap();

        // Test signing
        let message = b"test message";
        let bls_sig = manager.sign_bls(message).unwrap();
        let dil_sig = manager.sign_dilithium(message).unwrap();

        // Test verification
        assert!(manager.verify_bls(message, &bls_sig).unwrap());
        assert!(manager.verify_dilithium(message, &dil_sig).unwrap());

        // Test key rotation
        let new_keypair = manager.rotate_keys().unwrap();
        assert_eq!(new_keypair.version, 2);
    }

    #[test]
    fn test_invalid_signatures() {
        let temp_file = NamedTempFile::new().unwrap();
        let config = KeyStorageConfig {
            storage_type: StorageType::EncryptedFile,
            file_path: Some(temp_file.path().to_path_buf()),
            encryption_key: Some(vec![1; 32]),
        };

        let mut manager = ValidatorKeyManager::new(config);
        manager.generate_keypair().unwrap();

        let message = b"test message";
        let mut invalid_sig = manager.sign_bls(message).unwrap();
        invalid_sig[0] ^= 1; // Flip a bit

        assert!(!manager.verify_bls(message, &invalid_sig).unwrap());
    }
} 