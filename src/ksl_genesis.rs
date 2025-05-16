use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use sha3::{Digest, Sha3_256};
use crate::ksl_validator_keys::{ValidatorKeyPair, KeyType};
use crate::ksl_kapra_crypto::{KapraCrypto, SignatureScheme};
use crate::ksl_contract::{Contract, ContractAbi, AbiSchema};
use crate::ksl_package::{Package, PackageConfig};
use toml;
use clap::{App, Arg, SubCommand};
use crate::ksl_doc_lsp::{LspClient, DocumentValidation};
use zip::{ZipWriter, write::FileOptions};
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use tera::{Tera, Context};
use crate::ksl_scaffold::{ScaffoldOptions, Template};

/// Genesis configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Chain ID (auto-generated from genesis hash if not set)
    pub chain_id: String,
    /// Genesis timestamp
    pub timestamp: DateTime<Utc>,
    /// Initial token supply
    pub initial_supply: u64,
    /// Block interval in seconds
    pub block_interval: u64,
    /// Maximum block size in bytes
    pub max_block_size: u64,
    /// Emission schedule
    pub emission_schedule: EmissionSchedule,
    /// Consensus parameters
    pub consensus: ConsensusParams,
    /// Network profile (mainnet, testnet, etc)
    pub network: NetworkProfile,
    /// Epoch schedule
    pub epoch_schedule: Option<EpochSchedule>,
}

/// Emission schedule configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct EmissionSchedule {
    /// Initial block reward
    pub initial_reward: u64,
    /// Reward halving interval (in blocks)
    pub halving_interval: u64,
    /// Minimum block reward
    pub min_reward: u64,
    /// Maximum total supply
    pub max_supply: u64,
}

/// Consensus parameters
#[derive(Debug, Serialize, Deserialize)]
pub struct ConsensusParams {
    /// Minimum stake amount
    pub min_stake: u64,
    /// Maximum validators
    pub max_validators: u32,
    /// Block proposal timeout
    pub proposal_timeout: u64,
    /// Required quorum percentage
    pub quorum_percentage: u8,
    /// Slashing conditions
    pub slashing_conditions: SlashingConditions,
}

/// Slashing conditions
#[derive(Debug, Serialize, Deserialize)]
pub struct SlashingConditions {
    /// Downtime threshold
    pub downtime_threshold: u64,
    /// Double signing penalty
    pub double_sign_penalty: u64,
    /// Inactivity penalty
    pub inactivity_penalty: u64,
}

/// Network profile
#[derive(Debug, Serialize, Deserialize)]
pub enum NetworkProfile {
    Mainnet,
    Testnet,
    Devnet,
    Custom(String),
}

/// Epoch schedule
#[derive(Debug, Serialize, Deserialize)]
pub struct EpochSchedule {
    /// Epoch length in blocks
    pub epoch_length: u64,
    /// Initial epoch start block
    pub initial_epoch_block: u64,
    /// Epoch grace period
    pub epoch_grace_period: u64,
}

/// Validator role type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidatorRole {
    /// Full validator with all capabilities
    Full,
    /// Observer node (no block production)
    Observer,
    /// Delegator node (stake delegation only)
    Delegator,
    /// Custom role with specific capabilities
    Custom(Vec<String>),
}

/// DNS bootstrap configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBootstrap {
    /// DNS lookup timeout
    pub timeout: std::time::Duration,
    /// Retry attempts
    pub retries: u32,
    /// DNS servers to use
    pub dns_servers: Vec<String>,
    /// DNS resolution results
    #[serde(skip)]
    pub resolved_ips: HashMap<String, Vec<String>>,
}

/// Validator registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRegistration {
    /// Validator name
    pub name: String,
    /// Validator description
    pub description: String,
    /// Website URL
    pub website: String,
    /// Identity key (Dilithium)
    pub identity_key: Vec<u8>,
    /// Consensus key (BLS)
    pub consensus_key: Vec<u8>,
    /// Initial stake amount
    pub stake_amount: u64,
    /// Commission rate (0-100)
    pub commission_rate: u8,
    /// Registration signature
    pub signature: Option<Vec<u8>>,
    /// Validator role
    pub role: ValidatorRole,
    /// DNS name (optional)
    pub dns_name: Option<String>,
    /// Resolved IP addresses
    #[serde(skip)]
    pub resolved_ips: Vec<String>,
}

/// Genesis account balance
#[derive(Debug, Serialize, Deserialize)]
pub struct GenesisBalance {
    /// Account address
    pub address: String,
    /// Initial balance
    pub balance: u64,
    /// Vesting schedule (if any)
    pub vesting: Option<VestingSchedule>,
}

/// Vesting schedule
#[derive(Debug, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Start time
    pub start_time: DateTime<Utc>,
    /// End time
    pub end_time: DateTime<Utc>,
    /// Vesting interval
    pub interval: u64,
    /// Amount per interval
    pub amount_per_interval: u64,
}

/// Genesis bundle
#[derive(Debug)]
pub struct GenesisBundle {
    /// Output directory
    output_dir: PathBuf,
    /// Configuration
    config: GenesisConfig,
    /// Validators
    validators: Vec<ValidatorRegistration>,
    /// Balances
    balances: Vec<GenesisBalance>,
    /// System contracts
    system_contracts: Vec<Contract>,
    /// Genesis hash
    genesis_hash: [u8; 32],
}

/// Validator boot bundle for node initialization
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorBootBundle {
    /// Validator registration
    pub registration: ValidatorRegistration,
    /// Genesis hash snapshot
    pub genesis_hash: [u8; 32],
    /// Network configuration
    pub network_config: NetworkConfig,
    /// Chain configuration
    pub chain_config: ChainConfig,
    /// System contract ABIs
    pub system_abis: Vec<ContractAbi>,
    /// Boot timestamp
    pub timestamp: DateTime<Utc>,
}

/// Network configuration for validator boot
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// P2P listen address
    pub p2p_address: String,
    /// RPC listen address
    pub rpc_address: String,
    /// Bootstrap peers
    pub bootstrap_peers: Vec<String>,
    /// Network profile
    pub profile: NetworkProfile,
}

/// Chain configuration for validator boot
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain ID
    pub chain_id: String,
    /// Block interval
    pub block_interval: u64,
    /// Consensus parameters
    pub consensus: ConsensusParams,
    /// Epoch schedule
    pub epoch_schedule: Option<EpochSchedule>,
}

/// ABI hash manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiManifest {
    /// Genesis hash
    pub genesis_hash: [u8; 32],
    /// Contract ABIs with hashes
    pub contracts: Vec<AbiEntry>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Manifest version
    pub version: String,
}

/// ABI entry in manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiEntry {
    /// Contract name
    pub name: String,
    /// ABI hash
    pub abi_hash: [u8; 32],
    /// ABI schema version
    pub schema_version: String,
    /// Function signatures
    pub functions: Vec<String>,
    /// Event signatures
    pub events: Vec<String>,
}

/// HTML summary configuration
#[derive(Debug, Clone)]
pub struct HtmlSummaryConfig {
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Include charts
    pub include_charts: bool,
    /// Include validator details
    pub include_validator_details: bool,
    /// Include contract ABIs
    pub include_abis: bool,
    /// Custom CSS
    pub custom_css: Option<String>,
}

impl GenesisBundle {
    /// Creates a new genesis bundle
    pub fn new(output_dir: PathBuf) -> Self {
        GenesisBundle {
            output_dir,
            config: GenesisConfig::default(),
            validators: Vec::new(),
            balances: Vec::new(),
            system_contracts: Vec::new(),
            genesis_hash: [0; 32],
        }
    }

    /// Loads a minimal template
    pub fn minimal_template() -> Self {
        let mut bundle = Self::new(PathBuf::from("genesis_bundle"));
        bundle.config = GenesisConfig {
            chain_id: String::new(), // Will be set from hash
            timestamp: Utc::now(),
            initial_supply: 1_000_000_000,
            block_interval: 5,
            max_block_size: 5_000_000,
            emission_schedule: EmissionSchedule {
                initial_reward: 50,
                halving_interval: 2_100_000,
                min_reward: 1,
                max_supply: 21_000_000,
            },
            consensus: ConsensusParams {
                min_stake: 100_000,
                max_validators: 100,
                proposal_timeout: 10,
                quorum_percentage: 67,
                slashing_conditions: SlashingConditions {
                    downtime_threshold: 50,
                    double_sign_penalty: 100,
                    inactivity_penalty: 20,
                },
            },
            network: NetworkProfile::Testnet,
            epoch_schedule: Some(EpochSchedule {
                epoch_length: 5000,
                initial_epoch_block: 0,
                epoch_grace_period: 100,
            }),
        };
        bundle
    }

    /// Adds a validator registration
    pub fn add_validator(&mut self, registration: ValidatorRegistration) -> Result<(), String> {
        // Validate keys
        self.validate_validator_keys(&registration)?;
        
        // Validate signature if required
        if let Some(sig) = &registration.signature {
            self.verify_registration_signature(&registration, sig)?;
        }
        
        // Add to list
        self.validators.push(registration);
        Ok(())
    }

    /// Adds a genesis balance
    pub fn add_balance(&mut self, balance: GenesisBalance) -> Result<(), String> {
        // Validate address format
        if !Self::is_valid_address(&balance.address) {
            return Err("Invalid address format".to_string());
        }
        
        // Validate vesting if present
        if let Some(vesting) = &balance.vesting {
            if vesting.start_time >= vesting.end_time {
                return Err("Invalid vesting schedule".to_string());
            }
        }
        
        // Add to list
        self.balances.push(balance);
        Ok(())
    }

    /// Adds a system contract
    pub fn add_system_contract(&mut self, contract: Contract) -> Result<(), String> {
        // Validate contract
        contract.validate()?;
        
        // Add to list
        self.system_contracts.push(contract);
        Ok(())
    }

    /// Validates validator keys
    fn validate_validator_keys(&self, registration: &ValidatorRegistration) -> Result<(), String> {
        // Validate Dilithium identity key
        if !Self::is_valid_dilithium_key(&registration.identity_key) {
            return Err("Invalid Dilithium identity key".to_string());
        }
        
        // Validate BLS consensus key
        if !Self::is_valid_bls_key(&registration.consensus_key) {
            return Err("Invalid BLS consensus key".to_string());
        }
        
        Ok(())
    }

    /// Verifies registration signature
    fn verify_registration_signature(&self, registration: &ValidatorRegistration, signature: &[u8]) -> Result<(), String> {
        // Create registration message
        let msg = self.create_registration_message(registration);
        
        // Verify Dilithium signature
        if !KapraCrypto::verify_dilithium(&registration.identity_key, &msg, signature) {
            return Err("Invalid registration signature".to_string());
        }
        
        Ok(())
    }

    /// Creates registration message for signing
    fn create_registration_message(&self, registration: &ValidatorRegistration) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(&registration.name.as_bytes());
        hasher.update(&registration.identity_key);
        hasher.update(&registration.consensus_key);
        hasher.update(&registration.stake_amount.to_le_bytes());
        hasher.update(&registration.commission_rate.to_le_bytes());
        hasher.finalize().to_vec()
    }

    /// Validates address format
    fn is_valid_address(address: &str) -> bool {
        // Add proper address validation
        address.len() == 42 && address.starts_with("0x")
    }

    /// Validates Dilithium key
    fn is_valid_dilithium_key(key: &[u8]) -> bool {
        // Add proper Dilithium key validation
        key.len() == 1312 // Public key size
    }

    /// Validates BLS key
    fn is_valid_bls_key(key: &[u8]) -> bool {
        // Add proper BLS key validation
        key.len() == 96 // Public key size
    }

    /// Calculates genesis hash
    pub fn calculate_hash(&mut self) -> Result<[u8; 32], String> {
        let mut hasher = Sha3_256::new();
        
        // Add config
        let config_str = serde_json::to_string(&self.config)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        hasher.update(config_str.as_bytes());
        
        // Add validators
        let validators_str = serde_json::to_string(&self.validators)
            .map_err(|e| format!("Failed to serialize validators: {}", e))?;
        hasher.update(validators_str.as_bytes());
        
        // Add balances
        let balances_str = serde_json::to_string(&self.balances)
            .map_err(|e| format!("Failed to serialize balances: {}", e))?;
        hasher.update(balances_str.as_bytes());
        
        // Add contracts
        for contract in &self.system_contracts {
            hasher.update(&contract.bytecode);
        }
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        
        self.genesis_hash = hash;
        if self.config.chain_id.is_empty() {
            self.config.chain_id = hex::encode(hash);
        }
        
        Ok(hash)
    }

    /// Exports the genesis bundle
    pub fn export(&self) -> Result<(), String> {
        // Create output directory
        fs::create_dir_all(&self.output_dir)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;
        
        // Export config
        let config_path = self.output_dir.join("genesis_config.toml");
        let config_str = toml::to_string_pretty(&self.config)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        fs::write(config_path, config_str)
            .map_err(|e| format!("Failed to write config: {}", e))?;
        
        // Export validators
        let validators_path = self.output_dir.join("genesis_validators.json");
        let validators_str = serde_json::to_string_pretty(&self.validators)
            .map_err(|e| format!("Failed to serialize validators: {}", e))?;
        fs::write(validators_path, validators_str)
            .map_err(|e| format!("Failed to write validators: {}", e))?;
        
        // Export balances
        let balances_path = self.output_dir.join("genesis_balances.json");
        let balances_str = serde_json::to_string_pretty(&self.balances)
            .map_err(|e| format!("Failed to serialize balances: {}", e))?;
        fs::write(balances_path, balances_str)
            .map_err(|e| format!("Failed to write balances: {}", e))?;
        
        // Export genesis block
        let block_path = self.output_dir.join("genesis_block.json");
        let block = self.create_genesis_block()?;
        let block_str = serde_json::to_string_pretty(&block)
            .map_err(|e| format!("Failed to serialize block: {}", e))?;
        fs::write(block_path, block_str)
            .map_err(|e| format!("Failed to write block: {}", e))?;
        
        // Export system contracts
        if !self.system_contracts.is_empty() {
            let contracts_dir = self.output_dir.join("system_contracts");
            fs::create_dir_all(&contracts_dir)
                .map_err(|e| format!("Failed to create contracts directory: {}", e))?;
            
            for (i, contract) in self.system_contracts.iter().enumerate() {
                let contract_path = contracts_dir.join(format!("contract_{}.json", i));
                let contract_str = serde_json::to_string_pretty(contract)
                    .map_err(|e| format!("Failed to serialize contract: {}", e))?;
                fs::write(contract_path, contract_str)
                    .map_err(|e| format!("Failed to write contract: {}", e))?;
            }
        }
        
        Ok(())
    }

    /// Creates the genesis block
    fn create_genesis_block(&self) -> Result<GenesisBlock, String> {
        Ok(GenesisBlock {
            chain_id: self.config.chain_id.clone(),
            timestamp: self.config.timestamp,
            genesis_hash: self.genesis_hash,
            validator_set: self.validators.clone(),
            initial_balances: self.balances.clone(),
            system_contracts: self.system_contracts.iter().map(|c| c.abi.clone()).collect(),
        })
    }

    /// Creates a validator boot bundle
    pub fn create_validator_boot_bundle(&self, registration: &ValidatorRegistration) -> Result<ValidatorBootBundle, String> {
        // Ensure validator exists
        if !self.validators.contains(registration) {
            return Err("Validator not found in genesis set".to_string());
        }

        Ok(ValidatorBootBundle {
            registration: registration.clone(),
            genesis_hash: self.genesis_hash,
            network_config: NetworkConfig {
                p2p_address: "0.0.0.0:26656".to_string(),
                rpc_address: "0.0.0.0:26657".to_string(),
                bootstrap_peers: vec![],
                profile: self.config.network.clone(),
            },
            chain_config: ChainConfig {
                chain_id: self.config.chain_id.clone(),
                block_interval: self.config.block_interval,
                consensus: self.config.consensus.clone(),
                epoch_schedule: self.config.epoch_schedule.clone(),
            },
            system_abis: self.system_contracts.iter().map(|c| c.abi.clone()).collect(),
            timestamp: Utc::now(),
        })
    }

    /// Validates system contract ABIs
    fn validate_system_contracts(&self) -> Result<(), String> {
        for contract in &self.system_contracts {
            // Validate ABI schema matches protocol standard
            if !self.validate_abi_schema(&contract.abi) {
                return Err(format!("Invalid ABI schema for contract {}", contract.abi.name));
            }
        }
        Ok(())
    }

    /// Validates ABI schema against protocol standard
    fn validate_abi_schema(&self, abi: &ContractAbi) -> bool {
        // Check required functions exist
        let has_required_functions = abi.functions.iter().any(|f| f.name == "initialize") &&
                                   abi.functions.iter().any(|f| f.name == "upgrade");

        // Check event definitions
        let has_valid_events = abi.events.iter().all(|e| e.indexed_params <= 3);

        // Check function modifiers
        let has_valid_modifiers = abi.functions.iter().all(|f| {
            match f.modifier {
                Some(ref m) => ["view", "pure", "payable"].contains(&m.as_str()),
                None => true
            }
        });

        has_required_functions && has_valid_events && has_valid_modifiers
    }

    /// Exports validator boot bundle
    pub fn export_validator_boot_bundle(&self, registration: &ValidatorRegistration, output_dir: &Path) -> Result<(), String> {
        let bundle = self.create_validator_boot_bundle(registration)?;
        
        // Create output directory
        fs::create_dir_all(output_dir)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;
        
        // Export bundle
        let bundle_path = output_dir.join("validator_boot_bundle.json");
        let bundle_str = serde_json::to_string_pretty(&bundle)
            .map_err(|e| format!("Failed to serialize boot bundle: {}", e))?;
        fs::write(bundle_path, bundle_str)
            .map_err(|e| format!("Failed to write boot bundle: {}", e))?;
        
        Ok(())
    }

    /// Creates a zip bundle of the genesis files
    pub async fn create_zip_bundle(&self, output_path: &Path) -> Result<(), String> {
        let file = File::create(output_path)
            .map_err(|e| format!("Failed to create zip file: {}", e))?;
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o755);

        // Add config
        let config_str = toml::to_string_pretty(&self.config)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        zip.start_file("genesis_config.toml", options)
            .map_err(|e| format!("Failed to add config to zip: {}", e))?;
        zip.write_all(config_str.as_bytes())
            .map_err(|e| format!("Failed to write config to zip: {}", e))?;

        // Add validators
        let validators_str = serde_json::to_string_pretty(&self.validators)
            .map_err(|e| format!("Failed to serialize validators: {}", e))?;
        zip.start_file("genesis_validators.json", options)
            .map_err(|e| format!("Failed to add validators to zip: {}", e))?;
        zip.write_all(validators_str.as_bytes())
            .map_err(|e| format!("Failed to write validators to zip: {}", e))?;

        // Add balances
        let balances_str = serde_json::to_string_pretty(&self.balances)
            .map_err(|e| format!("Failed to serialize balances: {}", e))?;
        zip.start_file("genesis_balances.json", options)
            .map_err(|e| format!("Failed to add balances to zip: {}", e))?;
        zip.write_all(balances_str.as_bytes())
            .map_err(|e| format!("Failed to write balances to zip: {}", e))?;

        // Add system contracts
        if !self.system_contracts.is_empty() {
            for (i, contract) in self.system_contracts.iter().enumerate() {
                let contract_str = serde_json::to_string_pretty(contract)
                    .map_err(|e| format!("Failed to serialize contract: {}", e))?;
                zip.start_file(format!("system_contracts/contract_{}.json", i), options)
                    .map_err(|e| format!("Failed to add contract to zip: {}", e))?;
                zip.write_all(contract_str.as_bytes())
                    .map_err(|e| format!("Failed to write contract to zip: {}", e))?;
            }
        }

        // Add genesis block
        let block = self.create_genesis_block()?;
        let block_str = serde_json::to_string_pretty(&block)
            .map_err(|e| format!("Failed to serialize block: {}", e))?;
        zip.start_file("genesis_block.json", options)
            .map_err(|e| format!("Failed to add block to zip: {}", e))?;
        zip.write_all(block_str.as_bytes())
            .map_err(|e| format!("Failed to write block to zip: {}", e))?;

        zip.finish()
            .map_err(|e| format!("Failed to finalize zip file: {}", e))?;

        Ok(())
    }

    /// Resolves validator DNS names to IP addresses
    pub async fn resolve_validator_dns(&mut self) -> Result<(), String> {
                let resolver = match TokioAsyncResolver::tokio(            ResolverConfig::default(),            ResolverOpts::default(),        ) {            Ok(r) => r,            Err(e) => return Err(format!("Failed to create DNS resolver: {}", e)),        };

        for validator in &mut self.validators {
            if let Some(ref dns_name) = validator.dns_name {
                let response = resolver.lookup_ip(dns_name)
                    .await
                    .map_err(|e| format!("Failed to resolve DNS name {}: {}", dns_name, e))?;

                validator.resolved_ips = response
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect();
            }
        }

        Ok(())
    }

    /// Validates contract ABIs using LSP
    pub async fn validate_contract_abis(&self) -> Result<(), String> {
        let lsp_client = LspClient::new()
            .map_err(|e| format!("Failed to create LSP client: {}", e))?;

        for contract in &self.system_contracts {
            // Validate ABI schema
            if !self.validate_abi_schema(&contract.abi) {
                return Err(format!("Invalid ABI schema for contract {}", contract.abi.name));
            }

            // Validate using LSP
            let validation = lsp_client.validate_document(&contract.abi.source)
                .await
                .map_err(|e| format!("LSP validation failed: {}", e))?;

            if !validation.is_valid() {
                return Err(format!(
                    "Contract {} has LSP validation errors: {:?}",
                    contract.abi.name,
                    validation.diagnostics
                ));
            }
        }

        Ok(())
    }

    /// Generates ABI manifest
    pub fn generate_abi_manifest(&self) -> Result<AbiManifest, String> {
        let mut contracts = Vec::new();

        for contract in &self.system_contracts {
            // Calculate ABI hash
            let mut hasher = Sha3_256::new();
            let abi_json = serde_json::to_vec(&contract.abi)
                .map_err(|e| format!("Failed to serialize ABI: {}", e))?;
            hasher.update(&abi_json);
            let mut abi_hash = [0u8; 32];
            abi_hash.copy_from_slice(&hasher.finalize());

            // Collect function signatures
            let functions = contract.abi.functions.iter()
                .map(|f| format!("{}({})", f.name, f.inputs.join(",")))
                .collect();

            // Collect event signatures
            let events = contract.abi.events.iter()
                .map(|e| format!("{}({})", e.name, e.params.join(",")))
                .collect();

            contracts.push(AbiEntry {
                name: contract.abi.name.clone(),
                abi_hash,
                schema_version: contract.abi.version.clone(),
                functions,
                events,
            });
        }

        Ok(AbiManifest {
            genesis_hash: self.genesis_hash,
            contracts,
            created_at: Utc::now(),
            version: "1.0.0".to_string(),
        })
    }

    /// Exports ABI manifest
    pub fn export_abi_manifest(&self) -> Result<(), String> {
        let manifest = self.generate_abi_manifest()?;
        
        let manifest_path = self.output_dir.join("abi_manifest.json");
        let manifest_str = serde_json::to_string_pretty(&manifest)
            .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
        
        fs::write(manifest_path, manifest_str)
            .map_err(|e| format!("Failed to write manifest: {}", e))?;

        Ok(())
    }

    /// Generates HTML summary
    pub fn generate_html_summary(&self, config: &HtmlSummaryConfig) -> Result<String, String> {
        let mut tera = Tera::default();
        tera.add_raw_template("summary", include_str!("../templates/genesis_summary.html"))
            .map_err(|e| format!("Failed to load summary template: {}", e))?;

        let mut context = Context::new();
        context.insert("title", &config.title);
        context.insert("description", &config.description);
        context.insert("chain_id", &self.config.chain_id);
        context.insert("timestamp", &self.config.timestamp);
        context.insert("genesis_hash", &hex::encode(self.genesis_hash));

        // Add network stats
        let stats = self.generate_network_stats();
        context.insert("stats", &stats);

        // Add validator details if requested
        if config.include_validator_details {
            let validator_details = self.generate_validator_details();
            context.insert("validators", &validator_details);
        }

        // Add contract ABIs if requested
        if config.include_abis {
            let manifest = self.generate_abi_manifest()?;
            context.insert("abi_manifest", &manifest);
        }

        // Add charts if requested
        if config.include_charts {
            let chart_data = self.generate_chart_data();
            context.insert("chart_data", &chart_data);
        }

        // Add custom CSS if provided
        if let Some(ref css) = config.custom_css {
            context.insert("custom_css", css);
        }

        tera.render("summary", &context)
            .map_err(|e| format!("Failed to render summary: {}", e))
    }

    /// Generates network statistics
    fn generate_network_stats(&self) -> serde_json::Value {
        let total_supply: u64 = self.balances.iter()
            .map(|b| b.balance)
            .sum();

        let total_staked: u64 = self.validators.iter()
            .map(|v| v.stake_amount)
            .sum();

        serde_json::json!({
            "total_supply": total_supply,
            "total_staked": total_staked,
            "validator_count": self.validators.len(),
            "contract_count": self.system_contracts.len(),
            "initial_accounts": self.balances.len(),
        })
    }

    /// Generates validator details
    fn generate_validator_details(&self) -> Vec<serde_json::Value> {
        self.validators.iter()
            .map(|v| serde_json::json!({
                "name": v.name,
                "stake": v.stake_amount,
                "commission": v.commission_rate,
                "website": v.website,
                "role": format!("{:?}", v.role),
                "dns": v.dns_name,
                "ips": v.resolved_ips,
            }))
            .collect()
    }

    /// Generates chart data
    fn generate_chart_data(&self) -> serde_json::Value {
        // Generate stake distribution data
        let stake_data: Vec<_> = self.validators.iter()
            .map(|v| (v.name.clone(), v.stake_amount))
            .collect();

        // Generate balance distribution data
        let balance_data: Vec<_> = self.balances.iter()
            .map(|b| (b.address.clone(), b.balance))
            .collect();

        serde_json::json!({
            "stake_distribution": stake_data,
            "balance_distribution": balance_data,
            "contract_distribution": self.system_contracts.iter()
                .map(|c| c.abi.name.clone())
                .collect::<Vec<_>>(),
        })
    }

    /// Reinitializes genesis with force flag
    pub fn reinitialize(&mut self, force: bool) -> Result<(), String> {
        if !force && self.output_dir.exists() {
            return Err("Output directory already exists. Use --force to overwrite.".to_string());
        }

        // Clear output directory
        if self.output_dir.exists() {
            fs::remove_dir_all(&self.output_dir)
                .map_err(|e| format!("Failed to remove output directory: {}", e))?;
        }

        // Recreate directory structure
        self.generate_project_layout(&ScaffoldOptions {
            name: self.config.chain_id.clone(),
            path: self.output_dir.clone(),
            template: Template::Contract,
            sandbox: false,
            generate_abi: true,
            enable_zk: false,
            registry_url: None,
        })?;

        // Reset genesis hash
        self.genesis_hash = [0; 32];

        Ok(())
    }
}

/// Genesis block
#[derive(Debug, Serialize, Deserialize)]
pub struct GenesisBlock {
    /// Chain ID
    pub chain_id: String,
    /// Block timestamp
    pub timestamp: DateTime<Utc>,
    /// Genesis hash
    pub genesis_hash: [u8; 32],
    /// Initial validator set
    pub validator_set: Vec<ValidatorRegistration>,
    /// Initial balances
    pub initial_balances: Vec<GenesisBalance>,
    /// System contract ABIs
    pub system_contracts: Vec<ContractAbi>,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        GenesisConfig {
            chain_id: String::new(),
            timestamp: Utc::now(),
            initial_supply: 0,
            block_interval: 5,
            max_block_size: 5_000_000,
            emission_schedule: EmissionSchedule {
                initial_reward: 0,
                halving_interval: 0,
                min_reward: 0,
                max_supply: 0,
            },
            consensus: ConsensusParams {
                min_stake: 0,
                max_validators: 100,
                proposal_timeout: 10,
                quorum_percentage: 67,
                slashing_conditions: SlashingConditions {
                    downtime_threshold: 0,
                    double_sign_penalty: 0,
                    inactivity_penalty: 0,
                },
            },
            network: NetworkProfile::Testnet,
            epoch_schedule: None,
        }
    }
}

/// CLI integration
pub fn register_cli_commands(app: App) -> App {
    app.subcommand(
        SubCommand::with_name("init-chain")
            .about("Initialize a new chain")
            .arg(
                Arg::with_name("template")
                    .long("template")
                    .value_name("TEMPLATE")
                    .help("Template to use (minimal, full)")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("profile")
                    .long("profile")
                    .value_name("PROFILE")
                    .help("Network profile (mainnet, testnet, devnet, custom)")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("force")
                    .long("force")
                    .help("Force reinitialization of existing chain"),
            ),
    )
    .subcommand(
        SubCommand::with_name("launch-genesis")
            .about("Launch genesis from configuration")
            .arg(
                Arg::with_name("validators")
                    .long("validators")
                    .value_name("FILE")
                    .help("Validators configuration file")
                    .required(true),
            )
            .arg(
                Arg::with_name("output")
                    .long("output")
                    .value_name("DIR")
                    .help("Output directory")
                    .required(true),
            )
            .arg(
                Arg::with_name("html-summary")
                    .long("html-summary")
                    .value_name("FILE")
                    .help("Generate HTML summary"),
            )
            .arg(
                Arg::with_name("abi-manifest")
                    .long("abi-manifest")
                    .help("Generate ABI manifest"),
            ),
    )
    .subcommand(
        SubCommand::with_name("create-boot-bundle")
            .about("Create validator boot bundle")
            .arg(
                Arg::with_name("validator")
                    .long("validator")
                    .value_name("ADDRESS")
                    .help("Validator address")
                    .required(true),
            )
            .arg(
                Arg::with_name("genesis")
                    .long("genesis")
                    .value_name("DIR")
                    .help("Genesis bundle directory")
                    .required(true),
            )
            .arg(
                Arg::with_name("output")
                    .long("output")
                    .value_name("DIR")
                    .help("Output directory")
                    .required(true),
            ),
    )
    .subcommand(
        SubCommand::with_name("show-genesis-hash")
            .about("Show genesis hash"),
    )
    .subcommand(
        SubCommand::with_name("export-genesis")
            .about("Export genesis configuration")
            .arg(
                Arg::with_name("format")
                    .long("to")
                    .value_name("FORMAT")
                    .help("Output format (json, toml)")
                    .required(true),
            ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_template() {
        let bundle = GenesisBundle::minimal_template();
        assert_eq!(bundle.config.block_interval, 5);
        assert_eq!(bundle.config.max_validators, 100);
    }

    #[test]
    fn test_validator_registration() {
        let mut bundle = GenesisBundle::new(PathBuf::from("test_genesis"));
        
        let registration = ValidatorRegistration {
            name: "test_validator".to_string(),
            description: "Test validator".to_string(),
            website: "https://test.com".to_string(),
            identity_key: vec![0; 1312], // Mock Dilithium key
            consensus_key: vec![0; 96],  // Mock BLS key
            stake_amount: 100_000,
            commission_rate: 5,
            signature: None,
            role: ValidatorRole::Observer,
            dns_name: None,
            resolved_ips: Vec::new(),
        };
        
        assert!(bundle.add_validator(registration).is_ok());
    }

    #[test]
    fn test_genesis_hash() {
        let mut bundle = GenesisBundle::minimal_template();
        let hash = bundle.calculate_hash().unwrap();
        assert_ne!(hash, [0; 32]);
        assert!(!bundle.config.chain_id.is_empty());
    }

    #[test]
    fn test_export() {
        let mut bundle = GenesisBundle::minimal_template();
        bundle.calculate_hash().unwrap();
        assert!(bundle.export().is_ok());
        
        // Cleanup
        fs::remove_dir_all("genesis_bundle").unwrap_or(());
    }

    #[test]
    fn test_validator_boot_bundle() {
        let mut bundle = GenesisBundle::minimal_template();
        
        let registration = ValidatorRegistration {
            name: "test_validator".to_string(),
            description: "Test validator".to_string(),
            website: "https://test.com".to_string(),
            identity_key: vec![0; 1312],
            consensus_key: vec![0; 96],
            stake_amount: 100_000,
            commission_rate: 5,
            signature: None,
            role: ValidatorRole::Observer,
            dns_name: None,
            resolved_ips: Vec::new(),
        };
        
        bundle.add_validator(registration.clone()).unwrap();
        bundle.calculate_hash().unwrap();
        
        let boot_bundle = bundle.create_validator_boot_bundle(&registration).unwrap();
        assert_eq!(boot_bundle.genesis_hash, bundle.genesis_hash);
        assert_eq!(boot_bundle.registration.name, "test_validator");
    }

    #[test]
    fn test_abi_validation() {
        let mut bundle = GenesisBundle::minimal_template();
        
        // Add valid system contract
        let mut contract = Contract::default();
        contract.abi.functions.push(ContractFunction {
            name: "initialize".to_string(),
            inputs: vec![],
            outputs: vec![],
            modifier: None,
        });
        contract.abi.functions.push(ContractFunction {
            name: "upgrade".to_string(),
            inputs: vec![],
            outputs: vec![],
            modifier: None,
        });
        
        assert!(bundle.add_system_contract(contract).is_ok());
        assert!(bundle.validate_system_contracts().is_ok());
    }

    #[test]
    fn test_validator_roles() {
        let mut bundle = GenesisBundle::minimal_template();
        
        let registration = ValidatorRegistration {
            name: "test_validator".to_string(),
            description: "Test validator".to_string(),
            website: "https://test.com".to_string(),
            identity_key: vec![0; 1312],
            consensus_key: vec![0; 96],
            stake_amount: 100_000,
            commission_rate: 5,
            signature: None,
            role: ValidatorRole::Observer,
            dns_name: Some("validator.test.com".to_string()),
            resolved_ips: Vec::new(),
        };
        
        assert!(bundle.add_validator(registration).is_ok());
    }

    #[tokio::test]
    async fn test_dns_resolution() {
        let mut bundle = GenesisBundle::minimal_template();
        
        let registration = ValidatorRegistration {
            name: "test_validator".to_string(),
            description: "Test validator".to_string(),
            website: "https://test.com".to_string(),
            identity_key: vec![0; 1312],
            consensus_key: vec![0; 96],
            stake_amount: 100_000,
            commission_rate: 5,
            signature: None,
            role: ValidatorRole::Full,
            dns_name: Some("example.com".to_string()),
            resolved_ips: Vec::new(),
        };
        
        bundle.add_validator(registration).unwrap();
        assert!(bundle.resolve_validator_dns().await.is_ok());
    }

    #[tokio::test]
    async fn test_zip_bundle() {
        let mut bundle = GenesisBundle::minimal_template();
        bundle.calculate_hash().unwrap();
        
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("genesis.zip");
        
        assert!(bundle.create_zip_bundle(&zip_path).await.is_ok());
        assert!(zip_path.exists());
    }

    #[tokio::test]
    async fn test_abi_validation() {
        let mut bundle = GenesisBundle::minimal_template();
        
        // Add valid system contract
        let mut contract = Contract::default();
        contract.abi.functions.push(ContractFunction {
            name: "initialize".to_string(),
            inputs: vec![],
            outputs: vec![],
            modifier: None,
        });
        
        bundle.add_system_contract(contract).unwrap();
        assert!(bundle.validate_contract_abis().await.is_ok());
    }

    #[test]
    fn test_abi_manifest() {
        let mut bundle = GenesisBundle::minimal_template();
        
        // Add test contract
        let mut contract = Contract::default();
        contract.abi.name = "TestContract".to_string();
        contract.abi.version = "1.0.0".to_string();
        contract.abi.functions.push(ContractFunction {
            name: "initialize".to_string(),
            inputs: vec![],
            outputs: vec![],
            modifier: None,
        });
        
        bundle.add_system_contract(contract).unwrap();
        
        let manifest = bundle.generate_abi_manifest().unwrap();
        assert_eq!(manifest.contracts.len(), 1);
        assert_eq!(manifest.contracts[0].name, "TestContract");
    }

    #[test]
    fn test_html_summary() {
        let mut bundle = GenesisBundle::minimal_template();
        bundle.calculate_hash().unwrap();
        
        let config = HtmlSummaryConfig {
            title: "Genesis Summary".to_string(),
            description: "Test summary".to_string(),
            include_charts: true,
            include_validator_details: true,
            include_abis: true,
            custom_css: None,
        };
        
        let summary = bundle.generate_html_summary(&config).unwrap();
        assert!(summary.contains("Genesis Summary"));
        assert!(summary.contains(&bundle.config.chain_id));
    }

    #[test]
    fn test_force_reinitialization() {
        let temp_dir = tempdir().unwrap();
        let mut bundle = GenesisBundle::new(temp_dir.path().to_path_buf());
        
        // First initialization
        bundle.generate_project_layout(&ScaffoldOptions {
            name: "test".to_string(),
            path: temp_dir.path().to_path_buf(),
            template: Template::Contract,
            sandbox: false,
            generate_abi: false,
            enable_zk: false,
            registry_url: None,
        }).unwrap();
        
        // Should fail without force
        assert!(bundle.reinitialize(false).is_err());
        
        // Should succeed with force
        assert!(bundle.reinitialize(true).is_ok());
    }
} 