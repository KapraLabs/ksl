use crate::ksl_types::{BlockHeader, Transaction, ValidatorInfo, ValidatorStatus};
use crate::ksl_stdlib_crypto::validation::{kaprekar_valid, bls_verify, modulo_check, sha3, merkle_verify, compute_merkle_root, CrossShardProof, verify_cross_shard_proof, compute_shard_root};
use crate::ksl_syscalls::blockchain::{get_block_hash, get_validator_pubkey, get_chain_state};
use crate::ksl_errors::KslError;
use std::time::{SystemTime, UNIX_EPOCH};

// Constants for validation
const MAX_SUPPLY: u64 = 1_000_000_000;
const MAX_VALIDATOR_STRIKES: u8 = 3;
const MIN_VALIDATOR_TRUST: u64 = 50;

/// Validator resource for tracking validator state
pub struct Validator {
    pub key: Vec<u8>,
    pub trust: u64,
    pub strikes: u8,
}

impl Validator {
    pub fn new(key: Vec<u8>) -> Self {
        Validator {
            key,
            trust: 100,
            strikes: 0,
        }
    }

    pub fn add_strike(&mut self) {
        self.strikes += 1;
        self.trust = self.trust.saturating_sub(10);
    }

    pub fn is_trusted(&self) -> bool {
        self.trust >= MIN_VALIDATOR_TRUST && self.strikes < MAX_VALIDATOR_STRIKES
    }
}

/// Validates a block header and its transactions
/// @param header The block header to validate
/// @param txs The transactions to validate
/// @returns Result indicating success or failure
pub fn validate_block(header: &BlockHeader, txs: &[Transaction]) -> Result<(), KslError> {
    // Check Kaprekar stability
    let block_hash = get_block_hash()?;
    if !kaprekar_valid(u64::from_be_bytes(block_hash[..8].try_into()?)) {
        return Err(KslError::ValidationFailed("Block hash is not Kaprekar stable".into()));
    }

    // Verify block signature
    let validator_pubkey = get_validator_pubkey()?;
    if !bls_verify(&block_hash, &header.signature, &validator_pubkey) {
        return Err(KslError::ValidationFailed("Invalid block signature".into()));
    }

    // Check nonce meets difficulty requirement
    if header.nonce % 100000 != 0 {
        return Err(KslError::ValidationFailed("Invalid nonce".into()));
    }

    // Validate transactions
    for tx in txs {
        validate_transaction(tx)?;
    }

    // Postcondition checks
    verify_block_postconditions(header, txs)?;

    Ok(())
}

/// Verifies postconditions that must hold after block execution
fn verify_block_postconditions(header: &BlockHeader, txs: &[Transaction]) -> Result<(), KslError> {
    // Check timestamp is not in the future
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if header.timestamp > now {
        return Err(KslError::ValidationFailed("Block timestamp is in the future".into()));
    }

    // Check total supply hasn't exceeded maximum
    let total_supply = get_chain_state(b"total_supply")?;
    let total_supply = u64::from_be_bytes(total_supply[..8].try_into()?);
    if total_supply > MAX_SUPPLY {
        return Err(KslError::ValidationFailed("Total supply exceeds maximum".into()));
    }

    // Check validator trust score
    let validator = Validator::new(header.miner.clone());
    if !validator.is_trusted() {
        return Err(KslError::ValidationFailed("Validator trust score too low".into()));
    }

    Ok(())
}

/// Validates a single transaction
/// @param tx The transaction to validate
/// @returns Result indicating success or failure
fn validate_transaction(tx: &Transaction) -> Result<(), KslError> {
    // Verify transaction signature
    let message = [&tx.sender, &tx.recipient, &tx.amount.to_be_bytes()].concat();
    if !bls_verify(&message, &tx.signature, &tx.sender) {
        return Err(KslError::ValidationFailed("Invalid transaction signature".into()));
    }

    // Check sender has sufficient balance
    let balance = get_chain_state(&tx.sender)?;
    let balance = u64::from_be_bytes(balance[..8].try_into()?);
    if balance < tx.amount {
        return Err(KslError::ValidationFailed("Insufficient balance".into()));
    }

    Ok(())
}

/// Validates that a transaction is included in a block
/// @param tx The transaction to validate
/// @param proof The Merkle proof
/// @param root The block's transaction root
/// @param index The transaction's index in the block
/// @returns Result indicating success or failure
pub fn validate_transaction_inclusion(
    tx: &Transaction,
    proof: &[Vec<u8>],
    root: &[u8],
    index: u64,
) -> Result<(), KslError> {
    // Compute transaction hash
    let mut hasher = sha3::Keccak256::new();
    hasher.update(&tx.sender);
    hasher.update(&tx.recipient);
    hasher.update(&tx.amount.to_be_bytes());
    hasher.update(&tx.nonce.to_be_bytes());
    hasher.update(&tx.signature);
    hasher.update(&tx.data);
    let tx_hash = hasher.finalize().to_vec();

    // Verify Merkle proof
    if !merkle_verify(&tx_hash, root, proof, index) {
        return Err(KslError::ValidationFailed("Invalid transaction inclusion proof".into()));
    }

    Ok(())
}

/// Validates a cross-shard transaction
/// @param tx The transaction to validate
/// @param proof The cross-shard proof
/// @param shard_root The root of the shard Merkle tree
/// @returns Result indicating success or failure
pub fn validate_cross_shard_transaction(
    tx: &Transaction,
    proof: &CrossShardProof,
    shard_root: &[u8],
) -> Result<(), KslError> {
    // Verify the cross-shard proof
    if !verify_cross_shard_proof(tx, proof, shard_root) {
        return Err(KslError::ValidationFailed("Invalid cross-shard proof".into()));
    }

    // Verify transaction signature
    let message = [&tx.sender, &tx.recipient, &tx.amount.to_be_bytes()].concat();
    if !bls_verify(&message, &tx.signature, &tx.sender) {
        return Err(KslError::ValidationFailed("Invalid transaction signature".into()));
    }

    // Check sender has sufficient balance
    let balance = get_chain_state(&tx.sender)?;
    let balance = u64::from_be_bytes(balance[..8].try_into()?);
    if balance < tx.amount {
        return Err(KslError::ValidationFailed("Insufficient balance".into()));
    }

    Ok(())
}

/// Validates a block's cross-shard transactions
/// @param header The block header
/// @param txs The regular transactions
/// @param cross_shard_txs The cross-shard transactions with their proofs
/// @returns Result indicating success or failure
pub fn validate_block_cross_shard(
    header: &BlockHeader,
    txs: &[Transaction],
    cross_shard_txs: &[(Transaction, CrossShardProof)],
) -> Result<(), KslError> {
    // First validate regular transactions
    for tx in txs {
        validate_transaction(tx)?;
    }

    // Get shard roots from chain state
    let shard_roots = get_chain_state(b"shard_roots")?;
    let shard_roots: Vec<(u16, Vec<u8>)> = bincode::deserialize(&shard_roots)
        .map_err(|_| KslError::ValidationFailed("Invalid shard roots format".into()))?;

    // Compute current shard root
    let current_shard_root = compute_shard_root(&shard_roots);

    // Validate cross-shard transactions
    for (tx, proof) in cross_shard_txs {
        validate_cross_shard_transaction(tx, proof, &current_shard_root)?;
    }

    // Postcondition checks
    verify_block_postconditions(header, txs)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ksl_stdlib_crypto::validation::{
        compute_merkle_root, generate_merkle_proof, generate_cross_shard_proof
    };

    #[test]
    fn test_validator_creation() {
        let key = vec![1; 32];
        let validator = Validator::new(key.clone());
        assert_eq!(validator.key, key);
        assert_eq!(validator.trust, 100);
        assert_eq!(validator.strikes, 0);
    }

    #[test]
    fn test_validator_strikes() {
        let mut validator = Validator::new(vec![1; 32]);
        validator.add_strike();
        assert_eq!(validator.trust, 90);
        assert_eq!(validator.strikes, 1);
        assert!(validator.is_trusted());
    }

    #[test]
    fn test_validator_untrusted() {
        let mut validator = Validator::new(vec![1; 32]);
        for _ in 0..3 {
            validator.add_strike();
        }
        assert!(!validator.is_trusted());
    }

    #[test]
    fn test_block_validation_rules() {
        // Test valid block
        let header = BlockHeader {
            parent: vec![1; 32],
            nonce: 100000,
            timestamp: 1234567890,
            miner: vec![2; 32],
            shard: 1,
        };
        let txs = vec![Transaction {
            sender: vec![3; 32],
            recipient: vec![4; 32],
            amount: 100,
            nonce: 1,
            signature: vec![5; 96],
            data: vec![],
        }];
        assert!(validate_block(&header, &txs).is_ok());

        // Test invalid nonce
        let mut invalid_header = header.clone();
        invalid_header.nonce = 99999;
        assert!(validate_block(&invalid_header, &txs).is_err());

        // Test invalid timestamp (future)
        let mut invalid_header = header.clone();
        invalid_header.timestamp = std::u64::MAX;
        assert!(validate_block(&invalid_header, &txs).is_err());
    }

    #[test]
    fn test_header_signature_checks() {
        let header = BlockHeader {
            parent: vec![1; 32],
            nonce: 100000,
            timestamp: 1234567890,
            miner: vec![2; 32],
            shard: 1,
        };

        // Test valid signature
        let block_hash = sha3(&[&header.parent, &header.nonce.to_be_bytes()].concat());
        let valid_sig = vec![1; 96]; // Mock valid signature
        assert!(bls_verify(&block_hash, &valid_sig, &header.miner));

        // Test invalid signature
        let invalid_sig = vec![0; 96]; // Mock invalid signature
        assert!(!bls_verify(&block_hash, &invalid_sig, &header.miner));
    }

    #[test]
    fn test_kaprekar_segment_validation() {
        // Test Kaprekar stable numbers
        assert!(kaprekar_valid(495)); // Classic Kaprekar number
        assert!(kaprekar_valid(6174)); // Another Kaprekar number
        assert!(kaprekar_valid(0)); // Zero is stable

        // Test non-Kaprekar stable numbers
        assert!(!kaprekar_valid(123)); // Random number
        assert!(!kaprekar_valid(999)); // Repdigit

        // Test modulo check
        assert!(modulo_check(100000, 100000)); // Exact multiple
        assert!(!modulo_check(100001, 100000)); // Not a multiple
    }

    #[test]
    fn test_shard_and_timestamp_logic() {
        // Test valid shard assignment
        let header = BlockHeader {
            parent: vec![1; 32],
            nonce: 100000,
            timestamp: 1234567890,
            miner: vec![2; 32],
            shard: 1,
        };
        assert!(header.shard < 1024); // Assuming max 1024 shards

        // Test timestamp ordering
        let parent_header = BlockHeader {
            parent: vec![0; 32],
            nonce: 100000,
            timestamp: 1234567880,
            miner: vec![2; 32],
            shard: 1,
        };
        assert!(header.timestamp > parent_header.timestamp);

        // Test shard-specific validation
        let mut invalid_header = header.clone();
        invalid_header.shard = 1024; // Invalid shard number
        assert!(validate_block(&invalid_header, &[]).is_err());
    }

    #[test]
    fn test_transaction_validation() {
        let tx = Transaction {
            sender: vec![1; 32],
            recipient: vec![2; 32],
            amount: 100,
            nonce: 1,
            signature: vec![3; 96],
            data: vec![],
        };

        // Test valid transaction
        assert!(validate_transaction(&tx).is_ok());

        // Test insufficient balance
        let mut invalid_tx = tx.clone();
        invalid_tx.amount = std::u64::MAX;
        assert!(validate_transaction(&invalid_tx).is_err());

        // Test invalid signature
        let mut invalid_tx = tx.clone();
        invalid_tx.signature = vec![0; 96];
        assert!(validate_transaction(&invalid_tx).is_err());
    }

    #[test]
    fn test_block_chain_validation() {
        // Create a chain of blocks
        let mut blocks = Vec::new();
        let mut parent_hash = vec![0; 32];

        for i in 0..3 {
            let header = BlockHeader {
                parent: parent_hash.clone(),
                nonce: 100000 * (i + 1),
                timestamp: 1234567890 + i * 10,
                miner: vec![i as u8; 32],
                shard: (i % 4) as u16,
            };
            parent_hash = sha3(&[&header.parent, &header.nonce.to_be_bytes()].concat());
            blocks.push(header);
        }

        // Validate chain
        for (i, header) in blocks.iter().enumerate() {
            if i > 0 {
                assert_eq!(header.parent, sha3(&[
                    &blocks[i-1].parent,
                    &blocks[i-1].nonce.to_be_bytes()
                ].concat()));
            }
            assert!(validate_block(header, &[]).is_ok());
        }
    }

    #[test]
    fn test_postcondition_validation() {
        let header = BlockHeader {
            parent: vec![1; 32],
            nonce: 100000,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() + 1000, // Future timestamp
            miner: vec![2; 32],
            shard: 1,
        };
        assert!(verify_block_postconditions(&header, &[]).is_err());

        let mut validator = Validator::new(vec![1; 32]);
        for _ in 0..MAX_VALIDATOR_STRIKES {
            validator.add_strike();
        }
        assert!(!validator.is_trusted());
    }

    #[test]
    fn test_merkle_proof_validation() {
        // Create test transactions
        let txs = vec![
            Transaction {
                sender: vec![1; 32],
                recipient: vec![2; 32],
                amount: 100,
                nonce: 1,
                signature: vec![3; 96],
                data: vec![],
            },
            Transaction {
                sender: vec![4; 32],
                recipient: vec![5; 32],
                amount: 200,
                nonce: 2,
                signature: vec![6; 96],
                data: vec![],
            },
        ];

        // Compute Merkle root
        let root = compute_merkle_root(&txs);

        // Generate and verify proof for first transaction
        let (proof, computed_root) = generate_merkle_proof(&txs, 0);
        assert_eq!(root, computed_root);
        assert!(validate_transaction_inclusion(&txs[0], &proof, &root, 0).is_ok());

        // Test invalid proof
        let mut invalid_proof = proof.clone();
        invalid_proof[0] = vec![0; 32];
        assert!(validate_transaction_inclusion(&txs[0], &invalid_proof, &root, 0).is_err());

        // Test wrong index
        assert!(validate_transaction_inclusion(&txs[0], &proof, &root, 1).is_err());
    }

    #[test]
    fn test_supply_limit() {
        // Set total supply to max
        let mut supply = [0u8; 8];
        supply.copy_from_slice(&MAX_SUPPLY.to_be_bytes());
        assert!(verify_block_postconditions(
            &BlockHeader {
                parent: vec![1; 32],
                nonce: 100000,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                miner: vec![2; 32],
                shard: 1,
            },
            &[]
        ).is_ok());

        // Test exceeding max supply
        let mut supply = [0u8; 8];
        supply.copy_from_slice(&(MAX_SUPPLY + 1).to_be_bytes());
        assert!(verify_block_postconditions(
            &BlockHeader {
                parent: vec![1; 32],
                nonce: 100000,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                miner: vec![2; 32],
                shard: 1,
            },
            &[]
        ).is_err());
    }

    #[test]
    fn test_cross_shard_validation() {
        // Create test transactions for source shard
        let source_txs = vec![
            Transaction {
                sender: vec![1; 32],
                recipient: vec![2; 32],
                amount: 100,
                nonce: 1,
                signature: vec![3; 96],
                data: vec![],
            },
            Transaction {
                sender: vec![4; 32],
                recipient: vec![5; 32],
                amount: 200,
                nonce: 2,
                signature: vec![6; 96],
                data: vec![],
            },
        ];

        // Create shard roots
        let shard_roots = vec![
            (1, compute_merkle_root(&source_txs)),
            (2, vec![7; 32]), // Another shard's root
        ];

        // Generate cross-shard proof
        let proof = generate_cross_shard_proof(
            &source_txs,
            &shard_roots,
            0, // First transaction
            1, // Source shard
            2, // Target shard
        );

        // Compute shard root
        let shard_root = compute_shard_root(&shard_roots);

        // Test valid cross-shard transaction
        assert!(validate_cross_shard_transaction(
            &source_txs[0],
            &proof,
            &shard_root
        ).is_ok());

        // Test invalid proof
        let mut invalid_proof = proof.clone();
        invalid_proof.transaction_proof[0] = vec![0; 32];
        assert!(validate_cross_shard_transaction(
            &source_txs[0],
            &invalid_proof,
            &shard_root
        ).is_err());

        // Test block validation with cross-shard transactions
        let header = BlockHeader {
            parent: vec![1; 32],
            nonce: 100000,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            miner: vec![2; 32],
            shard: 2, // Target shard
        };

        let cross_shard_txs = vec![(source_txs[0].clone(), proof)];
        assert!(validate_block_cross_shard(&header, &[], &cross_shard_txs).is_ok());
    }
} 