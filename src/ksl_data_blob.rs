// ksl_data_blob.rs
// Implements data blob support for embedding large immutable data in KSL contracts

use crate::ksl_types::{Type, TypeError};
use crate::ksl_errors::{KslError, ErrorType};
use crate::ksl_bytecode::{KapraOpCode, Operand};
use sha3::{Digest, Sha3_256};
use std::sync::Arc;
use std::alloc::{alloc, dealloc, Layout};
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/// Represents a data blob with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KSLDataBlob {
    /// Element type of the data
    pub element_type: Type,
    /// Size in bytes
    pub size: usize,
    /// Memory alignment
    pub alignment: usize,
    /// Content hash for verification
    pub hash: [u8; 32],
    /// Actual data bytes
    pub data: Vec<u8>,
}

impl KSLDataBlob {
    /// Creates a new data blob from raw bytes
    pub fn new(data: Vec<u8>, element_type: Type, alignment: usize) -> Self {
        let size = data.len();
        let mut hasher = Sha3_256::new();
        hasher.update(&data);
        let hash = hasher.finalize().into();

        KSLDataBlob {
            element_type,
            size,
            alignment,
            hash,
            data,
        }
    }

    /// Loads a data blob from a file
    pub fn from_file<P: AsRef<Path>>(path: P, element_type: Type, alignment: usize) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(Self::new(data, element_type, alignment))
    }

    /// Saves a data blob to a file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(&self.data)
    }

    /// Verifies the data blob's hash
    pub fn verify(&self) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.data);
        let computed_hash: [u8; 32] = hasher.finalize().into();
        computed_hash == self.hash
    }

    /// Gets a reference to the data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Gets the memory layout for allocation
    pub fn layout(&self) -> Layout {
        Layout::from_size_align(self.size, self.alignment)
            .expect("Invalid layout parameters")
    }
}

/// Memory manager for data blobs
pub struct DataBlobMemoryManager {
    /// Allocated blobs
    blobs: Vec<Arc<KSLDataBlob>>,
}

impl DataBlobMemoryManager {
    /// Creates a new memory manager
    pub fn new() -> Self {
        DataBlobMemoryManager {
            blobs: Vec::new(),
        }
    }

    /// Allocates memory for a data blob
    pub fn allocate(&mut self, blob: KSLDataBlob) -> Result<Arc<KSLDataBlob>, KslError> {
        // Verify the blob first
        if !blob.verify() {
            return Err(KslError::new(
                ErrorType::DataBlobError,
                "Data blob verification failed".to_string(),
            ));
        }

        let blob = Arc::new(blob);
        self.blobs.push(Arc::clone(&blob));
        Ok(blob)
    }

    /// Deallocates a data blob
    pub fn deallocate(&mut self, blob: &Arc<KSLDataBlob>) {
        self.blobs.retain(|b| !Arc::ptr_eq(b, blob));
    }
}

/// Bytecode operations for data blobs
#[derive(Debug, Clone, Copy)]
pub enum DataBlobOpCode {
    /// Load a data blob from memory
    Load = 0x70,
    /// Store a data blob to memory
    Store = 0x71,
    /// Verify a data blob's hash
    Verify = 0x72,
}

impl From<DataBlobOpCode> for KapraOpCode {
    fn from(op: DataBlobOpCode) -> Self {
        KapraOpCode::from_u8(op as u8)
            .expect("Invalid data blob opcode")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_blob_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let blob = KSLDataBlob::new(
            data.clone(),
            Type::U8,
            8,
        );
        assert_eq!(blob.size, 5);
        assert_eq!(blob.data, data);
        assert!(blob.verify());
    }

    #[test]
    fn test_data_blob_memory_manager() {
        let mut manager = DataBlobMemoryManager::new();
        let blob = KSLDataBlob::new(
            vec![1, 2, 3],
            Type::U8,
            8,
        );
        let arc_blob = manager.allocate(blob).unwrap();
        assert_eq!(manager.blobs.len(), 1);
        manager.deallocate(&arc_blob);
        assert_eq!(manager.blobs.len(), 0);
    }
} 