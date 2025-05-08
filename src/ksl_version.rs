use crate::ksl_errors::{KslError, SourcePosition};
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::PathBuf;
use sha2::{Sha256, Digest};

/// Contract version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub checksum: [u8; 32],
}

impl ContractVersion {
    /// Creates a new contract version
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        ContractVersion {
            major,
            minor,
            patch,
            checksum: [0; 32],
        }
    }

    /// Updates the checksum based on contract content
    pub fn update_checksum(&mut self, content: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(content);
        self.checksum = hasher.finalize().into();
    }

    /// Increments the patch version
    pub fn increment_patch(&mut self) {
        self.patch += 1;
    }

    /// Increments the minor version
    pub fn increment_minor(&mut self) {
        self.minor += 1;
        self.patch = 0;
    }

    /// Increments the major version
    pub fn increment_major(&mut self) {
        self.major += 1;
        self.minor = 0;
        self.patch = 0;
    }

    /// Writes version info to file
    pub fn write_to_file(&self, path: &PathBuf) -> Result<(), KslError> {
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            KslError::type_error(
                format!("Failed to serialize version info: {}", e),
                SourcePosition::new(1, 1),
            )
        })?;

        fs::write(path, json).map_err(|e| {
            KslError::type_error(
                format!("Failed to write version file: {}", e),
                SourcePosition::new(1, 1),
            )
        })
    }

    /// Reads version info from file
    pub fn read_from_file(path: &PathBuf) -> Result<Self, KslError> {
        let content = fs::read_to_string(path).map_err(|e| {
            KslError::type_error(
                format!("Failed to read version file: {}", e),
                SourcePosition::new(1, 1),
            )
        })?;

        serde_json::from_str(&content).map_err(|e| {
            KslError::type_error(
                format!("Failed to parse version info: {}", e),
                SourcePosition::new(1, 1),
            )
        })
    }
}

/// Version manager for contracts
pub struct VersionManager {
    versions: Vec<ContractVersion>,
}

impl VersionManager {
    /// Creates a new version manager
    pub fn new() -> Self {
        VersionManager {
            versions: Vec::new(),
        }
    }

    /// Adds a new version
    pub fn add_version(&mut self, version: ContractVersion) {
        self.versions.push(version);
    }

    /// Gets the latest version
    pub fn get_latest(&self) -> Option<&ContractVersion> {
        self.versions.last()
    }

    /// Gets version by checksum
    pub fn get_by_checksum(&self, checksum: &[u8; 32]) -> Option<&ContractVersion> {
        self.versions.iter().find(|v| v.checksum == *checksum)
    }

    /// Verifies version compatibility
    pub fn verify_compatibility(&self, version: &ContractVersion) -> bool {
        if let Some(latest) = self.get_latest() {
            // Major version must match
            if version.major != latest.major {
                return false;
            }
            // Minor version must be >= latest
            if version.minor < latest.minor {
                return false;
            }
            // If minor version matches, patch must be >= latest
            if version.minor == latest.minor && version.patch < latest.patch {
                return false;
            }
            true
        } else {
            true // No previous versions, so compatible
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_creation() {
        let mut version = ContractVersion::new(1, 0, 0);
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 0);
        assert_eq!(version.patch, 0);

        version.increment_patch();
        assert_eq!(version.patch, 1);

        version.increment_minor();
        assert_eq!(version.minor, 1);
        assert_eq!(version.patch, 0);

        version.increment_major();
        assert_eq!(version.major, 2);
        assert_eq!(version.minor, 0);
        assert_eq!(version.patch, 0);
    }

    #[test]
    fn test_version_manager() {
        let mut manager = VersionManager::new();
        
        let v1 = ContractVersion::new(1, 0, 0);
        let v2 = ContractVersion::new(1, 1, 0);
        let v3 = ContractVersion::new(2, 0, 0);

        manager.add_version(v1.clone());
        manager.add_version(v2.clone());
        manager.add_version(v3.clone());

        assert_eq!(manager.get_latest().unwrap().major, 2);
        assert!(manager.verify_compatibility(&v2));
        assert!(!manager.verify_compatibility(&ContractVersion::new(1, 0, 0)));
    }
} 