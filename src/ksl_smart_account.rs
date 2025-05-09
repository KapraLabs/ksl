use crate::ksl_types::*;
use crate::ksl_kapra_crypto::FixedArray;
use serde::{Serialize, Deserialize};

/// Defines a SmartAccount resource in KSL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartAccount {
    pub balance: u64,
    pub sponsor: Option<FixedArray<32>>,         // Sponsor's address
    pub limit: u64,                              // Max gas a sponsor is willing to cover
    pub guardians: Vec<FixedArray<32>>,          // Guardian keys (recovery logic)
    pub version: u32,
}

impl SmartAccount {
    /// Creates a new SmartAccount instance
    pub fn new(balance: u64) -> Self {
        SmartAccount {
            balance,
            sponsor: None,
            limit: 0,
            guardians: Vec::new(),
            version: 1,
        }
    }

    /// Sets a sponsor for gas payments
    pub fn set_sponsor(&mut self, sponsor: FixedArray<32>, limit: u64) {
        self.sponsor = Some(sponsor);
        self.limit = limit;
    }

    /// Removes the current sponsor
    pub fn remove_sponsor(&mut self) {
        self.sponsor = None;
        self.limit = 0;
    }

    /// Adds a guardian key
    pub fn add_guardian(&mut self, guardian: FixedArray<32>) {
        if !self.guardians.contains(&guardian) {
            self.guardians.push(guardian);
        }
    }

    /// Removes a guardian key
    pub fn remove_guardian(&mut self, guardian: &FixedArray<32>) -> bool {
        if let Some(pos) = self.guardians.iter().position(|g| g == guardian) {
            self.guardians.remove(pos);
            true
        } else {
            false
        }
    }

    /// Checks if an address is a guardian
    pub fn is_guardian(&self, address: &FixedArray<32>) -> bool {
        self.guardians.contains(address)
    }

    /// Updates the account version
    pub fn update_version(&mut self) {
        self.version += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smart_account_creation() {
        let account = SmartAccount::new(1000);
        assert_eq!(account.balance, 1000);
        assert!(account.sponsor.is_none());
        assert_eq!(account.limit, 0);
        assert!(account.guardians.is_empty());
        assert_eq!(account.version, 1);
    }

    #[test]
    fn test_sponsor_management() {
        let mut account = SmartAccount::new(1000);
        let sponsor = FixedArray([1; 32]);
        
        account.set_sponsor(sponsor, 500);
        assert!(account.sponsor.is_some());
        assert_eq!(account.limit, 500);
        
        account.remove_sponsor();
        assert!(account.sponsor.is_none());
        assert_eq!(account.limit, 0);
    }

    #[test]
    fn test_guardian_management() {
        let mut account = SmartAccount::new(1000);
        let guardian = FixedArray([2; 32]);
        
        account.add_guardian(guardian);
        assert!(account.is_guardian(&guardian));
        
        assert!(account.remove_guardian(&guardian));
        assert!(!account.is_guardian(&guardian));
    }
} 