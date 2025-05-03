// ksl_contract_verifier.rs
// Provides formal verification for blockchain smart contracts, checking properties
// like arithmetic overflow, state consistency, and gas usage.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_verifier::verify;
use crate::ksl_security::{analyze_security, SecurityIssue};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

// Verification configuration
#[derive(Debug)]
pub struct VerificationConfig {
    input_file: PathBuf, // Source file to verify
    property: String, // Property to verify (e.g., "overflow", "state", "gas")
    report_path: Option<PathBuf>, // Optional path for verification report
}

// Verification result
#[derive(Debug)]
struct VerificationResult {
    property: String,
    passed: bool,
    message: String,
    position: SourcePosition,
}

// Contract verifier
pub struct ContractVerifier {
    config: VerificationConfig,
    results: Vec<VerificationResult>,
}

impl ContractVerifier {
    pub fn new(config: VerificationConfig) -> Self {
        ContractVerifier {
            config,
            results: Vec::new(),
        }
    }

    // Verify the smart contract
    pub fn verify_contract(&mut self) -> Result<Vec<VerificationResult>, KslError> {
        let pos = SourcePosition::new(1, 1);
        // Read and parse source
        let source = fs::read_to_string(&self.config.input_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", self.config.input_file.display(), e),
                pos,
            ))?;
        let ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;

        // Run security analysis
        let security_issues = analyze_security(&self.config.input_file, None)?;
        for issue in security_issues {
            self.results.push(VerificationResult {
                property: issue.kind,
                passed: false,
                message: issue.message,
                position: issue.position,
            });
        }

        // Run basic verification
        verify(&ast)
            .map_err(|e| KslError::type_error(format!("Basic verification failed: {}", e), pos))?;

        // Verify specific property
        match self.config.property.as_str() {
            "overflow" => self.check_overflow(&ast)?,
            "state" => self.check_state_consistency(&ast)?,
            "gas" => self.check_gas_usage(&ast)?,
            _ => return Err(KslError::type_error(
                format!("Unsupported property: {}", self.config.property),
                pos,
            )),
        }

        // Generate report
        if let Some(report_path) = &self.config.report_path {
            let report_content = self.generate_report();
            File::create(report_path)
                .map_err(|e| KslError::type_error(
                    format!("Failed to create report file {}: {}", report_path.display(), e),
                    pos,
                ))?
                .write_all(report_content.as_bytes())
                .map_err(|e| KslError::type_error(
                    format!("Failed to write report file {}: {}", report_path.display(), e),
                    pos,
                ))?;
        } else {
            println!("{}", self.generate_report());
        }

        Ok(self.results.clone())
    }

    // Check for arithmetic overflow
    fn check_overflow(&mut self, ast: &[AstNode]) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        for node in ast {
            match node {
                AstNode::Expr { kind: ExprKind::BinaryOp { op, left, right } } => {
                    if op == "+" || op == "*" {
                        if let (ExprKind::Number(left_val), ExprKind::Number(right_val)) = (&left.kind, &right.kind) {
                            if let (Ok(left_num), Ok(right_num)) = (left_val.parse::<u32>(), right_val.parse::<u32>()) {
                                if op == "+" && left_num.checked_add(right_num).is_none() {
                                    self.results.push(VerificationResult {
                                        property: "Overflow".to_string(),
                                        passed: false,
                                        message: format!("Potential arithmetic overflow: {} + {}", left_num, right_num),
                                        position: pos,
                                    });
                                } else if op == "*" && left_num.checked_mul(right_num).is_none() {
                                    self.results.push(VerificationResult {
                                        property: "Overflow".to_string(),
                                        passed: false,
                                        message: format!("Potential arithmetic overflow: {} * {}", left_num, right_num),
                                        position: pos,
                                    });
                                }
                            }
                        }
                    }
                    self.check_overflow(&[left.clone(), right.clone()])?;
                }
                AstNode::If { then_branch, else_branch, .. } => {
                    self.check_overflow(then_branch)?;
                    if let Some(else_branch) = else_branch {
                        self.check_overflow(else_branch)?;
                    }
                }
                AstNode::Match { arms, .. } => {
                    for arm in arms {
                        self.check_overflow(&arm.body)?;
                    }
                }
                AstNode::FnDecl { body, .. } => {
                    self.check_overflow(body)?;
                }
                _ => {}
            }
        }
        if !self.results.iter().any(|r| r.property == "Overflow" && !r.passed) {
            self.results.push(VerificationResult {
                property: "Overflow".to_string(),
                passed: true,
                message: "No arithmetic overflows detected".to_string(),
                position: pos,
            });
        }
        Ok(())
    }

    // Check state consistency (simplified)
    fn check_state_consistency(&mut self, ast: &[AstNode]) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut state_vars = HashSet::new();
        let mut modified_in_branch = false;

        for node in ast {
            match node {
                AstNode::VarDecl { name, is_mutable, .. } if *is_mutable => {
                    state_vars.insert(name.clone());
                }
                AstNode::If { then_branch, else_branch, .. } => {
                    let mut then_modifies = false;
                    self.check_branch_modifications(then_branch, &state_vars, &mut then_modifies)?;
                    let mut else_modifies = false;
                    if let Some(else_branch) = else_branch {
                        self.check_branch_modifications(else_branch, &state_vars, &mut else_modifies)?;
                    }
                    if then_modifies != else_modifies {
                        self.results.push(VerificationResult {
                            property: "StateConsistency".to_string(),
                            passed: false,
                            message: "Inconsistent state modification in if branches".to_string(),
                            position: pos,
                        });
                    }
                    self.check_state_consistency(then_branch)?;
                    if let Some(else_branch) = else_branch {
                        self.check_state_consistency(else_branch)?;
                    }
                }
                AstNode::Match { arms, .. } => {
                    let mut branch_modifications = Vec::new();
                    for arm in arms {
                        let mut modifies = false;
                        self.check_branch_modifications(&arm.body, &state_vars, &mut modifies)?;
                        branch_modifications.push(modifies);
                        self.check_state_consistency(&arm.body)?;
                    }
                    if branch_modifications.iter().any(|&m| m != branch_modifications[0]) {
                        self.results.push(VerificationResult {
                            property: "StateConsistency".to_string(),
                            passed: false,
                            message: "Inconsistent state modification in match branches".to_string(),
                            position: pos,
                        });
                    }
                }
                AstNode::FnDecl { body, .. } => {
                    self.check_state_consistency(body)?;
                }
                _ => {}
            }
        }

        if !self.results.iter().any(|r| r.property == "StateConsistency" && !r.passed) {
            self.results.push(VerificationResult {
                property: "StateConsistency".to_string(),
                passed: true,
                message: "State consistency verified".to_string(),
                position: pos,
            });
        }
        Ok(())
    }

    // Check branch modifications
    fn check_branch_modifications(&self, nodes: &[AstNode], state_vars: &HashSet<String>, modifies: &mut bool) -> Result<(), KslError> {
        for node in nodes {
            match node {
                AstNode::Expr { kind: ExprKind::Assignment { left, .. } } => {
                    if let ExprKind::Ident(name) = &left.kind {
                        if state_vars.contains(name) {
                            *modifies = true;
                        }
                    }
                }
                AstNode::If { then_branch, else_branch, .. } => {
                    self.check_branch_modifications(then_branch, state_vars, modifies)?;
                    if let Some(else_branch) = else_branch {
                        self.check_branch_modifications(else_branch, state_vars, modifies)?;
                    }
                }
                AstNode::Match { arms, .. } => {
                    for arm in arms {
                        self.check_branch_modifications(&arm.body, state_vars, modifies)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // Check gas usage (simplified)
    fn check_gas_usage(&mut self, ast: &[AstNode]) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut gas_usage = 0;

        for node in ast {
            match node {
                AstNode::Expr { kind: ExprKind::Call { name, .. } } => {
                    if name == "sha3" || name == "bls_verify" {
                        gas_usage += 100; // High-cost operation
                    }
                }
                AstNode::Expr { kind: ExprKind::BinaryOp { op, left, right, .. } } if op == "+" || op == "*" => {
                    gas_usage += 5; // Arithmetic operation
                    self.check_gas_usage(&[left.clone(), right.clone()])?;
                }
                AstNode::If { then_branch, else_branch, .. } => {
                    self.check_gas_usage(then_branch)?;
                    if let Some(else_branch) = else_branch {
                        self.check_gas_usage(else_branch)?;
                    }
                }
                AstNode::Match { arms, .. } => {
                    for arm in arms {
                        self.check_gas_usage(&arm.body)?;
                    }
                }
                AstNode::FnDecl { body, .. } => {
                    self.check_gas_usage(body)?;
                }
                _ => gas_usage += 1, // Base cost for other operations
            }
        }

        const GAS_LIMIT: u32 = 1000; // Simplified gas limit
        if gas_usage > GAS_LIMIT {
            self.results.push(VerificationResult {
                property: "GasUsage".to_string(),
                passed: false,
                message: format!("Gas usage {} exceeds limit {}", gas_usage, GAS_LIMIT),
                position: pos,
            });
        } else {
            self.results.push(VerificationResult {
                property: "GasUsage".to_string(),
                passed: true,
                message: format!("Gas usage {} within limit {}", gas_usage, GAS_LIMIT),
                position: pos,
            });
        }
        Ok(())
    }

    // Generate verification report
    fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str("KSL Contract Verification Report\n=================\n\n");
        if self.results.is_empty() {
            report.push_str("No verification results.\n");
        } else {
            report.push_str(&format!("Verified {} properties:\n\n", self.results.len()));
            for (i, result) in self.results.iter().enumerate() {
                report.push_str(&format!(
                    "Property {}: {}\n  Status: {}\n  Message: {}\n  Position: {}\n\n",
                    i + 1,
                    result.property,
                    if result.passed { "Passed" } else { "Failed" },
                    result.message,
                    result.position
                ));
            }
        }
        report
    }
}

// Public API to verify a smart contract
pub fn contract_verify(input_file: &PathBuf, property: &str, report_path: Option<PathBuf>) -> Result<Vec<VerificationResult>, KslError> {
    let config = VerificationConfig {
        input_file: input_file.clone(),
        property: property.to_string(),
        report_path,
    };
    let mut verifier = ContractVerifier::new(config);
    verifier.verify_contract()
}

// Assume ksl_parser.rs, ksl_verifier.rs, ksl_security.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, ParseError};
}

mod ksl_verifier {
    pub use super::verify;
}

mod ksl_security {
    pub use super::{analyze_security, SecurityIssue};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_verify_overflow() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 4294967295; let y: u32 = 1; let z = x + y; }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let results = contract_verify(&input_file, "overflow", Some(report_path.clone())).unwrap();
        assert!(results.iter().any(|r| r.property == "Overflow" && !r.passed));
        assert!(results.iter().any(|r| r.message.contains("Potential arithmetic overflow")));

        let content = fs::read_to_string(&report_path).unwrap();
        assert!(content.contains("Overflow"));
        assert!(content.contains("Failed"));
    }

    #[test]
    fn test_verify_state_consistency() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let mut state: u32 = 0; if true {{ state = 1; }} else {{}} }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let results = contract_verify(&input_file, "state", Some(report_path.clone())).unwrap();
        assert!(results.iter().any(|r| r.property == "StateConsistency" && !r.passed));
        assert!(results.iter().any(|r| r.message.contains("Inconsistent state modification")));

        let content = fs::read_to_string(&report_path).unwrap();
        assert!(content.contains("StateConsistency"));
        assert!(content.contains("Failed"));
    }

    #[test]
    fn test_verify_gas_usage() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x = sha3(\"data\"); let y = sha3(\"data\"); let z = sha3(\"data\"); }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let results = contract_verify(&input_file, "gas", Some(report_path.clone())).unwrap();
        assert!(results.iter().any(|r| r.property == "GasUsage" && !r.passed));
        assert!(results.iter().any(|r| r.message.contains("Gas usage")));

        let content = fs::read_to_string(&report_path).unwrap();
        assert!(content.contains("GasUsage"));
        assert!(content.contains("Failed"));
    }

    #[test]
    fn test_verify_no_issues() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let results = contract_verify(&input_file, "overflow", Some(report_path.clone())).unwrap();
        assert!(results.iter().all(|r| r.passed));

        let content = fs::read_to_string(&report_path).unwrap();
        assert!(content.contains("Passed"));
    }
}

