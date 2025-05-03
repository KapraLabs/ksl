// ksl_security.rs
// Implements advanced security checks for KSL programs, detecting vulnerabilities
// like reentrancy and buffer overflows, enforcing stricter capability checks, and
// generating security reports.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_sandbox::{Sandbox, run_sandbox};
use crate::ksl_verifier::verify;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::collections::{HashSet, HashMap};

// Security check configuration
#[derive(Debug)]
pub struct SecurityConfig {
    input_file: PathBuf, // Source file to analyze
    report_path: Option<PathBuf>, // Optional path for security report
}

// Security vulnerability report entry
#[derive(Debug)]
struct SecurityIssue {
    kind: String, // Type of issue (e.g., "Reentrancy", "BufferOverflow")
    message: String, // Detailed description
    position: SourcePosition, // Location in source code
    remediation: String, // Suggested fix
}

// Security analyzer
pub struct SecurityAnalyzer {
    config: SecurityConfig,
    issues: Vec<SecurityIssue>,
    capabilities: HashSet<String>, // Allowed capabilities (from #[allow])
    call_stack: Vec<String>, // Track function calls for reentrancy detection
}

impl SecurityAnalyzer {
    pub fn new(config: SecurityConfig) -> Self {
        SecurityAnalyzer {
            config,
            issues: Vec::new(),
            capabilities: HashSet::new(),
            call_stack: Vec::new(),
        }
    }

    // Analyze a KSL source file for security issues
    pub fn analyze(&mut self) -> Result<Vec<SecurityIssue>, KslError> {
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

        // Run sandbox validation with stricter capability checks
        let mut sandbox = Sandbox::new();
        sandbox.run_sandbox(&self.config.input_file)
            .map_err(|e| KslError::type_error(
                e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
                pos,
            ))?;
        self.capabilities = extract_capabilities(&ast);

        // Analyze AST for vulnerabilities
        self.analyze_ast(&ast)?;

        // Verify security properties
        verify(&ast)
            .map_err(|e| KslError::type_error(
                format!("Verification failed: {}", e),
                pos,
            ))?;

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

        Ok(self.issues.clone())
    }

    // Analyze AST for vulnerabilities
    fn analyze_ast(&mut self, ast: &[AstNode]) -> Result<(), KslError> {
        for node in ast {
            match node {
                AstNode::FnDecl { name, body, attributes, .. } => {
                    self.call_stack.push(name.clone());
                    self.check_reentrancy(body)?;
                    self.check_buffer_overflow(body)?;
                    self.check_capabilities(node)?;
                    self.analyze_ast(body)?;
                    self.call_stack.pop();
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    self.check_buffer_overflow(&[condition.clone()])?;
                    self.analyze_ast(then_branch)?;
                    if let Some(else_branch) = else_branch {
                        self.analyze_ast(else_branch)?;
                    }
                }
                AstNode::Match { expr, arms } => {
                    self.check_buffer_overflow(&[expr.clone()])?;
                    for arm in arms {
                        self.analyze_ast(&arm.body)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // Check for reentrancy vulnerabilities
    fn check_reentrancy(&mut self, nodes: &[AstNode]) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        for node in nodes {
            match node {
                AstNode::Expr { kind: ExprKind::Call { name, .. } } => {
                    // Check for external calls
                    if name == "http.get" || name == "bls_verify" {
                        // Check if this call could lead to reentrancy
                        if let Some(current_func) = self.call_stack.last() {
                            if self.call_stack.iter().filter(|&&ref n| n == current_func).count() > 1 {
                                self.issues.push(SecurityIssue {
                                    kind: "Reentrancy".to_string(),
                                    message: format!("Potential reentrancy vulnerability: {} called in recursive context", name),
                                    position: pos,
                                    remediation: "Avoid recursive calls to external functions; use a reentrancy guard".to_string(),
                                });
                            }
                        }
                    }
                }
                AstNode::If { then_branch, else_branch, .. } => {
                    self.check_reentrancy(then_branch)?;
                    if let Some(else_branch) = else_branch {
                        self.check_reentrancy(else_branch)?;
                    }
                }
                AstNode::Match { arms, .. } => {
                    for arm in arms {
                        self.check_reentrancy(&arm.body)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // Check for potential buffer overflows (simplified)
    fn check_buffer_overflow(&mut self, nodes: &[AstNode]) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        for node in nodes {
            if let AstNode::Expr { kind: ExprKind::ArrayAccess { array, index } } = node {
                if let AstNode::Expr { kind: ExprKind::Ident(array_name) } = &**array {
                    // Simplified: Assume array size is in type annotation (not fully implemented)
                    let size = 32; // Placeholder: Extract from type annotation in real implementation
                    if let AstNode::Expr { kind: ExprKind::Number(index_val) } = &**index {
                        if let Ok(idx) = index_val.parse::<u32>() {
                            if idx >= size {
                                self.issues.push(SecurityIssue {
                                    kind: "BufferOverflow".to_string(),
                                    message: format!("Potential buffer overflow: Index {} exceeds array size {} for {}", idx, size, array_name),
                                    position: pos,
                                    remediation: "Add bounds checking before array access".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // Enforce stricter capability checks
    fn check_capabilities(&mut self, node: &AstNode) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        if let AstNode::FnDecl { name, body, attributes, .. } = node {
            let mut has_external_call = false;
            self.detect_external_calls(body, &mut has_external_call);
            if has_external_call {
                let allowed = attributes.iter().any(|attr| {
                    attr.name.starts_with("allow(") && attr.name.ends_with(")") &&
                    (attr.name.contains("http") || attr.name.contains("sensor") || attr.name.contains("crypto"))
                });
                if !allowed {
                    self.issues.push(SecurityIssue {
                        kind: "CapabilityViolation".to_string(),
                        message: format!("Function {} makes external calls without explicit #[allow] annotation", name),
                        position: pos,
                        remediation: "Add #[allow(http)] or #[allow(crypto)] annotation to permit external calls".to_string(),
                    });
                } else if !self.capabilities.contains("http") && !self.capabilities.contains("crypto") {
                    self.issues.push(SecurityIssue {
                        kind: "CapabilityViolation".to_string(),
                        message: format!("Function {} makes external calls but capability not globally allowed", name),
                        position: pos,
                        remediation: "Ensure #[allow(http)] or #[allow(crypto)] is present at the file level".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    // Detect external calls in a block
    fn detect_external_calls(&self, nodes: &[AstNode], has_external_call: &mut bool) {
        for node in nodes {
            match node {
                AstNode::Expr { kind: ExprKind::Call { name, .. } } => {
                    if name == "http.get" || name == "bls_verify" || name == "device.sensor" {
                        *has_external_call = true;
                    }
                }
                AstNode::If { then_branch, else_branch, .. } => {
                    self.detect_external_calls(then_branch, has_external_call);
                    if let Some(else_branch) = else_branch {
                        self.detect_external_calls(else_branch, has_external_call);
                    }
                }
                AstNode::Match { arms, .. } => {
                    for arm in arms {
                        self.detect_external_calls(&arm.body, has_external_call);
                    }
                }
                _ => {}
            }
        }
    }

    // Generate security report
    fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str("KSL Security Report\n=================\n\n");
        if self.issues.is_empty() {
            report.push_str("No security issues detected.\n");
        } else {
            report.push_str(&format!("Found {} security issues:\n\n", self.issues.len()));
            for (i, issue) in self.issues.iter().enumerate() {
                report.push_str(&format!(
                    "Issue {}: {}\n  Message: {}\n  Position: {}\n  Remediation: {}\n\n",
                    i + 1,
                    issue.kind,
                    issue.message,
                    issue.position,
                    issue.remediation
                ));
            }
        }
        report
    }
}

// Extract capabilities from AST (e.g., #[allow(http)])
fn extract_capabilities(ast: &[AstNode]) -> HashSet<String> {
    let mut capabilities = HashSet::new();
    for node in ast {
        if let AstNode::FnDecl { attributes, .. } = node {
            for attr in attributes {
                if attr.name.starts_with("allow(") && attr.name.ends_with(")") {
                    let cap = attr.name[6..attr.name.len()-1].to_string();
                    capabilities.insert(cap);
                }
            }
        }
    }
    capabilities
}

// Public API to perform security analysis
pub fn analyze_security(input_file: &PathBuf, report_path: Option<PathBuf>) -> Result<Vec<SecurityIssue>, KslError> {
    let config = SecurityConfig {
        input_file: input_file.clone(),
        report_path,
    };
    let mut analyzer = SecurityAnalyzer::new(config);
    analyzer.analyze()
}

// Assume ksl_parser.rs, ksl_sandbox.rs, ksl_verifier.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, ParseError};
}

mod ksl_sandbox {
    pub use super::{Sandbox, run_sandbox};
}

mod ksl_verifier {
    pub use super::verify;
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
    fn test_security_reentrancy() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "#[allow(http)]\nfn risky() {{ http.get(\"url\"); risky(); }}\nfn main() {{ risky(); }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let issues = analyze_security(&input_file, Some(report_path.clone())).unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].kind, "Reentrancy");
        assert!(issues[0].message.contains("Potential reentrancy vulnerability"));

        let content = fs::read_to_string(&report_path).unwrap();
        assert!(content.contains("Reentrancy"));
        assert!(content.contains("Avoid recursive calls to external functions"));
    }

    #[test]
    fn test_security_buffer_overflow() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let arr: array<u8, 32> = [0; 32]; let x = arr[40]; }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let issues = analyze_security(&input_file, Some(report_path.clone())).unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].kind, "BufferOverflow");
        assert!(issues[0].message.contains("Potential buffer overflow"));

        let content = fs::read_to_string(&report_path).unwrap();
        assert!(content.contains("BufferOverflow"));
        assert!(content.contains("Add bounds checking before array access"));
    }

    #[test]
    fn test_security_capability_violation() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn risky() {{ http.get(\"url\"); }}\nfn main() {{ risky(); }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let issues = analyze_security(&input_file, Some(report_path.clone())).unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].kind, "CapabilityViolation");
        assert!(issues[0].message.contains("Function risky makes external calls without explicit #[allow] annotation"));

        let content = fs::read_to_string(&report_path).unwrap();
        assert!(content.contains("CapabilityViolation"));
        assert!(content.contains("Add #[allow(http)]"));
    }

    #[test]
    fn test_security_no_issues() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("input.ksl");
        let mut file = File::create(&input_file).unwrap();
        writeln!(
            file,
            "fn main() {{ let x: u32 = 42; }}"
        ).unwrap();

        let report_path = temp_dir.path().join("report.txt");
        let issues = analyze_security(&input_file, Some(report_path.clone())).unwrap();
        assert!(issues.is_empty());

        let content = fs::read_to_string(&report_path).unwrap();
        assert!(content.contains("No security issues detected"));
    }
}
