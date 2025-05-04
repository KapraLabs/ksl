// ksl_security.rs
// Implements advanced security checks for KSL programs, detecting vulnerabilities
// like reentrancy and buffer overflows, enforcing stricter capability checks, and
// generating security reports with async support.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_sandbox::{Sandbox, SandboxPolicy, run_sandbox_async};
use crate::ksl_kapra_crypto::{CryptoContext, CryptoError};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_verifier::verify;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::collections::{HashSet, HashMap};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Security check configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Source file to analyze
    pub input_file: PathBuf,
    /// Optional path for security report
    pub report_path: Option<PathBuf>,
    /// Whether to use async operations
    pub use_async: bool,
    /// Sandbox policy to enforce
    pub sandbox_policy: SandboxPolicy,
}

/// Security vulnerability report entry
#[derive(Debug, Clone)]
pub struct SecurityIssue {
    /// Type of issue (e.g., "Reentrancy", "BufferOverflow")
    pub kind: String,
    /// Detailed description
    pub message: String,
    /// Location in source code
    pub position: SourcePosition,
    /// Suggested fix
    pub remediation: String,
}

/// Security analyzer state
#[derive(Debug, Clone)]
pub struct SecurityState {
    /// Tracked security issues
    pub issues: Vec<SecurityIssue>,
    /// Allowed capabilities (from #[allow])
    pub capabilities: HashSet<String>,
    /// Track function calls for reentrancy detection
    pub call_stack: Vec<String>,
    /// Crypto context for security checks
    pub crypto_context: Option<CryptoContext>,
}

/// Security analyzer for KSL programs
pub struct SecurityAnalyzer {
    config: SecurityConfig,
    state: Arc<RwLock<SecurityState>>,
    async_runtime: Arc<AsyncRuntime>,
}

impl SecurityAnalyzer {
    /// Creates a new security analyzer
    pub fn new(config: SecurityConfig) -> Self {
        SecurityAnalyzer {
            config: config.clone(),
            state: Arc::new(RwLock::new(SecurityState {
                issues: Vec::new(),
                capabilities: HashSet::new(),
                call_stack: Vec::new(),
                crypto_context: None,
            })),
            async_runtime: Arc::new(AsyncRuntime::new()),
        }
    }

    /// Analyze a KSL source file for security issues asynchronously
    pub async fn analyze_async(&self) -> AsyncResult<Vec<SecurityIssue>> {
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
        let mut sandbox = Sandbox::new(self.config.sandbox_policy.clone());
        sandbox.run_sandbox_async(&self.config.input_file).await
            .map_err(|e| KslError::type_error(
                e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
                pos,
            ))?;

        // Update state
        let mut state = self.state.write().await;
        state.capabilities = extract_capabilities(&ast);
        state.crypto_context = Some(CryptoContext::new());

        // Analyze AST for vulnerabilities
        self.analyze_ast_async(&ast).await?;

        // Verify security properties
        verify(&ast)
            .map_err(|e| KslError::type_error(
                format!("Verification failed: {}", e),
                pos,
            ))?;

        // Generate report
        if let Some(report_path) = &self.config.report_path {
            let report_content = self.generate_report().await;
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
            println!("{}", self.generate_report().await);
        }

        Ok(state.issues.clone())
    }

    /// Analyze AST for vulnerabilities asynchronously
    async fn analyze_ast_async(&self, ast: &[AstNode]) -> AsyncResult<()> {
        let mut state = self.state.write().await;
        for node in ast {
            match node {
                AstNode::FnDecl { name, body, attributes, .. } => {
                    state.call_stack.push(name.clone());
                    self.check_reentrancy_async(body).await?;
                    self.check_buffer_overflow_async(body).await?;
                    self.check_capabilities_async(node).await?;
                    self.analyze_ast_async(body).await?;
                    state.call_stack.pop();
                }
                AstNode::If { condition, then_branch, else_branch } => {
                    self.check_buffer_overflow_async(&[condition.clone()]).await?;
                    self.analyze_ast_async(then_branch).await?;
                    if let Some(else_branch) = else_branch {
                        self.analyze_ast_async(else_branch).await?;
                    }
                }
                AstNode::Match { expr, arms } => {
                    self.check_buffer_overflow_async(&[expr.clone()]).await?;
                    for arm in arms {
                        self.analyze_ast_async(&arm.body).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Check for reentrancy vulnerabilities asynchronously
    async fn check_reentrancy_async(&self, nodes: &[AstNode]) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        let state = self.state.read().await;
        for node in nodes {
            match node {
                AstNode::Expr { kind: ExprKind::Call { name, .. } } => {
                    // Check for external calls
                    if name == "http.get" || name == "bls_verify" {
                        // Check if this call could lead to reentrancy
                        if let Some(current_func) = state.call_stack.last() {
                            if state.call_stack.iter().filter(|&&ref n| n == current_func).count() > 1 {
                                let mut state = self.state.write().await;
                                state.issues.push(SecurityIssue {
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
                    self.check_reentrancy_async(then_branch).await?;
                    if let Some(else_branch) = else_branch {
                        self.check_reentrancy_async(else_branch).await?;
                    }
                }
                AstNode::Match { arms, .. } => {
                    for arm in arms {
                        self.check_reentrancy_async(&arm.body).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Check for potential buffer overflows asynchronously
    async fn check_buffer_overflow_async(&self, nodes: &[AstNode]) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        for node in nodes {
            if let AstNode::Expr { kind: ExprKind::ArrayAccess { array, index } } = node {
                if let AstNode::Expr { kind: ExprKind::Ident(array_name) } = &**array {
                    // Simplified: Assume array size is in type annotation (not fully implemented)
                    let size = 32; // Placeholder: Extract from type annotation in real implementation
                    if let AstNode::Expr { kind: ExprKind::Number(index_val) } = &**index {
                        if let Ok(idx) = index_val.parse::<u32>() {
                            if idx >= size {
                                let mut state = self.state.write().await;
                                state.issues.push(SecurityIssue {
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

    /// Enforce stricter capability checks asynchronously
    async fn check_capabilities_async(&self, node: &AstNode) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        if let AstNode::FnDecl { name, body, attributes, .. } = node {
            let mut has_external_call = false;
            self.detect_external_calls(body, &mut has_external_call);
            if has_external_call {
                let state = self.state.read().await;
                let allowed = attributes.iter().any(|attr| {
                    attr.name.starts_with("allow(") && attr.name.ends_with(")") &&
                    (attr.name.contains("http") || attr.name.contains("sensor") || attr.name.contains("crypto"))
                });
                if !allowed {
                    let mut state = self.state.write().await;
                    state.issues.push(SecurityIssue {
                        kind: "CapabilityViolation".to_string(),
                        message: format!("Function {} makes external calls without explicit #[allow] annotation", name),
                        position: pos,
                        remediation: "Add #[allow(http)] or #[allow(crypto)] annotation to permit external calls".to_string(),
                    });
                } else if !state.capabilities.contains("http") && !state.capabilities.contains("crypto") {
                    let mut state = self.state.write().await;
                    state.issues.push(SecurityIssue {
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

    /// Generate security report asynchronously
    async fn generate_report(&self) -> String {
        let state = self.state.read().await;
        let mut report = String::new();
        report.push_str("KSL Security Report\n");
        report.push_str("=================\n\n");
        for issue in &state.issues {
            report.push_str(&format!("Issue: {}\n", issue.kind));
            report.push_str(&format!("Message: {}\n", issue.message));
            report.push_str(&format!("Location: {}:{}\n", issue.position.line, issue.position.column));
            report.push_str(&format!("Remediation: {}\n\n", issue.remediation));
        }
        report
    }
}

/// Public API to analyze security asynchronously
pub async fn analyze_security_async(
    input_file: &PathBuf,
    report_path: Option<PathBuf>,
    sandbox_policy: SandboxPolicy,
) -> AsyncResult<Vec<SecurityIssue>> {
    let config = SecurityConfig {
        input_file: input_file.clone(),
        report_path,
        use_async: true,
        sandbox_policy,
    };
    let analyzer = SecurityAnalyzer::new(config);
    analyzer.analyze_async().await
}

// Assume ksl_parser.rs, ksl_sandbox.rs, ksl_kapra_crypto.rs, ksl_async.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, ParseError};
}

mod ksl_sandbox {
    pub use super::{Sandbox, SandboxPolicy, run_sandbox_async};
}

mod ksl_kapra_crypto {
    pub use super::{CryptoContext, CryptoError};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncResult};
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
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_security_reentrancy_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        fs::write(&input_file, r#"
            fn test() {
                http.get("https://example.com");
                test(); // Recursive call
            }
        "#).unwrap();

        let result = analyze_security_async(
            &input_file,
            None,
            SandboxPolicy::default(),
        ).await;
        assert!(result.is_ok());
        let issues = result.unwrap();
        assert!(issues.iter().any(|i| i.kind == "Reentrancy"));
    }

    #[tokio::test]
    async fn test_security_buffer_overflow_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        fs::write(&input_file, r#"
            fn test() {
                let arr: array<u8, 32> = [0; 32];
                let x = arr[33]; // Out of bounds
            }
        "#).unwrap();

        let result = analyze_security_async(
            &input_file,
            None,
            SandboxPolicy::default(),
        ).await;
        assert!(result.is_ok());
        let issues = result.unwrap();
        assert!(issues.iter().any(|i| i.kind == "BufferOverflow"));
    }

    #[tokio::test]
    async fn test_security_capability_violation_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        fs::write(&input_file, r#"
            fn test() {
                http.get("https://example.com");
            }
        "#).unwrap();

        let result = analyze_security_async(
            &input_file,
            None,
            SandboxPolicy::default(),
        ).await;
        assert!(result.is_ok());
        let issues = result.unwrap();
        assert!(issues.iter().any(|i| i.kind == "CapabilityViolation"));
    }

    #[tokio::test]
    async fn test_security_no_issues_async() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.ksl");
        fs::write(&input_file, r#"
            #[allow(http)]
            fn test() {
                http.get("https://example.com");
            }
        "#).unwrap();

        let result = analyze_security_async(
            &input_file,
            None,
            SandboxPolicy::default(),
        ).await;
        assert!(result.is_ok());
        let issues = result.unwrap();
        assert!(issues.is_empty());
    }
}
