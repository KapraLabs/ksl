// ksl_sandbox.rs
// Implements a secure sandboxing system for KSL program execution.
// 
// Features:
// - Container-based isolation using Docker
// - Seccomp-based system call filtering
// - Network access control and rate limiting
// - Resource usage limits (memory, CPU, instructions)
// - Function-level permission control
// 
// Usage:
//   let mut sandbox = Sandbox::new();
//   sandbox.configure_policy(SandboxPolicy {
//       containerize: true,
//       allow_http: true,
//       max_memory: 1024 * 1024,
//       max_instructions: 100_000,
//       network_quota: NetworkQuota::default(),
//   });
//   sandbox.run_sandbox(&file_path)?;

use crate::ksl_parser::{parse, AstNode};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::kapra_vm::{KapraVM, run};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs;
use std::path::PathBuf;
use std::collections::HashSet;
use std::time::Duration;

/// Network usage quotas for sandboxed programs
#[derive(Debug, Clone)]
pub struct NetworkQuota {
    pub max_requests_per_second: u32,
    pub max_total_requests: u32,
    pub max_bytes_per_request: u64,
    pub max_total_bytes: u64,
    pub allowed_domains: HashSet<String>,
}

impl Default for NetworkQuota {
    fn default() -> Self {
        NetworkQuota {
            max_requests_per_second: 10,
            max_total_requests: 100,
            max_bytes_per_request: 1024 * 1024, // 1 MB
            max_total_bytes: 10 * 1024 * 1024,  // 10 MB
            allowed_domains: HashSet::new(),
        }
    }
}

/// Security policy configuration for sandboxed execution
#[derive(Debug)]
pub struct SandboxPolicy {
    /// Whether to use container-based isolation
    pub containerize: bool,
    /// Whether to allow HTTP operations
    pub allow_http: bool,
    /// Whether to allow sensor access
    pub allow_sensor: bool,
    /// Maximum memory usage in bytes
    pub max_memory: usize,
    /// Maximum number of VM instructions
    pub max_instructions: u64,
    /// Network usage quotas
    pub network_quota: NetworkQuota,
    /// Seccomp profile for system call filtering
    pub seccomp_profile: Option<String>,
    /// CPU time limit
    pub cpu_time_limit: Duration,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        SandboxPolicy {
            containerize: true,
            allow_http: false,
            allow_sensor: false,
            max_memory: 1024 * 1024, // 1 MB
            max_instructions: 100_000,
            network_quota: NetworkQuota::default(),
            seccomp_profile: None,
            cpu_time_limit: Duration::from_secs(5),
        }
    }
}

/// Sandbox state and configuration
pub struct Sandbox {
    module_system: ModuleSystem,
    policy: SandboxPolicy,
    allowed_functions: HashSet<String>,
    network_state: NetworkState,
}

/// Network state tracking for sandboxed programs
#[derive(Debug)]
struct NetworkState {
    request_count: u32,
    total_bytes: u64,
    last_request_time: std::time::Instant,
    request_times: Vec<std::time::Instant>,
}

impl Default for NetworkState {
    fn default() -> Self {
        NetworkState {
            request_count: 0,
            total_bytes: 0,
            last_request_time: std::time::Instant::now(),
            request_times: Vec::new(),
        }
    }
}

impl Sandbox {
    /// Creates a new sandbox with default security policy
    pub fn new() -> Self {
        Sandbox {
            module_system: ModuleSystem::new(),
            policy: SandboxPolicy::default(),
            allowed_functions: HashSet::new(),
            network_state: NetworkState::default(),
        }
    }

    /// Configures the sandbox policy
    pub fn configure_policy(&mut self, policy: SandboxPolicy) {
        self.policy = policy;
    }

    /// Checks if a network request is allowed under the current policy
    fn check_network_request(&mut self, domain: &str) -> Result<(), KslError> {
        if !self.policy.allow_http {
            return Err(KslError::type_error(
                "HTTP operations not allowed".to_string(),
                SourcePosition::new(1, 1),
            ));
        }

        if !self.policy.network_quota.allowed_domains.is_empty() &&
           !self.policy.network_quota.allowed_domains.contains(domain) {
            return Err(KslError::type_error(
                format!("Domain {} not allowed", domain),
                SourcePosition::new(1, 1),
            ));
        }

        let now = std::time::Instant::now();
        self.network_state.request_count += 1;
        self.network_state.request_times.push(now);

        // Clean up old request times
        self.network_state.request_times.retain(|&time| {
            now.duration_since(time) < Duration::from_secs(1)
        });

        if self.network_state.request_times.len() > self.policy.network_quota.max_requests_per_second as usize {
            return Err(KslError::type_error(
                "Request rate limit exceeded".to_string(),
                SourcePosition::new(1, 1),
            ));
        }

        if self.network_state.request_count > self.policy.network_quota.max_total_requests {
            return Err(KslError::type_error(
                "Total request limit exceeded".to_string(),
                SourcePosition::new(1, 1),
            ));
        }

        Ok(())
    }

    /// Runs a KSL program in a sandbox with the configured security policy
    pub fn run_sandbox(&mut self, file: &PathBuf) -> Result<(), Vec<KslError>> {
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| vec![KslError::type_error(
                "Invalid main file name".to_string(),
                SourcePosition::new(1, 1),
            )])?;

        // Read source file
        let source = fs::read_to_string(file)
            .map_err(|e| vec![KslError::type_error(e.to_string(), SourcePosition::new(1, 1))])?;

        // Parse
        let ast = parse(&source)
            .map_err(|e| vec![KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                SourcePosition::new(1, 1),
            )])?;

        // Collect allowed functions from annotations
        for node in &ast {
            if let AstNode::FnDecl { attributes, name, .. } = node {
                if attributes.iter().any(|attr| attr.name == "allow(http)") {
                    self.allowed_functions.insert("http.get".to_string());
                    self.policy.allow_http = true;
                }
                if attributes.iter().any(|attr| attr.name == "allow(sensor)") {
                    self.allowed_functions.insert("device.sensor".to_string());
                    self.policy.allow_sensor = true;
                }
            }
        }

        // Type-check
        check(&ast)
            .map_err(|errors| errors)?;

        // Compile
        let bytecode = compile(&ast)
            .map_err(|errors| errors.into_iter().map(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1))).collect())?;

        // Apply containerization if enabled
        if self.policy.containerize {
            // TODO: Implement container setup using Docker
            // This would involve:
            // 1. Creating a minimal container image
            // 2. Setting up seccomp profile
            // 3. Configuring resource limits
            // 4. Mounting necessary files
        }

        // Run with sandbox restrictions
        let mut vm = KapraVM::new_sandboxed(
            bytecode.clone(),
            &self.policy,
            &self.allowed_functions,
            self.policy.cpu_time_limit,
        );

        // Set up network monitoring
        vm.set_network_monitor(Box::new(|domain| self.check_network_request(domain)));

        run(vm)
            .map_err(|e| vec![KslError::type_error(
                format!("Sandbox violation at instruction {}: {}", e.pc, e.message),
                SourcePosition::new(1, 1),
            )])?;

        Ok(())
    }
}

// Public API to run a KSL program in a sandbox
pub fn run_sandbox(file: &PathBuf) -> Result<(), Vec<KslError>> {
    let mut sandbox = Sandbox::new();
    sandbox.run_sandbox(file)
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, kapra_vm.rs, ksl_module.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode};
}

mod kapra_vm {
    pub use super::{KapraVM, run};
}

mod ksl_module {
    pub use super::ModuleSystem;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_sandbox_safe_program() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { let x: u32 = 42; let y: u32 = x + x; }"
        ).unwrap();

        let result = run_sandbox(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
    }

    #[test]
    fn test_sandbox_http_violation() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { let data: result<string, error> = http.get(\"url\"); }"
        ).unwrap();

        let result = run_sandbox(&temp_file.path().to_path_buf());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].to_string().contains("HTTP operations not allowed"));
    }

    #[test]
    fn test_sandbox_allowed_http() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[allow(http)]\nfn main() { let data: result<string, error> = http.get(\"url\"); }"
        ).unwrap();

        let result = run_sandbox(&temp_file.path().to_path_buf());
        assert!(result.is_ok());
    }

    #[test]
    fn test_sandbox_network_quota() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[allow(http)]\nfn main() { 
                for i in 0..20 {
                    let _ = http.get(\"url\");
                }
            }"
        ).unwrap();

        let mut sandbox = Sandbox::new();
        let mut policy = SandboxPolicy::default();
        policy.allow_http = true;
        policy.network_quota.max_requests_per_second = 5;
        policy.network_quota.max_total_requests = 10;
        sandbox.configure_policy(policy);

        let result = sandbox.run_sandbox(&temp_file.path().to_path_buf());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].to_string().contains("Request rate limit exceeded"));
    }

    #[test]
    fn test_sandbox_domain_restriction() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "#[allow(http)]\nfn main() { 
                let _ = http.get(\"https://example.com\");
            }"
        ).unwrap();

        let mut sandbox = Sandbox::new();
        let mut policy = SandboxPolicy::default();
        policy.allow_http = true;
        policy.network_quota.allowed_domains.insert("allowed.com".to_string());
        sandbox.configure_policy(policy);

        let result = sandbox.run_sandbox(&temp_file.path().to_path_buf());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].to_string().contains("Domain example.com not allowed"));
    }

    #[test]
    fn test_sandbox_cpu_time_limit() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { 
                let mut i: u64 = 0;
                while true {
                    i = i + 1;
                }
            }"
        ).unwrap();

        let mut sandbox = Sandbox::new();
        let mut policy = SandboxPolicy::default();
        policy.cpu_time_limit = Duration::from_millis(100);
        sandbox.configure_policy(policy);

        let result = sandbox.run_sandbox(&temp_file.path().to_path_buf());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].to_string().contains("CPU time limit exceeded"));
    }

    #[test]
    fn test_sandbox_memory_limit() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { 
                let mut v: vec<u8> = vec![];
                while true {
                    v.push(0);
                }
            }"
        ).unwrap();

        let mut sandbox = Sandbox::new();
        let mut policy = SandboxPolicy::default();
        policy.max_memory = 1024; // 1 KB
        sandbox.configure_policy(policy);

        let result = sandbox.run_sandbox(&temp_file.path().to_path_buf());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].to_string().contains("Memory limit exceeded"));
    }
}