// ksl_sandbox.rs
// Implements a sandboxing system to restrict KSL program capabilities for secure execution.

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

// Sandbox policy configuration
#[derive(Debug)]
struct SandboxPolicy {
    allow_http: bool,
    allow_sensor: bool,
    max_memory: usize, // Bytes
    max_instructions: u64,
}

// Sandbox state
pub struct Sandbox {
    module_system: ModuleSystem,
    policy: SandboxPolicy,
    allowed_functions: HashSet<String>,
}

impl Sandbox {
    pub fn new() -> Self {
        Sandbox {
            module_system: ModuleSystem::new(),
            policy: SandboxPolicy {
                allow_http: false,
                allow_sensor: false,
                max_memory: 1024 * 1024, // 1 MB
                max_instructions: 100_000,
            },
            allowed_functions: HashSet::new(),
        }
    }

    // Run a KSL program in a sandbox
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

        // Run with sandbox restrictions
        let mut vm = KapraVM::new_sandboxed(bytecode.clone(), &self.policy, &self.allowed_functions);
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
        assert!(errors[0].to_string().contains("Unauthorized http.get call"));
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
}