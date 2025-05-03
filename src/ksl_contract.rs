// ksl_contract.rs
// Specialized compiler for blockchain smart contracts, generating optimized bytecode
// and WASM for Ethereum and Solana with gas limits and deterministic execution.

use crate::ksl_parser::{parse, AstNode, ParseError};
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_wasm::generate_wasm;
use crate::ksl_aot::aot_compile;
use crate::ksl_sandbox::run_sandbox;
use crate::ksl_verifier::verify;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

// Contract compilation configuration
#[derive(Debug)]
pub struct ContractConfig {
    target: String, // e.g., "ethereum", "solana"
    gas_limit: u64, // Maximum instructions (simulating gas)
    output_dir: PathBuf, // Directory for artifacts
}

// Contract compiler
pub struct ContractCompiler {
    config: ContractConfig,
}

impl ContractCompiler {
    pub fn new(config: ContractConfig) -> Self {
        ContractCompiler { config }
    }

    // Compile and optimize a KSL program as a blockchain smart contract
    pub fn compile_contract(&self, file: &PathBuf) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Read and parse source
        let source = fs::read_to_string(file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read file {}: {}", file.display(), e),
                pos,
            ))?;
        let ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;

        // Type-check
        check(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Type error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;

        // Verify contract properties
        verify(&ast)
            .map_err(|e| KslError::type_error(
                format!("Verification failed: {}", e),
                pos,
            ))?;

        // Compile to bytecode with optimizations
        let bytecode = compile(&ast)
            .map_err(|errors| KslError::type_error(
                errors.into_iter()
                    .map(|e| format!("Compile error at position {}: {}", e.position, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                pos,
            ))?;
        let optimized_bytecode = optimize_bytecode(&bytecode, self.config.gas_limit)?;

        // Run in sandbox to ensure security
        run_sandbox(file)
            .map_err(|e| KslError::type_error(
                e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
                pos,
            ))?;

        // Generate output based on target
        let file_stem = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KslError::type_error("Invalid file name".to_string(), pos))?;
        fs::create_dir_all(&self.config.output_dir)
            .map_err(|e| KslError::type_error(
                format!("Failed to create output directory {}: {}", self.config.output_dir.display(), e),
                pos,
            ))?;

        match self.config.target.as_str() {
            "ethereum" | "solana" => {
                // Generate WASM for blockchain
                let wasm_path = self.config.output_dir.join(format!("{}.wasm", file_stem));
                let wasm_bytes = generate_wasm(optimized_bytecode)
                    .map_err(|errors| KslError::type_error(
                        errors.into_iter()
                            .map(|e| format!("WASM error at instruction {}: {}", e.instruction, e.message))
                            .collect::<Vec<_>>()
                            .join("\n"),
                        pos,
                    ))?;
                fs::write(&wasm_path, &wasm_bytes)
                    .map_err(|e| KslError::type_error(
                        format!("Failed to write WASM binary {}: {}", wasm_path.display(), e),
                        pos,
                    ))?;
            }
            "native" => {
                // Generate AOT for testing
                let aot_path = self.config.output_dir.join(format!("{}.o", file_stem));
                aot_compile(file, &aot_path, "x86_64")
                    .map_err(|e| KslError::type_error(format!("AOT compilation failed: {}", e), pos))?;
            }
            _ => return Err(KslError::type_error(
                format!("Unsupported target: {}", self.config.target),
                pos,
            )),
        }

        Ok(())
    }
}

// Optimize bytecode for blockchain execution
fn optimize_bytecode(bytecode: &KapraBytecode, gas_limit: u64) -> Result<KapraBytecode, KslError> {
    let pos = SourcePosition::new(1, 1);
    let mut optimized = KapraBytecode::new();
    let mut instruction_count = 0;

    for instr in &bytecode.instructions {
        // Enforce gas limit
        instruction_count += match instr.opcode {
            KapraOpCode::Sha3 | KapraOpCode::BlsVerify => 100, // High-cost operations
            KapraOpCode::Add | KapraOpCode::Sub | KapraOpCode::Mul => 5, // Arithmetic
            _ => 1, // Other instructions
        };
        if instruction_count > gas_limit {
            return Err(KslError::type_error(
                format!("Gas limit {} exceeded: {} instructions", gas_limit, instruction_count),
                pos,
            ));
        }

        // Optimize: Skip redundant Mov instructions (simplified)
        if let KapraOpCode::Mov = instr.opcode {
            if let Some(prev_instr) = optimized.instructions.last() {
                if prev_instr.opcode == KapraOpCode::Mov && prev_instr.operands == instr.operands {
                    continue;
                }
            }
        }

        // Enforce deterministic execution (no time.now)
        if instr.opcode == KapraOpCode::Mov {
            if let Some(operand) = instr.operands.get(1) {
                if let crate::ksl_bytecode::Operand::Immediate(data) = operand {
                    if data.len() == 8 && instr.type_info == Some(crate::ksl_types::Type::U64) {
                        return Err(KslError::type_error(
                            "Non-deterministic time.now call detected".to_string(),
                            pos,
                        ));
                    }
                }
            }
        }

        optimized.instructions.push(instr.clone());
    }

    Ok(optimized)
}

// Public API to compile a blockchain smart contract
pub fn compile_contract(file: &PathBuf, target: &str, gas_limit: u64, output_dir: PathBuf) -> Result<(), KslError> {
    let config = ContractConfig {
        target: target.to_string(),
        gas_limit,
        output_dir,
    };
    let compiler = ContractCompiler::new(config);
    compiler.compile_contract(file)
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_wasm.rs, ksl_aot.rs, ksl_sandbox.rs, ksl_verifier.rs, ksl_bytecode.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ParseError};
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_wasm {
    pub use super::generate_wasm;
}

mod ksl_aot {
    pub use super::aot_compile;
}

mod ksl_sandbox {
    pub use super::run_sandbox;
}

mod ksl_verifier {
    pub use super::verify;
}

mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{TempDir, NamedTempFile};

    #[test]
    fn test_compile_contract_ethereum() {
        let temp_dir = TempDir::new().unwrap();
        let mut temp_file = NamedTempFile::new_in(&temp_dir).unwrap();
        writeln!(
            temp_file,
            "#[verify]\nfn main() { let hash: array<u8, 32> = sha3(\"data\"); }"
        ).unwrap();
        let output_dir = temp_dir.path().join("output");

        let result = compile_contract(&temp_file.path().to_path_buf(), "ethereum", 1000, output_dir.clone());
        assert!(result.is_ok());
        let wasm_path = output_dir.join(format!("{}.wasm", temp_file.path().file_stem().unwrap().to_str().unwrap()));
        assert!(wasm_path.exists());
    }

    #[test]
    fn test_compile_contract_gas_limit_exceeded() {
        let temp_dir = TempDir::new().unwrap();
        let mut temp_file = NamedTempFile::new_in(&temp_dir).unwrap();
        writeln!(
            temp_file,
            "fn main() { let hash: array<u8, 32> = sha3(\"data\"); let hash2: array<u8, 32> = sha3(\"data2\"); }"
        ).unwrap();
        let output_dir = temp_dir.path().join("output");

        let result = compile_contract(&temp_file.path().to_path_buf(), "ethereum", 150, output_dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Gas limit 150 exceeded"));
    }

    #[test]
    fn test_compile_contract_non_deterministic() {
        let temp_dir = TempDir::new().unwrap();
        let mut temp_file = NamedTempFile::new_in(&temp_dir).unwrap();
        writeln!(
            temp_file,
            "fn main() { let t: u64 = time.now(); }"
        ).unwrap();
        let output_dir = temp_dir.path().join("output");

        let result = compile_contract(&temp_file.path().to_path_buf(), "ethereum", 1000, output_dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Non-deterministic time.now call"));
    }

    #[test]
    fn test_compile_contract_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let invalid_file = PathBuf::from("nonexistent.ksl");
        let output_dir = temp_dir.path().join("output");

        let result = compile_contract(&invalid_file, "ethereum", 1000, output_dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read file"));
    }
}