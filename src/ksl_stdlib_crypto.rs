// ksl_stdlib_crypto.rs
// Implements cryptographic functions for KSL standard library, optimized for NFT use cases.

use crate::ksl_types::{Type, TypeError};
use crate::ksl_bytecode::{KapraOpCode, Operand, KapraInstruction};
use crate::ksl_errors::{KslError, SourcePosition};

// Cryptographic function signature
#[derive(Debug, PartialEq, Clone)]
pub struct CryptoStdLibFunction {
    pub name: &'static str,
    pub params: Vec<Type>,
    pub return_type: Type,
    pub opcode: Option<KapraOpCode>, // None for native implementations
}

// Cryptographic standard library registry
pub struct CryptoStdLib {
    functions: Vec<CryptoStdLibFunction>,
}

impl CryptoStdLib {
    pub fn new() -> Self {
        let functions = vec![
            // bls_verify(msg: array<u8, 32>, pubkey: array<u8, 48>, sig: array<u8, 96>) -> bool
            CryptoStdLibFunction {
                name: "bls_verify",
                params: vec![
                    Type::Array(Box::new(Type::U8), 32), // Message
                    Type::Array(Box::new(Type::U8), 48), // Public key
                    Type::Array(Box::new(Type::U8), 96), // Signature
                ],
                return_type: Type::U32, // Boolean as u32
                opcode: Some(KapraOpCode::BlsVerify),
            },
            // dil_verify(msg: array<u8, 32>, pubkey: array<u8, 1312>, sig: array<u8, 2420>) -> bool
            CryptoStdLibFunction {
                name: "dil_verify",
                params: vec![
                    Type::Array(Box::new(Type::U8), 32), // Message
                    Type::Array(Box::new(Type::U8), 1312), // Public key
                    Type::Array(Box::new(Type::U8), 2420), // Signature
                ],
                return_type: Type::U32, // Boolean as u32
                opcode: Some(KapraOpCode::DilithiumVerify),
            },
            // merkle_verify(root: array<u8, 32>, proof: array<u8, N>) -> bool
            CryptoStdLibFunction {
                name: "merkle_verify",
                params: vec![
                    Type::Array(Box::new(Type::U8), 32), // Root
                    Type::Array(Box::new(Type::U8), 0), // Variable-length proof (simplified)
                ],
                return_type: Type::U32, // Boolean as u32
                opcode: Some(KapraOpCode::MerkleVerify),
            },
        ];
        CryptoStdLib { functions }
    }

    // Get function by name
    pub fn get_function(&self, name: &str) -> Option<&CryptoStdLibFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    // Validate function call (used by type checker)
    pub fn validate_call(
        &self,
        name: &str,
        arg_types: &[Type],
        position: SourcePosition,
    ) -> Result<Type, KslError> {
        let func = self.get_function(name).ok_or_else(|| KslError::type_error(
            format!("Undefined cryptographic function: {}", name),
            position,
        ))?;
        if arg_types.len() != func.params.len() {
            return Err(KslError::type_error(
                format!(
                    "Expected {} arguments, got {}",
                    func.params.len(),
                    arg_types.len()
                ),
                position,
            ));
        }
        for (expected, actual) in func.params.iter().zip(arg_types) {
            if expected != actual {
                return Err(KslError::type_error(
                    format!("Argument type mismatch: expected {:?}, got {:?}", expected, actual),
                    position,
                ));
            }
        }
        Ok(func.return_type.clone())
    }

    // Generate bytecode for function call (used by compiler)
    pub fn emit_call(
        &self,
        name: &str,
        arg_regs: &[u8],
        dst_reg: u8,
    ) -> Result<Vec<KapraInstruction>, KslError> {
        let func = self.get_function(name).ok_or_else(|| KslError::type_error(
            format!("Undefined cryptographic function: {}", name),
            SourcePosition::new(1, 1), // Simplified
        ))?;
        if arg_regs.len() != func.params.len() {
            return Err(KslError::type_error(
                format!(
                    "Expected {} arguments, got {}",
                    func.params.len(),
                    arg_regs.len()
                ),
                SourcePosition::new(1, 1),
            ));
        }

        match func.opcode {
            Some(opcode) => {
                let mut operands = vec![Operand::Register(dst_reg)];
                operands.extend(arg_regs.iter().map(|&r| Operand::Register(r)));
                Ok(vec![KapraInstruction::new(
                    opcode,
                    operands,
                    Some(func.return_type.clone()),
                )])
            }
            None => Err(KslError::type_error(
                format!("No implementation for {}", name),
                SourcePosition::new(1, 1),
            )),
        }
    }
}

// Assume ksl_types.rs, ksl_bytecode.rs, and ksl_errors.rs are in the same crate
mod ksl_types {
    pub use super::{Type, TypeError};
}

mod ksl_bytecode {
    pub use super::{KapraOpCode, Operand, KapraInstruction};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_function() {
        let stdlib = CryptoStdLib::new();
        let func = stdlib.get_function("bls_verify").unwrap();
        assert_eq!(func.name, "bls_verify");
        assert_eq!(func.params.len(), 3);
        assert_eq!(func.params[0], Type::Array(Box::new(Type::U8), 32));
        assert_eq!(func.return_type, Type::U32);
        assert_eq!(func.opcode, Some(KapraOpCode::BlsVerify));

        let func = stdlib.get_function("dil_verify").unwrap();
        assert_eq!(func.name, "dil_verify");
        assert_eq!(func.params.len(), 3);
        assert_eq!(func.params[1], Type::Array(Box::new(Type::U8), 1312));
        assert_eq!(func.opcode, Some(KapraOpCode::DilithiumVerify));

        let func = stdlib.get_function("merkle_verify").unwrap();
        assert_eq!(func.name, "merkle_verify");
        assert_eq!(func.params.len(), 2);
        assert_eq!(func.params[0], Type::Array(Box::new(Type::U8), 32));
        assert_eq!(func.opcode, Some(KapraOpCode::MerkleVerify));
    }

    #[test]
    fn test_validate_call() {
        let stdlib = CryptoStdLib::new();
        let pos = SourcePosition::new(1, 1);
        assert_eq!(
            stdlib.validate_call("bls_verify", &[
                Type::Array(Box::new(Type::U8), 32),
                Type::Array(Box::new(Type::U8), 48),
                Type::Array(Box::new(Type::U8), 96),
            ], pos),
            Ok(Type::U32)
        );
        assert!(stdlib.validate_call("bls_verify", &[Type::U32], pos).is_err());
        assert!(stdlib.validate_call("unknown", &[], pos).is_err());
    }

    #[test]
    fn test_emit_call() {
        let stdlib = CryptoStdLib::new();
        let instructions = stdlib.emit_call("bls_verify", &[1, 2, 3], 0).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, KapraOpCode::BlsVerify);
        assert_eq!(
            instructions[0].operands,
            vec![
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
                Operand::Register(3),
            ]
        );
        assert_eq!(instructions[0].type_info, Some(Type::U32));
    }
}