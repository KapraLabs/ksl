// ksl_stdlib_crypto.rs
// Implements cryptographic functions for KSL standard library, optimized for NFT use cases.
// Provides both synchronous and asynchronous cryptographic operations.

use crate::ksl_types::{Type, TypeError};
use crate::ksl_bytecode::{KapraOpCode, Operand, KapraInstruction};
use crate::ksl_errors::{KslError, SourcePosition};

/// Cryptographic function signature with async support
#[derive(Debug, PartialEq, Clone)]
pub struct CryptoStdLibFunction {
    pub name: &'static str,
    pub params: Vec<Type>,
    pub return_type: Type,
    pub opcode: Option<KapraOpCode>, // None for native implementations
    pub is_async: bool, // Whether the function is asynchronous
}

/// Cryptographic standard library registry
pub struct CryptoStdLib {
    functions: Vec<CryptoStdLibFunction>,
}

impl CryptoStdLib {
    pub fn new() -> Self {
        let functions = vec![
            // Hashing functions
            CryptoStdLibFunction {
                name: "sha256",
                params: vec![Type::Array(Box::new(Type::U8), 0)], // Variable-length input
                return_type: Type::Array(Box::new(Type::U8), 32), // 32-byte hash
                opcode: Some(KapraOpCode::Sha256),
                is_async: false,
            },
            CryptoStdLibFunction {
                name: "sha3_256",
                params: vec![Type::Array(Box::new(Type::U8), 0)], // Variable-length input
                return_type: Type::Array(Box::new(Type::U8), 32), // 32-byte hash
                opcode: Some(KapraOpCode::Sha3_256),
                is_async: false,
            },
            CryptoStdLibFunction {
                name: "blake2b",
                params: vec![
                    Type::Array(Box::new(Type::U8), 0), // Input data
                    Type::Array(Box::new(Type::U8), 0), // Optional key
                ],
                return_type: Type::Array(Box::new(Type::U8), 64), // 64-byte hash
                opcode: Some(KapraOpCode::Blake2b),
                is_async: false,
            },
            // Async hashing functions
            CryptoStdLibFunction {
                name: "async_sha256",
                params: vec![Type::Array(Box::new(Type::U8), 0)],
                return_type: Type::Array(Box::new(Type::U8), 32),
                opcode: Some(KapraOpCode::AsyncSha256),
                is_async: true,
            },
            CryptoStdLibFunction {
                name: "async_sha3_256",
                params: vec![Type::Array(Box::new(Type::U8), 0)],
                return_type: Type::Array(Box::new(Type::U8), 32),
                opcode: Some(KapraOpCode::AsyncSha3_256),
                is_async: true,
            },
            // Existing verification functions
            CryptoStdLibFunction {
                name: "bls_verify",
                params: vec![
                    Type::Array(Box::new(Type::U8), 32), // Message
                    Type::Array(Box::new(Type::U8), 48), // Public key
                    Type::Array(Box::new(Type::U8), 96), // Signature
                ],
                return_type: Type::U32, // Boolean as u32
                opcode: Some(KapraOpCode::BlsVerify),
                is_async: false,
            },
            CryptoStdLibFunction {
                name: "dil_verify",
                params: vec![
                    Type::Array(Box::new(Type::U8), 32), // Message
                    Type::Array(Box::new(Type::U8), 1312), // Public key
                    Type::Array(Box::new(Type::U8), 2420), // Signature
                ],
                return_type: Type::U32, // Boolean as u32
                opcode: Some(KapraOpCode::DilithiumVerify),
                is_async: false,
            },
            CryptoStdLibFunction {
                name: "merkle_verify",
                params: vec![
                    Type::Array(Box::new(Type::U8), 32), // Root
                    Type::Array(Box::new(Type::U8), 0), // Variable-length proof
                ],
                return_type: Type::U32, // Boolean as u32
                opcode: Some(KapraOpCode::MerkleVerify),
                is_async: false,
            },
        ];
        CryptoStdLib { functions }
    }

    /// Example usage:
    /// ```ksl
    /// // Synchronous hashing
    /// let hash = sha256(data);
    /// let hash3 = sha3_256(data);
    /// let blake_hash = blake2b(data, key);
    /// 
    /// // Asynchronous hashing
    /// let hash = await async_sha256(data);
    /// let hash3 = await async_sha3_256(data);
    /// 
    /// // Verification
    /// let valid = bls_verify(msg, pubkey, sig);
    /// let valid = dil_verify(msg, pubkey, sig);
    /// let valid = merkle_verify(root, proof);
    /// ```
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
        
        // Test hashing functions
        let func = stdlib.get_function("sha256").unwrap();
        assert_eq!(func.name, "sha256");
        assert_eq!(func.params.len(), 1);
        assert_eq!(func.return_type, Type::Array(Box::new(Type::U8), 32));
        assert_eq!(func.is_async, false);

        let func = stdlib.get_function("async_sha256").unwrap();
        assert_eq!(func.name, "async_sha256");
        assert_eq!(func.is_async, true);

        // Test existing verification functions
        let func = stdlib.get_function("bls_verify").unwrap();
        assert_eq!(func.name, "bls_verify");
        assert_eq!(func.params.len(), 3);
        assert_eq!(func.return_type, Type::U32);
        assert_eq!(func.is_async, false);

        let func = stdlib.get_function("dil_verify").unwrap();
        assert_eq!(func.name, "dil_verify");
        assert_eq!(func.params.len(), 3);
        assert_eq!(func.params[1], Type::Array(Box::new(Type::U8), 1312));
        assert_eq!(func.is_async, false);

        let func = stdlib.get_function("merkle_verify").unwrap();
        assert_eq!(func.name, "merkle_verify");
        assert_eq!(func.params.len(), 2);
        assert_eq!(func.params[0], Type::Array(Box::new(Type::U8), 32));
        assert_eq!(func.is_async, false);
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