// ksl_stdlib.rs
// Implements the minimal standard library for KSL, supporting SHA3-256 and SHA3-512.

use crate::ksl_types::{Type, TypeError};
use crate::ksl_bytecode::{KapraOpCode, Operand, KapraInstruction};
use std::time::{SystemTime, UNIX_EPOCH};

// Standard library function signature
#[derive(Debug, PartialEq, Clone)]
pub struct StdLibFunction {
    pub name: &'static str,
    pub params: Vec<Type>,
    pub return_type: Type,
    pub opcode: Option<KapraOpCode>, // None for native implementations
}

// Standard library registry
pub struct StdLib {
    functions: Vec<StdLibFunction>,
}

impl StdLib {
    pub fn new() -> Self {
        let functions = vec![
            // sha3(input: string | array<u8, N>) -> array<u8, 32> (SHA3-256)
            StdLibFunction {
                name: "sha3",
                params: vec![Type::String], // Simplified: only string for now
                return_type: Type::Array(Box::new(Type::U8), 32),
                opcode: Some(KapraOpCode::Sha3),
            },
            // sha3_512(input: string | array<u8, N>) -> array<u8, 64> (SHA3-512)
            StdLibFunction {
                name: "sha3_512",
                params: vec![Type::String], // Simplified: only string for now
                return_type: Type::Array(Box::new(Type::U8), 64),
                opcode: Some(KapraOpCode::Sha3_512),
            },
            // kaprekar(input: u16 | array<u8, 4>) -> same_type
            StdLibFunction {
                name: "kaprekar",
                params: vec![Type::U32], // Simplified: only u32 for now
                return_type: Type::U32,
                opcode: Some(KapraOpCode::Kaprekar),
            },
            // time.now() -> u64
            StdLibFunction {
                name: "time.now",
                params: vec![],
                return_type: Type::U64,
                opcode: None, // Native implementation
            },
        ];
        StdLib { functions }
    }

    // Get function by name
    pub fn get_function(&self, name: &str) -> Option<&StdLibFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    // Validate function call (used by type checker)
    pub fn validate_call(
        &self,
        name: &str,
        arg_types: &[Type],
        position: usize,
    ) -> Result<Type, TypeError> {
        let func = self.get_function(name).ok_or_else(|| TypeError {
            message: format!("Undefined function: {}", name),
            position,
        })?;
        if arg_types.len() != func.params.len() {
            return Err(TypeError {
                message: format!(
                    "Expected {} arguments, got {}",
                    func.params.len(),
                    arg_types.len()
                ),
                position,
            });
        }
        for (expected, actual) in func.params.iter().zip(arg_types) {
            if expected != actual {
                return Err(TypeError {
                    message: format!("Argument type mismatch: expected {:?}, got {:?}", expected, actual),
                    position,
                });
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
    ) -> Result<Vec<KapraInstruction>, String> {
        let func = self.get_function(name).ok_or_else(|| format!("Undefined function: {}", name))?;
        if arg_regs.len() != func.params.len() {
            return Err(format!(
                "Expected {} arguments, got {}",
                func.params.len(),
                arg_regs.len()
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
            None => {
                // Native implementation (e.g., time.now)
                if name == "time.now" {
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    Ok(vec![KapraInstruction::new(
                        KapraOpCode::Mov,
                        vec![
                            Operand::Register(dst_reg),
                            Operand::Immediate((timestamp as u64).to_le_bytes().to_vec()),
                        ],
                        Some(Type::U64),
                    )])
                } else {
                    Err(format!("No native implementation for {}", name))
                }
            }
        }
    }
}

// Assume ksl_types.rs and ksl_bytecode.rs are in the same crate
mod ksl_types {
    pub use super::{Type, TypeError};
}

mod ksl_bytecode {
    pub use super::{KapraOpCode, Operand, KapraInstruction};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_function() {
        let stdlib = StdLib::new();
        let func = stdlib.get_function("sha3").unwrap();
        assert_eq!(func.name, "sha3");
        assert_eq!(func.params, vec![Type::String]);
        assert_eq!(func.return_type, Type::Array(Box::new(Type::U8), 32));
        assert_eq!(func.opcode, Some(KapraOpCode::Sha3));

        let func = stdlib.get_function("sha3_512").unwrap();
        assert_eq!(func.name, "sha3_512");
        assert_eq!(func.params, vec![Type::String]);
        assert_eq!(func.return_type, Type::Array(Box::new(Type::U8), 64));
        assert_eq!(func.opcode, Some(KapraOpCode::Sha3_512));
    }

    #[test]
    fn validate_call() {
        let stdlib = StdLib::new();
        assert_eq!(
            stdlib.validate_call("sha3", &[Type::String], 0),
            Ok(Type::Array(Box::new(Type::U8), 32))
        );
        assert_eq!(
            stdlib.validate_call("sha3_512", &[Type::String], 0),
            Ok(Type::Array(Box::new(Type::U8), 64))
        );
        assert!(stdlib.validate_call("sha3", &[Type::U32], 0).is_err());
        assert!(stdlib.validate_call("sha3_512", &[Type::U32], 0).is_err());
        assert!(stdlib.validate_call("sha3", &[], 0).is_err());
        assert_eq!(
            stdlib.validate_call("time.now", &[], 0),
            Ok(Type::U64)
        );
        assert!(stdlib.validate_call("unknown", &[], 0).is_err());
    }

    #[test]
    fn emit_call_sha3() {
        let stdlib = StdLib::new();
        let instructions = stdlib.emit_call("sha3", &[1], 0).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, KapraOpCode::Sha3);
        assert_eq!(
            instructions[0].operands,
            vec![Operand::Register(0), Operand::Register(1)]
        );
        assert_eq!(
            instructions[0].type_info,
            Some(Type::Array(Box::new(Type::U8), 32))
        );
    }

    #[test]
    fn emit_call_sha3_512() {
        let stdlib = StdLib::new();
        let instructions = stdlib.emit_call("sha3_512", &[1], 0).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, KapraOpCode::Sha3_512);
        assert_eq!(
            instructions[0].operands,
            vec![Operand::Register(0), Operand::Register(1)]
        );
        assert_eq!(
            instructions[0].type_info,
            Some(Type::Array(Box::new(Type::U8), 64))
        );
    }

    #[test]
    fn emit_call_time_now() {
        let stdlib = StdLib::new();
        let instructions = stdlib.emit_call("time.now", &[], 0).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, KapraOpCode::Mov);
        assert_eq!(instructions[0].operands[0], Operand::Register(0));
        assert_eq!(instructions[0].type_info, Some(Type::U64));
    }
}