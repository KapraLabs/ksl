// ksl_stdlib_math.rs
// Implements mathematical functions for KSL standard library, optimized for gaming and AI.

use crate::ksl_types::{Type, TypeError};
use crate::ksl_bytecode::{KapraOpCode, Operand, KapraInstruction};
use crate::ksl_errors::{KslError, SourcePosition};
use std::f64::consts::PI;

// Mathematical function signature
#[derive(Debug, PartialEq, Clone)]
pub struct MathStdLibFunction {
    pub name: &'static str,
    pub params: Vec<Type>,
    pub return_type: Type,
    pub opcode: Option<KapraOpCode>, // None for native implementations
}

// Mathematical standard library registry
pub struct MathStdLib {
    functions: Vec<MathStdLibFunction>,
}

impl MathStdLib {
    pub fn new() -> Self {
        let functions = vec![
            // math.sin(x: f64) -> f64
            MathStdLibFunction {
                name: "math.sin",
                params: vec![Type::F64],
                return_type: Type::F64,
                opcode: Some(KapraOpCode::Sin),
            },
            // math.cos(x: f64) -> f64
            MathStdLibFunction {
                name: "math.cos",
                params: vec![Type::F64],
                return_type: Type::F64,
                opcode: Some(KapraOpCode::Cos),
            },
            // math.sqrt(x: f64) -> f64
            MathStdLibFunction {
                name: "math.sqrt",
                params: vec![Type::F64],
                return_type: Type::F64,
                opcode: Some(KapraOpCode::Sqrt),
            },
            // matrix.mul<T: f32 | f64>(a: array<array<T, N>, M>, b: array<array<T, M>, P>) -> array<array<T, N>, P>
            MathStdLibFunction {
                name: "matrix.mul",
                params: vec![
                    Type::Array(Box::new(Type::Array(Box::new(Type::F64), 0)), 0), // Simplified: dynamic size
                    Type::Array(Box::new(Type::Array(Box::new(Type::F64), 0)), 0),
                ],
                return_type: Type::Array(Box::new(Type::Array(Box::new(Type::F64), 0)), 0),
                opcode: Some(KapraOpCode::MatrixMul),
            },
            // tensor.reduce<T: f32 | f64>(t: array<T, N>, fn: (T, T) -> T) -> T
            MathStdLibFunction {
                name: "tensor.reduce",
                params: vec![
                    Type::Array(Box::new(Type::F64), 0), // Simplified: dynamic size
                    Type::Function(vec![Type::F64, Type::F64], Box::new(Type::F64)),
                ],
                return_type: Type::F64,
                opcode: Some(KapraOpCode::TensorReduce),
            },
        ];
        MathStdLib { functions }
    }

    // Get function by name
    pub fn get_function(&self, name: &str) -> Option<&MathStdLibFunction> {
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
            format!("Undefined mathematical function: {}", name),
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
            format!("Undefined mathematical function: {}", name),
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
        let stdlib = MathStdLib::new();
        let func = stdlib.get_function("math.sin").unwrap();
        assert_eq!(func.name, "math.sin");
        assert_eq!(func.params, vec![Type::F64]);
        assert_eq!(func.return_type, Type::F64);
        assert_eq!(func.opcode, Some(KapraOpCode::Sin));

        let func = stdlib.get_function("matrix.mul").unwrap();
        assert_eq!(func.name, "matrix.mul");
        assert_eq!(func.params.len(), 2);
        assert_eq!(func.opcode, Some(KapraOpCode::MatrixMul));
    }

    #[test]
    fn test_validate_call() {
        let stdlib = MathStdLib::new();
        let pos = SourcePosition::new(1, 1);
        assert_eq!(
            stdlib.validate_call("math.sin", &[Type::F64], pos),
            Ok(Type::F64)
        );
        assert!(stdlib.validate_call("math.sin", &[Type::U32], pos).is_err());
        assert!(stdlib.validate_call("math.sin", &[], pos).is_err());
        assert!(stdlib.validate_call("unknown", &[], pos).is_err());
    }

    #[test]
    fn test_emit_call() {
        let stdlib = MathStdLib::new();
        let instructions = stdlib.emit_call("math.sin", &[1], 0).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, KapraOpCode::Sin);
        assert_eq!(
            instructions[0].operands,
            vec![Operand::Register(0), Operand::Register(1)]
        );
        assert_eq!(instructions[0].type_info, Some(Type::F64));
    }
}