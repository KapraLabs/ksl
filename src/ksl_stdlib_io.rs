// ksl_stdlib_io.rs
// Implements I/O functions for KSL standard library, optimized for mobile and IoT.

use crate::ksl_types::{Type, TypeError};
use crate::ksl_bytecode::{KapraOpCode, Operand, KapraInstruction};
use crate::ksl_errors::{KslError, SourcePosition};

// I/O function signature
#[derive(Debug, PartialEq, Clone)]
pub struct IOStdLibFunction {
    pub name: &'static str,
    pub params: Vec<Type>,
    pub return_type: Type,
    pub opcode: Option<KapraOpCode>, // None for native implementations
}

// I/O standard library registry
pub struct IOStdLib {
    functions: Vec<IOStdLibFunction>,
}

impl IOStdLib {
    pub fn new() -> Self {
        let functions = vec![
            // http.get(url: string) -> result<string, error>
            IOStdLibFunction {
                name: "http.get",
                params: vec![Type::String],
                return_type: Type::String, // Simplified: assumes success type
                opcode: Some(KapraOpCode::HttpGet),
            },
            // device.sensor(id: u32) -> result<f32, error>
            IOStdLibFunction {
                name: "device.sensor",
                params: vec![Type::U32],
                return_type: Type::F32, // Simplified: assumes success type
                opcode: Some(KapraOpCode::DeviceSensor),
            },
        ];
        IOStdLib { functions }
    }

    // Get function by name
    pub fn get_function(&self, name: &str) -> Option<&IOStdLibFunction> {
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
            format!("Undefined I/O function: {}", name),
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
            format!("Undefined I/O function: {}", name),
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
        let stdlib = IOStdLib::new();
        let func = stdlib.get_function("http.get").unwrap();
        assert_eq!(func.name, "http.get");
        assert_eq!(func.params, vec![Type::String]);
        assert_eq!(func.return_type, Type::String);
        assert_eq!(func.opcode, Some(KapraOpCode::HttpGet));

        let func = stdlib.get_function("device.sensor").unwrap();
        assert_eq!(func.name, "device.sensor");
        assert_eq!(func.params, vec![Type::U32]);
        assert_eq!(func.return_type, Type::F32);
        assert_eq!(func.opcode, Some(KapraOpCode::DeviceSensor));
    }

    #[test]
    fn test_validate_call() {
        let stdlib = IOStdLib::new();
        let pos = SourcePosition::new(1, 1);
        assert_eq!(
            stdlib.validate_call("http.get", &[Type::String], pos),
            Ok(Type::String)
        );
        assert_eq!(
            stdlib.validate_call("device.sensor", &[Type::U32], pos),
            Ok(Type::F32)
        );
        assert!(stdlib.validate_call("http.get", &[Type::U32], pos).is_err());
        assert!(stdlib.validate_call("unknown", &[], pos).is_err());
    }

    #[test]
    fn test_emit_call() {
        let stdlib = IOStdLib::new();
        let instructions = stdlib.emit_call("http.get", &[1], 0).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, KapraOpCode::HttpGet);
        assert_eq!(
            instructions[0].operands,
            vec![Operand::Register(0), Operand::Register(1)]
        );
        assert_eq!(instructions[0].type_info, Some(Type::String));
    }
}