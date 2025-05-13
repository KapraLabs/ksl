// ksl_stdlib.rs
// Implements the standard library for KSL, supporting core functions and networking operations.

use crate::ksl_types::{Type, TypeError};
use crate::ksl_bytecode::{KapraOpCode, Operand, KapraInstruction};
use crate::ksl_errors::{KslError, SourcePosition};
use std::time::{SystemTime, UNIX_EPOCH};

/// Trait for standard library functions that can be registered and executed.
/// @trait StdLibFunctionTrait
/// @method name Returns the function name.
/// @method params Returns the function parameter types.
/// @method return_type Returns the function return type.
/// @method opcode Returns the function's opcode, if any.
/// @method is_async Returns whether the function is asynchronous.
/// @method execute Executes the function with given arguments.
pub trait StdLibFunctionTrait {
    fn name(&self) -> &'static str;
    fn params(&self) -> &[Type];
    fn return_type(&self) -> &Type;
    fn opcode(&self) -> Option<KapraOpCode>;
    fn is_async(&self) -> bool;
    fn execute(&self, args: &[Value]) -> Result<Value, KslError>;
}

/// Value types supported by the standard library.
/// @enum Value
/// @variant String String value.
/// @variant U32 32-bit unsigned integer.
/// @variant U64 64-bit unsigned integer.
/// @variant Array Array of values with length.
/// @variant Void No value (for void functions).
#[derive(Debug, PartialEq, Clone)]
pub enum Value {
    String(String),
    U32(u32),
    U64(u64),
    Array(Vec<Value>, u32),
    Void,
}

/// Standard library function implementation.
/// @struct StdLibFunction
/// @field name Function name.
/// @field params Function parameter types.
/// @field return_type Function return type.
/// @field opcode Function opcode, if any.
/// @field is_async Whether the function is asynchronous.
#[derive(Debug, PartialEq, Clone)]
pub struct StdLibFunction {
    pub name: &'static str,
    pub params: Vec<Type>,
    pub return_type: Type,
    pub opcode: Option<KapraOpCode>,
    pub is_async: bool,
}

impl StdLibFunctionTrait for StdLibFunction {
    fn name(&self) -> &'static str {
        self.name
    }

    fn params(&self) -> &[Type] {
        &self.params
    }

    fn return_type(&self) -> &Type {
        &self.return_type
    }

    fn opcode(&self) -> Option<KapraOpCode> {
        self.opcode.clone()
    }

    fn is_async(&self) -> bool {
        self.is_async
    }

    fn execute(&self, args: &[Value]) -> Result<Value, KslError> {
        if args.len() != self.params.len() {
            return Err(KslError::type_error(
                format!("Expected {} arguments, got {}", self.params.len(), args.len()),
                SourcePosition::new(1, 1),
                "E002".to_string(),
            ));
        }

        for (expected, actual) in self.params.iter().zip(args) {
            match (expected, actual) {
                (Type::String, Value::String(_)) => continue,
                (Type::U32, Value::U32(_)) => continue,
                (Type::U64, Value::U64(_)) => continue,
                (Type::Array(_, _), Value::Array(_, _)) => continue,
                _ => return Err(KslError::type_error(
                    format!("Type mismatch: expected {:?}, got {:?}", expected, actual),
                    SourcePosition::new(1, 1),
                    "E002".to_string(),
                )),
            }
        }

        match self.name {
            "print" => {
                if let Value::String(s) = &args[0] {
                    println!("{}", s);
                    Ok(Value::Void)
                } else {
                    Err(KslError::type_error(
                        "print: expected string argument".to_string(),
                        SourcePosition::new(1, 1),
                        "E002".to_string(),
                    ))
                }
            }
            "time.now" => {
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                Ok(Value::U64(timestamp))
            }
            _ => Err(KslError::type_error(
                format!("No implementation for {}", self.name),
                SourcePosition::new(1, 1),
                "E003".to_string(),
            )),
        }
    }
}

/// Standard library registry.
/// @struct StdLib
/// @field functions Registered standard library functions.
pub struct StdLib {
    functions: Vec<StdLibFunction>,
}

impl StdLib {
    /// Creates a new standard library instance.
    /// @returns A new `StdLib` instance with core functions registered.
    pub fn new() -> Self {
        let functions = vec![
            // print(msg: string) -> void
            StdLibFunction {
                name: "print",
                params: vec![Type::String],
                return_type: Type::Void,
                opcode: Some(KapraOpCode::Print),
                is_async: false,
            },
            // sha3(input: string | array<u8, N>) -> array<u8, 32> (SHA3-256)
            StdLibFunction {
                name: "sha3",
                params: vec![Type::String],
                return_type: Type::Array(Box::new(Type::U8), 32),
                opcode: Some(KapraOpCode::Sha3),
                is_async: false,
            },
            // sha3_512(input: string | array<u8, N>) -> array<u8, 64> (SHA3-512)
            StdLibFunction {
                name: "sha3_512",
                params: vec![Type::String],
                return_type: Type::Array(Box::new(Type::U8), 64),
                opcode: Some(KapraOpCode::Sha3_512),
                is_async: false,
            },
            // kaprekar(input: u16 | array<u8, 4>) -> same_type
            StdLibFunction {
                name: "kaprekar",
                params: vec![Type::U32],
                return_type: Type::U32,
                opcode: Some(KapraOpCode::Kaprekar),
                is_async: false,
            },
            // time.now() -> u64
            StdLibFunction {
                name: "time.now",
                params: vec![],
                return_type: Type::U64,
                opcode: None,
                is_async: false,
            },
        ];
        StdLib { functions }
    }

    /// Registers a new standard library function.
    /// @param function The function to register.
    /// @returns `Ok(())` if registration succeeds, or `Err` if the function already exists.
    pub fn register_function(&mut self, function: StdLibFunction) -> Result<(), KslError> {
        if self.functions.iter().any(|f| f.name == function.name) {
            return Err(KslError::type_error(
                format!("Function already exists: {}", function.name),
                SourcePosition::new(1, 1),
                "E003".to_string(),
            ));
        }
        self.functions.push(function);
        Ok(())
    }

    /// Gets a function by name.
    /// @param name The function name to look up.
    /// @returns The function if found, or `None`.
    pub fn get_function(&self, name: &str) -> Option<&StdLibFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Validates a function call.
    /// @param name The function name.
    /// @param arg_types The argument types.
    /// @param position The source position for error reporting.
    /// @returns The return type if valid, or `Err` with a type error.
    pub fn validate_call(
        &self,
        name: &str,
        arg_types: &[Type],
        position: SourcePosition,
    ) -> Result<Type, KslError> {
        let func = self.get_function(name).ok_or_else(|| KslError::type_error(
            format!("Undefined function: {}", name),
            position,
            "E001".to_string(),
        ))?;
        if arg_types.len() != func.params.len() {
            return Err(KslError::type_error(
                format!(
                    "Expected {} arguments, got {}",
                    func.params.len(),
                    arg_types.len()
                ),
                position,
                "E002".to_string(),
            ));
        }
        for (expected, actual) in func.params.iter().zip(arg_types) {
            if expected != actual {
                return Err(KslError::type_error(
                    format!("Argument type mismatch: expected {:?}, got {:?}", expected, actual),
                    position,
                    "E002".to_string(),
                ));
            }
        }
        Ok(func.return_type.clone())
    }

    /// Generates bytecode for a function call.
    /// @param name The function name.
    /// @param arg_regs The argument register numbers.
    /// @param dst_reg The destination register number.
    /// @returns The bytecode instructions, or `Err` if the function is invalid.
    pub fn emit_call(
        &self,
        name: &str,
        arg_regs: &[u8],
        dst_reg: u8,
    ) -> Result<Vec<KapraInstruction>, KslError> {
        let func = self.get_function(name).ok_or_else(|| KslError::type_error(
            format!("Undefined function: {}", name),
            SourcePosition::new(1, 1),
            "E001".to_string(),
        ))?;
        if arg_regs.len() != func.params.len() {
            return Err(KslError::type_error(
                format!(
                    "Expected {} arguments, got {}",
                    func.params.len(),
                    arg_regs.len()
                ),
                SourcePosition::new(1, 1),
                "E002".to_string(),
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
                "E003".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_function() {
        let stdlib = StdLib::new();
        let func = stdlib.get_function("print").unwrap();
        assert_eq!(func.name, "print");
        assert_eq!(func.params, vec![Type::String]);
        assert_eq!(func.return_type, Type::Void);
        assert_eq!(func.opcode, Some(KapraOpCode::Print));
        assert!(!func.is_async);
    }

    #[test]
    fn test_validate_call() {
        let stdlib = StdLib::new();
        let pos = SourcePosition::new(1, 1);
        assert_eq!(
            stdlib.validate_call("print", &[Type::String], pos),
            Ok(Type::Void)
        );
        assert!(stdlib.validate_call("print", &[Type::U32], pos).is_err());
        assert!(stdlib.validate_call("unknown", &[], pos).is_err());
    }

    #[test]
    fn test_emit_call_print() {
        let stdlib = StdLib::new();
        let instructions = stdlib.emit_call("print", &[1], 0).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, KapraOpCode::Print);
        assert_eq!(
            instructions[0].operands,
            vec![Operand::Register(0), Operand::Register(1)]
        );
        assert_eq!(instructions[0].type_info, Some(Type::Void));
    }

    #[test]
    fn test_emit_call_sha3() {
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
    fn test_emit_call_time_now() {
        let stdlib = StdLib::new();
        let instructions = stdlib.emit_call("time.now", &[], 0).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, KapraOpCode::TimeNow);
        assert_eq!(instructions[0].operands, vec![Operand::Register(0)]);
        assert_eq!(instructions[0].type_info, Some(Type::U64));
    }

    #[test]
    fn test_execute_print() {
        let stdlib = StdLib::new();
        let func = stdlib.get_function("print").unwrap();
        let result = func.execute(&[Value::String("test".to_string())]);
        assert_eq!(result, Ok(Value::Void));
    }

    #[test]
    fn test_execute_time_now() {
        let stdlib = StdLib::new();
        let func = stdlib.get_function("time.now").unwrap();
        let result = func.execute(&[]);
        assert!(matches!(result, Ok(Value::U64(_))));
    }
}