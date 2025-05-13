// ksl_stdlib_math.rs
// Implements mathematical functions for KSL standard library, optimized for gaming and AI.

use crate::ksl_types::{Type, TypeError};
use crate::ksl_bytecode::{KapraOpCode, Operand, KapraInstruction};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_value::Value;
use std::f64::consts::PI;
use nalgebra::{DMatrix, DVector};
use std::collections::HashMap;

/// Mathematical function signature
/// @struct MathStdLibFunction
/// @field name Function name (e.g., "math.sin", "matrix.mul")
/// @field params Parameter types for the function
/// @field return_type Return type of the function
/// @field opcode Optional opcode for VM execution
#[derive(Debug, PartialEq, Clone)]
pub struct MathStdLibFunction {
    pub name: &'static str,
    pub params: Vec<Type>,
    pub return_type: Type,
    pub opcode: Option<KapraOpCode>, // None for native implementations
}

/// Mathematical standard library registry
/// @struct MathStdLib
/// @field functions Registered mathematical functions
pub struct MathStdLib {
    functions: Vec<MathStdLibFunction>,
}

impl MathStdLib {
    /// Creates a new mathematical standard library instance.
    /// @returns A new `MathStdLib` instance with all math functions registered.
    pub fn new() -> Self {
        let functions = vec![
            // math.sin(x: f64) -> f64
            // Computes the sine of x (in radians) with high precision
            MathStdLibFunction {
                name: "math.sin",
                params: vec![Type::F64],
                return_type: Type::F64,
                opcode: Some(KapraOpCode::Sin),
            },
            // math.cos(x: f64) -> f64
            // Computes the cosine of x (in radians) with high precision
            MathStdLibFunction {
                name: "math.cos",
                params: vec![Type::F64],
                return_type: Type::F64,
                opcode: Some(KapraOpCode::Cos),
            },
            // math.sqrt(x: f64) -> f64
            // Computes the square root with high precision
            MathStdLibFunction {
                name: "math.sqrt",
                params: vec![Type::F64],
                return_type: Type::F64,
                opcode: Some(KapraOpCode::Sqrt),
            },
            // matrix.mul<T: f64>(a: array<array<T, N>, M>, b: array<array<T, M>, P>) -> array<array<T, N>, P>
            // Performs optimized matrix multiplication using BLAS
            MathStdLibFunction {
                name: "matrix.mul",
                params: vec![
                    Type::Array(Box::new(Type::Array(Box::new(Type::F64), 0)), 0),
                    Type::Array(Box::new(Type::Array(Box::new(Type::F64), 0)), 0),
                ],
                return_type: Type::Array(Box::new(Type::Array(Box::new(Type::F64), 0)), 0),
                opcode: Some(KapraOpCode::MatrixMul),
            },
            // tensor.reduce<T: f64>(t: array<array<T, N>, M>, axis: u32) -> array<T, M>
            // Reduces tensor along specified axis using optimized BLAS operations
            MathStdLibFunction {
                name: "tensor.reduce",
                params: vec![
                    Type::Array(Box::new(Type::Array(Box::new(Type::F64), 0)), 0),
                    Type::U32,
                ],
                return_type: Type::Array(Box::new(Type::F64), 0),
                opcode: Some(KapraOpCode::TensorReduce),
            },
        ];
        MathStdLib { functions }
    }

    /// Gets a function by name.
    /// @param name The name of the function to get.
    /// @returns The function if found, None otherwise.
    pub fn get_function(&self, name: &str) -> Option<&MathStdLibFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Validates a function call.
    /// @param name The name of the function to validate.
    /// @param arg_types The types of the arguments.
    /// @param position The source position for error reporting.
    /// @returns The return type if valid, or an error.
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
            if !self.is_compatible(expected, actual) {
                return Err(KslError::type_error(
                    format!("Argument type mismatch: expected {:?}, got {:?}", expected, actual),
                    position,
                ));
            }
        }
        Ok(func.return_type.clone())
    }

    /// Generates bytecode for a function call.
    /// @param name The name of the function.
    /// @param arg_regs The registers containing the arguments.
    /// @param dst_reg The register to store the result.
    /// @returns The bytecode instructions for the function call.
    pub fn emit_call(
        &self,
        name: &str,
        arg_regs: &[u8],
        dst_reg: u8,
    ) -> Result<Vec<KapraInstruction>, KslError> {
        let func = self.get_function(name).ok_or_else(|| KslError::type_error(
            format!("Undefined mathematical function: {}", name),
            SourcePosition::new(1, 1),
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

    /// Executes a mathematical function.
    /// @param name The name of the function to execute.
    /// @param args The function arguments.
    /// @returns The function result.
    pub fn execute(&self, name: &str, args: Vec<Value>) -> Result<Value, KslError> {
        let pos = SourcePosition::new(1, 1);
        match name {
            "math.sin" => {
                if args.len() != 1 {
                    return Err(KslError::type_error(
                        format!("math.sin expects 1 argument, got {}", args.len()),
                        pos,
                    ));
                }
                let x = match &args[0] {
                    Value::F64(x) => *x,
                    _ => return Err(KslError::type_error("math.sin: argument must be f64".to_string(), pos, "E601".to_string())),
                };
                Ok(Value::F64(x.sin()))
            }
            "math.cos" => {
                if args.len() != 1 {
                    return Err(KslError::type_error(
                        format!("math.cos expects 1 argument, got {}", args.len()),
                        pos,
                    ));
                }
                let x = match &args[0] {
                    Value::F64(x) => *x,
                    _ => return Err(KslError::type_error("math.cos: argument must be f64".to_string(), pos, "E602".to_string())),
                };
                Ok(Value::F64(x.cos()))
            }
            "math.sqrt" => {
                if args.len() != 1 {
                    return Err(KslError::type_error(
                        format!("math.sqrt expects 1 argument, got {}", args.len()),
                        pos,
                    ));
                }
                let x = match &args[0] {
                    Value::F64(x) => *x,
                    _ => return Err(KslError::type_error("math.sqrt: argument must be f64".to_string(), pos, "E603".to_string())),
                };
                if x < 0.0 {
                    return Err(KslError::type_error("math.sqrt: argument must be non-negative".to_string(), pos, "E604".to_string()));
                }
                Ok(Value::F64(x.sqrt()))
            }
            "matrix.mul" => {
                if args.len() != 2 {
                    return Err(KslError::type_error(
                        format!("matrix.mul expects 2 arguments, got {}", args.len()),
                        pos,
                    ));
                }
                let (a, b) = match (&args[0], &args[1]) {
                    (Value::Array(a_data, _), Value::Array(b_data, _)) => {
                        let a_mat = self.array_to_matrix(a_data)?;
                        let b_mat = self.array_to_matrix(b_data)?;
                        (a_mat, b_mat)
                    }
                    _ => return Err(KslError::type_error("matrix.mul: arguments must be matrices".to_string(), pos, "E605".to_string())),
                };
                if a.ncols() != b.nrows() {
                    return Err(KslError::type_error(
                        format!("matrix.mul: incompatible dimensions: {}x{} * {}x{}", 
                            a.nrows(), a.ncols(), b.nrows(), b.ncols()),
                        pos,
                    ));
                }
                let result = a * b;
                Ok(Value::Array(self.matrix_to_array(&result), result.len()))
            }
            "tensor.reduce" => {
                if args.len() != 2 {
                    return Err(KslError::type_error(
                        format!("tensor.reduce expects 2 arguments, got {}", args.len()),
                        pos,
                    ));
                }
                let (tensor, axis) = match (&args[0], &args[1]) {
                    (Value::Array(data, _), Value::U32(axis)) => {
                        let tensor = self.array_to_tensor(data)?;
                        (*axis, tensor)
                    }
                    _ => return Err(KslError::type_error(
                        "tensor.reduce: first argument must be tensor, second must be u32".to_string(),
                        pos,
                    )),
                };
                let result = self.reduce_tensor(&tensor, axis)?;
                Ok(Value::Array(result, result.len()))
            }
            _ => Err(KslError::type_error(
                format!("Unknown mathematical function: {}", name),
                pos,
            )),
        }
    }

    // Helper methods for matrix/tensor operations
    fn array_to_matrix(&self, data: &[Value]) -> Result<DMatrix<f64>, KslError> {
        // Implementation using nalgebra
        unimplemented!()
    }

    fn matrix_to_array(&self, matrix: &DMatrix<f64>) -> Vec<Value> {
        // Implementation using nalgebra
        unimplemented!()
    }

    fn array_to_tensor(&self, data: &[Value]) -> Result<Vec<DMatrix<f64>>, KslError> {
        // Implementation using nalgebra
        unimplemented!()
    }

    fn reduce_tensor(&self, tensor: &[DMatrix<f64>], axis: u32) -> Result<Vec<Value>, KslError> {
        // Implementation using nalgebra
        unimplemented!()
    }

    fn is_compatible(&self, expected: &Type, actual: &Type) -> bool {
        match (expected, actual) {
            (Type::F64, Type::F64) => true,
            (Type::Array(e1, _), Type::Array(e2, _)) => self.is_compatible(e1, e2),
            _ => false,
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
    fn test_trig_functions() {
        let stdlib = MathStdLib::new();
        
        // Test sin
        let result = stdlib.execute("math.sin", vec![Value::F64(PI / 2.0)]).unwrap();
        assert!(matches!(result, Value::F64(x) if (x - 1.0).abs() < 1e-10));
        
        // Test cos
        let result = stdlib.execute("math.cos", vec![Value::F64(PI)]).unwrap();
        assert!(matches!(result, Value::F64(x) if (x + 1.0).abs() < 1e-10));
    }

    #[test]
    fn test_sqrt() {
        let stdlib = MathStdLib::new();
        
        // Test valid input
        let result = stdlib.execute("math.sqrt", vec![Value::F64(16.0)]).unwrap();
        assert!(matches!(result, Value::F64(x) if (x - 4.0).abs() < 1e-10));
        
        // Test negative input
        let result = stdlib.execute("math.sqrt", vec![Value::F64(-1.0)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_matrix_mul() {
        let stdlib = MathStdLib::new();
        
        // Create 2x2 matrices
        let a = vec![
            Value::F64(1.0), Value::F64(2.0),
            Value::F64(3.0), Value::F64(4.0),
        ];
        let b = vec![
            Value::F64(5.0), Value::F64(6.0),
            Value::F64(7.0), Value::F64(8.0),
        ];
        
        let result = stdlib.execute("matrix.mul", vec![
            Value::Array(a, 4),
            Value::Array(b, 4),
        ]).unwrap();
        
        // Expected result: [[19, 22], [43, 50]]
        match result {
            Value::Array(data, 4) => {
                assert_eq!(data[0], Value::F64(19.0));
                assert_eq!(data[1], Value::F64(22.0));
                assert_eq!(data[2], Value::F64(43.0));
                assert_eq!(data[3], Value::F64(50.0));
            }
            _ => panic!("Expected array result"),
        }
    }

    #[test]
    fn test_tensor_reduce() {
        let stdlib = MathStdLib::new();
        
        // Create 2x2x2 tensor
        let tensor = vec![
            Value::F64(1.0), Value::F64(2.0),
            Value::F64(3.0), Value::F64(4.0),
            Value::F64(5.0), Value::F64(6.0),
            Value::F64(7.0), Value::F64(8.0),
        ];
        
        let result = stdlib.execute("tensor.reduce", vec![
            Value::Array(tensor, 8),
            Value::U32(0), // Reduce along first axis
        ]).unwrap();
        
        // Expected result: sum along axis 0
        match result {
            Value::Array(data, 4) => {
                assert_eq!(data[0], Value::F64(6.0));  // 1 + 5
                assert_eq!(data[1], Value::F64(8.0));  // 2 + 6
                assert_eq!(data[2], Value::F64(10.0)); // 3 + 7
                assert_eq!(data[3], Value::F64(12.0)); // 4 + 8
            }
            _ => panic!("Expected array result"),
        }
    }

    #[test]
    fn test_type_validation() {
        let stdlib = MathStdLib::new();
        let pos = SourcePosition::new(1, 1);
        
        // Test valid types
        assert!(stdlib.validate_call("math.sin", &[Type::F64], pos).is_ok());
        assert!(stdlib.validate_call("matrix.mul", &[
            Type::Array(Box::new(Type::Array(Box::new(Type::F64), 2)), 2),
            Type::Array(Box::new(Type::Array(Box::new(Type::F64), 2)), 2),
        ], pos).is_ok());
        
        // Test invalid types
        assert!(stdlib.validate_call("math.sin", &[Type::U32], pos).is_err());
        assert!(stdlib.validate_call("matrix.mul", &[
            Type::Array(Box::new(Type::U32), 4),
            Type::Array(Box::new(Type::U32), 4),
        ], pos).is_err());
    }
}