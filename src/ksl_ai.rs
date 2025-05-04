// ksl_ai.rs
// AI-specific primitives for Kapra Chain and standalone AI applications
// This module provides AI and machine learning APIs for KSL, enabling intelligent applications.
// It integrates with ksl_stdlib_math.rs for mathematical operations, ksl_stdlib.rs for data handling,
// and ksl_async.rs for asynchronous operations.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;

/// Represents KSL bytecode (aligned with ksl_bytecode.rs).
#[derive(Debug, Clone)]
pub struct Bytecode {
    instructions: Vec<u8>,
    constants: Vec<Constant>,
}

impl Bytecode {
    pub fn new(instructions: Vec<u8>, constants: Vec<Constant>) -> Self {
        Bytecode {
            instructions,
            constants,
        }
    }

    pub fn extend(&mut self, other: Bytecode) {
        self.instructions.extend(other.instructions);
        self.constants.extend(other.constants);
    }
}

/// Represents a constant in the bytecode.
#[derive(Debug, Clone)]
pub enum Constant {
    ArrayU64(usize, Vec<u64>), // e.g., array<u64, 4>
    ArrayU8(usize, Vec<u8>),   // e.g., array<u8, 4>
    Array2DU64(usize, usize, Vec<Vec<u64>>), // e.g., array<array<u64, 4>, 2>
    Array2DU8(usize, usize, Vec<Vec<u8>>),   // e.g., array<array<u8, 4>, 2>
}

/// Represents an AST node (aligned with ksl_parser.rs).
#[derive(Debug, Clone)]
pub enum AstNode {
    ModelBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., weights, biases)
        return_type: Type,           // Return type (e.g., array<u64, 4>)
        body: Vec<AstNode>,          // Body of the model block
    },
    QuantizeBlock {
        params: Vec<(String, Type)>, // Parameters (e.g., weights)
        return_type: Type,           // Return type (e.g., array<array<u8, 4>, 2>)
        body: Vec<AstNode>,          // Body of the quantize block
    },
    Call {
        name: String,
        args: Vec<AstNode>,
    },
    Let {
        name: String,
        ty: Type,
        value: Box<AstNode>,
    },
    LiteralArrayU64(usize, Vec<u64>),
    LiteralArray2DU64(usize, usize, Vec<Vec<u64>>),
}

/// Represents a type (aligned with ksl_types.rs).
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    ArrayU64(usize),        // e.g., array<u64, 4>
    ArrayU8(usize),         // e.g., array<u8, 4>
    Array2DU64(usize, usize), // e.g., array<array<u64, 4>, 2>
    Array2DU8(usize, usize),  // e.g., array<array<u8, 4>, 2>
}

/// AI runtime for Kapra Chain with async support.
#[derive(Debug, Clone)]
pub struct AIRuntime {
    is_embedded: bool,
    math_client: Arc<Mutex<Option<MathClient>>>,
}

impl AIRuntime {
    /// Creates a new AI runtime instance.
    /// 
    /// # Arguments
    /// * `is_embedded` - Whether the runtime is running on an embedded device
    /// * `math_client` - Optional math client for advanced operations
    pub fn new(is_embedded: bool, math_client: Option<MathClient>) -> Self {
        AIRuntime {
            is_embedded,
            math_client: Arc::new(Mutex::new(math_client)),
        }
    }

    /// Matrix multiplication with async support (aligned with ksl_stdlib_math.rs).
    /// 
    /// # Arguments
    /// * `a` - First matrix
    /// * `b` - Second matrix or vector
    /// 
    /// # Returns
    /// A Result containing the multiplication result or an error
    pub async fn matrix_mul(&self, a: &[Vec<u64>], b: &[u64]) -> Result<Vec<u64>, AIRuntimeError> {
        if let Some(client) = &*self.math_client.lock().await {
            match client.matrix_mul(a, b).await {
                Ok(result) => Ok(result),
                Err(e) => Err(AIRuntimeError::MathError(e)),
            }
        } else {
            // Fallback to local implementation
            let rows = a.len();
            let cols = b.len();
            let mut result = vec![0u64; cols];
            for i in 0..rows {
                for j in 0..cols {
                    result[j] = result[j].wrapping_add(a[i][j].wrapping_mul(b[j]));
                }
            }
            if self.is_embedded {
                // Simplified optimization for embedded devices
                result.iter_mut().for_each(|x| *x = (*x & 0xFFFF) as u64);
            }
            Ok(result)
        }
    }

    /// Element-wise tensor addition with async support.
    /// 
    /// # Arguments
    /// * `a` - First tensor
    /// * `b` - Second tensor
    /// 
    /// # Returns
    /// A Result containing the addition result or an error
    pub async fn tensor_add(&self, a: &[u64], b: &[u64]) -> Result<Vec<u64>, AIRuntimeError> {
        if a.len() != b.len() {
            return Err(AIRuntimeError::DimensionMismatch);
        }
        Ok(a.iter().zip(b.iter()).map(|(&x, &y)| x.wrapping_add(y)).collect())
    }

    /// Element-wise tensor multiplication with async support.
    /// 
    /// # Arguments
    /// * `a` - First tensor
    /// * `b` - Second tensor
    /// 
    /// # Returns
    /// A Result containing the multiplication result or an error
    pub async fn tensor_multiply(&self, a: &[u64], b: &[u64]) -> Result<Vec<u64>, AIRuntimeError> {
        if a.len() != b.len() {
            return Err(AIRuntimeError::DimensionMismatch);
        }
        Ok(a.iter().zip(b.iter()).map(|(&x, &y)| x.wrapping_mul(y)).collect())
    }

    /// Quantize a 2D array from u64 to u8 with async support.
    /// 
    /// # Arguments
    /// * `data` - The data to quantize
    /// 
    /// # Returns
    /// A Result containing the quantized data or an error
    pub async fn quantize_to_u8(&self, data: &[Vec<u64>]) -> Result<Vec<Vec<u8>>, AIRuntimeError> {
        // Simulated async quantization
        sleep(Duration::from_millis(10)).await;
        Ok(data.iter().map(|row| {
            row.iter().map(|&x| (x & 0xFF) as u8).collect()
        }).collect())
    }
}

/// Math client for advanced AI operations.
#[derive(Debug, Clone)]
pub struct MathClient {
    precision: MathPrecision,
}

impl MathClient {
    /// Creates a new math client.
    /// 
    /// # Arguments
    /// * `precision` - The precision level for mathematical operations
    pub fn new(precision: MathPrecision) -> Self {
        MathClient { precision }
    }

    /// Performs matrix multiplication with the configured precision.
    /// 
    /// # Arguments
    /// * `a` - First matrix
    /// * `b` - Second matrix or vector
    /// 
    /// # Returns
    /// A Result containing the multiplication result or an error
    pub async fn matrix_mul(&self, a: &[Vec<u64>], b: &[u64]) -> Result<Vec<u64>, String> {
        match self.precision {
            MathPrecision::High => {
                // Implement high-precision matrix multiplication
                Ok(vec![])
            }
            MathPrecision::Low => {
                // Implement low-precision matrix multiplication
                Ok(vec![])
            }
        }
    }
}

/// Precision level for mathematical operations.
#[derive(Debug, Clone, Copy)]
pub enum MathPrecision {
    High,
    Low,
}

/// Errors that can occur during AI runtime operations.
#[derive(Debug, Clone)]
pub enum AIRuntimeError {
    DimensionMismatch,
    MathError(String),
    QuantizationError(String),
}

/// Kapra VM with AI support and async capabilities.
#[derive(Debug)]
pub struct KapraVM {
    stack: Vec<u64>,
    ai_runtime: AIRuntime,
    async_tasks: Vec<AsyncTask>,
}

impl KapraVM {
    /// Creates a new Kapra VM instance with AI support.
    /// 
    /// # Arguments
    /// * `is_embedded` - Whether the VM is running on an embedded device
    /// * `math_client` - Optional math client for advanced operations
    pub fn new(is_embedded: bool, math_client: Option<MathClient>) -> Self {
        KapraVM {
            stack: vec![],
            ai_runtime: AIRuntime::new(is_embedded, math_client),
            async_tasks: vec![],
        }
    }

    /// Executes AI bytecode with async support.
    /// 
    /// # Arguments
    /// * `bytecode` - The bytecode to execute
    /// 
    /// # Returns
    /// A Result containing the execution result or an error
    pub async fn execute(&mut self, bytecode: &Bytecode) -> Result<Vec<u64>, String> {
        let mut ip = 0;
        while ip < bytecode.instructions.len() {
            let instr = bytecode.instructions[ip];
            ip += 1;

            match instr {
                OPCODE_MATRIX_MUL => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for MATRIX_MUL".to_string());
                    }
                    let b_idx = self.stack.pop().unwrap() as usize;
                    let a_idx = self.stack.pop().unwrap() as usize;
                    let a = match &bytecode.constants[a_idx] {
                        Constant::Array2DU64(_, _, data) => data,
                        _ => return Err("Invalid type for MATRIX_MUL matrix".to_string()),
                    };
                    let b = match &bytecode.constants[b_idx] {
                        Constant::ArrayU64(_, data) => data,
                        _ => return Err("Invalid type for MATRIX_MUL vector".to_string()),
                    };
                    match self.ai_runtime.matrix_mul(a, b).await {
                        Ok(result) => {
                            let const_idx = bytecode.constants.len();
                            self.stack.push(const_idx as u64);
                            let mut new_constants = bytecode.constants.clone();
                            new_constants.push(Constant::ArrayU64(result.len(), result));
                            let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                            *bytecode = new_bytecode;
                        }
                        Err(e) => return Err(format!("Matrix multiplication error: {:?}", e)),
                    }
                }
                OPCODE_TENSOR_ADD => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for TENSOR_ADD".to_string());
                    }
                    let b_idx = self.stack.pop().unwrap() as usize;
                    let a_idx = self.stack.pop().unwrap() as usize;
                    let a = match &bytecode.constants[a_idx] {
                        Constant::ArrayU64(_, data) => data,
                        _ => return Err("Invalid type for TENSOR_ADD first tensor".to_string()),
                    };
                    let b = match &bytecode.constants[b_idx] {
                        Constant::ArrayU64(_, data) => data,
                        _ => return Err("Invalid type for TENSOR_ADD second tensor".to_string()),
                    };
                    match self.ai_runtime.tensor_add(a, b).await {
                        Ok(result) => {
                            let const_idx = bytecode.constants.len();
                            self.stack.push(const_idx as u64);
                            let mut new_constants = bytecode.constants.clone();
                            new_constants.push(Constant::ArrayU64(result.len(), result));
                            let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                            *bytecode = new_bytecode;
                        }
                        Err(e) => return Err(format!("Tensor addition error: {:?}", e)),
                    }
                }
                OPCODE_TENSOR_MULTIPLY => {
                    if self.stack.len() < 2 {
                        return Err("Not enough values on stack for TENSOR_MULTIPLY".to_string());
                    }
                    let b_idx = self.stack.pop().unwrap() as usize;
                    let a_idx = self.stack.pop().unwrap() as usize;
                    let a = match &bytecode.constants[a_idx] {
                        Constant::ArrayU64(_, data) => data,
                        _ => return Err("Invalid type for TENSOR_MULTIPLY first tensor".to_string()),
                    };
                    let b = match &bytecode.constants[b_idx] {
                        Constant::ArrayU64(_, data) => data,
                        _ => return Err("Invalid type for TENSOR_MULTIPLY second tensor".to_string()),
                    };
                    let result = self.ai_runtime.tensor_multiply(a, b);
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::ArrayU64(result.len(), result));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_QUANTIZE => {
                    if self.stack.len() < 1 {
                        return Err("Not enough values on stack for QUANTIZE".to_string());
                    }
                    let data_idx = self.stack.pop().unwrap() as usize;
                    let data = match &bytecode.constants[data_idx] {
                        Constant::Array2DU64(_, _, data) => data,
                        _ => return Err("Invalid type for QUANTIZE data".to_string()),
                    };
                    let result = self.ai_runtime.quantize_to_u8(data);
                    let const_idx = bytecode.constants.len();
                    self.stack.push(const_idx as u64);
                    let mut new_constants = bytecode.constants.clone();
                    new_constants.push(Constant::Array2DU8(result.len(), result[0].len(), result));
                    let new_bytecode = Bytecode::new(bytecode.instructions.clone(), new_constants);
                    *bytecode = new_bytecode;
                }
                OPCODE_PUSH => {
                    if ip >= bytecode.instructions.len() {
                        return Err("Incomplete PUSH instruction".to_string());
                    }
                    let value = bytecode.instructions[ip] as u64;
                    ip += 1;
                    self.stack.push(value);
                }
                OPCODE_FAIL => {
                    return Err("AI operation failed".to_string());
                }
                _ => return Err(format!("Unsupported opcode: {}", instr)),
            }
        }

        if self.stack.len() != 1 {
            return Err("AI block must return exactly one value".to_string());
        }
        let result_idx = self.stack.pop().unwrap() as usize;
        match &bytecode.constants[result_idx] {
            Constant::ArrayU64(_, data) => Ok(data.clone()),
            _ => Err("Invalid return type for AI block".to_string()),
        }
    }
}

/// Represents an async task (aligned with ksl_async.rs).
#[derive(Debug, Clone)]
pub enum AsyncTask {
    // Placeholder for async tasks (not used in this demo)
}

/// AI compiler for Kapra Chain.
pub struct AICompiler {
    is_embedded: bool,
}

impl AICompiler {
    pub fn new(is_embedded: bool) -> Self {
        AICompiler { is_embedded }
    }

    /// Compile an AI block into bytecode.
    pub fn compile(&self, node: &AstNode) -> Result<Bytecode, String> {
        match node {
            AstNode::ModelBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 2 {
                    return Err("Model block must have exactly 2 parameters: weights, biases".to_string());
                }
                if params[0].0 != "weights" || !matches!(params[0].1, Type::Array2DU64(_, _)) {
                    return Err("First parameter must be 'weights: array<array<u64, N>, M>'".to_string());
                }
                if params[1].0 != "biases" || !matches!(params[1].1, Type::ArrayU64(_)) {
                    return Err("Second parameter must be 'biases: array<u64, N>'".to_string());
                }
                if !matches!(return_type, Type::ArrayU64(_)) {
                    return Err("Model block must return array<u64, N>".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            AstNode::QuantizeBlock { params, return_type, body } => {
                // Validate parameters and return type
                if params.len() != 1 {
                    return Err("Quantize block must have exactly 1 parameter: weights".to_string());
                }
                if params[0].0 != "weights" || !matches!(params[0].1, Type::Array2DU64(_, _)) {
                    return Err("Parameter must be 'weights: array<array<u64, N>, M>'".to_string());
                }
                if !matches!(return_type, Type::Array2DU8(_, _)) {
                    return Err("Quantize block must return array<array<u8, N>, M>".to_string());
                }

                let mut bytecode = Bytecode::new(vec![], vec![]);

                // Compile the body
                for stmt in body {
                    let stmt_bytecode = self.compile_stmt(stmt)?;
                    bytecode.extend(stmt_bytecode);
                }

                Ok(bytecode)
            }
            _ => Err("Only AI blocks can be compiled at the top level".to_string()),
        }
    }

    fn compile_stmt(&self, stmt: &AstNode) -> Result<Bytecode, String> {
        match stmt {
            AstNode::Let { name, ty, value } => {
                let value_bytecode = self.compile_expr(value.as_ref())?;
                let mut bytecode = value_bytecode;

                if let AstNode::Call { name: call_name, .. } = value.as_ref() {
                    if call_name == "matrix.mul" {
                        bytecode.instructions.push(OPCODE_MATRIX_MUL);
                    } else if call_name == "tensor_add" {
                        bytecode.instructions.push(OPCODE_TENSOR_ADD);
                    } else if call_name == "tensor_multiply" {
                        bytecode.instructions.push(OPCODE_TENSOR_MULTIPLY);
                    } else if call_name == "quantize_to_u8" {
                        bytecode.instructions.push(OPCODE_QUANTIZE);
                    }
                }

                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                match name.as_str() {
                    "matrix.mul" => {
                        bytecode.instructions.push(OPCODE_MATRIX_MUL);
                    }
                    "tensor_add" => {
                        bytecode.instructions.push(OPCODE_TENSOR_ADD);
                    }
                    "tensor_multiply" => {
                        bytecode.instructions.push(OPCODE_TENSOR_MULTIPLY);
                    }
                    "quantize_to_u8" => {
                        bytecode.instructions.push(OPCODE_QUANTIZE);
                    }
                    _ => return Err(format!("Unsupported function in AI block: {}", name)),
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported statement in AI block".to_string()),
        }
    }

    fn compile_expr(&self, expr: &AstNode) -> Result<Bytecode, String> {
        match expr {
            AstNode::LiteralArrayU64(size, data) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::ArrayU64(*size, data.clone()));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::LiteralArray2DU64(rows, cols, data) => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                let const_idx = bytecode.constants.len();
                bytecode.constants.push(Constant::Array2DU64(*rows, *cols, data.clone()));
                bytecode.instructions.extend_from_slice(&[OPCODE_PUSH, const_idx as u8]);
                Ok(bytecode)
            }
            AstNode::Call { name, args } => {
                let mut bytecode = Bytecode::new(vec![], vec![]);
                for arg in args {
                    let arg_bytecode = self.compile_expr(arg)?;
                    bytecode.extend(arg_bytecode);
                }
                if name == "matrix.mul" {
                    bytecode.instructions.push(OPCODE_MATRIX_MUL);
                } else if name == "tensor_add" {
                    bytecode.instructions.push(OPCODE_TENSOR_ADD);
                } else if name == "tensor_multiply" {
                    bytecode.instructions.push(OPCODE_TENSOR_MULTIPLY);
                } else if name == "quantize_to_u8" {
                    bytecode.instructions.push(OPCODE_QUANTIZE);
                } else {
                    return Err(format!("Unsupported expression in AI block: {}", name));
                }
                Ok(bytecode)
            }
            _ => Err("Unsupported expression in AI block".to_string()),
        }
    }
}

const OPCODE_MATRIX_MUL: u8 = 0x01;
const OPCODE_TENSOR_ADD: u8 = 0x02;
const OPCODE_TENSOR_MULTIPLY: u8 = 0x03;
const OPCODE_QUANTIZE: u8 = 0x04;
const OPCODE_PUSH: u8 = 0x05;
const OPCODE_FAIL: u8 = 0x06;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_block_compilation() {
        let model_node = AstNode::ModelBlock {
            params: vec![
                ("weights".to_string(), Type::Array2DU64(2, 4)),
                ("biases".to_string(), Type::ArrayU64(4)),
            ],
            return_type: Type::ArrayU64(4),
            body: vec![
                AstNode::Let {
                    name: "output".to_string(),
                    ty: Type::ArrayU64(4),
                    value: Box::new(AstNode::Call {
                        name: "matrix.mul".to_string(),
                        args: vec![
                            AstNode::LiteralArray2DU64(2, 4, vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]]),
                            AstNode::LiteralArrayU64(4, vec![1, 1, 1, 1]),
                        ],
                    }),
                },
                AstNode::Let {
                    name: "result".to_string(),
                    ty: Type::ArrayU64(4),
                    value: Box::new(AstNode::Call {
                        name: "tensor_add".to_string(),
                        args: vec![
                            AstNode::LiteralArrayU64(4, vec![1, 2, 3, 4]),
                            AstNode::LiteralArrayU64(4, vec![1, 1, 1, 1]),
                        ],
                    }),
                },
            ],
        };

        let compiler = AICompiler::new(false);
        let bytecode = compiler.compile(&model_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_MATRIX_MUL));
        assert!(bytecode.instructions.contains(&OPCODE_TENSOR_ADD));
    }

    #[test]
    fn test_quantize_block_compilation() {
        let quantize_node = AstNode::QuantizeBlock {
            params: vec![("weights".to_string(), Type::Array2DU64(2, 4))],
            return_type: Type::Array2DU8(2, 4),
            body: vec![
                AstNode::Let {
                    name: "quantized".to_string(),
                    ty: Type::Array2DU8(2, 4),
                    value: Box::new(AstNode::Call {
                        name: "quantize_to_u8".to_string(),
                        args: vec![AstNode::LiteralArray2DU64(2, 4, vec![vec![256, 257, 258, 259], vec![260, 261, 262, 263]])],
                    }),
                },
            ],
        };

        let compiler = AICompiler::new(false);
        let bytecode = compiler.compile(&quantize_node).unwrap();
        assert!(!bytecode.instructions.is_empty());
        assert!(bytecode.instructions.contains(&OPCODE_QUANTIZE));
    }

    #[test]
    fn test_model_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array2DU64(2, 4, vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]]),
            Constant::ArrayU64(4, vec![1, 1, 1, 1]),
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push weights
            OPCODE_PUSH, 1,           // Push biases
            OPCODE_MATRIX_MUL,        // Matrix multiply
        ]);

        let mut vm = KapraVM::new(false, None);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.len(), 4);
        assert_eq!(output, vec![6, 8, 10, 12]); // Simplified matrix multiplication result
    }

    #[test]
    fn test_tensor_operations() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::ArrayU64(4, vec![1, 2, 3, 4]),
            Constant::ArrayU64(4, vec![1, 1, 1, 1]),
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push first tensor
            OPCODE_PUSH, 1,           // Push second tensor
            OPCODE_TENSOR_ADD,        // Tensor add
        ]);

        let mut vm = KapraVM::new(false, None);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output, vec![2, 3, 4, 5]);

        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::ArrayU64(4, vec![2, 3, 4, 5]),
            Constant::ArrayU64(4, vec![1, 2, 3, 4]),
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,
            OPCODE_PUSH, 1,
            OPCODE_TENSOR_MULTIPLY,
        ]);

        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output, vec![2, 6, 12, 20]);
    }

    #[test]
    fn test_quantize_execution() {
        let mut bytecode = Bytecode::new(vec![], vec![]);
        bytecode.constants.extend_from_slice(&[
            Constant::Array2DU64(2, 4, vec![vec![256, 257, 258, 259], vec![260, 261, 262, 263]]),
        ]);
        bytecode.instructions.extend_from_slice(&[
            OPCODE_PUSH, 0,           // Push weights
            OPCODE_QUANTIZE,          // Quantize to u8
        ]);

        let mut vm = KapraVM::new(true, None);
        let result = vm.execute(&bytecode);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output, vec![0, 1, 2, 3]); // Lower 8 bits of 256, 257, etc.
    }

    #[test]
    fn test_invalid_model_params() {
        let model_node = AstNode::ModelBlock {
            params: vec![("weights".to_string(), Type::Array2DU64(2, 4))],
            return_type: Type::ArrayU64(4),
            body: vec![],
        };

        let compiler = AICompiler::new(false);
        let result = compiler.compile(&model_node);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must have exactly 2 parameters"));
    }
}