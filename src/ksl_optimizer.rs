// ksl_optimizer.rs
// Implements bytecode optimizations for KSL with advanced techniques
// including async operation optimizations and enhanced constant propagation

use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand, Constant};
use crate::ksl_types::Type;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_macros::NetworkOpType;
use crate::ksl_module::Module;
use inkwell::attributes::AttributeKind;
use std::collections::{HashMap, HashSet};

/// Optimization error
type OptError = KslError;

/// Optimizer configuration
#[derive(Debug, Clone)]
pub struct OptimizerConfig {
    /// Maximum iterations for loop unrolling
    pub max_unroll_iterations: u32,
    /// Whether to enable async optimizations
    pub optimize_async: bool,
    /// Whether to enable networking optimizations
    pub optimize_networking: bool,
    /// Whether this is for an embedded target
    pub is_embedded: bool,
}

/// Optimizer state
pub struct Optimizer {
    bytecode: KapraBytecode,
    errors: Vec<OptError>,
    config: OptimizerConfig,
    /// Tracks async operations for optimization
    async_ops: Vec<AsyncOpInfo>,
}

/// Information about async operations for optimization
#[derive(Debug, Clone)]
struct AsyncOpInfo {
    /// Instruction index
    index: usize,
    /// Type of async operation
    op_type: AsyncOpType,
    /// Dependencies
    dependencies: Vec<usize>,
}

/// Types of async operations
#[derive(Debug, Clone)]
enum AsyncOpType {
    /// Simple async task
    Task,
    /// Async network operation
    Network(NetworkOpType),
    /// Async file operation
    File,
}

/// LLVM optimization pass registry
#[derive(Debug)]
pub struct LLVMPassRegistry {
    /// Available optimization passes
    passes: Vec<Box<dyn LLVMPass>>,
    /// Pass dependencies
    dependencies: HashMap<String, Vec<String>>,
    /// Pass execution order
    execution_order: Vec<String>,
}

/// Trait for LLVM optimization passes
pub trait LLVMPass {
    /// Name of the pass
    fn name(&self) -> &'static str;
    /// Run the pass on the LLVM module
    fn run_on_module(&self, module: &mut Module) -> bool;
    /// Dependencies of this pass
    fn dependencies(&self) -> Vec<&'static str> { Vec::new() }
}

/// Blockchain-specific inlining pass
pub struct BlockchainInlining {
    /// Hot functions to inline
    hot_functions: HashSet<String>,
    /// Validator-specific functions
    validator_functions: HashSet<String>,
}

impl LLVMPass for BlockchainInlining {
    fn name(&self) -> &'static str {
        "blockchain-inlining"
    }

    fn run_on_module(&self, module: &mut Module) -> bool {
        let mut modified = false;
        
        // Inline hot validator functions
        for func in module.get_functions() {
            let name = func.get_name().to_str().unwrap_or("");
            if self.validator_functions.contains(name) || 
               (self.hot_functions.contains(name) && name.contains("validate")) {
                func.add_attribute(AttributeKind::AlwaysInline);
                modified = true;
            }
        }

        modified
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["function-attrs"]
    }
}

/// Shard operation vectorization pass
pub struct ShardVectorization {
    /// Shard operation patterns
    shard_patterns: Vec<String>,
    /// Vector width for the target
    vector_width: usize,
}

impl LLVMPass for ShardVectorization {
    fn name(&self) -> &'static str {
        "shard-vectorization"
    }

    fn run_on_module(&self, module: &mut Module) -> bool {
        let mut modified = false;

        // Find shard operation patterns
        for func in module.get_functions() {
            if let Some(body) = func.get_body() {
                // Look for shard operation patterns
                for pattern in &self.shard_patterns {
                    if let Some(ops) = find_shard_operations(&body, pattern) {
                        // Vectorize compatible operations
                        if let Ok(vectorized) = vectorize_shard_ops(ops, self.vector_width) {
                            replace_with_vector_ops(&mut body, vectorized);
                            modified = true;
                        }
                    }
                }
            }
        }

        modified
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["loop-vectorize", "slp-vectorizer"]
    }
}

impl Optimizer {
    /// Creates a new optimizer with default configuration
    pub fn new(bytecode: KapraBytecode) -> Self {
        Optimizer {
            bytecode,
            errors: Vec::new(),
            config: OptimizerConfig {
                max_unroll_iterations: 4,
                optimize_async: true,
                optimize_networking: true,
                is_embedded: false,
            },
            async_ops: Vec::new(),
        }
    }

    /// Creates a new optimizer with custom configuration
    pub fn with_config(bytecode: KapraBytecode, config: OptimizerConfig) -> Self {
        Optimizer {
            bytecode,
            errors: Vec::new(),
            config,
            async_ops: Vec::new(),
        }
    }

    /// Optimize the bytecode with all passes
    pub fn optimize(&mut self) -> Result<KapraBytecode, Vec<OptError>> {
        let mut optimized = self.bytecode.clone();

        // Pass 1: Collect async operation information
        if self.config.optimize_async {
            self.collect_async_ops(&optimized);
        }

        // Pass 2: Constant propagation
        optimized = self.propagate_constants(optimized);

        // Pass 3: Constant folding
        optimized = self.constant_folding(optimized);

        // Pass 4: Loop unrolling
        optimized = self.loop_unrolling(optimized);

        // Pass 5: Dead code elimination
        optimized = self.dead_code_elimination(optimized);

        // Pass 6: Tail call optimization
        optimized = self.tail_call_optimization(optimized);

        // Pass 7: Async operation optimization
        if self.config.optimize_async {
            optimized = self.optimize_async_ops(optimized);
        }

        // Pass 8: Blockchain operations optimization
        optimized = self.optimize_blockchain_ops(optimized);

        if self.errors.is_empty() {
            Ok(optimized)
        } else {
            Err(self.errors.clone())
        }
    }

    /// Collect information about async operations in the bytecode
    fn collect_async_ops(&mut self, bytecode: &KapraBytecode) {
        for (i, instr) in bytecode.instructions.iter().enumerate() {
            match instr.opcode {
                KapraOpCode::AsyncStart => {
                    self.async_ops.push(AsyncOpInfo {
                        index: i,
                        op_type: AsyncOpType::Task,
                        dependencies: vec![],
                    });
                }
                KapraOpCode::HttpGet | KapraOpCode::HttpPost => {
                    self.async_ops.push(AsyncOpInfo {
                        index: i,
                        op_type: AsyncOpType::Network(NetworkOpType::from(instr.opcode)),
                        dependencies: vec![],
                    });
                }
                _ => {}
            }
        }
    }

    /// Optimize async operations by reordering and combining
    fn optimize_async_ops(&self, bytecode: KapraBytecode) -> KapraBytecode {
        let mut result = bytecode.clone();
        
        // Group network operations by endpoint
        if self.config.optimize_networking {
            let mut network_ops: HashMap<String, Vec<usize>> = HashMap::new();
            
            for op in &self.async_ops {
                if let AsyncOpType::Network(_) = op.op_type {
                    if let Some(Operand::Immediate(endpoint)) = result.instructions[op.index].operands.get(0) {
                        if let Ok(endpoint_str) = String::from_utf8(endpoint.clone()) {
                            network_ops.entry(endpoint_str).or_default().push(op.index);
                        }
                    }
                }
            }
            
            // Combine multiple requests to same endpoint
            for (_, indices) in network_ops {
                if indices.len() > 1 {
                    // Keep first operation, replace others with NOOP
                    for &idx in &indices[1..] {
                        result.instructions[idx] = KapraInstruction::new(
                            KapraOpCode::Noop,
                            vec![],
                            None,
                        );
                    }
                }
            }
        }
        
        // Remove NOOP instructions
        result.instructions.retain(|instr| instr.opcode != KapraOpCode::Noop);
        result
    }

    // Constant propagation: Propagate constant values to eliminate redundant computations
    fn propagate_constants(&self, bytecode: KapraBytecode) -> KapraBytecode {
        let mut result = bytecode.clone();
        let mut constants = bytecode.constants.clone();
        let mut constant_map: HashMap<u8, u64> = HashMap::new();

        // Identify instructions that load constants
        let mut i = 0;
        while i < result.instructions.len() {
            let instr = &result.instructions[i];
            
            // Skip async operations during constant propagation
            if matches!(instr.opcode, KapraOpCode::AsyncStart | KapraOpCode::HttpGet | KapraOpCode::HttpPost) {
                i += 1;
                continue;
            }

            if instr.opcode == KapraOpCode::Mov {
                if let (Operand::Register(dst), Operand::Immediate(data)) = (&instr.operands[0], &instr.operands[1]) {
                    if let Ok(value) = u64::from_le_bytes(data.as_slice().try_into().map_err(|_| ())) {
                        constant_map.insert(*dst, value);
                    }
                }
            } else if instr.opcode == KapraOpCode::Noop {
                if i + 1 < result.instructions.len() {
                    let const_idx = result.instructions[i + 1].operands.get(0)
                        .and_then(|op| if let Operand::Immediate(data) = op { Some(u32::from_le_bytes(data.as_slice().try_into().unwrap_or([0u8;4])) as usize) } else { None } )
                        .unwrap_or(constants.len());
                    if const_idx < constants.len() {
                        match &constants[const_idx] {
                            Constant::U64(val) => {
                                constant_map.insert(const_idx as u8, *val);
                            }
                            _ => {}
                        }
                    }
                }
            } else if instr.opcode == KapraOpCode::Add {
                if let (Operand::Register(dst), Operand::Register(src1), Operand::Register(src2)) =
                    (&instr.operands[0], &instr.operands[1], &instr.operands[2])
                {
                    if let (Some(val1), Some(val2)) = (constant_map.get(src1), constant_map.get(src2)) {
                        let result_val = val1.wrapping_add(val2);
                        result.instructions[i] = KapraInstruction::new(
                            KapraOpCode::Mov,
                            vec![
                                Operand::Register(*dst),
                                Operand::Immediate(result_val.to_le_bytes().to_vec()),
                            ],
                            instr.type_info.clone(),
                        );
                        constant_map.insert(*dst, result_val);
                    }
                }
            } else if instr.opcode == KapraOpCode::MatrixMul {
                if let (Operand::Register(dst), Operand::Register(src1), Operand::Register(src2)) =
                    (&instr.operands[0], &instr.operands[1], &instr.operands[2])
                {
                    if constant_map.contains_key(src1) && constant_map.contains_key(src2) {
                        // Skip matrix multiplication if inputs are constant (in reality, compute result)
                        result.instructions[i] = KapraInstruction::new(
                            KapraOpCode::Noop,
                            vec![],
                            None,
                        );
                    }
                }
            }
            i += 1;
        }

        // Remove NOOP instructions
        result.instructions.retain(|instr| instr.opcode != KapraOpCode::Noop);
        result.constants = constants;
        result
    }

    // Constant folding: Evaluate constant expressions
    fn constant_folding(&self, bytecode: KapraBytecode) -> KapraBytecode {
        let mut result = KapraBytecode::new();
        let mut const_values: HashMap<u8, u64> = HashMap::new();

        for instr in bytecode.instructions.iter() {
            match instr.opcode {
                KapraOpCode::Mov => {
                    if let (Operand::Register(dst), Operand::Immediate(data)) = (&instr.operands[0], &instr.operands[1]) {
                        if let Ok(value) = u64::from_le_bytes(data.as_slice().try_into().map_err(|_| ())) {
                            const_values.insert(*dst, value);
                            result.add_instruction(instr.clone());
                        } else {
                            result.add_instruction(instr.clone());
                        }
                    } else {
                        result.add_instruction(instr.clone());
                    }
                }
                KapraOpCode::Add | KapraOpCode::Sub | KapraOpCode::Mul => {
                    if let (Operand::Register(dst), Operand::Register(src1), Operand::Register(src2)) =
                        (&instr.operands[0], &instr.operands[1], &instr.operands[2])
                    {
                        if let (Some(val1), Some(val2)) = (const_values.get(src1), const_values.get(src2)) {
                            let result_val = match instr.opcode {
                                KapraOpCode::Add => val1 + val2,
                                KapraOpCode::Sub => val1 - val2,
                                KapraOpCode::Mul => val1 * val2,
                                _ => unreachable!(),
                            };
                            result.add_instruction(KapraInstruction::new(
                                KapraOpCode::Mov,
                                vec![
                                    Operand::Register(*dst),
                                    Operand::Immediate(result_val.to_le_bytes().to_vec()),
                                ],
                                instr.type_info.clone(),
                            ));
                            const_values.insert(*dst, result_val);
                        } else {
                            result.add_instruction(instr.clone());
                        }
                    } else {
                        result.add_instruction(instr.clone());
                    }
                }
                _ => {
                    result.add_instruction(instr.clone());
                }
            }
        }

        result
    }

    // Loop unrolling: Unroll small, fixed-iteration loops
    fn loop_unrolling(&self, bytecode: KapraBytecode) -> KapraBytecode {
        let mut result = KapraBytecode::new();
        let mut i = 0;

        while i < bytecode.instructions.len() {
            let instr = &bytecode.instructions[i];
            if instr.opcode == KapraOpCode::Jump && i > 0 {
                if let Operand::Immediate(offset_data) = &instr.operands[0] {
                    let offset = u32::from_le_bytes(offset_data.as_slice().try_into().unwrap_or([0; 4])) as usize;
                    if offset < i {
                        // Detected a backward jump (potential loop)
                        let loop_start = offset;
                        let loop_body: Vec<_> = bytecode.instructions[loop_start..i].to_vec();
                        let is_fixed_iteration = loop_body.iter().any(|instr| {
                            matches!(instr.opcode, KapraOpCode::Add | KapraOpCode::Sub | KapraOpCode::Mul)
                        });

                        // Determine unrolling limit based on is_embedded
                        let unroll_limit = if self.config.is_embedded { 2 } else { 4 };
                        let iterations = if is_fixed_iteration && loop_body.len() <= unroll_limit as usize {
                            unroll_limit // Unroll up to the limit
                        } else {
                            0 // Don't unroll
                        };

                        if iterations > 0 {
                            // Unroll the loop
                            for _ in 0..iterations {
                                result.instructions.extend(loop_body.clone());
                            }
                            i += 1; // Skip the jump
                            continue;
                        }
                    }
                }
            } else if instr.opcode == KapraOpCode::Loop {
                if i + 2 >= bytecode.instructions.len() {
                    self.errors.push(KslError::type_error(
                        "Incomplete LOOP instruction".to_string(),
                        SourcePosition::new(1, 1),
                    ));
                    return bytecode;
                }
                let iterations = bytecode.instructions[i + 1].operands.get(0)
                    .and_then(|op| if let Operand::Immediate(data) = op {
                        Some(u32::from_le_bytes(data.as_slice().try_into().unwrap_or([0; 4])))
                    } else {
                        None
                    })
                    .unwrap_or(0);
                let body_start = i + 2;
                let body_end = bytecode.instructions[i + 2].operands.get(0)
                    .and_then(|op| if let Operand::Immediate(data) = op {
                        Some(u32::from_le_bytes(data.as_slice().try_into().unwrap_or([0; 4])) as usize)
                    } else {
                        None
                    })
                    .unwrap_or(bytecode.instructions.len());
                i = body_end + 1;

                // Only unroll small loops to avoid code bloat
                if iterations <= self.config.max_unroll_iterations {
                    // Unroll the loop by repeating the body
                    for _ in 0..iterations {
                        result.instructions.extend_from_slice(&bytecode.instructions[body_start..body_end]);
                    }
                } else {
                    // Keep the loop as-is
                    result.instructions.push(KapraInstruction::new(
                        KapraOpCode::Loop,
                        vec![Operand::Immediate(iterations.to_le_bytes().to_vec())],
                        None,
                    ));
                    result.instructions.extend_from_slice(&bytecode.instructions[body_start..=body_end]);
                }
                continue;
            }
            result.add_instruction(instr.clone());
            i += 1;
        }

        result
    }

    // Dead code elimination: Remove unreachable or unused instructions
    fn dead_code_elimination(&self, bytecode: KapraBytecode) -> KapraBytecode {
        let mut result = KapraBytecode::new();
        let mut used_registers: HashSet<u8> = HashSet::new();
        let mut reachable = vec![true; bytecode.instructions.len()];

        // Pass 1: Mark unreachable code after fail/halt
        let mut i = 0;
        while i < bytecode.instructions.len() {
            let instr = &bytecode.instructions[i];
            if instr.opcode == KapraOpCode::Fail || instr.opcode == KapraOpCode::Halt {
                i += 1;
                while i < bytecode.instructions.len() && bytecode.instructions[i].opcode != KapraOpCode::Loop {
                    reachable[i] = false;
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        // Pass 2: Identify used registers
        i = bytecode.instructions.len();
        while i > 0 {
            i -= 1;
            if !reachable[i] {
                continue;
            }
            let instr = &bytecode.instructions[i];
            match instr.opcode {
                KapraOpCode::Halt | KapraOpCode::Fail => {
                    result.instructions.insert(0, instr.clone());
                }
                KapraOpCode::Mov => {
                    if let (Operand::Register(dst), src) = (&instr.operands[0], &instr.operands[1]) {
                        if used_registers.contains(dst) || src.is_register() {
                            used_registers.insert(*dst);
                            if let Operand::Register(src_reg) = src {
                                used_registers.insert(*src_reg);
                            }
                            result.instructions.insert(0, instr.clone());
                        }
                    }
                }
                KapraOpCode::Add | KapraOpCode::Sub | KapraOpCode::Mul => {
                    if let (Operand::Register(dst), Operand::Register(src1), Operand::Register(src2)) =
                        (&instr.operands[0], &instr.operands[1], &instr.operands[2])
                    {
                        if used_registers.contains(dst) {
                            used_registers.insert(*dst);
                            used_registers.insert(*src1);
                            used_registers.insert(*src2);
                            result.instructions.insert(0, instr.clone());
                        }
                    }
                }
                _ => {
                    result.instructions.insert(0, instr.clone());
                }
            }
        }

        result
    }

    // Tail call optimization: Convert tail-recursive calls to jumps
    fn tail_call_optimization(&self, bytecode: KapraBytecode) -> KapraBytecode {
        let mut result = KapraBytecode::new();
        let mut i = 0;

        while i < bytecode.instructions.len() {
            let instr = &bytecode.instructions[i];
            if i + 1 < bytecode.instructions.len() && instr.opcode == KapraOpCode::Call {
                let next_instr = &bytecode.instructions[i + 1];
                if next_instr.opcode == KapraOpCode::Return {
                    // Tail call detected
                    if let Operand::Immediate(fn_index_data) = &instr.operands[0] {
                        let fn_index = u32::from_le_bytes(fn_index_data.as_slice().try_into().unwrap_or([0; 4]));
                        result.add_instruction(KapraInstruction::new(
                            KapraOpCode::Jump,
                            vec![Operand::Immediate(fn_index.to_le_bytes().to_vec())],
                            None,
                        ));
                        i += 2; // Skip Call and Return
                        continue;
                    }
                }
            }
            result.add_instruction(instr.clone());
            i += 1;
        }

        result
    }

    /// Optimizes blockchain operations
    fn optimize_blockchain_ops(&mut self, bytecode: KapraBytecode) -> KapraBytecode {
        let mut result = KapraBytecode::new();
        let mut shard_ops = Vec::new();
        let mut current_shard = None;

        for instr in bytecode.instructions.iter() {
            match instr.opcode {
                KapraOpCode::MerkleVerify | 
                KapraOpCode::BlsVerify | 
                KapraOpCode::DilithiumVerify => {
                    // Batch verification operations
                    if let Some(batch) = self.batch_verify_ops(&shard_ops, &instr.opcode) {
                        result.add_instruction(batch);
                        shard_ops.clear();
                    } else {
                        shard_ops.push(instr.clone());
                    }
                }
                KapraOpCode::AsyncCall => {
                    // Track shard context
                    if let Some(shard_id) = self.get_shard_id(instr) {
                        current_shard = Some(shard_id);
                    }
                    result.add_instruction(instr.clone());
                }
                _ => {
                    // Process any remaining shard operations
                    if !shard_ops.is_empty() {
                        for op in shard_ops.drain(..) {
                            result.add_instruction(op);
                        }
                    }
                    result.add_instruction(instr.clone());
                }
            }
        }

        result
    }

    /// Batches verification operations when possible
    fn batch_verify_ops(&self, ops: &[KapraInstruction], op_type: &KapraOpCode) -> Option<KapraInstruction> {
        if ops.len() < 2 {
            return None;
        }

        match op_type {
            KapraOpCode::MerkleVerify => {
                // Combine multiple Merkle path verifications
                Some(KapraInstruction::new(
                    KapraOpCode::BatchMerkleVerify,
                    self.combine_merkle_ops(ops),
                    None
                ))
            }
            KapraOpCode::BlsVerify => {
                // Batch BLS signature verifications
                Some(KapraInstruction::new(
                    KapraOpCode::BatchBlsVerify,
                    self.combine_bls_ops(ops),
                    None
                ))
            }
            _ => None
        }
    }

    /// Gets shard ID from async call if it's a shard operation
    fn get_shard_id(&self, instr: &KapraInstruction) -> Option<u32> {
        if let KapraOpCode::AsyncCall = instr.opcode {
            if let Some(Operand::Immediate(data)) = instr.operands.get(0) {
                let func_name = String::from_utf8_lossy(data);
                if func_name.contains("shard") {
                    // Extract shard ID from function name or arguments
                    if let Some(Operand::Immediate(shard_data)) = instr.operands.get(1) {
                        return Some(u32::from_le_bytes(shard_data[..4].try_into().unwrap_or([0; 4])));
                    }
                }
            }
        }
        None
    }

    /// Combines multiple Merkle verification operations
    fn combine_merkle_ops(&self, ops: &[KapraInstruction]) -> Vec<Operand> {
        let mut combined = Vec::new();
        for op in ops {
            combined.extend_from_slice(&op.operands);
        }
        combined
    }

    /// Combines multiple BLS verification operations
    fn combine_bls_ops(&self, ops: &[KapraInstruction]) -> Vec<Operand> {
        let mut combined = Vec::new();
        for op in ops {
            combined.extend_from_slice(&op.operands);
        }
        combined
    }
}

// Extension trait for Operand
trait OperandExt {
    fn is_register(&self) -> bool;
}

impl OperandExt for Operand {
    fn is_register(&self) -> bool {
        matches!(self, Operand::Register(_))
    }
}

// Public API to optimize bytecode
pub fn optimize(bytecode: KapraBytecode) -> Result<KapraBytecode, Vec<OptError>> {
    Optimizer::new(bytecode).optimize()
}

// Public API to optimize bytecode with custom configuration
pub fn optimize_with_config(
    bytecode: KapraBytecode, 
    config: OptimizerConfig
) -> Result<KapraBytecode, Vec<OptError>> {
    Optimizer::with_config(bytecode, config).optimize()
}

// Assume ksl_bytecode.rs, ksl_types.rs, and ksl_errors.rs are in the same crate
mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
}

mod ksl_types {
    pub use super::Type;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_propagation_and_folding() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(5u64.to_le_bytes().to_vec()),
            ],
            Some(Type::U64),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(1),
                Operand::Immediate(3u64.to_le_bytes().to_vec()),
            ],
            Some(Type::U64),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(2),
                Operand::Register(0),
                Operand::Register(1),
            ],
            Some(Type::U64),
        ));

        let optimized = optimize(bytecode).unwrap();
        assert_eq!(optimized.instructions.len(), 3);
        assert_eq!(optimized.instructions[2].opcode, KapraOpCode::Mov);
        assert_eq!(
            optimized.instructions[2].operands[1],
            Operand::Immediate(8u64.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn test_loop_unrolling() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Loop,
            vec![Operand::Immediate(2u32.to_le_bytes().to_vec())], // 2 iterations
            None,
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
            ],
            Some(Type::U64),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::LoopEnd,
            vec![Operand::Immediate(0u32.to_le_bytes().to_vec())],
            None,
        ));

        let optimized = optimize(bytecode).unwrap();
        assert!(!optimized.instructions.contains(&KapraOpCode::Loop));
        assert_eq!(optimized.instructions.len(), 2); // Two ADD instructions
        assert_eq!(optimized.instructions[0].opcode, KapraOpCode::Add);
        assert_eq!(optimized.instructions[1].opcode, KapraOpCode::Add);
    }

    #[test]
    fn test_dead_code_elimination() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(42u64.to_le_bytes().to_vec()),
            ],
            Some(Type::U64),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(1),
                Operand::Immediate(10u64.to_le_bytes().to_vec()),
            ],
            Some(Type::U64),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(2),
                Operand::Register(0),
                Operand::Register(1),
            ],
            Some(Type::U64),
        ));

        let optimized = optimize(bytecode).unwrap();
        assert_eq!(optimized.instructions.len(), 2); // Mov + Halt
        assert_eq!(optimized.instructions[1].opcode, KapraOpCode::Halt);
    }

    #[test]
    fn test_tail_call_optimization() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Call,
            vec![Operand::Immediate(0u32.to_le_bytes().to_vec())],
            None,
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Return,
            vec![],
            None,
        ));

        let optimized = optimize(bytecode).unwrap();
        assert_eq!(optimized.instructions.len(), 1);
        assert_eq!(optimized.instructions[0].opcode, KapraOpCode::Jump);
    }

    #[test]
    fn test_no_unroll_large_loops_embedded() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Loop,
            vec![Operand::Immediate(5u32.to_le_bytes().to_vec())], // 5 iterations
            None,
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
            ],
            Some(Type::U64),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::LoopEnd,
            vec![Operand::Immediate(0u32.to_le_bytes().to_vec())],
            None,
        ));

        let optimized = optimize(bytecode).unwrap();
        assert!(optimized.instructions.contains(&KapraOpCode::Loop));
        assert_eq!(optimized.instructions.len(), 3); // Loop + Add + LoopEnd
    }
}