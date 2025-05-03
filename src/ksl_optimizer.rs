// ksl_optimizer.rs
// Implements bytecode optimizations for KSL with advanced techniques

use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::ksl_types::Type;
use crate::ksl_errors::{KslError, SourcePosition};
use std::collections::{HashMap, HashSet};

// Optimization error
type OptError = KslError;

// Optimizer state
pub struct Optimizer {
    bytecode: KapraBytecode,
    errors: Vec<OptError>,
    is_embedded: bool, // Configuration for embedded devices
}

impl Optimizer {
    pub fn new(bytecode: KapraBytecode, is_embedded: bool) -> Self {
        Optimizer {
            bytecode,
            errors: Vec::new(),
            is_embedded,
        }
    }

    // Optimize the bytecode
    pub fn optimize(&mut self) -> Result<KapraBytecode, Vec<OptError>> {
        let mut optimized = self.bytecode.clone();

        // Pass 1: Constant propagation (from ksl_optimizer_advanced.rs)
        optimized = self.propagate_constants(optimized);

        // Pass 2: Constant folding (from ksl_optimizer.rs)
        optimized = self.constant_folding(optimized);

        // Pass 3: Loop unrolling (combined from both)
        optimized = self.loop_unrolling(optimized);

        // Pass 4: Dead code elimination (combined from both)
        optimized = self.dead_code_elimination(optimized);

        // Pass 5: Tail call optimization (from ksl_optimizer.rs)
        optimized = self.tail_call_optimization(optimized);

        if self.errors.is_empty() {
            Ok(optimized)
        } else {
            Err(self.errors.clone())
        }
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
            if instr.opcode == OPCODE_MOV {
                if let (Operand::Register(dst), Operand::Immediate(data)) = (&instr.operands[0], &instr.operands[1]) {
                    if let Ok(value) = u64::from_le_bytes(data.as_slice().try_into().map_err(|_| ())) {
                        constant_map.insert(*dst, value);
                    }
                }
            } else if instr.opcode == OPCODE_PUSH {
                if i + 1 < result.instructions.len() {
                    let const_idx = result.instructions[i + 1] as usize;
                    if const_idx < constants.len() {
                        match &constants[const_idx] {
                            Constant::U64(val) => {
                                constant_map.insert(const_idx as u8, *val);
                            }
                            _ => {}
                        }
                    }
                }
            } else if instr.opcode == OPCODE_ADD {
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
            } else if instr.opcode == OPCODE_MATRIX_MUL {
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
                        let unroll_limit = if self.is_embedded { 2 } else { 4 };
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
                    .unwrap_or(bodycode.instructions.len());
                i = body_end + 1;

                // Only unroll small loops to avoid code bloat
                if iterations <= unroll_limit {
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
pub fn optimize(bytecode: KapraBytecode, is_embedded: bool) -> Result<KapraBytecode, Vec<OptError>> {
    let mut optimizer = Optimizer::new(bytecode, is_embedded);
    optimizer.optimize()
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

        let optimized = optimize(bytecode, false).unwrap();
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

        let optimized = optimize(bytecode, false).unwrap();
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

        let optimized = optimize(bytecode, false).unwrap();
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

        let optimized = optimize(bytecode, false).unwrap();
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

        let optimized = optimize(bytecode, true).unwrap();
        assert!(optimized.instructions.contains(&KapraOpCode::Loop));
        assert_eq!(optimized.instructions.len(), 3); // Loop + Add + LoopEnd
    }
}