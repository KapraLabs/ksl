// ksl_optimizer.rs
// Implements bytecode optimizations for KSL.

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
}

impl Optimizer {
    pub fn new(bytecode: KapraBytecode) -> Self {
        Optimizer {
            bytecode,
            errors: Vec::new(),
        }
    }

    // Optimize the bytecode
    pub fn optimize(&mut self) -> Result<KapraBytecode, Vec<OptError>> {
        let mut optimized = self.bytecode.clone();

        // Pass 1: Constant folding
        optimized = self.constant_folding(optimized);

        // Pass 2: Dead code elimination
        optimized = self.dead_code_elimination(optimized);

        // Pass 3: Loop unrolling (simplified)
        optimized = self.loop_unrolling(optimized);

        // Pass 4: Tail call optimization
        optimized = self.tail_call_optimization(optimized);

        if self.errors.is_empty() {
            Ok(optimized)
        } else {
            Err(self.errors.clone())
        }
    }

    // Constant folding: Evaluate constant expressions
    fn constant_folding(&self, bytecode: KapraBytecode) -> KapraBytecode {
        let mut result = KapraBytecode::new();
        let mut const_values: HashMap<u8, u32> = HashMap::new();

        for instr in bytecode.instructions.iter() {
            match instr.opcode {
                KapraOpCode::Mov => {
                    if let (Operand::Register(dst), Operand::Immediate(data)) = (&instr.operands[0], &instr.operands[1]) {
                        if let Ok(value) = u32::from_le_bytes(data.as_slice().try_into().map_err(|_| ())) {
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

    // Dead code elimination: Remove unreachable or unused instructions
    fn dead_code_elimination(&self, bytecode: KapraBytecode) -> KapraBytecode {
        let mut result = KapraBytecode::new();
        let mut used_registers: HashSet<u8> = HashSet::new();
        let mut reachable = true;

        // Pass 1: Identify used registers
        for instr in bytecode.instructions.iter().rev() {
            if !reachable {
                continue;
            }
            match instr.opcode {
                KapraOpCode::Halt | KapraOpCode::Fail => {
                    reachable = false;
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

    // Loop unrolling: Unroll small, fixed-iteration loops (simplified)
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

                        if is_fixed_iteration && loop_body.len() <= 3 {
                            // Unroll small loop (e.g., 3 iterations)
                            for _ in 0..3 {
                                result.instructions.extend(loop_body.clone());
                            }
                            i += 1; // Skip the jump
                            continue;
                        }
                    }
                }
            }
            result.add_instruction(instr.clone());
            i += 1;
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
pub fn optimize(bytecode: KapraBytecode) -> Result<KapraBytecode, Vec<OptError>> {
    let mut optimizer = Optimizer::new(bytecode);
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
    fn test_constant_folding() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(2u32.to_le_bytes().to_vec()),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(1),
                Operand::Immediate(3u32.to_le_bytes().to_vec()),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(2),
                Operand::Register(0),
                Operand::Register(1),
            ],
            Some(Type::U32),
        ));

        let optimized = optimize(bytecode).unwrap();
        assert_eq!(optimized.instructions.len(), 3);
        assert_eq!(optimized.instructions[2].opcode, KapraOpCode::Mov);
        assert_eq!(
            optimized.instructions[2].operands[1],
            Operand::Immediate(5u32.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn test_dead_code_elimination() {
        let mut bytecode = KapraBytecode::new();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(42u32.to_le_bytes().to_vec()),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(1),
                Operand::Immediate(10u32.to_le_bytes().to_vec()),
            ],
            Some(Type::U32),
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
            Some(Type::U32),
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
}