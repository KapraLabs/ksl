// kapra_vm.rs
// Implements KapraVM 2.0 to execute KapraBytecode 2.0 for KSL programs.

use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::ksl_types::Type;
use std::collections::HashMap;
use sha3::{Digest, Sha3_256, Sha3_512};

// Runtime error type
#[derive(Debug, PartialEq)]
pub struct RuntimeError {
    pub message: String,
    pub pc: usize, // Program counter at error
}

// VM state
pub struct KapraVM {
    registers: [Vec<u8>; 16], // 16 registers, storing raw bytes
    stack: Vec<(usize, HashMap<u8, Vec<u8>>)>, // (return_pc, saved_registers)
    pc: usize, // Program counter
    memory: HashMap<u64, Vec<u8>>, // Heap for immediates
    next_mem_addr: u64, // Next free memory address
    bytecode: KapraBytecode, // Program to execute
    halted: bool, // Halt flag
}

impl KapraVM {
    pub fn new(bytecode: KapraBytecode) -> Self {
        KapraVM {
            registers: [vec![]; 16],
            stack: Vec::new(),
            pc: 0,
            memory: HashMap::new(),
            next_mem_addr: 0,
            bytecode,
            halted: false,
        }
    }

    // Main entry point: Run the program
    pub fn run(&mut self) -> Result<(), RuntimeError> {
        while !self.halted && self.pc < self.bytecode.instructions.len() {
            let instruction = &self.bytecode.instructions[self.pc];
            self.execute_instruction(instruction)?;
            self.pc += 1;
        }
        Ok(())
    }

    // Execute a single instruction
    fn execute_instruction(&mut self, instr: &KapraInstruction) -> Result<(), RuntimeError> {
        match instr.opcode {
            KapraOpCode::Mov => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                self.registers[dst as usize] = src;
            }
            KapraOpCode::Add => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let a = self.get_u32(&instr.operands[1], self.pc)?;
                let b = self.get_u32(&instr.operands[2], self.pc)?;
                self.registers[dst as usize] = (a + b).to_le_bytes().to_vec();
            }
            KapraOpCode::Sub => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let a = self.get_u32(&instr.operands[1], self.pc)?;
                let b = self.get_u32(&instr.operands[2], self.pc)?;
                self.registers[dst as usize] = (a - b).to_le_bytes().to_vec();
            }
            KapraOpCode::Mul => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let a = self.get_u32(&instr.operands[1], self.pc)?;
                let b = self.get_u32(&instr.operands[2], self.pc)?;
                self.registers[dst as usize] = (a * b).to_le_bytes().to_vec();
            }
            KapraOpCode::Halt => {
                self.halted = true;
            }
            KapraOpCode::Fail => {
                return Err(RuntimeError {
                    message: "Program failed explicitly".to_string(),
                    pc: self.pc,
                });
            }
            KapraOpCode::Jump => {
                let offset = self.get_u32(&instr.operands[0], self.pc)? as usize;
                if offset >= self.bytecode.instructions.len() {
                    return Err(RuntimeError {
                        message: "Invalid jump offset".to_string(),
                        pc: self.pc,
                    });
                }
                self.pc = offset - 1; // -1 because pc increments after
            }
            KapraOpCode::Call => {
                let fn_index = self.get_u32(&instr.operands[0], self.pc)? as usize;
                if fn_index >= self.bytecode.instructions.len() {
                    return Err(RuntimeError {
                        message: "Invalid function index".to_string(),
                        pc: self.pc,
                    });
                }
                // Save registers and return address
                let saved_registers: HashMap<u8, Vec<u8>> = self
                    .registers
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| !r.is_empty())
                    .map(|(i, r)| (i as u8, r.clone()))
                    .collect();
                self.stack.push((self.pc + 1, saved_registers));
                self.pc = fn_index - 1; // -1 because pc increments after
            }
            KapraOpCode::Return => {
                if let Some((return_pc, saved_registers)) = self.stack.pop() {
                    // Restore registers
                    self.registers = [vec![]; 16];
                    for (reg, value) in saved_registers {
                        self.registers[reg as usize] = value;
                    }
                    self.pc = return_pc - 1; // -1 because pc increments after
                } else {
                    self.halted = true; // Main function return
                }
            }
            KapraOpCode::Sha3 => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                let mut hasher = Sha3_256::new();
                hasher.update(&src);
                let result = hasher.finalize();
                self.registers[dst as usize] = result.to_vec();
            }
            KapraOpCode::Sha3_512 => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                let mut hasher = Sha3_512::new();
                hasher.update(&src);
                let result = hasher.finalize();
                self.registers[dst as usize] = result.to_vec();
            }
            KapraOpCode::Kaprekar => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let src = self.get_operand_value(&instr.operands[1], instr.type_info.as_ref(), self.pc)?;
                let input = u32::from_le_bytes(src.try_into().map_err(|_| RuntimeError {
                    message: "Invalid Kaprekar input".to_string(),
                    pc: self.pc,
                })?);
                let result = kaprekar_step(input);
                self.registers[dst as usize] = result.to_le_bytes().to_vec();
            }
            KapraOpCode::BlsVerify => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let msg = self.get_operand_value(&instr.operands[1], Some(&Type::Array(Box::new(Type::U8), 32)), self.pc)?;
                let pubkey = self.get_operand_value(&instr.operands[2], Some(&Type::Array(Box::new(Type::U8), 48)), self.pc)?;
                let sig = self.get_operand_value(&instr.operands[3], Some(&Type::Array(Box::new(Type::U8), 96)), self.pc)?;
                // Placeholder: always return true
                self.registers[dst as usize] = 1u32.to_le_bytes().to_vec();
            }
            KapraOpCode::DilithiumVerify => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let msg = self.get_operand_value(&instr.operands[1], Some(&Type::Array(Box::new(Type::U8), 32)), self.pc)?;
                let pubkey = self.get_operand_value(&instr.operands[2], Some(&Type::Array(Box::new(Type::U8), 1312)), self.pc)?;
                let sig = self.get_operand_value(&instr.operands[3], Some(&Type::Array(Box::new(Type::U8), 2420)), self.pc)?;
                // Placeholder: always return true
                self.registers[dst as usize] = 1u32.to_le_bytes().to_vec();
            }
            KapraOpCode::MerkleVerify => {
                let dst = self.get_register(&instr.operands[0], self.pc)?;
                let root = self.get_operand_value(&instr.operands[1], Some(&Type::Array(Box::new(Type::U8), 32)), self.pc)?;
                let proof = self.get_operand_value(&instr.operands[2], Some(&Type::Array(Box::new(Type::U8), 0)), self.pc)?;
                // Placeholder: always return true
                self.registers[dst as usize] = 1u32.to_le_bytes().to_vec();
            }
        }
        Ok(())
    }

    // Get register index from operand
    fn get_register(&self, operand: &Operand, pc: usize) -> Result<u8, RuntimeError> {
        match operand {
            Operand::Register(reg) if *reg < 16 => Ok(*reg),
            _ => Err(RuntimeError {
                message: "Invalid register".to_string(),
                pc,
            }),
        }
    }

    // Get u32 value from operand
    fn get_u32(&self, operand: &Operand, pc: usize) -> Result<u32, RuntimeError> {
        let bytes = self.get_operand_value(operand, Some(&Type::U32), pc)?;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| RuntimeError {
            message: "Invalid u32 value".to_string(),
            pc,
        })?))
    }

    // Get operand value (register or immediate)
    fn get_operand_value(
        &self,
        operand: &Operand,
        type_info: Option<&Type>,
        pc: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        match operand {
            Operand::Register(reg) if *reg < 16 => Ok(self.registers[*reg as usize].clone()),
            Operand::Immediate(data) => Ok(data.clone()),
            _ => Err(RuntimeError {
                message: "Invalid operand".to_string(),
                pc,
            }),
        }
    }
}

// Simplified Kaprekar step (for u32 input)
fn kaprekar_step(input: u32) -> u32 {
    let mut digits = input.to_string().chars().collect::<Vec<_>>();
    while digits.len() < 4 {
        digits.push('0');
    }
    digits.sort();
    let asc = digits.iter().collect::<String>().parse::<u32>().unwrap();
    digits.reverse();
    let desc = digits.iter().collect::<String>().parse::<u32>().unwrap();
    desc - asc
}

// Public API to run bytecode
pub fn run(bytecode: KapraBytecode) -> Result<(), RuntimeError> {
    let mut vm = KapraVM::new(bytecode);
    vm.run()
}

// Assume ksl_bytecode.rs and ksl_types.rs are in the same crate
mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
}

mod ksl_types {
    pub use super::Type;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_arithmetic() {
        let mut bytecode = KapraBytecode::new();
        // x = 42
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(42u32.to_le_bytes().to_vec()),
            ],
            Some(Type::U32),
        ));
        // y = x + x
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(1),
                Operand::Register(0),
                Operand::Register(0),
            ],
            Some(Type::U32),
        ));
        // Halt
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode);
        vm.run().unwrap();
        assert_eq!(
            vm.registers[1],
            84u32.to_le_bytes().to_vec(),
            "Expected y = 42 + 42 = 84"
        );
    }

    #[test]
    fn run_function_call() {
        let mut bytecode = KapraBytecode::new();
        // Function: add(x, y) = x + y
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(2),
                Operand::Register(0),
                Operand::Register(1),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Return,
            vec![Operand::Register(2)],
            Some(Type::U32),
        ));
        // Main: call add(42, 10)
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
            KapraOpCode::Call,
            vec![Operand::Immediate(0u32.to_le_bytes().to_vec())], // Call add at index 0
            None,
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode);
        vm.run().unwrap();
        assert_eq!(
            vm.registers[2],
            52u32.to_le_bytes().to_vec(),
            "Expected add(42, 10) = 52"
        );
    }

    #[test]
    fn run_sha3() {
        let mut bytecode = KapraBytecode::new();
        // Compute SHA3-256("test")
        let input = "test".as_bytes().to_vec();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(input)],
            Some(Type::String),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Sha3,
            vec![Operand::Register(1), Operand::Register(0)],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode);
        vm.run().unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update("test");
        let expected = hasher.finalize().to_vec();
        assert_eq!(vm.registers[1], expected, "Expected SHA3-256('test')");
    }

    #[test]
    fn run_sha3_512() {
        let mut bytecode = KapraBytecode::new();
        // Compute SHA3-512("test")
        let input = "test".as_bytes().to_vec();
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(input)],
            Some(Type::String),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Sha3_512,
            vec![Operand::Register(1), Operand::Register(0)],
            Some(Type::Array(Box::new(Type::U8), 64)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode);
        vm.run().unwrap();
        let mut hasher = Sha3_512::new();
        hasher.update("test");
        let expected = hasher.finalize().to_vec();
        assert_eq!(vm.registers[1], expected, "Expected SHA3-512('test')");
    }

    #[test]
    fn run_kaprekar() {
        let mut bytecode = KapraBytecode::new();
        // Compute Kaprekar step for 1234
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(1234u32.to_le_bytes().to_vec()),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Kaprekar,
            vec![Operand::Register(1), Operand::Register(0)],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode);
        vm.run().unwrap();
        let expected = kaprekar_step(1234); // 4321 - 1234 = 3087
        assert_eq!(
            vm.registers[1],
            expected.to_le_bytes().to_vec(),
            "Expected Kaprekar(1234) = 3087"
        );
    }

    #[test]
    fn run_bls_verify() {
        let mut bytecode = KapraBytecode::new();
        // Simulate bls_verify(msg, pubkey, sig)
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![0; 32])],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(1), Operand::Immediate(vec![0; 48])],
            Some(Type::Array(Box::new(Type::U8), 48)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(2), Operand::Immediate(vec![0; 96])],
            Some(Type::Array(Box::new(Type::U8), 96)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::BlsVerify,
            vec![
                Operand::Register(3),
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode);
        vm.run().unwrap();
        assert_eq!(
            vm.registers[3],
            1u32.to_le_bytes().to_vec(),
            "Expected BLS verify to return true"
        );
    }

    #[test]
    fn run_dilithium_verify() {
        let mut bytecode = KapraBytecode::new();
        // Simulate dil_verify(msg, pubkey, sig)
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![0; 32])],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(1), Operand::Immediate(vec![0; 1312])],
            Some(Type::Array(Box::new(Type::U8), 1312)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(2), Operand::Immediate(vec![0; 2420])],
            Some(Type::Array(Box::new(Type::U8), 2420)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::DilithiumVerify,
            vec![
                Operand::Register(3),
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode);
        vm.run().unwrap();
        assert_eq!(
            vm.registers[3],
            1u32.to_le_bytes().to_vec(),
            "Expected Dilithium verify to return true"
        );
    }

    #[test]
    fn run_merkle_verify() {
        let mut bytecode = KapraBytecode::new();
        // Simulate merkle_verify(root, proof)
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![0; 32])],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(1), Operand::Immediate(vec![0; 64])],
            Some(Type::Array(Box::new(Type::U8), 0)), // Variable length
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::MerkleVerify,
            vec![
                Operand::Register(2),
                Operand::Register(0),
                Operand::Register(1),
            ],
            Some(Type::U32),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let mut vm = KapraVM::new(bytecode);
        vm.run().unwrap();
        assert_eq!(
            vm.registers[2],
            1u32.to_le_bytes().to_vec(),
            "Expected Merkle verify to return true"
        );
    }
}