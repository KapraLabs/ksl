// ksl_bytecode.rs
// Defines the KapraBytecode 2.0 format for KSL programs.

use crate::ksl_types::Type;
use std::fmt;

// Operand types for instructions
#[derive(Debug, PartialEq, Clone)]
pub enum Operand {
    Register(u8), // Virtual register (0–15)
    Immediate(Vec<u8>), // Immediate value (e.g., number, string)
}

impl Operand {
    // Encode operand to bytes
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Operand::Register(reg) => vec![*reg],
            Operand::Immediate(data) => {
                let mut bytes = vec![data.len() as u8];
                bytes.extend(data);
                bytes
            }
        }
    }

    // Decode operand from bytes
    pub fn decode(bytes: &[u8], offset: &mut usize) -> Option<Self> {
        if *offset >= bytes.len() {
            return None;
        }
        let kind = bytes[*offset];
        *offset += 1;
        if kind <= 15 {
            Some(Operand::Register(kind))
        } else {
            let len = kind as usize;
            if *offset + len > bytes.len() {
                return None;
            }
            let data = bytes[*offset..*offset + len].to_vec();
            *offset += len;
            Some(Operand::Immediate(data))
        }
    }
}

// Opcodes for KapraBytecode
#[derive(Debug, PartialEq, Clone)]
pub enum KapraOpCode {
    // Core operations
    Mov, // Mov dst_reg, src_reg_or_imm
    Add, // Add dst_reg, src_reg1, src_reg2
    Sub, // Sub dst_reg, src_reg1, src_reg2
    Mul, // Mul dst_reg, src_reg1, src_reg2
    Halt, // Halt program
    Fail, // Immediate failure
    // Control flow
    Jump, // Jump to offset (immediate)
    Call, // Call function (immediate index)
    Return, // Return from function
    // Crypto operations
    Sha3, // Sha3 dst_reg, src_reg (string or array)
    Sha3_512, // Sha3_512 dst_reg, src_reg (string or array)
    Kaprekar, // Kaprekar dst_reg, src_reg (array<u8, 4> or u16)
    BlsVerify, // BlsVerify dst_reg, msg_reg, pubkey_reg, sig_reg
    DilithiumVerify, // DilithiumVerify dst_reg, msg_reg, pubkey_reg, sig_reg
    MerkleVerify, // MerkleVerify dst_reg, root_reg, proof_reg
}

impl KapraOpCode {
    // Encode opcode to a single byte
    pub fn encode(&self) -> u8 {
        match self {
            KapraOpCode::Mov => 0x01,
            KapraOpCode::Add => 0x02,
            KapraOpCode::Sub => 0x03,
            KapraOpCode::Mul => 0x04,
            KapraOpCode::Halt => 0x05,
            KapraOpCode::Fail => 0x06,
            KapraOpCode::Jump => 0x07,
            KapraOpCode::Call => 0x08,
            KapraOpCode::Return => 0x09,
            KapraOpCode::Sha3 => 0x0A,
            KapraOpCode::Sha3_512 => 0x0C,
            KapraOpCode::Kaprekar => 0x0B,
            KapraOpCode::BlsVerify => 0x0D,
            KapraOpCode::DilithiumVerify => 0x0E,
            KapraOpCode::MerkleVerify => 0x0F,
        }
    }

    // Decode opcode from a byte
    pub fn decode(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(KapraOpCode::Mov),
            0x02 => Some(KapraOpCode::Add),
            0x03 => Some(KapraOpCode::Sub),
            0x04 => Some(KapraOpCode::Mul),
            0x05 => Some(KapraOpCode::Halt),
            0x06 => Some(KapraOpCode::Fail),
            0x07 => Some(KapraOpCode::Jump),
            0x08 => Some(KapraOpCode::Call),
            0x09 => Some(KapraOpCode::Return),
            0x0A => Some(KapraOpCode::Sha3),
            0x0C => Some(KapraOpCode::Sha3_512),
            0x0B => Some(KapraOpCode::Kaprekar),
            0x0D => Some(KapraOpCode::BlsVerify),
            0x0E => Some(KapraOpCode::DilithiumVerify),
            0x0F => Some(KapraOpCode::MerkleVerify),
            _ => None,
        }
    }
}

// Instruction structure
#[derive(Debug, PartialEq, Clone)]
pub struct KapraInstruction {
    pub opcode: KapraOpCode,
    pub operands: Vec<Operand>,
    pub type_info: Option<Type>, // Type of result (e.g., u32, array<u8, 32>)
}

impl KapraInstruction {
    pub fn new(opcode: KapraOpCode, operands: Vec<Operand>, type_info: Option<Type>) -> Self {
        KapraInstruction {
            opcode,
            operands,
            type_info,
        }
    }

    // Encode instruction to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![self.opcode.encode()];
        for operand in &self.operands {
            bytes.extend(operand.encode());
        }
        bytes
    }

    // Decode instruction from bytes
    pub fn decode(bytes: &[u8], offset: &mut usize) -> Option<Self> {
        if *offset >= bytes.len() {
            return None;
        }
        let opcode = KapraOpCode::decode(bytes[*offset])?;
        *offset += 1;
        let mut operands = Vec::new();

        // Simplified: Assume fixed operand count based on opcode
        let operand_count = match opcode {
            KapraOpCode::Mov => 2, // dst, src
            KapraOpCode::Add | KapraOpCode::Sub | KapraOpCode::Mul => 3, // dst, src1, src2
            KapraOpCode::Halt | KapraOpCode::Fail | KapraOpCode::Return => 0,
            KapraOpCode::Jump | KapraOpCode::Call => 1, // offset or index
            KapraOpCode::Sha3 | KapraOpCode::Sha3_512 | KapraOpCode::Kaprekar => 2, // dst, src
            KapraOpCode::BlsVerify | KapraOpCode::DilithiumVerify => 4, // dst, msg, pubkey, sig
            KapraOpCode::MerkleVerify => 3, // dst, root, proof
        };

        for _ in 0..operand_count {
            let operand = Operand::decode(bytes, offset)?;
            operands.push(operand);
        }

        // Type info not encoded yet (can be added later)
        Some(KapraInstruction {
            opcode,
            operands,
            type_info: None,
        })
    }
}

// Bytecode program structure
#[derive(Debug, PartialEq)]
pub struct KapraBytecode {
    pub instructions: Vec<KapraInstruction>,
}

impl KapraBytecode {
    pub fn new() -> Self {
        KapraBytecode {
            instructions: Vec::new(),
        }
    }

    // Add an instruction
    pub fn add_instruction(&mut self, instruction: KapraInstruction) {
        self.instructions.push(instruction);
    }

    // Encode entire program to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for instruction in &self.instructions {
            bytes.extend(instruction.encode());
        }
        bytes
    }

    // Decode program from bytes
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut instructions = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let instruction = KapraInstruction::decode(bytes, &mut offset)?;
            instructions.push(instruction);
        }
        Some(KapraBytecode { instructions })
    }
}

impl fmt::Display for KapraBytecode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, instr) in self.instructions.iter().enumerate() {
            write!(f, "{:04x}: {:?}", i, instr.opcode)?;
            for op in &instr.operands {
                write!(f, " {:?}", op)?;
            }
            if let Some(ty) = &instr.type_info {
                write!(f, " : {:?}", ty)?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

// Assume ksl_types.rs is in the same crate
mod ksl_types {
    pub use super::Type;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_instruction() {
        let instr = KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(vec![42]),
            ],
            Some(Type::U32),
        );
        let bytes = instr.encode();
        let mut offset = 0;
        let decoded = KapraInstruction::decode(&bytes, &mut offset).unwrap();
        assert_eq!(decoded.opcode, instr.opcode);
        assert_eq!(decoded.operands, instr.operands);
        // Note: type_info not decoded yet
    }

    #[test]
    fn encode_decode_program() {
        let mut program = KapraBytecode::new();
        program.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(vec![42]),
            ],
            Some(Type::U32),
        ));
        program.add_instruction(KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(1),
                Operand::Register(0),
                Operand::Register(0),
            ],
            Some(Type::U32),
        ));
        program.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let bytes = program.encode();
        let decoded = KapraBytecode::decode(&bytes).unwrap();
        assert_eq!(decoded.instructions.len(), 3);
        assert_eq!(decoded.instructions[0].opcode, KapraOpCode::Mov);
        assert_eq!(decoded.instructions[1].opcode, KapraOpCode::Add);
        assert_eq!(decoded.instructions[2].opcode, KapraOpCode::Halt);
    }

    #[test]
    fn instruction_serialization() {
        let mut program = KapraBytecode::new();
        program.add_instruction(KapraInstruction::new(
            KapraOpCode::Sha3,
            vec![
                Operand::Register(0),
                Operand::Register(1),
            ],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        let output = program.to_string();
        assert!(output.contains("Sha3"));
        assert!(output.contains("Register(0)"));
        assert!(output.contains("Array(U8, 32)"));
    }

    #[test]
    fn encode_decode_bls_verify() {
        let instr = KapraInstruction::new(
            KapraOpCode::BlsVerify,
            vec![
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
                Operand::Register(3),
            ],
            Some(Type::U32),
        );
        let bytes = instr.encode();
        let mut offset = 0;
        let decoded = KapraInstruction::decode(&bytes, &mut offset).unwrap();
        assert_eq!(decoded.opcode, KapraOpCode::BlsVerify);
        assert_eq!(decoded.operands.len(), 4);
    }

    #[test]
    fn encode_decode_dilithium_verify() {
        let instr = KapraInstruction::new(
            KapraOpCode::DilithiumVerify,
            vec![
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
                Operand::Register(3),
            ],
            Some(Type::U32),
        );
        let bytes = instr.encode();
        let mut offset = 0;
        let decoded = KapraInstruction::decode(&bytes, &mut offset).unwrap();
        assert_eq!(decoded.opcode, KapraOpCode::DilithiumVerify);
        assert_eq!(decoded.operands.len(), 4);
    }

    #[test]
    fn encode_decode_merkle_verify() {
        let instr = KapraInstruction::new(
            KapraOpCode::MerkleVerify,
            vec![
                Operand::Register(0),
                Operand::Register(1),
                Operand::Register(2),
            ],
            Some(Type::U32),
        );
        let bytes = instr.encode();
        let mut offset = 0;
        let decoded = KapraInstruction::decode(&bytes, &mut offset).unwrap();
        assert_eq!(decoded.opcode, KapraOpCode::MerkleVerify);
        assert_eq!(decoded.operands.len(), 3);
    }
}