// ksl_bytecode.rs
// Defines the KapraBytecode 2.0 format for KSL programs.

use crate::ksl_types::Type;
use std::fmt;
use std::collections::HashMap;

// Assume ksl_jit.rs provides JitCompiler
mod ksl_jit {
    pub struct JitCompiler;
    impl JitCompiler {
        pub fn compile_ir(_ir: &str) -> Result<(), ()> {
            Ok(()) // Placeholder
        }
    }
}

// Assume ksl_docgen.rs provides DocGenerator
mod ksl_docgen {
    pub struct DocGenerator;
    impl DocGenerator {
        pub fn process_json(_json: &str) -> Result<(), ()> {
            Ok(()) // Placeholder
        }
    }
}

/// Operand types for KapraBytecode instructions.
#[derive(Debug, PartialEq, Clone)]
pub enum Operand {
    Register(u8),       // Virtual register (0–15)
    Immediate(Vec<u8>), // Immediate value (e.g., number, string)
}

impl Operand {
    /// Encodes the operand to bytes.
    /// @returns A vector of bytes representing the operand.
    /// @example
    /// ```ksl
    /// let op = Operand::Register(0);
    /// assert_eq!(op.encode(), vec![0]);
    /// ```
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

    /// Decodes an operand from bytes.
    /// @param bytes The input byte slice.
    /// @param offset The current offset in the byte slice (updated during decoding).
    /// @returns An `Option` containing the decoded operand, or `None` if invalid.
    /// @example
    /// ```ksl
    /// let bytes = vec![0];
    /// let mut offset = 0;
    /// let op = Operand::decode(&bytes, &mut offset).unwrap();
    /// assert_eq!(op, Operand::Register(0));
    /// ```
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

/// Opcodes for KapraBytecode instructions.
#[derive(Debug, PartialEq, Clone)]
pub enum KapraOpCode {
    // Core operations
    Mov,         // Mov dst_reg, src_reg_or_imm
    Add,         // Add dst_reg, src_reg1, src_reg2
    Sub,         // Sub dst_reg, src_reg1, src_reg2
    Mul,         // Mul dst_reg, src_reg1, src_reg2
    Halt,        // Halt program
    Fail,        // Immediate failure
    // Control flow
    Jump,        // Jump to offset (immediate)
    Call,        // Call function (immediate index)
    Return,      // Return from function
    // Crypto operations
    Sha3,        // Sha3 dst_reg, src_reg (string or array)
    Sha3_512,    // Sha3_512 dst_reg, src_reg (string or array)
    Kaprekar,    // Kaprekar dst_reg, src_reg (array<u8, 4> or u16)
    BlsVerify,   // BlsVerify dst_reg, msg_reg, pubkey_reg, sig_reg
    DilithiumVerify, // DilithiumVerify dst_reg, msg_reg, pubkey_reg, sig_reg
    MerkleVerify, // MerkleVerify dst_reg, root_reg, proof_reg
    // Async operations
    AsyncCall,   // AsyncCall dst_reg, func_index (immediate)
    // Networking operations
    TcpConnect,  // TcpConnect dst_reg, host_reg, port_reg
    UdpSend,     // UdpSend dst_reg, host_reg, port_reg, data_reg
    HttpPost,    // HttpPost dst_reg, url_reg, data_reg
    HttpGet,     // HttpGet dst_reg, url_reg
    // I/O operations
    Print,       // Print src_reg (string)
    DeviceSensor, // DeviceSensor dst_reg, id_reg
    // Math operations
    Sin,         // Sin dst_reg, src_reg (f64)
    Cos,         // Cos dst_reg, src_reg (f64)
    Sqrt,        // Sqrt dst_reg, src_reg (f64)
    MatrixMul,   // MatrixMul dst_reg, a_reg, b_reg (array<array<f64, N>, N>)
    TensorReduce, // TensorReduce dst_reg, src_reg (array<array<u64, N>, M>)
}

impl KapraOpCode {
    /// Encodes the opcode to a single byte.
    /// @returns The encoded byte.
    /// @example
    /// ```ksl
    /// let opcode = KapraOpCode::Mov;
    /// assert_eq!(opcode.encode(), 0x01);
    /// ```
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
            KapraOpCode::AsyncCall => 0x10,
            // New opcodes
            KapraOpCode::TcpConnect => 0x11,
            KapraOpCode::UdpSend => 0x12,
            KapraOpCode::HttpPost => 0x13,
            KapraOpCode::HttpGet => 0x14,
            KapraOpCode::Print => 0x15,
            KapraOpCode::DeviceSensor => 0x16,
            KapraOpCode::Sin => 0x17,
            KapraOpCode::Cos => 0x18,
            KapraOpCode::Sqrt => 0x19,
            KapraOpCode::MatrixMul => 0x1A,
            KapraOpCode::TensorReduce => 0x1B,
        }
    }

    /// Decodes an opcode from a byte.
    /// @param byte The input byte.
    /// @returns An `Option` containing the decoded opcode, or `None` if invalid.
    /// @example
    /// ```ksl
    /// let opcode = KapraOpCode::decode(0x01).unwrap();
    /// assert_eq!(opcode, KapraOpCode::Mov);
    /// ```
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
            0x10 => Some(KapraOpCode::AsyncCall),
            // New opcodes
            0x11 => Some(KapraOpCode::TcpConnect),
            0x12 => Some(KapraOpCode::UdpSend),
            0x13 => Some(KapraOpCode::HttpPost),
            0x14 => Some(KapraOpCode::HttpGet),
            0x15 => Some(KapraOpCode::Print),
            0x16 => Some(KapraOpCode::DeviceSensor),
            0x17 => Some(KapraOpCode::Sin),
            0x18 => Some(KapraOpCode::Cos),
            0x19 => Some(KapraOpCode::Sqrt),
            0x1A => Some(KapraOpCode::MatrixMul),
            0x1B => Some(KapraOpCode::TensorReduce),
            _ => None,
        }
    }

    /// Generates JSON documentation for the opcode.
    /// @returns A JSON string describing the opcode, operands, and type.
    /// @example
    /// ```ksl
    /// let opcode = KapraOpCode::Mov;
    /// let json = opcode.to_doc_json(&Type::U32);
    /// // Returns JSON string
    /// ```
    pub fn to_doc_json(&self, type_info: &Option<Type>) -> String {
        let (description, operand_count) = match self {
            KapraOpCode::Mov => ("Moves value to register", 2),
            KapraOpCode::Add => ("Adds two registers", 3),
            KapraOpCode::Sub => ("Subtracts two registers", 3),
            KapraOpCode::Mul => ("Multiplies two registers", 3),
            KapraOpCode::Halt => ("Halts program execution", 0),
            KapraOpCode::Fail => ("Triggers immediate failure", 0),
            KapraOpCode::Jump => ("Jumps to offset", 1),
            KapraOpCode::Call => ("Calls function by index", 1),
            KapraOpCode::Return => ("Returns from function", 0),
            KapraOpCode::Sha3 => ("Computes SHA3 hash", 2),
            KapraOpCode::Sha3_512 => ("Computes SHA3-512 hash", 2),
            KapraOpCode::Kaprekar => ("Applies Kaprekar operation", 2),
            KapraOpCode::BlsVerify => ("Verifies BLS signature", 4),
            KapraOpCode::DilithiumVerify => ("Verifies Dilithium signature", 4),
            KapraOpCode::MerkleVerify => ("Verifies Merkle proof", 3),
            KapraOpCode::AsyncCall => ("Calls async function by index", 2),
            // New opcodes
            KapraOpCode::TcpConnect => ("Establishes TCP connection", 3),
            KapraOpCode::UdpSend => ("Sends UDP packet", 4),
            KapraOpCode::HttpPost => ("Sends HTTP POST request", 3),
            KapraOpCode::HttpGet => ("Sends HTTP GET request", 2),
            KapraOpCode::Print => ("Prints string to output", 1),
            KapraOpCode::DeviceSensor => ("Reads device sensor value", 2),
            KapraOpCode::Sin => ("Computes sine of angle", 2),
            KapraOpCode::Cos => ("Computes cosine of angle", 2),
            KapraOpCode::Sqrt => ("Computes square root", 2),
            KapraOpCode::MatrixMul => ("Multiplies two matrices", 3),
            KapraOpCode::TensorReduce => ("Reduces tensor dimensions", 2),
        };
        let type_str = match type_info {
            Some(ty) => format!("{:?}", ty),
            None => "None".to_string(),
        };
        format!(
            r#"{{
                "opcode": "{:?}",
                "description": "{}",
                "operands": {},
                "type": "{}"
            }}"#,
            self, description, operand_count, type_str
        )
    }
}

/// Instruction structure for KapraBytecode.
#[derive(Debug, PartialEq, Clone)]
pub struct KapraInstruction {
    pub opcode: KapraOpCode,
    pub operands: Vec<Operand>,
    pub type_info: Option<Type>, // Type of result (e.g., u32, array<u8, 32>)
}

impl KapraInstruction {
    /// Creates a new instruction.
    /// @param opcode The opcode.
    /// @param operands The list of operands.
    /// @param type_info The optional result type.
    /// @returns A new `KapraInstruction`.
    /// @example
    /// ```ksl
    /// let instr = KapraInstruction::new(
    ///     KapraOpCode::Mov,
    ///     vec![Operand::Register(0), Operand::Immediate(vec![42])],
    ///     Some(Type::U32)
    /// );
    /// ```
    pub fn new(opcode: KapraOpCode, operands: Vec<Operand>, type_info: Option<Type>) -> Self {
        KapraInstruction {
            opcode,
            operands,
            type_info,
        }
    }

    /// Encodes the instruction to bytes.
    /// @returns A vector of bytes representing the instruction.
    /// @example
    /// ```ksl
    /// let instr = KapraInstruction::new(
    ///     KapraOpCode::Mov,
    ///     vec![Operand::Register(0), Operand::Immediate(vec![42])],
    ///     Some(Type::U32)
    /// );
    /// let bytes = instr.encode();
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![self.opcode.encode()];
        for operand in &self.operands {
            bytes.extend(operand.encode());
        }
        bytes
    }

    /// Decodes an instruction from bytes.
    /// @param bytes The input byte slice.
    /// @param offset The current offset in the byte slice (updated during decoding).
    /// @returns An `Option` containing the decoded instruction, or `None` if invalid.
    /// @example
    /// ```ksl
    /// let bytes = vec![0x01, 0, 1, 42];
    /// let mut offset = 0;
    /// let instr = KapraInstruction::decode(&bytes, &mut offset).unwrap();
    /// assert_eq!(instr.opcode, KapraOpCode::Mov);
    /// ```
    pub fn decode(bytes: &[u8], offset: &mut usize) -> Option<Self> {
        if *offset >= bytes.len() {
            return None;
        }
        let opcode = KapraOpCode::decode(bytes[*offset])?;
        *offset += 1;
        let mut operands = Vec::new();

        let operand_count = match opcode {
            KapraOpCode::Mov => 2, // dst, src
            KapraOpCode::Add | KapraOpCode::Sub | KapraOpCode::Mul => 3, // dst, src1, src2
            KapraOpCode::Halt | KapraOpCode::Fail | KapraOpCode::Return => 0,
            KapraOpCode::Jump | KapraOpCode::Call => 1, // offset or index
            KapraOpCode::Sha3 | KapraOpCode::Sha3_512 | KapraOpCode::Kaprekar => 2, // dst, src
            KapraOpCode::BlsVerify | KapraOpCode::DilithiumVerify => 4, // dst, msg, pubkey, sig
            KapraOpCode::MerkleVerify => 3, // dst, root, proof
            KapraOpCode::AsyncCall => 2, // dst, func_index
            // New opcodes
            KapraOpCode::TcpConnect | KapraOpCode::UdpSend | KapraOpCode::HttpPost | KapraOpCode::HttpGet => 3, // dst, host, port
            KapraOpCode::Print => 1, // src
            KapraOpCode::DeviceSensor => 2, // dst, id
            KapraOpCode::Sin | KapraOpCode::Cos | KapraOpCode::Sqrt => 2, // dst, src
            KapraOpCode::MatrixMul => 3, // dst, a, b
            KapraOpCode::TensorReduce => 2, // dst, src
        };

        for _ in 0..operand_count {
            let operand = Operand::decode(bytes, offset)?;
            operands.push(operand);
        }

        Some(KapraInstruction {
            opcode,
            operands,
            type_info: None,
        })
    }

    /// Generates LLVM-style IR for the instruction.
    /// @returns A string containing the IR representation.
    /// @example
    /// ```ksl
    /// let instr = KapraInstruction::new(
    ///     KapraOpCode::Mov,
    ///     vec![Operand::Register(0), Operand::Immediate(vec![42])],
    ///     Some(Type::U32)
    /// );
    /// let ir = instr.to_jit_ir();
    /// // Returns "store i32 42, i32* %r0"
    /// ```
    pub fn to_jit_ir(&self) -> String {
        match self.opcode {
            KapraOpCode::Mov => {
                if let [Operand::Register(dst), src] = self.operands.as_slice() {
                    match src {
                        Operand::Register(src_reg) => {
                            format!("store i32 %r{}, i32* %r{}", src_reg, dst)
                        }
                        Operand::Immediate(data) => {
                            let value = data.iter().fold(0, |acc, &x| (acc << 8) | x as u32);
                            format!("store i32 {}, i32* %r{}", value, dst)
                        }
                    }
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Add => {
                if let [Operand::Register(dst), Operand::Register(src1), Operand::Register(src2)] =
                    self.operands.as_slice()
                {
                    format!(
                        "%r{} = add i32 %r{}, %r{}",
                        dst, src1, src2
                    )
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Sub => {
                if let [Operand::Register(dst), Operand::Register(src1), Operand::Register(src2)] =
                    self.operands.as_slice()
                {
                    format!(
                        "%r{} = sub i32 %r{}, %r{}",
                        dst, src1, src2
                    )
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Mul => {
                if let [Operand::Register(dst), Operand::Register(src1), Operand::Register(src2)] =
                    self.operands.as_slice()
                {
                    format!(
                        "%r{} = mul i32 %r{}, %r{}",
                        dst, src1, src2
                    )
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Halt => "ret void".to_string(),
            KapraOpCode::Fail => "unreachable".to_string(),
            KapraOpCode::Jump => {
                if let [Operand::Immediate(offset)] = self.operands.as_slice() {
                    let value = offset.iter().fold(0, |acc, &x| (acc << 8) | x as u32);
                    format!("br label %{}", value)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Call => {
                if let [Operand::Immediate(index)] = self.operands.as_slice() {
                    let value = index.iter().fold(0, |acc, &x| (acc << 8) | x as u32);
                    format!("call void @func{}", value)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Return => "ret void".to_string(),
            KapraOpCode::Sha3 => {
                if let [Operand::Register(dst), Operand::Register(src)] = self.operands.as_slice() {
                    format!("%r{} = call [32 x i8] @sha3(i32 %r{})", dst, src)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Sha3_512 => {
                if let [Operand::Register(dst), Operand::Register(src)] = self.operands.as_slice() {
                    format!("%r{} = call [64 x i8] @sha3_512(i32 %r{})", dst, src)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Kaprekar => {
                if let [Operand::Register(dst), Operand::Register(src)] = self.operands.as_slice() {
                    format!("%r{} = call i32 @kaprekar(i32 %r{})", dst, src)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::BlsVerify => {
                if let [Operand::Register(dst), Operand::Register(msg), Operand::Register(pubkey), Operand::Register(sig)] =
                    self.operands.as_slice()
                {
                    format!(
                        "%r{} = call i32 @bls_verify(i32 %r{}, i32 %r{}, i32 %r{})",
                        dst, msg, pubkey, sig
                    )
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::DilithiumVerify => {
                if let [Operand::Register(dst), Operand::Register(msg), Operand::Register(pubkey), Operand::Register(sig)] =
                    self.operands.as_slice()
                {
                    format!(
                        "%r{} = call i32 @dilithium_verify(i32 %r{}, i32 %r{}, i32 %r{})",
                        dst, msg, pubkey, sig
                    )
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::MerkleVerify => {
                if let [Operand::Register(dst), Operand::Register(root), Operand::Register(proof)] =
                    self.operands.as_slice()
                {
                    format!(
                        "%r{} = call i32 @merkle_verify(i32 %r{}, i32 %r{})",
                        dst, root, proof
                    )
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::AsyncCall => {
                if let [Operand::Register(dst), Operand::Immediate(index)] = self.operands.as_slice() {
                    let value = index.iter().fold(0, |acc, &x| (acc << 8) | x as u32);
                    format!("%r{} = call i32 @async_func{}", dst, value)
                } else {
                    "unreachable".to_string()
                }
            }
            // New opcodes
            KapraOpCode::TcpConnect => {
                if let [Operand::Register(dst), Operand::Register(host), Operand::Register(port)] = self.operands.as_slice() {
                    format!("%r{} = call i32 @tcp_connect(i32 %r{}, i32 %r{}, i32 %r{})", dst, host, port)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::UdpSend => {
                if let [Operand::Register(dst), Operand::Register(host), Operand::Register(port), Operand::Register(data)] = self.operands.as_slice() {
                    format!("%r{} = call i32 @udp_send(i32 %r{}, i32 %r{}, i32 %r{}, i32 %r{})", dst, host, port, data)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::HttpPost => {
                if let [Operand::Register(dst), Operand::Register(url), Operand::Register(data)] = self.operands.as_slice() {
                    format!("%r{} = call i32 @http_post(i32 %r{}, i32 %r{}, i32 %r{})", dst, url, data)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::HttpGet => {
                if let [Operand::Register(dst), Operand::Register(url)] = self.operands.as_slice() {
                    format!("%r{} = call i32 @http_get(i32 %r{}, i32 %r{})", dst, url)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Print => {
                if let [Operand::Register(src)] = self.operands.as_slice() {
                    format!("call void @print(i32 %r{})", src)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::DeviceSensor => {
                if let [Operand::Register(dst), Operand::Register(id)] = self.operands.as_slice() {
                    format!("%r{} = call i32 @device_sensor(i32 %r{}, i32 %r{})", dst, id)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Sin => {
                if let [Operand::Register(dst), Operand::Register(src)] = self.operands.as_slice() {
                    format!("%r{} = call f64 @sin(f64 %r{})", dst, src)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Cos => {
                if let [Operand::Register(dst), Operand::Register(src)] = self.operands.as_slice() {
                    format!("%r{} = call f64 @cos(f64 %r{})", dst, src)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::Sqrt => {
                if let [Operand::Register(dst), Operand::Register(src)] = self.operands.as_slice() {
                    format!("%r{} = call f64 @sqrt(f64 %r{})", dst, src)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::MatrixMul => {
                if let [Operand::Register(dst), Operand::Register(a), Operand::Register(b)] = self.operands.as_slice() {
                    format!("%r{} = call [32 x i8] @matrix_mul(i32 %r{}, i32 %r{}, i32 %r{})", dst, a, b)
                } else {
                    "unreachable".to_string()
                }
            }
            KapraOpCode::TensorReduce => {
                if let [Operand::Register(dst), Operand::Register(src)] = self.operands.as_slice() {
                    format!("%r{} = call [32 x i8] @tensor_reduce(i32 %r{}, i32 %r{})", dst, src)
                } else {
                    "unreachable".to_string()
                }
            }
        }
    }
}

/// Configuration for bytecode generation
#[derive(Debug, Clone)]
pub struct BytecodeConfig {
    /// Whether to skip bytecode generation for LLVM compilation
    pub skip_for_llvm: bool,
    /// Whether to enable micro-VM optimizations
    pub enable_micro_vm: bool,
    /// Whether to generate LLVM IR
    pub generate_llvm_ir: bool,
    /// Target architecture for micro-VM
    pub micro_vm_target: Option<String>,
}

impl Default for BytecodeConfig {
    fn default() -> Self {
        BytecodeConfig {
            skip_for_llvm: false,
            enable_micro_vm: false,
            generate_llvm_ir: false,
            micro_vm_target: None,
        }
    }
}

/// Bytecode program structure.
#[derive(Debug, PartialEq)]
pub struct KapraBytecode {
    pub instructions: Vec<KapraInstruction>,
    pub config: BytecodeConfig,
    pub llvm_ir: Option<String>,
    pub micro_vm_optimizations: Option<MicroVMOptimizations>,
}

/// Micro-VM specific optimizations
#[derive(Debug, Clone)]
pub struct MicroVMOptimizations {
    pub register_usage: HashMap<u8, usize>,
    pub hot_paths: Vec<Vec<usize>>,
    pub constant_pool: Vec<Vec<u8>>,
    pub instruction_cache: HashMap<KapraOpCode, usize>,
}

impl KapraBytecode {
    /// Creates a new bytecode program with configuration
    pub fn new_with_config(config: BytecodeConfig) -> Self {
        KapraBytecode {
            instructions: Vec::new(),
            config,
            llvm_ir: None,
            micro_vm_optimizations: None,
        }
    }

    /// Creates a new bytecode program with default configuration
    pub fn new() -> Self {
        Self::new_with_config(BytecodeConfig::default())
    }

    /// Adds an instruction to the program with micro-VM optimizations
    pub fn add_instruction(&mut self, instruction: KapraInstruction) {
        if self.config.skip_for_llvm {
            return;
        }

        self.instructions.push(instruction.clone());

        if self.config.enable_micro_vm {
            self.apply_micro_vm_optimizations(&instruction);
        }
    }

    /// Applies micro-VM specific optimizations
    fn apply_micro_vm_optimizations(&mut self, instruction: &KapraInstruction) {
        if self.micro_vm_optimizations.is_none() {
            self.micro_vm_optimizations = Some(MicroVMOptimizations {
                register_usage: HashMap::new(),
                hot_paths: Vec::new(),
                constant_pool: Vec::new(),
                instruction_cache: HashMap::new(),
            });
        }

        if let Some(optimizations) = &mut self.micro_vm_optimizations {
            // Track register usage
            for operand in &instruction.operands {
                if let Operand::Register(reg) = operand {
                    *optimizations.register_usage.entry(*reg).or_insert(0) += 1;
                }
            }

            // Track instruction frequency
            *optimizations.instruction_cache.entry(instruction.opcode.clone()).or_insert(0) += 1;

            // Track constants
            for operand in &instruction.operands {
                if let Operand::Immediate(data) = operand {
                    if !optimizations.constant_pool.contains(data) {
                        optimizations.constant_pool.push(data.clone());
                    }
                }
            }
        }
    }

    /// Generates LLVM IR for the program
    pub fn generate_llvm_ir(&mut self) -> Result<String, String> {
        if !self.config.generate_llvm_ir {
            return Ok(String::new());
        }

        let mut ir = String::new();
        ir.push_str("; ModuleID = 'ksl_module'\n");
        ir.push_str("target triple = \"x86_64-unknown-linux-gnu\"\n\n");

        // Generate function declarations
        ir.push_str("declare i32 @printf(i8*, ...)\n");
        ir.push_str("declare void @llvm.memcpy.p0i8.p0i8.i64(i8*, i8*, i64, i1)\n\n");

        // Generate main function
        ir.push_str("define i32 @main() {\n");
        ir.push_str("entry:\n");

        // Generate instructions
        for (i, instr) in self.instructions.iter().enumerate() {
            ir.push_str(&format!("  ; Instruction {}\n", i));
            ir.push_str(&format!("  {}\n", instr.to_jit_ir()));
        }

        ir.push_str("  ret i32 0\n");
        ir.push_str("}\n");

        self.llvm_ir = Some(ir.clone());
        Ok(ir)
    }

    /// Optimizes the bytecode for micro-VM execution
    pub fn optimize_for_micro_vm(&mut self) -> Result<(), String> {
        if !self.config.enable_micro_vm {
            return Ok(());
        }

        // Apply register allocation optimization
        self.optimize_register_allocation()?;

        // Apply constant folding
        self.optimize_constant_folding()?;

        // Apply instruction reordering
        self.optimize_instruction_order()?;

        Ok(())
    }

    /// Optimizes register allocation for micro-VM
    fn optimize_register_allocation(&mut self) -> Result<(), String> {
        if let Some(optimizations) = &self.micro_vm_optimizations {
            let mut register_map = HashMap::new();
            let mut next_reg = 0;

            // Map frequently used registers to lower numbers
            let mut register_usage: Vec<_> = optimizations.register_usage.iter().collect();
            register_usage.sort_by(|a, b| b.1.cmp(a.1));

            for (reg, _) in register_usage {
                register_map.insert(*reg, next_reg);
                next_reg += 1;
            }

            // Update instructions with new register numbers
            for instr in &mut self.instructions {
                for operand in &mut instr.operands {
                    if let Operand::Register(reg) = operand {
                        *reg = register_map[reg];
                    }
                }
            }
        }
        Ok(())
    }

    /// Optimizes constant folding for micro-VM
    fn optimize_constant_folding(&mut self) -> Result<(), String> {
        let mut i = 0;
        while i < self.instructions.len() {
            let instr = &self.instructions[i];
            match instr.opcode {
                KapraOpCode::Add | KapraOpCode::Sub | KapraOpCode::Mul => {
                    if let [Operand::Register(dst), Operand::Immediate(a), Operand::Immediate(b)] = &instr.operands {
                        let a_val = u32::from_le_bytes(a.as_slice().try_into().map_err(|_| "Invalid immediate value")?);
                        let b_val = u32::from_le_bytes(b.as_slice().try_into().map_err(|_| "Invalid immediate value")?);
                        let result = match instr.opcode {
                            KapraOpCode::Add => a_val + b_val,
                            KapraOpCode::Sub => a_val - b_val,
                            KapraOpCode::Mul => a_val * b_val,
                            _ => unreachable!(),
                        };
                        self.instructions[i] = KapraInstruction::new(
                            KapraOpCode::Mov,
                            vec![Operand::Register(*dst), Operand::Immediate(result.to_le_bytes().to_vec())],
                            instr.type_info.clone(),
                        );
                    }
                }
                _ => {}
            }
            i += 1;
        }
        Ok(())
    }

    /// Optimizes instruction order for micro-VM
    fn optimize_instruction_order(&mut self) -> Result<(), String> {
        if let Some(optimizations) = &self.micro_vm_optimizations {
            // Group instructions by frequency
            let mut instruction_groups: HashMap<KapraOpCode, Vec<usize>> = HashMap::new();
            for (i, instr) in self.instructions.iter().enumerate() {
                instruction_groups.entry(instr.opcode.clone()).or_default().push(i);
            }

            // Reorder instructions to minimize cache misses
            let mut new_instructions = Vec::new();
            for (opcode, indices) in instruction_groups {
                for idx in indices {
                    new_instructions.push(self.instructions[idx].clone());
                }
            }
            self.instructions = new_instructions;
        }
        Ok(())
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

    #[test]
    fn encode_decode_async_call() {
        let instr = KapraInstruction::new(
            KapraOpCode::AsyncCall,
            vec![
                Operand::Register(0),
                Operand::Immediate(vec![1]),
            ],
            Some(Type::Option(Box::new(Type::String))),
        );
        let bytes = instr.encode();
        let mut offset = 0;
        let decoded = KapraInstruction::decode(&bytes, &mut offset).unwrap();
        assert_eq!(decoded.opcode, KapraOpCode::AsyncCall);
        assert_eq!(decoded.operands.len(), 2);
    }

    #[test]
    fn jit_ir_generation() {
        let instr = KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(vec![42]),
            ],
            Some(Type::U32),
        );
        let ir = instr.to_jit_ir();
        assert_eq!(ir, "store i32 42, i32* %r0");

        let instr = KapraInstruction::new(
            KapraOpCode::Add,
            vec![
                Operand::Register(1),
                Operand::Register(0),
                Operand::Register(0),
            ],
            Some(Type::U32),
        );
        let ir = instr.to_jit_ir();
        assert_eq!(ir, "%r1 = add i32 %r0, %r0");

        let instr = KapraInstruction::new(
            KapraOpCode::AsyncCall,
            vec![
                Operand::Register(0),
                Operand::Immediate(vec![1]),
            ],
            Some(Type::Option(Box::new(Type::String))),
        );
        let ir = instr.to_jit_ir();
        assert_eq!(ir, "%r0 = call i32 @async_func1");
    }

    #[test]
    fn opcode_documentation() {
        let opcode = KapraOpCode::Mov;
        let json = opcode.to_doc_json(&Some(Type::U32));
        assert!(json.contains(r#""opcode": "Mov""#));
        assert!(json.contains(r#""description": "Moves value to register""#));
        assert!(json.contains(r#""operands": 2"#));
        assert!(json.contains(r#""type": "U32""#));
    }

    #[test]
    fn encode_decode_networking() {
        let opcodes = vec![
            (KapraOpCode::TcpConnect, 0x11),
            (KapraOpCode::UdpSend, 0x12),
            (KapraOpCode::HttpPost, 0x13),
            (KapraOpCode::HttpGet, 0x14),
        ];

        for (opcode, byte) in opcodes {
            assert_eq!(opcode.encode(), byte);
            assert_eq!(KapraOpCode::decode(byte), Some(opcode));
        }
    }

    #[test]
    fn encode_decode_io() {
        let opcodes = vec![
            (KapraOpCode::Print, 0x15),
            (KapraOpCode::DeviceSensor, 0x16),
        ];

        for (opcode, byte) in opcodes {
            assert_eq!(opcode.encode(), byte);
            assert_eq!(KapraOpCode::decode(byte), Some(opcode));
        }
    }

    #[test]
    fn encode_decode_math() {
        let opcodes = vec![
            (KapraOpCode::Sin, 0x17),
            (KapraOpCode::Cos, 0x18),
            (KapraOpCode::Sqrt, 0x19),
            (KapraOpCode::MatrixMul, 0x1A),
            (KapraOpCode::TensorReduce, 0x1B),
        ];

        for (opcode, byte) in opcodes {
            assert_eq!(opcode.encode(), byte);
            assert_eq!(KapraOpCode::decode(byte), Some(opcode));
        }
    }

    #[test]
    fn networking_instruction_serialization() {
        let instructions = vec![
            KapraInstruction::new(
                KapraOpCode::TcpConnect,
                vec![Operand::Register(0), Operand::Register(1), Operand::Register(2)],
                Some(Type::U32),
            ),
            KapraInstruction::new(
                KapraOpCode::UdpSend,
                vec![Operand::Register(0), Operand::Register(1), Operand::Register(2), Operand::Register(3)],
                Some(Type::U32),
            ),
            KapraInstruction::new(
                KapraOpCode::HttpPost,
                vec![Operand::Register(0), Operand::Register(1), Operand::Register(2)],
                Some(Type::String),
            ),
            KapraInstruction::new(
                KapraOpCode::HttpGet,
                vec![Operand::Register(0), Operand::Register(1)],
                Some(Type::String),
            ),
        ];

        for instr in instructions {
            let bytes = instr.encode();
            let mut offset = 0;
            let decoded = KapraInstruction::decode(&bytes, &mut offset).unwrap();
            assert_eq!(instr, decoded);
        }
    }

    #[test]
    fn io_instruction_serialization() {
        let instructions = vec![
            KapraInstruction::new(
                KapraOpCode::Print,
                vec![Operand::Register(0)],
                Some(Type::Void),
            ),
            KapraInstruction::new(
                KapraOpCode::DeviceSensor,
                vec![Operand::Register(0), Operand::Register(1)],
                Some(Type::F64),
            ),
        ];

        for instr in instructions {
            let bytes = instr.encode();
            let mut offset = 0;
            let decoded = KapraInstruction::decode(&bytes, &mut offset).unwrap();
            assert_eq!(instr, decoded);
        }
    }

    #[test]
    fn math_instruction_serialization() {
        let instructions = vec![
            KapraInstruction::new(
                KapraOpCode::Sin,
                vec![Operand::Register(0), Operand::Register(1)],
                Some(Type::F64),
            ),
            KapraInstruction::new(
                KapraOpCode::Cos,
                vec![Operand::Register(0), Operand::Register(1)],
                Some(Type::F64),
            ),
            KapraInstruction::new(
                KapraOpCode::Sqrt,
                vec![Operand::Register(0), Operand::Register(1)],
                Some(Type::F64),
            ),
            KapraInstruction::new(
                KapraOpCode::MatrixMul,
                vec![Operand::Register(0), Operand::Register(1), Operand::Register(2)],
                Some(Type::Array(Box::new(Type::Array(Box::new(Type::F64), 4)), 4)),
            ),
            KapraInstruction::new(
                KapraOpCode::TensorReduce,
                vec![Operand::Register(0), Operand::Register(1)],
                Some(Type::Array(Box::new(Type::U64), 4)),
            ),
        ];

        for instr in instructions {
            let bytes = instr.encode();
            let mut offset = 0;
            let decoded = KapraInstruction::decode(&bytes, &mut offset).unwrap();
            assert_eq!(instr, decoded);
        }
    }

    #[test]
    fn networking_jit_ir() {
        let instructions = vec![
            KapraInstruction::new(
                KapraOpCode::TcpConnect,
                vec![Operand::Register(0), Operand::Register(1), Operand::Register(2)],
                Some(Type::U32),
            ),
            KapraInstruction::new(
                KapraOpCode::UdpSend,
                vec![Operand::Register(0), Operand::Register(1), Operand::Register(2), Operand::Register(3)],
                Some(Type::U32),
            ),
        ];

        for instr in instructions {
            let ir = instr.to_jit_ir();
            assert!(!ir.is_empty());
            assert!(!ir.contains("unreachable"));
        }
    }

    #[test]
    fn io_jit_ir() {
        let instructions = vec![
            KapraInstruction::new(
                KapraOpCode::Print,
                vec![Operand::Register(0)],
                Some(Type::Void),
            ),
            KapraInstruction::new(
                KapraOpCode::DeviceSensor,
                vec![Operand::Register(0), Operand::Register(1)],
                Some(Type::F64),
            ),
        ];

        for instr in instructions {
            let ir = instr.to_jit_ir();
            assert!(!ir.is_empty());
            assert!(!ir.contains("unreachable"));
        }
    }

    #[test]
    fn math_jit_ir() {
        let instructions = vec![
            KapraInstruction::new(
                KapraOpCode::Sin,
                vec![Operand::Register(0), Operand::Register(1)],
                Some(Type::F64),
            ),
            KapraInstruction::new(
                KapraOpCode::MatrixMul,
                vec![Operand::Register(0), Operand::Register(1), Operand::Register(2)],
                Some(Type::Array(Box::new(Type::Array(Box::new(Type::F64), 4)), 4)),
            ),
        ];

        for instr in instructions {
            let ir = instr.to_jit_ir();
            assert!(!ir.is_empty());
            assert!(!ir.contains("unreachable"));
        }
    }
}
