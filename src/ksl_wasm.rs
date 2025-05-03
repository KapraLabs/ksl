// ksl_wasm.rs
// Translates KapraBytecode 2.0 to WebAssembly for KSL programs.

use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::ksl_types::Type;
use wasm_encoder::{
    CodeSection, ExportSection, Function, FunctionSection, ImportSection, Instruction, MemorySection,
    MemoryType, Module, TypeSection, ValType,
};
use std::collections::HashMap;

// WASM generation error
#[derive(Debug, PartialEq)]
pub struct WasmError {
    pub message: String,
    pub instruction: usize, // Bytecode instruction index
}

impl WasmError {
    pub fn new(message: String, instruction: usize) -> Self {
        WasmError { message, instruction }
    }
}

// WASM generator state
pub struct WasmGenerator {
    bytecode: KapraBytecode,
    module: Module,
    registers: HashMap<u8, u32>, // Register to local index
    locals: Vec<ValType>, // Local variables (i32 for now)
    function_indices: HashMap<u32, u32>, // Bytecode index to WASM function index
    memory_offset: u32, // Current memory offset for strings and arrays
    errors: Vec<WasmError>,
}

impl WasmGenerator {
    pub fn new(bytecode: KapraBytecode) -> Self {
        WasmGenerator {
            bytecode,
            module: Module::new(),
            registers: HashMap::new(),
            locals: Vec::new(),
            function_indices: HashMap::new(),
            memory_offset: 0,
            errors: Vec::new(),
        }
    }

    // Generate WASM module
    pub fn generate(&mut self) -> Result<Vec<u8>, Vec<WasmError>> {
        // Define types
        let mut type_section = TypeSection::new();
        // Main function: () -> ()
        type_section.function([], []);
        // Imported crypto functions: (i32, i32) -> () (ptr, len -> result in memory)
        type_section.function([ValType::I32, ValType::I32], []); // sha3, sha3_512, kaprekar
        // Imported crypto verify functions: (i32, i32, i32, i32, i32, i32) -> i32 (msg_ptr, msg_len, pubkey_ptr, pubkey_len, sig_ptr, sig_len -> bool)
        type_section.function(
            [ValType::I32, ValType::I32, ValType::I32, ValType::I32, ValType::I32, ValType::I32],
            [ValType::I32],
        ); // bls_verify, dil_verify
        // Merkle verify: (i32, i32, i32, i32) -> i32 (root_ptr, root_len, proof_ptr, proof_len -> bool)
        type_section.function([ValType::I32, ValType::I32, ValType::I32, ValType::I32], [ValType::I32]); // merkle_verify
        self.module.section(&type_section);

        // Define imports
        let mut import_section = ImportSection::new();
        import_section.import("env", "sha3", wasm_encoder::EntityType::Function(1));
        import_section.import("env", "sha3_512", wasm_encoder::EntityType::Function(1));
        import_section.import("env", "kaprekar", wasm_encoder::EntityType::Function(1));
        import_section.import("env", "bls_verify", wasm_encoder::EntityType::Function(2));
        import_section.import("env", "dil_verify", wasm_encoder::EntityType::Function(2));
        import_section.import("env", "merkle_verify", wasm_encoder::EntityType::Function(3));
        self.module.section(&import_section);

        // Define functions
        let mut function_section = FunctionSection::new();
        function_section.function(0); // Main function
        self.module.section(&function_section);

        // Define memory
        let mut memory_section = MemorySection::new();
        memory_section.memory(MemoryType {
            minimum: 1, // 64KB
            maximum: None,
            memory64: false,
            shared: false,
        });
        self.module.section(&memory_section);

        // Define exports
        let mut export_section = ExportSection::new();
        export_section.export("main", wasm_encoder::ExportKind::Function, 0);
        export_section.export("memory", wasm_encoder::ExportKind::Memory, 0);
        self.module.section(&export_section);

        // Generate code
        let mut code_section = CodeSection::new();
        let mut main_function = Function::new_with_locals_types(self.locals.clone());

        // Map registers to locals
        for i in 0..16 {
            self.registers.insert(i, i as u32);
            self.locals.push(ValType::I32); // Simplified: u32 only
        }

        // Generate instructions
        for (i, instr) in self.bytecode.instructions.iter().enumerate() {
            self.generate_instruction(instr, i, &mut main_function)?;
        }

        // End main function
        main_function.instruction(&Instruction::End);
        code_section.function(&main_function);
        self.module.section(&code_section);

        if self.errors.is_empty() {
            Ok(self.module.finish())
        } else {
            Err(self.errors.clone())
        }
    }

    // Generate WASM instructions for a bytecode instruction
    fn generate_instruction(
        &mut self,
        instr: &KapraInstruction,
        instr_index: usize,
        function: &mut Function,
    ) -> Result<(), WasmError> {
        match instr.opcode {
            KapraOpCode::Mov => {
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let src = self.get_operand_value(&instr.operands[1], instr_index)?;
                match src {
                    OperandValue::Register(src_reg) => {
                        function.instruction(&Instruction::LocalGet(src_reg));
                        function.instruction(&Instruction::LocalSet(dst));
                    }
                    OperandValue::Immediate(data) => {
                        let value = u32::from_le_bytes(
                            data.try_into().map_err(|_| WasmError::new(
                                "Invalid immediate value".to_string(),
                                instr_index,
                            ))?,
                        );
                        function.instruction(&Instruction::I32Const(value as i32));
                        function.instruction(&Instruction::LocalSet(dst));
                    }
                }
            }
            KapraOpCode::Add => {
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let src1 = self.get_register(&instr.operands[1], instr_index)?;
                let src2 = self.get_register(&instr.operands[2], instr_index)?;
                function.instruction(&Instruction::LocalGet(src1));
                function.instruction(&Instruction::LocalGet(src2));
                function.instruction(&Instruction::I32Add);
                function.instruction(&Instruction::LocalSet(dst));
            }
            KapraOpCode::Sub => {
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let src1 = self.get_register(&instr.operands[1], instr_index)?;
                let src2 = self.get_register(&instr.operands[2], instr_index)?;
                function.instruction(&Instruction::LocalGet(src1));
                function.instruction(&Instruction::LocalGet(src2));
                function.instruction(&Instruction::I32Sub);
                function.instruction(&Instruction::LocalSet(dst));
            }
            KapraOpCode::Mul => {
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let src1 = self.get_register(&instr.operands[1], instr_index)?;
                let src2 = self.get_register(&instr.operands[2], instr_index)?;
                function.instruction(&Instruction::LocalGet(src1));
                function.instruction(&Instruction::LocalGet(src2));
                function.instruction(&Instruction::I32Mul);
                function.instruction(&Instruction::LocalSet(dst));
            }
            KapraOpCode::Halt => {
                function.instruction(&Instruction::Unreachable);
            }
            KapraOpCode::Fail => {
                function.instruction(&Instruction::Unreachable);
            }
            KapraOpCode::Jump => {
                let offset = self.get_u32(&instr.operands[0], instr_index)?;
                function.instruction(&Instruction::Br(offset));
            }
            KapraOpCode::Call => {
                let fn_index = self.get_u32(&instr.operands[0], instr_index)?;
                let wasm_fn_index = *self.function_indices.get(&fn_index).ok_or_else(|| {
                    WasmError::new("Invalid function index".to_string(), instr_index)
                })?;
                function.instruction(&Instruction::Call(wasm_fn_index));
            }
            KapraOpCode::Return => {
                function.instruction(&Instruction::Return);
            }
            KapraOpCode::Sha3 => {
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let src = self.get_register(&instr.operands[1], instr_index)?;
                // Store input in memory
                let offset = self.memory_offset;
                self.memory_offset += 32; // Reserve 32 bytes for result
                function.instruction(&Instruction::LocalGet(src));
                function.instruction(&Instruction::I32Const(offset as i32));
                function.instruction(&Instruction::I32Const(32)); // Length
                function.instruction(&Instruction::Call(0)); // Imported sha3
                // Load result from memory
                function.instruction(&Instruction::I32Const(offset as i32));
                function.instruction(&Instruction::I32Load(0, 0));
                function.instruction(&Instruction::LocalSet(dst));
            }
            KapraOpCode::Sha3_512 => {
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let src = self.get_register(&instr.operands[1], instr_index)?;
                // Store input in memory
                let offset = self.memory_offset;
                self.memory_offset += 64; // Reserve 64 bytes for result
                function.instruction(&Instruction::LocalGet(src));
                function.instruction(&Instruction::I32Const(offset as i32));
                function.instruction(&Instruction::I32Const(64)); // Length
                function.instruction(&Instruction::Call(1)); // Imported sha3_512
                // Load result from memory
                function.instruction(&Instruction::I32Const(offset as i32));
                function.instruction(&Instruction::I32Load(0, 0));
                function.instruction(&Instruction::LocalSet(dst));
            }
            KapraOpCode::Kaprekar => {
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let src = self.get_register(&instr.operands[1], instr_index)?;
                // Call imported kaprekar
                function.instruction(&Instruction::LocalGet(src));
                function.instruction(&Instruction::I32Const(4)); // Length
                function.instruction(&Instruction::Call(2)); // Imported kaprekar
                function.instruction(&Instruction::LocalSet(dst));
            }
            KapraOpCode::BlsVerify => {
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let msg = self.get_register(&instr.operands[1], instr_index)?;
                let pubkey = self.get_register(&instr.operands[2], instr_index)?;
                let sig = self.get_register(&instr.operands[3], instr_index)?;
                // Store inputs in memory
                let msg_offset = self.memory_offset;
                self.memory_offset += 32; // Message
                let pubkey_offset = self.memory_offset;
                self.memory_offset += 48; // Public key
                let sig_offset = self.memory_offset;
                self.memory_offset += 96; // Signature
                // Message
                function.instruction(&Instruction::LocalGet(msg));
                function.instruction(&Instruction::I32Const(msg_offset as i32));
                function.instruction(&Instruction::I32Const(32)); // Message length
                // Public key
                function.instruction(&Instruction::LocalGet(pubkey));
                function.instruction(&Instruction::I32Const(pubkey_offset as i32));
                function.instruction(&Instruction::I32Const(48)); // Pubkey length
                // Signature
                function.instruction(&Instruction::LocalGet(sig));
                function.instruction(&Instruction::I32Const(sig_offset as i32));
                function.instruction(&Instruction::I32Const(96)); // Signature length
                function.instruction(&Instruction::Call(3)); // Imported bls_verify
                // Store result (i32 boolean)
                function.instruction(&Instruction::LocalSet(dst));
            }
            KapraOpCode::DilithiumVerify => {
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let msg = self.get_register(&instr.operands[1], instr_index)?;
                let pubkey = self.get_register(&instr.operands[2], instr_index)?;
                let sig = self.get_register(&instr.operands[3], instr_index)?;
                // Store inputs in memory
                let msg_offset = self.memory_offset;
                self.memory_offset += 32; // Message
                let pubkey_offset = self.memory_offset;
                self.memory_offset += 1312; // Public key
                let sig_offset = self.memory_offset;
                self.memory_offset += 2420; // Signature
                // Message
                function.instruction(&Instruction::LocalGet(msg));
                function.instruction(&Instruction::I32Const(msg_offset as i32));
                function.instruction(&Instruction::I32Const(32)); // Message length
                // Public key
                function.instruction(&Instruction::LocalGet(pubkey));
                function.instruction(&Instruction::I32Const(pubkey_offset as i32));
                function.instruction(&Instruction::I32Const(1312)); // Pubkey length
                // Signature
                function.instruction(&Instruction::LocalGet(sig));
                function.instruction(&Instruction::I32Const(sig_offset as i32));
                function.instruction(&Instruction::I32Const(2420)); // Signature length
                function.instruction(&Instruction::Call(4)); // Imported dil_verify
                // Store result (i32 boolean)
                function.instruction(&Instruction::LocalSet(dst));
            }
            KapraOpCode::MerkleVerify => {
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let root = self.get_register(&instr.operands[1], instr_index)?;
                let proof = self.get_register(&instr.operands[2], instr_index)?;
                // Store inputs in memory
                let root_offset = self.memory_offset;
                self.memory_offset += 32; // Root
                let proof_offset = self.memory_offset;
                self.memory_offset += 64; // Proof (variable length, assume 64 for now)
                // Root
                function.instruction(&Instruction::LocalGet(root));
                function.instruction(&Instruction::I32Const(root_offset as i32));
                function.instruction(&Instruction::I32Const(32)); // Root length
                // Proof
                function.instruction(&Instruction::LocalGet(proof));
                function.instruction(&Instruction::I32Const(proof_offset as i32));
                function.instruction(&Instruction::I32Const(64)); // Proof length
                function.instruction(&Instruction::Call(5)); // Imported merkle_verify
                // Store result (i32 boolean)
                function.instruction(&Instruction::LocalSet(dst));
            }
        }
        Ok(())
    }

    // Get register index
    fn get_register(&self, operand: &Operand, instr_index: usize) -> Result<u32, WasmError> {
        match operand {
            Operand::Register(reg) if *reg < 16 => {
                self.registers.get(reg).copied().ok_or_else(|| {
                    WasmError::new("Invalid register".to_string(), instr_index)
                })
            }
            _ => Err(WasmError::new("Expected register operand".to_string(), instr_index)),
        }
    }

    // Get u32 value from operand
    fn get_u32(&self, operand: &Operand, instr_index: usize) -> Result<u32, WasmError> {
        match operand {
            Operand::Immediate(data) => {
                Ok(u32::from_le_bytes(data.try_into().map_err(|_| {
                    WasmError::new("Invalid immediate value".to_string(), instr_index)
                })?))
            }
            _ => Err(WasmError::new("Expected immediate operand".to_string(), instr_index)),
        }
    }

    // Get operand value (register or immediate)
    fn get_operand_value(&self, operand: &Operand, instr_index: usize) -> Result<OperandValue, WasmError> {
        match operand {
            Operand::Register(reg) if *reg < 16 => {
                let local = self.registers.get(reg).copied().ok_or_else(|| {
                    WasmError::new("Invalid register".to_string(), instr_index)
                })?;
                Ok(OperandValue::Register(local))
            }
            Operand::Immediate(data) => Ok(OperandValue::Immediate(data.clone())),
            _ => Err(WasmError::new("Invalid operand".to_string(), instr_index)),
        }
    }
}

#[derive(Debug)]
enum OperandValue {
    Register(u32), // WASM local index
    Immediate(Vec<u8>),
}

// Public API to generate WASM
pub fn generate_wasm(bytecode: KapraBytecode) -> Result<Vec<u8>, Vec<WasmError>> {
    let mut generator = WasmGenerator::new(bytecode);
    generator.generate()
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
    use wasmparser::{Parser as WasmParser, Payload};

    #[test]
    fn test_generate_arithmetic() {
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

        let wasm = generate_wasm(bytecode).unwrap();
        let mut parser = WasmParser::new(0);
        let mut parsed = parser.parse_all(&wasm);
        let mut has_main = false;
        for payload in parsed {
            if let Payload::ExportSection(exports) = payload.unwrap() {
                for export in exports {
                    assert_eq!(export.name, "main");
                    has_main = true;
                }
            }
        }
        assert!(has_main, "Expected main function export");
    }

    #[test]
    fn test_generate_sha3() {
        let mut bytecode = KapraBytecode::new();
        // sha3("test")
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

        let wasm = generate_wasm(bytecode).unwrap();
        let mut parser = WasmParser::new(0);
        let mut parsed = parser.parse_all(&wasm);
        let mut has_sha3_import = false;
        for payload in parsed {
            if let Payload::ImportSection(imports) = payload.unwrap() {
                for import in imports {
                    if import.name == "sha3" {
                        has_sha3_import = true;
                    }
                }
            }
        }
        assert!(has_sha3_import, "Expected sha3 import");
    }

    #[test]
    fn test_generate_bls_verify() {
        let mut bytecode = KapraBytecode::new();
        // bls_verify(msg, pubkey, sig)
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

        let wasm = generate_wasm(bytecode).unwrap();
        let mut parser = WasmParser::new(0);
        let mut parsed = parser.parse_all(&wasm);
        let mut has_bls_verify_import = false;
        for payload in parsed {
            if let Payload::ImportSection(imports) = payload.unwrap() {
                for import in imports {
                    if import.name == "bls_verify" {
                        has_bls_verify_import = true;
                    }
                }
            }
        }
        assert!(has_bls_verify_import, "Expected bls_verify import");
    }

    #[test]
    fn test_generate_dil_verify() {
        let mut bytecode = KapraBytecode::new();
        // dil_verify(msg, pubkey, sig)
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

        let wasm = generate_wasm(bytecode).unwrap();
        let mut parser = WasmParser::new(0);
        let mut parsed = parser.parse_all(&wasm);
        let mut has_dil_verify_import = false;
        for payload in parsed {
            if let Payload::ImportSection(imports) = payload.unwrap() {
                for import in imports {
                    if import.name == "dil_verify" {
                        has_dil_verify_import = true;
                    }
                }
            }
        }
        assert!(has_dil_verify_import, "Expected dil_verify import");
    }

    #[test]
    fn test_generate_merkle_verify() {
        let mut bytecode = KapraBytecode::new();
        // merkle_verify(root, proof)
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(0), Operand::Immediate(vec![0; 32])],
            Some(Type::Array(Box::new(Type::U8), 32)),
        ));
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![Operand::Register(1), Operand::Immediate(vec![0; 64])],
            Some(Type::Array(Box::new(Type::U8), 0)),
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

        let wasm = generate_wasm(bytecode).unwrap();
        let mut parser = WasmParser::new(0);
        let mut parsed = parser.parse_all(&wasm);
        let mut has_merkle_verify_import = false;
        for payload in parsed {
            if let Payload::ImportSection(imports) = payload.unwrap() {
                for import in imports {
                    if import.name == "merkle_verify" {
                        has_merkle_verify_import = true;
                    }
                }
            }
        }
        assert!(has_merkle_verify_import, "Expected merkle_verify import");
    }
}