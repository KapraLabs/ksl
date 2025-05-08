// ksl_wasm.rs
// Translates KapraBytecode 2.0 to WebAssembly for KSL programs, with async support.

use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::ksl_types::Type;
use crate::ksl_async::{AsyncRuntime, AsyncVM};
use crate::ksl_compiler::{Compiler, CompileConfig};
use wasm_encoder::{
    CodeSection, ExportSection, Function, FunctionSection, ImportSection, Instruction, MemorySection,
    MemoryType, Module, TypeSection, ValType,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::ksl_abi::{ABIGenerator, ContractABI};
use crate::ksl_version::{ContractVersion, VersionManager};
use serde_json;

/// WASM generation error with async support
#[derive(Debug, PartialEq)]
pub struct WasmError {
    pub message: String,
    pub instruction: usize, // Bytecode instruction index
    pub is_async: bool,    // Whether the error occurred in async context
}

impl WasmError {
    pub fn new(message: String, instruction: usize, is_async: bool) -> Self {
        WasmError { message, instruction, is_async }
    }
}

/// WASM generator state with async support
pub struct WasmGenerator {
    bytecode: KapraBytecode,
    module: Module,
    registers: HashMap<u8, u32>, // Register to local index
    locals: Vec<ValType>, // Local variables (i32 for now)
    function_indices: HashMap<u32, u32>, // Bytecode index to WASM function index
    memory_offset: u32, // Current memory offset for strings and arrays
    errors: Vec<WasmError>,
    async_runtime: Arc<RwLock<AsyncRuntime>>, // Async runtime for async execution
    is_async: bool, // Whether current function is async
}

impl WasmGenerator {
    /// Creates a new WASM generator with async support
    pub fn new(bytecode: KapraBytecode) -> Self {
        WasmGenerator {
            bytecode,
            module: Module::new(),
            registers: HashMap::new(),
            locals: Vec::new(),
            function_indices: HashMap::new(),
            memory_offset: 0,
            errors: Vec::new(),
            async_runtime: Arc::new(RwLock::new(AsyncRuntime::new())),
            is_async: false,
        }
    }

    /// Generates WASM module with ABI and versioning support
    pub async fn generate_async(&mut self) -> Result<Vec<u8>, Vec<WasmError>> {
        // Define types
        let mut type_section = TypeSection::new();
        // Main function: () -> ()
        type_section.function([], []);
        // Async function: () -> i32 (promise handle)
        type_section.function([], [ValType::I32]);
        // Imported crypto functions: (i32, i32) -> () (ptr, len -> result in memory)
        type_section.function([ValType::I32, ValType::I32], []); // sha3, sha3_512, kaprekar
        // Imported crypto verify functions: (i32, i32, i32, i32, i32, i32) -> i32 (msg_ptr, msg_len, pubkey_ptr, pubkey_len, sig_ptr, sig_len -> bool)
        type_section.function(
            [ValType::I32, ValType::I32, ValType::I32, ValType::I32, ValType::I32, ValType::I32],
            [ValType::I32],
        ); // bls_verify, dil_verify
        // Merkle verify: (i32, i32, i32, i32) -> i32 (root_ptr, root_len, proof_ptr, proof_len -> bool)
        type_section.function([ValType::I32, ValType::I32, ValType::I32, ValType::I32], [ValType::I32]); // merkle_verify
        // Async imports: (i32, i32) -> i32 (ptr, len -> promise handle)
        type_section.function([ValType::I32, ValType::I32], [ValType::I32]); // async_http_get, async_http_post
        self.module.section(&type_section);

        // Define imports
        let mut import_section = ImportSection::new();
        import_section.import("env", "sha3", wasm_encoder::EntityType::Function(2));
        import_section.import("env", "sha3_512", wasm_encoder::EntityType::Function(2));
        import_section.import("env", "kaprekar", wasm_encoder::EntityType::Function(2));
        import_section.import("env", "bls_verify", wasm_encoder::EntityType::Function(3));
        import_section.import("env", "dil_verify", wasm_encoder::EntityType::Function(3));
        import_section.import("env", "merkle_verify", wasm_encoder::EntityType::Function(4));
        import_section.import("env", "async_http_get", wasm_encoder::EntityType::Function(5));
        import_section.import("env", "async_http_post", wasm_encoder::EntityType::Function(5));
        self.module.section(&import_section);

        // Define functions
        let mut function_section = FunctionSection::new();
        function_section.function(0); // Main function
        function_section.function(1); // Async function
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
        export_section.export("main_async", wasm_encoder::ExportKind::Function, 1);
        export_section.export("memory", wasm_encoder::ExportKind::Memory, 0);
        self.module.section(&export_section);

        // Generate code
        let mut code_section = CodeSection::new();
        let mut main_function = Function::new_with_locals_types(self.locals.clone());
        let mut async_function = Function::new_with_locals_types(self.locals.clone());

        // Map registers to locals
        for i in 0..16 {
            self.registers.insert(i, i as u32);
            self.locals.push(ValType::I32); // Simplified: u32 only
        }

        // Generate instructions for main function
        self.is_async = false;
        for (i, instr) in self.bytecode.instructions.iter().enumerate() {
            self.generate_instruction(instr, i, &mut main_function)?;
        }
        main_function.instruction(&Instruction::End);
        code_section.function(&main_function);

        // Generate instructions for async function
        self.is_async = true;
        for (i, instr) in self.bytecode.instructions.iter().enumerate() {
            self.generate_instruction(instr, i, &mut async_function)?;
        }
        async_function.instruction(&Instruction::End);
        code_section.function(&async_function);

        self.module.section(&code_section);

        // Add ABI custom section
        let mut abi_gen = ABIGenerator::new();
        let abi = abi_gen.generate_contract_abi(&self.bytecode.instructions, "contract").unwrap();
        let abi_json = serde_json::to_string(&abi).unwrap();
        self.module.custom_section("ksl_abi", abi_json.as_bytes());

        // Add version custom section
        let mut version = ContractVersion::new(1, 0, 0);
        version.update_checksum(&self.bytecode.instructions);
        let version_json = serde_json::to_string(&version).unwrap();
        self.module.custom_section("ksl_version", version_json.as_bytes());

        if self.errors.is_empty() {
            Ok(self.module.finish())
        } else {
            Err(self.errors.clone())
        }
    }

    /// Generates WASM instructions with gas metering
    fn generate_instruction(
        &mut self,
        instr: &KapraInstruction,
        instr_index: usize,
        function: &mut Function,
    ) -> Result<(), WasmError> {
        // Add gas metering
        let gas_cost = match instr.opcode {
            KapraOpCode::Add | KapraOpCode::Sub | KapraOpCode::Mul => 3,
            KapraOpCode::Sha3 => 30,
            KapraOpCode::Sha3_512 => 60,
            KapraOpCode::BlsVerify => 100,
            KapraOpCode::DilVerify => 120,
            KapraOpCode::MerkleVerify => 50,
            _ => 1,
        };

        // Add gas check
        function.instruction(&Instruction::LocalGet(0)); // gas counter
        function.instruction(&Instruction::I32Const(gas_cost));
        function.instruction(&Instruction::I32Sub);
        function.instruction(&Instruction::LocalTee(0)); // Update gas counter
        function.instruction(&Instruction::I32Const(0));
        function.instruction(&Instruction::I32LtS);
        function.instruction(&Instruction::If(BlockType::Empty));
        function.instruction(&Instruction::Unreachable); // Out of gas
        function.instruction(&Instruction::End);

        // Generate actual instruction
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
                                self.is_async,
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
                    WasmError::new("Invalid function index".to_string(), instr_index, self.is_async)
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
                function.instruction(&Instruction::Call(2)); // Imported sha3
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
                function.instruction(&Instruction::Call(2)); // Imported sha3_512
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
                function.instruction(&Instruction::Call(3)); // Imported dil_verify
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
                function.instruction(&Instruction::Call(4)); // Imported merkle_verify
                // Store result (i32 boolean)
                function.instruction(&Instruction::LocalSet(dst));
            }
            KapraOpCode::AsyncHttpGet => {
                if !self.is_async {
                    return Err(WasmError::new(
                        "Async operation in non-async context".to_string(),
                        instr_index,
                        false,
                    ));
                }
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let url = self.get_register(&instr.operands[1], instr_index)?;
                // Store URL in memory
                let url_offset = self.memory_offset;
                self.memory_offset += 256; // Reserve 256 bytes for URL
                function.instruction(&Instruction::LocalGet(url));
                function.instruction(&Instruction::I32Const(url_offset as i32));
                function.instruction(&Instruction::I32Const(256)); // URL length
                function.instruction(&Instruction::Call(5)); // Imported async_http_get
                // Store promise handle
                function.instruction(&Instruction::LocalSet(dst));
            }
            KapraOpCode::AsyncHttpPost => {
                if !self.is_async {
                    return Err(WasmError::new(
                        "Async operation in non-async context".to_string(),
                        instr_index,
                        false,
                    ));
                }
                let dst = self.get_register(&instr.operands[0], instr_index)?;
                let url = self.get_register(&instr.operands[1], instr_index)?;
                let data = self.get_register(&instr.operands[2], instr_index)?;
                // Store URL and data in memory
                let url_offset = self.memory_offset;
                self.memory_offset += 256; // Reserve 256 bytes for URL
                let data_offset = self.memory_offset;
                self.memory_offset += 1024; // Reserve 1024 bytes for data
                // URL
                function.instruction(&Instruction::LocalGet(url));
                function.instruction(&Instruction::I32Const(url_offset as i32));
                function.instruction(&Instruction::I32Const(256)); // URL length
                // Data
                function.instruction(&Instruction::LocalGet(data));
                function.instruction(&Instruction::I32Const(data_offset as i32));
                function.instruction(&Instruction::I32Const(1024)); // Data length
                function.instruction(&Instruction::Call(5)); // Imported async_http_post
                // Store promise handle
                function.instruction(&Instruction::LocalSet(dst));
            }
            KapraOpCode::Assert => {
                let cond = self.get_register(&instr.operands[0], instr_index)?;
                
                // Load condition value
                function.instruction(&Instruction::LocalGet(cond));
                
                // Check if condition is false (0)
                function.instruction(&Instruction::I32Eqz);
                
                // If condition is false, trap (unreachable)
                function.instruction(&Instruction::If(BlockType::Empty));
                function.instruction(&Instruction::Unreachable);
                function.instruction(&Instruction::End);
            }
            _ => {
                return Err(WasmError::new(
                    format!("Unsupported opcode: {:?}", instr.opcode),
                    instr_index,
                    self.is_async,
                ));
            }
        }
        Ok(())
    }

    // Get register index
    fn get_register(&self, operand: &Operand, instr_index: usize) -> Result<u32, WasmError> {
        match operand {
            Operand::Register(reg) if *reg < 16 => {
                self.registers.get(reg).copied().ok_or_else(|| {
                    WasmError::new("Invalid register".to_string(), instr_index, self.is_async)
                })
            }
            _ => Err(WasmError::new(
                "Expected register operand".to_string(),
                instr_index,
                self.is_async,
            )),
        }
    }

    // Get u32 value from operand
    fn get_u32(&self, operand: &Operand, instr_index: usize) -> Result<u32, WasmError> {
        match operand {
            Operand::Immediate(data) => {
                Ok(u32::from_le_bytes(data.try_into().map_err(|_| {
                    WasmError::new("Invalid immediate value".to_string(), instr_index, self.is_async)
                })?))
            }
            _ => Err(WasmError::new(
                "Expected immediate operand".to_string(),
                instr_index,
                self.is_async,
            )),
        }
    }

    // Get operand value (register or immediate)
    fn get_operand_value(&self, operand: &Operand, instr_index: usize) -> Result<OperandValue, WasmError> {
        match operand {
            Operand::Register(reg) if *reg < 16 => {
                let local = self.registers.get(reg).copied().ok_or_else(|| {
                    WasmError::new("Invalid register".to_string(), instr_index, self.is_async)
                })?;
                Ok(OperandValue::Register(local))
            }
            Operand::Immediate(data) => Ok(OperandValue::Immediate(data.clone())),
            _ => Err(WasmError::new(
                "Invalid operand".to_string(),
                instr_index,
                self.is_async,
            )),
        }
    }
}

#[derive(Debug)]
enum OperandValue {
    Register(u32), // WASM local index
    Immediate(Vec<u8>),
}

/// Public API to generate WASM with async support
pub async fn generate_wasm_async(bytecode: KapraBytecode) -> Result<Vec<u8>, Vec<WasmError>> {
    let mut generator = WasmGenerator::new(bytecode);
    generator.generate_async().await
}

/// Compiles KSL source to WASM with async support
pub async fn compile_to_wasm(source: &str, config: CompileConfig) -> Result<Vec<u8>, Vec<WasmError>> {
    let mut compiler = Compiler::new(config);
    let bytecode = compiler.compile(source)?;
    generate_wasm_async(bytecode).await
}

// Assume ksl_bytecode.rs, ksl_types.rs, ksl_async.rs, and ksl_compiler.rs are in the same crate
mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
}

mod ksl_types {
    pub use super::Type;
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncVM};
}

mod ksl_compiler {
    pub use super::{Compiler, CompileConfig};
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmparser::{Parser as WasmParser, Payload};
    use tokio::runtime::Runtime;

    #[tokio::test]
    async fn test_generate_arithmetic() {
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

        let wasm = generate_wasm_async(bytecode).await.unwrap();
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

    #[tokio::test]
    async fn test_generate_async() {
        let mut bytecode = KapraBytecode::new();
        // url = "https://example.com"
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Mov,
            vec![
                Operand::Register(0),
                Operand::Immediate(b"https://example.com".to_vec()),
            ],
            Some(Type::String),
        ));
        // response = await http.get(url)
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::AsyncHttpGet,
            vec![
                Operand::Register(1),
                Operand::Register(0),
            ],
            Some(Type::String),
        ));
        // Halt
        bytecode.add_instruction(KapraInstruction::new(
            KapraOpCode::Halt,
            vec![],
            None,
        ));

        let wasm = generate_wasm_async(bytecode).await.unwrap();
        let mut parser = WasmParser::new(0);
        let mut parsed = parser.parse_all(&wasm);
        let mut has_async_import = false;
        for payload in parsed {
            if let Payload::ImportSection(imports) = payload.unwrap() {
                for import in imports {
                    if import.name == "async_http_get" {
                        has_async_import = true;
                    }
                }
            }
        }
        assert!(has_async_import, "Expected async_http_get import");
    }

    #[tokio::test]
    async fn test_compile_to_wasm() {
        let source = r#"
            async fn main() {
                let url = "https://example.com";
                let response = await http.get(url);
            }
        "#;
        let config = CompileConfig {
            optimize: true,
            target: "wasm".to_string(),
            enable_async: true,
        };
        let wasm = compile_to_wasm(source, config).await.unwrap();
        let mut parser = WasmParser::new(0);
        let mut parsed = parser.parse_all(&wasm);
        let mut has_async_export = false;
        for payload in parsed {
            if let Payload::ExportSection(exports) = payload.unwrap() {
                for export in exports {
                    if export.name == "main_async" {
                        has_async_export = true;
                    }
                }
            }
        }
        assert!(has_async_export, "Expected main_async export");
    }

    #[test]
    async fn test_wasm_generation_with_abi() {
        let bytecode = KapraBytecode {
            instructions: vec![
                KapraInstruction {
                    opcode: KapraOpCode::Add,
                    operands: vec![
                        Operand::Register(0),
                        Operand::Register(1),
                        Operand::Register(2),
                    ],
                },
            ],
        };

        let mut generator = WasmGenerator::new(bytecode);
        let wasm = generator.generate_async().await.unwrap();

        // Verify ABI custom section
        let module = wasmparser::Parser::new(0).parse_all(&wasm).unwrap();
        let mut found_abi = false;
        let mut found_version = false;

        for section in module {
            if let Ok(wasmparser::Section::Custom(custom)) = section {
                if custom.name() == "ksl_abi" {
                    found_abi = true;
                    let abi: ContractABI = serde_json::from_slice(custom.data()).unwrap();
                    assert_eq!(abi.name, "contract");
                } else if custom.name() == "ksl_version" {
                    found_version = true;
                    let version: ContractVersion = serde_json::from_slice(custom.data()).unwrap();
                    assert_eq!(version.major, 1);
                    assert_eq!(version.minor, 0);
                    assert_eq!(version.patch, 0);
                }
            }
        }

        assert!(found_abi);
        assert!(found_version);
    }
}