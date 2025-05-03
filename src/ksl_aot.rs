// ksl_aot.rs
// Implements Ahead-of-Time (AOT) compilation for KSL programs to generate native machine code.

use crate::ksl_parser::parse;
use crate::ksl_checker::check;
use crate::ksl_compiler::compile;
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::ksl_module::ModuleSystem;
use crate::ksl_errors::{KslError, SourcePosition};
use cranelift::prelude::*;
use cranelift_module::{Module, Linkage};
use cranelift_object::{ObjectModule, ObjectBuilder};
use cranelift_codegen::isa::TargetIsa;
use cranelift_codegen::settings;
use cranelift_codegen::isa::lookup as isa_lookup;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

// AOT compiler state
pub struct AotCompiler {
    module_system: ModuleSystem,
    module: ObjectModule,
}

impl AotCompiler {
    pub fn new(target: &str) -> Result<Self, KslError> {
        let isa = isa_lookup(target.parse().map_err(|e| KslError::type_error(
            format!("Invalid target: {}", e),
            SourcePosition::new(1, 1),
        ))?)?
            .finish(settings::Flags::new(settings::builder()))
            .map_err(|e| KslError::type_error(
                format!("Failed to create ISA: {}", e),
                SourcePosition::new(1, 1),
            ))?;
        let builder = ObjectBuilder::new(
            isa,
            "ksl_aot",
            cranelift_module::default_libcall_names(),
        )
        .map_err(|e| KslError::type_error(
            format!("Failed to create module: {}", e),
            SourcePosition::new(1, 1),
        ))?;
        let module = ObjectModule::new(builder);
        Ok(AotCompiler {
            module_system: ModuleSystem::new(),
            module,
        })
    }

    // Compile a KSL file to native code
    pub fn compile_file(&mut self, file: &PathBuf, output: &PathBuf) -> Result<(), KslError> {
        let main_module_name = file.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KslError::type_error(
                "Invalid main file name".to_string(),
                SourcePosition::new(1, 1),
            ))?;

        // Read source file
        let source = fs::read_to_string(file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Parse
        let ast = parse(&source)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                SourcePosition::new(1, 1),
            ))?;

        // Type-check
        check(&ast)
            .map_err(|errors| errors)?;

        // Compile to bytecode
        let bytecode = compile(&ast)
            .map_err(|errors| errors.into_iter().map(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1))).collect())?;

        // Generate native code
        self.compile_bytecode(&bytecode)?;

        // Write object file
        fs::create_dir_all(output.parent().unwrap_or(output))
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let object_data = self.module.finish()
            .emit()
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        let output_file = output.with_extension("o");
        let mut file = File::create(&output_file)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
        file.write_all(&object_data)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        Ok(())
    }

    // Compile bytecode to native code
    fn compile_bytecode(&mut self, bytecode: &KapraBytecode) -> Result<(), KslError> {
        let mut context = self.module.make_context();
        let mut func_builder_ctx = FunctionBuilderContext::new();
        let main_func_id = self.module
            .declare_function("main", Linkage::Export, &context.func.signature)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        // Define function signature (simplified: void main())
        context.func.signature.returns.push(AbiParam::new(types::I32));

        // Build function body
        let mut builder = FunctionBuilder::new(&mut context.func, &mut func_builder_ctx);
        let entry_block = builder.create_block();
        builder.switch_to_block(entry_block);
        builder.seal_block(entry_block);

        // Map registers to variables
        let mut var_map: HashMap<u8, Variable> = HashMap::new();
        for i in 0..16 {
            let var = Variable::new(i);
            builder.declare_var(var, types::I32); // Simplified: assume i32 for registers
            var_map.insert(i as u8, var);
        }

        // Translate bytecode instructions
        for (index, instr) in bytecode.instructions.iter().enumerate() {
            match instr.opcode {
                KapraOpCode::Mov => {
                    let dst = self.get_register(&instr.operands[0], index)?;
                    let src = self.get_operand_value(&instr.operands[1], index)?;
                    let dst_var = var_map[&dst];
                    if let Operand::Immediate(data) = &instr.operands[1] {
                        let value = i32::from_le_bytes(data.try_into().map_err(|_| KslError::type_error(
                            "Invalid immediate value".to_string(),
                            SourcePosition::new(1, 1),
                        ))?);
                        builder.ins().iconst(types::I32, value as i64);
                        builder.def_var(dst_var, builder.use_var(dst_var));
                    } else {
                        let src_var = var_map[&src];
                        let src_val = builder.use_var(src_var);
                        builder.def_var(dst_var, src_val);
                    }
                }
                KapraOpCode::Add => {
                    let dst = self.get_register(&instr.operands[0], index)?;
                    let src1 = self.get_register(&instr.operands[1], index)?;
                    let src2 = self.get_register(&instr.operands[2], index)?;
                    let dst_var = var_map[&dst];
                    let src1_val = builder.use_var(var_map[&src1]);
                    let src2_val = builder.use_var(var_map[&src2]);
                    let result = builder.ins().iadd(src1_val, src2_val);
                    builder.def_var(dst_var, result);
                }
                // Simplified: only Mov and Add for now
                _ => {
                    return Err(KslError::type_error(
                        format!("Unsupported opcode for AOT: {:?}", instr.opcode),
                        SourcePosition::new(1, 1),
                    ));
                }
            }
        }

        // Return 0 (simplified)
        builder.ins().return_(&[builder.ins().iconst(types::I32, 0)]);
        builder.finalize();

        // Define function in module
        self.module
            .define_function(main_func_id, &mut context)
            .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;

        Ok(())
    }

    // Helper to get register index
    fn get_register(&self, operand: &Operand, pc: usize) -> Result<u8, KslError> {
        match operand {
            Operand::Register(reg) => Ok(*reg),
            _ => Err(KslError::type_error(
                "Expected register operand".to_string(),
                SourcePosition::new(1, 1),
            )),
        }
    }

    // Helper to get operand value (simplified)
    fn get_operand_value(&self, operand: &Operand, pc: usize) -> Result<u8, KslError> {
        match operand {
            Operand::Register(reg) => Ok(*reg),
            _ => Err(KslError::type_error(
                "Expected register operand".to_string(),
                SourcePosition::new(1, 1),
            )),
        }
    }
}

// Public API to compile a KSL file to native code
pub fn aot_compile(file: &PathBuf, output: &PathBuf, target: &str) -> Result<(), KslError> {
    let mut compiler = AotCompiler::new(target)?;
    compiler.compile_file(file, output)
}

// Assume ksl_parser.rs, ksl_checker.rs, ksl_compiler.rs, ksl_bytecode.rs, ksl_module.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::parse;
}

mod ksl_checker {
    pub use super::check;
}

mod ksl_compiler {
    pub use super::compile;
}

mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
}

mod ksl_module {
    pub use super::ModuleSystem;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn test_aot_compile() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "fn main() { let x: u32 = 42; let y: u32 = x + x; }"
        ).unwrap();

        let output_dir = temp_file.path().parent().unwrap().join("aot");
        let result = aot_compile(&temp_file.path().to_path_buf(), &output_dir, "x86_64");
        assert!(result.is_ok());

        let object_file = output_dir.with_extension("o");
        assert!(object_file.exists());
        let mut contents = Vec::new();
        File::open(&object_file).unwrap().read_to_end(&mut contents).unwrap();
        assert!(!contents.is_empty());
    }
}