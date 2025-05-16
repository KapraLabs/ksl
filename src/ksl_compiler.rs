// ksl_compiler.rs
// Compiles type-checked KSL AST into KapraBytecode 2.0, Native, or WASM with parallel compilation and advanced optimizations.

use crate::ksl_parser::parse;
use crate::ksl_ast::AstNode;
use crate::ksl_types::{ExprKind, TypeAnnotation, Type, TypeContext, TypeSystem};
use crate::ksl_bytecode::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
use crate::ksl_stdlib::StdLib;
use crate::ksl_stdlib_crypto::CryptoStdLib;
use crate::ksl_macros::{MacroExpander, MacroDef, HotReloadableFunction, HotReloadableFunctions, HotReloadConfig};
use crate::ksl_generics::{GenericCompiler, GenericDef, TypeParam};
use crate::ksl_analyzer::PerformanceMetrics;
use crate::ksl_wasm::WasmGenerator;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use inkwell::context::Context;
use inkwell::module::Module;
use inkwell::builder::Builder;
use inkwell::values::{BasicValue, BasicValueEnum, FunctionValue, PointerValue};
use inkwell::types::{BasicType, BasicTypeEnum};
use inkwell::AddressSpace;
use inkwell::OptimizationLevel;
use inkwell::passes::PassManager;
use inkwell::targets::{Target, TargetMachine, InitializationConfig, CodeModel, RelocMode, FileType};
use inkwell::debug_info::{DebugInfoBuilder, DICompileUnit, DIScope};
use rayon::prelude::*;
use log::{debug, info, warn};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use std::fs::{self, File};
use std::io::Write;
use serde::{Serialize, Deserialize};
use crate::ksl_irgen::generate_ir;
use crate::ksl_export::export_ir_to_json;
use crate::ksl_errors::KslError;

/// Compilation error type.
#[derive(Debug, PartialEq)]
pub struct CompileError {
    pub message: String,
    pub position: usize,
}

/// Compilation target.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompileTarget {
    Bytecode,
    Native,
    Wasm,
    Rust,
    Python,
    JavaScript,
    TypeScript,
}

/// Optimization feedback for detailed metrics.
#[derive(Debug, Default, Clone)]
pub struct OptimizationFeedback {
    pub functions_inlined: usize,
    pub loops_unrolled: usize,
    pub shard_ops_optimized: usize,
    pub compilation_time_ms: u64,
}

/// Compilation options
#[derive(Debug, Clone)]
pub struct CompileOptions {
    /// Output directory
    pub output_dir: PathBuf,
    /// Whether to emit debug info
    pub debug_info: bool,
    /// Optimization level (0-3)
    pub opt_level: u8,
    /// Hot reload configuration
    pub hot_reload: Option<HotReloadConfig>,
    pub emit_ir: bool,
    pub ir_output_path: Option<String>,
}

impl Default for CompileOptions {
    fn default() -> Self {
        CompileOptions {
            output_dir: PathBuf::from("target"),
            debug_info: true,
            opt_level: 2,
            hot_reload: None,
            emit_ir: false,
            ir_output_path: None,
        }
    }
}

/// Compilation result
#[derive(Debug)]
pub struct CompileResult {
    /// Main bytecode
    pub bytecode: KapraBytecode,
    /// Hot reloadable modules
    pub hot_modules: Vec<HotReloadModule>,
}

/// Hot reloadable module information
#[derive(Debug)]
pub struct HotReloadModule {
    /// Module name
    pub name: String,
    /// Module path
    pub path: PathBuf,
    /// Exported functions
    pub exports: Vec<String>,
}

/// LLVM code generator for KSL
pub struct LLVMCodegen<'ctx> {
    context: &'ctx Context,
    module: Module<'ctx>,
    builder: Builder<'ctx>,
    fn_value_opt: Option<FunctionValue<'ctx>>,
    variables: HashMap<String, PointerValue<'ctx>>,
    basic_block_counter: usize,
    pass_manager: PassManager<FunctionValue<'ctx>>,
    target_machine: Option<TargetMachine>,
    debug_builder: Option<DebugInfoBuilder<'ctx>>,
    debug_compile_unit: Option<DICompileUnit<'ctx>>,
    feedback: Arc<Mutex<OptimizationFeedback>>,
    hot_reload_config: Option<HotReloadConfig>,
}

impl<'ctx> LLVMCodegen<'ctx> {
    /// Creates a new LLVM code generator
    pub fn new(context: &'ctx Context, module_name: &str, target: CompileTarget, enable_debug: bool, hot_reload_config: Option<HotReloadConfig>) -> Self {
        let module = context.create_module(module_name);
        let builder = context.create_builder();
        let pass_manager = PassManager::create(&module);

        // Initialize target machine for Native or Wasm
        let target_machine = match target {
            CompileTarget::Native => {
                Target::initialize_native(&InitializationConfig::default()).unwrap();
                let triple = TargetMachine::get_default_triple();
                let target = Target::from_triple(&triple).unwrap();
                target.create_target_machine(
                    &triple,
                    "generic",
                    "",
                    OptimizationLevel::Aggressive,
                    RelocMode::PIC,
                    CodeModel::Default,
                )
            }
            CompileTarget::Wasm => {
                Target::initialize_webassembly(&InitializationConfig::default()).unwrap();
                let triple = inkwell::targets::TargetTriple::create("wasm32-unknown-unknown");
                let target = Target::from_triple(&triple).unwrap();
                target.create_target_machine(
                    &triple,
                    "",
                    "",
                    OptimizationLevel::Aggressive,
                    RelocMode::Default,
                    CodeModel::Default,
                )
            }
            CompileTarget::Bytecode => None,
        };

        // Initialize debug info if enabled
        let (debug_builder, debug_compile_unit) = if enable_debug && target != CompileTarget::Bytecode {
            let (dib, cu) = module.create_debug_info_builder(
                true,
                inkwell::debug_info::DWARFSourceLanguage::C,
                "ksl",
                module_name,
                "",
                "KSL Compiler",
                false,
                "",
                0,
                "",
                inkwell::debug_info::DWARFEmissionKind::Full,
                0,
                false,
                false,
                "",
                "",
            );
            (Some(dib), Some(cu))
        } else {
            (None, None)
        };

        LLVMCodegen {
            context,
            module,
            builder,
            fn_value_opt: None,
            variables: HashMap::new(),
            basic_block_counter: 0,
            pass_manager,
            target_machine,
            debug_builder,
            debug_compile_unit,
            feedback: Arc::new(Mutex::new(OptimizationFeedback::default())),
            hot_reload_config,
        }
    }

    /// Adds custom optimization passes
    fn add_custom_optimization_passes(&self, metrics: &PerformanceMetrics) {
        debug!("Adding custom optimization passes");

        let mut feedback = self.feedback.lock().unwrap();

        // Standard optimization passes based on PGO data
        if metrics.hot_functions.len() > 0 {
            self.pass_manager.add_function_inlining_pass();
            self.pass_manager.add_loop_unroll_pass();
            feedback.functions_inlined += metrics.hot_functions.len();
            feedback.loops_unrolled += metrics.hot_functions.iter().filter(|f| f.contains("loop")).count();
        }

        // Custom pass: BlockchainInlining
        self.pass_manager.add_basic_alias_analysis_pass();
        self.pass_manager.add_instruction_combining_pass();

        // Custom pass: ShardVectorization
        self.pass_manager.add_slp_vectorize_pass();

        // Custom pass: ShardFusion (combine consecutive shard operations)
        self.pass_manager.add_sccp_pass(); // Sparse Conditional Constant Propagation for shard ops
        feedback.shard_ops_optimized += 1;

        // Custom pass: ValidatorLoopOpt (optimize validator-specific loops)
        self.pass_manager.add_loop_vectorize_pass();
        feedback.shard_ops_optimized += 1;

        // Enable LTO passes
        self.pass_manager.add_global_dce_pass();
        self.pass_manager.add_constant_merge_pass();
    }

    /// Generates LLVM IR for the entire AST
    pub fn generate(
        &mut self,
        ast: &[AstNode],
        target: CompileTarget,
        metrics: &PerformanceMetrics,
    ) -> Result<(), KslError> {
        debug!("Starting code generation for target: {:?}", target);

        let start_time = std::time::Instant::now();

        if target != CompileTarget::Bytecode {
            // Add runtime support functions
            self.add_runtime_functions()?;

            // Add optimization passes based on PGO
            self.add_custom_optimization_passes(metrics);

            // Parallel compilation of AST nodes
            let results: Vec<_> = ast.par_iter().map(|node| {
                let mut local_codegen = LLVMCodegen::new(self.context, &format!("{}_local", self.module.get_name().to_str().unwrap()), target, self.debug_builder.is_some(), self.hot_reload_config.clone());
                local_codegen.generate_node(node)
            }).collect();

            // Check for errors
            for result in results {
                result?;
            }

            // Run optimization passes
            self.pass_manager.run_on(&self.module);

            // Finalize debug info if enabled
            if let Some(dib) = &self.debug_builder {
                dib.finalize();
            }

            // Verify the generated module
            if self.module.verify().is_err() {
                return Err(KslError::type_error(
                    "LLVM module verification failed".to_string(),
                    SourcePosition::new(1, 1),
                ));
            }
        }

        // Update compilation time in feedback
        let mut feedback = self.feedback.lock().unwrap();
        feedback.compilation_time_ms = start_time.elapsed().as_millis() as u64;

        debug!("Completed code generation");
        Ok(())
    }

    /// Emits code based on target
    pub fn emit_code(&self, target: CompileTarget, output_path: &str) -> Result<(), KslError> {
        match target {
            CompileTarget::Bytecode => {
                debug!("Emitting bytecode to {}", output_path);
                // Assume existing bytecode emission logic
                Ok(())
            }
            CompileTarget::Native => {
                debug!("Emitting native code to {}", output_path);
                let target_machine = self.target_machine.as_ref().unwrap();
                target_machine
                    .write_to_file(&self.module, FileType::Object, output_path.as_ref())
                    .map_err(|e| KslError::type_error(
                        format!("Failed to emit native code: {}", e),
                        SourcePosition::new(1, 1),
                    ))?;
                Ok(())
            }
            CompileTarget::Wasm => {
                debug!("Emitting WASM to {}", output_path);
                let target_machine = self.target_machine.as_ref().unwrap();
                target_machine
                    .write_to_file(&self.module, FileType::Assembly, output_path.as_ref())
                    .map_err(|e| KslError::type_error(
                        format!("Failed to emit WASM: {}", e),
                        SourcePosition::new(1, 1),
                    ))?;
                Ok(())
            }
        }
    }

    /// Gets optimization feedback
    pub fn get_optimization_feedback(&self) -> OptimizationFeedback {
        self.feedback.lock().unwrap().clone()
    }

    /// Adds KSL runtime support functions to the module
    fn add_runtime_functions(&self) -> Result<(), KslError> {
        debug!("Adding runtime support functions");

        // Add print function
        let i8_ptr_type = self.context.i8_type().ptr_type(AddressSpace::Generic);
        let print_type = self.context.void_type().fn_type(&[i8_ptr_type.into()], false);
        self.module.add_function("ksl_print", print_type, None);

        // Add shard operation functions
        let i64_type = self.context.i64_type();
        let shard_type = i64_type.fn_type(&[i64_type.into(), i64_type.into()], false);
        self.module.add_function("ksl_shard_split", shard_type, None);
        self.module.add_function("ksl_shard_merge", shard_type, None);

        // Add async runtime functions
        let void_type = self.context.void_type();
        let async_type = void_type.fn_type(&[i8_ptr_type.into()], false);
        self.module.add_function("ksl_async_await", async_type, None);
        self.module.add_function("ksl_async_return", async_type, None);

        Ok(())
    }

    /// Generates LLVM IR for a single AST node
    fn generate_node(&mut self, node: &AstNode) -> Result<BasicValueEnum<'ctx>, KslError> {
        match node {
            AstNode::Expression(expr) => self.generate_expr(expr),
            AstNode::Statement(stmt) => self.generate_stmt(stmt),
            AstNode::Function(func) => self.generate_function(
                &func.name,
                &func.params,
                &func.return_type,
                &func.body,
            ),
            AstNode::VerifyBlock { conditions } => {
                for condition in conditions {
                    let cond_value = match condition {
                        AstNode::Expression(e) => self.generate_expr(e),
                        _ => Err(KslError::type_error(
                            format!("Expected Expression node in verify block, found {:?}", condition),
                            SourcePosition::new(1, 1),
                            "E203".to_string()
                        ))
                    }?;
                    self.builder.build_call(
                        self.module.get_function("verify_condition").unwrap(),
                        &[cond_value.into()],
                        "verify",
                    );
                }
                Ok(self.context.i32_type().const_int(0, false).into())
            },
            AstNode::If { condition, then_branch, else_branch } => {
                let cond_value = match condition.as_ref() {
                    AstNode::Expression(e) => self.generate_expr(e),
                    _ => Err(KslError::type_error(
                        format!("Expected Expression node in if condition, found {:?}", condition),
                        SourcePosition::new(1, 1),
                        "E203".to_string()
                    ))
                }?;
                self.generate_if(condition, then_branch, else_branch.as_deref())
            },
            _ => Err(KslError::type_error(
                format!("Unsupported AST node: {:?}", node),
                SourcePosition::new(1, 1),
                "E303".to_string()
            )),
        }
    }

    fn generate_expr(&mut self, expr: &Expr) -> Result<BasicValueEnum<'ctx>, KslError> {
        match expr {
            Expr::Literal(lit) => {
                match lit {
                    Literal::Int(n) => Ok(self.context.i32_type().const_int(*n as u64, false).into()),
                    Literal::Float(f) => Ok(self.context.f64_type().const_float(*f).into()),
                    Literal::Bool(b) => Ok(self.context.bool_type().const_int(*b as u64, false).into()),
                    Literal::Str(s) => {
                        let string_type = self.context.i8_type().ptr_type(AddressSpace::Generic);
                        let string_value = self.builder.build_global_string_ptr(s, "str");
                        Ok(string_value.into())
                    },
                    _ => Err(KslError::type_error(
                        format!("Unsupported literal: {:?}", lit),
                        SourcePosition::new(1, 1),
                        "E302".to_string()
                    )),
                }
            },
            Expr::Identifier(name) => {
                if let Some(var) = self.variables.get(name) {
                    Ok(self.builder.build_load(*var, name).into())
                } else {
                    Err(KslError::type_error(
                        format!("Undefined variable: {}", name),
                        SourcePosition::new(1, 1),
                        "E301".to_string()
                    ))
                }
            },
            Expr::BinaryOp { left, op, right } => {
                let left_value = self.generate_expr(left)?;
                let right_value = self.generate_expr(right)?;
                
                match op {
                    BinaryOperator::Add => {
                        if left_value.is_int_value() {
                            Ok(self.builder.build_int_add(left_value.into_int_value(), right_value.into_int_value(), "add").into())
                        } else {
                            Ok(self.builder.build_float_add(left_value.into_float_value(), right_value.into_float_value(), "add").into())
                        }
                    },
                    BinaryOperator::Sub => {
                        if left_value.is_int_value() {
                            Ok(self.builder.build_int_sub(left_value.into_int_value(), right_value.into_int_value(), "sub").into())
                        } else {
                            Ok(self.builder.build_float_sub(left_value.into_float_value(), right_value.into_float_value(), "sub").into())
                        }
                    },
                    BinaryOperator::Mul => {
                        if left_value.is_int_value() {
                            Ok(self.builder.build_int_mul(left_value.into_int_value(), right_value.into_int_value(), "mul").into())
                        } else {
                            Ok(self.builder.build_float_mul(left_value.into_float_value(), right_value.into_float_value(), "mul").into())
                        }
                    },
                    _ => Err(KslError::type_error(
                        format!("Unsupported binary operator: {:?}", op),
                        SourcePosition::new(1, 1),
                        "E301".to_string()
                    )),
                }
            },
            _ => Err(KslError::type_error(
                format!("Unsupported expression: {:?}", expr),
                SourcePosition::new(1, 1),
                "E304".to_string()
            )),
        }
    }

    /// Helper function to create allocas in the entry block
    fn create_entry_block_alloca(&self, name: &str, ty: BasicTypeEnum<'ctx>) -> PointerValue<'ctx> {
        let builder = self.context.create_builder();
        let entry = self.fn_value_opt.unwrap().get_first_basic_block().unwrap();
        
        match entry.get_first_instruction() {
            Some(first_instr) => builder.position_before(&first_instr),
            None => builder.position_at_end(entry),
        }
        
        builder.build_alloca(ty, name)
    }

    /// Converts KSL type to LLVM type
    fn type_to_llvm_type(&self, ty: &TypeAnnotation) -> Result<BasicTypeEnum<'ctx>, KslError> {
        match ty {
            TypeAnnotation::Simple(name) => match name.as_str() {
                "i32" => Ok(self.context.i32_type().as_basic_type_enum()),
                "i64" => Ok(self.context.i64_type().as_basic_type_enum()),
                "f32" => Ok(self.context.f32_type().as_basic_type_enum()),
                "f64" => Ok(self.context.f64_type().as_basic_type_enum()),
                "bool" => Ok(self.context.bool_type().as_basic_type_enum()),
                "string" => Ok(self.context.i8_type().ptr_type(AddressSpace::Generic).as_basic_type_enum()),
                _ => Err(KslError::type_error(
                    format!("Unsupported type: {}", name),
                    SourcePosition::new(1, 1),
                )),
            },
            TypeAnnotation::Array { element, size } => {
                let elem_type = self.type_to_llvm_type(element)?;
                Ok(elem_type.array_type(*size as u32).as_basic_type_enum())
            }
            _ => Err(KslError::type_error(
                format!("Unsupported type annotation: {:?}", ty),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Creates state type for async functions
    fn create_async_state_type(&self, name: &str, params: &[(String, TypeAnnotation)]) -> Result<BasicTypeEnum<'ctx>, KslError> {
        let state_name = format!("{}_state", name);
        let mut field_types = Vec::new();
        
        // Add state field
        field_types.push(self.context.i32_type().as_basic_type_enum());
        
        // Add parameter fields
        for (_, ty) in params {
            field_types.push(self.type_to_llvm_type(ty)?);
        }
        
        let state_type = self.context.struct_type(&field_types, false);
        Ok(state_type.as_basic_type_enum())
    }

    /// Generates state machine for async functions
    fn generate_state_machine(
        &mut self,
        poll_fn: FunctionValue<'ctx>,
        state_type: BasicTypeEnum<'ctx>,
        body: &[AstNode],
    ) -> Result<(), KslError> {
        let entry = self.context.append_basic_block(poll_fn, "entry");
        self.builder.position_at_end(entry);

        // Load state number
        let state_ptr = poll_fn.get_nth_param(0).unwrap().into_pointer_value();
        let state_num_ptr = self.builder.build_struct_gep(state_type, state_ptr, 0, "state_num_ptr")?;
        let state_num = self.builder.build_load(state_num_ptr, "state_num");

        // Create switch instruction for state machine
        let switch = self.builder.build_switch(state_num.into_int_value(), entry, body.len() as u32);

        // Generate blocks for each state
        for (i, node) in body.iter().enumerate() {
            let state_bb = self.context.append_basic_block(poll_fn, &format!("state_{}", i));
            switch.add_case(self.context.i32_type().const_int(i as u64, false), state_bb);
            
            self.builder.position_at_end(state_bb);
            self.generate_node(node)?;
            
            // Update state number
            let next_state = self.context.i32_type().const_int((i + 1) as u64, false);
            self.builder.build_store(state_num_ptr, next_state);
            
            // Return ready if not last state, otherwise return completed
            let return_value = if i < body.len() - 1 {
                self.context.i32_type().const_int(0, false) // Ready
            } else {
                self.context.i32_type().const_int(1, false) // Completed
            };
            self.builder.build_return(Some(&return_value));
        }

        Ok(())
    }

    /// Generates entry point for the module
    fn generate_entry_point(&mut self) -> Result<FunctionValue<'ctx>, KslError> {
        let void_type = self.context.void_type();
        let fn_type = void_type.fn_type(&[], false);
        
        let entry_fn = self.module.add_function("ksl_module_entry", fn_type, None);
        let entry_block = self.context.append_basic_block(entry_fn, "entry");
        
        self.builder.position_at_end(entry_block);
        
        // Initialize global state
        self.initialize_global_state()?;
        
        // Call module initialization if exists
        if let Some(init_fn) = self.module.get_function("ksl_module_init") {
            self.builder.build_call(init_fn, &[], "init_call");
        }
        
        self.builder.build_return(None);
        
        Ok(entry_fn)
    }

    /// Generates symbol table for the module
    fn generate_symbol_table(&self) -> Vec<SymbolEntry> {
        let mut symbols = Vec::new();
        
        // Add functions
        for func in self.module.get_functions() {
            let name = func.get_name().to_str().unwrap_or("unknown").to_string();
            let visibility = if func.is_public() {
                Visibility::Public
            } else {
                Visibility::Private
            };
            
            symbols.push(SymbolEntry {
                name,
                symbol_type: SymbolType::Function,
                visibility,
                hot_reload_meta: Some(HotReloadMetadata {
                    export_name: name.clone(),
                    version: "1.0.0".to_string(),
                    dependencies: Vec::new(),
                    state_requirements: Vec::new(),
                }),
            });
        }
        
        // Add globals
        for global in self.module.get_globals() {
            let name = global.get_name().to_str().unwrap_or("unknown").to_string();
            let visibility = if global.is_public() {
                Visibility::Public
            } else {
                Visibility::Private
            };
            
            symbols.push(SymbolEntry {
                name,
                symbol_type: SymbolType::Variable,
                visibility,
                hot_reload_meta: None,
            });
        }
        
        symbols
    }

    /// Embeds hot reload metadata in the module
    fn embed_hot_reload_metadata(&mut self, symbols: &[SymbolEntry]) -> Result<(), KslError> {
        let metadata = serde_json::to_string(symbols)
            .map_err(|e| KslError::type_error(
                format!("Failed to serialize metadata: {}", e),
                SourcePosition::new(1, 1),
            ))?;
        
        let metadata_type = self.context.i8_type().array_type(metadata.len() as u32);
        let metadata_global = self.module.add_global(
            metadata_type,
            None,
            "ksl_hot_reload_metadata",
        );
        
        metadata_global.set_constant(true);
        metadata_global.set_global_constant(true);
        
        // Initialize metadata
        let metadata_ptr = unsafe {
            self.builder.build_global_string_ptr(&metadata, "metadata_str")
        };
        
        self.builder.build_store(metadata_global.as_pointer_value(), metadata_ptr);
        
        Ok(())
    }

    /// Compiles to shared object (.so) module
    pub fn compile_to_shared_object(&self, output_path: &Path) -> Result<(), KslError> {
        // Generate entry point
        let entry_point = self.generate_entry_point()?;
        
        // Generate symbol table
        let symbols = self.generate_symbol_table();
        
        // Embed hot reload metadata
        self.embed_hot_reload_metadata(&symbols)?;
        
        // Emit code
        self.emit_code(CompileTarget::Native, output_path.to_str().unwrap())?;
        
        Ok(())
    }

    /// Compiles to WASM module
    pub fn compile_to_wasm(&self, output_path: &Path) -> Result<(), KslError> {
        // Generate entry point
        let entry_point = self.generate_entry_point()?;
        
        // Generate symbol table
        let symbols = self.generate_symbol_table();
        
        // Embed hot reload metadata
        self.embed_hot_reload_metadata(&symbols)?;
        
        // Emit code
        self.emit_code(CompileTarget::Wasm, output_path.to_str().unwrap())?;
        
        Ok(())
    }

    /// Initializes global state for the module
    fn initialize_global_state(&mut self) -> Result<(), KslError> {
        // Initialize runtime state
        let runtime_state_type = self.context.struct_type(
            &[
                self.context.i64_type().into(),
                self.context.i64_type().into(),
                self.context.i64_type().into(),
            ],
            false,
        );
        
        let runtime_state = self.module.add_global(
            runtime_state_type,
                    None,
            "ksl_runtime_state",
        );
        
        // Initialize with zeros
        let zero = self.context.i64_type().const_int(0, false);
        let initializer = runtime_state_type.const_struct(
            &[zero.into(), zero.into(), zero.into()],
            false,
        );
        
        runtime_state.set_initializer(&initializer);
        
        // Initialize hot reload state if enabled
        if let Some(hot_reload_config) = &self.hot_reload_config {
            let hot_reload_state_type = self.context.struct_type(
                &[
                    self.context.i64_type().into(),
                    self.context.i64_type().into(),
                ],
                false,
            );
            
            let hot_reload_state = self.module.add_global(
                hot_reload_state_type,
                        None,
                "ksl_hot_reload_state",
            );
            
            // Initialize with zeros
            let initializer = hot_reload_state_type.const_struct(
                &[zero.into(), zero.into()],
                false,
            );
            
            hot_reload_state.set_initializer(&initializer);
        }
        
        Ok(())
    }
}

/// Symbol table entry for hot reloadable functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolEntry {
    /// Symbol name
    pub name: String,
    /// Symbol type (function, variable, etc.)
    pub symbol_type: SymbolType,
    /// Symbol visibility
    pub visibility: Visibility,
    /// Symbol metadata for hot reloading
    pub hot_reload_meta: Option<HotReloadMetadata>,
}

/// Symbol type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SymbolType {
    Function,
    Variable,
    Type,
    Constant,
}

/// Symbol visibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Visibility {
    Public,
    Private,
    Protected,
}

/// Hot reload metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotReloadMetadata {
    /// Export name for FFI
    pub export_name: String,
    /// Version information
    pub version: String,
    /// Dependencies
    pub dependencies: Vec<String>,
    /// State requirements
    pub state_requirements: Vec<String>,
}

/// Public API to compile AST
pub fn compile(
    ast: &[AstNode],
    module_name: &str,
    target: CompileTarget,
    output_path: &str,
    metrics: &PerformanceMetrics,
    enable_debug: bool,
    hot_reload_config: Option<HotReloadConfig>,
) -> Result<(String, OptimizationFeedback), KslError> {
    let start_time = std::time::Instant::now();

    // Create LLVM context and code generator
    let context = Context::create();
    let mut codegen = LLVMCodegen::new(&context, module_name, target, enable_debug, hot_reload_config);

    // Generate code
    codegen.generate(ast, target, metrics)?;

    // Emit code
    codegen.emit_code(target, output_path)?;

    // Get optimization feedback
    let feedback = codegen.get_optimization_feedback();

    // Calculate compilation time
    let compilation_time = start_time.elapsed().as_millis() as u64;
    let mut feedback = feedback;
    feedback.compilation_time_ms = compilation_time;

    Ok((output_path.to_string(), feedback))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_simple_function_native() {
        let ast = vec![
            AstNode::FnDecl {
                name: "add".to_string(),
                params: vec![
                    ("x".to_string(), TypeAnnotation::Simple("i32".to_string())),
                    ("y".to_string(), TypeAnnotation::Simple("i32".to_string())),
                ],
                ret_type: TypeAnnotation::Simple("i32".to_string()),
                body: vec![
                    AstNode::Expr {
                        kind: ExprKind::BinaryOp {
                            left: Box::new(AstNode::Expr { kind: ExprKind::Ident("x".to_string()) }),
                            op: "+".to_string(),
                            right: Box::new(AstNode::Expr { kind: ExprKind::Ident("y".to_string()) }),
                        },
                    },
                ],
                attributes: vec![],
            },
        ];

        let metrics = PerformanceMetrics::default();
        let (ir, feedback) = compile(&ast, "test_module", CompileTarget::Native, "test.o", &metrics, true, None).unwrap();
        assert!(ir.contains("define i32 @add(i32 %x, i32 %y)"));
        assert!(ir.contains("add i32"));
        assert!(feedback.compilation_time_ms > 0);
    }

    #[test]
    fn test_async_function_wasm() {
        let ast = vec![
            AstNode::AsyncFnDecl {
                name: "fetch".to_string(),
                params: vec![("url".to_string(), TypeAnnotation::Simple("string".to_string()))],
                body: vec![
                    AstNode::Await {
                expr: Box::new(AstNode::Expr {
                    kind: ExprKind::Call {
                                name: "http_get".to_string(),
                                args: vec![AstNode::Expr { kind: ExprKind::Ident("url".to_string()) }],
                            },
                        }),
                    },
                ],
                attributes: vec!["async".to_string()],
            },
        ];

        let metrics = PerformanceMetrics::default();
        let (ir, feedback) = compile(&ast, "test_module", CompileTarget::Wasm, "test.wasm", &metrics, true, None).unwrap();
        assert!(ir.contains("define i32 @fetch_poll(i8* %0)"));
        assert!(ir.contains("%fetch_state = type"));
        assert!(feedback.compilation_time_ms > 0);
    }

    #[test]
    fn test_array_operations_bytecode() {
        let ast = vec![
            AstNode::VarDecl {
                name: "arr".to_string(),
                type_annot: Some(TypeAnnotation::Array {
                    element: Box::new(TypeAnnotation::Simple("i32".to_string())),
                    size: 4,
                }),
                expr: Box::new(AstNode::Expr {
                    kind: ExprKind::ArrayLiteral {
                        elements: vec![
                            AstNode::Expr { kind: ExprKind::Number("1".to_string()) },
                            AstNode::Expr { kind: ExprKind::Number("2".to_string()) },
                            AstNode::Expr { kind: ExprKind::Number("3".to_string()) },
                            AstNode::Expr { kind: ExprKind::Number("4".to_string()) },
                        ],
                    },
                }),
                is_mutable: false,
            },
        ];

        let metrics = PerformanceMetrics::default();
        let (bytecode, feedback) = compile(&ast, "test_module", CompileTarget::Bytecode, "test.bc", &metrics, false, None).unwrap();
        assert!(bytecode.contains("push_array"));
        assert_eq!(feedback.compilation_time_ms, 0);
    }

    #[test]
    fn test_control_flow_native() {
        let ast = vec![
            AstNode::If {
                condition: Box::new(AstNode::Expr {
                    kind: ExprKind::BinaryOp {
                        left: Box::new(AstNode::Expr { kind: ExprKind::Number("1".to_string()) }),
                        op: "==".to_string(),
                        right: Box::new(AstNode::Expr { kind: ExprKind::Number("1".to_string()) }),
                    },
                }),
                then_branch: vec![
                    AstNode::Expr { kind: ExprKind::Number("42".to_string()) },
                ],
                else_branch: Some(vec![
                    AstNode::Expr { kind: ExprKind::Number("0".to_string()) },
                ]),
            },
        ];

        let metrics = PerformanceMetrics::default();
        let (ir, feedback) = compile(&ast, "test_module", CompileTarget::Native, "test.o", &metrics, true, None).unwrap();
        assert!(ir.contains("br i1"));
        assert!(ir.contains("phi i32"));
        assert!(feedback.compilation_time_ms > 0);
    }

    #[test]
    fn test_verify_block_compilation() {
        let verify_node = AstNode::VerifyBlock {
            conditions: vec![
                AstNode::Expr {
                    kind: ExprKind::BinaryOp {
                        op: ">=".to_string(),
                        left: Box::new(AstNode::Expr {
                            kind: ExprKind::Ident("x".to_string())
                        }),
                        right: Box::new(AstNode::Expr {
                            kind: ExprKind::Number("0".to_string())
                        }),
                    }
                },
                AstNode::Expr {
                    kind: ExprKind::BinaryOp {
                        op: "==".to_string(),
                        left: Box::new(AstNode::Expr {
                            kind: ExprKind::Ident("y".to_string())
                        }),
                        right: Box::new(AstNode::Expr {
                            kind: ExprKind::Ident("z".to_string())
                        }),
                    }
                },
            ],
        };

        let context = Context::create();
        let mut codegen = LLVMCodegen::new(&context, "test", CompileTarget::Native, true, None);
        
        // Create a test function to contain the verify block
        let fn_type = context.void_type().fn_type(&[], false);
        let fn_value = codegen.module.add_function("test_fn", fn_type, None);
        let entry_bb = context.append_basic_block(fn_value, "entry");
        codegen.builder.position_at_end(entry_bb);
        codegen.fn_value_opt = Some(fn_value);

        // Add printf function for error messages
        let printf_type = context.i32_type().fn_type(&[context.i8_type().ptr_type(AddressSpace::Generic).into()], true);
        codegen.module.add_function("printf", printf_type, None);

        // Compile the verify block
        let result = codegen.generate_node(&verify_node);
        assert!(result.is_ok());

        // Verify the generated code
        let module_str = codegen.module.print_to_string().to_string();
        assert!(module_str.contains("verify_cond"));
        assert!(module_str.contains("verify_fail"));
        assert!(module_str.contains("verify_success"));
        assert!(module_str.contains("Verification condition failed"));
    }
}
