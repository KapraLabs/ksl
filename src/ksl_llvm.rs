// ksl_llvm.rs
// LLVM IR generation for KSL

use crate::ksl_ast::{self, AstNode, Expr, Literal, BinaryOperator, Type, Function};
use crate::ksl_errors::{KslError, SourcePosition};
use inkwell::context::Context;
use inkwell::module::Module;
use inkwell::builder::Builder;
use inkwell::values::{BasicValue, BasicValueEnum, FunctionValue, PointerValue};
use inkwell::types::{BasicType, BasicTypeEnum};
use inkwell::AddressSpace;
use inkwell::OptimizationLevel;
use std::collections::HashMap;
use log::{debug, info, warn};
use crate::ksl_abi::{ABIGenerator, ContractABI};
use crate::ksl_version::{ContractVersion, VersionManager};
use crate::ksl_analyzer::PerformanceMetrics;

/// LLVM code generator for KSL
pub struct LLVMCodegen<'ctx> {
    context: &'ctx Context,
    module: Module<'ctx>,
    builder: Builder<'ctx>,
    fn_value_opt: Option<FunctionValue<'ctx>>,
    variables: HashMap<String, PointerValue<'ctx>>,
    basic_block_counter: usize,
}

impl<'ctx> LLVMCodegen<'ctx> {
    /// Creates a new LLVM code generator
    pub fn new(context: &'ctx Context, module_name: &str) -> Self {
        let module = context.create_module(module_name);
        let builder = context.create_builder();

        LLVMCodegen {
            context,
            module,
            builder,
            fn_value_opt: None,
            variables: HashMap::new(),
            basic_block_counter: 0,
        }
    }

    /// Generates LLVM IR for the entire AST
    pub fn generate(&mut self, ast: &[AstNode], metrics: Option<&PerformanceMetrics>) -> Result<(), KslError> {
        debug!("Starting LLVM IR generation");
        
        // Add runtime support functions
        self.add_runtime_functions()?;

        // Generate IR for each top-level node
        for node in ast {
            self.generate_node(node)?;
        }

        // Apply optimizations if metrics are provided
        if let Some(metrics) = metrics {
            self.apply_optimizations(metrics)?;
        }

        // Verify the generated module
        if self.module.verify().is_err() {
            return Err(KslError::type_error(
                "LLVM module verification failed".to_string(),
                SourcePosition::new(1, 1),
            ));
        }

        debug!("Completed LLVM IR generation");
        Ok(())
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
            AstNode::Literal(lit) => self.generate_literal(lit),
            AstNode::Identifier(name) => self.generate_identifier(name),
            AstNode::BinaryOp { left, op, right } => self.generate_binary_op(left, op, right),
            AstNode::Call { function, args } => self.generate_call(function, args),
            AstNode::Index { base, index } => self.generate_index(base, index),
            AstNode::ArrayLiteral { elements, element_type } => self.generate_array_literal(elements, element_type),
            AstNode::VerifyBlock { conditions } => {
                // Create blocks for assertion handling
                let parent = self.fn_value_opt.unwrap();
                let success_block = self.context.append_basic_block(parent, "assert_success");
                let fail_block = self.context.append_basic_block(parent, "assert_fail");
                let continue_block = self.context.append_basic_block(parent, "assert_continue");

                // Add error message string
                let error_msg = self.builder.build_global_string_ptr(
                    "Assertion failed",
                    "assert_error_msg"
                );

                // Generate code for each condition
                for condition in conditions {
                    let cond_value = self.generate_expr(condition)?;
                    
                    // Convert condition to boolean if needed
                    let bool_value = if cond_value.get_type().is_int_type() {
                        self.builder.build_int_compare(
                            inkwell::IntPredicate::NE,
                            cond_value.into_int_value(),
                            self.context.i32_type().const_int(0, false),
                            "assert_cond"
                        )
                    } else {
                        cond_value.into_int_value()
                    };

                    // Branch based on condition
                    self.builder.build_conditional_branch(bool_value, success_block, fail_block);
                    
                    // Generate failure block
                    self.builder.position_at_end(fail_block);
                    let printf_fn = self.module.get_function("printf").unwrap();
                    self.builder.build_call(
                        printf_fn,
                        &[error_msg.as_pointer_value().into()],
                        "print_error"
                    );
                    self.builder.build_return(None);

                    // Continue with success block
                    self.builder.position_at_end(success_block);
                }

                // Branch to continue block after all conditions pass
                self.builder.build_unconditional_branch(continue_block);
                self.builder.position_at_end(continue_block);

                Ok(self.context.void_type().const_void().as_basic_value_enum())
            },
            AstNode::Expression(expr) => self.generate_expr(expr),
            AstNode::Statement(stmt) => self.generate_stmt(stmt),
            AstNode::Function(func) => {
                self.generate_function_def(func)?;
                Ok(self.context.void_type().const_void().as_basic_value_enum())
            },
            _ => Err(KslError::type_error(
                format!("Unsupported AST node: {:?}", node),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Generate LLVM IR for an expression
    fn generate_expr(&mut self, expr: &Expr) -> Result<BasicValueEnum<'ctx>, KslError> {
        match expr {
            Expr::Literal(lit) => self.generate_literal(lit),
            Expr::Identifier(name) => self.generate_identifier(name),
            Expr::BinaryOp { left, op, right } => {
                let lhs = self.generate_expr(left)?;
                let rhs = self.generate_expr(right)?;

                match op {
                    BinaryOperator::Add => Ok(self.builder.build_int_add(
                        lhs.into_int_value(),
                        rhs.into_int_value(),
                        "add",
                    ).as_basic_value_enum()),
                    BinaryOperator::Sub => Ok(self.builder.build_int_sub(
                        lhs.into_int_value(),
                        rhs.into_int_value(),
                        "sub",
                    ).as_basic_value_enum()),
                    BinaryOperator::Mul => Ok(self.builder.build_int_mul(
                        lhs.into_int_value(),
                        rhs.into_int_value(),
                        "mul",
                    ).as_basic_value_enum()),
                    BinaryOperator::Div => Ok(self.builder.build_int_signed_div(
                        lhs.into_int_value(),
                        rhs.into_int_value(),
                        "div",
                    ).as_basic_value_enum()),
                    BinaryOperator::Eq => Ok(self.builder.build_int_compare(
                        inkwell::IntPredicate::EQ,
                        lhs.into_int_value(),
                        rhs.into_int_value(),
                        "eq",
                    ).as_basic_value_enum()),
                    _ => Err(KslError::type_error(
                        format!("Unsupported binary operator: {:?}", op),
                        SourcePosition::new(1, 1),
                    )),
                }
            },
            Expr::Call { function, args } => {
                let fn_val = match function.as_ref() {
                    Expr::Identifier(name) => self.module.get_function(name).ok_or_else(|| {
                        KslError::type_error(
                            format!("Undefined function: {}", name),
                            SourcePosition::new(1, 1),
                        )
                    })?,
                    _ => return Err(KslError::type_error(
                        "Function call target must be an identifier".to_string(),
                        SourcePosition::new(1, 1),
                    )),
                };

                let mut arg_values = Vec::new();
                for arg in args {
                    arg_values.push(self.generate_expr(arg)?);
                }

                Ok(self.builder.build_call(
                    fn_val,
                    &arg_values,
                    "call",
                ).try_as_basic_value().left().unwrap())
            },
            _ => Err(KslError::type_error(
                format!("Unsupported expression: {:?}", expr),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Generate LLVM IR for a statement
    fn generate_stmt(&mut self, stmt: &Stmt) -> Result<BasicValueEnum<'ctx>, KslError> {
        match stmt {
            Stmt::Let { name, typ, value } => {
                let val = self.generate_expr(value)?;
                let alloca = self.builder.build_alloca(val.get_type(), name);
                self.builder.build_store(alloca, val);
                self.variables.insert(name.clone(), alloca);
                Ok(self.context.void_type().const_void().as_basic_value_enum())
            },
            Stmt::Return(expr) => {
                let val = self.generate_expr(expr)?;
                self.builder.build_return(Some(&val));
                Ok(self.context.void_type().const_void().as_basic_value_enum())
            },
            _ => Err(KslError::type_error(
                format!("Unsupported statement: {:?}", stmt),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Generates LLVM IR for a literal value
    fn generate_literal(&self, lit: &Literal) -> Result<BasicValueEnum<'ctx>, KslError> {
        match lit {
            Literal::Int(n) => Ok(self.context.i64_type().const_int(*n as u64, false).as_basic_value_enum()),
            Literal::Float(f) => Ok(self.context.f64_type().const_float(*f).as_basic_value_enum()),
            Literal::Bool(b) => Ok(self.context.bool_type().const_int(*b as u64, false).as_basic_value_enum()),
            Literal::Str(s) => {
                let str_value = self.builder.build_global_string_ptr(s, "str");
                Ok(str_value.as_pointer_value().as_basic_value_enum())
            }
            Literal::Array(elements, element_type) => {
                let elem_type = self.type_to_llvm_type(element_type)?;
                let array_type = elem_type.array_type(elements.len() as u32);
                let alloca = self.builder.build_alloca(array_type, "array");

                for (i, elem) in elements.iter().enumerate() {
                    let elem_value = self.generate_literal(elem)?;
                    let elem_ptr = unsafe {
                        self.builder.build_gep(alloca, &[
                            self.context.i32_type().const_int(0, false),
                            self.context.i32_type().const_int(i as u64, false),
                        ], "elem_ptr")
                    };
                    self.builder.build_store(elem_ptr, elem_value);
                }

                Ok(alloca.as_basic_value_enum())
            }
        }
    }

    /// Generates LLVM IR for an identifier
    fn generate_identifier(&self, name: &str) -> Result<BasicValueEnum<'ctx>, KslError> {
        if let Some(ptr) = self.variables.get(name) {
            Ok(self.builder.build_load(*ptr, name))
        } else {
            Err(KslError::type_error(
                format!("Undefined variable: {}", name),
                SourcePosition::new(1, 1),
            ))
        }
    }

    /// Generates LLVM IR for a binary operation
    fn generate_binary_op(
        &mut self,
        left: &Box<AstNode>,
        op: &BinaryOperator,
        right: &Box<AstNode>,
    ) -> Result<BasicValueEnum<'ctx>, KslError> {
        let lhs = self.generate_node(left)?;
        let rhs = self.generate_node(right)?;

        match op {
            BinaryOperator::Add => Ok(self.builder.build_int_add(
                lhs.into_int_value(),
                rhs.into_int_value(),
                "add",
            ).as_basic_value_enum()),
            BinaryOperator::Sub => Ok(self.builder.build_int_sub(
                lhs.into_int_value(),
                rhs.into_int_value(),
                "sub",
            ).as_basic_value_enum()),
            BinaryOperator::Mul => Ok(self.builder.build_int_mul(
                lhs.into_int_value(),
                rhs.into_int_value(),
                "mul",
            ).as_basic_value_enum()),
            BinaryOperator::Div => Ok(self.builder.build_int_signed_div(
                lhs.into_int_value(),
                rhs.into_int_value(),
                "div",
            ).as_basic_value_enum()),
            BinaryOperator::Eq => Ok(self.builder.build_int_compare(
                inkwell::IntPredicate::EQ,
                lhs.into_int_value(),
                rhs.into_int_value(),
                "eq",
            ).as_basic_value_enum()),
            _ => Err(KslError::type_error(
                format!("Unsupported binary operator: {:?}", op),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Generates LLVM IR for a function call
    fn generate_call(
        &mut self,
        function: &Box<AstNode>,
        args: &[AstNode],
    ) -> Result<BasicValueEnum<'ctx>, KslError> {
        let fn_val = match function.as_ref() {
            AstNode::Identifier(name) => self.module.get_function(name).ok_or_else(|| {
                KslError::type_error(
                    format!("Undefined function: {}", name),
                    SourcePosition::new(1, 1),
                )
            })?,
            _ => return Err(KslError::type_error(
                "Function call target must be an identifier".to_string(),
                SourcePosition::new(1, 1),
            )),
        };

        let mut arg_values = Vec::new();
        for arg in args {
            arg_values.push(self.generate_node(arg)?);
        }

        Ok(self.builder.build_call(
            fn_val,
            &arg_values,
            "call",
        ).try_as_basic_value().left().unwrap())
    }

    /// Generates LLVM IR for array indexing
    fn generate_index(
        &mut self,
        base: &Box<AstNode>,
        index: &Box<AstNode>,
    ) -> Result<BasicValueEnum<'ctx>, KslError> {
        let base_val = self.generate_node(base)?;
        let index_val = self.generate_node(index)?;

        let elem_ptr = unsafe {
            self.builder.build_gep(
                base_val.into_pointer_value(),
                &[
                    self.context.i32_type().const_int(0, false),
                    index_val.into_int_value(),
                ],
                "elem_ptr",
            )
        };

        Ok(self.builder.build_load(elem_ptr, "elem"))
    }

    /// Generates LLVM IR for array literals
    fn generate_array_literal(
        &mut self,
        elements: &[AstNode],
        element_type: &Type,
    ) -> Result<BasicValueEnum<'ctx>, KslError> {
        let elem_type = self.type_to_llvm_type(element_type)?;
        let array_type = elem_type.array_type(elements.len() as u32);
        let alloca = self.builder.build_alloca(array_type, "array");

        for (i, elem) in elements.iter().enumerate() {
            let elem_value = self.generate_node(elem)?;
            let elem_ptr = unsafe {
                self.builder.build_gep(alloca, &[
                    self.context.i32_type().const_int(0, false),
                    self.context.i32_type().const_int(i as u64, false),
                ], "elem_ptr")
            };
            self.builder.build_store(elem_ptr, elem_value);
        }

        Ok(alloca.as_basic_value_enum())
    }

    /// Converts KSL type to LLVM type
    fn type_to_llvm_type(&self, ty: &Type) -> Result<BasicTypeEnum<'ctx>, KslError> {
        match ty {
            Type::Int => Ok(self.context.i64_type().as_basic_type_enum()),
            Type::Float => Ok(self.context.f64_type().as_basic_type_enum()),
            Type::Bool => Ok(self.context.bool_type().as_basic_type_enum()),
            Type::Str => Ok(self.context.i8_type().ptr_type(AddressSpace::Generic).as_basic_type_enum()),
            Type::Array(elem_type, size) => {
                let elem_type = self.type_to_llvm_type(elem_type)?;
                Ok(elem_type.array_type(*size).as_basic_type_enum())
            }
            _ => Err(KslError::type_error(
                format!("Unsupported type: {:?}", ty),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Generates LLVM IR for a function definition
    fn generate_function_def(&mut self, func: &Function) -> Result<(), KslError> {
        // Convert parameter types to LLVM types
        let param_types: Vec<BasicTypeEnum> = func.params.iter()
            .map(|param| self.type_to_llvm_type(&param.ty))
            .collect::<Result<Vec<_>, _>>()?;

        // Get return type
        let return_type = if let Some(ty) = &func.return_type {
            self.type_to_llvm_type(ty)?
        } else {
            self.context.void_type().as_basic_type_enum()
        };

        // Create function type
        let fn_type = return_type.fn_type(&param_types, false);

        // Create function
        let fn_value = self.module.add_function(&func.name, fn_type, None);
        self.fn_value_opt = Some(fn_value);

        // Create entry block
        let entry_block = self.context.append_basic_block(fn_value, "entry");
        self.builder.position_at_end(entry_block);

        // Allocate parameters
        for (i, param) in func.params.iter().enumerate() {
            let param_value = fn_value.get_nth_param(i as u32).unwrap();
            let alloca = self.builder.build_alloca(param_value.get_type(), &param.name);
            self.builder.build_store(alloca, param_value);
            self.variables.insert(param.name.clone(), alloca);
        }

        // Generate function body
        for node in &func.body {
            self.generate_node(node)?;
        }

        // Add return if not present
        if !self.builder.get_insert_block().unwrap().get_terminator().is_some() {
            if return_type.is_void_type() {
                self.builder.build_return(None);
            } else {
                return Err(KslError::type_error(
                    "Function must return a value".to_string(),
                    SourcePosition::new(1, 1),
                ));
            }
        }

        Ok(())
    }

    /// Generates contract ABI
    fn generate_contract_abi(&self, contract_name: &str) -> Result<ContractABI, KslError> {
        let mut abi_gen = ABIGenerator::new();
        let mut version_manager = VersionManager::new();

        // Get all public functions
        let mut public_fns = Vec::new();
        for func in self.module.get_functions() {
            if func.get_name().to_str().unwrap().starts_with("public_") {
                public_fns.push(func);
            }
        }

        // Generate ABI
        let abi = abi_gen.generate_contract_abi(&public_fns, contract_name)?;

        // Update version
        let mut version = ContractVersion::new(1, 0, 0);
        version.update_checksum(&self.module.print_to_string().as_bytes());
        version_manager.add_version(version.clone());

        Ok(abi)
    }

    /// Generates LLVM IR for an assertion
    fn generate_assert(&mut self, cond: BasicValueEnum<'ctx>) -> Result<(), KslError> {
        let parent = self.fn_value_opt.unwrap();
        let success_block = self.context.append_basic_block(parent, "assert_success");
        let fail_block = self.context.append_basic_block(parent, "assert_fail");
        let continue_block = self.context.append_basic_block(parent, "assert_continue");

        // Add error message string
        let error_msg = self.builder.build_global_string_ptr(
            "Assertion failed",
            "assert_error_msg"
        );

        // Convert condition to boolean if needed
        let bool_value = if cond.get_type().is_int_type() {
            self.builder.build_int_compare(
                inkwell::IntPredicate::NE,
                cond.into_int_value(),
                self.context.i32_type().const_int(0, false),
                "assert_cond"
            )
        } else {
            cond.into_int_value()
        };

        // Branch based on condition
        self.builder.build_conditional_branch(bool_value, success_block, fail_block);
        
        // Generate failure block
        self.builder.position_at_end(fail_block);
        let printf_fn = self.module.get_function("printf").unwrap();
        self.builder.build_call(
            printf_fn,
            &[error_msg.as_pointer_value().into()],
            "print_error"
        );
        self.builder.build_return(None);

        // Continue with success block
        self.builder.position_at_end(success_block);
        self.builder.build_unconditional_branch(continue_block);
        self.builder.position_at_end(continue_block);

        Ok(())
    }

    /// Apply optimizations based on performance metrics
    fn apply_optimizations(&mut self, metrics: &PerformanceMetrics) -> Result<(), KslError> {
        // This is a stub function that will be implemented when needed
        // It's here to make the code compatible with ksl_jit.rs
        Ok(())
    }

    /// Add aggressive inlining optimization
    pub fn add_aggressive_inlining(&mut self) -> Result<(), KslError> {
        // This is a stub that would be implemented with actual LLVM optimization passes
        debug!("Adding aggressive inlining optimization");
        // Actual implementation would use LLVM pass manager to add inlining passes
        Ok(())
    }

    /// Add loop unrolling optimization
    pub fn add_loop_unrolling(&mut self) -> Result<(), KslError> {
        // This is a stub that would be implemented with actual LLVM optimization passes
        debug!("Adding loop unrolling optimization");
        // Actual implementation would use LLVM pass manager to add loop unrolling passes
        Ok(())
    }

    /// Add loop unrolling with specific factor
    pub fn add_loop_unrolling_with_factor(&mut self, loop_id: usize, factor: usize) -> Result<(), KslError> {
        // This is a stub that would be implemented with actual LLVM optimization passes
        debug!("Adding loop unrolling for loop {} with factor {}", loop_id, factor);
        // Actual implementation would set metadata on the loop and use LLVM pass manager
        Ok(())
    }

    /// Add vectorization optimization
    pub fn add_vectorization(&mut self) -> Result<(), KslError> {
        // This is a stub that would be implemented with actual LLVM optimization passes
        debug!("Adding vectorization optimization");
        // Actual implementation would use LLVM pass manager to add vectorization passes
        Ok(())
    }

    /// Add function inlining for a specific function
    pub fn add_function_inlining(&mut self, function_name: &str) -> Result<(), KslError> {
        // This is a stub that would be implemented with actual LLVM optimization passes
        debug!("Adding function inlining for {}", function_name);
        // Actual implementation would set inlining attributes on the function
        Ok(())
    }
}

/// Public API to convert AST to LLVM IR with ABI generation
pub fn ast_to_llvm(ast: &[AstNode], module_name: &str) -> Result<(String, ContractABI), KslError> {
    let context = Context::create();
    let mut codegen = LLVMCodegen::new(&context, module_name);
    
    // Generate IR
    codegen.generate(ast, None)?;

    // Generate ABI
    let abi = codegen.generate_contract_abi(module_name)?;

    Ok((codegen.module.print_to_string(), abi))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_simple_arithmetic() {
        let ast = vec![
            AstNode::BinaryOp {
                left: Box::new(AstNode::Literal(Literal::Int(1))),
                op: BinaryOperator::Add,
                right: Box::new(AstNode::Literal(Literal::Int(2))),
            },
        ];

        let ir = ast_to_llvm(&ast, "test_module").unwrap();
        assert!(ir.contains("add i64"));
    }

    #[test]
    fn test_array_operations() {
        let ast = vec![
            AstNode::ArrayLiteral {
                elements: vec![
                    Expr::Literal(Literal::Int(1)),
                    Expr::Literal(Literal::Int(2)),
                    Expr::Literal(Literal::Int(3)),
                ],
                element_type: Type::Int,
            },
        ];

        let ir = ast_to_llvm(&ast, "test_module").unwrap();
        assert!(ir.contains("[3 x i64]"));
        assert!(ir.contains("alloca"));
    }

    #[test]
    fn test_function_call() {
        let ast = vec![
            AstNode::Call {
                function: Box::new(Expr::Identifier("print".to_string())),
                args: vec![
                    Expr::Literal(Literal::Str("Hello, World!".to_string())),
                ],
            },
        ];

        let ir = ast_to_llvm(&ast, "test_module").unwrap();
        assert!(ir.contains("@print"));
        assert!(ir.contains("Hello, World!"));
    }

    #[test]
    fn test_array_indexing() {
        let ast = vec![
            AstNode::Index {
                base: Box::new(Expr::Identifier("arr".to_string())),
                index: Box::new(Expr::Literal(Literal::Int(0))),
            },
        ];

        let ir = ast_to_llvm(&ast, "test_module").unwrap();
        assert!(ir.contains("getelementptr"));
    }

    #[test]
    fn test_function_definition() {
        let context = Context::create();
        let mut codegen = LLVMCodegen::new(&context, "test");

        let func = Function {
            name: "add".to_string(),
            params: vec![
                Parameter {
                    name: "a".to_string(),
                    ty: Type::Primitive("i64".to_string()),
                },
                Parameter {
                    name: "b".to_string(),
                    ty: Type::Primitive("i64".to_string()),
                },
            ],
            return_type: Some(Type::Primitive("i64".to_string())),
            is_public: true,
            body: vec![
                AstNode::BinaryOp {
                    left: Box::new(Expr::Identifier("a".to_string())),
                    op: BinaryOperator::Add,
                    right: Box::new(Expr::Identifier("b".to_string())),
                },
            ],
        };

        codegen.generate_function_def(&func).unwrap();
        let ir = codegen.module.print_to_string();
        assert!(ir.contains("define i64 @add(i64 %a, i64 %b)"));
    }

    #[test]
    fn test_contract_abi_generation() {
        let context = Context::create();
        let mut codegen = LLVMCodegen::new(&context, "MyToken");

        let func = Function {
            name: "transfer".to_string(),
            params: vec![
                Parameter {
                    name: "to".to_string(),
                    ty: Type::Primitive("address".to_string()),
                },
                Parameter {
                    name: "amount".to_string(),
                    ty: Type::Primitive("u64".to_string()),
                },
            ],
            return_type: Some(Type::Primitive("bool".to_string())),
            is_public: true,
            body: vec![],
        };

        codegen.generate_function_def(&func).unwrap();
        let abi = codegen.generate_contract_abi("MyToken").unwrap();

        assert_eq!(abi.name, "MyToken");
        assert_eq!(abi.methods.len(), 1);
        assert_eq!(abi.methods[0].name, "transfer");
    }
} 