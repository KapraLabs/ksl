// ksl_llvm.rs
// LLVM IR generation for KSL

use crate::ksl_ast::{AstNode, Expr, Literal, BinaryOperator, Type, Function};
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
    pub fn generate(&mut self, ast: &[AstNode]) -> Result<(), KslError> {
        debug!("Starting LLVM IR generation");
        
        // Add runtime support functions
        self.add_runtime_functions()?;

        // Generate IR for each top-level node
        for node in ast {
            self.generate_node(node)?;
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
            _ => Err(KslError::type_error(
                format!("Unsupported AST node: {:?}", node),
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
        left: &Box<Expr>,
        op: &BinaryOperator,
        right: &Box<Expr>,
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
        function: &Box<Expr>,
        args: &[Expr],
    ) -> Result<BasicValueEnum<'ctx>, KslError> {
        let fn_val = match &**function {
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
        base: &Box<Expr>,
        index: &Box<Expr>,
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
        elements: &[Expr],
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
}

/// Public API to convert AST to LLVM IR
pub fn ast_to_llvm(ast: &[AstNode], module_name: &str) -> Result<String, KslError> {
    debug!("Converting AST to LLVM IR");

    // Create LLVM context and code generator
    let context = Context::create();
    let mut codegen = LLVMCodegen::new(&context, module_name);

    // Generate LLVM IR
    codegen.generate(ast)?;

    // Get IR string
    let ir = codegen.module.print_to_string().to_string();
    debug!("Generated LLVM IR:\n{}", ir);

    Ok(ir)
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
} 