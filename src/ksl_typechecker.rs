/// Typechecker module for KSL to validate program semantics.
/// This is a stub implementation to be expanded later.
pub mod ksl_typechecker {
    use crate::ksl_ast::{AstNode, Expr, Function, Literal, Module, Stmt};
    use crate::ksl_errors::{KslError, SourcePosition};
    use crate::ksl_types::{Type, TypeConstraint, TypeSystem};
    use std::collections::HashMap;

    /// Type environment for the type checker
    #[derive(Debug, Clone)]
    pub struct TypeEnv {
        /// Variable types
        variables: HashMap<String, Type>,
        /// Function signatures
        functions: HashMap<String, FunctionType>,
        /// Current return type (if inside a function)
        current_return_type: Option<Type>,
        /// Type constraints
        constraints: Vec<TypeConstraint>,
    }

    /// Function type representation
    #[derive(Debug, Clone)]
    pub struct FunctionType {
        /// Parameter types
        pub params: Vec<Type>,
        /// Return type
        pub return_type: Type,
        /// Is the function public?
        pub is_public: bool,
    }

    impl TypeEnv {
        /// Creates a new type environment
        pub fn new() -> Self {
            TypeEnv {
                variables: HashMap::new(),
                functions: HashMap::new(),
                current_return_type: None,
                constraints: Vec::new(),
            }
        }

        /// Adds a variable to the type environment
        pub fn add_variable(&mut self, name: &str, typ: Type) -> Result<(), KslError> {
            if self.variables.contains_key(name) {
                return Err(KslError::type_error(
                    format!("Variable '{}' already defined", name),
                    SourcePosition::new(0, 0),
                    "E101".to_string(),
                ));
            }
            
            self.variables.insert(name.to_string(), typ);
            Ok(())
        }

        /// Gets a variable type from the environment
        pub fn get_variable(&self, name: &str) -> Option<&Type> {
            self.variables.get(name)
        }

        /// Adds a function to the type environment
        pub fn add_function(&mut self, name: &str, func_type: FunctionType) -> Result<(), KslError> {
            if self.functions.contains_key(name) {
                return Err(KslError::type_error(
                    format!("Function '{}' already defined", name),
                    SourcePosition::new(0, 0),
                    "E102".to_string(),
                ));
            }
            
            self.functions.insert(name.to_string(), func_type);
            Ok(())
        }

        /// Gets a function type from the environment
        pub fn get_function(&self, name: &str) -> Option<&FunctionType> {
            self.functions.get(name)
        }

        /// Adds a type constraint
        pub fn add_constraint(&mut self, constraint: TypeConstraint) {
            self.constraints.push(constraint);
        }

        /// Sets the current return type
        pub fn set_return_type(&mut self, return_type: Type) {
            self.current_return_type = Some(return_type);
        }

        /// Gets the current return type
        pub fn get_return_type(&self) -> Option<&Type> {
            self.current_return_type.as_ref()
        }
    }

    /// Type checks an entire AST
    pub fn check_program(program: &[AstNode]) -> Result<TypeEnv, KslError> {
        let mut env = TypeEnv::new();
        
        // First pass: collect all function signatures
        for node in program {
            if let AstNode::Function(func) = node {
                check_function_signature(&mut env, func)?;
            }
        }
        
        // Second pass: type check all function bodies
        for node in program {
            match node {
                AstNode::Function(func) => check_function(&mut env, func)?,
                AstNode::Module(module) => check_module(&mut env, module)?,
                _ => {}
            }
        }
        
        Ok(env)
    }

    /// Type checks a function signature
    fn check_function_signature(env: &mut TypeEnv, func: &Function) -> Result<(), KslError> {
        let param_types: Vec<Type> = func.params.iter()
            .map(|param| param.ty.clone())
            .collect();
        
        let return_type = func.return_type.clone().unwrap_or(Type::Void);
        
        let function_type = FunctionType {
            params: param_types,
            return_type,
            is_public: func.is_public,
        };
        
        env.add_function(&func.name, function_type)
    }

    /// Type checks a function
    fn check_function(env: &mut TypeEnv, func: &Function) -> Result<(), KslError> {
        let mut function_env = env.clone();
        
        // Set the return type for the function environment
        if let Some(return_type) = &func.return_type {
            function_env.set_return_type(return_type.clone());
        } else {
            function_env.set_return_type(Type::Void);
        }
        
        // Add parameters to the environment
        for param in &func.params {
            function_env.add_variable(&param.name, param.ty.clone())?;
        }
        
        // Check the function body
        for stmt in &func.body {
            check_statement(&mut function_env, stmt)?;
        }
        
        Ok(())
    }

    /// Type checks a module
    fn check_module(env: &mut TypeEnv, module: &Module) -> Result<(), KslError> {
        // First pass: collect all function signatures in the module
        for func in &module.functions {
            check_function_signature(env, func)?;
        }
        
        // Second pass: type check all function bodies
        for func in &module.functions {
            check_function(env, func)?;
        }
        
        Ok(())
    }

    /// Type checks a statement
    fn check_statement(env: &mut TypeEnv, stmt: &Stmt) -> Result<(), KslError> {
        match stmt {
            Stmt::Let { name, typ, value } => {
                let value_type = check_expression(env, value)?;
                
                if let Some(explicit_type) = typ {
                    // Check that the value type matches the explicit type
                    if !type_matches(explicit_type, &value_type) {
                        return Err(KslError::type_error(
                            format!("Type mismatch: expected {:?}, got {:?}", explicit_type, value_type),
                            SourcePosition::new(0, 0),
                            "E103".to_string(),
                        ));
                    }
                    
                    env.add_variable(name, explicit_type.clone())?;
                } else {
                    // Infer the type from the value
                    env.add_variable(name, value_type)?;
                }
                
                Ok(())
            }
            
            Stmt::Assign { target, value } => {
                // TODO: Implement assignment checking
                Ok(())
            }
            
            Stmt::ExprStmt(expr) => {
                check_expression(env, expr)?;
                Ok(())
            }
            
            Stmt::Return(expr) => {
                let expr_type = check_expression(env, expr)?;
                
                if let Some(return_type) = env.get_return_type() {
                    if !type_matches(return_type, &expr_type) {
                        return Err(KslError::type_error(
                            format!("Return type mismatch: expected {:?}, got {:?}", return_type, expr_type),
                            SourcePosition::new(0, 0),
                            "E104".to_string(),
                        ));
                    }
                }
                
                Ok(())
            }
            
            Stmt::If { condition, then_branch, else_branch } => {
                let cond_type = check_expression(env, condition)?;
                
                // Ensure the condition is a boolean
                if !matches!(cond_type, Type::Bool) {
                    return Err(KslError::type_error(
                        format!("Condition must be a boolean, got {:?}", cond_type),
                        SourcePosition::new(0, 0),
                        "E105".to_string(),
                    ));
                }
                
                // Check the then branch
                for stmt in then_branch {
                    check_statement(env, stmt)?;
                }
                
                // Check the else branch if it exists
                if let Some(else_stmts) = else_branch {
                    for stmt in else_stmts {
                        check_statement(env, stmt)?;
                    }
                }
                
                Ok(())
            }
            
            Stmt::While { condition, body } => {
                let cond_type = check_expression(env, condition)?;
                
                // Ensure the condition is a boolean
                if !matches!(cond_type, Type::Bool) {
                    return Err(KslError::type_error(
                        format!("Condition must be a boolean, got {:?}", cond_type),
                        SourcePosition::new(0, 0),
                        "E106".to_string(),
                    ));
                }
                
                // Check the body
                for stmt in body {
                    check_statement(env, stmt)?;
                }
                
                Ok(())
            }
            
            Stmt::For { iterator, iterable, body } => {
                // TODO: Implement for loop checking
                Ok(())
            }
            
            Stmt::VerifyBlock { conditions } => {
                // Check each condition
                for expr in conditions {
                    let cond_type = check_expression(env, expr)?;
                    
                    // Ensure the condition is a boolean
                    if !matches!(cond_type, Type::Bool) {
                        return Err(KslError::type_error(
                            format!("Verification condition must be a boolean, got {:?}", cond_type),
                            SourcePosition::new(0, 0),
                            "E107".to_string(),
                        ));
                    }
                }
                
                Ok(())
            }
        }
    }

    /// Type checks an expression
    fn check_expression(env: &TypeEnv, expr: &Expr) -> Result<Type, KslError> {
        match expr {
            Expr::Literal(lit) => Ok(check_literal(lit)),
            
            Expr::Identifier(name) => {
                if let Some(typ) = env.get_variable(name) {
                    Ok(typ.clone())
                } else {
                    Err(KslError::type_error(
                        format!("Undefined variable: {}", name),
                        SourcePosition::new(0, 0),
                        "E108".to_string(),
                    ))
                }
            }
            
            Expr::BinaryOp { left, op, right } => {
                let left_type = check_expression(env, left)?;
                let right_type = check_expression(env, right)?;
                
                // TODO: Implement binary operator type checking
                match op {
                    // Add additional type checking for operators
                    _ => Ok(left_type)
                }
            }
            
            // Implement other expression types...
            _ => Err(KslError::type_error(
                format!("Type checking not implemented for expression: {:?}", expr),
                SourcePosition::new(0, 0),
                "E109".to_string(),
            )),
        }
    }

    /// Gets the type of a literal
    fn check_literal(lit: &Literal) -> Type {
        match lit {
            Literal::Int(_) => Type::I32,
            Literal::Float(_) => Type::F64,
            Literal::Bool(_) => Type::Bool,
            Literal::Str(_) => Type::String,
            Literal::Array(elements, _) => {
                if let Some(first) = elements.first() {
                    let element_type = check_literal(first);
                    Type::Array(Box::new(element_type), elements.len())
                } else {
                    // Default to void for empty arrays
                    Type::Array(Box::new(Type::Void), 0)
                }
            }
        }
    }

    /// Checks if two types match
    fn type_matches(expected: &Type, actual: &Type) -> bool {
        match (expected, actual) {
            (Type::I32, Type::I32) => true,
            (Type::F64, Type::F64) => true,
            (Type::Bool, Type::Bool) => true,
            (Type::String, Type::String) => true,
            (Type::Array(a, size_a), Type::Array(b, size_b)) => 
                type_matches(a, b) && size_a == size_b,
            // Add more type matching rules as needed
            _ => false,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        
        #[test]
        fn test_simple_let_statement() {
            // TODO: Add tests for the type checker
        }
    }
} 