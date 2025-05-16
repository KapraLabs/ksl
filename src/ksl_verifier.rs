/// ksl_verifier.rs
/// Implements Z3-based formal verification for KSL functions, supporting async execution,
/// new type system features, and comprehensive verification rules.

use crate::ksl_parser::{AstNode, ExprKind, TypeAnnotation, Attribute};
use crate::ksl_types::{Type, TypeSystem, TypeContext};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_stdlib::StdLib;
use crate::ksl_stdlib_crypto::CryptoStdLib;
use crate::ksl_checker::{check_types, TypeCheckResult};
use crate::ksl_async::{AsyncRuntime, AsyncTask};
use z3::{ast::{Int, Bool, Array, Ast, FuncDecl}, Config, Context, Solver, Sort};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

/// Verification error (reuses KslError)
type VerError = KslError;

/// Enhanced verification attribute with async support
#[derive(Debug, PartialEq, Clone)]
pub struct VerifyAttribute {
    /// Postcondition expression
    pub postcondition: String,
    /// Whether async verification is required
    pub is_async: bool,
    /// Verification timeout in milliseconds
    pub timeout_ms: Option<u64>,
    /// Memory limit in bytes
    pub memory_limit: Option<u64>,
}

/// Enhanced verifier state with async support
pub struct Verifier<'a> {
    ast: &'a [AstNode],
    ctx: Context,
    solver: Solver<'a>,
    variables: HashMap<String, Int<'a>>,
    bool_variables: HashMap<String, Bool<'a>>,
    array_variables: HashMap<String, Array<'a>>,
    stdlib: StdLib,
    crypto_stdlib: CryptoStdLib,
    type_system: TypeSystem,
    async_runtime: Option<Arc<RwLock<AsyncRuntime>>>,
    errors: Vec<VerError>,
}

impl<'a> Verifier<'a> {
    /// Create a new verifier with the given AST
    pub fn new(ast: &'a [AstNode]) -> Self {
        let config = Config::new();
        let ctx = Context::new(&config);
        let solver = Solver::new(&ctx);
        Verifier {
            ast,
            ctx,
            solver,
            variables: HashMap::new(),
            bool_variables: HashMap::new(),
            array_variables: HashMap::new(),
            stdlib: StdLib::new(),
            crypto_stdlib: CryptoStdLib::new(),
            type_system: TypeSystem::new(),
            async_runtime: None,
            errors: Vec::new(),
        }
    }

    /// Create a new verifier with async support
    pub fn new_async(ast: &'a [AstNode], runtime: Arc<RwLock<AsyncRuntime>>) -> Self {
        let mut verifier = Self::new(ast);
        verifier.async_runtime = Some(runtime);
        verifier
    }

    /// Verify all functions with #[verify] attributes
    pub async fn verify(&mut self) -> Result<(), Vec<VerError>> {
        // First, run type checking
        let type_check_result = check_types(self.ast)?;
        
        for node in self.ast {
            match node {
                AstNode::FnDecl { name, params, return_type, body, attributes } |
                AstNode::AsyncFnDecl { name, params, return_type, body, attributes, doc } => {
                    // Check for #[verify] attribute
                    if let Some(attr) = attributes.iter().find(|a| a.name == "verify") {
                        let verify_attr = match self.parse_verify_attribute(attr) {
                            Ok(attr) => attr,
                            Err(err) => {
                                self.errors.push(err);
                                return Err(self.errors.clone());
                            }
                        };
                        if verify_attr.is_async {
                            if let Some(runtime) = &self.async_runtime {
                                self.verify_async_function(name, params, return_type, body, &verify_attr, runtime).await?;
                            } else {
                                self.errors.push(KslError::type_error(
                                    "Async verification requested but no async runtime provided".to_string(),
                                    SourcePosition::new(1, 1),
                                    "E001".to_string(),
                                ));
                                return Err(self.errors.clone());
                            }
                        } else {
                            self.verify_function(name, params, return_type, body, &verify_attr)?;
                        }
                    }
                }
                _ => {}
            }
        }

        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors.clone())
        }
    }

    /// Parse verification attribute
    fn parse_verify_attribute(&self, attr: &Attribute) -> Result<VerifyAttribute, VerError> {
        let mut verify_attr = VerifyAttribute {
            postcondition: String::new(),
            is_async: false,
            timeout_ms: None,
            memory_limit: None,
        };

        for (key, value) in &attr.params {
            match key.as_str() {
                "postcondition" => verify_attr.postcondition = value.clone(),
                "async" => verify_attr.is_async = value.parse().unwrap_or(false),
                "timeout_ms" => verify_attr.timeout_ms = value.parse().ok(),
                "memory_limit" => verify_attr.memory_limit = value.parse().ok(),
                _ => {
                    return Err(KslError::type_error(
                        format!("Unknown verification attribute parameter: {}", key),
                        SourcePosition::new(1, 1),
                        "E002".to_string(),
                    ));
                }
            }
        }

        if verify_attr.postcondition.is_empty() {
            return Err(KslError::type_error(
                "Missing postcondition in verify attribute".to_string(),
                SourcePosition::new(1, 1),
                "E003".to_string(),
            ));
        }

        Ok(verify_attr)
    }

    /// Verify an async function
    async fn verify_async_function(
        &mut self,
        name: &str,
        params: &[(String, TypeAnnotation)],
        return_type: &TypeAnnotation,
        body: &[AstNode],
        attr: &VerifyAttribute,
        runtime: &Arc<RwLock<AsyncRuntime>>,
    ) -> Result<(), VerError> {
        // Reset variables for new function
        self.variables.clear();
        self.bool_variables.clear();
        self.array_variables.clear();

        // Create Z3 variables for parameters with new type system support
        for (param_name, param_type) in params {
            let z3_var = self.create_z3_variable(param_name, param_type)?;
            match z3_var {
                Z3Variable::Int(var) => { self.variables.insert(param_name.clone(), var); }
                Z3Variable::Bool(var) => { self.bool_variables.insert(param_name.clone(), var); }
                Z3Variable::Array(var) => { self.array_variables.insert(param_name.clone(), var); }
            }
        }

        // Create Z3 variable for result with new type system support
        let result_type = self.type_system.resolve_type(return_type)?;
        let result_var = self.create_z3_variable("result", return_type)?;
        match result_var {
            Z3Variable::Int(var) => { self.variables.insert("result".to_string(), var); }
            Z3Variable::Bool(var) => { self.bool_variables.insert("result".to_string(), var); }
            Z3Variable::Array(var) => { self.array_variables.insert("result".to_string(), var); }
        }

        // Create async task for verification
        let task = AsyncTask::new(async move {
            // Translate body to Z3 constraints with timeout
            let timeout = attr.timeout_ms.unwrap_or(5000);
            let result = tokio::time::timeout(
                std::time::Duration::from_millis(timeout),
                self.translate_async_body(body, runtime),
            ).await;

            match result {
                Ok(Ok(_)) => {
                    // Parse and assert postcondition
                    let postcondition = self.parse_postcondition(&attr.postcondition)?;
                    self.solver.assert(&postcondition);

                    // Check satisfiability
                    match self.solver.check() {
                        z3::SatResult::Unsat => Ok(()), // Postcondition holds
                        z3::SatResult::Sat => {
                            let model = self.solver.get_model().unwrap();
                            Err(KslError::type_error(
                                format!("Async verification failed for {}: postcondition violated, model: {}", name, model),
                                SourcePosition::new(1, 1),
                                "E004".to_string(),
                            ))
                        }
                        z3::SatResult::Unknown => {
                            Err(KslError::type_error(
                                format!("Async verification inconclusive for {}", name),
                                SourcePosition::new(1, 1),
                                "E005".to_string(),
                            ))
                        }
                    }
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(KslError::type_error(
                    format!("Async verification timeout for {}", name),
                    SourcePosition::new(1, 1),
                    "E006".to_string(),
                )),
            }
        });

        // Run async verification task
        let mut runtime = runtime.write().await;
        runtime.spawn(task).await?;
        
        Ok(())
    }

    /// Create a Z3 variable for a given type
    fn create_z3_variable(&self, name: &str, ty: &TypeAnnotation) -> Result<Z3Variable<'a>, VerError> {
        let name_string = name.to_string();
        match ty {
            TypeAnnotation::Simple(t) => match t.as_str() {
                "u32" | "i32" | "usize" => Ok(Z3Variable::Int(Int::new_const(&self.ctx, &name_string))),
                "bool" => Ok(Z3Variable::Bool(Bool::new_const(&self.ctx, &name_string))),
                _ => Err(KslError::type_error(
                    format!("Unsupported type for verification: {}", t),
                    SourcePosition::new(1, 1),
                    "E004".to_string(),
                )),
            },
            TypeAnnotation::Array { element, size } => {
                let domain = Sort::int(&self.ctx);
                let range = match element.as_str() {
                    "u8" | "u32" | "i32" => Sort::int(&self.ctx),
                    "bool" => Sort::bool(&self.ctx),
                    _ => return Err(KslError::type_error(
                        format!("Unsupported array element type: {}", element),
                        SourcePosition::new(1, 1),
                        "E005".to_string(),
                    )),
                };
                Ok(Z3Variable::Array(Array::new_const(&self.ctx, &name_string, &domain, &range)))
            }
            _ => Err(KslError::type_error(
                format!("Unsupported type annotation: {:?}", ty),
                SourcePosition::new(1, 1),
                "E006".to_string(),
            )),
        }
    }

    /// Verify a synchronous function
    fn verify_function(
        &mut self,
        name: &str,
        params: &[(String, TypeAnnotation)],
        return_type: &TypeAnnotation,
        body: &[AstNode],
        attr: &VerifyAttribute,
    ) -> Result<(), VerError> {
        // Reset variables for new function
        self.variables.clear();
        self.bool_variables.clear();
        self.array_variables.clear();

        // Create Z3 variables for parameters with new type system support
        for (param_name, param_type) in params {
            let z3_var = self.create_z3_variable(param_name, param_type)?;
            match z3_var {
                Z3Variable::Int(var) => { self.variables.insert(param_name.clone(), var); }
                Z3Variable::Bool(var) => { self.bool_variables.insert(param_name.clone(), var); }
                Z3Variable::Array(var) => { self.array_variables.insert(param_name.clone(), var); }
            }
        }

        // Create Z3 variable for result with new type system support
        let result_type = self.type_system.resolve_type(return_type)?;
        let result_var = self.create_z3_variable("result", return_type)?;
        match result_var {
            Z3Variable::Int(var) => { self.variables.insert("result".to_string(), var); }
            Z3Variable::Bool(var) => { self.bool_variables.insert("result".to_string(), var); }
            Z3Variable::Array(var) => { self.array_variables.insert("result".to_string(), var); }
        }

        // Translate body to Z3 constraints
        for node in body {
            self.translate_node(node)?;
        }

        // Parse and assert postcondition
        let postcondition = self.parse_postcondition(&attr.postcondition)?;
        self.solver.assert(&postcondition);

        // Check satisfiability
        match self.solver.check() {
            z3::SatResult::Unsat => Ok(()), // Postcondition holds
            z3::SatResult::Sat => {
                let model = self.solver.get_model().unwrap();
                Err(KslError::type_error(
                    format!("Verification failed for {}: postcondition violated, model: {}", name, model),
                    SourcePosition::new(1, 1),
                    "E007".to_string(),
                ))
            }
            z3::SatResult::Unknown => {
                Err(KslError::type_error(
                    format!("Verification inconclusive for {}", name),
                    SourcePosition::new(1, 1),
                    "E008".to_string(),
                ))
            }
        }
    }

    /// Translate an AST node to Z3 constraints
    fn translate_node(&mut self, node: &AstNode) -> Result<(), VerError> {
        match node {
            AstNode::Expr { kind } => {
                match kind {
                    ExprKind::BinaryOp { op, left, right } => {
                        let left_z3 = self.translate_expr(left)?;
                        let right_z3 = self.translate_expr(right)?;
                        match op.as_str() {
                            "+" => {
                                let result = match (left_z3, right_z3) {
                                    (Z3Variable::Int(l), Z3Variable::Int(r)) => Z3Variable::Int(&l + &r),
                                    _ => return Err(KslError::type_error(
                                        "Addition requires integer operands".to_string(),
                                        SourcePosition::new(1, 1),
                                        "E007".to_string(),
                                    )),
                                };
                                self.add_constraint(result)?;
                            }
                            "-" => {
                                let result = match (left_z3, right_z3) {
                                    (Z3Variable::Int(l), Z3Variable::Int(r)) => Z3Variable::Int(&l - &r),
                                    _ => return Err(KslError::type_error(
                                        "Subtraction requires integer operands".to_string(),
                                        SourcePosition::new(1, 1),
                                        "E008".to_string(),
                                    )),
                                };
                                self.add_constraint(result)?;
                            }
                            "*" => {
                                let result = match (left_z3, right_z3) {
                                    (Z3Variable::Int(l), Z3Variable::Int(r)) => Z3Variable::Int(&l * &r),
                                    _ => return Err(KslError::type_error(
                                        "Multiplication requires integer operands".to_string(),
                                        SourcePosition::new(1, 1),
                                        "E009".to_string(),
                                    )),
                                };
                                self.add_constraint(result)?;
                            }
                            ">" | "<" | ">=" | "<=" | "==" | "!=" => {
                                let condition = self.create_comparison(op, left_z3, right_z3)?;
                                self.solver.assert(&condition);
                            }
                            _ => {
                                return Err(KslError::type_error(
                                    format!("Unsupported operator: {}", op),
                                    SourcePosition::new(1, 1),
                                    "E010".to_string(),
                                ));
                            }
                        }
                    }
                    ExprKind::Call { name, args } => {
                        // Handle standard library and crypto functions
                        let arg_types: Vec<Type> = args.iter()
                            .map(|arg| self.type_system.infer_type(arg))
                            .collect::<Result<_, _>>()?;
                        
                        let pos = SourcePosition::new(1, 1);
                        if let Some(func) = self.stdlib.get_function(name) {
                            let return_type = self.stdlib.validate_call(name, &arg_types, pos)?;
                            let z3_args = args.iter()
                                .map(|arg| self.translate_expr(arg))
                                .collect::<Result<Vec<_>, _>>()?;
                            let result = self.create_function_call(name, &z3_args, &return_type)?;
                            self.add_constraint(result)?;
                        } else if let Some(func) = self.crypto_stdlib.get_function(name) {
                            let return_type = self.crypto_stdlib.validate_call(name, &arg_types, pos)?;
                            let z3_args = args.iter()
                                .map(|arg| self.translate_expr(arg))
                                .collect::<Result<Vec<_>, _>>()?;
                            let result = self.create_function_call(name, &z3_args, &return_type)?;
                            self.add_constraint(result)?;
                        } else {
                            return Err(KslError::type_error(
                                format!("Undefined function: {}", name),
                                SourcePosition::new(1, 1),
                                "E011".to_string(),
                            ));
                        }
                    }
                    ExprKind::ArrayAccess { array, index } => {
                        let array_z3 = self.translate_expr(array)?;
                        let index_z3 = self.translate_expr(index)?;
                        match (array_z3, index_z3) {
                            (Z3Variable::Array(arr), Z3Variable::Int(idx)) => {
                                let result = arr.select(&idx);
                                self.add_constraint(Z3Variable::Int(result))?;
                            }
                            _ => {
                                return Err(KslError::type_error(
                                    "Array access requires array and integer index".to_string(),
                                    SourcePosition::new(1, 1),
                                    "E012".to_string(),
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }
            AstNode::If { condition, then_branch, else_branch } => {
                let cond_z3 = self.translate_bool_expr(condition)?;
                
                // Create a new scope for then branch
                let then_constraints = then_branch.iter()
                    .map(|node| self.translate_node(node))
                    .collect::<Result<Vec<_>, _>>()?;
                
                // Create a new scope for else branch
                if let Some(else_branch) = else_branch {
                    let else_constraints = else_branch.iter()
                        .map(|node| self.translate_node(node))
                        .collect::<Result<Vec<_>, _>>()?;
                    
                    // Add if-then-else constraint
                    self.solver.assert(&cond_z3.ite(&then_constraints.into_iter().collect(), &else_constraints.into_iter().collect()));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Create a comparison operation in Z3
    fn create_comparison(&self, op: &str, left: Z3Variable<'a>, right: Z3Variable<'a>) -> Result<Bool<'a>, VerError> {
        match (left, right) {
            (Z3Variable::Int(l), Z3Variable::Int(r)) => {
                Ok(match op {
                    ">" => l.gt(&r),
                    "<" => l.lt(&r),
                    ">=" => l.ge(&r),
                    "<=" => l.le(&r),
                    "==" => l._eq(&r),
                    "!=" => !l._eq(&r),
                    _ => return Err(KslError::type_error(
                        format!("Unsupported comparison operator: {}", op),
                        SourcePosition::new(1, 1),
                        "E012".to_string(),
                    )),
                })
            }
            (Z3Variable::Bool(l), Z3Variable::Bool(r)) => {
                Ok(match op {
                    "==" => l._eq(&r),
                    "!=" => !l._eq(&r),
                    _ => return Err(KslError::type_error(
                        format!("Unsupported boolean comparison: {}", op),
                        SourcePosition::new(1, 1),
                        "E013".to_string(),
                    )),
                })
            }
            _ => Err(KslError::type_error(
                "Comparison requires matching operand types".to_string(),
                SourcePosition::new(1, 1),
                "E014".to_string(),
            )),
        }
    }

    /// Create a function call in Z3
    fn create_function_call(
        &self,
        name: &str,
        args: &[Z3Variable<'a>],
        return_type: &Type,
    ) -> Result<Z3Variable<'a>, VerError> {
        match name {
            "sha3" => {
                // Model sha3 as an uninterpreted function
                let domain = Sort::int(&self.ctx);
                let range = Sort::int(&self.ctx);
                let func = FuncDecl::new(&self.ctx, name, &[domain], &range);
                let arg = match &args[0] {
                    Z3Variable::Int(i) => i,
                    _ => return Err(KslError::type_error(
                        "sha3 requires integer input".to_string(),
                        SourcePosition::new(1, 1),
                        "E015".to_string(),
                    )),
                };
                Ok(Z3Variable::Int(func.apply(&[arg]).as_int().unwrap()))
            }
            "bls_verify" | "verify_dilithium" => {
                // Model crypto verification as an uninterpreted boolean function
                let domain = Sort::int(&self.ctx);
                let range = Sort::bool(&self.ctx);
                let func = FuncDecl::new(&self.ctx, name, &[domain], &range);
                let arg = match &args[0] {
                    Z3Variable::Int(i) => i,
                    _ => return Err(KslError::type_error(
                        "Crypto verification requires integer input".to_string(),
                        SourcePosition::new(1, 1),
                        "E016".to_string(),
                    )),
                };
                Ok(Z3Variable::Bool(func.apply(&[arg]).as_bool().unwrap()))
            }
            _ => Err(KslError::type_error(
                format!("Unsupported function: {}", name),
                SourcePosition::new(1, 1),
                "E015".to_string(),
            )),
        }
    }

    /// Add a constraint to the solver
    fn add_constraint(&mut self, var: Z3Variable<'a>) -> Result<(), VerError> {
        match var {
            Z3Variable::Int(i) => self.solver.assert(&i.ge(&Int::from_i64(&self.ctx, 0))), // Non-negative constraint
            Z3Variable::Bool(b) => self.solver.assert(&b),
            Z3Variable::Array(a) => {
                // Add array bounds checking
                let size = Int::from_i64(&self.ctx, a.get_size() as i64);
                let idx = Int::new_const(&self.ctx, "idx");
                self.solver.assert(&idx.ge(&Int::from_i64(&self.ctx, 0)));
                self.solver.assert(&idx.lt(&size));
            }
        }
        Ok(())
    }

    /// Parse a postcondition expression
    fn parse_postcondition(&self, expr: &str) -> Result<Bool<'a>, VerError> {
        // Simple parser for basic boolean expressions
        if expr == "true" {
            Ok(Bool::from_bool(&self.ctx, true))
        } else if expr == "false" {
            Ok(Bool::from_bool(&self.ctx, false))
        } else if expr.contains("||") {
            let parts: Vec<&str> = expr.split("||").map(|s| s.trim()).collect();
            let conditions = parts.iter()
                .map(|p| self.parse_postcondition(p))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Bool::or(&self.ctx, &conditions))
        } else if expr.contains("&&") {
            let parts: Vec<&str> = expr.split("&&").map(|s| s.trim()).collect();
            let conditions = parts.iter()
                .map(|p| self.parse_postcondition(p))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Bool::and(&self.ctx, &conditions))
        } else if expr.contains("==") {
            let parts: Vec<&str> = expr.split("==").map(|s| s.trim()).collect();
            if parts.len() != 2 {
                return Err(KslError::type_error(
                    "Invalid equality expression".to_string(),
                    SourcePosition::new(1, 1),
                    "E017".to_string(),
                ));
            }
            let left = self.parse_expr(parts[0])?;
            let right = self.parse_expr(parts[1])?;
            match (left, right) {
                (Z3Variable::Int(l), Z3Variable::Int(r)) => Ok(l._eq(&r)),
                (Z3Variable::Bool(l), Z3Variable::Bool(r)) => Ok(l._eq(&r)),
                _ => Err(KslError::type_error(
                    "Type mismatch in equality".to_string(),
                    SourcePosition::new(1, 1),
                    "E016".to_string(),
                )),
            }
        } else {
            Err(KslError::type_error(
                format!("Unsupported postcondition: {}", expr),
                SourcePosition::new(1, 1),
                "E017".to_string(),
            ))
        }
    }

    /// Parse an expression in a postcondition
    fn parse_expr(&self, expr: &str) -> Result<Z3Variable<'a>, VerError> {
        let expr = expr.trim();
        if let Ok(num) = expr.parse::<i64>() {
            Ok(Z3Variable::Int(Int::from_i64(&self.ctx, num)))
        } else if expr == "true" {
            Ok(Z3Variable::Bool(Bool::from_bool(&self.ctx, true)))
        } else if expr == "false" {
            Ok(Z3Variable::Bool(Bool::from_bool(&self.ctx, false)))
        } else if let Some(var) = self.variables.get(expr) {
            Ok(Z3Variable::Int(var.clone()))
        } else if let Some(var) = self.bool_variables.get(expr) {
            Ok(Z3Variable::Bool(var.clone()))
        } else if let Some(var) = self.array_variables.get(expr) {
            Ok(Z3Variable::Array(var.clone()))
        } else {
            Err(KslError::type_error(
                format!("Unknown variable in expression: {}", expr),
                SourcePosition::new(1, 1),
                "E017".to_string(),
            ))
        }
    }
}

/// Z3 variable types
enum Z3Variable<'a> {
    Int(Int<'a>),
    Bool(Bool<'a>),
    Array(Array<'a>),
}

/// Public API to verify an AST with async support
pub async fn verify(ast: &[AstNode], enable_async: bool) -> Result<(), Vec<VerError>> {
    if enable_async {
        let runtime = Arc::new(RwLock::new(AsyncRuntime::new()));
        let mut verifier = Verifier::new_async(ast, runtime);
        verifier.verify().await
    } else {
        let mut verifier = Verifier::new(ast);
        verifier.verify().await
    }
}

// Assume ksl_parser.rs, ksl_types.rs, ksl_errors.rs, ksl_stdlib.rs, and ksl_stdlib_crypto.rs are in the same crate
mod ksl_parser {
    pub use super::{AstNode, ExprKind, TypeAnnotation, Attribute};
}

mod ksl_types {
    pub use super::Type;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

mod ksl_stdlib {
    pub use super::StdLib;
}

mod ksl_stdlib_crypto {
    pub use super::CryptoStdLib;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ksl_parser::{AstNode, ExprKind, TypeAnnotation};

    #[test]
    fn test_verify_simple_function() {
        let ast = vec![
            AstNode::FnDecl {
                name: "verify_compute".to_string(),
                params: vec![("x".to_string(), TypeAnnotation::Simple("u32".to_string()))],
                return_type: TypeAnnotation::Simple("u32".to_string()),
                body: vec![
                    AstNode::Expr {
                        kind: ExprKind::BinaryOp {
                            op: "+".to_string(),
                            left: Box::new(AstNode::Expr {
                                kind: ExprKind::Ident("x".to_string()),
                            }),
                            right: Box::new(AstNode::Expr {
                                kind: ExprKind::Number("1".to_string()),
                            }),
                        },
                    },
                ],
            },
        ];

        let result = verify(&ast, false);
        assert!(result.is_ok(), "Expected verification to succeed");
    }

    #[test]
    fn test_verify_failing_function() {
        let ast = vec![
            AstNode::FnDecl {
                name: "verify_compute".to_string(),
                params: vec![("x".to_string(), TypeAnnotation::Simple("u32".to_string()))],
                return_type: TypeAnnotation::Simple("u32".to_string()),
                body: vec![
                    AstNode::Expr {
                        kind: ExprKind::BinaryOp {
                            op: "-".to_string(),
                            left: Box::new(AstNode::Expr {
                                kind: ExprKind::Ident("x".to_string()),
                            }),
                            right: Box::new(AstNode::Expr {
                                kind: ExprKind::Number("1".to_string()),
                            }),
                        },
                    },
                ],
            },
        ];

        let result = verify(&ast, false);
        assert!(result.is_err(), "Expected verification to fail");
        let errors = result.unwrap_err();
        assert!(errors[0].to_string().contains("Verification failed"));
    }

    #[test]
    fn test_verify_bls_verify() {
        let ast = vec![
            AstNode::FnDecl {
                name: "bls_verify".to_string(),
                params: vec![
                    ("msg".to_string(), TypeAnnotation::Array { element: "u8".to_string(), size: 32 }),
                    ("pubkey".to_string(), TypeAnnotation::Array { element: "u8".to_string(), size: 48 }),
                    ("sig".to_string(), TypeAnnotation::Array { element: "u8".to_string(), size: 96 }),
                ],
                return_type: TypeAnnotation::Simple("bool".to_string()),
                body: vec![
                    AstNode::Expr {
                        kind: ExprKind::Call {
                            name: "bls_verify".to_string(),
                            args: vec![
                                AstNode::Expr { kind: ExprKind::Ident("msg".to_string()) },
                                AstNode::Expr { kind: ExprKind::Ident("pubkey".to_string()) },
                                AstNode::Expr { kind: ExprKind::Ident("sig".to_string()) },
                            ],
                        },
                    },
                ],
            },
        ];

        let result = verify(&ast, false);
        assert!(result.is_ok(), "Expected verification to succeed for bls_verify");
    }

    #[test]
    fn test_verify_dil_verify() {
        let ast = vec![
            AstNode::FnDecl {
                name: "dil_verify".to_string(),
                params: vec![
                    ("msg".to_string(), TypeAnnotation::Array { element: "u8".to_string(), size: 32 }),
                    ("pubkey".to_string(), TypeAnnotation::Array { element: "u8".to_string(), size: 1312 }),
                    ("sig".to_string(), TypeAnnotation::Array { element: "u8".to_string(), size: 2420 }),
                ],
                return_type: TypeAnnotation::Simple("bool".to_string()),
                body: vec![
                    AstNode::Expr {
                        kind: ExprKind::Call {
                            name: "dil_verify".to_string(),
                            args: vec![
                                AstNode::Expr { kind: ExprKind::Ident("msg".to_string()) },
                                AstNode::Expr { kind: ExprKind::Ident("pubkey".to_string()) },
                                AstNode::Expr { kind: ExprKind::Ident("sig".to_string()) },
                            ],
                        },
                    },
                ],
            },
        ];

        let result = verify(&ast, false);
        assert!(result.is_ok(), "Expected verification to succeed for dil_verify");
    }
}