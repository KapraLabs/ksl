// ksl_verifier.rs
// Implements Z3-based formal verification for KSL functions.

use crate::ksl_parser::{AstNode, ExprKind, TypeAnnotation};
use crate::ksl_types::Type;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_stdlib::StdLib;
use crate::ksl_stdlib_crypto::CryptoStdLib;
use z3::{ast::{Int, Bool}, Config, Context, Solver, ast::Ast};
use std::collections::HashMap;

// Verification error (reuses KslError)
type VerError = KslError;

// Attribute for verification
#[derive(Debug, PartialEq, Clone)]
struct VerifyAttribute {
    postcondition: String, // e.g., "result == true || result == false"
}

// Verifier state
pub struct Verifier<'a> {
    ast: &'a [AstNode],
    ctx: Context,
    solver: Solver<'a>,
    variables: HashMap<String, Int<'a>>, // Maps variable names to Z3 variables
    bool_variables: HashMap<String, Bool<'a>>, // Maps boolean variables (e.g., for bls_verify)
    stdlib: StdLib,
    crypto_stdlib: CryptoStdLib,
    errors: Vec<VerError>,
}

impl<'a> Verifier<'a> {
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
            stdlib: StdLib::new(),
            crypto_stdlib: CryptoStdLib::new(),
            errors: Vec::new(),
        }
    }

    // Verify all functions with #[verify] attributes
    pub fn verify(&mut self) -> Result<(), Vec<VerError>> {
        for node in self.ast {
            if let AstNode::FnDecl { name, params, return_type, body } = node {
                // Check for #[verify] attribute
                // Placeholder: assume functions named "bls_verify" or "dil_verify" have verify attribute
                if name == "bls_verify" || name == "dil_verify" {
                    let attr = VerifyAttribute {
                        postcondition: "result == true || result == false".to_string(),
                    };
                    self.verify_function(name, params, return_type, body, &attr)?;
                }
            }
        }
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors.clone())
        }
    }

    // Verify a single function
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

        // Create Z3 variables for parameters
        for (param_name, param_type) in params {
            match param_type {
                TypeAnnotation::Simple(t) if t == "u32" => {
                    let z3_var = Int::new_const(&self.ctx, param_name);
                    self.variables.insert(param_name.clone(), z3_var);
                }
                TypeAnnotation::Array { element, size } if element == "u8" => {
                    // Simplified: treat array as uninterpreted for now
                    let z3_var = Int::new_const(&self.ctx, param_name);
                    self.variables.insert(param_name.clone(), z3_var);
                }
                _ => {
                    self.errors.push(KslError::type_error(
                        format!("Unsupported parameter type: {:?}", param_type),
                        SourcePosition::new(1, 1), // Simplified
                    ));
                    return Err(self.errors.last().unwrap().clone());
                }
            }
        }

        // Create Z3 variable for result
        let result_type = TypeSystem::parse_type_annotation(return_type, 0).unwrap_or(Type::Void);
        let result_var = match result_type {
            Type::U32 => Int::new_const(&self.ctx, "result"),
            Type::Bool => Bool::new_const(&self.ctx, "result"),
            _ => {
                self.errors.push(KslError::type_error(
                    format!("Unsupported return type: {:?}", return_type),
                    SourcePosition::new(1, 1),
                ));
                return Err(self.errors.last().unwrap().clone());
            }
        };
        if result_type == Type::Bool {
            self.bool_variables.insert("result".to_string(), result_var.clone());
        } else {
            self.variables.insert("result".to_string(), result_var.clone());
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
                self.errors.push(KslError::type_error(
                    format!("Verification failed for {}: postcondition violated, model: {}", name, model),
                    SourcePosition::new(1, 1), // Simplified
                ));
                Err(self.errors.last().unwrap().clone())
            }
            z3::SatResult::Unknown => {
                self.errors.push(KslError::type_error(
                    format!("Verification inconclusive for {}", name),
                    SourcePosition::new(1, 1), // Simplified
                ));
                Err(self.errors.last().unwrap().clone())
            }
        }
    }

    // Parse postcondition (simplified: handles "result == true || result == false")
    fn parse_postcondition(&self, post: &str) -> Result<Bool<'a>, VerError> {
        if post == "result == true || result == false" {
            let result_var = self.bool_variables.get("result").ok_or_else(|| KslError::type_error(
                "Result variable not found".to_string(),
                SourcePosition::new(1, 1),
            ))?;
            let true_val = Bool::from_bool(&self.ctx, true);
            let false_val = Bool::from_bool(&self.ctx, false);
            Ok(Bool::or(&self.ctx, &[&result_var._eq(&true_val), &result_var._eq(&false_val)]))
        } else {
            Err(KslError::type_error(
                format!("Unsupported postcondition: {}", post),
                SourcePosition::new(1, 1),
            ))
        }
    }

    // Translate AST node to Z3 constraints
    fn translate_node(&mut self, node: &AstNode) -> Result<(), VerError> {
        match node {
            AstNode::VarDecl { name, expr, .. } => {
                let z3_expr = self.translate_expr(expr)?;
                let z3_var = Int::new_const(&self.ctx, name);
                self.variables.insert(name.clone(), z3_var);
                self.solver.assert(&z3_var._eq(&z3_expr));
                Ok(())
            }
            AstNode::Expr { kind } => {
                let z3_expr = self.translate_expr(&AstNode::Expr { kind: kind.clone() })?;
                self.solver.assert(&z3_expr._eq(&Int::from_i64(&self.ctx, 0))); // Simplified
                Ok(())
            }
            AstNode::If { condition, then_branch, else_branch } => {
                let cond = self.translate_bool_expr(condition)?;
                let then_solver = Solver::new(&self.ctx);
                for node in then_branch {
                    self.translate_node(node)?;
                }
                if let Some(else_nodes) = else_branch {
                    let else_solver = Solver::new(&self.ctx);
                    for node in else_nodes {
                        self.translate_node(node)?;
                    }
                    // Simplified: assert condition implies then or else
                    if !then_solver.get_assertions().is_empty() {
                        self.solver.assert(&cond.implies(&then_solver.get_assertions()[0]));
                    }
                    if !else_solver.get_assertions().is_empty() {
                        self.solver.assert(&cond.not().implies(&else_solver.get_assertions()[0]));
                    }
                }
                Ok(())
            }
            _ => {
                self.errors.push(KslError::type_error(
                    "Unsupported node in verification".to_string(),
                    SourcePosition::new(1, 1), // Simplified
                ));
                Err(self.errors.last().unwrap().clone())
            }
        }
    }

    // Translate expression to Z3 AST (for integer expressions)
    fn translate_expr(&self, expr: &AstNode) -> Result<Int<'a>, VerError> {
        match expr {
            AstNode::Expr { kind } => match kind {
                ExprKind::Number(num) => {
                    let value = num.parse::<i64>().map_err(|_| KslError::type_error(
                        "Invalid number".to_string(),
                        SourcePosition::new(1, 1),
                    ))?;
                    Ok(Int::from_i64(&self.ctx, value))
                }
                ExprKind::String(_) => {
                    // Simplified: treat string as uninterpreted integer
                    Ok(Int::new_const(&self.ctx, "string_placeholder"))
                }
                ExprKind::Ident(name) => {
                    self.variables.get(name).cloned().ok_or_else(|| KslError::type_error(
                        format!("Undefined variable: {}", name),
                        SourcePosition::new(1, 1),
                    ))
                }
                ExprKind::BinaryOp { op, left, right } => {
                    let left_z3 = self.translate_expr(left)?;
                    let right_z3 = self.translate_expr(right)?;
                    match op.as_str() {
                        "+" => Ok(&left_z3 + &right_z3),
                        "-" => Ok(&left_z3 - &right_z3),
                        "*" => Ok(&left_z3 * &right_z3),
                        ">" => Ok(Int::from_bool(&self.ctx, &left_z3.gt(&right_z3))),
                        "==" => Ok(Int::from_bool(&self.ctx, &left_z3._eq(&right_z3))),
                        _ => Err(KslError::type_error(
                            format!("Unsupported operator: {}", op),
                            SourcePosition::new(1, 1),
                        )),
                    }
                }
                ExprKind::Call { name, args } => {
                    // Handle standard library and crypto functions
                    let arg_types: Vec<Type> = args.iter()
                        .map(|arg| TypeSystem::infer_type(arg, &TypeContext::new(), 0).unwrap_or(Type::Void))
                        .collect();
                    let pos = SourcePosition::new(1, 1);
                    if self.stdlib.get_function(name).is_some() || self.crypto_stdlib.get_function(name).is_some() {
                        // Simplified: treat as uninterpreted function returning appropriate type
                        let return_type = if let Ok(ty) = self.stdlib.validate_call(name, &arg_types, pos) {
                            ty
                        } else if let Ok(ty) = self.crypto_stdlib.validate_call(name, &arg_types, pos) {
                            ty
                        } else {
                            return Err(KslError::type_error(
                                format!("Invalid function call: {}", name),
                                SourcePosition::new(1, 1),
                            ));
                        };
                        match return_type {
                            Type::U32 => Ok(Int::new_const(&self.ctx, format!("{}_result", name))),
                            Type::Bool => {
                                let bool_var = Bool::new_const(&self.ctx, format!("{}_result", name));
                                self.bool_variables.insert(format!("{}_result", name), bool_var.clone());
                                Ok(Int::from_bool(&self.ctx, &bool_var))
                            }
                            _ => Err(KslError::type_error(
                                format!("Unsupported return type for function: {}", name),
                                SourcePosition::new(1, 1),
                            )),
                        }
                    } else {
                        Err(KslError::type_error(
                            format!("Undefined function: {}", name),
                            SourcePosition::new(1, 1),
                        ))
                    }
                }
            },
            _ => Err(KslError::type_error(
                "Unsupported expression".to_string(),
                SourcePosition::new(1, 1),
            )),
        }
    }

    // Translate expression to Z3 boolean AST (for conditions)
    fn translate_bool_expr(&self, expr: &AstNode) -> Result<Bool<'a>, VerError> {
        match expr {
            AstNode::Expr { kind } => match kind {
                ExprKind::BinaryOp { op, left, right } if op == ">" || op == "==" => {
                    let left_z3 = self.translate_expr(left)?;
                    let right_z3 = self.translate_expr(right)?;
                    match op.as_str() {
                        ">" => Ok(left_z3.gt(&right_z3)),
                        "==" => Ok(left_z3._eq(&right_z3)),
                        _ => unreachable!(),
                    }
                }
                ExprKind::Call { name, args } => {
                    let arg_types: Vec<Type> = args.iter()
                        .map(|arg| TypeSystem::infer_type(arg, &TypeContext::new(), 0).unwrap_or(Type::Void))
                        .collect();
                    let pos = SourcePosition::new(1, 1);
                    if let Ok(Type::Bool) = self.crypto_stdlib.validate_call(name, &arg_types, pos) {
                        let bool_var = Bool::new_const(&self.ctx, format!("{}_result", name));
                        self.bool_variables.insert(format!("{}_result", name), bool_var.clone());
                        Ok(bool_var)
                    } else {
                        Err(KslError::type_error(
                            format!("Function {} does not return bool", name),
                            SourcePosition::new(1, 1),
                        ))
                    }
                }
                _ => Err(KslError::type_error(
                    "Expected boolean expression".to_string(),
                    SourcePosition::new(1, 1),
                )),
            },
            _ => Err(KslError::type_error(
                "Unsupported boolean expression".to_string(),
                SourcePosition::new(1, 1),
            )),
        }
    }
}

// Public API to verify an AST
pub fn verify(ast: &[AstNode]) -> Result<(), Vec<VerError>> {
    let mut verifier = Verifier::new(ast);
    verifier.verify()
}

// Assume ksl_parser.rs, ksl_types.rs, ksl_errors.rs, ksl_stdlib.rs, and ksl_stdlib_crypto.rs are in the same crate
mod ksl_parser {
    pub use super::{AstNode, ExprKind, TypeAnnotation};
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

        let result = verify(&ast);
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

        let result = verify(&ast);
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

        let result = verify(&ast);
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

        let result = verify(&ast);
        assert!(result.is_ok(), "Expected verification to succeed for dil_verify");
    }
}