// ksl_checker.rs
// Performs type checking and inference on KSL AST to ensure type safety.

use crate::ksl_ast::{BinaryOp, UnaryOp, AstNode};
use crate::ksl_types::{Type, TypeContext, TypeSystem, ExprKind, TypeAnnotation, TypeError};
use crate::ksl_macros::MacroExpander;
use crate::ksl_generics::GenericResolver;

// Assume ksl_macros.rs provides MacroExpander
mod ksl_macros {
    use super::{Type, TypeContext, TypeError, AstNode};
    pub struct MacroExpander;
    impl MacroExpander {
        pub fn check_macro(
            _name: &str,
            _params: &[(String, Type)],
            _body: &[AstNode],
            _ctx: &TypeContext,
            _position: usize,
        ) -> Result<(), TypeError> {
            Ok(()) // Placeholder
        }
    }
}

// Assume ksl_generics.rs provides GenericResolver
mod ksl_generics {
    use super::{Type, TypeContext, TypeError};
    pub struct GenericResolver;
    impl GenericResolver {
        pub fn check_generic(
            _ty: &Type,
            _ctx: &TypeContext,
            _position: usize,
        ) -> Result<Type, TypeError> {
            Ok(Type::Void) // Placeholder
        }
    }
}

/// Type checker for KSL AST.
pub struct TypeChecker {
    ctx: TypeContext,       // Tracks variable bindings
    errors: Vec<TypeError>, // Collects type errors
}

impl TypeChecker {
    /// Creates a new type checker.
    /// @returns A new `TypeChecker` instance.
    /// @example
    /// ```ksl
    /// let checker = TypeChecker::new();
    /// ```
    pub fn new() -> Self {
        TypeChecker {
            ctx: TypeContext::new(),
            errors: Vec::new(),
        }
    }

    /// Checks an entire program for type safety.
    /// @param nodes The list of AST nodes to check.
    /// @returns `Ok(())` if type checking succeeds, or `Err` with type errors.
    /// @example
    /// ```ksl
    /// let nodes = vec![AstNode::VarDecl { ... }];
    /// let result = TypeChecker::new().check_program(&nodes);
    /// ```
    pub fn check_program(&mut self, nodes: &[AstNode]) -> Result<(), Vec<TypeError>> {
        for node in nodes {
            self.check_node(node, 0);
        }
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors.clone())
        }
    }

    // Check a single AST node
    fn check_node(&mut self, node: &AstNode, position: usize) {
        match node {
            AstNode::VarDecl {
                is_mutable,
                name,
                type_annot,
                expr,
            } => {
                self.check_var_decl(*is_mutable, name, type_annot, expr, position);
            }
            AstNode::FnDecl {
                name,
                params,
                return_type,
                body,
            } => {
                self.check_fn_decl(name, params, return_type, body, position);
            }
            AstNode::If {
                condition,
                then_branch,
                else_branch,
            } => {
                self.check_if(condition, then_branch, else_branch, position);
            }
            AstNode::Match { expr, arms } => {
                self.check_match(expr, arms, position);
            }
            AstNode::MacroDef {
                name,
                params,
                body,
            } => {
                self.check_macro_def(name, params, body, position);
            }
            AstNode::Expr { kind } => {
                self.check_expr(kind, position);
            }
        }
    }

    // Check variable declaration
    fn check_var_decl(
        &mut self,
        is_mutable: bool,
        name: &str,
        type_annot: &Option<String>,
        expr: &AstNode,
        position: usize,
    ) {
        let expr_type = match TypeSystem::infer_type(expr, &self.ctx, position) {
            Ok(ty) => ty,
            Err(err) => {
                self.errors.push(err);
                return;
            }
        };

        let declared_type = if let Some(annot) = type_annot {
            match TypeSystem::parse_type_annotation(annot, position) {
                Ok(ty) => {
                    // Check generic types
                    if matches!(ty, Type::Generic { .. }) {
                        match ksl_generics::GenericResolver::check_generic(&ty, &self.ctx, position) {
                            Ok(resolved_ty) => Some(resolved_ty),
                            Err(err) => {
                                self.errors.push(err);
                                return;
                            }
                        }
                    } else {
                        Some(ty)
                    }
                }
                Err(err) => {
                    self.errors.push(err);
                    return;
                }
            }
        } else {
            None
        };

        // If there's a type annotation, ensure it matches the expression type
        if let Some(decl_ty) = declared_type {
            if !TypeSystem::is_compatible(&decl_ty, &expr_type) {
                self.errors.push(TypeError {
                    message: format!(
                        "Type mismatch: expected {:?}, got {:?}",
                        decl_ty, expr_type
                    ),
                    position,
                });
                return;
            }
        }

        // Add variable to context (use declared type if present, else inferred)
        let var_type = declared_type.unwrap_or(expr_type);
        self.ctx.add_binding(name.to_string(), var_type);
    }

    /// Check function declaration
    /// @param name Function name
    /// @param params Function parameters
    /// @param return_type Return type annotation
    /// @param body Function body
    /// @param position Source position
    fn check_fn_decl(
        &mut self,
        name: &str,
        params: &[(String, String)],
        return_type: &str,
        body: &[AstNode],
        position: usize,
    ) {
        // Parse return type
        let ret_type = match TypeSystem::parse_type_annotation(return_type, position) {
            Ok(ty) => ty,
            Err(err) => {
                self.errors.push(err);
                return;
            }
        };

        // Enter new scope for function
        let old_ctx = self.ctx.clone();
        self.ctx = TypeContext::new();

        // Add parameters to context
        for (param_name, param_type) in params {
            let param_ty = match TypeSystem::parse_type_annotation(param_type, position) {
                Ok(ty) => {
                    if matches!(ty, Type::Generic { .. }) {
                        match ksl_generics::GenericResolver::check_generic(&ty, &self.ctx, position) {
                            Ok(resolved_ty) => resolved_ty,
                            Err(err) => {
                                self.errors.push(err);
                                return;
                            }
                        }
                    } else {
                        ty
                    }
                }
                Err(err) => {
                    self.errors.push(err);
                    return;
                }
            };
            self.ctx.add_binding(param_name.clone(), param_ty);
        }

        // Check body
        for node in body {
            self.check_node(node, position);
        }

        // Check return type (simplified: assume last expression is returned)
        if let Some(last_node) = body.last() {
            let last_type = match TypeSystem::infer_type(last_node, &self.ctx, position) {
                Ok(ty) => ty,
                Err(err) => {
                    self.errors.push(err);
                    return;
                }
            };
            if !TypeSystem::is_compatible(&ret_type, &last_type) {
                self.errors.push(TypeError {
                    message: format!(
                        "Function return type mismatch: expected {:?}, got {:?}",
                        ret_type, last_type
                    ),
                    position,
                });
            }
        } else if ret_type != Type::Void {
            self.errors.push(TypeError {
                message: "Function must return a value".to_string(),
                position,
            });
        }

        // Restore outer scope
        self.ctx = old_ctx;

        // Add function to context (simplified: treat as void for now)
        self.ctx.add_binding(name.to_string(), Type::Void);
    }

    // Check macro definition
    fn check_macro_def(
        &mut self,
        name: &str,
        params: &[(String, String)],
        body: &[AstNode],
        position: usize,
    ) {
        // Enter new scope for macro
        let old_ctx = self.ctx.clone();
        self.ctx = TypeContext::new();

        // Add parameters to context
        let mut typed_params = Vec::new();
        for (param_name, param_type) in params {
            let param_ty = match TypeSystem::parse_type_annotation(param_type, position) {
                Ok(ty) => ty,
                Err(err) => {
                    self.errors.push(err);
                    return;
                }
            };
            self.ctx.add_binding(param_name.clone(), param_ty.clone());
            typed_params.push((param_name.clone(), param_ty));
        }

        // Check body
        for node in body {
            self.check_node(node, position);
        }

        // Validate macro with ksl_macros
        if let Err(err) = ksl_macros::MacroExpander::check_macro(name, &typed_params, body, &self.ctx, position) {
            self.errors.push(err);
        }

        // Restore outer scope
        self.ctx = old_ctx;

        // Add macro to context (simplified: treat as void)
        self.ctx.add_binding(name.to_string(), Type::Void);
    }

    // Check if statement
    fn check_if(
        &mut self,
        condition: &AstNode,
        then_branch: &[AstNode],
        else_branch: &Option<Vec<AstNode>>,
        position: usize,
    ) {
        // Check condition type (must be u32 for now, representing boolean-like)
        let cond_type = match TypeSystem::infer_type(condition, &self.ctx, position) {
            Ok(ty) => ty,
            Err(err) => {
                self.errors.push(err);
                return;
            }
        };
        if cond_type != Type::U32 {
            self.errors.push(TypeError {
                message: format!("If condition must be u32, got {:?}", cond_type),
                position,
            });
        }

        // Check then branch
        for node in then_branch {
            self.check_node(node, position);
        }

        // Check else branch if present
        if let Some(else_nodes) = else_branch {
            for node in else_nodes {
                self.check_node(node, position);
            }
        }
    }

    // Check match statement
    fn check_match(&mut self, expr: &AstNode, arms: &[(AstNode, Vec<AstNode>)], position: usize) {
        // Infer expression type
        let expr_type = match TypeSystem::infer_type(expr, &self.ctx, position) {
            Ok(ty) => ty,
            Err(err) => {
                self.errors.push(err);
                return;
            }
        };

        // Check each arm
        for (pattern, body) in arms {
            // Check pattern type matches expression type
            let pattern_type = match TypeSystem::infer_type(pattern, &self.ctx, position) {
                Ok(ty) => ty,
                Err(err) => {
                    self.errors.push(err);
                    continue;
                }
            };
            if !TypeSystem::is_compatible(&expr_type, &pattern_type) {
                self.errors.push(TypeError {
                    message: format!(
                        "Match pattern type mismatch: expected {:?}, got {:?}",
                        expr_type, pattern_type
                    ),
                    position,
                });
            }

            // Check arm body
            for node in body {
                self.check_node(node, position);
            }
        }
    }

    /// Check expression
    /// @param kind Expression kind
    /// @param position Source position
    fn check_expr(&mut self, kind: &ExprKind, position: usize) {
        match kind {
            ExprKind::Literal(lit) => {
                match lit {
                    Literal::Int(_) => Type::Int,
                    Literal::Float(_) => Type::Float,
                    Literal::String(_) => Type::String,
                    Literal::Bool(_) => Type::Bool,
                    Literal::Array(elems) => {
                        let mut elem_types = Vec::new();
                        for elem in elems {
                            match TypeSystem::infer_type(elem, &self.ctx, position) {
                                Ok(ty) => elem_types.push(ty),
                                Err(err) => {
                                    self.errors.push(err);
                                    return;
                                }
                            }
                        }
                        Type::Array(Box::new(elem_types[0].clone()))
                    }
                }
            }
            ExprKind::Identifier(name) => {
                match self.ctx.get_type(name) {
                    Some(ty) => ty,
                    None => {
                        self.errors.push(TypeError {
                            message: format!("Undefined variable: {}", name),
                            position,
                        });
                        Type::Error
                    }
                }
            }
            ExprKind::BinaryOp { op, left, right } => {
                let left_type = TypeSystem::infer_type(left, &self.ctx, position);
                let right_type = TypeSystem::infer_type(right, &self.ctx, position);

                match (left_type, right_type) {
                    (Ok(left_ty), Ok(right_ty)) => {
                        match op {
                            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div => {
                                if left_ty == Type::Int && right_ty == Type::Int {
                                    Type::Int
                                } else if left_ty == Type::Float && right_ty == Type::Float {
                                    Type::Float
                                } else {
                                    self.errors.push(TypeError {
                                        message: format!(
                                            "Cannot apply operator {:?} to types {:?} and {:?}",
                                            op, left_ty, right_ty
                                        ),
                                        position,
                                    });
                                    Type::Error
                                }
                            }
                            BinaryOp::Eq | BinaryOp::Neq => {
                                if TypeSystem::is_compatible(&left_ty, &right_ty) {
                                    Type::Bool
                                } else {
                                    self.errors.push(TypeError {
                                        message: format!(
                                            "Cannot compare types {:?} and {:?}",
                                            left_ty, right_ty
                                        ),
                                        position,
                                    });
                                    Type::Error
                                }
                            }
                            _ => {
                                self.errors.push(TypeError {
                                    message: format!("Unsupported operator: {:?}", op),
                                    position,
                                });
                                Type::Error
                            }
                        }
                    }
                    (Err(err), _) | (_, Err(err)) => {
                        self.errors.push(err);
                        Type::Error
                    }
                }
            }
            ExprKind::Call { callee, args } => {
                let callee_type = TypeSystem::infer_type(callee, &self.ctx, position);
                match callee_type {
                    Ok(Type::Function { params, ret }) => {
                        if args.len() != params.len() {
                            self.errors.push(TypeError {
                                message: format!(
                                    "Expected {} arguments, got {}",
                                    params.len(),
                                    args.len()
                                ),
                                position,
                            });
                            return;
                        }

                        for (arg, param_ty) in args.iter().zip(params.iter()) {
                            match TypeSystem::infer_type(arg, &self.ctx, position) {
                                Ok(arg_ty) => {
                                    if !TypeSystem::is_compatible(&arg_ty, param_ty) {
                                        self.errors.push(TypeError {
                                            message: format!(
                                                "Type mismatch in function call: expected {:?}, got {:?}",
                                                param_ty, arg_ty
                                            ),
                                            position,
                                        });
                                    }
                                }
                                Err(err) => {
                                    self.errors.push(err);
                                }
                            }
                        }
                        *ret
                    }
                    Ok(_) => {
                        self.errors.push(TypeError {
                            message: "Cannot call non-function type".to_string(),
                            position,
                        });
                        Type::Error
                    }
                    Err(err) => {
                        self.errors.push(err);
                        Type::Error
                    }
                }
            }
            ExprKind::ArrayAccess { array, index } => {
                match self.check_array_access(array, index, position) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        Type::Error
                    }
                }
            }
            ExprKind::UnaryOp { op, expr } => {
                match TypeSystem::infer_type(expr, &self.ctx, position) {
                    Ok(ty) => match op {
                        UnaryOp::Neg => {
                            if ty == Type::Int || ty == Type::Float {
                                ty
                            } else {
                                self.errors.push(TypeError {
                                    message: format!("Cannot negate type {:?}", ty),
                                    position,
                                });
                                Type::Error
                            }
                        }
                        UnaryOp::Not => {
                            if ty == Type::Bool {
                                Type::Bool
                            } else {
                                self.errors.push(TypeError {
                                    message: format!("Cannot apply not operator to type {:?}", ty),
                                    position,
                                });
                                Type::Error
                            }
                        }
                    },
                    Err(err) => {
                        self.errors.push(err);
                        Type::Error
                    }
                }
            }
        }
    }

    fn check_type_annotation(&mut self, annot: &TypeAnnotation, position: usize) -> Result<Type, TypeError> {
        match annot {
            TypeAnnotation::Simple(name) => {
                match name.as_str() {
                    "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" |
                    "f32" | "f64" | "bool" | "string" | "void" => Ok(Type::Simple(name.clone())),
                    _ => Err(TypeError {
                        message: format!("Unknown type: {}", name),
                        position,
                    })
                }
            }
            TypeAnnotation::Array { element, size } => {
                // Check that size is a valid constant
                if *size == 0 {
                    return Err(TypeError {
                        message: "Array size must be greater than 0".to_string(),
                        position,
                    });
                }

                // Recursively check element type
                let element_type = self.check_type_annotation(element, position)?;
                
                // Validate element type is allowed in arrays
                match element_type {
                    Type::Simple(ref name) if matches!(name.as_str(), "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "f32" | "f64" | "bool") => {
                        Ok(Type::Array(Box::new(element_type), *size))
                    }
                    _ => Err(TypeError {
                        message: format!("Invalid array element type: {:?}", element_type),
                        position,
                    })
                }
            }
            TypeAnnotation::Result { success, error } => {
                let success_type = self.check_type_annotation(success, position)?;
                let error_type = self.check_type_annotation(error, position)?;
                Ok(Type::Result {
                    ok: Box::new(success_type),
                    err: Box::new(error_type),
                })
            }
        }
    }

    fn check_array_access(&mut self, array: &AstNode, index: &AstNode, position: usize) -> Result<Type, TypeError> {
        // Check array expression type
        let array_type = self.check_node(array, position)?;
        
        // Check index expression type
        let index_type = self.check_node(index, position)?;
        
        // Verify index is an integer type
        if !matches!(index_type, Type::Simple(ref name) if matches!(name.as_str(), "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64")) {
            return Err(TypeError {
                message: "Array index must be an integer type".to_string(),
                position,
            });
        }
        
        // Extract element type from array type
        match array_type {
            Type::Array(element_type, _) => Ok(*element_type),
            _ => Err(TypeError {
                message: "Expected array type".to_string(),
                position,
            })
        }
    }
}

/// Public API to check an AST for type safety.
/// @param nodes The list of AST nodes to check.
/// @returns `Ok(())` if type checking succeeds, or `Err` with type errors.
/// @example
/// ```ksl
/// let nodes = vec![AstNode::VarDecl { ... }];
/// let result = check(&nodes);
/// ```
pub fn check(nodes: &[AstNode]) -> Result<(), Vec<TypeError>> {
    let mut checker = TypeChecker::new();
    checker.check_program(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ksl_types::Type;

    #[test]
    fn check_var_decl() {
        let nodes = vec![
            AstNode::VarDecl {
                is_mutable: true,
                name: "x".to_string(),
                type_annot: Some("u32".to_string()),
                expr: Box::new(AstNode::Expr {
                    kind: ExprKind::Number("42".to_string()),
                }),
            },
        ];
        assert!(check(&nodes).is_ok());

        let nodes = vec![
            AstNode::VarDecl {
                is_mutable: true,
                name: "x".to_string(),
                type_annot: Some("u32".to_string()),
                expr: Box::new(AstNode::Expr {
                    kind: ExprKind::Number("3.14".to_string()),
                }),
            },
        ];
        assert!(check(&nodes).is_err());
    }

    #[test]
    fn check_var_inference() {
        let nodes = vec![
            AstNode::VarDecl {
                is_mutable: true,
                name: "x".to_string(),
                type_annot: None,
                expr: Box::new(AstNode::Expr {
                    kind: ExprKind::Number("42".to_string()),
                }),
            },
        ];
        assert!(check(&nodes).is_ok());
    }

    #[test]
    fn check_fn_decl() {
        let nodes = vec![
            AstNode::FnDecl {
                name: "add".to_string(),
                params: vec![
                    ("x".to_string(), "u32".to_string()),
                    ("y".to_string(), "u32".to_string()),
                ],
                return_type: "u32".to_string(),
                body: vec![
                    AstNode::Expr {
                        kind: ExprKind::BinaryOp {
                            op: "+".to_string(),
                            left: Box::new(AstNode::Expr {
                                kind: ExprKind::Ident("x".to_string()),
                            }),
                            right: Box::new(AstNode::Expr {
                                kind: ExprKind::Ident("y".to_string()),
                            }),
                        },
                    },
                ],
            },
        ];
        assert!(check(&nodes).is_ok());

        let nodes = vec![
            AstNode::FnDecl {
                name: "add".to_string(),
                params: vec![
                    ("x".to_string(), "u32".to_string()),
                    ("y".to_string(), "u32".to_string()),
                ],
                return_type: "f32".to_string(),
                body: vec![
                    AstNode::Expr {
                        kind: ExprKind::BinaryOp {
                            op: "+".to_string(),
                            left: Box::new(AstNode::Expr {
                                kind: ExprKind::Ident("x".to_string()),
                            }),
                            right: Box::new(AstNode::Expr {
                                kind: ExprKind::Ident("y".to_string()),
                            }),
                        },
                    },
                ],
            },
        ];
        assert!(check(&nodes).is_err());
    }

    #[test]
    fn check_if() {
        let nodes = vec![
            AstNode::If {
                condition: Box::new(AstNode::Expr {
                    kind: ExprKind::BinaryOp {
                        op: ">".to_string(),
                        left: Box::new(AstNode::Expr {
                            kind: ExprKind::Number("42".to_string()),
                        }),
                        right: Box::new(AstNode::Expr {
                            kind: ExprKind::Number("0".to_string()),
                        }),
                    },
                }),
                then_branch: vec![
                    AstNode::VarDecl {
                        is_mutable: true,
                        name: "y".to_string(),
                        type_annot: Some("u32".to_string()),
                        expr: Box::new(AstNode::Expr {
                            kind: ExprKind::Number("1".to_string()),
                        }),
                    },
                ],
                else_branch: Some(vec![
                    AstNode::VarDecl {
                        is_mutable: true,
                        name: "y".to_string(),
                        type_annot: Some("u32".to_string()),
                        expr: Box::new(AstNode::Expr {
                            kind: ExprKind::Number("2".to_string()),
                        }),
                    },
                ]),
            },
        ];
        assert!(check(&nodes).is_ok());
    }

    #[test]
    fn check_match() {
        let nodes = vec![
            AstNode::Match {
                expr: Box::new(AstNode::Expr {
                    kind: ExprKind::Ident("x".to_string()),
                }),
                arms: vec![
                    (
                        AstNode::Expr {
                            kind: ExprKind::Number("0".to_string()),
                        },
                        vec![
                            AstNode::Expr {
                                kind: ExprKind::Number("1".to_string()),
                            },
                        ],
                    ),
                    (
                        AstNode::Expr {
                            kind: ExprKind::Ident("_".to_string()),
                        },
                        vec![
                            AstNode::Expr {
                                kind: ExprKind::Number("2".to_string()),
                            },
                        ],
                    ),
                ],
            },
        ];
        let mut checker = TypeChecker::new();
        checker.ctx.add_binding("x".to_string(), Type::U32);
        assert!(checker.check_program(&nodes).is_ok());
    }

    #[test]
    fn check_macro_def() {
        let nodes = vec![
            AstNode::MacroDef {
                name: "log".to_string(),
                params: vec![("msg".to_string(), "string".to_string())],
                body: vec![
                    AstNode::Expr {
                        kind: ExprKind::Call {
                            name: "print".to_string(),
                            args: vec![
                                AstNode::Expr {
                                    kind: ExprKind::Ident("msg".to_string()),
                                },
                            ],
                        },
                    },
                ],
            },
        ];
        let mut checker = TypeChecker::new();
        checker.ctx.add_binding("print".to_string(), Type::Tuple(vec![Type::String]));
        assert!(checker.check_program(&nodes).is_ok());
    }

    #[test]
    fn check_macro_call() {
        let nodes = vec![
            AstNode::MacroDef {
                name: "log".to_string(),
                params: vec![("msg".to_string(), "string".to_string())],
                body: vec![
                    AstNode::Expr {
                        kind: ExprKind::Call {
                            name: "print".to_string(),
                            args: vec![
                                AstNode::Expr {
                                    kind: ExprKind::Ident("msg".to_string()),
                                },
                            ],
                        },
                    },
                ],
            },
            AstNode::Expr {
                kind: ExprKind::MacroCall {
                    name: "log".to_string(),
                    args: vec![
                        AstNode::Expr {
                            kind: ExprKind::String("Hello".to_string()),
                        },
                    ],
                },
            },
        ];
        let mut checker = TypeChecker::new();
        checker.ctx.add_binding("print".to_string(), Type::Tuple(vec![Type::String]));
        assert!(checker.check_program(&nodes).is_ok());
    }

    #[test]
    fn check_async_call() {
        let nodes = vec![
            AstNode::FnDecl {
                name: "fetch".to_string(),
                params: vec![("url".to_string(), "string".to_string())],
                return_type: "string".to_string(),
                body: vec![
                    AstNode::Expr {
                        kind: ExprKind::Call {
                            name: "net.http_get".to_string(),
                            args: vec![
                                AstNode::Expr {
                                    kind: ExprKind::Ident("url".to_string()),
                                },
                            ],
                        },
                    },
                ],
            },
            AstNode::Expr {
                kind: ExprKind::AsyncCall {
                    name: "fetch".to_string(),
                    args: vec![
                        AstNode::Expr {
                            kind: ExprKind::String("https://api.example.com".to_string()),
                        },
                    ],
                },
            },
        ];
        let mut checker = TypeChecker::new();
        checker.ctx.add_binding("net.http_get".to_string(), Type::Tuple(vec![Type::String]));
        checker.ctx.add_binding("fetch".to_string(), Type::Tuple(vec![Type::String]));
        assert!(checker.check_program(&nodes).is_ok());
    }

    #[test]
    fn check_generic() {
        let nodes = vec![
            AstNode::FnDecl {
                name: "add".to_string(),
                params: vec![
                    ("x".to_string(), "T<u32 | f32>".to_string()),
                    ("y".to_string(), "T<u32 | f32>".to_string()),
                ],
                return_type: "T<u32 | f32>".to_string(),
                body: vec![
                    AstNode::Expr {
                        kind: ExprKind::BinaryOp {
                            op: "+".to_string(),
                            left: Box::new(AstNode::Expr {
                                kind: ExprKind::Ident("x".to_string()),
                            }),
                            right: Box::new(AstNode::Expr {
                                kind: ExprKind::Ident("y".to_string()),
                            }),
                        },
                    },
                ],
            },
            AstNode::VarDecl {
                is_mutable: true,
                name: "x".to_string(),
                type_annot: Some("u32".to_string()),
                expr: Box::new(AstNode::Expr {
                    kind: ExprKind::Call {
                        name: "add".to_string(),
                        args: vec![
                            AstNode::Expr {
                                kind: ExprKind::Number("1".to_string()),
                            },
                            AstNode::Expr {
                                kind: ExprKind::Number("2".to_string()),
                            },
                        ],
                    },
                }),
            },
        ];
        let mut checker = TypeChecker::new();
        checker.ctx.add_binding("add".to_string(), Type::Tuple(vec![Type::Generic {
            name: "T".to_string(),
            constraints: vec![Type::U32, Type::F32],
        }]));
        assert!(checker.check_program(&nodes).is_ok());
    }

    #[test]
    fn test_check_async_fn() {
        let mut checker = TypeChecker::new();
        
        // Test valid async function
        let result = checker.check_fn_decl(
            "fetch_data",
            &[("url".to_string(), "string".to_string())],
            "result<string, error>",
            &[
                AstNode::Expr {
                    kind: ExprKind::AsyncCall {
                        name: "http.get".to_string(),
                        args: vec![AstNode::Expr {
                            kind: ExprKind::Ident("url".to_string()),
                        }],
                    },
                },
            ],
            &[Attribute { name: "async".to_string() }],
            0,
        );
        assert!(result.is_ok());

        // Test invalid async function (wrong return type)
        let result = checker.check_fn_decl(
            "fetch_data",
            &[("url".to_string(), "string".to_string())],
            "string",
            &[
                AstNode::Expr {
                    kind: ExprKind::AsyncCall {
                        name: "http.get".to_string(),
                        args: vec![AstNode::Expr {
                            kind: ExprKind::Ident("url".to_string()),
                        }],
                    },
                },
            ],
            &[Attribute { name: "async".to_string() }],
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_check_http_post() {
        let mut checker = TypeChecker::new();
        
        // Test valid http.post call
        let result = checker.check_expr(
            &ExprKind::AsyncCall {
                name: "http.post".to_string(),
                args: vec![
                    AstNode::Expr {
                        kind: ExprKind::String("https://api.example.com".to_string()),
                    },
                    AstNode::Expr {
                        kind: ExprKind::String("{\"data\": 123}".to_string()),
                    },
                ],
            },
            0,
        );
        assert!(result.is_ok());

        // Test invalid http.post call (wrong argument type)
        let result = checker.check_expr(
            &ExprKind::AsyncCall {
                name: "http.post".to_string(),
                args: vec![
                    AstNode::Expr {
                        kind: ExprKind::String("https://api.example.com".to_string()),
                    },
                    AstNode::Expr {
                        kind: ExprKind::Number("123".to_string()),
                    },
                ],
            },
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_check_print() {
        let mut checker = TypeChecker::new();
        
        // Test valid print call
        let result = checker.check_expr(
            &ExprKind::Call {
                name: "print".to_string(),
                args: vec![
                    AstNode::Expr {
                        kind: ExprKind::String("Hello, world!".to_string()),
                    },
                ],
            },
            0,
        );
        assert!(result.is_ok());

        // Test invalid print call (wrong argument type)
        let result = checker.check_expr(
            &ExprKind::Call {
                name: "print".to_string(),
                args: vec![
                    AstNode::Expr {
                        kind: ExprKind::Number("123".to_string()),
                    },
                ],
            },
            0,
        );
        assert!(result.is_err());
    }
}