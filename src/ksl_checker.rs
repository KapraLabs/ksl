// ksl_checker.rs
// Performs type checking and inference on KSL AST to ensure type safety.

use crate::ksl_types::{Type, TypeContext, TypeError, TypeSystem};
use crate::ksl_parser::{AstNode, ExprKind};

// Re-export AstNode and ExprKind from ksl_parser.rs for integration
// (In a real project, these would be in a shared module)
#[derive(Debug, PartialEq)]
pub enum AstNode {
    VarDecl {
        is_mutable: bool,
        name: String,
        type_annot: Option<String>,
        expr: Box<AstNode>,
    },
    FnDecl {
        name: String,
        params: Vec<(String, String)>,
        return_type: String,
        body: Vec<AstNode>,
    },
    If {
        condition: Box<AstNode>,
        then_branch: Vec<AstNode>,
        else_branch: Option<Vec<AstNode>>,
    },
    Match {
        expr: Box<AstNode>,
        arms: Vec<(AstNode, Vec<AstNode>)>,
    },
    Expr {
        kind: ExprKind,
    },
}

#[derive(Debug, PartialEq)]
pub enum ExprKind {
    Ident(String),
    Number(String),
    BinaryOp {
        op: String,
        left: Box<AstNode>,
        right: Box<AstNode>,
    },
}

// Type checker struct
pub struct TypeChecker {
    ctx: TypeContext, // Tracks variable bindings
    errors: Vec<TypeError>, // Collects type errors
}

impl TypeChecker {
    pub fn new() -> Self {
        TypeChecker {
            ctx: TypeContext::new(),
            errors: Vec::new(),
        }
    }

    // Main entry point: Check an entire program (list of AST nodes)
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
                Ok(ty) => Some(ty),
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

    // Check function declaration
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
                Ok(ty) => ty,
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

    // Check expression
    fn check_expr(&mut self, kind: &ExprKind, position: usize) {
        // Infer type to ensure expression is valid
        if let Err(err) = TypeSystem::infer_type(&AstNode::Expr { kind: kind.clone() }, &self.ctx, position) {
            self.errors.push(err);
        }
    }
}

// Public API to check an AST
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
}

// Assume ksl_types.rs and ksl_parser.rs are in the same crate
mod ksl_types {
    pub use super::{Type, TypeContext, TypeError, TypeSystem};
}

mod ksl_parser {
    pub use super::{AstNode, ExprKind};
}