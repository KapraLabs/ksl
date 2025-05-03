// ksl_types.rs
// Defines the KSL type system and utilities for type inference and validation.

use std::collections::HashMap;

// Type representation for KSL
#[derive(Debug, PartialEq, Clone)]
pub enum Type {
    // Primitive types
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    // Complex types
    String,
    Array(Box<Type>, u32), // e.g., array<u8, 32>
    Struct {
        name: String,
        fields: Vec<(String, Type)>, // (field_name, type)
    },
    Enum {
        name: String,
        variants: Vec<(String, Option<Type>)>, // (variant_name, optional payload type)
    },
    Option(Box<Type>), // e.g., option<u32>
    Result {
        ok: Box<Type>,
        err: Box<Type>,
    }, // e.g., result<string, error>
    Tuple(Vec<Type>), // e.g., (u32, f32)
    Void, // For functions with no return value
}

// Context for type inference (e.g., variable bindings)
#[derive(Debug, Default)]
pub struct TypeContext {
    bindings: HashMap<String, Type>, // Maps variable names to their types
}

impl TypeContext {
    pub fn new() -> Self {
        TypeContext {
            bindings: HashMap::new(),
        }
    }

    pub fn add_binding(&mut self, name: String, ty: Type) {
        self.bindings.insert(name, ty);
    }

    pub fn get_binding(&self, name: &str) -> Option<&Type> {
        self.bindings.get(name)
    }
}

// Type inference and validation errors
#[derive(Debug, PartialEq)]
pub struct TypeError {
    pub message: String,
    pub position: usize,
}

// Type utilities
pub struct TypeSystem;

impl TypeSystem {
    // Parse a type annotation from a string (e.g., "u32", "array<u8, 32>")
    pub fn parse_type_annotation(annot: &str, position: usize) -> Result<Type, TypeError> {
        match annot {
            "u8" => Ok(Type::U8),
            "u16" => Ok(Type::U16),
            "u32" => Ok(Type::U32),
            "u64" => Ok(Type::U64),
            "i8" => Ok(Type::I8),
            "i16" => Ok(Type::I16),
            "i32" => Ok(Type::I32),
            "i64" => Ok(Type::I64),
            "f32" => Ok(Type::F32),
            "f64" => Ok(Type::F64),
            "string" => Ok(Type::String),
            "void" => Ok(Type::Void),
            _ if annot.starts_with("array<") && annot.ends_with('>') => {
                let inner = &annot[6..annot.len() - 1]; // Extract "u8, 32"
                let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
                if parts.len() != 2 {
                    return Err(TypeError {
                        message: "Array type requires type and size".to_string(),
                        position,
                    });
                }
                let inner_type = Self::parse_type_annotation(parts[0], position)?;
                let size: u32 = parts[1].parse().map_err(|_| TypeError {
                    message: "Invalid array size".to_string(),
                    position,
                })?;
                Ok(Type::Array(Box::new(inner_type), size))
            }
            _ if annot.starts_with("option<") && annot.ends_with('>') => {
                let inner = &annot[7..annot.len() - 1];
                let inner_type = Self::parse_type_annotation(inner, position)?;
                Ok(Type::Option(Box::new(inner_type)))
            }
            _ => Err(TypeError {
                message: format!("Unknown type: {}", annot),
                position,
            }),
        }
    }

    // Infer the type of an AST node (simplified, integrates with ksl_parser.rs)
    pub fn infer_type(
        node: &AstNode,
        ctx: &TypeContext,
        position: usize,
    ) -> Result<Type, TypeError> {
        match node {
            AstNode::VarDecl { expr, type_annot, .. } => {
                if let Some(annot) = type_annot {
                    let annot_type = Self::parse_type_annotation(annot, position)?;
                    let expr_type = Self::infer_type(expr, ctx, position)?;
                    if annot_type != expr_type {
                        return Err(TypeError {
                            message: format!(
                                "Type mismatch: expected {:?}, got {:?}",
                                annot_type, expr_type
                            ),
                            position,
                        });
                    }
                    Ok(annot_type)
                } else {
                    Self::infer_type(expr, ctx, position)
                }
            }
            AstNode::Expr { kind } => match kind {
                ExprKind::Number(num) => {
                    if num.contains('.') {
                        Ok(Type::F32) // Simplified: treat all decimals as f32 for now
                    } else {
                        Ok(Type::U32) // Simplified: treat integers as u32
                    }
                }
                ExprKind::Ident(name) => ctx.get_binding(name).cloned().ok_or_else(|| TypeError {
                    message: format!("Undefined variable: {}", name),
                    position,
                }),
                ExprKind::BinaryOp { op, left, right } => {
                    let left_type = Self::infer_type(left, ctx, position)?;
                    let right_type = Self::infer_type(right, ctx, position)?;
                    match op.as_str() {
                        "+" => {
                            if left_type == right_type && matches!(left_type, Type::U32 | Type::F32) {
                                Ok(left_type)
                            } else {
                                Err(TypeError {
                                    message: "Invalid types for +".to_string(),
                                    position,
                                })
                            }
                        }
                        ">" | "==" => {
                            if left_type == right_type {
                                Ok(Type::U32) // Comparisons return u32 (boolean-like)
                            } else {
                                Err(TypeError {
                                    message: "Type mismatch in comparison".to_string(),
                                    position,
                                })
                            }
                        }
                        _ => Err(TypeError {
                            message: format!("Unsupported operator: {}", op),
                            position,
                        }),
                    }
                }
            },
            _ => Err(TypeError {
                message: "Type inference not yet supported for this node".to_string(),
                position,
            }),
        }
    }

    // Check if two types are compatible (e.g., for assignments)
    pub fn is_compatible(expected: &Type, actual: &Type) -> bool {
        expected == actual // Strict equality for now
    }
}

// Re-export AstNode and ExprKind from ksl_parser.rs for integration
// (In a real project, these would likely be in a shared module)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_type_annotation() {
        assert_eq!(
            TypeSystem::parse_type_annotation("u32", 0),
            Ok(Type::U32)
        );
        assert_eq!(
            TypeSystem::parse_type_annotation("array<u8, 32>", 0),
            Ok(Type::Array(Box::new(Type::U8), 32))
        );
        assert_eq!(
            TypeSystem::parse_type_annotation("option<u32>", 0),
            Ok(Type::Option(Box::new(Type::U32)))
        );
        assert!(TypeSystem::parse_type_annotation("unknown", 0).is_err());
    }

    #[test]
    fn infer_type_number() {
        let node = AstNode::Expr {
            kind: ExprKind::Number("42".to_string()),
        };
        let ctx = TypeContext::new();
        assert_eq!(TypeSystem::infer_type(&node, &ctx, 0), Ok(Type::U32));

        let node = AstNode::Expr {
            kind: ExprKind::Number("3.14".to_string()),
        };
        assert_eq!(TypeSystem::infer_type(&node, &ctx, 0), Ok(Type::F32));
    }

    #[test]
    fn infer_type_var_decl() {
        let node = AstNode::VarDecl {
            is_mutable: true,
            name: "x".to_string(),
            type_annot: Some("u32".to_string()),
            expr: Box::new(AstNode::Expr {
                kind: ExprKind::Number("42".to_string()),
            }),
        };
        let ctx = TypeContext::new();
        assert_eq!(TypeSystem::infer_type(&node, &ctx, 0), Ok(Type::U32));

        let node = AstNode::VarDecl {
            is_mutable: true,
            name: "x".to_string(),
            type_annot: Some("u32".to_string()),
            expr: Box::new(AstNode::Expr {
                kind: ExprKind::Number("3.14".to_string()),
            }),
        };
        assert!(TypeSystem::infer_type(&node, &ctx, 0).is_err());
    }

    #[test]
    fn infer_type_binary_op() {
        let node = AstNode::Expr {
            kind: ExprKind::BinaryOp {
                op: "+".to_string(),
                left: Box::new(AstNode::Expr {
                    kind: ExprKind::Number("42".to_string()),
                }),
                right: Box::new(AstNode::Expr {
                    kind: ExprKind::Number("10".to_string()),
                }),
            },
        };
        let ctx = TypeContext::new();
        assert_eq!(TypeSystem::infer_type(&node, &ctx, 0), Ok(Type::U32));

        let node = AstNode::Expr {
            kind: ExprKind::BinaryOp {
                op: ">".to_string(),
                left: Box::new(AstNode::Expr {
                    kind: ExprKind::Number("42".to_string()),
                }),
                right: Box::new(AstNode::Expr {
                    kind: ExprKind::Number("10".to_string()),
                }),
            },
        };
        assert_eq!(TypeSystem::infer_type(&node, &ctx, 0), Ok(Type::U32));
    }
}