// ksl_types.rs
// Defines the KSL type system and utilities for type inference and validation.

use std::collections::HashMap;
use std::fmt;
use crate::ksl_errors::KslError;
use crate::ksl_kapra_zkp::{ZkScheme, ZkProof as RuntimeZkProof};

// Assume ksl_generics.rs provides GenericResolver
mod ksl_generics {
    use super::{Type, TypeContext, TypeError};
    pub struct GenericResolver;
    impl GenericResolver {
        pub fn resolve_type(
            _name: &str,
            _constraints: &[Type],
            _ctx: &TypeContext,
        ) -> Result<Type, TypeError> {
            Ok(Type::Void) // Placeholder
        }
    }
}

// Assume ksl_typegen.rs provides TypeGenerator
mod ksl_typegen {
    use super::TypeError;
    pub struct TypeGenerator;
    impl TypeGenerator {
        pub fn validate_schema(_schema: &str) -> Result<(), TypeError> {
            Ok(()) // Placeholder
        }
    }
}

/// Type representation for KSL.
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
    Generic {
        name: String,
        constraints: Vec<Type>, // e.g., T: U32 | F32
    },
    Generated {
        schema: String, // e.g., schema name for JSON/Protobuf
    },
    // Networking types
    Function {
        params: Vec<Type>,
        return_type: Box<Type>,
    }, // e.g., function<u32, string>
    Error, // For error handling
    Socket, // For network sockets
    HttpRequest, // For HTTP requests
    HttpResponse, // For HTTP responses
    Bool,
    ZkProof(ZkProofType),
    Signature(SignatureType),
}

/// Context for type inference (e.g., variable bindings).
#[derive(Debug, Default)]
pub struct TypeContext {
    bindings: HashMap<String, Type>, // Maps variable names to their types
}

impl TypeContext {
    /// Creates a new type context.
    /// @returns A new `TypeContext` instance.
    /// @example
    /// ```ksl
    /// let ctx = TypeContext::new();
    /// ```
    pub fn new() -> Self {
        TypeContext {
            bindings: HashMap::new(),
        }
    }

    /// Adds a variable binding to the context.
    /// @param name The variable name.
    /// @param ty The variable's type.
    /// @example
    /// ```ksl
    /// let mut ctx = TypeContext::new();
    /// ctx.add_binding("x".to_string(), Type::U32);
    /// ```
    pub fn add_binding(&mut self, name: String, ty: Type) {
        self.bindings.insert(name, ty);
    }

    /// Retrieves a variable's type from the context.
    /// @param name The variable name.
    /// @returns An `Option` containing the type, if found.
    /// @example
    /// ```ksl
    /// let mut ctx = TypeContext::new();
    /// ctx.add_binding("x".to_string(), Type::U32);
    /// assert_eq!(ctx.get_binding("x"), Some(&Type::U32));
    /// ```
    pub fn get_binding(&self, name: &str) -> Option<&Type> {
        self.bindings.get(name)
    }
}

/// Type inference and validation errors.
#[derive(Debug, PartialEq)]
pub struct TypeError {
    pub message: String,
    pub position: usize,
}

/// Type utilities for parsing and inference.
pub struct TypeSystem;

impl TypeSystem {
    /// Parses a type annotation from a string.
    /// @param annot The type annotation (e.g., "u32", "array<u8, 32>", "T<U32 | F32>").
    /// @param position The source position for error reporting.
    /// @returns A `Result` containing the parsed `Type` or a `TypeError`.
    /// @example
    /// ```ksl
    /// let ty = TypeSystem::parse_type_annotation("u32", 0).unwrap();
    /// assert_eq!(ty, Type::U32);
    /// ```
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
            "error" => Ok(Type::Error),
            "socket" => Ok(Type::Socket),
            "http_request" => Ok(Type::HttpRequest),
            "http_response" => Ok(Type::HttpResponse),
            "bool" => Ok(Type::Bool),
            "option<" => {
                let inner = &annot[7..annot.len() - 1];
                let inner_type = Self::parse_type_annotation(inner, position)?;
                Ok(Type::Option(Box::new(inner_type)))
            }
            "result<" => {
                let inner = &annot[7..annot.len() - 1];
                let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
                if parts.len() != 2 {
                    return Err(TypeError {
                        message: "Result type requires ok and err types".to_string(),
                        position,
                    });
                }
                let ok_type = Self::parse_type_annotation(parts[0], position)?;
                let err_type = Self::parse_type_annotation(parts[1], position)?;
                Ok(Type::Result {
                    ok: Box::new(ok_type),
                    err: Box::new(err_type),
                })
            }
            "array<" => {
                let inner = &annot[6..annot.len() - 1];
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
            "generated<" => {
                let schema = &annot[10..annot.len() - 1].trim().to_string();
                ksl_typegen::TypeGenerator::validate_schema(schema).map_err(|e| TypeError {
                    message: e.message,
                    position,
                })?;
                Ok(Type::Generated { schema: schema.to_string() })
            }
            "function<" => {
                let inner = &annot[9..annot.len() - 1];
                let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
                if parts.len() < 2 {
                    return Err(TypeError {
                        message: "Function type requires at least return type".to_string(),
                        position,
                    });
                }
                let return_type = Self::parse_type_annotation(parts.last().unwrap(), position)?;
                let params = parts[..parts.len() - 1]
                    .iter()
                    .map(|s| Self::parse_type_annotation(s, position))
                    .collect::<Result<Vec<Type>, TypeError>>()?;
                Ok(Type::Function {
                    params,
                    return_type: Box::new(return_type),
                })
            }
            "zkproof<" => {
                let inner = &annot[10..annot.len() - 1];
                let proof_type = Self::parse_zkproof_type(inner, position)?;
                Ok(Type::ZkProof(proof_type))
            }
            "signature<" => {
                let inner = &annot[11..annot.len() - 1];
                let sig_type = Self::parse_signature_type(inner, position)?;
                Ok(Type::Signature(sig_type))
            }
            _ => Err(TypeError {
                message: format!("Unknown type: {}", annot),
                position,
            }),
        }
    }

    /// Infers the type of an AST node.
    /// @param node The AST node to infer the type for.
    /// @param ctx The type context with variable bindings.
    /// @param position The source position for error reporting.
    /// @returns A `Result` containing the inferred `Type` or a `TypeError`.
    /// @example
    /// ```ksl
    /// let node = AstNode::Expr {
    ///     kind: ExprKind::Number("42".to_string()),
    /// };
    /// let ctx = TypeContext::new();
    /// let ty = TypeSystem::infer_type(&node, &ctx, 0).unwrap();
    /// assert_eq!(ty, Type::U32);
    /// ```
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
                    if !Self::is_compatible(&annot_type, &expr_type) {
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
            AstNode::FnDecl { return_type, body, .. } => {
                let ret_type = Self::parse_type_annotation(return_type, position)?;
                if let Some(last_node) = body.last() {
                    let last_type = Self::infer_type(last_node, ctx, position)?;
                    if !Self::is_compatible(&ret_type, &last_type) {
                        return Err(TypeError {
                            message: format!(
                                "Function return type mismatch: expected {:?}, got {:?}",
                                ret_type, last_type
                            ),
                            position,
                        });
                    }
                }
                Ok(ret_type)
            }
            AstNode::MacroDef { .. } => {
                // Macros don't have a type; return Void
                Ok(Type::Void)
            }
            AstNode::Expr { kind } => match kind {
                ExprKind::Number(num) => {
                    if num.contains('.') {
                        Ok(Type::F32)
                    } else {
                        Ok(Type::U32)
                    }
                }
                ExprKind::String(_) => Ok(Type::String),
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
                                Ok(Type::U32)
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
                ExprKind::Call { name, args } => {
                    // Simplified: Assume function type is in context
                    let fn_type = ctx.get_binding(name).cloned().ok_or_else(|| TypeError {
                        message: format!("Undefined function: {}", name),
                        position,
                    })?;
                    // Basic validation of arguments
                    if let Type::Tuple(arg_types) = fn_type {
                        if arg_types.len() != args.len() {
                            return Err(TypeError {
                                message: format!(
                                    "Expected {} arguments, got {}",
                                    arg_types.len(),
                                    args.len()
                                ),
                                position,
                            });
                        }
                        for (arg, expected_type) in args.iter().zip(arg_types.iter()) {
                            let arg_type = Self::infer_type(arg, ctx, position)?;
                            if !Self::is_compatible(expected_type, &arg_type) {
                                return Err(TypeError {
                                    message: format!(
                                        "Argument type mismatch: expected {:?}, got {:?}",
                                        expected_type, arg_type
                                    ),
                                    position,
                                });
                            }
                        }
                    }
                    Ok(Type::Void) // Simplified: Assume void return for now
                }
                ExprKind::MacroCall { .. } => {
                    // Macro calls don't have a type; return Void
                    Ok(Type::Void)
                }
                ExprKind::AsyncCall { name, args } => {
                    // Simplified: Assume async function returns a Future-like type
                    let fn_type = ctx.get_binding(name).cloned().ok_or_else(|| TypeError {
                        message: format!("Undefined async function: {}", name),
                        position,
                    })?;
                    if let Type::Tuple(arg_types) = fn_type {
                        if arg_types.len() != args.len() {
                            return Err(TypeError {
                                message: format!(
                                    "Expected {} arguments, got {}",
                                    arg_types.len(),
                                    args.len()
                                ),
                                position,
                            });
                        }
                        for (arg, expected_type) in args.iter().zip(arg_types.iter()) {
                            let arg_type = Self::infer_type(arg, ctx, position)?;
                            if !Self::is_compatible(expected_type, &arg_type) {
                                return Err(TypeError {
                                    message: format!(
                                        "Argument type mismatch: expected {:?}, got {:?}",
                                        expected_type, arg_type
                                    ),
                                    position,
                                });
                            }
                        }
                    }
                    Ok(Type::Option(Box::new(Type::Void))) // Simplified: Assume async returns Option<Void>
                }
            },
            _ => Err(TypeError {
                message: "Type inference not yet supported for this node".to_string(),
                position,
            }),
        }
    }

    /// Checks if two types are compatible for assignments.
    /// @param expected The expected type.
    /// @param actual The actual type.
    /// @returns `true` if the types are compatible, `false` otherwise.
    /// @example
    /// ```ksl
    /// assert!(TypeSystem::is_compatible(&Type::U32, &Type::U32));
    /// ```
    pub fn is_compatible(expected: &Type, actual: &Type) -> bool {
        match (expected, actual) {
            (Type::Generic { constraints, .. }, actual) => {
                constraints.iter().any(|c| c == actual)
            }
            (expected, Type::Generic { constraints, .. }) => {
                constraints.iter().any(|c| c == expected)
            }
            (Type::Function { params: p1, return_type: r1 }, Type::Function { params: p2, return_type: r2 }) => {
                p1.len() == p2.len() && p1.iter().zip(p2.iter()).all(|(t1, t2)| Self::is_compatible(t1, t2))
                    && Self::is_compatible(r1, r2)
            }
            (Type::Error, Type::Error) => true,
            (Type::Socket, Type::Socket) => true,
            (Type::HttpRequest, Type::HttpRequest) => true,
            (Type::HttpResponse, Type::HttpResponse) => true,
            (Type::Result { ok: ok1, err: err1 }, Type::Result { ok: ok2, err: err2 }) => {
                Self::is_compatible(ok1, ok2) && Self::is_compatible(err1, err2)
            }
            _ => expected == actual,
        }
    }
}

// Updated AstNode and ExprKind to match ksl_parser.rs
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
    MacroDef {
        name: String,
        params: Vec<(String, String)>,
        body: Vec<AstNode>,
    },
    Expr {
        kind: ExprKind,
    },
}

#[derive(Debug, PartialEq)]
pub enum ExprKind {
    Ident(String),
    Number(String),
    String(String),
    BinaryOp {
        op: String,
        left: Box<AstNode>,
        right: Box<AstNode>,
    },
    Call {
        name: String,
        args: Vec<AstNode>,
    },
    MacroCall {
        name: String,
        args: Vec<AstNode>,
    },
    AsyncCall {
        name: String,
        args: Vec<AstNode>,
    },
}

/// Represents different types of zero-knowledge proofs
#[derive(Debug, Clone, PartialEq)]
pub enum ZkProofType {
    /// BLS signature-based proof (96 bytes)
    Bls,
    /// Dilithium post-quantum proof (2420 bytes)
    Dilithium,
    /// Generic proof type when scheme is determined at runtime
    Generic,
}

/// Represents different types of cryptographic signatures
#[derive(Debug, Clone, PartialEq)]
pub enum SignatureType {
    /// Ed25519 signature (64 bytes)
    Ed25519,
    /// BLS signature (96 bytes)
    Bls,
    /// Dilithium signature (2420 bytes)
    Dilithium,
}

impl Type {
    /// Get the size in bytes for fixed-size types
    pub fn size_in_bytes(&self) -> Option<usize> {
        match self {
            Type::U8 => Some(1),
            Type::U32 => Some(4),
            Type::U64 => Some(8),
            Type::Bool => Some(1),
            Type::Array(inner, len) => inner.size_in_bytes().map(|s| s * len),
            Type::ZkProof(proof_type) => Some(match proof_type {
                ZkProofType::Bls => 96,
                ZkProofType::Dilithium => 2420,
                ZkProofType::Generic => 0, // Size determined at runtime
            }),
            Type::Signature(sig_type) => Some(match sig_type {
                SignatureType::Ed25519 => 64,
                SignatureType::Bls => 96,
                SignatureType::Dilithium => 2420,
            }),
            _ => None, // Dynamic size for strings, tuples, etc.
        }
    }

    /// Check if a type can be converted to another type
    pub fn can_convert_to(&self, target: &Type) -> bool {
        match (self, target) {
            // Allow conversion between proof types if sizes match
            (Type::ZkProof(a), Type::ZkProof(b)) => {
                matches!((a, b),
                    (ZkProofType::Bls, ZkProofType::Generic) |
                    (ZkProofType::Dilithium, ZkProofType::Generic) |
                    (ZkProofType::Generic, ZkProofType::Bls) |
                    (ZkProofType::Generic, ZkProofType::Dilithium) |
                    (a, b) if a == b
                )
            },
            // Allow conversion between signature types if sizes match
            (Type::Signature(a), Type::Signature(b)) => {
                a.size_in_bytes() == b.size_in_bytes()
            },
            // Allow array to proof/signature conversion if sizes match
            (Type::Array(inner, len), Type::ZkProof(proof_type)) => {
                if let Type::U8 = **inner {
                    let proof_size = match proof_type {
                        ZkProofType::Bls => 96,
                        ZkProofType::Dilithium => 2420,
                        ZkProofType::Generic => 0,
                    };
                    *len == proof_size
                } else {
                    false
                }
            },
            (Type::Array(inner, len), Type::Signature(sig_type)) => {
                if let Type::U8 = **inner {
                    let sig_size = match sig_type {
                        SignatureType::Ed25519 => 64,
                        SignatureType::Bls => 96,
                        SignatureType::Dilithium => 2420,
                    };
                    *len == sig_size
                } else {
                    false
                }
            },
            // ... existing conversion rules ...
            _ => self == target,
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::ZkProof(proof_type) => match proof_type {
                ZkProofType::Bls => write!(f, "zkproof<bls>"),
                ZkProofType::Dilithium => write!(f, "zkproof<dilithium>"),
                ZkProofType::Generic => write!(f, "zkproof"),
            },
            Type::Signature(sig_type) => match sig_type {
                SignatureType::Ed25519 => write!(f, "signature<ed25519>"),
                SignatureType::Bls => write!(f, "signature<bls>"),
                SignatureType::Dilithium => write!(f, "signature<dilithium>"),
            },
            // ... existing display implementations ...
            _ => write!(f, "{:?}", self),
        }
    }
}

/// Runtime value representation
#[derive(Debug, Clone)]
pub enum Value {
    // ... existing values ...
    U8(u8),
    U32(u32),
    U64(u64),
    Bool(bool),
    String(String),
    Array(Vec<Value>),
    Tuple(Vec<Value>),
    
    /// Zero-knowledge proof value
    ZkProof(RuntimeZkProof),
    
    /// Signature value
    Signature(Vec<u8>),
}

impl Value {
    /// Get the type of a value
    pub fn get_type(&self) -> Type {
        match self {
            Value::ZkProof(proof) => Type::ZkProof(match proof.scheme() {
                ZkScheme::BLS => ZkProofType::Bls,
                ZkScheme::Dilithium => ZkProofType::Dilithium,
            }),
            Value::Signature(bytes) => Type::Signature(match bytes.len() {
                64 => SignatureType::Ed25519,
                96 => SignatureType::Bls,
                2420 => SignatureType::Dilithium,
                _ => panic!("Invalid signature length"),
            }),
            // ... existing type implementations ...
            _ => panic!("Unknown value type"),
        }
    }

    /// Try to convert a value to a different type
    pub fn try_convert(&self, target_type: &Type) -> Result<Value, KslError> {
        match (self, target_type) {
            (Value::Array(bytes), Type::ZkProof(proof_type)) => {
                let scheme = match proof_type {
                    ZkProofType::Bls => ZkScheme::BLS,
                    ZkProofType::Dilithium => ZkScheme::Dilithium,
                    ZkProofType::Generic => return Err(KslError::TypeError("Cannot convert to generic proof type".into())),
                };
                let bytes_vec: Vec<u8> = bytes.iter().map(|v| match v {
                    Value::U8(b) => *b,
                    _ => panic!("Array must contain u8 values"),
                }).collect();
                Ok(Value::ZkProof(RuntimeZkProof::from_bytes(scheme, bytes_vec)?))
            },
            // ... existing conversion implementations ...
            _ => Err(KslError::TypeError(format!(
                "Cannot convert {:?} to {:?}",
                self.get_type(),
                target_type
            ))),
        }
    }
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
        assert_eq!(
            TypeSystem::parse_type_annotation("T<u32 | f32>", 0),
            Ok(Type::Generic {
                name: "T".to_string(),
                constraints: vec![Type::U32, Type::F32],
            })
        );
        assert_eq!(
            TypeSystem::parse_type_annotation("generated<user_schema>", 0),
            Ok(Type::Generated {
                schema: "user_schema".to_string(),
            })
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

    #[test]
    fn infer_type_generic() {
        let mut ctx = TypeContext::new();
        ctx.add_binding(
            "add".to_string(),
            Type::Tuple(vec![Type::Generic {
                name: "T".to_string(),
                constraints: vec![Type::U32, Type::F32],
            }]),
        );
        let node = AstNode::Expr {
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
        };
        assert_eq!(TypeSystem::infer_type(&node, &ctx, 0), Ok(Type::Void));
    }

    #[test]
    fn parse_networking_types() {
        let tests = vec![
            ("function<u32, string>", Type::Function {
                params: vec![Type::U32],
                return_type: Box::new(Type::String),
            }),
            ("result<string, error>", Type::Result {
                ok: Box::new(Type::String),
                err: Box::new(Type::Error),
            }),
            ("array<u8, 1024>", Type::Array(Box::new(Type::U8), 1024)),
            ("socket", Type::Socket),
            ("http_request", Type::HttpRequest),
            ("http_response", Type::HttpResponse),
        ];

        for (input, expected) in tests {
            let result = TypeSystem::parse_type_annotation(input, 0);
            assert_eq!(result, Ok(expected));
        }
    }

    #[test]
    fn is_compatible_networking() {
        let tests = vec![
            (
                Type::Function {
                    params: vec![Type::U32],
                    return_type: Box::new(Type::String),
                },
                Type::Function {
                    params: vec![Type::U32],
                    return_type: Box::new(Type::String),
                },
                true,
            ),
            (
                Type::Result {
                    ok: Box::new(Type::String),
                    err: Box::new(Type::Error),
                },
                Type::Result {
                    ok: Box::new(Type::String),
                    err: Box::new(Type::Error),
                },
                true,
            ),
            (
                Type::Array(Box::new(Type::U8), 1024),
                Type::Array(Box::new(Type::U8), 1024),
                true,
            ),
            (
                Type::Socket,
                Type::Socket,
                true,
            ),
            (
                Type::HttpRequest,
                Type::HttpResponse,
                false,
            ),
        ];

        for (t1, t2, expected) in tests {
            assert_eq!(TypeSystem::is_compatible(&t1, &t2), expected);
        }
    }

    #[test]
    fn infer_networking_types() {
        let ctx = TypeContext::new();
        let tests = vec![
            (
                AstNode::Expr {
                    kind: ExprKind::AsyncCall {
                        name: "http.get".to_string(),
                        args: vec![AstNode::Expr {
                            kind: ExprKind::String("url".to_string()),
                        }],
                    },
                },
                Type::Result {
                    ok: Box::new(Type::String),
                    err: Box::new(Type::Error),
                },
            ),
            (
                AstNode::Expr {
                    kind: ExprKind::AsyncCall {
                        name: "http.post".to_string(),
                        args: vec![
                            AstNode::Expr {
                                kind: ExprKind::String("url".to_string()),
                            },
                            AstNode::Expr {
                                kind: ExprKind::String("data".to_string()),
                            },
                        ],
                    },
                },
                Type::Result {
                    ok: Box::new(Type::String),
                    err: Box::new(Type::Error),
                },
            ),
        ];

        for (node, expected) in tests {
            let result = TypeSystem::infer_type(&node, &ctx, 0);
            assert_eq!(result, Ok(expected));
        }
    }

    #[test]
    fn test_zkproof_type_size() {
        assert_eq!(Type::ZkProof(ZkProofType::Bls).size_in_bytes(), Some(96));
        assert_eq!(Type::ZkProof(ZkProofType::Dilithium).size_in_bytes(), Some(2420));
        assert_eq!(Type::ZkProof(ZkProofType::Generic).size_in_bytes(), Some(0));
    }

    #[test]
    fn test_signature_type_size() {
        assert_eq!(Type::Signature(SignatureType::Ed25519).size_in_bytes(), Some(64));
        assert_eq!(Type::Signature(SignatureType::Bls).size_in_bytes(), Some(96));
        assert_eq!(Type::Signature(SignatureType::Dilithium).size_in_bytes(), Some(2420));
    }

    #[test]
    fn test_type_conversion() {
        let bls_proof = Type::ZkProof(ZkProofType::Bls);
        let generic_proof = Type::ZkProof(ZkProofType::Generic);
        assert!(bls_proof.can_convert_to(&generic_proof));
        assert!(generic_proof.can_convert_to(&bls_proof));

        let bls_array = Type::Array(Box::new(Type::U8), 96);
        assert!(bls_array.can_convert_to(&Type::ZkProof(ZkProofType::Bls)));
        assert!(!bls_array.can_convert_to(&Type::ZkProof(ZkProofType::Dilithium)));
    }

    #[test]
    fn test_type_display() {
        assert_eq!(
            Type::ZkProof(ZkProofType::Bls).to_string(),
            "zkproof<bls>"
        );
        assert_eq!(
            Type::Signature(SignatureType::Ed25519).to_string(),
            "signature<ed25519>"
        );
    }
}