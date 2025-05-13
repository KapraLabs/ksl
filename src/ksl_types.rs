// ksl_types.rs
// Defines the KSL type system and utilities for type inference and validation.

use std::collections::HashMap;
use std::fmt;
use crate::ksl_errors::KslError;
use crate::ksl_kapra_zkp::{ZkScheme, ZkProof as RuntimeZkProof};
use serde::{Serialize, Deserialize};

pub type TypeAnnotation = String; // Added TypeAnnotation as a type alias for String

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
            let _schema_string = _schema.to_string();
            Ok(()) // Placeholder
        }
    }
}

/// Type representation for KSL.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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
    // Data blob type
    DataBlob {
        element_type: Box<Type>,
        size: usize,
        alignment: usize,
    },
    Blockchain(BlockchainType),
}

/// Context for type inference (e.g., variable bindings).
#[derive(Debug, Default, Serialize, Deserialize)]
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
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TypeError {
    pub message: String,
    pub position: usize,
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TypeError: {:?}", self)
    }
}

/// Type utilities for parsing and inference.
#[derive(Debug)]
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

/// Blockchain-specific types
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum BlockchainType {
    BlockHeader,
    Transaction,
    ValidatorInfo,
    Hash,
    Signature,
    MerkleProof,
}

impl Type {
    /// Get the size in bytes for fixed-size types
    pub fn size_in_bytes(&self) -> Option<usize> {
        match self {
            Type::U8 => Some(1),
            Type::U16 => Some(2),
            Type::U32 => Some(4),
            Type::U64 => Some(8),
            Type::I8 => Some(1),
            Type::I16 => Some(2),
            Type::I32 => Some(4),
            Type::I64 => Some(8),
            Type::F32 => Some(4),
            Type::F64 => Some(8),
            Type::Bool => Some(1),
            Type::String => None, // Dynamic size
            Type::Array(_, size) => Some(size as usize),
            Type::Struct { fields, .. } => {
                let mut total = 0;
                for (_, field_type) in fields {
                    if let Some(size) = field_type.size_in_bytes() {
                        total += size;
                    } else {
                        return None;
                    }
                }
                Some(total)
            }
            Type::Enum { .. } => None, // Size depends on largest variant
            Type::Option(inner) => {
                if let Some(size) = inner.size_in_bytes() {
                    Some(size + 1) // +1 for discriminant
                } else {
                    None
                }
            }
            Type::Result { ok, err } => {
                let ok_size = ok.size_in_bytes()?;
                let err_size = err.size_in_bytes()?;
                Some(std::cmp::max(ok_size, err_size) + 1) // +1 for discriminant
            }
            Type::Tuple(types) => {
                let mut total = 0;
                for ty in types {
                    if let Some(size) = ty.size_in_bytes() {
                        total += size;
                    } else {
                        return None;
                    }
                }
                Some(total)
            }
            Type::Void => Some(0),
            Type::Generic { .. } => None,
            Type::Generated { .. } => None,
            Type::Function { .. } => None,
            Type::Error => None,
            Type::Socket => None,
            Type::HttpRequest => None,
            Type::HttpResponse => None,
            Type::ZkProof(proof_type) => match proof_type {
                ZkProofType::Bls => Some(96),
                ZkProofType::Dilithium => Some(2420),
                ZkProofType::Generic => None,
            },
            Type::Signature(sig_type) => match sig_type {
                SignatureType::Ed25519 => Some(64),
                SignatureType::Bls => Some(96),
                SignatureType::Dilithium => Some(2420),
            },
            Type::DataBlob { size, .. } => Some(*size),
            Type::Blockchain(blockchain_type) => match blockchain_type {
                BlockchainType::BlockHeader => Some(32 + 8 + 8 + 32 + 2 + 64), // parent + nonce + timestamp + miner + shard + signature
                BlockchainType::Transaction => Some(32 + 32 + 8 + 8 + 64 + 32), // sender + recipient + amount + nonce + signature + data
                BlockchainType::ValidatorInfo => Some(32 + 8 + 2 + 1), // public_key + stake + shard + status
                BlockchainType::Hash => Some(32),
                BlockchainType::Signature => Some(64),
                BlockchainType::MerkleProof => None, // Variable size
            },
        }
    }

    /// Check if a type can be converted to another type
    pub fn can_convert_to(&self, target: &Type) -> bool {
        match (self, target) {
            (Type::U8, Type::U16) | (Type::U8, Type::U32) | (Type::U8, Type::U64) |
            (Type::U16, Type::U32) | (Type::U16, Type::U64) |
            (Type::U32, Type::U64) |
            (Type::I8, Type::I16) | (Type::I8, Type::I32) | (Type::I8, Type::I64) |
            (Type::I16, Type::I32) | (Type::I16, Type::I64) |
            (Type::I32, Type::I64) |
            (Type::F32, Type::F64) => true,
            (Type::Array(inner1, size1), Type::Array(inner2, size2)) => {
                size1 == size2 && inner1.can_convert_to(inner2)
            }
            (Type::Struct { name: name1, fields: fields1 }, Type::Struct { name: name2, fields: fields2 }) => {
                name1 == name2 && fields1.len() == fields2.len() &&
                fields1.iter().zip(fields2.iter()).all(|((name1, type1), (name2, type2))| {
                    name1 == name2 && type1.can_convert_to(type2)
                })
            }
            (Type::Enum { name: name1, variants: variants1 }, Type::Enum { name: name2, variants: variants2 }) => {
                name1 == name2 && variants1.len() == variants2.len() &&
                variants1.iter().zip(variants2.iter()).all(|((name1, type1), (name2, type2))| {
                    name1 == name2 && match (type1, type2) {
                        (Some(t1), Some(t2)) => t1.can_convert_to(t2),
                        (None, None) => true,
                        _ => false,
                    }
                })
            }
            (Type::Option(inner1), Type::Option(inner2)) => inner1.can_convert_to(inner2),
            (Type::Result { ok: ok1, err: err1 }, Type::Result { ok: ok2, err: err2 }) => {
                ok1.can_convert_to(ok2) && err1.can_convert_to(err2)
            }
            (Type::Tuple(types1), Type::Tuple(types2)) => {
                types1.len() == types2.len() &&
                types1.iter().zip(types2.iter()).all(|(t1, t2)| t1.can_convert_to(t2))
            }
            (Type::Generic { name: name1, constraints: constraints1 }, Type::Generic { name: name2, constraints: constraints2 }) => {
                name1 == name2 && constraints1.len() == constraints2.len() &&
                constraints1.iter().zip(constraints2.iter()).all(|(c1, c2)| c1.can_convert_to(c2))
            }
            (Type::Generated { schema: schema1 }, Type::Generated { schema: schema2 }) => {
                schema1 == schema2
            }
            (Type::Function { params: params1, return_type: ret1 }, Type::Function { params: params2, return_type: ret2 }) => {
                params1.len() == params2.len() &&
                params1.iter().zip(params2.iter()).all(|(p1, p2)| p1.can_convert_to(p2)) &&
                ret1.can_convert_to(ret2)
            }
            (Type::ZkProof(proof1), Type::ZkProof(proof2)) => proof1 == proof2,
            (Type::Signature(sig1), Type::Signature(sig2)) => sig1 == sig2,
            (Type::DataBlob { element_type: type1, size: size1, alignment: align1 },
             Type::DataBlob { element_type: type2, size: size2, alignment: align2 }) => {
                type1.can_convert_to(type2) && size1 == size2 && align1 == align2
            }
            (Type::Blockchain(block1), Type::Blockchain(block2)) => block1 == block2,
            _ => false,
        }
    }

    pub fn is_data_blob(&self) -> bool {
        matches!(self, Type::DataBlob { .. })
    }

    pub fn data_blob_size(&self) -> Option<usize> {
        if let Type::DataBlob { size, .. } = self {
            Some(*size)
        } else {
            None
        }
    }

    pub fn data_blob_alignment(&self) -> Option<usize> {
        if let Type::DataBlob { alignment, .. } = self {
            Some(*alignment)
        } else {
            None
        }
    }

    pub fn data_blob_element_type(&self) -> Option<&Type> {
        if let Type::DataBlob { element_type, .. } = self {
            Some(element_type)
        } else {
            None
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::U8 => write!(f, "u8"),
            Type::U16 => write!(f, "u16"),
            Type::U32 => write!(f, "u32"),
            Type::U64 => write!(f, "u64"),
            Type::I8 => write!(f, "i8"),
            Type::I16 => write!(f, "i16"),
            Type::I32 => write!(f, "i32"),
            Type::I64 => write!(f, "i64"),
            Type::F32 => write!(f, "f32"),
            Type::F64 => write!(f, "f64"),
            Type::String => write!(f, "string"),
            Type::Bool => write!(f, "bool"),
            Type::Array(inner, size) => write!(f, "array<{}, {}>", inner, size),
            Type::Struct { name, fields } => {
                write!(f, "struct {} {{ ", name)?;
                for (i, (field_name, field_type)) in fields.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", field_name, field_type)?;
                }
                write!(f, " }}")
            }
            Type::Enum { name, variants } => {
                write!(f, "enum {} {{ ", name)?;
                for (i, (variant_name, variant_type)) in variants.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", variant_name)?;
                    if let Some(ty) = variant_type {
                        write!(f, "({})", ty)?;
                    }
                }
                write!(f, " }}")
            }
            Type::Option(inner) => write!(f, "option<{}>", inner),
            Type::Result { ok, err } => write!(f, "result<{}, {}>", ok, err),
            Type::Tuple(types) => {
                write!(f, "(")?;
                for (i, ty) in types.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", ty)?;
                }
                write!(f, ")")
            }
            Type::Void => write!(f, "void"),
            Type::Generic { name, constraints } => {
                write!(f, "{}", name)?;
                if !constraints.is_empty() {
                    write!(f, ": ")?;
                    for (i, constraint) in constraints.iter().enumerate() {
                        if i > 0 {
                            write!(f, " | ")?;
                        }
                        write!(f, "{}", constraint)?;
                    }
                }
                Ok(())
            }
            Type::Generated { schema } => write!(f, "generated<{}>", schema),
            Type::Function { params, return_type } => {
                write!(f, "function<")?;
                for (i, param) in params.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", param)?;
                }
                write!(f, "> -> {}", return_type)
            }
            Type::Error => write!(f, "error"),
            Type::Socket => write!(f, "socket"),
            Type::HttpRequest => write!(f, "http_request"),
            Type::HttpResponse => write!(f, "http_response"),
            Type::ZkProof(proof_type) => write!(f, "zkproof<{:?}>", proof_type),
            Type::Signature(sig_type) => write!(f, "signature<{:?}>", sig_type),
            Type::DataBlob { element_type, size, alignment } => {
                write!(f, "datablob<{}, {}, {}>", element_type, size, alignment)
            }
            Type::Blockchain(blockchain_type) => write!(f, "blockchain<{:?}>", blockchain_type),
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
                    ZkProofType::Generic => return Err(KslError::type_error("Cannot convert to generic proof type".into(), SourcePosition::new(1, 1), "E015")),
                };
                let bytes_vec: Vec<u8> = bytes.iter().map(|v| match v {
                    Value::U8(b) => *b,
                    _ => panic!("Array must contain u8 values"),
                }).collect();
                Ok(Value::ZkProof(RuntimeZkProof::from_bytes(scheme, bytes_vec)?))
            },
            // ... existing conversion implementations ...
            _ => Err(KslError::type_error(format!("Type error occurred"), SourcePosition::new(1, 1), "E016")),
        }
    }
}

/// Data blob metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KSLDataBlob {
    /// Blob name/identifier
    pub name: String,
    /// Element type
    pub element_type: Type,
    /// Number of elements
    pub length: usize,
    /// Raw data bytes
    pub contents: Vec<u8>,
    /// Source file or label
    pub source: Option<String>,
    /// Memory alignment requirement
    pub alignment: usize,
    /// Content hash for verification
    pub hash: [u8; 32],
}

impl KSLDataBlob {
    /// Create a new data blob
    pub fn new(name: String, element_type: Type, length: usize) -> Self {
        Self {
            name,
            element_type,
            length,
            contents: Vec::new(),
            source: None,
            alignment: 8, // Default alignment
            hash: [0; 32],
        }
    }

    /// Load blob data from file
    pub fn load_from_file(&mut self, path: &str) -> std::io::Result<()> {
        self.contents = std::fs::read(path)?;
        self.source = Some(path.to_string());
        self.update_hash();
        Ok(())
    }

    /// Set blob data directly
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.contents = data;
        self.update_hash();
    }

    /// Update content hash
    fn update_hash(&mut self) {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.contents);
        self.hash.copy_from_slice(&hasher.finalize());
    }

    /// Get size in bytes
    pub fn byte_size(&self) -> usize {
        self.length * self.element_type_size()
    }

    /// Get size of element type in bytes
    fn element_type_size(&self) -> usize {
        match &self.element_type {
            Type::U8 | Type::I8 => 1,
            Type::U16 | Type::I16 => 2,
            Type::U32 | Type::I32 | Type::F32 => 4,
            Type::U64 | Type::I64 | Type::F64 => 8,
            _ => panic!("Unsupported element type for data blob"),
        }
    }
}

/// Block header structure for KSL blockchain
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent: Vec<u8>,
    pub nonce: u64,
    pub timestamp: u64,
    pub miner: Vec<u8>,
    pub shard: u16,
    pub signature: Vec<u8>,
}

/// Transaction structure for KSL blockchain
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub sender: Vec<u8>, // Address
    pub recipient: Vec<u8>, // Address
    pub amount: u64,
    pub nonce: u64,
    pub signature: Vec<u8>,
    pub data: Vec<u8>,
}

/// Validator information structure
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub public_key: Vec<u8>,
    pub stake: u64,
    pub shard: u16,
    pub status: ValidatorStatus,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Slashed,
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

    #[test]
    fn test_data_blob_creation() {
        let blob = KSLDataBlob::new(
            "weights".to_string(),
            Type::F64,
            1024
        );
        assert_eq!(blob.name, "weights");
        assert_eq!(blob.length, 1024);
        assert_eq!(blob.alignment, 8);
    }

    #[test]
    fn test_data_blob_size() {
        let blob = KSLDataBlob::new(
            "data".to_string(),
            Type::F64,
            1024
        );
        assert_eq!(blob.byte_size(), 8 * 1024); // F64 is 8 bytes
    }

    #[test]
    fn test_data_blob_hash() {
        let mut blob = KSLDataBlob::new(
            "data".to_string(),
            Type::U8,
            4
        );
        blob.set_data(vec![1, 2, 3, 4]);
        assert_ne!(blob.hash, [0; 32]); // Hash should be updated
    }

    #[test]
    fn test_data_blob_type_display() {
        let t = Type::DataBlob {
            element_type: Box::new(Type::F64),
            size: 1024,
            alignment: 8,
        };
        assert_eq!(t.to_string(), "data_blob<f64, 1024>");
    }
}