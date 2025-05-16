// ksl_common.rs
// Common type definitions used across the KSL project
// Serves as a central point to avoid circular dependencies and provide shared functionality

use std::collections::HashMap;
use std::sync::Arc;
use crate::ksl_parser::parse;

/// Bytecode type for Kapra VM
pub type KapraBytecode = Vec<u8>;

/// Runtime error type
#[derive(Debug, Clone)]
pub struct RuntimeError {
    pub message: String,
}

/// Opcodes for the Kapra VM
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Opcode {
    HttpGet,
    HttpPost,
    // Other opcodes as needed
}

/// Asynchronous state for tracking tasks
#[derive(Debug, Default, Clone)]
pub struct AsyncState {
    pub pending: bool,
    pub pending_futures: usize,
    pub completed_tasks: usize,
    pub task_ids: Vec<u64>,
    pub paused_tasks: Vec<u64>,
}

/// Compilation configuration
#[derive(Debug, Clone)]
pub struct CompileConfig {
    pub target: Option<CompileTarget>,
    pub optimize: bool,
    pub debug_level: u8,
}

/// Compilation target
#[derive(Debug, Clone)]
pub enum CompileTarget {
    Rust,
    Python,
    JavaScript,
    TypeScript,
}

/// AST Node type for parsing KSL code
#[derive(Debug, Clone)]
pub enum AstNode {
    // Basic variant for compilation
    Expr {
        kind: ExprKind,
    },
    // Add your other variants here
    FnDecl {
        doc: Option<DocComment>,
        name: String,
        params: Vec<(String, TypeAnnotation)>,
        return_type: TypeAnnotation,
        body: Vec<AstNode>,
        attributes: Vec<Attribute>,
    },
    VarDecl {
        doc: Option<DocComment>,
        is_mutable: bool,
        name: String,
        type_annot: Option<TypeAnnotation>,
        expr: Box<AstNode>,
    },
    If {
        condition: Box<AstNode>,
        then_branch: Vec<AstNode>,
        else_branch: Option<Vec<AstNode>>,
    },
    Match {
        expr: Box<AstNode>,
        arms: Vec<MatchArm>,
    },
    // Add any other needed variants
}

/// Match arm for pattern matching
#[derive(Debug, Clone)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub body: Vec<AstNode>,
}

impl MatchArm {
    /// Creates a clone with a new body
    pub fn clone_with_body(&self, new_body: Vec<AstNode>) -> Self {
        MatchArm {
            pattern: self.pattern.clone(),
            body: new_body,
        }
    }
}

/// Pattern for match expressions
#[derive(Debug, Clone)]
pub enum Pattern {
    Literal(Literal),
    Ident(String),
    Wildcard,
}

/// Literal values for pattern matching and expressions
#[derive(Debug, Clone)]
pub enum Literal {
    String(String),
    Number(String),
    Bool(bool),
}

/// Expression kind enum
#[derive(Debug, Clone)]
pub enum ExprKind {
    Ident(String),
    String(String),
    Number(String),
    Bool(bool),
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
    ArrayAccess {
        array: Box<AstNode>,
        index: Box<AstNode>,
    },
}

/// Type annotation for AST nodes
#[derive(Debug, Clone)]
pub enum TypeAnnotation {
    /// Simple type (e.g., "u32")
    Simple(String),
    /// Array type (e.g., "array<u8, 32>")
    Array {
        element: String,
        size: usize,
    },
    /// Result type (e.g., "result<u32, string>")
    Result {
        success: String,
        error: String,
    },
}

/// Documentation comment
#[derive(Debug, Clone)]
pub struct DocComment {
    pub text: String,
}

/// Attribute for decorating AST nodes
#[derive(Debug, Clone)]
pub struct Attribute {
    pub name: String,
    pub params: Vec<(String, String)>,
}

/// Parse error representation
#[derive(Debug, Clone)]
pub struct ParseError {
    /// Error position
    pub position: usize,
    /// Error message
    pub message: String,
}

/// Type checking function stub
pub fn check(ast: &[AstNode]) -> Result<(), Vec<String>> {
    // Stub implementation
    Ok(())
}

/// Compilation function stub
pub fn compile(ast: &[AstNode], config: &CompileConfig) -> Result<KapraBytecode, Vec<String>> {
    // Stub implementation
    Ok(Vec::new())
}

/// Re-export commonly used types
pub mod reexports {
    pub use super::{AstNode, ExprKind, TypeAnnotation, Attribute, ParseError, CompileConfig, CompileTarget};
} 