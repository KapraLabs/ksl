// ksl_ast.rs - Abstract Syntax Tree for KSL Language

// Import Attribute from ksl_macros
pub use crate::ksl_macros::Attribute;

pub enum Literal {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(String),
    Array(Vec<Literal>, Box<Type>), // Array literal with element type
}

pub enum BinaryOperator {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    And,
    Or,
}

pub enum Expr {
    Literal(Literal),
    Identifier(String),
    BinaryOp {
        left: Box<Expr>,
        op: BinaryOperator,
        right: Box<Expr>,
    },
    Call {
        function: Box<Expr>,
        args: Vec<Expr>,
    },
    Index {
        base: Box<Expr>,
        index: Box<Expr>,
    },
    ArrayLiteral {
        elements: Vec<Expr>,
        element_type: Type,
    },
    Range {
        start: Box<Expr>,
        end: Box<Expr>,
    },
    Match {
        value: Box<Expr>,
        arms: Vec<MatchArm>,
    },
    Attribute(String, Box<Expr>),
    // Add Loop for simulated loop iterations in tests
    Loop {
        id: usize,
        count: usize,
        body: Vec<Expr>,
    },
}

pub struct MatchArm {
    pub pattern: Pattern,
    pub body: Expr,
}

pub enum Pattern {
    Literal(Literal),
    Wildcard,
    Identifier(String),
    Range(Literal, Literal),
    Array(Vec<Pattern>), // Array pattern matching
}

pub enum Stmt {
    Let {
        name: String,
        typ: Option<Type>,
        value: Expr,
    },
    Assign {
        target: AssignTarget,
        value: Expr,
    },
    ExprStmt(Expr),
    Return(Expr),
    If {
        condition: Expr,
        then_branch: Vec<Stmt>,
        else_branch: Option<Vec<Stmt>>,
    },
    While {
        condition: Expr,
        body: Vec<Stmt>,
    },
    For {
        iterator: String,
        iterable: Expr,
        body: Vec<Stmt>,
    },
    VerifyBlock {
        conditions: Vec<Expr>, // Postconditions/assertions to verify
    },
}

pub enum AssignTarget {
    Identifier(String),
    Index {
        base: Box<Expr>,
        index: Box<Expr>,
    },
}

pub struct Function {
    pub name: String,
    pub params: Vec<Parameter>,
    pub return_type: Option<Type>,
    pub is_public: bool,
    pub body: Vec<Stmt>,
    pub attributes: Vec<String>,
}

pub struct Module {
    pub functions: Vec<Function>,
    pub structs: Vec<Struct>,
    pub externs: Vec<ExternBlock>,
}

pub struct Struct {
    pub name: String,
    pub fields: Vec<(String, Type)>,
    pub type_params: Vec<String>, // For generic structs
}

pub struct ExternBlock {
    pub functions: Vec<ExternFunction>,
}

pub struct ExternFunction {
    pub name: String,
    pub params: Vec<Type>,
    pub ret_type: Type,
}

#[derive(Clone, PartialEq, Debug)]
pub enum Type {
    Int,
    Float,
    Bool,
    Str,
    Array(Box<Type>, usize), // Fixed-size array type
    DynamicArray(Box<Type>), // Dynamic-size array type
    Result(Box<Type>, Box<Type>),
    Custom(String),
    Generic {
        name: String,
        type_params: Vec<Type>,
    },
    Void,
    Primitive(String), // String representation of primitive type
}

impl Type {
    pub fn is_numeric(&self) -> bool {
        matches!(self, Type::Int | Type::Float)
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Type::Array(_, _) | Type::DynamicArray(_))
    }

    pub fn element_type(&self) -> Option<&Type> {
        match self {
            Type::Array(elem_type, _) | Type::DynamicArray(elem_type) => Some(elem_type),
            _ => None
        }
    }

    pub fn array_size(&self) -> Option<usize> {
        match self {
            Type::Array(_, size) => Some(*size),
            _ => None
        }
    }
}

// Add a top-level AstNode type to wrap the existing types
// This allows for compatibility with other modules that expect an AstNode type
#[derive(Debug, Clone)]
pub enum AstNode {
    Expression(Expr),
    Statement(Stmt),
    Function(Function),
    Module(Module),
    Struct(Struct),
    VerifyBlock { conditions: Vec<Expr> },
    BinaryOp { left: Box<AstNode>, op: BinaryOperator, right: Box<AstNode> },
    Literal(Literal),
    Identifier(String),
    Call { function: Box<AstNode>, args: Vec<AstNode> },
    Index { base: Box<AstNode>, index: Box<AstNode> },
    ArrayLiteral { elements: Vec<AstNode>, element_type: Type },
    Return { value: Option<Box<AstNode>> },
    If { condition: Box<AstNode>, then_branch: Box<AstNode>, else_branch: Option<Box<AstNode>> },
    // Add plugin-related nodes
    PluginDecl {
        name: String,
        namespace: String,
        version: String,
        ops: Vec<PluginOp>,
    },
    UsePlugin {
        name: String,
        namespace: String,
    },
    RequestCapability {
        capability: String,
    },
    ShardBlock {
        attributes: Vec<Attribute>,
        params: Vec<(String, Type)>,
        body: Vec<AstNode>,
    },
    ValidatorBlock {
        attributes: Vec<Attribute>,
        params: Vec<(String, Type)>,
        body: Vec<AstNode>,
    },
    ContractBlock {
        attributes: Vec<Attribute>,
        name: String,
        state: Vec<(String, Type)>,
        methods: Vec<AstNode>,
    },
}

// Add ContractAst type used in ksl_contract.rs
pub struct ContractAst {
    pub name: String,
    pub functions: Vec<Function>,
    pub storage_vars: Vec<(String, Type)>,
    pub events: Vec<Event>,
    pub capabilities: Vec<String>,
}

// Add Event type used in ContractAst
pub struct Event {
    pub name: String,
    pub fields: Vec<(String, Type)>,
    pub indexed: bool,
}

// Add these plugin-related types to ksl_ast.rs

/// Represents a plugin operation
#[derive(Debug, Clone)]
pub struct PluginOp {
    /// Name of the operation
    pub name: String,
    /// Parameter types
    pub signature: Vec<Type>,
    /// Return type
    pub return_type: Type,
    /// Handler for the operation
    pub handler: PluginHandler,
}

/// Represents a plugin handler
#[derive(Debug, Clone)]
pub struct PluginHandler {
    /// Type of handler (native, wasm, etc.)
    pub kind: String,
    /// Handler name/path
    pub name: String,
}

// Add Parameter struct 
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub ty: Type,
}

impl From<i64> for Literal {
    fn from(n: i64) -> Self {
        Literal::Int(n)
    }
}

impl From<f64> for Literal {
    fn from(f: f64) -> Self {
        Literal::Float(f)
    }
}

impl From<bool> for Literal {
    fn from(b: bool) -> Self {
        Literal::Bool(b)
    }
}

impl From<String> for Literal {
    fn from(s: String) -> Self {
        Literal::Str(s)
    }
}

impl From<&str> for Literal {
    fn from(s: &str) -> Self {
        Literal::Str(s.to_string())
    }
}
