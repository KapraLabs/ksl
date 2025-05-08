// ksl_ast.rs - Abstract Syntax Tree for KSL Language

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
    pub params: Vec<(String, Type)>,
    pub ret_type: Type,
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
