// ksl_errors.rs
// Unified error handling for KSL.

use std::fmt;

// Source position for error reporting
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct SourcePosition {
    pub line: usize,
    pub column: usize,
}

impl SourcePosition {
    pub fn new(line: usize, column: usize) -> Self {
        SourcePosition { line, column }
    }
}

impl fmt::Display for SourcePosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, column {}", self.line, self.column)
    }
}

// Main error type for KSL
#[derive(Debug, PartialEq)]
pub enum KslError {
    Parse {
        message: String,
        position: SourcePosition,
    },
    Type {
        message: String,
        position: SourcePosition,
    },
    Compile {
        message: String,
        position: SourcePosition,
    },
    Runtime {
        message: String,
        instruction: usize, // Instruction index (no source position)
    },
}

impl KslError {
    // Create a parse error
    pub fn parse(message: String, position: SourcePosition) -> Self {
        KslError::Parse { message, position }
    }

    // Create a type error
    pub fn type_error(message: String, position: SourcePosition) -> Self {
        KslError::Type { message, position }
    }

    // Create a compile error
    pub fn compile(message: String, position: SourcePosition) -> Self {
        KslError::Compile { message, position }
    }

    // Create a runtime error
    pub fn runtime(message: String, instruction: usize) -> Self {
        KslError::Runtime { message, instruction }
    }
}

impl fmt::Display for KslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KslError::Parse { message, position } => {
                write!(f, "Parse error at {}: {}", position, message)
            }
            KslError::Type { message, position } => {
                write!(f, "Type error at {}: {}", position, message)
            }
            KslError::Compile { message, position } => {
                write!(f, "Compile error at {}: {}", position, message)
            }
            KslError::Runtime { message, instruction } => {
                write!(f, "Runtime error at instruction {}: {}", instruction, message)
            }
        }
    }
}

// Utility to compute source position from input and offset
pub fn compute_position(input: &str, offset: usize) -> SourcePosition {
    let mut line = 1;
    let mut column = 1;
    for (i, c) in input.chars().enumerate() {
        if i >= offset {
            break;
        }
        if c == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    SourcePosition::new(line, column)
}

// Assume other modules are in the same crate (for type definitions)
mod ksl_parser {
    pub use super::{AstNode, ExprKind};
}

mod ksl_types {
    pub use super::Type;
}

mod ksl_bytecode {
    pub use super::{KapraBytecode, KapraInstruction, KapraOpCode, Operand};
}

mod kapra_vm {
    pub use super::RuntimeError;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error() {
        let err = KslError::parse(
            "Unexpected character".to_string(),
            SourcePosition::new(1, 5),
        );
        assert_eq!(
            err.to_string(),
            "Parse error at line 1, column 5: Unexpected character"
        );
    }

    #[test]
    fn test_type_error() {
        let err = KslError::type_error(
            "Type mismatch: expected u32, got f32".to_string(),
            SourcePosition::new(2, 10),
        );
        assert_eq!(
            err.to_string(),
            "Type error at line 2, column 10: Type mismatch: expected u32, got f32"
        );
    }

    #[test]
    fn test_compile_error() {
        let err = KslError::compile(
            "No free registers".to_string(),
            SourcePosition::new(3, 15),
        );
        assert_eq!(
            err.to_string(),
            "Compile error at line 3, column 15: No free registers"
        );
    }

    #[test]
    fn test_runtime_error() {
        let err = KslError::runtime("Invalid register".to_string(), 42);
        assert_eq!(
            err.to_string(),
            "Runtime error at instruction 42: Invalid register"
        );
    }

    #[test]
    fn test_compute_position() {
        let input = "let x: u32 = 42;\nfn main() { x }";
        let pos = compute_position(input, 0);
        assert_eq!(pos, SourcePosition::new(1, 1));
        let pos = compute_position(input, 16); // After newline
        assert_eq!(pos, SourcePosition::new(2, 1));
        let pos = compute_position(input, 20); // Inside fn main
        assert_eq!(pos, SourcePosition::new(2, 5));
    }
}