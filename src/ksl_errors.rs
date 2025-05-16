// ksl_errors.rs
// Unified error handling for KSL.

use std::fmt;

// Assume ksl_logger.rs provides Logger
mod ksl_logger {
    pub struct Logger;
    impl Logger {
        pub fn log_error(_message: &str, _trace: Option<&str>) {}
    }
}

// Assume ksl_lsp.rs provides Diagnostic types
mod ksl_lsp {
    pub struct Range {
        pub start: super::SourcePosition,
        pub end: super::SourcePosition,
    }
    pub enum Severity {
        Error,
    }
    pub struct Diagnostic {
        pub message: String,
        pub range: Range,
        pub severity: Severity,
    }
}

// Source position for error reporting
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SourcePosition {
    pub line: usize,
    pub column: usize,
}

impl SourcePosition {
    /// Creates a new source position.
    /// @param line The line number (1-based).
    /// @param column The column number (1-based).
    /// @returns A new `SourcePosition` instance.
    /// @example
    /// ```ksl
    /// let pos = SourcePosition::new(1, 5);
    /// ```
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
#[derive(Debug, Clone)]
pub enum KslError {
    Parse {
        message: String,
        position: SourcePosition,
        code: String, // e.g., "E001"
    },
    Type {
        message: String,
        position: SourcePosition,
        code: String,
    },
    Compile {
        message: String,
        position: SourcePosition,
        code: String,
    },
    Runtime {
        message: String,
        instruction: usize,
        code: String,
    },
    Network {
        message: String,
        position: SourcePosition,
        code: String,
    },
    Serialization {
        message: String,
        position: SourcePosition,
        code: String,
    },
    IO {
        message: String,
        position: SourcePosition,
        code: String,
    },
    Validation {
        message: String,
        position: SourcePosition,
        code: String,
    },
    NotFound {
        message: String,
        position: SourcePosition,
        code: String,
    },
    Scheduler {
        message: String,
        position: SourcePosition,
        code: String,
    },
    CLI {
        message: String,
        position: SourcePosition,
        code: String,
    },
    InvalidProof(String),
    Web3 {
        message: String,
        position: SourcePosition,
        code: String,
    },
}

// Implement From trait for converting String to KslError
impl From<String> for KslError {
    fn from(message: String) -> Self {
        KslError::runtime_error(message, SourcePosition::new(0, 0), "E999".to_string())
    }
}

impl KslError {
    /// Creates a parse error with a message, position, and error code.
    /// @param message The error message.
    /// @param position The source position of the error.
    /// @param code The error code (e.g., "E001").
    /// @returns A new `KslError::Parse` variant.
    /// @example
    /// ```ksl
    /// let err = KslError::parse("Unexpected token".to_string(), SourcePosition::new(1, 5), "E001".to_string());
    /// ```
    pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
        KslError::Parse { message, position, code }
    }

    /// Creates a type error with a message, position, and error code.
    /// @param message The error message.
    /// @param position The source position of the error.
    /// @param code The error code (e.g., "E002").
    /// @returns A new `KslError::Type` variant.
    /// @example
    /// ```ksl
    /// let err = KslError::type_error("Type mismatch".to_string(), SourcePosition::new(2, 10), "E002".to_string());
    /// ```
    pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
        KslError::Type { message, position, code }
    }

    /// Creates a compile error with a message, position, and error code.
    /// @param message The error message.
    /// @param position The source position of the error.
    /// @param code The error code (e.g., "E003").
    /// @returns A new `KslError::Compile` variant.
    /// @example
    /// ```ksl
    /// let err = KslError::compile("No free registers".to_string(), SourcePosition::new(3, 15), "E003".to_string());
    /// ```
    pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
        KslError::Compile { message, position, code }
    }

    /// Creates a runtime error with a message, instruction index, and error code.
    /// @param message The error message.
    /// @param instruction The instruction index causing the error.
    /// @param code The error code (e.g., "E004").
    /// @returns A new `KslError::Runtime` variant.
    /// @example
    /// ```ksl
    /// let err = KslError::runtime("Invalid register".to_string(), 42, "E004".to_string());
    /// ```
    pub fn runtime(message: String, instruction: usize, code: String) -> Self {
        KslError::Runtime { message, instruction, code }
    }

    /// Creates a network error with a message, position, and error code.
    /// @param message The error message.
    /// @param position The source position of the error.
    /// @param code The error code (e.g., "E010").
    /// @returns A new `KslError::Network` variant.
    /// @example
    /// ```ksl
    /// let err = KslError::network("Connection timeout".to_string(), SourcePosition::new(1, 5), "E010".to_string());
    /// ```
    pub fn network(message: String, position: SourcePosition, code: String) -> Self {
        KslError::Network { message, position, code }
    }

    /// Creates a serialization error with a message, position, and error code.
    /// @param message The error message.
    /// @param position The source position of the error.
    /// @param code The error code (e.g., "E011").
    /// @returns A new `KslError::Serialization` variant.
    /// @example
    /// ```ksl
    /// let err = KslError::serialization("Serialization failed".to_string(), SourcePosition::new(1, 5), "E011".to_string());
    /// ```
    pub fn serialization(message: String, position: SourcePosition, code: String) -> Self {
        KslError::Serialization { message, position, code }
    }

    /// Creates an I/O error with a message, position, and error code.
    /// @param message The error message.
    /// @param position The source position of the error.
    /// @param code The error code (e.g., "E012").
    /// @returns A new `KslError::IO` variant.
    /// @example
    /// ```ksl
    /// let err = KslError::io("File not found".to_string(), SourcePosition::new(1, 5), "E012".to_string());
    /// ```
    pub fn io(message: String, position: SourcePosition, code: String) -> Self {
        KslError::IO { message, position, code }
    }

    /// Creates a validation error with a message, position, and error code.
    /// @param message The error message.
    /// @param position The source position of the error.
    /// @param code The error code (e.g., "E013").
    /// @returns A new `KslError::Validation` variant.
    /// @example
    /// ```ksl
    /// let err = KslError::validation("Invalid input".to_string(), SourcePosition::new(1, 5), "E013".to_string());
    /// ```
    pub fn validation(message: String, position: SourcePosition, code: String) -> Self {
        KslError::Validation { message, position, code }
    }

    /// Creates a not found error with a message, position, and error code.
    /// @param message The error message.
    /// @param position The source position of the error.
    /// @param code The error code (e.g., "E014").
    /// @returns A new `KslError::NotFound` variant.
    /// @example
    /// ```ksl
    /// let err = KslError::not_found("Resource not found".to_string(), SourcePosition::new(1, 5), "E014".to_string());
    /// ```
    pub fn not_found(message: String, position: SourcePosition, code: String) -> Self {
        KslError::NotFound { message, position, code }
    }

    /// Creates a scheduler error with a message, position, and error code.
    /// @param message The error message.
    /// @param position The source position of the error.
    /// @param code The error code (e.g., "E015").
    /// @returns A new `KslError::Scheduler` variant.
    /// @example
    /// ```ksl
    /// let err = KslError::scheduler("Scheduler error".to_string(), SourcePosition::new(1, 5), "E015".to_string());
    /// ```
    pub fn scheduler(message: String, position: SourcePosition, code: String) -> Self {
        KslError::Scheduler { message, position, code }
    }

    /// Creates a CLI error with a message, position, and error code.
    /// @param message The error message.
    /// @param position The source position of the error.
    /// @param code The error code (e.g., "E016").
    /// @returns A new `KslError::CLI` variant.
    /// @example
    /// ```ksl
    /// let err = KslError::cli("CLI error".to_string(), SourcePosition::new(1, 5), "E016".to_string());
    /// ```
    pub fn cli(message: String, position: SourcePosition, code: String) -> Self {
        KslError::CLI { message, position, code }
    }

    /// Logs the error with a stack trace using ksl_logger.
    /// @example
    /// ```ksl
    /// let err = KslError::parse("Unexpected token".to_string(), SourcePosition::new(1, 5), "E001".to_string());
    /// err.log_with_trace();
    /// ```
    pub fn log_with_trace(&self) {
        let message = self.to_string();
        let trace = Some("Stack trace placeholder"); // Replace with actual stack trace in production
        ksl_logger::Logger::log_error(&message, trace);
    }

    /// Converts the error to an LSP diagnostic for IDE integration.
    /// @returns A `Diagnostic` compatible with ksl_lsp.
    /// @example
    /// ```ksl
    /// let err = KslError::parse("Unexpected token".to_string(), SourcePosition::new(1, 5), "E001".to_string());
    /// let diag = err.to_diagnostic();
    /// ```
    pub fn to_diagnostic(&self) -> ksl_lsp::Diagnostic {
        match self {
            KslError::Parse { message, position, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {}", code, message),
                range: ksl_lsp::Range {
                    start: *position,
                    end: *position,
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::Type { message, position, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {}", code, message),
                range: ksl_lsp::Range {
                    start: *position,
                    end: *position,
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::Compile { message, position, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {}", code, message),
                range: ksl_lsp::Range {
                    start: *position,
                    end: *position,
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::Runtime { message, instruction, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {} at instruction {}", code, message, instruction),
                range: ksl_lsp::Range {
                    start: SourcePosition::new(1, 1), // Runtime errors lack source position
                    end: SourcePosition::new(1, 1),
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::Network { message, position, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {}", code, message),
                range: ksl_lsp::Range {
                    start: *position,
                    end: *position,
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::Serialization { message, position, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {}", code, message),
                range: ksl_lsp::Range {
                    start: *position,
                    end: *position,
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::IO { message, position, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {}", code, message),
                range: ksl_lsp::Range {
                    start: *position,
                    end: *position,
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::Validation { message, position, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {}", code, message),
                range: ksl_lsp::Range {
                    start: *position,
                    end: *position,
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::NotFound { message, position, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {}", code, message),
                range: ksl_lsp::Range {
                    start: *position,
                    end: *position,
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::Scheduler { message, position, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {}", code, message),
                range: ksl_lsp::Range {
                    start: *position,
                    end: *position,
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::CLI { message, position, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {}", code, message),
                range: ksl_lsp::Range {
                    start: *position,
                    end: *position,
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::InvalidProof(message) => ksl_lsp::Diagnostic {
                message: format!("Invalid proof: {}", message),
                range: ksl_lsp::Range {
                    start: SourcePosition::new(0, 0),
                    end: SourcePosition::new(0, 0),
                },
                severity: ksl_lsp::Severity::Error,
            },
            KslError::Web3 { message, position, code } => ksl_lsp::Diagnostic {
                message: format!("[{}] {}", code, message),
                range: ksl_lsp::Range {
                    start: *position,
                    end: *position,
                },
                severity: ksl_lsp::Severity::Error,
            },
        }
    }

    /// Alias for serialization
    pub fn serialization_error(message: String, position: SourcePosition, code: String) -> Self {
        Self::serialization(message, position, code)
    }

    /// Alias for io
    pub fn io_error(message: String, position: SourcePosition, code: String) -> Self {
        Self::io(message, position, code)
    }

    /// Alias for validation
    pub fn validation_error(message: String, position: SourcePosition, code: String) -> Self {
        Self::validation(message, position, code)
    }

    /// Alias for not_found
    pub fn not_found_error(message: String, position: SourcePosition, code: String) -> Self {
        Self::not_found(message, position, code)
    }

    /// Alias for scheduler
    pub fn scheduler_error(message: String, position: SourcePosition, code: String) -> Self {
        Self::scheduler(message, position, code)
    }

    /// Alias for cli
    pub fn cli_error(message: String, position: SourcePosition, code: String) -> Self {
        Self::cli(message, position, code)
    }

    /// Creates a new KslError based on the ErrorType
    pub fn new(error_type: ErrorType, message: String) -> Self {
        let pos = SourcePosition::new(0, 0);
        match error_type {
            ErrorType::ValidationError => Self::validation(message, pos, "E400".to_string()),
            ErrorType::FileError => Self::io(message, pos, "E401".to_string()),
            ErrorType::TemplateError => Self::not_found(message, pos, "E402".to_string()),
            ErrorType::ConfigError => Self::io(message, pos, "E403".to_string()),
            ErrorType::AsyncError => Self::runtime(message, 0, "E404".to_string()),
            ErrorType::DataBlobError => Self::io(message, pos, "E405".to_string()),
            ErrorType::DataBlobVerificationError => Self::validation(message, pos, "E406".to_string()),
            ErrorType::DataBlobAllocationError => Self::runtime(message, 0, "E407".to_string()),
            ErrorType::DataBlobTypeError => Self::type_error(message, pos, "E408".to_string()),
        }
    }

    /// Creates a Web3 error
    pub fn web3_error(message: String, position: SourcePosition, code: String) -> Self {
        KslError::Web3 {
            message,
            position,
            code,
        }
    }
}

impl fmt::Display for KslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KslError::Parse { message, position, code } => {
                write!(f, "Parse error [{}] at {}: {}", code, position, message)
            }
            KslError::Type { message, position, code } => {
                write!(f, "Type error [{}] at {}: {}", code, position, message)
            }
            KslError::Compile { message, position, code } => {
                write!(f, "Compile error [{}] at {}: {}", code, position, message)
            }
            KslError::Runtime { message, instruction, code } => {
                write!(f, "Runtime error [{}] at instruction {}: {}", code, instruction, message)
            }
            KslError::Network { message, position, code } => {
                write!(f, "Network error [{}] at {}: {}", code, position, message)
            }
            KslError::Serialization { message, position, code } => {
                write!(f, "Serialization error [{}] at {}: {}", code, position, message)
            }
            KslError::IO { message, position, code } => {
                write!(f, "I/O error [{}] at {}: {}", code, position, message)
            }
            KslError::Validation { message, position, code } => {
                write!(f, "Validation error [{}] at {}: {}", code, position, message)
            }
            KslError::NotFound { message, position, code } => {
                write!(f, "Not found error [{}] at {}: {}", code, position, message)
            }
            KslError::Scheduler { message, position, code } => {
                write!(f, "Scheduler error [{}] at {}: {}", code, position, message)
            }
            KslError::CLI { message, position, code } => {
                write!(f, "CLI error [{}] at {}: {}", code, position, message)
            }
            KslError::InvalidProof(message) => {
                write!(f, "Invalid proof: {}", message)
            }
            KslError::Web3 { message, position, code } => {
                write!(f, "Web3 error [{}] at {}: {}", code, position, message)
            }
        }
    }
}

/// Computes the source position from input and character offset.
/// @param input The source code string.
/// @param offset The character offset in the input.
/// @returns The computed `SourcePosition`.
/// @example
/// ```ksl
/// let pos = compute_position("let x = 42;", 4);
/// // Returns SourcePosition { line: 1, column: 5 }
/// ```
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error() {
        let err = KslError::parse(
            "Unexpected token".to_string(),
            SourcePosition::new(1, 5),
            "E001".to_string(),
        );
        assert_eq!(
            err.to_string(),
            "Parse error [E001] at line 1, column 5: Unexpected token"
        );
    }

    #[test]
    fn test_type_error() {
        let err = KslError::type_error(
            "Type mismatch".to_string(),
            SourcePosition::new(2, 10),
            "E002".to_string(),
        );
        assert_eq!(
            err.to_string(),
            "Type error [E002] at line 2, column 10: Type mismatch"
        );
    }

    #[test]
    fn test_compile_error() {
        let err = KslError::compile(
            "No free registers".to_string(),
            SourcePosition::new(3, 15),
            "E003".to_string(),
        );
        assert_eq!(
            err.to_string(),
            "Compile error [E003] at line 3, column 15: No free registers"
        );
    }

    #[test]
    fn test_runtime_error() {
        let err = KslError::runtime(
            "Invalid register".to_string(),
            42,
            "E004".to_string(),
        );
        assert_eq!(
            err.to_string(),
            "Runtime error [E004] at instruction 42: Invalid register"
        );
    }

    #[test]
    fn test_network_error() {
        let err = KslError::network(
            "Connection timeout".to_string(),
            SourcePosition::new(1, 5),
            "E010".to_string(),
        );
        assert_eq!(
            err.to_string(),
            "Network error [E010] at line 1, column 5: Connection timeout"
        );
    }

    #[test]
    fn test_compute_position() {
        let pos = compute_position("let x = 42;\nlet y = 43;", 4);
        assert_eq!(pos, SourcePosition::new(1, 5));
        let pos = compute_position("let x = 42;\nlet y = 43;", 12);
        assert_eq!(pos, SourcePosition::new(2, 1));
    }

    #[test]
    fn test_log_with_trace() {
        let err = KslError::parse(
            "Unexpected token".to_string(),
            SourcePosition::new(1, 5),
            "E001".to_string(),
        );
        err.log_with_trace(); // Just verify it doesn't panic
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ErrorType {
    // ... existing error types ...
    ValidationError,
    FileError,
    TemplateError,
    ConfigError,
    AsyncError,
    DataBlobError,
    DataBlobVerificationError,
    DataBlobAllocationError,
    DataBlobTypeError,
}

impl ErrorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            // ... existing matches ...
            ErrorType::ValidationError => "Validation error",
            ErrorType::FileError => "File error",
            ErrorType::TemplateError => "Template error",
            ErrorType::ConfigError => "Configuration error",
            ErrorType::AsyncError => "Async error",
            ErrorType::DataBlobError => "Data blob error",
            ErrorType::DataBlobVerificationError => "Data blob verification failed",
            ErrorType::DataBlobAllocationError => "Data blob allocation failed",
            ErrorType::DataBlobTypeError => "Data blob type mismatch",
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TypeError {
    pub message: String,
    pub position: usize,
}
