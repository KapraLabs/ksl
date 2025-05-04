// ksl_stdlib_io.rs
// Implements I/O functions for KSL standard library, optimized for mobile and IoT.

use crate::ksl_types::{Type, TypeError};
use crate::ksl_bytecode::{KapraOpCode, Operand, KapraInstruction};
use crate::ksl_errors::{KslError, SourcePosition};
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::io::{self, Write};

/// I/O function signature
/// @struct IOStdLibFunction
/// @field name Function name
/// @field params Function parameters
/// @field return_type Function return type
/// @field opcode Function opcode (None for native implementations)
#[derive(Debug, PartialEq, Clone)]
pub struct IOStdLibFunction {
    pub name: &'static str,
    pub params: Vec<Type>,
    pub return_type: Type,
    pub opcode: Option<KapraOpCode>,
}

/// I/O standard library registry
/// @struct IOStdLib
/// @field functions Registered I/O functions
/// @field http_client HTTP client for network requests
/// @field output_stream Output stream for print operations
pub struct IOStdLib {
    functions: Vec<IOStdLibFunction>,
    http_client: Arc<Mutex<Client>>,
    output_stream: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl IOStdLib {
    /// Creates a new I/O standard library
    /// @returns A new `IOStdLib` instance
    pub fn new() -> Self {
        let functions = vec![
            // http.get(url: string) -> result<string, error>
            IOStdLibFunction {
                name: "http.get",
                params: vec![Type::String],
                return_type: Type::Result {
                    ok: Box::new(Type::String),
                    err: Box::new(Type::Error),
                },
                opcode: Some(KapraOpCode::HttpGet),
            },
            // print(msg: string) -> void
            IOStdLibFunction {
                name: "print",
                params: vec![Type::String],
                return_type: Type::Void,
                opcode: Some(KapraOpCode::Print),
            },
        ];
        IOStdLib {
            functions,
            http_client: Arc::new(Mutex::new(Client::new())),
            output_stream: Arc::new(Mutex::new(Box::new(io::stdout()))),
        }
    }

    /// Creates a new I/O standard library with custom output stream
    /// @param output_stream Custom output stream for print operations
    /// @returns A new `IOStdLib` instance
    pub fn with_output_stream(output_stream: Box<dyn Write + Send>) -> Self {
        let mut stdlib = Self::new();
        stdlib.output_stream = Arc::new(Mutex::new(output_stream));
        stdlib
    }

    /// Gets a function by name
    /// @param name Function name
    /// @returns `Some(function)` if found, `None` otherwise
    pub fn get_function(&self, name: &str) -> Option<&IOStdLibFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Validates a function call
    /// @param name Function name
    /// @param arg_types Argument types
    /// @param position Source position
    /// @returns `Ok(return_type)` if valid, `Err` with a `KslError` otherwise
    pub fn validate_call(
        &self,
        name: &str,
        arg_types: &[Type],
        position: SourcePosition,
    ) -> Result<Type, KslError> {
        let func = self.get_function(name).ok_or_else(|| KslError::type_error(
            format!("Undefined I/O function: {}", name),
            position,
        ))?;
        if arg_types.len() != func.params.len() {
            return Err(KslError::type_error(
                format!(
                    "Expected {} arguments, got {}",
                    func.params.len(),
                    arg_types.len()
                ),
                position,
            ));
        }
        for (expected, actual) in func.params.iter().zip(arg_types) {
            if expected != actual {
                return Err(KslError::type_error(
                    format!("Argument type mismatch: expected {:?}, got {:?}", expected, actual),
                    position,
                ));
            }
        }
        Ok(func.return_type.clone())
    }

    /// Generates bytecode for a function call
    /// @param name Function name
    /// @param arg_regs Argument registers
    /// @param dst_reg Destination register
    /// @returns `Ok(instructions)` if successful, `Err` with a `KslError` otherwise
    pub fn emit_call(
        &self,
        name: &str,
        arg_regs: &[u8],
        dst_reg: u8,
    ) -> Result<Vec<KapraInstruction>, KslError> {
        let func = self.get_function(name).ok_or_else(|| KslError::type_error(
            format!("Undefined I/O function: {}", name),
            SourcePosition::new(1, 1),
        ))?;
        if arg_regs.len() != func.params.len() {
            return Err(KslError::type_error(
                format!(
                    "Expected {} arguments, got {}",
                    func.params.len(),
                    arg_regs.len()
                ),
                SourcePosition::new(1, 1),
            ));
        }

        match func.opcode {
            Some(opcode) => {
                let mut operands = vec![Operand::Register(dst_reg)];
                operands.extend(arg_regs.iter().map(|&r| Operand::Register(r)));
                Ok(vec![KapraInstruction::new(
                    opcode,
                    operands,
                    Some(func.return_type.clone()),
                )])
            }
            None => Err(KslError::type_error(
                format!("No implementation for {}", name),
                SourcePosition::new(1, 1),
            )),
        }
    }

    /// Executes an HTTP GET request
    /// @param url URL to fetch
    /// @returns `Ok(response)` if successful, `Err` with a `KslError` otherwise
    pub async fn http_get(&self, url: &str) -> Result<String, KslError> {
        let client = self.http_client.lock().await;
        let response = client.get(url)
            .send()
            .await
            .map_err(|e| KslError::type_error(
                format!("HTTP GET failed: {}", e),
                SourcePosition::new(1, 1),
            ))?;
        
        if !response.status().is_success() {
            return Err(KslError::type_error(
                format!("HTTP GET failed with status: {}", response.status()),
                SourcePosition::new(1, 1),
            ));
        }

        let text = response.text()
            .await
            .map_err(|e| KslError::type_error(
                format!("Failed to read response: {}", e),
                SourcePosition::new(1, 1),
            ))?;
        Ok(text)
    }

    /// Prints a message to the output stream
    /// @param msg Message to print
    /// @returns `Ok(())` if successful, `Err` with a `KslError` otherwise
    pub fn print(&self, msg: &str) -> Result<(), KslError> {
        let mut output = self.output_stream.lock().unwrap();
        writeln!(output, "{}", msg)
            .map_err(|e| KslError::type_error(
                format!("Failed to print: {}", e),
                SourcePosition::new(1, 1),
            ))
    }
}

// Assume ksl_types.rs, ksl_bytecode.rs, and ksl_errors.rs are in the same crate
mod ksl_types {
    pub use super::{Type, TypeError};
}

mod ksl_bytecode {
    pub use super::{KapraOpCode, Operand, KapraInstruction};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;
    use std::sync::mpsc;
    use std::io::Cursor;

    #[test]
    fn test_get_function() {
        let stdlib = IOStdLib::new();
        
        // Test http.get
        let func = stdlib.get_function("http.get").unwrap();
        assert_eq!(func.name, "http.get");
        assert_eq!(func.params, vec![Type::String]);
        assert_eq!(func.return_type, Type::Result {
            ok: Box::new(Type::String),
            err: Box::new(Type::Error),
        });
        assert_eq!(func.opcode, Some(KapraOpCode::HttpGet));

        // Test print
        let func = stdlib.get_function("print").unwrap();
        assert_eq!(func.name, "print");
        assert_eq!(func.params, vec![Type::String]);
        assert_eq!(func.return_type, Type::Void);
        assert_eq!(func.opcode, Some(KapraOpCode::Print));
    }

    #[test]
    fn test_validate_call() {
        let stdlib = IOStdLib::new();
        let pos = SourcePosition::new(1, 1);
        
        // Test http.get
        assert_eq!(
            stdlib.validate_call("http.get", &[Type::String], pos),
            Ok(Type::Result {
                ok: Box::new(Type::String),
                err: Box::new(Type::Error),
            })
        );
        
        // Test print
        assert_eq!(
            stdlib.validate_call("print", &[Type::String], pos),
            Ok(Type::Void)
        );
        
        // Test invalid calls
        assert!(stdlib.validate_call("http.get", &[Type::U32], pos).is_err());
        assert!(stdlib.validate_call("print", &[Type::U32], pos).is_err());
        assert!(stdlib.validate_call("unknown", &[], pos).is_err());
    }

    #[test]
    fn test_emit_call() {
        let stdlib = IOStdLib::new();
        
        // Test http.get
        let instructions = stdlib.emit_call("http.get", &[1], 0).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, KapraOpCode::HttpGet);
        assert_eq!(
            instructions[0].operands,
            vec![Operand::Register(0), Operand::Register(1)]
        );
        
        // Test print
        let instructions = stdlib.emit_call("print", &[1], 0).unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, KapraOpCode::Print);
        assert_eq!(
            instructions[0].operands,
            vec![Operand::Register(0), Operand::Register(1)]
        );
    }

    #[tokio::test]
    async fn test_http_get() {
        let stdlib = IOStdLib::new();
        
        // Test successful request
        let response = stdlib.http_get("https://httpbin.org/get").await;
        assert!(response.is_ok());
        let body = response.unwrap();
        assert!(body.contains("httpbin.org"));
        
        // Test failed request
        let response = stdlib.http_get("https://nonexistent.example.com").await;
        assert!(response.is_err());
    }

    #[test]
    fn test_print() {
        // Test with custom output stream
        let output = Cursor::new(Vec::new());
        let stdlib = IOStdLib::with_output_stream(Box::new(output));
        
        // Test successful print
        let result = stdlib.print("Hello, world!");
        assert!(result.is_ok());
        
        // Get the output
        let output = stdlib.output_stream.lock().unwrap();
        let output = output.get_ref();
        assert!(String::from_utf8_lossy(output).contains("Hello, world!"));
    }
}