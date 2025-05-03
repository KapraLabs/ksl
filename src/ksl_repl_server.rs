// ksl_repl_server.rs
// Provides a REPL server for remote KSL code execution and debugging, enabling
// interactive sessions over TCP with debugging support.

use crate::ksl_interpreter::{Interpreter, Value};
use crate::ksl_debug::{Debugger, DebugCommand};
use crate::ksl_logger::{init_logger, log_with_trace, Level};
use crate::ksl_errors::{KslError, SourcePosition};
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write, BufReader, BufRead};
use std::thread;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;

// REPL server configuration
#[derive(Debug)]
pub struct ReplServerConfig {
    port: u16, // Port to listen on
}

// REPL server
pub struct ReplServer {
    config: ReplServerConfig,
}

impl ReplServer {
    pub fn new(config: ReplServerConfig) -> Self {
        ReplServer { config }
    }

    // Start the REPL server
    pub fn start(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Initialize logger
        init_logger(Level::Info, true, None, false)?;

        // Start TCP server
        let listener = TcpListener::bind(("127.0.0.1", self.config.port))
            .map_err(|e| KslError::type_error(
                format!("Failed to bind to port {}: {}", self.config.port, e),
                pos,
            ))?;
        log_with_trace(Level::Info, &format!("REPL server started on port {}", self.config.port), None);

        // Accept client connections
        for stream in listener.incoming() {
            let stream = stream.map_err(|e| KslError::type_error(
                format!("Failed to accept connection: {}", e),
                pos,
            ))?;
            let peer_addr = stream.peer_addr()
                .map_err(|e| KslError::type_error(
                    format!("Failed to get peer address: {}", e),
                    pos,
                ))?;
            log_with_trace(Level::Info, &format!("New client connected: {}", peer_addr), None);

            // Handle client in a separate thread
            thread::spawn(move || {
                if let Err(e) = handle_client(stream) {
                    log_with_trace(Level::Error, &format!("Client error: {}", e), None);
                }
            });
        }

        Ok(())
    }
}

// Handle a single client connection
fn handle_client(mut stream: TcpStream) -> Result<(), KslError> {
    let pos = SourcePosition::new(1, 1);
    let mut interpreter = Interpreter::new();
    let debugger = Arc::new(Mutex::new(Debugger::new()));
    let mut reader = BufReader::new(&stream);
    let mut buffer = String::new();

    // Send welcome message
    stream.write_all(b"Welcome to KSL REPL Server! Enter KSL code or !commands for debugging (e.g., !break 10).\n> ")
        .map_err(|e| KslError::type_error(format!("Failed to write to stream: {}", e), pos))?;
    stream.flush()
        .map_err(|e| KslError::type_error(format!("Failed to flush stream: {}", e), pos))?;

    loop {
        buffer.clear();
        reader.read_line(&mut buffer)
            .map_err(|e| KslError::type_error(format!("Failed to read from stream: {}", e), pos))?;

        let input = buffer.trim();
        if input.is_empty() {
            continue;
        }

        if input == "exit" {
            stream.write_all(b"Goodbye!\n")
                .map_err(|e| KslError::type_error(format!("Failed to write to stream: {}", e), pos))?;
            break;
        }

        // Check for debug commands
        let response = if input.starts_with('!') {
            let command = input[1..].trim();
            match command {
                "break" => {
                    if let Some(line) = command.split_whitespace().nth(1) {
                        if let Ok(line_num) = line.parse::<usize>() {
                            let mut debugger = debugger.lock().unwrap();
                            debugger.set_breakpoint(line_num);
                            format!("Breakpoint set at line {}\n", line_num)
                        } else {
                            "Invalid line number\n".to_string()
                        }
                    } else {
                        "Usage: !break <line>\n".to_string()
                    }
                }
                "inspect" => {
                    let debugger = debugger.lock().unwrap();
                    format!("Variables: {:?}\n", debugger.inspect_variables())
                }
                "continue" => {
                    let mut debugger = debugger.lock().unwrap();
                    debugger.clear_breakpoints();
                    "Continuing execution\n".to_string()
                }
                _ => "Unknown debug command. Available: !break, !inspect, !continue\n".to_string(),
            }
        } else {
            // Execute KSL code
            let temp_file = PathBuf::from("repl_temp.ksl");
            File::create(&temp_file)
                .map_err(|e| KslError::type_error(format!("Failed to create temp file: {}", e), pos))?
                .write_all(input.as_bytes())
                .map_err(|e| KslError::type_error(format!("Failed to write temp file: {}", e), pos))?;

            match interpreter.interpret(&temp_file) {
                Ok(value) => {
                    let mut debugger = debugger.lock().unwrap();
                    if debugger.should_break() {
                        format!("Hit breakpoint! Value: {:?}\nUse !inspect or !continue\n", value)
                    } else {
                        format!("Result: {:?}\n", value)
                    }
                }
                Err(e) => format!("Error: {}\n", e),
            }
        };

        stream.write_all(response.as_bytes())
            .map_err(|e| KslError::type_error(format!("Failed to write to stream: {}", e), pos))?;
        stream.write_all(b"> ")
            .map_err(|e| KslError::type_error(format!("Failed to write to stream: {}", e), pos))?;
        stream.flush()
            .map_err(|e| KslError::type_error(format!("Failed to flush stream: {}", e), pos))?;

        log_with_trace(Level::Info, &format!("Processed command: {}", input), None);
    }

    Ok(())
}

// Public API to start the REPL server
pub fn start_repl_server(port: u16) -> Result<(), KslError> {
    let config = ReplServerConfig { port };
    let server = ReplServer::new(config);
    server.start()
}

// Assume ksl_interpreter.rs, ksl_debug.rs, ksl_logger.rs, and ksl_errors.rs are in the same crate
mod ksl_interpreter {
    pub use super::{Interpreter, Value};
}

mod ksl_debug {
    pub use super::{Debugger, DebugCommand};
}

mod ksl_logger {
    pub use super::{init_logger, log_with_trace, Level};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_repl_server() {
        // Start REPL server in a separate thread
        thread::spawn(|| {
            start_repl_server(9000).unwrap();
        });

        // Give the server a moment to start
        thread::sleep(Duration::from_millis(100));

        // Connect to the server
        let mut stream = TcpStream::connect("127.0.0.1:9000").unwrap();
        let mut buffer = [0; 1024];

        // Read welcome message
        let bytes_read = stream.read(&mut buffer).unwrap();
        let welcome = String::from_utf8_lossy(&buffer[..bytes_read]);
        assert!(welcome.contains("Welcome to KSL REPL Server"));

        // Send a simple KSL command
        stream.write_all(b"let x: u32 = 42;\n").unwrap();
        stream.flush().unwrap();

        let bytes_read = stream.read(&mut buffer).unwrap();
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
        assert!(response.contains("Result: Void"));

        // Send a debug command
        stream.write_all(b"!break 1\n").unwrap();
        stream.flush().unwrap();

        let bytes_read = stream.read(&mut buffer).unwrap();
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
        assert!(response.contains("Breakpoint set at line 1"));

        // Exit the session
        stream.write_all(b"exit\n").unwrap();
        stream.flush().unwrap();

        let bytes_read = stream.read(&mut buffer).unwrap();
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
        assert!(response.contains("Goodbye"));
    }

    #[test]
    fn test_repl_server_invalid_port() {
        let result = start_repl_server(0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to bind to port"));
    }
}
