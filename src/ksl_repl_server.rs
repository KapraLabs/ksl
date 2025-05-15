/// ksl_repl_server.rs
/// Provides a REPL server for remote KSL code execution and debugging, enabling
/// interactive sessions over TCP with debugging support and async operations.
/// Supports multiple concurrent sessions and network-based code execution.

use crate::ksl_repl::{Repl, ReplConfig, ReplSession};
use crate::ksl_interpreter::{Interpreter, Value};
use crate::ksl_debug::{Debugger, DebugCommand};
use crate::ksl_logger::{init_logger, log_with_trace, Level};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_stdlib_net::{NetworkManager, TcpConfig};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use tokio::sync::{RwLock, Mutex};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

/// Configuration for the REPL server
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReplServerConfig {
    /// Port to listen on
    pub port: u16,
    /// Maximum concurrent sessions
    pub max_sessions: usize,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Network configuration
    pub network_config: TcpConfig,
}

/// State for a REPL session
#[derive(Debug)]
struct SessionState {
    /// Session identifier
    id: String,
    /// Last activity timestamp
    last_active: std::time::Instant,
    /// REPL instance
    repl: Arc<RwLock<Repl>>,
    /// Debugger instance
    debugger: Arc<Mutex<Debugger>>,
}

/// Async REPL server implementation
pub struct ReplServer {
    /// Server configuration
    config: ReplServerConfig,
    /// Active sessions
    sessions: Arc<RwLock<HashMap<String, SessionState>>>,
    /// Network manager
    network: Arc<NetworkManager>,
    /// Async runtime
    runtime: Arc<AsyncRuntime>,
}

impl ReplServer {
    /// Creates a new REPL server instance
    pub fn new(config: ReplServerConfig) -> Result<Self, KslError> {
        Ok(ReplServer {
            config: config.clone(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            network: Arc::new(NetworkManager::new(config.network_config)?),
            runtime: Arc::new(AsyncRuntime::new()),
        })
    }

    /// Starts the REPL server asynchronously
    pub async fn start_async(&self) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        
        // Initialize logger
        init_logger(Level::Info, true, None, false)?;

        // Start TCP server
        let addr = format!("127.0.0.1:{}", self.config.port);
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| KslError::type_error(
                format!("Failed to bind to port {}: {}", self.config.port, e),
                pos,
                "REPL_BIND_ERROR".to_string()
            ))?;
        log_with_trace(Level::Info, &format!("REPL server started on {}", addr), None);

        // Start session cleanup task
        let sessions = self.sessions.clone();
        let timeout = self.config.session_timeout;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                Self::cleanup_sessions(sessions.clone(), timeout).await;
            }
        });

        // Accept connections
        loop {
            let (stream, addr) = listener.accept().await
                .map_err(|e| KslError::type_error(format!("Failed to accept connection: {}", e), pos, "REPL_ACCEPT_ERROR".to_string()))?;
            
            log_with_trace(Level::Info, &format!("New client connected: {}", addr), None);

            // Check session limit
            let session_count = self.sessions.read().await.len();
            if session_count >= self.config.max_sessions {
                stream.write_all(b"Server at capacity. Please try again later.\n").await
                    .map_err(|e| KslError::type_error(format!("Failed to write to stream: {}", e), pos, "REPL_WRITE_ERROR".to_string()))?;
                continue;
            }

            // Handle client
            let sessions = self.sessions.clone();
            let network = self.network.clone();
            let runtime = self.runtime.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client_async(stream, addr.to_string(), sessions, network, runtime).await {
                    log_with_trace(Level::Error, &format!("Client error: {}", e), None);
                }
            });
        }
    }

    /// Handles a client connection asynchronously
    async fn handle_client_async(
        stream: TcpStream,
        session_id: String,
        sessions: Arc<RwLock<HashMap<String, SessionState>>>,
        network: Arc<NetworkManager>,
        runtime: Arc<AsyncRuntime>,
    ) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut buffer = String::new();

        // Create session state
        let repl_config = ReplConfig {
            history_size: 1000,
            network_enabled: true,
            ..Default::default()
        };
        let session = SessionState {
            id: session_id.clone(),
            last_active: std::time::Instant::now(),
            repl: Arc::new(RwLock::new(Repl::new(repl_config)?)),
            debugger: Arc::new(Mutex::new(Debugger::new())),
        };

        // Store session
        sessions.write().await.insert(session_id.clone(), session);

        // Send welcome message
        writer.write_all(b"Welcome to KSL REPL Server! Enter KSL code or !commands.\n> ").await
            .map_err(|e| KslError::type_error(format!("Failed to write to stream: {}", e), pos, "REPL_WELCOME_ERROR".to_string()))?;

        loop {
            buffer.clear();
            if reader.read_line(&mut buffer).await
                .map_err(|e| KslError::type_error(format!("Failed to read from stream: {}", e), pos, "REPL_READ_ERROR".to_string()))? == 0 {
                break; // EOF
            }

            let input = buffer.trim();
            if input.is_empty() {
                continue;
            }

            if input == "exit" {
                writer.write_all(b"Goodbye!\n").await
                    .map_err(|e| KslError::type_error(format!("Failed to write to stream: {}", e), pos, "REPL_GOODBYE_ERROR".to_string()))?;
                break;
            }

            // Update session activity
            if let Some(session) = sessions.write().await.get_mut(&session_id) {
                session.last_active = std::time::Instant::now();
            }

            // Process command
            let response = if input.starts_with('!') {
                Self::handle_debug_command(input, &sessions, &session_id).await?
            } else {
                Self::execute_code(input, &sessions, &session_id, &network, &runtime).await?
            };

            // Send response
            writer.write_all(response.as_bytes()).await
                .map_err(|e| KslError::type_error(format!("Failed to write to stream: {}", e), pos, "REPL_RESPONSE_ERROR".to_string()))?;
            writer.write_all(b"> ").await
                .map_err(|e| KslError::type_error(format!("Failed to write to stream: {}", e), pos, "REPL_PROMPT_ERROR".to_string()))?;
            writer.flush().await
                .map_err(|e| KslError::type_error(format!("Failed to flush stream: {}", e), pos, "REPL_FLUSH_ERROR".to_string()))?;

            log_with_trace(Level::Info, &format!("Processed command for session {}: {}", session_id, input), None);
        }

        // Cleanup session
        sessions.write().await.remove(&session_id);
        Ok(())
    }

    /// Handles debug commands
    async fn handle_debug_command(
        input: &str,
        sessions: &Arc<RwLock<HashMap<String, SessionState>>>,
        session_id: &str,
    ) -> AsyncResult<String> {
        let command = input[1..].trim();
        let sessions = sessions.read().await;
        let session = sessions.get(session_id)
            .ok_or_else(|| KslError::type_error("Session not found".to_string(), SourcePosition::new(1, 1), "E401".to_string()))?;

        match command.split_whitespace().next().unwrap_or("") {
            "break" => {
                if let Some(line) = command.split_whitespace().nth(1) {
                    if let Ok(line_num) = line.parse::<usize>() {
                        let mut debugger = session.debugger.lock().await;
                        debugger.set_breakpoint(line_num);
                        Ok(format!("Breakpoint set at line {}\n", line_num))
                    } else {
                        Ok("Invalid line number\n".to_string())
                    }
                } else {
                    Ok("Usage: !break <line>\n".to_string())
                }
            }
            "inspect" => {
                let debugger = session.debugger.lock().await;
                Ok(format!("Variables: {:?}\n", debugger.inspect_variables()))
            }
            "continue" => {
                let mut debugger = session.debugger.lock().await;
                debugger.clear_breakpoints();
                Ok("Continuing execution\n".to_string())
            }
            "help" => Ok("Available commands:\n  !break <line> - Set breakpoint\n  !inspect - View variables\n  !continue - Resume execution\n  !help - Show this help\n".to_string()),
            _ => Ok("Unknown command. Use !help for available commands.\n".to_string()),
        }
    }

    /// Executes KSL code in a session
    async fn execute_code(
        code: &str,
        sessions: &Arc<RwLock<HashMap<String, SessionState>>>,
        session_id: &str,
        network: &Arc<NetworkManager>,
        runtime: &Arc<AsyncRuntime>,
    ) -> AsyncResult<String> {
        let pos = SourcePosition::new(1, 1);
        let sessions = sessions.read().await;
        let session = sessions.get(session_id)
            .ok_or_else(|| KslError::type_error("Session not found".to_string(), pos, "E401".to_string()))?;

        let mut repl = session.repl.write().await;
        match repl.eval_async(code, network, runtime).await {
            Ok(value) => {
                let debugger = session.debugger.lock().await;
                if debugger.should_break() {
                    Ok(format!("Hit breakpoint! Value: {:?}\nUse !inspect or !continue\n", value))
                } else {
                    Ok(format!("Result: {:?}\n", value))
                }
            }
            Err(e) => Ok(format!("Error: {}\n", e)),
        }
    }

    /// Cleans up inactive sessions
    async fn cleanup_sessions(sessions: Arc<RwLock<HashMap<String, SessionState>>>, timeout: u64) {
        let mut sessions = sessions.write().await;
        let now = std::time::Instant::now();
        sessions.retain(|_, session| {
            now.duration_since(session.last_active).as_secs() < timeout
        });
    }
}

/// Public API to start the REPL server asynchronously
pub async fn start_repl_server_async(config: ReplServerConfig) -> AsyncResult<()> {
    let server = ReplServer::new(config)?;
    server.start_async().await
}

// Module imports
mod ksl_repl {
    pub use super::{Repl, ReplConfig, ReplSession};
}

mod ksl_interpreter {
    pub use super::{Interpreter, Value};
}

mod ksl_debug {
    pub use super::{Debugger, DebugCommand};
}

mod ksl_logger {
    pub use super::{init_logger, log_with_trace, Level};
}

mod ksl_stdlib_net {
    pub use super::{NetworkManager, TcpConfig};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncResult};
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_repl_server_async() {
        let config = ReplServerConfig {
            port: 9000,
            max_sessions: 10,
            session_timeout: 3600,
            network_config: TcpConfig::default(),
        };

        // Start server
        let server = ReplServer::new(config.clone()).unwrap();
        tokio::spawn(async move {
            server.start_async().await.unwrap();
        });

        // Wait for server to start
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Connect client
        let mut stream = TcpStream::connect("127.0.0.1:9000").await.unwrap();
        
        // Test simple evaluation
        stream.write_all(b"1 + 1\n").await.unwrap();
        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).await.unwrap();
        assert!(String::from_utf8_lossy(&buffer[..n]).contains("2"));

        // Test debug command
        stream.write_all(b"!help\n").await.unwrap();
        let n = stream.read(&mut buffer).await.unwrap();
        assert!(String::from_utf8_lossy(&buffer[..n]).contains("Available commands"));

        // Test exit
        stream.write_all(b"exit\n").await.unwrap();
        let n = stream.read(&mut buffer).await.unwrap();
        assert!(String::from_utf8_lossy(&buffer[..n]).contains("Goodbye"));
    }

    #[tokio::test]
    async fn test_repl_server_session_limit() {
        let config = ReplServerConfig {
            port: 9001,
            max_sessions: 1,
            session_timeout: 3600,
            network_config: TcpConfig::default(),
        };

        // Start server
        let server = ReplServer::new(config.clone()).unwrap();
        tokio::spawn(async move {
            server.start_async().await.unwrap();
        });

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // First client should succeed
        let _stream1 = TcpStream::connect("127.0.0.1:9001").await.unwrap();

        // Second client should receive capacity error
        let mut stream2 = TcpStream::connect("127.0.0.1:9001").await.unwrap();
        let mut buffer = [0; 1024];
        let n = stream2.read(&mut buffer).await.unwrap();
        assert!(String::from_utf8_lossy(&buffer[..n]).contains("capacity"));
    }
}
