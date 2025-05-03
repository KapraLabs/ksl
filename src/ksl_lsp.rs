// ksl_lsp.rs
// Implements a Language Server Protocol (LSP) server for KSL, providing IDE features
// like autocompletion, go-to-definition, hover documentation, and diagnostics.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_linter::{LintError, lint};
use crate::ksl_docgen::generate_docgen;
use crate::ksl_errors::{KslError, SourcePosition};
use serde_json::{json, Value as JsonValue};
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write, BufReader, BufRead};
use std::thread;
use std::path::PathBuf;
use std::collections::HashMap;

// LSP server configuration
#[derive(Debug)]
pub struct LspServerConfig {
    port: u16, // Port to listen on
}

// LSP server
pub struct LspServer {
    config: LspServerConfig,
    documents: HashMap<String, String>, // URI -> Document content
}

impl LspServer {
    pub fn new(config: LspServerConfig) -> Self {
        LspServer {
            config,
            documents: HashMap::new(),
        }
    }

    // Start the LSP server
    pub fn start(&mut self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let listener = TcpListener::bind(("127.0.0.1", self.config.port))
            .map_err(|e| KslError::type_error(
                format!("Failed to bind to port {}: {}", self.config.port, e),
                pos,
            ))?;
        println!("LSP server started on port {}", self.config.port);

        for stream in listener.incoming() {
            let stream = stream.map_err(|e| KslError::type_error(
                format!("Failed to accept connection: {}", e),
                pos,
            ))?;
            let mut server = self.clone();
            thread::spawn(move || {
                if let Err(e) = server.handle_client(stream) {
                    println!("Client error: {}", e);
                }
            });
        }

        Ok(())
    }

    // Handle a single client connection
    fn handle_client(&mut self, mut stream: TcpStream) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut reader = BufReader::new(&stream);
        let mut buffer = String::new();

        loop {
            buffer.clear();
            let bytes_read = reader.read_line(&mut buffer)
                .map_err(|e| KslError::type_error(format!("Failed to read from stream: {}", e), pos))?;
            if bytes_read == 0 {
                break; // Client disconnected
            }

            // Parse Content-Length header
            if !buffer.starts_with("Content-Length:") {
                continue;
            }
            let content_length: usize = buffer[15..].trim()
                .parse()
                .map_err(|e| KslError::type_error(format!("Invalid Content-Length: {}", e), pos))?;
            reader.read_line(&mut buffer) // Skip empty line
                .map_err(|e| KslError::type_error(format!("Failed to read from stream: {}", e), pos))?;

            // Read the JSON-RPC message
            let mut message_bytes = vec![0; content_length];
            reader.read_exact(&mut message_bytes)
                .map_err(|e| KslError::type_error(format!("Failed to read message: {}", e), pos))?;
            let message: JsonValue = serde_json::from_slice(&message_bytes)
                .map_err(|e| KslError::type_error(format!("Failed to parse JSON-RPC message: {}", e), pos))?;

            // Process the LSP request
            let response = self.handle_request(&message)?;
            let response_bytes = serde_json::to_vec(&response)
                .map_err(|e| KslError::type_error(format!("Failed to serialize response: {}", e), pos))?;
            let response_header = format!("Content-Length: {}\r\n\r\n", response_bytes.len());
            stream.write_all(response_header.as_bytes())
                .map_err(|e| KslError::type_error(format!("Failed to write to stream: {}", e), pos))?;
            stream.write_all(&response_bytes)
                .map_err(|e| KslError::type_error(format!("Failed to write to stream: {}", e), pos))?;
            stream.flush()
                .map_err(|e| KslError::type_error(format!("Failed to flush stream: {}", e), pos))?;
        }

        Ok(())
    }

    // Handle an LSP request
    fn handle_request(&mut self, request: &JsonValue) -> Result<JsonValue, KslError> {
        let pos = SourcePosition::new(1, 1);
        let id = request.get("id")
            .ok_or_else(|| KslError::type_error("Missing request ID".to_string(), pos))?;
        let method = request.get("method")
            .and_then(|m| m.as_str())
            .ok_or_else(|| KslError::type_error("Missing or invalid method".to_string(), pos))?;
        let params = request.get("params").unwrap_or(&json!({}));

        match method {
            "initialize" => {
                Ok(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "capabilities": {
                            "textDocumentSync": 1,
                            "completionProvider": {},
                            "definitionProvider": true,
                            "hoverProvider": true
                        }
                    }
                }))
            }
            "textDocument/didOpen" => {
                let uri = params.get("textDocument")
                    .and_then(|doc| doc.get("uri"))
                    .and_then(|uri| uri.as_str())
                    .ok_or_else(|| KslError::type_error("Missing URI".to_string(), pos))?;
                let text = params.get("textDocument")
                    .and_then(|doc| doc.get("text"))
                    .and_then(|text| text.as_str())
                    .ok_or_else(|| KslError::type_error("Missing text".to_string(), pos))?;
                self.documents.insert(uri.to_string(), text.to_string());

                // Publish diagnostics
                let diagnostics = self.generate_diagnostics(uri, text)?;
                Ok(json!({
                    "jsonrpc": "2.0",
                    "method": "textDocument/publishDiagnostics",
                    "params": {
                        "uri": uri,
                        "diagnostics": diagnostics
                    }
                }))
            }
            "textDocument/completion" => {
                let uri = params.get("textDocument")
                    .and_then(|doc| doc.get("uri"))
                    .and_then(|uri| uri.as_str())
                    .ok_or_else(|| KslError::type_error("Missing URI".to_string(), pos))?;
                let text = self.documents.get(uri)
                    .ok_or_else(|| KslError::type_error(format!("Document not found: {}", uri), pos))?;
                let completions = self.generate_completions(text)?;
                Ok(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": completions
                }))
            }
            "textDocument/definition" => {
                let uri = params.get("textDocument")
                    .and_then(|doc| doc.get("uri"))
                    .and_then(|uri| uri.as_str())
                    .ok_or_else(|| KslError::type_error("Missing URI".to_string(), pos))?;
                let position = params.get("position")
                    .ok_or_else(|| KslError::type_error("Missing position".to_string(), pos))?;
                let line = position.get("line")
                    .and_then(|l| l.as_u64())
                    .ok_or_else(|| KslError::type_error("Invalid line".to_string(), pos))? as usize;
                let character = position.get("character")
                    .and_then(|c| c.as_u64())
                    .ok_or_else(|| KslError::type_error("Invalid character".to_string(), pos))? as usize;
                let text = self.documents.get(uri)
                    .ok_or_else(|| KslError::type_error(format!("Document not found: {}", uri), pos))?;
                let definition = self.goto_definition(text, line, character)?;
                Ok(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": definition
                }))
            }
            "textDocument/hover" => {
                let uri = params.get("textDocument")
                    .and_then(|doc| doc.get("uri"))
                    .and_then(|uri| uri.as_str())
                    .ok_or_else(|| KslError::type_error("Missing URI".to_string(), pos))?;
                let position = params.get("position")
                    .ok_or_else(|| KslError::type_error("Missing position".to_string(), pos))?;
                let line = position.get("line")
                    .and_then(|l| l.as_u64())
                    .ok_or_else(|| KslError::type_error("Invalid line".to_string(), pos))? as usize;
                let character = position.get("character")
                    .and_then(|c| c.as_u64())
                    .ok_or_else(|| KslError::type_error("Invalid character".to_string(), pos))? as usize;
                let text = self.documents.get(uri)
                    .ok_or_else(|| KslError::type_error(format!("Document not found: {}", uri), pos))?;
                let hover = self.hover(text, line, character)?;
                Ok(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": hover
                }))
            }
            "shutdown" => {
                Ok(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": null
                }))
            }
            "exit" => {
                std::process::exit(0);
            }
            _ => Ok(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "Method not found"
                }
            }))
        }
    }

    // Generate diagnostics for a document
    fn generate_diagnostics(&self, uri: &str, text: &str) -> Result<Vec<JsonValue>, KslError> {
        let pos = SourcePosition::new(1, 1);
        // Use ksl_linter.rs to generate diagnostics (simplified)
        let lint_errors = match lint(text) {
            Ok(errors) => errors,
            Err(_) => vec![],
        };
        let diagnostics: Vec<JsonValue> = lint_errors.into_iter()
            .map(|err| {
                json!({
                    "range": {
                        "start": {
                            "line": err.position.line - 1,
                            "character": err.position.column - 1
                        },
                        "end": {
                            "line": err.position.line - 1,
                            "character": err.position.column
                        }
                    },
                    "severity": 1, // Error
                    "message": err.message
                })
            })
            .collect();
        Ok(diagnostics)
    }

    // Generate completions for a document
    fn generate_completions(&self, text: &str) -> Result<Vec<JsonValue>, KslError> {
        let pos = SourcePosition::new(1, 1);
        let ast = parse(text)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;

        let mut completions = Vec::new();
        let mut identifiers = HashSet::new();

        // Collect identifiers from the AST
        for node in &ast {
            match node {
                AstNode::FnDecl { name, .. } => {
                    identifiers.insert(name.clone());
                }
                AstNode::VarDecl { name, .. } => {
                    identifiers.insert(name.clone());
                }
                _ => {}
            }
        }

        // Add standard library functions
        identifiers.insert("sha3".to_string());
        identifiers.insert("matrix.mul".to_string());
        identifiers.insert("device.sensor".to_string());

        // Add keywords
        identifiers.insert("fn".to_string());
        identifiers.insert("let".to_string());
        identifiers.insert("if".to_string());
        identifiers.insert("match".to_string());

        for ident in identifiers {
            completions.push(json!({
                "label": ident,
                "kind": if ident.starts_with("fn") || ident.contains('.') { 3 } else { 6 }, // Function or Variable
                "detail": if ident.contains('.') { "Standard library function" } else { "Local identifier" }
            }));
        }

        Ok(completions)
    }

    // Handle go-to-definition request
    fn goto_definition(&self, text: &str, line: usize, character: usize) -> Result<JsonValue, KslError> {
        let pos = SourcePosition::new(1, 1);
        let ast = parse(text)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;

        // Find the identifier at the given position (simplified: check line only)
        let mut target_ident = None;
        for (line_num, text_line) in text.lines().enumerate() {
            if line_num == line {
                let start = character.saturating_sub(10);
                let end = (character + 10).min(text_line.len());
                let snippet = &text_line[start..end];
                for word in snippet.split_whitespace() {
                    if word.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        target_ident = Some(word.to_string());
                        break;
                    }
                }
                break;
            }
        }

        if let Some(ident) = target_ident {
            // Find the definition in the AST
            for node in &ast {
                match node {
                    AstNode::FnDecl { name, .. } if name == &ident => {
                        return Ok(json!({
                            "uri": "file://current_document.ksl",
                            "range": {
                                "start": { "line": 0, "character": 0 },
                                "end": { "line": 0, "character": ident.len() }
                            }
                        }));
                    }
                    AstNode::VarDecl { name, .. } if name == &ident => {
                        return Ok(json!({
                            "uri": "file://current_document.ksl",
                            "range": {
                                "start": { "line": 0, "character": 0 },
                                "end": { "line": 0, "character": ident.len() }
                            }
                        }));
                    }
                    _ => {}
                }
            }

            // Check standard library functions
            if ident == "sha3" || ident == "matrix.mul" || ident == "device.sensor" {
                return Ok(json!({
                    "uri": "file://stdlib.ksl",
                    "range": {
                        "start": { "line": 0, "character": 0 },
                        "end": { "line": 0, "character": ident.len() }
                    }
                }));
            }
        }

        Ok(json!({})) // No definition found
    }

    // Handle hover request
    fn hover(&self, text: &str, line: usize, character: usize) -> Result<JsonValue, KslError> {
        let pos = SourcePosition::new(1, 1);
        let ast = parse(text)
            .map_err(|e| KslError::type_error(
                format!("Parse error at position {}: {}", e.position, e.message),
                pos,
            ))?;

        // Find the identifier at the given position (simplified: check line only)
        let mut target_ident = None;
        for (line_num, text_line) in text.lines().enumerate() {
            if line_num == line {
                let start = character.saturating_sub(10);
                let end = (character + 10).min(text_line.len());
                let snippet = &text_line[start..end];
                for word in snippet.split_whitespace() {
                    if word.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        target_ident = Some(word.to_string());
                        break;
                    }
                }
                break;
            }
        }

        if let Some(ident) = target_ident {
            // Find documentation in the AST
            for node in &ast {
                if let AstNode::FnDecl { name, doc, params, return_type, .. } = node {
                    if name == &ident {
                        let mut contents = String::new();
                        if let Some(doc) = doc {
                            contents.push_str(&format!("{}\n", doc.text));
                        }
                        contents.push_str(&format!("**fn {}({}) -> {}**", name, params.iter()
                            .map(|(p, t)| format!("{}: {}", p, t))
                            .collect::<Vec<_>>()
                            .join(", "), return_type));
                        return Ok(json!({
                            "contents": {
                                "kind": "markdown",
                                "value": contents
                            }
                        }));
                    }
                }
            }

            // Simulate ksl_docgen.rs for standard library functions
            if ident == "sha3" {
                return Ok(json!({
                    "contents": {
                        "kind": "markdown",
                        "value": "**sha3(data: string) -> array<u8, 32>**\n\nComputes the SHA-3 hash of the input data."
                    }
                }));
            } else if ident == "matrix.mul" {
                return Ok(json!({
                    "contents": {
                        "kind": "markdown",
                        "value": "**matrix.mul(a: array<array<f64, N>, N>, b: array<array<f64, N>, N>) -> array<array<f64, N>, N>**\n\nPerforms matrix multiplication."
                    }
                }));
            } else if ident == "device.sensor" {
                return Ok(json!({
                    "contents": {
                        "kind": "markdown",
                        "value": "**device.sensor(id: u32) -> f32**\n\nReads data from an IoT sensor."
                    }
                }));
            }
        }

        Ok(json!({})) // No hover info
    }
}

// Public API to start the LSP server
pub fn start_lsp(port: u16) -> Result<(), KslError> {
    let config = LspServerConfig { port };
    let mut server = LspServer::new(config);
    server.start()
}

// Assume ksl_parser.rs, ksl_linter.rs, ksl_docgen.rs, and ksl_errors.rs are in the same crate
mod ksl_parser {
    pub use super::{parse, AstNode, ExprKind, ParseError};
}

mod ksl_linter {
    pub use super::{LintError, lint};
}

mod ksl_docgen {
    pub use super::generate_docgen;
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
    fn test_lsp_server() {
        // Start LSP server in a separate thread
        thread::spawn(|| {
            start_lsp(9001).unwrap();
        });

        // Give the server a moment to start
        thread::sleep(Duration::from_millis(100));

        // Connect to the server
        let mut stream = TcpStream::connect("127.0.0.1:9001").unwrap();

        // Send initialize request
        let init_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let init_message = serde_json::to_string(&init_request).unwrap();
        let init_header = format!("Content-Length: {}\r\n\r\n", init_message.len());
        stream.write_all(init_header.as_bytes()).unwrap();
        stream.write_all(init_message.as_bytes()).unwrap();
        stream.flush().unwrap();

        // Read response
        let mut buffer = [0; 1024];
        let bytes_read = stream.read(&mut buffer).unwrap();
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
        assert!(response.contains("\"completionProvider\": {}"));

        // Send didOpen request
        let did_open_request = json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file://test.ksl",
                    "languageId": "ksl",
                    "version": 1,
                    "text": "fn main() { let x: u32 = 42; }"
                }
            }
        });
        let did_open_message = serde_json::to_string(&did_open_request).unwrap();
        let did_open_header = format!("Content-Length: {}\r\n\r\n", did_open_message.len());
        stream.write_all(did_open_header.as_bytes()).unwrap();
        stream.write_all(did_open_message.as_bytes()).unwrap();
        stream.flush().unwrap();

        // Read diagnostics response
        let bytes_read = stream.read(&mut buffer).unwrap();
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
        assert!(response.contains("textDocument/publishDiagnostics"));

        // Send completion request
        let completion_request = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {
                    "uri": "file://test.ksl"
                },
                "position": {
                    "line": 0,
                    "character": 10
                }
            }
        });
        let completion_message = serde_json::to_string(&completion_request).unwrap();
        let completion_header = format!("Content-Length: {}\r\n\r\n", completion_message.len());
        stream.write_all(completion_header.as_bytes()).unwrap();
        stream.write_all(completion_message.as_bytes()).unwrap();
        stream.flush().unwrap();

        let bytes_read = stream.read(&mut buffer).unwrap();
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
        assert!(response.contains("\"label\": \"main\""));
        assert!(response.contains("\"label\": \"sha3\""));

        // Send hover request
        let hover_request = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {
                    "uri": "file://test.ksl"
                },
                "position": {
                    "line": 0,
                    "character": 3
                }
            }
        });
        let hover_message = serde_json::to_string(&hover_request).unwrap();
        let hover_header = format!("Content-Length: {}\r\n\r\n", hover_message.len());
        stream.write_all(hover_header.as_bytes()).unwrap();
        stream.write_all(hover_message.as_bytes()).unwrap();
        stream.flush().unwrap();

        let bytes_read = stream.read(&mut buffer).unwrap();
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
        assert!(response.contains("fn main()"));

        // Send shutdown and exit
        let shutdown_request = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "shutdown",
            "params": {}
        });
        let shutdown_message = serde_json::to_string(&shutdown_request).unwrap();
        let shutdown_header = format!("Content-Length: {}\r\n\r\n", shutdown_message.len());
        stream.write_all(shutdown_header.as_bytes()).unwrap();
        stream.write_all(shutdown_message.as_bytes()).unwrap();
        stream.flush().unwrap();

        let exit_request = json!({
            "jsonrpc": "2.0",
            "method": "exit",
            "params": {}
        });
        let exit_message = serde_json::to_string(&exit_request).unwrap();
        let exit_header = format!("Content-Length: {}\r\n\r\n", exit_message.len());
        stream.write_all(exit_header.as_bytes()).unwrap();
        stream.write_all(exit_message.as_bytes()).unwrap();
        stream.flush().unwrap();
    }
}
