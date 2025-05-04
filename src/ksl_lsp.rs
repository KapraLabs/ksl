// ksl_lsp.rs
// Implements a Language Server Protocol (LSP) server for KSL, providing IDE features
// like autocompletion, go-to-definition, hover documentation, and diagnostics.
// Supports async operations, enhanced analysis, and new language features.

use crate::ksl_parser::{parse, AstNode, ExprKind, ParseError};
use crate::ksl_linter::{LintError, lint};
use crate::ksl_docgen::generate_docgen;
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_analyzer::{Analyzer, AnalysisResult};
use crate::ksl_async::{AsyncRuntime, AsyncVM};
use serde_json::{json, Value as JsonValue};
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write, BufReader, BufRead};
use std::thread;
use std::path::PathBuf;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

/// LSP server configuration with async support
#[derive(Debug)]
pub struct LspServerConfig {
    /// Port to listen on
    port: u16,
    /// Whether to enable async operations
    enable_async: bool,
    /// Analyzer configuration
    analyzer_config: Option<AnalyzerConfig>,
}

/// Analyzer configuration for enhanced diagnostics
#[derive(Debug)]
pub struct AnalyzerConfig {
    /// Whether to perform type inference
    enable_type_inference: bool,
    /// Whether to check for async safety
    check_async_safety: bool,
    /// Whether to analyze network operations
    analyze_network_ops: bool,
}

/// Enhanced LSP server with async support
pub struct LspServer {
    config: LspServerConfig,
    documents: HashMap<String, String>, // URI -> Document content
    analyzer: Option<Analyzer>,
    async_runtime: Arc<RwLock<AsyncRuntime>>,
    analysis_cache: Arc<Mutex<HashMap<String, AnalysisResult>>>, // URI -> Analysis result
}

impl LspServer {
    /// Create a new LSP server with the given configuration
    pub fn new(config: LspServerConfig) -> Self {
        LspServer {
            config,
            documents: HashMap::new(),
            analyzer: if config.analyzer_config.is_some() {
                Some(Analyzer::new())
            } else {
                None
            },
            async_runtime: Arc::new(RwLock::new(AsyncRuntime::new())),
            analysis_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start the LSP server with async support
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

    /// Handle a single client connection with async support
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
            let response = if self.config.enable_async {
                // Run async request handling
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(self.handle_request_async(&message))?
            } else {
                // Run sync request handling
                self.handle_request(&message)?
            };

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

    /// Handle an LSP request asynchronously
    async fn handle_request_async(&mut self, request: &JsonValue) -> Result<JsonValue, KslError> {
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
                            "completionProvider": {
                                "resolveProvider": true,
                                "triggerCharacters": [".", ":"]
                            },
                            "definitionProvider": true,
                            "hoverProvider": true,
                            "referencesProvider": true,
                            "documentSymbolProvider": true,
                            "workspaceSymbolProvider": true,
                            "codeActionProvider": true,
                            "documentFormattingProvider": true,
                            "documentRangeFormattingProvider": true,
                            "documentHighlightProvider": true,
                            "renameProvider": true
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

                // Run async analysis if enabled
                if let Some(analyzer) = &self.analyzer {
                    let analysis = analyzer.analyze_async(text).await?;
                    let mut cache = self.analysis_cache.lock().unwrap();
                    cache.insert(uri.to_string(), analysis);
                }

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

    /// Generate diagnostics for a document with analyzer support
    fn generate_diagnostics(&self, uri: &str, text: &str) -> Result<Vec<JsonValue>, KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut diagnostics = Vec::new();

        // Get lint errors
        let lint_errors = match lint(text) {
            Ok(errors) => errors,
            Err(_) => vec![],
        };
        diagnostics.extend(lint_errors.into_iter().map(|err| {
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
        }));

        // Get analyzer diagnostics if enabled
        if let Some(analyzer) = &self.analyzer {
            let cache = self.analysis_cache.lock().unwrap();
            if let Some(analysis) = cache.get(uri) {
                diagnostics.extend(analysis.diagnostics.iter().map(|diag| {
                    json!({
                        "range": {
                            "start": {
                                "line": diag.range.start.line - 1,
                                "character": diag.range.start.column - 1
                            },
                            "end": {
                                "line": diag.range.end.line - 1,
                                "character": diag.range.end.column
                            }
                        },
                        "severity": diag.severity as i32,
                        "message": diag.message
                    })
                }));
            }
        }

        Ok(diagnostics)
    }

    /// Generate completions for a document with new language features
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
                AstNode::AsyncFnDecl { name, .. } => {
                    identifiers.insert(name.clone());
                }
                AstNode::Network { name, .. } => {
                    identifiers.insert(name.clone());
                }
                _ => {}
            }
        }

        // Add standard library functions
        identifiers.insert("sha3".to_string());
        identifiers.insert("matrix.mul".to_string());
        identifiers.insert("device.sensor".to_string());
        identifiers.insert("network.send".to_string());
        identifiers.insert("async.await".to_string());

        // Add keywords
        identifiers.insert("fn".to_string());
        identifiers.insert("let".to_string());
        identifiers.insert("if".to_string());
        identifiers.insert("match".to_string());
        identifiers.insert("async".to_string());
        identifiers.insert("await".to_string());
        identifiers.insert("network".to_string());

        for ident in identifiers {
            completions.push(json!({
                "label": ident,
                "kind": if ident.starts_with("fn") || ident.contains('.') { 3 } else { 6 }, // Function or Variable
                "detail": if ident.contains('.') { "Standard library function" } else { "Local identifier" }
            }));
        }

        Ok(completions)
    }

    /// Handle go-to-definition request with new language features
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
                    AstNode::AsyncFnDecl { name, .. } if name == &ident => {
                        return Ok(json!({
                            "uri": "file://current_document.ksl",
                            "range": {
                                "start": { "line": 0, "character": 0 },
                                "end": { "line": 0, "character": ident.len() }
                            }
                        }));
                    }
                    AstNode::Network { name, .. } if name == &ident => {
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
            if ident == "sha3" || ident == "matrix.mul" || ident == "device.sensor" || 
               ident == "network.send" || ident == "async.await" {
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

    /// Handle hover request with new language features
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
                match node {
                    AstNode::FnDecl { name, doc, params, return_type, .. } if name == &ident => {
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
                    AstNode::AsyncFnDecl { name, doc, params, return_type, .. } if name == &ident => {
                        let mut contents = String::new();
                        if let Some(doc) = doc {
                            contents.push_str(&format!("{}\n", doc.text));
                        }
                        contents.push_str(&format!("**async fn {}({}) -> {}**", name, params.iter()
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
                    AstNode::Network { name, doc, .. } if name == &ident => {
                        let mut contents = String::new();
                        if let Some(doc) = doc {
                            contents.push_str(&format!("{}\n", doc.text));
                        }
                        contents.push_str(&format!("**network {}**", name));
                        return Ok(json!({
                            "contents": {
                                "kind": "markdown",
                                "value": contents
                            }
                        }));
                    }
                    _ => {}
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
            } else if ident == "network.send" {
                return Ok(json!({
                    "contents": {
                        "kind": "markdown",
                        "value": "**network.send(data: string) -> result<(), string>**\n\nSends data over the network."
                    }
                }));
            } else if ident == "async.await" {
                return Ok(json!({
                    "contents": {
                        "kind": "markdown",
                        "value": "**async.await(expr: async T) -> T**\n\nAwaits an async expression."
                    }
                }));
            }
        }

        Ok(json!({})) // No hover info
    }
}

// Public API to start the LSP server with async support
pub fn start_lsp(port: u16, enable_async: bool, analyzer_config: Option<AnalyzerConfig>) -> Result<(), KslError> {
    let config = LspServerConfig {
        port,
        enable_async,
        analyzer_config,
    };
    let mut server = LspServer::new(config);
    server.start()
}

// Assume ksl_parser.rs, ksl_linter.rs, ksl_docgen.rs, ksl_errors.rs, ksl_analyzer.rs, and ksl_async.rs are in the same crate
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

mod ksl_analyzer {
    pub use super::{Analyzer, AnalysisResult, AnalyzerConfig};
}

mod ksl_async {
    pub use super::{AsyncRuntime, AsyncVM};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use std::thread;
    use std::time::Duration;

    #[tokio::test]
    async fn test_lsp_server_async() {
        // Start LSP server in a separate thread
        thread::spawn(|| {
            start_lsp(9001, true, Some(AnalyzerConfig {
                enable_type_inference: true,
                check_async_safety: true,
                analyze_network_ops: true,
            })).unwrap();
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
        assert!(response.contains("\"async\": true"));

        // Send didOpen request with async code
        let did_open_request = json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file://test.ksl",
                    "languageId": "ksl",
                    "version": 1,
                    "text": "async fn main() { let x: u32 = 42; }"
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
    }
}
