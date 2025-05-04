// ksl_doc_lsp.rs
// Integrates ksl_docgen.rs with ksl_lsp.rs to provide documentation in IDEs via LSP,
// serving hover and completion docs with caching and async support.

use crate::ksl_docgen::generate_docgen;
use crate::ksl_lsp::{start_lsp, LspServer};
use crate::ksl_ast_transform::{AstNode, AstTransformer};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Doc LSP configuration
#[derive(Debug, Clone)]
pub struct DocLspConfig {
    /// Port to listen on
    pub port: u16,
    /// Directory for cached documentation
    pub doc_cache_dir: PathBuf,
    /// Whether to use async operations
    pub use_async: bool,
}

/// Doc LSP server state
#[derive(Debug, Clone)]
pub struct DocLspState {
    /// Last processed AST node
    pub last_node: Option<AstNode>,
    /// Documentation cache
    pub doc_cache: HashMap<String, String>,
}

/// Doc LSP server for providing documentation in IDEs
pub struct DocLspServer {
    config: DocLspConfig,
    lsp_server: Arc<LspServer>,
    async_runtime: Arc<AsyncRuntime>,
    state: Arc<RwLock<DocLspState>>,
}

impl DocLspServer {
    /// Creates a new Doc LSP server
    pub fn new(config: DocLspConfig) -> Self {
        DocLspServer {
            config: config.clone(),
            lsp_server: Arc::new(LspServer::new(config.port)),
            async_runtime: Arc::new(AsyncRuntime::new()),
            state: Arc::new(RwLock::new(DocLspState {
                last_node: None,
                doc_cache: HashMap::new(),
            })),
        }
    }

    /// Start the Doc LSP server asynchronously
    pub async fn start_async(&self) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        // Preload documentation for standard library
        self.preload_docs_async().await?;

        // Start LSP server with custom hover handler
        self.lsp_server.start_async().await?;
        Ok(())
    }

    /// Preload documentation into cache asynchronously
    async fn preload_docs_async(&self) -> AsyncResult<()> {
        let pos = SourcePosition::new(1, 1);
        // Generate documentation for standard library
        let temp_file = self.config.doc_cache_dir.join("std_temp.ksl");
        let mut file = File::create(&temp_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to create temp file {}: {}", temp_file.display(), e),
                pos,
            ))?;
        writeln!(
            file,
            "/// Computes the SHA-3 hash\n/// See [matrix.mul](...) for related ops\nfn sha3(data: string): array<u8, 32> {{}}\n/// Matrix multiplication\nfn matrix.mul(a: array<array<f64, 4>, 4>, b: array<array<f64, 4>, 4>): array<array<f64, 4>, 4> {{}}\n/// Reads IoT sensor data\nfn device.sensor(id: u32): f32 {{}}"
        ).map_err(|e| KslError::type_error(
            format!("Failed to write temp file {}: {}", temp_file.display(), e),
            pos,
        ))?;

        generate_docgen("std", "markdown", self.config.doc_cache_dir.clone())?;
        let doc_file = self.config.doc_cache_dir.join("std.md");
        let content = fs::read_to_string(&doc_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to read doc file {}: {}", doc_file.display(), e),
                pos,
            ))?;

        // Parse documentation into cache
        let mut state = self.state.write().await;
        let mut current_func = None;
        let mut current_doc = String::new();
        for line in content.lines() {
            if line.starts_with("## Function `") {
                if let Some(func) = current_func {
                    state.doc_cache.insert(func, current_doc.trim().to_string());
                }
                current_func = Some(line[12..line.len()-1].to_string());
                current_doc = String::new();
            } else if current_func.is_some() {
                current_doc.push_str(line);
                current_doc.push('\n');
            }
        }
        if let Some(func) = current_func {
            state.doc_cache.insert(func, current_doc.trim().to_string());
        }
        drop(state);

        // Clean up temp file
        fs::remove_file(&temp_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to clean up temp file {}: {}", temp_file.display(), e),
                pos,
            ))?;
        Ok(())
    }

    /// Get documentation for a function asynchronously
    pub async fn get_doc_async(&self, func_name: &str) -> AsyncResult<Option<String>> {
        let state = self.state.read().await;
        Ok(state.doc_cache.get(func_name).cloned())
    }

    /// Process AST node and update documentation asynchronously
    pub async fn process_ast_node_async(&self, node: AstNode) -> AsyncResult<()> {
        let mut state = self.state.write().await;
        state.last_node = Some(node.clone());
        
        // Generate documentation for the node
        let doc = AstTransformer::generate_doc(&node)?;
        if let Some(name) = node.get_name() {
            state.doc_cache.insert(name, doc);
        }
        Ok(())
    }

    /// Get the last processed AST node
    pub async fn last_node(&self) -> Option<AstNode> {
        self.state.read().await.last_node.clone()
    }
}

/// Public API to start the Doc LSP server asynchronously
pub async fn start_doc_lsp_async(port: u16, doc_cache_dir: PathBuf) -> AsyncResult<()> {
    let pos = SourcePosition::new(1, 1);
    if port < 1024 || port > 65535 {
        return Err(KslError::type_error(
            "Port must be between 1024 and 65535".to_string(),
            pos,
        ));
    }

    let config = DocLspConfig {
        port,
        doc_cache_dir,
        use_async: true,
    };
    let server = DocLspServer::new(config);
    server.start_async().await
}

// Assume ksl_docgen.rs, ksl_lsp.rs, ksl_ast_transform.rs, ksl_async.rs, and ksl_errors.rs are in the same crate
mod ksl_docgen {
    pub use super::generate_docgen;
}

mod ksl_lsp {
    pub use super::{start_lsp, LspServer};
}

mod ksl_ast_transform {
    pub use super::{AstNode, AstTransformer};
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
    use std::io::Read;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_doc_lsp_preload_async() {
        let temp_dir = TempDir::new().unwrap();
        let doc_cache_dir = temp_dir.path().join("docs");
        fs::create_dir_all(&doc_cache_dir).unwrap();

        let config = DocLspConfig {
            port: 9002,
            doc_cache_dir: doc_cache_dir.clone(),
            use_async: true,
        };
        let server = DocLspServer::new(config);

        let result = server.preload_docs_async().await;
        assert!(result.is_ok());

        let doc_file = doc_cache_dir.join("std.md");
        assert!(doc_file.exists());
        let content = fs::read_to_string(&doc_file).unwrap();
        assert!(content.contains("## Function `sha3`"));
        assert!(content.contains("## Function `matrix.mul`"));
        assert!(content.contains("## Function `device.sensor`"));

        let doc = server.get_doc_async("sha3").await.unwrap();
        assert!(doc.is_some());
        let doc_content = doc.unwrap();
        assert!(doc_content.contains("Computes the SHA-3 hash"));
        assert!(doc_content.contains("[matrix.mul](...)")); // Cross-reference
    }

    #[tokio::test]
    async fn test_doc_lsp_invalid_port_async() {
        let temp_dir = TempDir::new().unwrap();
        let doc_cache_dir = temp_dir.path().join("docs");

        let result = start_doc_lsp_async(80, doc_cache_dir).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Port must be between 1024 and 65535"));
    }

    #[tokio::test]
    async fn test_doc_lsp_get_doc_missing_async() {
        let temp_dir = TempDir::new().unwrap();
        let doc_cache_dir = temp_dir.path().join("docs");
        fs::create_dir_all(&doc_cache_dir).unwrap();

        let config = DocLspConfig {
            port: 9002,
            doc_cache_dir: doc_cache_dir.clone(),
            use_async: true,
        };
        let server = DocLspServer::new(config);

        let _ = server.preload_docs_async().await;
        let doc = server.get_doc_async("nonexistent").await.unwrap();
        assert!(doc.is_none());
    }

    #[tokio::test]
    async fn test_doc_lsp_process_ast_node_async() {
        let temp_dir = TempDir::new().unwrap();
        let doc_cache_dir = temp_dir.path().join("docs");
        fs::create_dir_all(&doc_cache_dir).unwrap();

        let config = DocLspConfig {
            port: 9002,
            doc_cache_dir: doc_cache_dir.clone(),
            use_async: true,
        };
        let server = DocLspServer::new(config);

        let node = AstNode::new_function("test_func", vec![]);
        let result = server.process_ast_node_async(node.clone()).await;
        assert!(result.is_ok());

        let last_node = server.last_node().await;
        assert!(last_node.is_some());
        assert_eq!(last_node.unwrap().get_name().unwrap(), "test_func");
    }
}
