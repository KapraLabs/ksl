// ksl_doc_lsp.rs
// Integrates ksl_docgen.rs with ksl_lsp.rs to provide documentation in IDEs via LSP,
// serving hover and completion docs with caching.

use crate::ksl_docgen::generate_docgen;
use crate::ksl_lsp::start_lsp;
use crate::ksl_errors::{KslError, SourcePosition};
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// Doc LSP configuration
#[derive(Debug)]
pub struct DocLspConfig {
    port: u16, // Port to listen on
    doc_cache_dir: PathBuf, // Directory for cached documentation
}

// Doc LSP server
pub struct DocLspServer {
    config: DocLspConfig,
    doc_cache: Arc<Mutex<HashMap<String, String>>>, // Cache of documentation (function -> doc)
}

impl DocLspServer {
    pub fn new(config: DocLspConfig) -> Self {
        DocLspServer {
            config,
            doc_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // Start the Doc LSP server
    pub fn start(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Preload documentation for standard library
        self.preload_docs()?;

        // Start LSP server with custom hover handler
        start_lsp(self.config.port)?;
        Ok(())
    }

    // Preload documentation into cache
    fn preload_docs(&self) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        // Generate documentation for standard library (simulated)
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
        let mut cache = self.doc_cache.lock().unwrap();
        let mut current_func = None;
        let mut current_doc = String::new();
        for line in content.lines() {
            if line.starts_with("## Function `") {
                if let Some(func) = current_func {
                    cache.insert(func, current_doc.trim().to_string());
                }
                current_func = Some(line[12..line.len()-1].to_string());
                current_doc = String::new();
            } else if current_func.is_some() {
                current_doc.push_str(line);
                current_doc.push('\n');
            }
        }
        if let Some(func) = current_func {
            cache.insert(func, current_doc.trim().to_string());
        }

        // Clean up temp file
        fs::remove_file(&temp_file)
            .map_err(|e| KslError::type_error(
                format!("Failed to clean up temp file {}: {}", temp_file.display(), e),
                pos,
            ))?;
        Ok(())
    }

    // Get documentation for a function (used by LSP server)
    pub fn get_doc(&self, func_name: &str) -> Option<String> {
        let cache = self.doc_cache.lock().unwrap();
        cache.get(func_name).cloned()
    }
}

// Public API to start the Doc LSP server
pub fn start_doc_lsp(port: u16, doc_cache_dir: PathBuf) -> Result<(), KslError> {
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
    };
    let server = DocLspServer::new(config);
    server.start()
}

// Assume ksl_docgen.rs, ksl_lsp.rs, and ksl_errors.rs are in the same crate
mod ksl_docgen {
    pub use super::generate_docgen;
}

mod ksl_lsp {
    pub use super::start_lsp;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_doc_lsp_preload() {
        let temp_dir = TempDir::new().unwrap();
        let doc_cache_dir = temp_dir.path().join("docs");
        fs::create_dir_all(&doc_cache_dir).unwrap();

        let config = DocLspConfig {
            port: 9002,
            doc_cache_dir: doc_cache_dir.clone(),
        };
        let server = DocLspServer::new(config);

        let result = server.preload_docs();
        assert!(result.is_ok());

        let doc_file = doc_cache_dir.join("std.md");
        assert!(doc_file.exists());
        let content = fs::read_to_string(&doc_file).unwrap();
        assert!(content.contains("## Function `sha3`"));
        assert!(content.contains("## Function `matrix.mul`"));
        assert!(content.contains("## Function `device.sensor`"));

        let doc = server.get_doc("sha3");
        assert!(doc.is_some());
        let doc_content = doc.unwrap();
        assert!(doc_content.contains("Computes the SHA-3 hash"));
        assert!(doc_content.contains("[matrix.mul](...)")); // Cross-reference
    }

    #[test]
    fn test_doc_lsp_invalid_port() {
        let temp_dir = TempDir::new().unwrap();
        let doc_cache_dir = temp_dir.path().join("docs");

        let result = start_doc_lsp(80, doc_cache_dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Port must be between 1024 and 65535"));
    }

    #[test]
    fn test_doc_lsp_get_doc_missing() {
        let temp_dir = TempDir::new().unwrap();
        let doc_cache_dir = temp_dir.path().join("docs");
        fs::create_dir_all(&doc_cache_dir).unwrap();

        let config = DocLspConfig {
            port: 9002,
            doc_cache_dir: doc_cache_dir.clone(),
        };
        let server = DocLspServer::new(config);

        let _ = server.preload_docs();
        let doc = server.get_doc("nonexistent");
        assert!(doc.is_none());
    }
}
