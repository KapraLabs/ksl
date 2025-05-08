// ksl_doc_lsp.rs
// Integrates ksl_docgen.rs with ksl_lsp.rs to provide documentation in IDEs via LSP,
// serving hover and completion docs with caching and async support.

use crate::ksl_docgen::generate_docgen;
use crate::ksl_lsp::{start_lsp, LspServer, LspMessage, LspNotification, LspRequest, LspResponse};
use crate::ksl_ast_transform::{AstNode, AstTransformer};
use crate::ksl_async::{AsyncRuntime, AsyncResult};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_macros::{MacroDoc, MacroDef, MacroKind};
use crate::ksl_analyzer::{Analyzer, GasStats};
use crate::ksl_contract::{ContractAbi, ContractFunction};
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use serde_json::{Value, json};

/// Doc LSP configuration
#[derive(Debug, Clone)]
pub struct DocLspConfig {
    /// Port to listen on
    pub port: u16,
    /// Directory for cached documentation
    pub doc_cache_dir: PathBuf,
    /// Whether to use async operations
    pub use_async: bool,
    /// Whether to enable semantic highlighting
    pub enable_semantic_highlighting: bool,
    /// Whether to show gas estimates
    pub show_gas_estimates: bool,
    /// Whether to include source line numbers in docs
    pub include_source_links: bool,
    /// Whether to group functions by category
    pub group_by_category: bool,
    /// Whether to generate CLI documentation
    pub generate_cli_docs: bool,
}

/// Doc LSP server state
#[derive(Debug, Clone)]
pub struct DocLspState {
    /// Last processed AST node
    pub last_node: Option<AstNode>,
    /// Documentation cache
    pub doc_cache: HashMap<String, String>,
    /// Macro documentation cache
    pub macro_docs: HashMap<String, MacroDoc>,
    /// Contract ABI cache
    pub contract_abis: HashMap<String, ContractAbi>,
    /// Gas cost estimates
    pub gas_estimates: HashMap<String, GasStats>,
    /// Semantic tokens
    pub semantic_tokens: HashMap<String, Vec<SemanticToken>>,
    /// Source position mapping for documentation
    pub source_positions: HashMap<String, SourcePosition>,
    /// Function categories
    pub function_categories: HashMap<String, Vec<String>>,
    /// CLI command documentation
    pub cli_docs: HashMap<String, String>,
}

/// Semantic token for highlighting
#[derive(Debug, Clone)]
pub struct SemanticToken {
    /// Token type (keyword, type, macro, etc.)
    pub token_type: String,
    /// Token modifiers (async, deprecated, etc.)
    pub modifiers: HashSet<String>,
    /// Start position
    pub start: SourcePosition,
    /// End position
    pub end: SourcePosition,
}

/// Doc LSP server for providing documentation in IDEs
pub struct DocLspServer {
    config: DocLspConfig,
    lsp_server: Arc<LspServer>,
    async_runtime: Arc<AsyncRuntime>,
    state: Arc<RwLock<DocLspState>>,
    analyzer: Arc<Analyzer>,
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
                macro_docs: HashMap::new(),
                contract_abis: HashMap::new(),
                gas_estimates: HashMap::new(),
                semantic_tokens: HashMap::new(),
                source_positions: HashMap::new(),
                function_categories: HashMap::new(),
                cli_docs: HashMap::new(),
            })),
            analyzer: Arc::new(Analyzer::new()),
        }
    }

    /// Start the Doc LSP server asynchronously
    pub async fn start_async(&self) -> AsyncResult<()> {
        // Preload documentation for standard library
        self.preload_docs_async().await?;

        // Register LSP handlers
        self.register_handlers().await?;

        // Start LSP server
        self.lsp_server.start_async().await?;
        Ok(())
    }

    /// Register LSP message handlers
    async fn register_handlers(&self) -> AsyncResult<()> {
        let server = self.lsp_server.clone();
        let state = self.state.clone();
        let config = self.config.clone();

        // Document symbols handler
        server.register_handler("textDocument/documentSymbol", move |params: Value| {
            let state = state.clone();
            async move {
                let symbols = state.read().await.get_document_symbols(&params["textDocument"]["uri"].as_str().unwrap());
                Ok(json!({
                    "symbols": symbols
                }))
            }
        });

        // Hover handler
        server.register_handler("textDocument/hover", move |params: Value| {
            let state = state.clone();
            let config = config.clone();
            async move {
                let hover_info = state.read().await.get_hover_info(
                    &params["textDocument"]["uri"].as_str().unwrap(),
                    params["position"]["line"].as_u64().unwrap() as u32,
                    params["position"]["character"].as_u64().unwrap() as u32,
                    config.show_gas_estimates,
                );
                Ok(json!({
                    "contents": hover_info
                }))
            }
        });

        // Semantic tokens handler
        if config.enable_semantic_highlighting {
            server.register_handler("textDocument/semanticTokens/full", move |params: Value| {
                let state = state.clone();
                async move {
                    let tokens = state.read().await.get_semantic_tokens(&params["textDocument"]["uri"].as_str().unwrap());
                    Ok(json!({
                        "data": tokens
                    }))
                }
            });
        }

        // Diagnostics handler
        server.register_handler("textDocument/diagnostics", move |params: Value| {
            let state = state.clone();
            async move {
                let diagnostics = state.read().await.get_diagnostics(&params["textDocument"]["uri"].as_str().unwrap());
                Ok(json!({
                    "diagnostics": diagnostics
                }))
            }
        });

        Ok(())
    }

    /// Get document symbols for LSP
    async fn get_document_symbols(&self, uri: &str) -> Vec<Value> {
        let state = self.state.read().await;
        let mut symbols = Vec::new();

        // Add function symbols
        for (name, doc) in &state.doc_cache {
            symbols.push(json!({
                "name": name,
                "kind": "function",
                "location": {
                    "uri": uri,
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": name.len() as u32}
                    }
                }
            }));
        }

        // Add macro symbols
        for (name, doc) in &state.macro_docs {
            symbols.push(json!({
                "name": name,
                "kind": "macro",
                "location": {
                    "uri": uri,
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": name.len() as u32}
                    }
                }
            }));
        }

        // Add contract symbols
        for (name, abi) in &state.contract_abis {
            symbols.push(json!({
                "name": name,
                "kind": "contract",
                "location": {
                    "uri": uri,
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": name.len() as u32}
                    }
                }
            }));
        }

        symbols
    }

    /// Get hover information for LSP
    async fn get_hover_info(&self, uri: &str, line: u32, character: u32, show_gas: bool) -> Value {
        let state = self.state.read().await;
        let mut contents = Vec::new();

        // Check for function documentation
        if let Some(doc) = state.doc_cache.get(&self.get_symbol_at_position(uri, line, character)) {
            contents.push(json!({
                "kind": "markdown",
                "value": doc
            }));
        }

        // Check for macro documentation
        if let Some(doc) = state.macro_docs.get(&self.get_symbol_at_position(uri, line, character)) {
            contents.push(json!({
                "kind": "markdown",
                "value": doc.to_markdown()
            }));
        }

        // Check for contract documentation
        if let Some(abi) = state.contract_abis.get(&self.get_symbol_at_position(uri, line, character)) {
            let mut contract_doc = String::new();
            contract_doc.push_str("### Contract Functions\n\n");
            for func in &abi.functions {
                contract_doc.push_str(&format!("- `{}`\n", func.name));
                if show_gas {
                    if let Some(gas) = state.gas_estimates.get(&func.name) {
                        contract_doc.push_str(&format!("  Gas: {} (avg)\n", gas.avg_gas));
                    }
                }
            }
            contents.push(json!({
                "kind": "markdown",
                "value": contract_doc
            }));
        }

        json!({
            "contents": contents,
            "range": {
                "start": {"line": line, "character": character},
                "end": {"line": line, "character": character + 1}
            }
        })
    }

    /// Get semantic tokens for highlighting
    async fn get_semantic_tokens(&self, uri: &str) -> Vec<Value> {
        let state = self.state.read().await;
        let mut tokens = Vec::new();

        if let Some(file_tokens) = state.semantic_tokens.get(uri) {
            for token in file_tokens {
                tokens.push(json!({
                    "line": token.start.line,
                    "startChar": token.start.column,
                    "length": token.end.column - token.start.column,
                    "tokenType": token.token_type,
                    "tokenModifiers": token.modifiers.iter().collect::<Vec<_>>()
                }));
            }
        }

        tokens
    }

    /// Get diagnostics for LSP
    async fn get_diagnostics(&self, uri: &str) -> Vec<Value> {
        let state = self.state.read().await;
        let mut diagnostics = Vec::new();

        // Check for async/blocking mismatches
        if let Some(node) = &state.last_node {
            if let AstNode::AsyncFnDecl { name, .. } = node {
                if !name.contains("async") {
                    diagnostics.push(json!({
                        "range": {
                            "start": {"line": 0, "character": 0},
                            "end": {"line": 0, "character": name.len() as u32}
                        },
                        "severity": 2, // Warning
                        "message": "Async function should be marked with 'async' keyword"
                    }));
                }
            }
        }

        // Check for unused variables
        if let Some(node) = &state.last_node {
            if let AstNode::Let { name, .. } = node {
                if !self.is_variable_used(name) {
                    diagnostics.push(json!({
                        "range": {
                            "start": {"line": 0, "character": 0},
                            "end": {"line": 0, "character": name.len() as u32}
                        },
                        "severity": 2, // Warning
                        "message": "Unused variable"
                    }));
                }
            }
        }

        // Check for missing #[no_mangle] on hot reloadable functions
        if let Some(node) = &state.last_node {
            if let AstNode::FnDecl { name, .. } = node {
                if self.is_hot_reloadable(name) && !self.has_no_mangle(name) {
                    diagnostics.push(json!({
                        "range": {
                            "start": {"line": 0, "character": 0},
                            "end": {"line": 0, "character": name.len() as u32}
                        },
                        "severity": 2, // Warning
                        "message": "Hot reloadable function should be marked with #[no_mangle]"
                    }));
                }
            }
        }

        diagnostics
    }

    /// Helper to get symbol at position
    fn get_symbol_at_position(&self, uri: &str, line: u32, character: u32) -> String {
        // Simplified implementation - would need proper source parsing
        String::new()
    }

    /// Helper to check if variable is used
    fn is_variable_used(&self, name: &str) -> bool {
        // Simplified implementation - would need proper AST analysis
        true
    }

    /// Helper to check if function is hot reloadable
    fn is_hot_reloadable(&self, name: &str) -> bool {
        // Simplified implementation - would need proper attribute parsing
        false
    }

    /// Helper to check if function has #[no_mangle]
    fn has_no_mangle(&self, name: &str) -> bool {
        // Simplified implementation - would need proper attribute parsing
        false
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
        let doc = self.generate_documentation(&node)?;
        if let Some(name) = node.get_name() {
            state.doc_cache.insert(name, doc);
            
            // Store source position if enabled
            if self.config.include_source_links {
                if let Some(pos) = node.get_source_position() {
                    state.source_positions.insert(name, pos);
                }
            }

            // Update function categories
            if self.config.group_by_category {
                self.update_function_categories(&mut state, &node)?;
            }
        }

        // Update semantic tokens if enabled
        if self.config.enable_semantic_highlighting {
            self.update_semantic_tokens(&mut state, &node)?;
        }

        // Update gas estimates if enabled
        if self.config.show_gas_estimates {
            self.update_gas_estimates(&mut state, &node).await?;
        }

        // Generate CLI docs if enabled
        if self.config.generate_cli_docs {
            self.generate_cli_documentation(&mut state, &node)?;
        }

        Ok(())
    }

    /// Generate documentation for a node with enhanced features
    fn generate_documentation(&self, node: &AstNode) -> Result<String, KslError> {
        let mut doc = String::new();
        
        // Get base documentation
        doc.push_str(&AstTransformer::generate_doc(node)?);

        // Add macro expansion metadata if applicable
        if let AstNode::MacroDef { name, expansion, .. } = node {
            doc.push_str("\n\n### Macro Expansion\n```ksl\n");
            doc.push_str(&expansion);
            doc.push_str("\n```\n");
        }

        // Add contract ABI if applicable
        if let AstNode::ContractDef { name, abi, .. } = node {
            doc.push_str("\n\n### Contract ABI\n```json\n");
            doc.push_str(&serde_json::to_string_pretty(&abi)?);
            doc.push_str("\n```\n");
        }

        // Add source link if enabled
        if self.config.include_source_links {
            if let Some(pos) = node.get_source_position() {
                doc.push_str(&format!("\n\n[Source]({}#L{})", pos.file, pos.line));
            }
        }

        // Add cross-references
        doc = self.add_cross_references(doc);

        Ok(doc)
    }

    /// Add cross-references to documentation
    fn add_cross_references(&self, doc: String) -> String {
        let mut result = doc;
        let state = self.state.read().unwrap();

        // Replace [fn_name] with proper markdown links
        for (name, _) in &state.doc_cache {
            let pattern = format!("[{}]", name);
            let replacement = format!("[{}]({})", name, self.get_doc_url(name));
            result = result.replace(&pattern, &replacement);
        }

        result
    }

    /// Get documentation URL for a function
    fn get_doc_url(&self, name: &str) -> String {
        format!("#function-{}", name.to_lowercase().replace(".", "-"))
    }

    /// Update function categories
    fn update_function_categories(&self, state: &mut DocLspState, node: &AstNode) -> Result<(), KslError> {
        if let Some(name) = node.get_name() {
            let category = self.determine_function_category(node)?;
            state.function_categories
                .entry(category)
                .or_insert_with(Vec::new)
                .push(name);
        }
        Ok(())
    }

    /// Determine function category based on name and attributes
    fn determine_function_category(&self, node: &AstNode) -> Result<String, KslError> {
        let name = node.get_name().unwrap_or_default();
        
        // Determine category based on function name prefix
        if name.starts_with("crypto.") {
            Ok("Cryptographic".to_string())
        } else if name.starts_with("hash.") {
            Ok("Hash-based".to_string())
        } else if name.starts_with("identity.") {
            Ok("Identity-based".to_string())
        } else if name.starts_with("matrix.") {
            Ok("Matrix Operations".to_string())
        } else if name.starts_with("device.") {
            Ok("Device I/O".to_string())
        } else {
            Ok("General".to_string())
        }
    }

    /// Generate CLI documentation
    fn generate_cli_documentation(&self, state: &mut DocLspState, node: &AstNode) -> Result<(), KslError> {
        if let AstNode::FnDecl { name, params, .. } = node {
            let mut cli_doc = String::new();
            cli_doc.push_str(&format!("## Command: {}\n\n", name));
            
            // Add description
            if let Some(doc) = state.doc_cache.get(name) {
                cli_doc.push_str(&format!("{}\n\n", doc));
            }

            // Add parameters
            cli_doc.push_str("### Parameters\n\n");
            for param in params {
                cli_doc.push_str(&format!("- `{}`: {}\n", param.name, param.ty));
            }

            // Add examples
            cli_doc.push_str("\n### Examples\n\n");
            cli_doc.push_str("```bash\n");
            cli_doc.push_str(&format!("ksl {} ", name));
            for param in params {
                cli_doc.push_str(&format!("<{}> ", param.name));
            }
            cli_doc.push_str("\n```\n");

            state.cli_docs.insert(name.clone(), cli_doc);
        }
        Ok(())
    }

    /// Generate category-based documentation
    pub async fn generate_category_docs(&self) -> AsyncResult<String> {
        let state = self.state.read().await;
        let mut doc = String::new();
        doc.push_str("# KSL Standard Library\n\n");

        // Group functions by category
        for (category, functions) in &state.function_categories {
            doc.push_str(&format!("## {}\n\n", category));
            for func in functions {
                if let Some(func_doc) = state.doc_cache.get(func) {
                    doc.push_str(&format!("### {}\n\n", func));
                    doc.push_str(func_doc);
                    doc.push_str("\n\n");
                }
            }
        }

        Ok(doc)
    }

    /// Update semantic tokens for a node
    fn update_semantic_tokens(&self, state: &mut DocLspState, node: &AstNode) -> Result<(), KslError> {
        let mut tokens = Vec::new();

        match node {
            AstNode::FnDecl { name, .. } => {
                tokens.push(SemanticToken {
                    token_type: "function".to_string(),
                    modifiers: HashSet::new(),
                    start: SourcePosition::new(0, 0),
                    end: SourcePosition::new(0, name.len() as u32),
                });
            }
            AstNode::AsyncFnDecl { name, .. } => {
                let mut modifiers = HashSet::new();
                modifiers.insert("async".to_string());
                tokens.push(SemanticToken {
                    token_type: "function".to_string(),
                    modifiers,
                    start: SourcePosition::new(0, 0),
                    end: SourcePosition::new(0, name.len() as u32),
                });
            }
            AstNode::MacroDef { name, .. } => {
                tokens.push(SemanticToken {
                    token_type: "macro".to_string(),
                    modifiers: HashSet::new(),
                    start: SourcePosition::new(0, 0),
                    end: SourcePosition::new(0, name.len() as u32),
                });
            }
            _ => {}
        }

        if !tokens.is_empty() {
            state.semantic_tokens.insert("current_file".to_string(), tokens);
        }

        Ok(())
    }

    /// Update gas estimates for a node
    async fn update_gas_estimates(&self, state: &mut DocLspState, node: &AstNode) -> AsyncResult<()> {
        if let Some(name) = node.get_name() {
            let gas_stats = self.analyzer.analyze_gas_usage(node).await?;
            state.gas_estimates.insert(name, gas_stats);
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
        enable_semantic_highlighting: true,
        show_gas_estimates: true,
        include_source_links: true,
        group_by_category: true,
        generate_cli_docs: true,
    };
    let server = DocLspServer::new(config);
    server.start_async().await
}

/// CLI wrapper for documentation generation
pub struct DocGenCli {
    /// Whether to generate standard library docs
    pub std: bool,
    /// Input file path
    pub file: Option<PathBuf>,
    /// Output directory
    pub output: PathBuf,
    /// Whether to include source links
    pub source_links: bool,
    /// Whether to group by category
    pub group_by_category: bool,
    /// Whether to generate CLI docs
    pub cli_docs: bool,
}

impl DocGenCli {
    /// Create new CLI configuration
    pub fn new() -> Self {
        DocGenCli {
            std: false,
            file: None,
            output: PathBuf::from("docs"),
            source_links: true,
            group_by_category: true,
            cli_docs: true,
        }
    }

    /// Generate documentation based on CLI configuration
    pub async fn generate_async(&self) -> AsyncResult<()> {
        let config = DocLspConfig {
            port: 9002,
            doc_cache_dir: self.output.clone(),
            use_async: true,
            enable_semantic_highlighting: true,
            show_gas_estimates: true,
            include_source_links: self.source_links,
            group_by_category: self.group_by_category,
            generate_cli_docs: self.cli_docs,
        };

        let server = DocLspServer::new(config);

        if self.std {
            // Generate standard library docs
            server.preload_docs_async().await?;
            let category_docs = server.generate_category_docs().await?;
            fs::write(self.output.join("std.md"), category_docs)?;
        }

        if let Some(file) = &self.file {
            // Generate docs for specific file
            let content = fs::read_to_string(file)?;
            let node = AstTransformer::parse(&content)?;
            server.process_ast_node_async(node).await?;
        }

        Ok(())
    }
}

// Assume ksl_docgen.rs, ksl_lsp.rs, ksl_ast_transform.rs, ksl_async.rs, and ksl_errors.rs are in the same crate
mod ksl_docgen {
    pub use super::generate_docgen;
}

mod ksl_lsp {
    pub use super::{start_lsp, LspServer, LspMessage, LspNotification, LspRequest, LspResponse};
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

mod ksl_macros {
    pub use super::{MacroDoc, MacroDef, MacroKind};
}

mod ksl_analyzer {
    pub use super::{Analyzer, GasStats};
}

mod ksl_contract {
    pub use super::{ContractAbi, ContractFunction};
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
            enable_semantic_highlighting: true,
            show_gas_estimates: true,
            include_source_links: true,
            group_by_category: true,
            generate_cli_docs: true,
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
            enable_semantic_highlighting: true,
            show_gas_estimates: true,
            include_source_links: true,
            group_by_category: true,
            generate_cli_docs: true,
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
            enable_semantic_highlighting: true,
            show_gas_estimates: true,
            include_source_links: true,
            group_by_category: true,
            generate_cli_docs: true,
        };
        let server = DocLspServer::new(config);

        let node = AstNode::FnDecl {
            name: "test_func".to_string(),
            params: vec![],
            return_type: Type::Unit,
            body: vec![],
        };

        let result = server.process_ast_node_async(node).await;
        assert!(result.is_ok());

        let doc = server.get_doc_async("test_func").await.unwrap();
        assert!(doc.is_some());
    }

    #[tokio::test]
    async fn test_doc_gen_cli() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("docs");
        fs::create_dir_all(&output_dir).unwrap();

        let cli = DocGenCli {
            std: true,
            file: None,
            output: output_dir.clone(),
            source_links: true,
            group_by_category: true,
            cli_docs: true,
        };

        let result = cli.generate_async().await;
        assert!(result.is_ok());

        let std_doc = fs::read_to_string(output_dir.join("std.md")).unwrap();
        assert!(std_doc.contains("# KSL Standard Library"));
        assert!(std_doc.contains("## Cryptographic"));
        assert!(std_doc.contains("## Hash-based"));
    }
}
