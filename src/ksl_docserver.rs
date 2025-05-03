// ksl_docserver.rs
// Implements a web server to host KSL package documentation, providing fast access
// to library references with search, navigation, and offline caching.

use crate::ksl_doc::{generate, StdLibFunctionTrait};
use crate::ksl_errors::{KslError, SourcePosition};
use crate::ksl_registry::fetch_package;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use pulldown_cmark::{html, Parser};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use dirs::home_dir;
use reqwest::blocking::Client;

// Configuration for the documentation server
#[derive(Debug, Deserialize)]
pub struct DocServerConfig {
    port: u16,
    cache_dir: Option<PathBuf>,
}

// State for the documentation server
struct DocServerState {
    cache_dir: PathBuf,
    docs: Mutex<HashMap<String, String>>, // module_name -> HTML content
    search_index: Mutex<Vec<SearchEntry>>,
}

// Search index entry for quick lookup
#[derive(Serialize, Deserialize, Clone)]
struct SearchEntry {
    name: String, // e.g., "std::crypto::bls_verify"
    description: String,
    module: String, // e.g., "std::crypto"
    url: String, // e.g., "/docs/std#bls_verify"
}

// Initialize the documentation server
pub struct DocServer {
    config: DocServerConfig,
    client: Client,
}

impl DocServer {
    pub fn new(config: DocServerConfig) -> Self {
        DocServer {
            config,
            client: Client::new(),
        }
    }

    // Start the documentation server
    pub fn start(&self) -> Result<(), KslError> {
        let cache_dir = self.config.cache_dir.clone()
            .unwrap_or_else(|| home_dir().unwrap_or_default().join(".ksl/docs"));
        fs::create_dir_all(&cache_dir)
            .map_err(|e| KslError::type_error(
                format!("Failed to create cache directory {}: {}", cache_dir.display(), e),
                SourcePosition::new(1, 1),
            ))?;

        // Initialize state
        let state = web::Data::new(DocServerState {
            cache_dir: cache_dir.clone(),
            docs: Mutex::new(HashMap::new()),
            search_index: Mutex::new(Vec::new()),
        });

        // Load standard library documentation
        self.load_std_docs(&state)?;

        // Start Actix-web server
        let port = self.config.port;
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .route("/", web::get().to(index))
                .route("/docs/{module}", web::get().to(serve_doc))
                .route("/search", web::get().to(search))
                .route("/static/{file}", web::get().to(serve_static))
        })
        .bind(("127.0.0.1", port))
        .map_err(|e| KslError::type_error(
            format!("Failed to bind server to port {}: {}", port, e),
            SourcePosition::new(1, 1),
        ))?
        .run()
        .map_err(|e| KslError::type_error(
            format!("Server error: {}", e),
            SourcePosition::new(1, 1),
        ))?;

        Ok(())
    }

    // Load standard library documentation into cache
    fn load_std_docs(&self, state: &web::Data<DocServerState>) -> Result<(), KslError> {
        let cache_dir = &state.cache_dir;
        let std_doc_path = cache_dir.join("std.md");

        // Generate standard library documentation if not cached
        if !std_doc_path.exists() {
            generate(None, true, Some(cache_dir))?;
        }

        // Convert Markdown to HTML and update state
        let markdown = fs::read_to_string(&std_doc_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to read std.md: {}", e),
                SourcePosition::new(1, 1),
            ))?;
        let html = markdown_to_html(&markdown);
        let mut docs = state.docs.lock().unwrap();
        docs.insert("std".to_string(), html);

        // Build search index
        let mut search_index = state.search_index.lock().unwrap();
        build_search_index(&markdown, "std", &mut search_index);

        Ok(())
    }

    // Fetch and cache package documentation from registry
    fn fetch_package_doc(&self, package: &str, version: &str, state: &web::Data<DocServerState>) -> Result<(), KslError> {
        let cache_dir = &state.cache_dir;
        let package_doc_path = cache_dir.join(format!("{}-{}.md", package, version));

        if !package_doc_path.exists() {
            // Fetch from registry (assumes ksl_registry.rs provides tarball)
            let tarball = fetch_package(package, version, &self.client)?;
            let doc_content = extract_doc_from_tarball(&tarball, package, version)?;
            fs::write(&package_doc_path, &doc_content)
                .map_err(|e| KslError::type_error(
                    format!("Failed to write package doc {}: {}", package_doc_path.display(), e),
                    SourcePosition::new(1, 1),
                ))?;
        }

        let markdown = fs::read_to_string(&package_doc_path)
            .map_err(|e| KslError::type_error(
                format!("Failed to read package doc {}: {}", package_doc_path.display(), e),
                SourcePosition::new(1, 1),
            ))?;
        let html = markdown_to_html(&markdown);
        let mut docs = state.docs.lock().unwrap();
        let module_name = format!("{}-{}", package, version);
        docs.insert(module_name.clone(), html);

        let mut search_index = state.search_index.lock().unwrap();
        build_search_index(&markdown, &module_name, &mut search_index);

        Ok(())
    }
}

// Convert Markdown to HTML
fn markdown_to_html(markdown: &str) -> String {
    let parser = Parser::new(markdown);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    wrap_in_html_template(&html_output)
}

// Wrap content in an HTML template with navigation and search
fn wrap_in_html_template(content: &str) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>KSL Documentation</title>
    <link rel="stylesheet" href="/static/style.css">
    <script src="/static/search.js"></script>
</head>
<body>
    <div class="container">
        <nav>
            <h2>KSL Documentation</h2>
            <ul>
                <li><a href="/docs/std">Standard Library</a></li>
                <!-- Add package links dynamically via JS -->
            </ul>
            <input type="text" id="search" placeholder="Search..." onkeyup="searchDocs()">
        </nav>
        <main>
            {}
        </main>
    </div>
</body>
</html>
        "#,
        content
    )
}

// Build search index from Markdown
fn build_search_index(markdown: &str, module: &str, index: &mut Vec<SearchEntry>) {
    let lines = markdown.lines();
    let mut current_section = String::new();
    let mut description = String::new();

    for line in lines {
        if line.starts_with("## ") || line.starts_with("### ") {
            if !current_section.is_empty() {
                index.push(SearchEntry {
                    name: current_section.clone(),
                    description: description.trim().to_string(),
                    module: module.to_string(),
                    url: format!("/docs/{}#{}", module, current_section.replace("::", "_")),
                });
                description.clear();
            }
            current_section = line.trim_start_matches('#').trim().to_string();
        } else if !current_section.is_empty() && !line.is_empty() {
            description.push_str(line);
            description.push(' ');
        }
    }

    if !current_section.is_empty() {
        index.push(SearchEntry {
            name: current_section,
            description: description.trim().to_string(),
            module: module.to_string(),
            url: format!("/docs/{}#{}", module, current_section.replace("::", "_")),
        });
    }
}

// Extract documentation from tarball (simplified)
fn extract_doc_from_tarball(tarball: &[u8], package: &str, version: &str) -> Result<String, KslError> {
    // Simulate extraction (assumes tarball contains docs/{package}-{version}.md)
    let doc_path = format!("docs/{}-{}.md", package, version);
    Ok(format!("# Package {} v{}\n\nDocumentation placeholder.", package, version))
}

// Web route: Serve index page
async fn index() -> impl Responder {
    HttpResponse::Ok().body(wrap_in_html_template(
        "<h1>Welcome to KSL Documentation</h1><p>Select a module from the sidebar or use search.</p>"
    ))
}

// Web route: Serve documentation for a module
async fn serve_doc(
    module: web::Path<String>,
    state: web::Data<DocServerState>,
) -> impl Responder {
    let module = module.into_inner();
    let docs = state.docs.lock().unwrap();
    if let Some(html) = docs.get(&module) {
        HttpResponse::Ok().content_type("text/html").body(html.clone())
    } else {
        // Try fetching package documentation
        let parts: Vec<&str> = module.split('-').collect();
        if parts.len() == 2 {
            let server = DocServer::new(DocServerConfig { port: 8080, cache_dir: Some(state.cache_dir.clone()) });
            if server.fetch_package_doc(parts[0], parts[1], &state).is_ok() {
                if let Some(html) = docs.get(&module) {
                    return HttpResponse::Ok().content_type("text/html").body(html.clone());
                }
            }
        }
        HttpResponse::NotFound().body("Documentation not found")
    }
}

// Web route: Handle search queries
async fn search(
    query: web::Query<HashMap<String, String>>,
    state: web::Data<DocServerState>,
) -> impl Responder {
    let query = query.get("q").map(|q| q.to_lowercase()).unwrap_or_default();
    let search_index = state.search_index.lock().unwrap();
    let results: Vec<SearchEntry> = search_index
        .iter()
        .filter(|entry| entry.name.to_lowercase().contains(&query) || entry.description.to_lowercase().contains(&query))
        .cloned()
        .collect();
    HttpResponse::Ok().json(results)
}

// Web route: Serve static files (CSS, JS)
async fn serve_static(file: web::Path<String>) -> impl Responder {
    let file = file.into_inner();
    let content_type = match file.as_str() {
        "style.css" => "text/css",
        "search.js" => "application/javascript",
        _ => "application/octet-stream",
    };
    let content = match file.as_str() {
        "style.css" => include_str!("static/style.css").to_string(),
        "search.js" => include_str!("static/search.js").to_string(),
        _ => return HttpResponse::NotFound().body("Static file not found"),
    };
    HttpResponse::Ok().content_type(content_type).body(content)
}

// Static files (embedded for simplicity)
mod static_files {
    pub const STYLE_CSS: &str = r#"
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
        .container { display: flex; }
        nav { width: 250px; padding: 20px; background: #f0f0f0; }
        nav ul { list-style: none; padding: 0; }
        nav ul li { margin: 10px 0; }
        nav input { width: 100%; padding: 8px; }
        main { flex-grow: 1; padding: 20px; }
        h1, h2, h3 { color: #333; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    "#;

    pub const SEARCH_JS: &str = r#"
        function searchDocs() {
            const query = document.getElementById('search').value;
            fetch(`/search?q=${encodeURIComponent(query)}`)
                .then(response => response.json())
                .then(results => {
                    const main = document.querySelector('main');
                    main.innerHTML = '<h2>Search Results</h2><ul>' +
                        results.map(r => `<li><a href="${r.url}">${r.name}</a>: ${r.description}</li>`).join('') +
                        '</ul>';
                });
        }
    "#;
}

// Public API to start the documentation server
pub fn start_docserver(port: u16, cache_dir: Option<PathBuf>) -> Result<(), KslError> {
    let config = DocServerConfig { port, cache_dir };
    let server = DocServer::new(config);
    server.start()
}

// Assume ksl_doc.rs, ksl_registry.rs, and ksl_errors.rs are in the same crate
mod ksl_doc {
    pub use super::{generate, StdLibFunctionTrait};
}

mod ksl_registry {
    pub use super::fetch_package;
}

mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_load_std_docs() {
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path().join("docs");
        let state = web::Data::new(DocServerState {
            cache_dir: cache_dir.clone(),
            docs: Mutex::new(HashMap::new()),
            search_index: Mutex::new(Vec::new()),
        });
        let server = DocServer::new(DocServerConfig { port: 8080, cache_dir: Some(cache_dir.clone()) });
        let result = server.load_std_docs(&state);
        assert!(result.is_ok());

        let docs = state.docs.lock().unwrap();
        assert!(docs.contains_key("std"));
        let html = docs.get("std").unwrap();
        assert!(html.contains("<h1>Standard Library</h1>"));

        let search_index = state.search_index.lock().unwrap();
        assert!(!search_index.is_empty());
        assert!(search_index.iter().any(|entry| entry.name.contains("bls_verify")));
    }

    #[test]
    fn test_markdown_to_html() {
        let markdown = "# Module std\n## Function bls_verify\nDocumentation.";
        let html = markdown_to_html(markdown);
        assert!(html.contains("<h1>Module std</h1>"));
        assert!(html.contains("<h2>Function bls_verify</h2>"));
        assert!(html.contains("Documentation."));
        assert!(html.contains("<nav>"));
        assert!(html.contains("<input type=\"text\" id=\"search\""));
    }

    #[test]
    fn test_build_search_index() {
        let markdown = "# Module std\n## Function bls_verify\nVerifies BLS signature.";
        let mut index = Vec::new();
        build_search_index(markdown, "std", &mut index);
        assert_eq!(index.len(), 1);
        assert_eq!(index[0].name, "Function bls_verify");
        assert_eq!(index[0].description, "Verifies BLS signature.");
        assert_eq!(index[0].module, "std");
        assert_eq!(index[0].url, "/docs/std#Function_bls_verify");
    }
}
