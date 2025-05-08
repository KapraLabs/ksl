use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use toml;
use reqwest;
use handlebars::Handlebars;
use crate::ksl_package::{Package, PackageConfig, Dependency};
use semver::{Version, VersionReq};
use web_view::*;
use ignore::{WalkBuilder, gitignore::Gitignore};
use dirs::cache_dir;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Template type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Template {
    Contract,
    Validator,
    AI,
    IoT,
    ShardModule,
    ZkProof,
    Custom(String),
}

/// Template metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMetadata {
    /// Template name
    pub name: String,
    /// Template description
    pub description: String,
    /// Template version
    pub version: String,
    /// Required dependencies
    pub dependencies: Vec<Dependency>,
    /// Required features
    pub required_features: Vec<String>,
    /// Template source (local or remote)
    pub source: TemplateSource,
    /// CLI help text
    pub cli_help: Option<String>,
    /// Sandbox policy configuration
    pub sandbox_policy: Option<SandboxPolicy>,
    /// Contract documentation template
    pub contract_docs: Option<String>,
}

/// Template source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateSource {
    Local(PathBuf),
    Remote(String),
}

/// Template version specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVersion {
    /// Template name
    pub name: String,
    /// Version requirement
    pub version_req: VersionReq,
    /// Registry URL
    pub registry: Option<String>,
}

impl TemplateVersion {
    /// Parses a template version string (e.g. "@kapra/template@1.2.0")
    pub fn parse(input: &str) -> Result<Self, String> {
        if !input.starts_with('@') {
            return Err("Template version must start with @".to_string());
        }

        let parts: Vec<&str> = input.split('@').collect();
        if parts.len() != 3 {
            return Err("Invalid template version format".to_string());
        }

        let name = parts[1].to_string();
        let version_req = VersionReq::parse(parts[2])
            .map_err(|e| format!("Invalid version requirement: {}", e))?;

        Ok(TemplateVersion {
            name,
            version_req,
            registry: None,
        })
    }
}

/// Component type for scaffolding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComponentType {
    Service,
    Model,
    Contract,
    Validator,
    Middleware,
    Custom(String),
}

/// Component scaffold options
#[derive(Debug, Clone)]
pub struct ComponentOptions {
    /// Component name
    pub name: String,
    /// Component type
    pub component_type: ComponentType,
    /// Output path
    pub path: PathBuf,
    /// Additional features
    pub features: Vec<String>,
    /// Generate tests
    pub generate_tests: bool,
}

/// Sandbox policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Filesystem access rules
    pub filesystem: Vec<String>,
    /// Network access rules
    pub network: Vec<String>,
    /// System call restrictions
    pub syscalls: Vec<String>,
    /// Memory limits
    pub memory_limit: Option<usize>,
}

/// Scaffold options
#[derive(Debug, Clone)]
pub struct ScaffoldOptions {
    /// Project name
    pub name: String,
    /// Project path
    pub path: PathBuf,
    /// Template type
    pub template: Template,
    /// Enable sandbox mode
    pub sandbox: bool,
    /// Generate ABI
    pub generate_abi: bool,
    /// Enable ZK features
    pub enable_zk: bool,
    /// Template registry URL (optional)
    pub registry_url: Option<String>,
    /// Inject into existing module graph
    pub inject: bool,
    /// Target module for injection
    pub target_module: Option<String>,
}

/// Template registry client
pub struct TemplateRegistry {
    /// Registry URL
    url: String,
    /// HTTP client
    client: reqwest::Client,
}

/// Template cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateCacheEntry {
    /// Template metadata
    pub metadata: TemplateMetadata,
    /// Cache timestamp
    pub cached_at: DateTime<Utc>,
    /// Cache expiry
    pub expires_at: DateTime<Utc>,
    /// Template content
    pub content: String,
}

/// Template cache
#[derive(Debug)]
pub struct TemplateCache {
    /// Cache directory
    cache_dir: PathBuf,
    /// Cache entries
    entries: HashMap<String, TemplateCacheEntry>,
    /// Cache TTL
    ttl: chrono::Duration,
}

/// GUI preview options
#[derive(Debug, Clone)]
pub struct PreviewOptions {
    /// Window title
    pub title: String,
    /// Window width
    pub width: i32,
    /// Window height
    pub height: i32,
    /// Custom CSS
    pub custom_css: Option<String>,
}

/// Scaffold manager
pub struct ScaffoldManager {
    /// Template registry
    registry: Option<TemplateRegistry>,
    /// Handlebars engine
    handlebars: Handlebars<'static>,
}

impl ScaffoldManager {
    /// Creates a new scaffold manager
    pub fn new() -> Self {
        let mut handlebars = Handlebars::new();
        handlebars.register_template_string("contract", include_str!("../templates/contract.ksl"))
            .expect("Failed to load contract template");
        handlebars.register_template_string("validator", include_str!("../templates/validator.ksl"))
            .expect("Failed to load validator template");
        handlebars.register_template_string("ai", include_str!("../templates/ai.ksl"))
            .expect("Failed to load AI template");
        handlebars.register_template_string("iot", include_str!("../templates/iot.ksl"))
            .expect("Failed to load IoT template");
        handlebars.register_template_string("shard", include_str!("../templates/shard.ksl"))
            .expect("Failed to load shard template");
        handlebars.register_template_string("zk", include_str!("../templates/zk.ksl"))
            .expect("Failed to load ZK template");

        ScaffoldManager {
            registry: None,
            handlebars,
        }
    }

    /// Initializes a new project
    pub async fn init_project(&self, options: ScaffoldOptions) -> Result<(), String> {
        // Create project directory
        fs::create_dir_all(&options.path)
            .map_err(|e| format!("Failed to create project directory: {}", e))?;

        // Generate project layout
        self.generate_project_layout(&options)?;

        // Load template metadata
        let metadata = match &options.template {
            Template::Custom(name) if name.starts_with('@') => {
                self.load_remote_template(name).await?
            }
            _ => self.load_local_template(&options.template)?,
        };

        // Generate main source file
        self.generate_main_source(&options, &metadata)?;

        // Generate package config
        self.generate_package_config(&options, &metadata)?;

        // Generate contract documentation if available
        self.generate_contract_docs(&options, &metadata)?;

        // Generate additional files based on options
        if options.generate_abi {
            self.generate_abi(&options)?;
        }
        if options.sandbox {
            self.generate_sandbox_config(&options)?;
        }
        if options.enable_zk {
            self.generate_zk_verifier(&options)?;
        }

        // Handle injection if requested
        if options.inject {
            self.inject_into_module(&options)?;
        }

        Ok(())
    }

    /// Generates project layout
    fn generate_project_layout(&self, options: &ScaffoldOptions) -> Result<(), String> {
        let dirs = [
            "src",
            "test",
            "docs",
            "contracts",
            "build",
        ];

        for dir in &dirs {
            fs::create_dir_all(options.path.join(dir))
                .map_err(|e| format!("Failed to create directory {}: {}", dir, e))?;
        }

        // Create README.md
        let readme = format!(
            "# {}\n\nGenerated using KSL scaffold system with {} template.",
            options.name,
            format!("{:?}", options.template).to_lowercase()
        );
        fs::write(options.path.join("docs/README.md"), readme)
            .map_err(|e| format!("Failed to create README: {}", e))?;

        Ok(())
    }

    /// Loads a local template
    fn load_local_template(&self, template: &Template) -> Result<TemplateMetadata, String> {
        let (name, description, dependencies) = match template {
            Template::Contract => (
                "contract".to_string(),
                "Smart contract template".to_string(),
                vec![
                    Dependency::new("ksl_contract", "^1.0.0"),
                    Dependency::new("ksl_storage", "^1.0.0"),
                ],
            ),
            Template::Validator => (
                "validator".to_string(),
                "Validator node template".to_string(),
                vec![
                    Dependency::new("ksl_consensus", "^1.0.0"),
                    Dependency::new("ksl_validator", "^1.0.0"),
                ],
            ),
            Template::AI => (
                "ai".to_string(),
                "AI model template".to_string(),
                vec![
                    Dependency::new("ksl_tensor", "^1.0.0"),
                    Dependency::new("ksl_ml", "^1.0.0"),
                ],
            ),
            Template::IoT => (
                "iot".to_string(),
                "IoT device template".to_string(),
                vec![
                    Dependency::new("ksl_wasm", "^1.0.0"),
                    Dependency::new("ksl_async", "^1.0.0"),
                ],
            ),
            Template::ShardModule => (
                "shard".to_string(),
                "Shard module template".to_string(),
                vec![
                    Dependency::new("ksl_shard", "^1.0.0"),
                    Dependency::new("ksl_network", "^1.0.0"),
                ],
            ),
            Template::ZkProof => (
                "zk".to_string(),
                "Zero-knowledge proof template".to_string(),
                vec![
                    Dependency::new("ksl_zk", "^1.0.0"),
                    Dependency::new("ksl_crypto", "^1.0.0"),
                ],
            ),
            Template::Custom(_) => return Err("Cannot load custom template locally".to_string()),
        };

        Ok(TemplateMetadata {
            name,
            description,
            version: "1.0.0".to_string(),
            dependencies,
            required_features: Vec::new(),
            source: TemplateSource::Local(PathBuf::from("templates")),
            cli_help: None,
            sandbox_policy: None,
            contract_docs: None,
        })
    }

    /// Loads a remote template
    async fn load_remote_template(&self, name: &str) -> Result<TemplateMetadata, String> {
        let registry = self.registry.as_ref()
            .ok_or_else(|| "Template registry not configured".to_string())?;
        registry.fetch_template(name).await
    }

    /// Generates main source file
    fn generate_main_source(&self, options: &ScaffoldOptions, metadata: &TemplateMetadata) -> Result<(), String> {
        let template_name = metadata.name.as_str();
        let data = serde_json::json!({
            "project_name": options.name,
            "sandbox": options.sandbox,
            "generate_abi": options.generate_abi,
            "enable_zk": options.enable_zk,
        });

        let source = self.handlebars
            .render(template_name, &data)
            .map_err(|e| format!("Failed to render template: {}", e))?;

        fs::write(options.path.join("src/main.ksl"), source)
            .map_err(|e| format!("Failed to write main source: {}", e))?;

        Ok(())
    }

    /// Generates package configuration
    fn generate_package_config(&self, options: &ScaffoldOptions, metadata: &TemplateMetadata) -> Result<(), String> {
        let config = PackageConfig {
            name: options.name.clone(),
            version: "0.1.0".to_string(),
            description: format!("Generated from {} template", metadata.name),
            dependencies: metadata.dependencies.clone(),
            features: metadata.required_features.clone(),
        };

        let toml = toml::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize package config: {}", e))?;

        fs::write(options.path.join("ksl.toml"), toml)
            .map_err(|e| format!("Failed to write package config: {}", e))?;

        Ok(())
    }

    /// Generates ABI layout
    fn generate_abi(&self, options: &ScaffoldOptions) -> Result<(), String> {
        let abi_template = include_str!("../templates/abi.json");
        fs::write(options.path.join("contracts/abi.json"), abi_template)
            .map_err(|e| format!("Failed to write ABI: {}", e))?;
        Ok(())
    }

    /// Generates sandbox configuration
    fn generate_sandbox_config(&self, options: &ScaffoldOptions) -> Result<(), String> {
        let sandbox_template = include_str!("../templates/sandbox.toml");
        fs::write(options.path.join("sandbox.toml"), sandbox_template)
            .map_err(|e| format!("Failed to write sandbox config: {}", e))?;
        Ok(())
    }

    /// Generates ZK verifier
    fn generate_zk_verifier(&self, options: &ScaffoldOptions) -> Result<(), String> {
        let verifier_template = include_str!("../templates/verifier.ksl");
        fs::write(options.path.join("src/verifier.ksl"), verifier_template)
            .map_err(|e| format!("Failed to write verifier: {}", e))?;
        Ok(())
    }

    /// Generates contract documentation from ABI
    fn generate_contract_docs(&self, options: &ScaffoldOptions, metadata: &TemplateMetadata) -> Result<(), String> {
        if let Some(docs_template) = &metadata.contract_docs {
            let docs_path = options.path.join("docs").join("contracts");
            fs::create_dir_all(&docs_path)
                .map_err(|e| format!("Failed to create docs directory: {}", e))?;

            let abi_path = options.path.join("abi").join(format!("{}.json", options.name));
            if abi_path.exists() {
                let abi_content = fs::read_to_string(&abi_path)
                    .map_err(|e| format!("Failed to read ABI file: {}", e))?;
                
                let mut handlebars = Handlebars::new();
                handlebars.register_template_string("contract_docs", docs_template)
                    .map_err(|e| format!("Failed to register docs template: {}", e))?;

                let data = serde_json::json!({
                    "name": options.name,
                    "abi": serde_json::from_str::<serde_json::Value>(&abi_content)
                        .map_err(|e| format!("Failed to parse ABI: {}", e))?,
                });

                let docs_content = handlebars.render("contract_docs", &data)
                    .map_err(|e| format!("Failed to render docs: {}", e))?;

                let docs_file = docs_path.join(format!("{}.md", options.name));
                fs::write(&docs_file, docs_content)
                    .map_err(|e| format!("Failed to write docs file: {}", e))?;
            }
        }
        Ok(())
    }

    /// Generates sandbox configuration for a component
    fn generate_component_sandbox(&self, options: &ComponentOptions, policy: &SandboxPolicy) -> Result<(), String> {
        let sandbox_path = options.path.join("sandbox.toml");
        let mut config = toml::Value::Table(toml::value::Table::new());

        // Add filesystem rules
        if !policy.filesystem.is_empty() {
            config["filesystem"] = toml::Value::Array(
                policy.filesystem.iter()
                    .map(|r| toml::Value::String(r.clone()))
                    .collect()
            );
        }

        // Add network rules
        if !policy.network.is_empty() {
            config["network"] = toml::Value::Array(
                policy.network.iter()
                    .map(|r| toml::Value::String(r.clone()))
                    .collect()
            );
        }

        // Add syscall restrictions
        if !policy.syscalls.is_empty() {
            config["syscalls"] = toml::Value::Array(
                policy.syscalls.iter()
                    .map(|r| toml::Value::String(r.clone()))
                    .collect()
            );
        }

        // Add memory limit
        if let Some(limit) = policy.memory_limit {
            config["memory_limit"] = toml::Value::Integer(limit as i64);
        }

        let config_str = toml::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize sandbox config: {}", e))?;

        fs::write(&sandbox_path, config_str)
            .map_err(|e| format!("Failed to write sandbox config: {}", e))?;

        Ok(())
    }

    /// Injects a component into an existing module graph
    fn inject_into_module(&self, options: &ScaffoldOptions) -> Result<(), String> {
        if let Some(target_module) = &options.target_module {
            let module_path = options.path.join("src").join(target_module);
            if !module_path.exists() {
                return Err(format!("Target module {} does not exist", target_module));
            }

            // Read existing module graph
            let graph_path = module_path.join("module_graph.json");
            let mut graph: serde_json::Value = if graph_path.exists() {
                let content = fs::read_to_string(&graph_path)
                    .map_err(|e| format!("Failed to read module graph: {}", e))?;
                serde_json::from_str(&content)
                    .map_err(|e| format!("Failed to parse module graph: {}", e))?
            } else {
                serde_json::json!({
                    "modules": [],
                    "dependencies": {}
                })
            };

            // Add new module to graph
            let modules = graph["modules"].as_array_mut()
                .ok_or_else(|| "Invalid module graph format".to_string())?;
            
            modules.push(serde_json::json!({
                "name": options.name,
                "type": options.template,
                "path": format!("{}/src", options.name)
            }));

            // Write updated graph
            let graph_str = serde_json::to_string_pretty(&graph)
                .map_err(|e| format!("Failed to serialize module graph: {}", e))?;
            fs::write(&graph_path, graph_str)
                .map_err(|e| format!("Failed to write module graph: {}", e))?;
        }
        Ok(())
    }

    /// Resolves a template version from registry
    pub async fn resolve_template_version(&self, version_spec: &TemplateVersion) -> Result<TemplateMetadata, String> {
        let registry = self.registry.as_ref()
            .ok_or_else(|| "Template registry not configured".to_string())?;

        // Fetch all versions
        let versions = registry.fetch_template_versions(&version_spec.name).await?;

        // Find matching version
        let matching_version = versions.into_iter()
            .filter(|v| version_spec.version_req.matches(&v.version))
            .max_by(|a, b| a.version.cmp(&b.version))
            .ok_or_else(|| format!("No matching version found for {}", version_spec.name))?;

        Ok(matching_version)
    }

    /// Shows GUI preview of scaffolded files
    pub fn show_preview(&self, path: &Path, options: &PreviewOptions) -> Result<(), String> {
        let mut files = Vec::new();
        let mut file_contents = HashMap::new();

        // Collect files while respecting .kslignore
        let ignore = self.load_ignore(path)?;
        for entry in WalkBuilder::new(path)
            .hidden(false)
            .ignore(false)
            .git_ignore(false)
            .build()
        {
            let entry = entry.map_err(|e| format!("Failed to read directory: {}", e))?;
            let path = entry.path();
            if path.is_file() {
                let relative_path = path.strip_prefix(path)
                    .map_err(|e| format!("Failed to get relative path: {}", e))?;
                if !ignore.matched_path_or_any_parents(relative_path, path.is_dir()) {
                    files.push(relative_path.to_string_lossy().into_owned());
                    let content = fs::read_to_string(path)
                        .map_err(|e| format!("Failed to read file: {}", e))?;
                    file_contents.insert(files.last().unwrap().clone(), content);
                }
            }
        }

        // Generate HTML
        let mut html = String::from(include_str!("../templates/preview.html"));
        
        // Add custom CSS
        if let Some(css) = &options.custom_css {
            html.push_str(&format!("<style>{}</style>", css));
        }

        // Add file tree
        html.push_str("<div class='file-tree'>");
        for file in &files {
            html.push_str(&format!(
                "<div class='file' data-path='{}'>{}</div>",
                file, file
            ));
        }
        html.push_str("</div>");

        // Add file viewer
        html.push_str("<div class='file-viewer'>");
        for (path, content) in &file_contents {
            html.push_str(&format!(
                "<pre class='file-content' data-path='{}'>{}</pre>",
                path,
                html_escape::encode_text(content)
            ));
        }
        html.push_str("</div>");

        // Show preview window
        web_view::builder()
            .title(&options.title)
            .content(Content::Html(html))
            .size(options.width, options.height)
            .resizable(true)
            .debug(true)
            .user_data(())
            .invoke_handler(|_webview, _arg| Ok(()))
            .build()
            .map_err(|e| format!("Failed to create preview window: {}", e))?
            .run()
            .map_err(|e| format!("Failed to run preview window: {}", e))?;

        Ok(())
    }

    /// Loads .kslignore file
    fn load_ignore(&self, path: &Path) -> Result<Gitignore, String> {
        let ignore_path = path.join(".kslignore");
        if ignore_path.exists() {
            Gitignore::new(&ignore_path)
                .map_err(|e| format!("Failed to load .kslignore: {}", e))
        } else {
            Ok(Gitignore::empty())
        }
    }

    /// Resolves template version with fallback
    pub async fn resolve_template_version_with_fallback(&self, version_spec: &TemplateVersion) -> Result<TemplateMetadata, String> {
        // Try exact version first
        match self.resolve_template_version(version_spec).await {
            Ok(metadata) => Ok(metadata),
            Err(_) => {
                // Try version range fallback
                let fallback_req = if version_spec.version_req.to_string().contains("-") {
                    // Already a range, use as is
                    version_spec.version_req.clone()
                } else {
                    // Convert to range (e.g. 1.2.0 -> ^1.2.0)
                    VersionReq::parse(&format!("^{}", version_spec.version_req))
                        .map_err(|e| format!("Failed to parse version range: {}", e))?
                };

                let mut version_spec = version_spec.clone();
                version_spec.version_req = fallback_req;
                self.resolve_template_version(&version_spec).await
            }
        }
    }

    /// Updates local template cache
    pub async fn update_templates(&mut self) -> Result<(), String> {
        let cache = TemplateCache::new()
            .map_err(|e| format!("Failed to create template cache: {}", e))?;

        let registry = self.registry.as_ref()
            .ok_or_else(|| "Template registry not configured".to_string())?;

        // Fetch all templates
        let templates = registry.fetch_templates().await?;

        // Update cache
        for template in templates {
            let content = registry.fetch_template_content(&template.name).await?;
            cache.update(template.name.clone(), template, content);
        }

        // Save cache
        cache.save()
            .map_err(|e| format!("Failed to save template cache: {}", e))?;

        Ok(())
    }

    /// Scaffolds a new component
    pub fn scaffold_component(&self, options: &ComponentOptions) -> Result<(), String> {
        // Create component directory
        fs::create_dir_all(&options.path)
            .map_err(|e| format!("Failed to create component directory: {}", e))?;

        // Load component template
        let template_name = match options.component_type {
            ComponentType::Service => "service",
            ComponentType::Model => "model",
            ComponentType::Contract => "contract",
            ComponentType::Validator => "validator",
            ComponentType::Middleware => "middleware",
            ComponentType::Custom(ref name) => name,
        };

        let data = serde_json::json!({
            "component_name": options.name,
            "features": options.features,
        });

        // Generate main component file
        let source = self.handlebars
            .render(template_name, &data)
            .map_err(|e| format!("Failed to render component template: {}", e))?;

        let main_file = options.path.join(format!("{}.ksl", options.name));
        fs::write(&main_file, source)
            .map_err(|e| format!("Failed to write component file: {}", e))?;

        // Generate tests if requested
        if options.generate_tests {
            let test_source = self.handlebars
                .render(&format!("{}_test", template_name), &data)
                .map_err(|e| format!("Failed to render test template: {}", e))?;

            let test_file = options.path.join(format!("{}_test.ksl", options.name));
            fs::write(test_file, test_source)
                .map_err(|e| format!("Failed to write test file: {}", e))?;
        }

        // Update README with component links
        self.update_readme_links(&options.path, &options.name, &options.component_type)?;

        // Generate sandbox config if template has policy
        if let Some(policy) = &metadata.sandbox_policy {
            self.generate_component_sandbox(options, policy)?;
        }

        Ok(())
    }

    /// Updates README with component links
    fn update_readme_links(&self, path: &Path, name: &str, component_type: &ComponentType) -> Result<(), String> {
        let readme_path = path.join("README.md");
        if !readme_path.exists() {
            return Ok(());
        }

        let mut content = fs::read_to_string(&readme_path)
            .map_err(|e| format!("Failed to read README: {}", e))?;

        // Add component section if not exists
        if !content.contains("## Components") {
            content.push_str("\n\n## Components\n");
        }

        // Add component link
        let component_link = match component_type {
            ComponentType::Contract => {
                format!("- [{}](./{}.ksl) - Smart contract ([ABI](./abi/{}.json))", name, name, name)
            }
            ComponentType::Validator => {
                format!("- [{}](./{}.ksl) - Validator ([ZK Verifier](./verifier/{}_verifier.ksl))", name, name, name)
            }
            _ => {
                format!("- [{}](./{}.ksl) - {}", name, name, format!("{:?}", component_type))
            }
        };

        content.push_str(&format!("\n{}", component_link));

        fs::write(readme_path, content)
            .map_err(|e| format!("Failed to update README: {}", e))?;

        Ok(())
    }
}

impl TemplateRegistry {
    /// Creates a new template registry client
    pub fn new(url: String) -> Self {
        TemplateRegistry {
            url,
            client: reqwest::Client::new(),
        }
    }

    /// Fetches a template from the registry
    pub async fn fetch_template(&self, name: &str) -> Result<TemplateMetadata, String> {
        let url = format!("{}/templates/{}", self.url, name);
        let response = self.client.get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch template: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Failed to fetch template: {}", response.status()));
        }

        let metadata: TemplateMetadata = response.json()
            .await
            .map_err(|e| format!("Failed to parse template metadata: {}", e))?;

        Ok(metadata)
    }

    /// Fetches template versions from registry
    pub async fn fetch_template_versions(&self, name: &str) -> Result<Vec<TemplateMetadata>, String> {
        let url = format!("{}/templates/{}/versions", self.url, name);
        let response = self.client.get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch template versions: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Failed to fetch template versions: {}", response.status()));
        }

        let versions: Vec<TemplateMetadata> = response.json()
            .await
            .map_err(|e| format!("Failed to parse template versions: {}", e))?;

        Ok(versions)
    }

    /// Fetches all templates
    pub async fn fetch_templates(&self) -> Result<Vec<TemplateMetadata>, String> {
        let url = format!("{}/templates", self.url);
        let response = self.client.get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch templates: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Failed to fetch templates: {}", response.status()));
        }

        let templates: Vec<TemplateMetadata> = response.json()
            .await
            .map_err(|e| format!("Failed to parse templates: {}", e))?;

        Ok(templates)
    }

    /// Fetches template content
    pub async fn fetch_template_content(&self, name: &str) -> Result<String, String> {
        let url = format!("{}/templates/{}/content", self.url, name);
        let response = self.client.get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch template content: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Failed to fetch template content: {}", response.status()));
        }

        response.text()
            .await
            .map_err(|e| format!("Failed to read template content: {}", e))
    }
}

impl TemplateCache {
    /// Creates a new template cache
    pub fn new() -> io::Result<Self> {
        let cache_dir = cache_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Failed to get cache directory"))?
            .join("ksl/templates");

        fs::create_dir_all(&cache_dir)?;

        Ok(TemplateCache {
            cache_dir,
            entries: HashMap::new(),
            ttl: chrono::Duration::hours(24),
        })
    }

    /// Loads cache from disk
    pub fn load(&mut self) -> io::Result<()> {
        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".json") {
                        let content = fs::read_to_string(entry.path())?;
                        let cache_entry: TemplateCacheEntry = serde_json::from_str(&content)?;
                        self.entries.insert(name[..name.len()-5].to_string(), cache_entry);
                    }
                }
            }
        }
        Ok(())
    }

    /// Saves cache to disk
    pub fn save(&self) -> io::Result<()> {
        for (name, entry) in &self.entries {
            let path = self.cache_dir.join(format!("{}.json", name));
            let content = serde_json::to_string_pretty(entry)?;
            fs::write(path, content)?;
        }
        Ok(())
    }

    /// Updates cache entry
    pub fn update(&mut self, name: String, metadata: TemplateMetadata, content: String) {
        let now = Utc::now();
        self.entries.insert(name, TemplateCacheEntry {
            metadata,
            cached_at: now,
            expires_at: now + self.ttl,
            content,
        });
    }

    /// Gets cache entry
    pub fn get(&self, name: &str) -> Option<&TemplateCacheEntry> {
        self.entries.get(name)
    }

    /// Checks if cache entry is valid
    pub fn is_valid(&self, name: &str) -> bool {
        if let Some(entry) = self.entries.get(name) {
            Utc::now() < entry.expires_at
        } else {
            false
        }
    }
}

/// CLI integration
pub fn register_cli_commands(app: App) -> App {
    app.subcommand(
        SubCommand::with_name("scaffold")
            .about("Scaffold a new KSL project or component")
            .arg(
                Arg::with_name("name")
                    .help("Project or component name")
                    .required(true)
                    .index(1),
            )
            .arg(
                Arg::with_name("template")
                    .help("Template to use (contract, validator, ai, iot, shard, zk, or custom)")
                    .required(true)
                    .index(2),
            )
            .arg(
                Arg::with_name("path")
                    .help("Output path")
                    .long("path")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("sandbox")
                    .help("Enable sandbox mode")
                    .long("sandbox")
                    .takes_value(false),
            )
            .arg(
                Arg::with_name("generate-abi")
                    .help("Generate ABI")
                    .long("generate-abi")
                    .takes_value(false),
            )
            .arg(
                Arg::with_name("enable-zk")
                    .help("Enable ZK features")
                    .long("enable-zk")
                    .takes_value(false),
            )
            .arg(
                Arg::with_name("registry")
                    .help("Template registry URL")
                    .long("registry")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("inject")
                    .help("Inject into existing module graph")
                    .long("inject")
                    .takes_value(false),
            )
            .arg(
                Arg::with_name("target-module")
                    .help("Target module for injection")
                    .long("target-module")
                    .takes_value(true)
                    .requires("inject"),
            )
            .arg(
                Arg::with_name("component")
                    .help("Scaffold a component instead of a project")
                    .long("component")
                    .takes_value(false),
            )
            .arg(
                Arg::with_name("component-type")
                    .help("Component type (service, model, contract, validator, middleware, or custom)")
                    .long("component-type")
                    .takes_value(true)
                    .requires("component"),
            )
            .arg(
                Arg::with_name("features")
                    .help("Additional features to enable")
                    .long("features")
                    .takes_value(true)
                    .multiple(true),
            )
            .arg(
                Arg::with_name("generate-tests")
                    .help("Generate tests")
                    .long("generate-tests")
                    .takes_value(false),
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_local_template_loading() {
        let manager = ScaffoldManager::new();
        let metadata = manager.load_local_template(&Template::Contract).unwrap();
        assert_eq!(metadata.name, "contract");
        assert!(!metadata.dependencies.is_empty());
    }

    #[tokio::test]
    async fn test_project_initialization() {
        let manager = ScaffoldManager::new();
        let temp_dir = tempdir().unwrap();
        
        let options = ScaffoldOptions {
            name: "test_project".to_string(),
            path: temp_dir.path().to_path_buf(),
            template: Template::Contract,
            sandbox: true,
            generate_abi: true,
            enable_zk: false,
            registry_url: None,
            inject: false,
            target_module: None,
        };
        
        assert!(manager.init_project(options).await.is_ok());
        assert!(temp_dir.path().join("src/main.ksl").exists());
        assert!(temp_dir.path().join("ksl.toml").exists());
        assert!(temp_dir.path().join("contracts/abi.json").exists());
    }

    #[test]
    fn test_project_layout() {
        let manager = ScaffoldManager::new();
        let temp_dir = tempdir().unwrap();
        
        let options = ScaffoldOptions {
            name: "test_project".to_string(),
            path: temp_dir.path().to_path_buf(),
            template: Template::Contract,
            sandbox: false,
            generate_abi: false,
            enable_zk: false,
            registry_url: None,
            inject: false,
            target_module: None,
        };
        
        assert!(manager.generate_project_layout(&options).is_ok());
        assert!(temp_dir.path().join("src").exists());
        assert!(temp_dir.path().join("test").exists());
        assert!(temp_dir.path().join("docs").exists());
        assert!(temp_dir.path().join("docs/README.md").exists());
    }

    #[test]
    fn test_template_version_parsing() {
        let version = TemplateVersion::parse("@kapra/template@1.2.0").unwrap();
        assert_eq!(version.name, "kapra/template");
        assert!(version.version_req.matches(&Version::new(1, 2, 0)));
    }

    #[tokio::test]
    async fn test_version_resolution() {
        let manager = ScaffoldManager::new();
        let version = TemplateVersion {
            name: "kapra/template".to_string(),
            version_req: VersionReq::parse("^1.2.0").unwrap(),
            registry: None,
        };
        
        // This will fail without a mock registry
        assert!(manager.resolve_template_version(&version).await.is_err());
    }

    #[test]
    fn test_component_scaffolding() {
        let manager = ScaffoldManager::new();
        let temp_dir = tempdir().unwrap();
        
        let options = ComponentOptions {
            name: "test_service".to_string(),
            component_type: ComponentType::Service,
            path: temp_dir.path().to_path_buf(),
            features: vec!["async".to_string()],
            generate_tests: true,
        };
        
        assert!(manager.scaffold_component(&options).is_ok());
        assert!(temp_dir.path().join("test_service.ksl").exists());
        assert!(temp_dir.path().join("test_service_test.ksl").exists());
    }

    #[test]
    fn test_readme_links() {
        let manager = ScaffoldManager::new();
        let temp_dir = tempdir().unwrap();
        
        // Create README
        fs::write(
            temp_dir.path().join("README.md"),
            "# Test Project\n",
        ).unwrap();
        
        let options = ComponentOptions {
            name: "test_contract".to_string(),
            component_type: ComponentType::Contract,
            path: temp_dir.path().to_path_buf(),
            features: vec![],
            generate_tests: false,
        };
        
        assert!(manager.scaffold_component(&options).is_ok());
        
        let readme = fs::read_to_string(temp_dir.path().join("README.md")).unwrap();
        assert!(readme.contains("## Components"));
        assert!(readme.contains("[ABI]"));
    }

    #[test]
    fn test_template_cache() {
        let mut cache = TemplateCache::new().unwrap();
        
        let metadata = TemplateMetadata {
            name: "test".to_string(),
            description: "Test template".to_string(),
            version: "1.0.0".to_string(),
            dependencies: vec![],
            required_features: vec![],
            source: TemplateSource::Local(PathBuf::from("test")),
            cli_help: None,
            sandbox_policy: None,
            contract_docs: None,
        };
        
        cache.update("test".to_string(), metadata, "content".to_string());
        assert!(cache.is_valid("test"));
        
        let entry = cache.get("test").unwrap();
        assert_eq!(entry.content, "content");
    }

    #[test]
    fn test_kslignore() {
        let manager = ScaffoldManager::new();
        let temp_dir = tempdir().unwrap();
        
        // Create .kslignore
        fs::write(
            temp_dir.path().join(".kslignore"),
            "*.tmp\n/build/",
        ).unwrap();
        
        let ignore = manager.load_ignore(temp_dir.path()).unwrap();
        assert!(ignore.matched("test.tmp", false));
        assert!(ignore.matched("build/output", false));
    }

    #[tokio::test]
    async fn test_version_range_fallback() {
        let manager = ScaffoldManager::new();
        let version = TemplateVersion {
            name: "kapra/template".to_string(),
            version_req: VersionReq::parse("1.2.0").unwrap(),
            registry: None,
        };
        
        // This will fail without a mock registry
        assert!(manager.resolve_template_version_with_fallback(&version).await.is_err());
    }
} 