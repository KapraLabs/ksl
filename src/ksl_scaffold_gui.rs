use std::sync::{Arc, Mutex};
use web_view::*;
use serde::{Serialize, Deserialize};
use crate::ksl_scaffold::{ScaffoldManager, ScaffoldOptions, ComponentOptions, Template, ComponentType};

/// GUI state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaffoldGuiState {
    /// Selected template
    pub template: String,
    /// Project name
    pub project_name: String,
    /// Output path
    pub output_path: String,
    /// Enable sandbox
    pub sandbox: bool,
    /// Generate ABI
    pub generate_abi: bool,
    /// Enable ZK features
    pub enable_zk: bool,
    /// Additional features
    pub features: Vec<String>,
    /// Generate tests
    pub generate_tests: bool,
    /// Inject into module
    pub inject: bool,
    /// Target module
    pub target_module: Option<String>,
    /// Component mode
    pub component_mode: bool,
    /// Component type
    pub component_type: Option<String>,
}

impl Default for ScaffoldGuiState {
    fn default() -> Self {
        Self {
            template: "contract".to_string(),
            project_name: String::new(),
            output_path: String::new(),
            sandbox: false,
            generate_abi: false,
            enable_zk: false,
            features: Vec::new(),
            generate_tests: false,
            inject: false,
            target_module: None,
            component_mode: false,
            component_type: None,
        }
    }
}

/// GUI manager
pub struct ScaffoldGui {
    /// Scaffold manager
    manager: Arc<Mutex<ScaffoldManager>>,
    /// GUI state
    state: Arc<Mutex<ScaffoldGuiState>>,
}

impl ScaffoldGui {
    /// Creates a new GUI manager
    pub fn new() -> Self {
        Self {
            manager: Arc::new(Mutex::new(ScaffoldManager::new())),
            state: Arc::new(Mutex::new(ScaffoldGuiState::default())),
        }
    }

    /// Shows the scaffold GUI
    pub fn show(&self) -> Result<(), String> {
        let state = self.state.clone();
        let manager = self.manager.clone();

        // Load HTML template
        let html = include_str!("../templates/scaffold_gui.html");

        // Create web view
        web_view::builder()
            .title("KSL Scaffold")
            .content(Content::Html(html))
            .size(800, 600)
            .resizable(true)
            .debug(true)
            .user_data(())
            .invoke_handler(move |webview, arg| {
                let state = state.lock().unwrap();
                let manager = manager.lock().unwrap();

                match arg {
                    "get_templates" => {
                        // Return available templates
                        let templates = vec![
                            "contract", "validator", "ai", "iot", "shard", "zk"
                        ];
                        webview.eval(&format!(
                            "window.updateTemplates({});",
                            serde_json::to_string(&templates).unwrap()
                        ))?;
                    }
                    "get_component_types" => {
                        // Return available component types
                        let types = vec![
                            "service", "model", "contract", "validator", "middleware"
                        ];
                        webview.eval(&format!(
                            "window.updateComponentTypes({});",
                            serde_json::to_string(&types).unwrap()
                        ))?;
                    }
                    "scaffold" => {
                        // Parse scaffold options
                        let options = if state.component_mode {
                            // Component mode
                            let component_type = state.component_type.as_ref()
                                .ok_or_else(|| "Component type not specified".to_string())?;
                            
                            ComponentOptions {
                                name: state.project_name.clone(),
                                component_type: match component_type.as_str() {
                                    "service" => ComponentType::Service,
                                    "model" => ComponentType::Model,
                                    "contract" => ComponentType::Contract,
                                    "validator" => ComponentType::Validator,
                                    "middleware" => ComponentType::Middleware,
                                    _ => ComponentType::Custom(component_type.clone()),
                                },
                                path: std::path::PathBuf::from(&state.output_path),
                                features: state.features.clone(),
                                generate_tests: state.generate_tests,
                            }
                        } else {
                            // Project mode
                            ScaffoldOptions {
                                name: state.project_name.clone(),
                                path: std::path::PathBuf::from(&state.output_path),
                                template: match state.template.as_str() {
                                    "contract" => Template::Contract,
                                    "validator" => Template::Validator,
                                    "ai" => Template::AI,
                                    "iot" => Template::IoT,
                                    "shard" => Template::ShardModule,
                                    "zk" => Template::ZkProof,
                                    _ => Template::Custom(state.template.clone()),
                                },
                                sandbox: state.sandbox,
                                generate_abi: state.generate_abi,
                                enable_zk: state.enable_zk,
                                registry_url: None,
                                inject: state.inject,
                                target_module: state.target_module.clone(),
                            }
                        };

                        // Execute scaffold
                        if state.component_mode {
                            manager.scaffold_component(&options)?;
                        } else {
                            // Use tokio runtime for async operations
                            let runtime = tokio::runtime::Runtime::new()
                                .map_err(|e| format!("Failed to create runtime: {}", e))?;
                            runtime.block_on(manager.init_project(options))?;
                        }

                        // Show success message
                        webview.eval("window.showSuccess('Scaffold completed successfully!');")?;
                    }
                    _ => return Err("Unknown command".into()),
                }

                Ok(())
            })
            .build()
            .map_err(|e| format!("Failed to create web view: {}", e))?
            .run()
            .map_err(|e| format!("Failed to run web view: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gui_state_default() {
        let state = ScaffoldGuiState::default();
        assert_eq!(state.template, "contract");
        assert!(state.project_name.is_empty());
        assert!(state.output_path.is_empty());
        assert!(!state.sandbox);
        assert!(!state.generate_abi);
        assert!(!state.enable_zk);
        assert!(state.features.is_empty());
        assert!(!state.generate_tests);
        assert!(!state.inject);
        assert!(state.target_module.is_none());
        assert!(!state.component_mode);
        assert!(state.component_type.is_none());
    }
} 