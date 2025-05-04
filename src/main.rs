mod kapra_dsl;
mod kapra_vm;
mod ksl_compiler;
mod ksl_cli;
mod ksl_typechecker; 

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::sleep;
use std::time::Duration;

use ksl_cli::Cli;
use ksl_config::Config;
use ksl_async::AsyncRuntime;
use ksl_errors::Error;
use ksl_dev_tools::DevTools;
use ksl_vscode::VSCodeIntegration;

/// Main entry point for the KSL toolchain.
/// 
/// # Arguments
/// * `args` - Command line arguments
/// 
/// # Returns
/// A Result containing () on success or an Error on failure
#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize async runtime
    let async_runtime = AsyncRuntime::new();
    
    // Initialize configuration
    let config = Arc::new(Mutex::new(Config::load()?));
    
    // Initialize development tools
    let dev_tools = Arc::new(Mutex::new(DevTools::new(config.clone())));
    
    // Initialize VSCode integration
    let vscode = Arc::new(Mutex::new(VSCodeIntegration::new(config.clone())));
    
    // Initialize command-line interface
    let cli = Cli::new(
        config.clone(),
        dev_tools.clone(),
        vscode.clone(),
        async_runtime.clone(),
    );
    
    // Parse command line arguments
    let args = std::env::args().collect::<Vec<String>>();
    let command = cli.parse_args(&args)?;
    
    // Execute command with async support
    match command {
        Command::Build { input, output } => {
            // Initialize build process
            let build_result = async_runtime.spawn(async move {
                // Simulate build process
                sleep(Duration::from_millis(100)).await;
                Ok(())
            }).await?;
            
            // Handle build result
            match build_result {
                Ok(_) => println!("Build completed successfully"),
                Err(e) => return Err(Error::BuildError(e.to_string())),
            }
        }
        Command::Test { input } => {
            // Initialize test process
            let test_result = async_runtime.spawn(async move {
                // Simulate test process
                sleep(Duration::from_millis(50)).await;
                Ok(())
            }).await?;
            
            // Handle test result
            match test_result {
                Ok(_) => println!("Tests completed successfully"),
                Err(e) => return Err(Error::TestError(e.to_string())),
            }
        }
        Command::DevTools { command } => {
            // Execute dev tools command
            let tools_result = dev_tools.lock().await.execute_command(&command).await?;
            println!("Dev tools command executed: {:?}", tools_result);
        }
        Command::VSCode { command } => {
            // Execute VSCode command
            let vscode_result = vscode.lock().await.execute_command(&command).await?;
            println!("VSCode command executed: {:?}", vscode_result);
        }
        Command::Help => {
            cli.print_help();
        }
    }
    
    Ok(())
}

/// Represents a command that can be executed by the KSL toolchain.
#[derive(Debug)]
pub enum Command {
    Build {
        input: String,
        output: String,
    },
    Test {
        input: String,
    },
    DevTools {
        command: String,
    },
    VSCode {
        command: String,
    },
    Help,
}

/// Command-line interface for the KSL toolchain.
pub struct Cli {
    config: Arc<Mutex<Config>>,
    dev_tools: Arc<Mutex<DevTools>>,
    vscode: Arc<Mutex<VSCodeIntegration>>,
    async_runtime: AsyncRuntime,
}

impl Cli {
    /// Creates a new CLI instance.
    /// 
    /// # Arguments
    /// * `config` - Configuration manager
    /// * `dev_tools` - Development tools manager
    /// * `vscode` - VSCode integration manager
    /// * `async_runtime` - Async runtime manager
    pub fn new(
        config: Arc<Mutex<Config>>,
        dev_tools: Arc<Mutex<DevTools>>,
        vscode: Arc<Mutex<VSCodeIntegration>>,
        async_runtime: AsyncRuntime,
    ) -> Self {
        Cli {
            config,
            dev_tools,
            vscode,
            async_runtime,
        }
    }
    
    /// Parses command line arguments.
    /// 
    /// # Arguments
    /// * `args` - Command line arguments
    /// 
    /// # Returns
    /// A Result containing the parsed Command or an Error
    pub fn parse_args(&self, args: &[String]) -> Result<Command, Error> {
        if args.len() < 2 {
            return Ok(Command::Help);
        }
        
        match args[1].as_str() {
            "build" => {
                if args.len() != 4 {
                    return Err(Error::CliError("build command requires input and output paths".to_string()));
                }
                Ok(Command::Build {
                    input: args[2].clone(),
                    output: args[3].clone(),
                })
            }
            "test" => {
                if args.len() != 3 {
                    return Err(Error::CliError("test command requires input path".to_string()));
                }
                Ok(Command::Test {
                    input: args[2].clone(),
                })
            }
            "dev-tools" => {
                if args.len() != 3 {
                    return Err(Error::CliError("dev-tools command requires a subcommand".to_string()));
                }
                Ok(Command::DevTools {
                    command: args[2].clone(),
                })
            }
            "vscode" => {
                if args.len() != 3 {
                    return Err(Error::CliError("vscode command requires a subcommand".to_string()));
                }
                Ok(Command::VSCode {
                    command: args[2].clone(),
                })
            }
            "help" => Ok(Command::Help),
            _ => Err(Error::CliError(format!("Unknown command: {}", args[1]))),
        }
    }
    
    /// Prints help information for the CLI.
    pub fn print_help(&self) {
        println!("KSL Toolchain");
        println!();
        println!("Usage: ksl <command> [options]");
        println!();
        println!("Commands:");
        println!("  build <input> <output>    Build a KSL project");
        println!("  test <input>              Test a KSL project");
        println!("  dev-tools <command>       Run development tools command");
        println!("  vscode <command>          Run VSCode integration command");
        println!("  help                      Show this help message");
    }
}

