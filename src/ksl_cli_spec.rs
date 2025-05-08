// ksl_cli_spec.rs — CLI structure for KSL using `clap`

use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
#[command(name = "ksl", version = "1.0", author = "Kapra Dev Team", about = "KSL Compiler & Blockchain Dev Tool")]
pub struct KslCli {
    #[command(subcommand)]
    pub command: KslCommand,
}

#[derive(Subcommand)]
pub enum KslCommand {
    /// Create a new KSL project from a template
    New(NewArgs),

    /// Build the current project
    Build(BuildArgs),

    /// Run unit and integration tests
    Test,

    /// Publish a package to the registry
    Publish(PublishArgs),

    /// Yank or deprecate a published version
    Yank(YankArgs),

    /// Install packages or dependencies
    Install(InstallArgs),

    /// Update dependencies
    Update(UpdateArgs),

    /// View or generate documentation
    Doc(DocArgs),

    /// Hot reload a running module (contract/validator)
    Reload(ReloadArgs),

    /// Generate a project scaffold
    Init(InitArgs),

    /// Format and lint source code
    Fmt,

    /// Run live REPL session
    Repl,
}

#[derive(Args)]
pub struct NewArgs {
    /// Project name
    pub name: String,

    /// Optional template: blockchain, validator, ai, iot
    #[arg(short, long)]
    pub template: Option<String>,
}

#[derive(Args)]
pub struct BuildArgs {
    /// Target: native, wasm, or bytecode
    #[arg(short, long, default_value = "native")]
    pub target: String,

    /// Enable optimizations
    #[arg(short, long)]
    pub release: bool,
}

#[derive(Args)]
pub struct PublishArgs {
    /// Sign the package before publishing
    #[arg(long)]
    pub sign: bool,

    /// Remote registry URL
    #[arg(short, long)]
    pub registry: Option<String>,
}

#[derive(Args)]
pub struct YankArgs {
    pub package: String,
    pub version: String,
    #[arg(short, long)]
    pub reason: Option<String>,
}

#[derive(Args)]
pub struct InstallArgs {
    pub package: String,
    #[arg(short, long)]
    pub version: Option<String>,
}

#[derive(Args)]
pub struct UpdateArgs {
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args)]
pub struct DocArgs {
    /// Specific module or file to document
    pub target: Option<String>,
}

#[derive(Args)]
pub struct ReloadArgs {
    /// Module name to reload (e.g., validator, contract)
    pub module: String,
}

#[derive(Args)]
pub struct InitArgs {
    /// Initialize from template (blockchain, ai, iot)
    #[arg(short, long)]
    pub template: Option<String>,
}
