# KSL File Overview

This file tracks all source files in the KSL project, grouped by purpose. For each file, you'll find a brief description and placeholders for documentation and integration status. Please keep this file up to date as you add, rename, or integrate files.

*See the README for a high-level project structure and onboarding instructions.*

---

## Core Language & VM
- **ksl_parser.rs**: KSL parser and AST.  
  Documentation: [ ]  Integration: [ ]
- **ksl_ast.rs**: AST node definitions.  
  Documentation: [ ]  Integration: [ ]
- **ksl_ast_transform.rs**: AST transformations for optimization.  
  Documentation: [ ]  Integration: [ ]
- **ksl_bytecode.rs**: Bytecode generation.  
  Documentation: [ ]  Integration: [ ]
- **ksl_compiler.rs**: Compiler and optimizer.  
  Documentation: [ ]  Integration: [ ]
- **kapra_vm.rs**: Kapra Virtual Machine.  
  Documentation: [ ]  Integration: [ ]
- **ksl_jit.rs**: JIT compilation.  
  Documentation: [ ]  Integration: [ ]
- **ksl_aot.rs**: Ahead-of-Time compilation.  
  Documentation: [ ]  Integration: [ ]
- **ksl_interpreter.rs**: Interpreter for prototyping.  
  Documentation: [ ]  Integration: [ ]
- **ksl_types.rs**: Type system.  
  Documentation: [ ]  Integration: [ ]
- **ksl_errors.rs**: Error types.  
  Documentation: [ ]  Integration: [ ]
- **ksl_macros.rs**: Macro system.  
  Documentation: [ ]  Integration: [ ]
- **ksl_generics.rs**: Generic types and functions.  
  Documentation: [ ]  Integration: [ ]
- **ksl_checker.rs**: Type checker.  
  Documentation: [ ]  Integration: [ ]
- **ksl_optimizer.rs**: Bytecode optimizer.  
  Documentation: [ ]  Integration: [ ]
- **ksl_profile.rs**: Profiling and flame graphs.  
  Documentation: [ ]  Integration: [ ]
- **ksl_benchmark.rs**: Benchmarking framework.  
  Documentation: [ ]  Integration: [ ]
- **ksl_test.rs**: Testing framework.  
  Documentation: [ ]  Integration: [ ]
- **ksl_testgen.rs**: Automatic test generator.  
  Documentation: [ ]  Integration: [ ]
- **ksl_linter.rs**: Static analysis tool.  
  Documentation: [ ]  Integration: [ ]
- **ksl_formatter.rs**: Code formatter.  
  Documentation: [ ]  Integration: [ ]
- **ksl_module.rs**: Module system.  
  Documentation: [ ]  Integration: [ ]
- **ksl_plugin.rs**: Plugin system.  
  Documentation: [ ]  Integration: [ ]
- **ksl_bind.rs**: FFI binding generator.  
  Documentation: [ ]  Integration: [ ]
- **ksl_ffi.rs**: Foreign Function Interface.  
  Documentation: [ ]  Integration: [ ]
- **ksl_transpiler.rs**: Transpiles KSL to other languages.  
  Documentation: [ ]  Integration: [ ]
- **ksl_typegen.rs**: Type generator.  
  Documentation: [ ]  Integration: [ ]
- **ksl_embedded.rs**: Embedded systems support.  
  Documentation: [ ]  Integration: [ ]
- **ksl_simulator.rs**: Virtual environment simulation.  
  Documentation: [ ]  Integration: [ ]

## Standard Library & Utilities
- **ksl_stdlib.rs**: Standard library.  
  Documentation: [ ]  Integration: [ ]
- **ksl_stdlib_crypto.rs**: Cryptography.  
  Documentation: [ ]  Integration: [ ]
- **ksl_stdlib_net.rs**: Networking.  
  Documentation: [ ]  Integration: [ ]
- **ksl_data_blob.rs**: Data blob utilities.  
  Documentation: [ ]  Integration: [ ]
- **ksl_export.rs**: Export utilities.  
  Documentation: [ ]  Integration: [ ]
- **ksl_metrics.rs**: Runtime metrics.  
  Documentation: [ ]  Integration: [ ]
- **ksl_debug.rs**: Debugging framework.  
  Documentation: [ ]  Integration: [ ]
- **ksl_sandbox.rs**: Sandboxing.  
  Documentation: [ ]  Integration: [ ]
- **ksl_security.rs**: Security checks.  
  Documentation: [ ]  Integration: [ ]
- **ksl_updater.rs**: Updater tool.  
  Documentation: [ ]  Integration: [ ]
- **ksl_bundler.rs**: Bundles projects.  
  Documentation: [ ]  Integration: [ ]

## Blockchain & Smart Contracts
- **ksl_kapra_shard.rs**: Sharding primitives.  
  Documentation: [ ]  Integration: [ ]
- **ksl_kapra_consensus.rs**: Consensus logic.  
  Documentation: [ ]  Integration: [ ]
- **ksl_kapra_crypto.rs**: Quantum-resistant crypto.  
  Documentation: [ ]  Integration: [ ]
- **ksl_kapra_zkp.rs**: Zero-knowledge proofs.  
  Documentation: [ ]  Integration: [ ]
- **ksl_validator_contract.rs**: Validator contract logic.  
  Documentation: [ ]  Integration: [ ]
- **ksl_validator_keys.rs**: Validator key management.  
  Documentation: [ ]  Integration: [ ]
- **ksl_contract.rs**: Smart contract compiler.  
  Documentation: [ ]  Integration: [ ]
- **ksl_contract_verifier.rs**: Contract verification.  
  Documentation: [ ]  Integration: [ ]
- **ksl_smart_account.rs**: Smart account logic.  
  Documentation: [ ]  Integration: [ ]
- **ksl_package.rs**: Package management.  
  Documentation: [ ]  Integration: [ ]
- **ksl_package_publish.rs**: Package publishing.  
  Documentation: [ ]  Integration: [ ]
- **ksl_package_version.rs**: Version management.  
  Documentation: [ ]  Integration: [ ]
- **ksl_registry.rs**: Package registry client.  
  Documentation: [ ]  Integration: [ ]
- **ksl_kapra_validator.rs**: Validator primitives.  
  Documentation: [ ]  Integration: [ ]
- **ksl_genesis.rs**: Genesis block logic.  
  Documentation: [ ]  Integration: [ ]
- **ksl_kapra_scheduler.rs**: Validator scheduling.  
  Documentation: [ ]  Integration: [ ]

## AI, IoT, and Gaming
- **ksl_ai.rs**: AI/tensor operations.  
  Documentation: [ ]  Integration: [ ]
- **ksl_iot.rs**: IoT device communication.  
  Documentation: [ ]  Integration: [ ]
- **ksl_game.rs**: Game engine/physics.  
  Documentation: [ ]  Integration: [ ]
- **ksl_web3.rs**: Web3 integration.  
  Documentation: [ ]  Integration: [ ]

## Developer Tools & Integration
- **ksl_repl.rs**: Interactive REPL.  
  Documentation: [ ]  Integration: [ ]
- **ksl_repl_server.rs**: REPL server.  
  Documentation: [ ]  Integration: [ ]
- **ksl_docgen.rs**: API documentation generator.  
  Documentation: [ ]  Integration: [ ]
- **ksl_doc_lsp.rs**: LSP documentation integration.  
  Documentation: [ ]  Integration: [ ]
- **ksl_docserver.rs**: Documentation server.  
  Documentation: [ ]  Integration: [ ]
- **ksl_doc.rs**: Documentation generator.  
  Documentation: [ ]  Integration: [ ]
- **ksl_analyzer.rs**: Dynamic analysis/profiling.  
  Documentation: [ ]  Integration: [ ]
- **ksl_bench.rs**: Benchmarking tool.  
  Documentation: [ ]  Integration: [ ]
- **ksl_hot_reload.rs**: Hot reloading.  
  Documentation: [ ]  Integration: [ ]
- **ksl_runtime_monitor.rs**: Runtime monitoring.  
  Documentation: [ ]  Integration: [ ]
- **ksl_cli.rs**: CLI for KSL.  
  Documentation: [ ]  Integration: [ ]
- **ksl_cli_spec.rs**: CLI specification.  
  Documentation: [ ]  Integration: [ ]
- **ksl_vscode.rs**: VS Code extension config.  
  Documentation: [ ]  Integration: [ ]
- **ksl_dev_tools.rs**: Developer tools.  
  Documentation: [ ]  Integration: [ ]
- **ksl_project.rs**: Project initialization.  
  Documentation: [ ]  Integration: [ ]
- **ksl_template.rs**: Project templates.  
  Documentation: [ ]  Integration: [ ]
- **ksl_scaffold.rs**: Project scaffolding.  
  Documentation: [ ]  Integration: [ ]
- **ksl_scaffold_gui.rs**: GUI scaffolding.  
  Documentation: [ ]  Integration: [ ]
- **ksl_dep_audit.rs**: Dependency auditing.  
  Documentation: [ ]  Integration: [ ]
- **ksl_refactor.rs**: Refactoring tools.  
  Documentation: [ ]  Integration: [ ]
- **ksl_migrate.rs**: Migration tools.  
  Documentation: [ ]  Integration: [ ]
- **ksl_coverage.rs**: Code coverage.  
  Documentation: [ ]  Integration: [ ]

## Miscellaneous & Community
- **ksl_community.rs**: Community features.  
  Documentation: [ ]  Integration: [ ]
- **ksl_version.rs**: Version info.  
  Documentation: [ ]  Integration: [ ]
- **ksl_debug.rs**: Debugging utilities.  
  Documentation: [ ]  Integration: [ ]
- **ksl_metrics.rs**: Metrics collection.  
  Documentation: [ ]  Integration: [ ]
- **ksl_profile.rs**: Profiling.  
  Documentation: [ ]  Integration: [ ]
- **ksl_logger.rs**: Logging framework.  
  Documentation: [ ]  Integration: [ ]

## Entrypoints
- **main.rs**: Main binary entrypoint.  
  Documentation: [ ]  Integration: [ ]
- **lib.rs**: Library entrypoint.  
  Documentation: [ ]  Integration: [ ]
- **gas_profile.rs**: Gas profiling.  
  Documentation: [ ]  Integration: [ ]

---

*Update this file as you add, rename, or integrate files. For a high-level overview, see the README.*

