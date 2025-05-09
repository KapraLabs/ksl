# KSL (Kapra Smart Language)
A next-generation language and VM optimized for blockchain, AI, gaming, and beyond.

![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/language-Rust-orange)
![LLVM](https://img.shields.io/badge/backend-LLVM-informational)

KSL is a high-performance, extensible programming language and ecosystem designed for demanding applications such as blockchain (Kapra Chain), AI, IoT, gaming, and general-purpose programming. It features a lightweight virtual machine (Kapra VM), optimized bytecode, and WebAssembly (WASM) support, with a comprehensive suite of developer tools and libraries.

## Features
- **Modular Architecture:** Parsing, compilation, and execution via Kapra VM and AOT/JIT backends.
- **Blockchain-Ready:** Native support for sharding, consensus, validator contracts, and quantum-resistant cryptography.
- **AI & IoT Integration:** Tensor operations, device communication, and low-power optimizations.
- **Gaming Support:** Physics, rendering, and multiplayer networking modules.
- **Developer Tools:** REPL, fuzz testing, hot reloading, documentation generation, and LSP integration.
- **Interoperability:** FFI bindings for Rust and networking for distributed systems.

## Project Structure

```
src/
├── Core Language & VM
│   ├── ksl_parser.rs           # Parser and AST
│   ├── ksl_ast.rs, ksl_ast_transform.rs
│   ├── ksl_bytecode.rs        # Bytecode generation
│   ├── ksl_compiler.rs        # Compiler and optimizer
│   ├── kapra_vm.rs            # Kapra Virtual Machine
│   ├── ksl_jit.rs, ksl_aot.rs # JIT and AOT compilation
│   ├── ksl_interpreter.rs     # Interpreter
│   ├── ksl_types.rs           # Type system
│   ├── ksl_errors.rs          # Error types
│   ├── ksl_macros.rs, ksl_generics.rs
│   ├── ksl_checker.rs, ksl_optimizer.rs
│   ├── ksl_profile.rs, ksl_benchmark.rs
│   ├── ksl_test.rs, ksl_testgen.rs
│   ├── ksl_linter.rs, ksl_formatter.rs
│   ├── ksl_module.rs, ksl_plugin.rs
│   ├── ksl_bind.rs, ksl_ffi.rs
│   ├── ksl_transpiler.rs, ksl_typegen.rs
│   ├── ksl_embedded.rs, ksl_simulator.rs
│   └── ...
│
├── Standard Library & Utilities
│   ├── ksl_stdlib.rs, ksl_stdlib_crypto.rs, ksl_stdlib_net.rs
│   ├── ksl_data_blob.rs, ksl_export.rs
│   ├── ksl_metrics.rs, ksl_debug.rs
│   ├── ksl_sandbox.rs, ksl_security.rs
│   ├── ksl_updater.rs, ksl_bundler.rs
│   └── ...
│
├── Blockchain & Smart Contracts
│   ├── ksl_kapra_shard.rs, ksl_kapra_consensus.rs, ksl_kapra_crypto.rs, ksl_kapra_zkp.rs
│   ├── ksl_validator_contract.rs, ksl_validator_keys.rs
│   ├── ksl_contract.rs, ksl_contract_verifier.rs
│   ├── ksl_smart_account.rs
│   ├── ksl_package.rs, ksl_package_publish.rs, ksl_package_version.rs
│   ├── ksl_registry.rs
│   └── ...
│
├── AI, IoT, and Gaming
│   ├── ksl_ai.rs, ksl_iot.rs, ksl_game.rs
│   ├── ksl_web3.rs
│   └── ...
│
├── Developer Tools & Integration
│   ├── ksl_repl.rs, ksl_repl_server.rs
│   ├── ksl_docgen.rs, ksl_doc_lsp.rs, ksl_docserver.rs, ksl_doc.rs
│   ├── ksl_analyzer.rs, ksl_bench.rs
│   ├── ksl_hot_reload.rs, ksl_runtime_monitor.rs
│   ├── ksl_cli.rs, ksl_cli_spec.rs
│   ├── ksl_vscode.rs, ksl_dev_tools.rs
│   ├── ksl_project.rs, ksl_template.rs, ksl_scaffold.rs, ksl_scaffold_gui.rs
│   ├── ksl_dep_audit.rs, ksl_refactor.rs, ksl_migrate.rs
│   ├── ksl_coverage.rs
│   └── ...
│
├── WASM & Interop
│   ├── ksl_wasm.rs, ksl_ir.rs, ksl_irgen.rs
│   ├── ksl_export.rs
│   └── ...
│
├── Miscellaneous & Community
│   ├── ksl_community.rs
│   ├── ksl_version.rs
│   └── ...
│
├── Tests & Benchmarks
│   ├── ksl_test.rs, ksl_bench.rs, ksl_benchmark.rs
│   └── ...
│
├── Main Entrypoints
│   ├── main.rs, lib.rs
│   └── ...
```

*See `FILE_OVERVIEW.md` for a full, up-to-date list of files and their integration status.*

## Installation
### Prerequisites
- **Rust** (latest stable): [https://rustup.rs/](https://rustup.rs/)
- **CMake** (>=3.15): [https://cmake.org/download/](https://cmake.org/download/)
- **Perl** (for LLVM build): [https://strawberryperl.com/](https://strawberryperl.com/)
- **LLVM 12.0.0** (with `llvm-config`):
  - **Recommended:** Use [`llvmenv`](https://crates.io/crates/llvmenv) to build and manage LLVM for Rust/inkwell compatibility.

#### Windows LLVM Setup (Recommended)
1. Install [CMake](https://cmake.org/download/) and [Strawberry Perl](https://strawberryperl.com/).
2. Install `llvmenv`:
   ```powershell
   cargo install llvmenv
   llvmenv init
   llvmenv build-entry 12.0.0
   llvmenv global 12.0.0
   llvmenv prefix  # Shows the LLVM path
   ```
3. Ensure `llvm-config.exe` is in your PATH (from the prefix above).
4. Set the environment variable (if needed):
   ```powershell
   $env:LLVM_SYS_120_PREFIX = "<path from llvmenv prefix>"
   ```

#### Linux/Mac
- Install LLVM 12.0.0 via your package manager or build from source.
- Ensure `llvm-config` is in your PATH.

## Building KSL
```sh
cargo build
```

## Usage

### Quick Start: Hello, KSL!
```sh
echo 'print("Hello, KSL!")' > hello.ksl
cargo run --bin kslc -- ./hello.ksl
```

### REPL (Interactive Shell)
```sh
cargo run --bin ksl_repl
```

### Compile & Run a KSL Program
`kslc` is the CLI compiler and runner:
```sh
cargo run --bin kslc -- ./examples/hello_world.ksl
```

### Generate Documentation
```sh
cargo run --bin ksl_docgen path/to/contract.ir.json
```

## WASM/Embedded
KSL supports WebAssembly and embedded devices via `ksl_wasm.rs` and `ksl_embedded.rs`.

Build for WASM:
```sh
wasm-pack build --target web
```

## Testing
Run all tests:
```sh
cargo test
```

## Roadmap
- [x] Bytecode compiler and Kapra VM
- [x] REPL and docgen tooling
- [ ] Formal IR verification blocks
- [ ] WASI and mobile runtime integration
- [ ] Smart contract upgrade/versioning system

## Contributing
1. Fork the repository and create a feature branch.
2. Follow the integration plan and update `FILE_OVERVIEW.md` as you process files.
3. Add `///` documentation to all new code and run `ksl_docgen` to verify.
4. Test thoroughly using `ksl_fuzzer` and `ksl_analyzer`.
5. Submit a pull request with a clear description of your changes.

## Security & Performance
- Quantum-resistant cryptography (Dilithium, BLS, Ed25519)
- Fuzz testing and contract verification
- Optimized for low-power and high-throughput environments

## License
[MIT](LICENSE)

## Contact
For questions or contributions, open an issue or pull request on GitHub. 