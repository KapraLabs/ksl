# KSL Scaffold for VS Code

A powerful Visual Studio Code extension that integrates with the KSL scaffold system, providing a modern GUI for scaffolding KSL projects and components.

## Features

- 🚀 **Modern GUI Interface**
  - Clean, intuitive interface for scaffolding
  - Real-time file tree preview
  - Live template search and suggestions

- 📦 **Template Management**
  - Browse and search templates
  - Remote template registry support
  - Template categorization and filtering

- 🔍 **Preview & Validation**
  - File tree preview before scaffolding
  - .kslignore preview panel
  - Real-time validation of inputs
  - Diagnostic reporting for missing folders

- 🧪 **Test Simulator**
  - In-memory project simulation
  - CI/CD integration support
  - Mock project testing

- 🌳 **VS Code Integration**
  - Native sidebar explorer
  - Command palette integration
  - Output channel for logging
  - File explorer refresh

## Installation

1. Open VS Code
2. Press `Ctrl+P` to open the Quick Open dialog
3. Paste the following command:
   ```
   ext install ksl.scaffold
   ```
4. Press Enter and click Install

## Usage

### Starting the Scaffold GUI

1. Open the Command Palette (`Ctrl+Shift+P`)
2. Type "KSL: Scaffold Project/Component"
3. Press Enter

### Using the Template Explorer

1. Open the Explorer sidebar
2. Look for the "KSL Scaffold" section
3. Browse available templates
4. Click on a template to start scaffolding

### Scaffolding a Project

1. Select "Project Mode" in the GUI
2. Choose a template
3. Fill in project details:
   - Project name
   - Output path
   - Features to include
4. Preview the file tree
5. Click "Confirm Scaffold"

### Scaffolding a Component

1. Select "Component Mode" in the GUI
2. Choose a component type
3. Fill in component details:
   - Component name
   - Output path
   - Features to include
4. Preview the file tree
5. Click "Confirm Scaffold"

### Using the Test Simulator

1. Start the simulator:
   - Command Palette → "KSL: Start Simulator"
   - Or use the GUI's simulator controls
2. Monitor the simulation in the output channel
3. Stop the simulator when done:
   - Command Palette → "KSL: Stop Simulator"
   - Or use the GUI's stop button

## Configuration

### Extension Settings

This extension contributes the following settings:

* `ksl.scaffold.templateRegistry`: URL of the template registry
* `ksl.scaffold.defaultOutputPath`: Default output path for scaffolded files
* `ksl.scaffold.enableSimulator`: Enable/disable the test simulator
* `ksl.scaffold.autoRefresh`: Automatically refresh the file explorer after scaffolding

### Template Registry

The extension supports remote template registries. Configure your registry in `ksl.templates.json`:

```json
{
  "registry": {
    "url": "https://registry.ksl.dev",
    "auth": "token",
    "cache": {
      "enabled": true,
      "ttl": 3600
    }
  }
}
```

## Requirements

- VS Code 1.60.0 or higher
- Node.js 16.x or higher
- KSL CLI installed and in PATH

## Extension Commands

* `ksl.scaffold`: Open the scaffold GUI
* `ksl.scaffold.selectTemplate`: Select a template from the explorer
* `ksl.scaffold.refresh`: Refresh the template list
* `ksl.scaffold.startSimulator`: Start the test simulator
* `ksl.scaffold.stopSimulator`: Stop the test simulator

## Known Issues

- None at the moment. Please report any issues on GitHub.

## Release Notes

See the [CHANGELOG.md](CHANGELOG.md) file for release notes.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This extension is licensed under the [MIT License](LICENSE).

## Support

- [GitHub Issues](https://github.com/your-org/ksl-scaffold/issues)
- [Documentation](https://docs.ksl.dev)
- [Discord Community](https://discord.gg/ksl)

## Acknowledgments

- VS Code Extension API
- KSL Scaffold System
- All contributors and users 