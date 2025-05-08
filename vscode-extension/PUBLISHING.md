# Publishing KSL Scaffold to Visual Studio Marketplace

This guide explains how to publish and maintain the KSL Scaffold extension in the Visual Studio Marketplace.

## Prerequisites

1. **Visual Studio Marketplace Account**
   - Create a [Visual Studio Marketplace](https://marketplace.visualstudio.com/) account
   - Sign in with your Microsoft account or GitHub account

2. **Personal Access Token (PAT)**
   - Go to [Azure DevOps](https://dev.azure.com)
   - Create a new organization if you don't have one
   - Go to User Settings (top right) → Personal Access Tokens
   - Create a new token with the following scopes:
     - Marketplace > Manage
     - Marketplace > Publish
   - Save the token securely (you'll need it for publishing)

3. **Required Tools**
   ```bash
   npm install -g @vscode/vsce
   ```

## Publishing Steps

### 1. Prepare Your Extension

1. **Update Version**
   - Update the version in `package.json`
   - Follow [semantic versioning](https://semver.org/)
   ```json
   {
     "version": "1.0.0"
   }
   ```

2. **Update Changelog**
   - Create/update `CHANGELOG.md`
   - Document all changes since last release
   - Follow the [Keep a Changelog](https://keepachangelog.com/) format

3. **Verify Package.json**
   - Ensure all required fields are present:
   ```json
   {
     "name": "ksl-scaffold",
     "displayName": "KSL Scaffold",
     "description": "KSL Scaffold System Integration for VS Code",
     "version": "1.0.0",
     "publisher": "your-publisher-name",
     "repository": {
       "type": "git",
       "url": "https://github.com/your-org/ksl-scaffold.git"
     },
     "engines": {
       "vscode": "^1.60.0"
     }
   }
   ```

### 2. Build and Package

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Compile TypeScript**
   ```bash
   npm run compile
   ```

3. **Run Tests**
   ```bash
   npm test
   ```

4. **Package Extension**
   ```bash
   vsce package
   ```
   This creates a `.vsix` file in your project directory.

### 3. Publish to Marketplace

#### Using GitHub Actions (Recommended)

1. **Add Secrets to GitHub Repository**
   - Go to your repository settings
   - Navigate to Secrets and Variables → Actions
   - Add new secret:
     - Name: `VSCE_PAT`
     - Value: Your Visual Studio Marketplace PAT

2. **Create a Release**
   - Go to GitHub repository
   - Click "Releases" → "Create a new release"
   - Tag version (e.g., `v1.0.0`)
   - Add release notes
   - Publish release

The GitHub Action will automatically:
- Build the extension
- Run tests
- Package the extension
- Create a GitHub release
- Publish to VS Code Marketplace

#### Manual Publishing

1. **Login to Marketplace**
   ```bash
   vsce login your-publisher-name
   ```

2. **Publish Extension**
   ```bash
   vsce publish
   ```

### 4. Verify Publication

1. **Check Marketplace**
   - Visit [Visual Studio Marketplace](https://marketplace.visualstudio.com/)
   - Search for "KSL Scaffold"
   - Verify extension details and installation instructions

2. **Test Installation**
   - Install the extension in a clean VS Code instance
   - Verify all features work as expected
   - Check for any installation issues

## Updating the Extension

### Minor Updates

1. **Update Version**
   - Increment patch version (e.g., 1.0.0 → 1.0.1)
   - Update CHANGELOG.md
   - Create new release on GitHub

### Major Updates

1. **Update Version**
   - Increment major version (e.g., 1.0.0 → 2.0.0)
   - Update CHANGELOG.md
   - Review and update:
     - README.md
     - package.json
     - Documentation
   - Create new release on GitHub

## Troubleshooting

### Common Issues

1. **Publishing Fails**
   - Verify PAT has correct permissions
   - Check version number is higher than current
   - Ensure all required fields in package.json

2. **Installation Issues**
   - Verify VS Code version compatibility
   - Check extension dependencies
   - Review error logs

3. **CI/CD Pipeline Fails**
   - Check GitHub Actions logs
   - Verify secrets are correctly set
   - Review build and test output

## Best Practices

1. **Version Control**
   - Use semantic versioning
   - Keep CHANGELOG.md updated
   - Tag releases in git

2. **Documentation**
   - Keep README.md current
   - Document all features
   - Include usage examples

3. **Testing**
   - Run tests before publishing
   - Test on multiple platforms
   - Verify all features work

4. **Security**
   - Keep dependencies updated
   - Review security advisories
   - Use secure coding practices

## Support

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: [docs.ksl.dev](https://docs.ksl.dev)
- **Community**: Join our Discord server

## Resources

- [VS Code Extension Publishing](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
- [VS Code Extension Guidelines](https://code.visualstudio.com/api/references/extension-guidelines)
- [Marketplace Publishing](https://docs.microsoft.com/en-us/azure/devops/extend/publish/overview) 