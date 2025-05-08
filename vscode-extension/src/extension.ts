import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Tree item for the scaffold explorer
class ScaffoldTreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly template?: string,
        public readonly itemDescription?: string
    ) {
        super(label, collapsibleState);
        this.description = itemDescription || '';
        this.tooltip = itemDescription || '';
    }
}

// Tree data provider for the scaffold explorer
class ScaffoldTreeDataProvider implements vscode.TreeDataProvider<ScaffoldTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<ScaffoldTreeItem | undefined | null | void> = new vscode.EventEmitter<ScaffoldTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<ScaffoldTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private templates: any[] = [];

    constructor(private context: vscode.ExtensionContext) {
        this.loadTemplates();
    }

    private async loadTemplates() {
        try {
            const { stdout } = await execAsync('ksl scaffold --list-templates');
            this.templates = JSON.parse(stdout);
            this._onDidChangeTreeData.fire();
        } catch (error) {
            vscode.window.showErrorMessage('Failed to load templates');
        }
    }

    getTreeItem(element: ScaffoldTreeItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: ScaffoldTreeItem): Promise<ScaffoldTreeItem[]> {
        if (!element) {
            // Root level - show template categories
            return [
                new ScaffoldTreeItem('Smart Contracts', vscode.TreeItemCollapsibleState.Expanded, 'contracts'),
                new ScaffoldTreeItem('Validators', vscode.TreeItemCollapsibleState.Expanded, 'validators'),
                new ScaffoldTreeItem('AI Models', vscode.TreeItemCollapsibleState.Expanded, 'ai'),
                new ScaffoldTreeItem('IoT Devices', vscode.TreeItemCollapsibleState.Expanded, 'iot'),
                new ScaffoldTreeItem('Shard Modules', vscode.TreeItemCollapsibleState.Expanded, 'shards'),
                new ScaffoldTreeItem('ZK Proofs', vscode.TreeItemCollapsibleState.Expanded, 'zk')
            ];
        }

        // Filter templates by category
        const categoryTemplates = this.templates.filter(t => t.category === element.template);
        return categoryTemplates.map(t => new ScaffoldTreeItem(
            t.name,
            vscode.TreeItemCollapsibleState.None,
            t.id,
            t.description
        ));
    }

    refresh(): void {
        this.loadTemplates();
    }
}

// Diagnostic collection for scaffold validation
class ScaffoldDiagnostics {
    private collection: vscode.DiagnosticCollection;

    constructor() {
        this.collection = vscode.languages.createDiagnosticCollection('ksl-scaffold');
    }

    update(uri: vscode.Uri, diagnostics: vscode.Diagnostic[]) {
        this.collection.set(uri, diagnostics);
    }

    clear() {
        this.collection.clear();
    }
}

// Test simulator for scaffolded projects
class ScaffoldSimulator {
    private process: any = null;
    private outputChannel: vscode.OutputChannel;

    constructor(outputChannel: vscode.OutputChannel) {
        this.outputChannel = outputChannel;
    }

    async start(projectPath: string): Promise<void> {
        if (this.process) {
            throw new Error('Simulator is already running');
        }

        try {
            // Start the simulator process
            this.process = exec('ksl scaffold --simulate', {
                cwd: projectPath
            });

            this.process.stdout.on('data', (data: string) => {
                this.outputChannel.appendLine(data);
            });

            this.process.stderr.on('data', (data: string) => {
                this.outputChannel.appendLine(`Error: ${data}`);
            });

            this.process.on('close', (code: number) => {
                this.process = null;
                if (code !== 0) {
                    this.outputChannel.appendLine(`Simulator exited with code ${code}`);
                }
            });
        } catch (error) {
            this.process = null;
            throw error;
        }
    }

    stop(): void {
        if (this.process) {
            this.process.kill();
            this.process = null;
        }
    }

    isRunning(): boolean {
        return this.process !== null;
    }
}

export function activate(context: vscode.ExtensionContext) {
    // Create tree view
    const treeDataProvider = new ScaffoldTreeDataProvider(context);
    const treeView = vscode.window.createTreeView('kslScaffoldExplorer', {
        treeDataProvider,
        showCollapseAll: true
    });

    // Create diagnostics
    const diagnostics = new ScaffoldDiagnostics();

    // Create simulator
    const simulator = new ScaffoldSimulator(vscode.window.createOutputChannel('KSL Simulator'));

    // Register KSL Scaffold command
    let disposable = vscode.commands.registerCommand('ksl.scaffold', async () => {
        try {
            // Get workspace folder
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
            if (!workspaceFolder) {
                throw new Error('No workspace folder found');
            }

            // Create output channel for logging
            const outputChannel = vscode.window.createOutputChannel('KSL Scaffold');
            outputChannel.show();

            // Show scaffold GUI
            const gui = new ScaffoldGui(workspaceFolder.uri.fsPath, outputChannel, diagnostics, simulator);
            await gui.show();
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to start KSL Scaffold: ${error}`);
        }
    });

    // Register template selection command
    let templateCommand = vscode.commands.registerCommand('ksl.scaffold.selectTemplate', async (template: string) => {
        try {
            const gui = new ScaffoldGui(
                vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '',
                vscode.window.createOutputChannel('KSL Scaffold'),
                diagnostics,
                simulator
            );
            await gui.show(template);
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to select template: ${error}`);
        }
    });

    // Register refresh command
    let refreshCommand = vscode.commands.registerCommand('ksl.scaffold.refresh', () => {
        treeDataProvider.refresh();
    });

    context.subscriptions.push(disposable, templateCommand, refreshCommand, treeView);
}

class ScaffoldGui {
    private outputChannel: vscode.OutputChannel;
    private workspacePath: string;
    private diagnostics: ScaffoldDiagnostics;
    private simulator: ScaffoldSimulator;
    private panel: vscode.WebviewPanel | undefined;

    constructor(
        workspacePath: string,
        outputChannel: vscode.OutputChannel,
        diagnostics: ScaffoldDiagnostics,
        simulator: ScaffoldSimulator
    ) {
        this.workspacePath = workspacePath;
        this.outputChannel = outputChannel;
        this.diagnostics = diagnostics;
        this.simulator = simulator;
    }

    async show(selectedTemplate?: string) {
        // Create webview panel
        this.panel = vscode.window.createWebviewPanel(
            'kslScaffold',
            'KSL Scaffold',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        // Set webview content
        this.panel.webview.html = this.getWebviewContent(selectedTemplate);

        // Handle messages from webview
        this.panel.webview.onDidReceiveMessage(
            async message => {
                switch (message.command) {
                    case 'get_templates':
                        this.getTemplates(this.panel!);
                        break;
                    case 'get_component_types':
                        this.getComponentTypes(this.panel!);
                        break;
                    case 'scaffold':
                        await this.scaffold(this.panel!, message.data);
                        break;
                    case 'validate':
                        this.validateScaffold(message.data);
                        break;
                    case 'startSimulator':
                        await this.startSimulator(message.data);
                        break;
                    case 'stopSimulator':
                        this.stopSimulator();
                        break;
                    case 'selectTemplate':
                        await this.selectTemplate(message.templateId);
                        break;
                }
            },
            undefined,
            []
        );

        // Handle panel close
        this.panel.onDidDispose(() => {
            this.stopSimulator();
            this.panel = undefined;
        });
    }

    private getWebviewContent(selectedTemplate?: string) {
        // Read HTML template
        const htmlPath = path.join(__dirname, '..', 'templates', 'scaffold_preview.html');
        let html = fs.readFileSync(htmlPath, 'utf8');

        // Replace external.invoke with vscode.postMessage
        html = html.replace(/external\.invoke\(/g, 'vscode.postMessage({ command: ');
        html = html.replace(/\)/g, ' })');

        // Set selected template if provided
        if (selectedTemplate) {
            html = html.replace('id="template"', `id="template" value="${selectedTemplate}"`);
        }

        return html;
    }

    private async getTemplates(panel: vscode.WebviewPanel) {
        try {
            // Execute ksl scaffold --list-templates
            const { stdout } = await execAsync('ksl scaffold --list-templates');
            const templates = JSON.parse(stdout);

            // Send templates to webview
            panel.webview.postMessage({
                command: 'updateTemplates',
                templates
            });
        } catch (error) {
            this.outputChannel.appendLine(`Failed to get templates: ${error}`);
            vscode.window.showErrorMessage('Failed to get templates');
        }
    }

    private async getComponentTypes(panel: vscode.WebviewPanel) {
        try {
            // Execute ksl scaffold --list-component-types
            const { stdout } = await execAsync('ksl scaffold --list-component-types');
            const types = JSON.parse(stdout);

            // Send component types to webview
            panel.webview.postMessage({
                command: 'updateComponentTypes',
                types
            });
        } catch (error) {
            this.outputChannel.appendLine(`Failed to get component types: ${error}`);
            vscode.window.showErrorMessage('Failed to get component types');
        }
    }

    private validateScaffold(data: any) {
        const diagnostics: vscode.Diagnostic[] = [];
        const uri = vscode.Uri.file(path.join(this.workspacePath, data.output_path));

        // Check if output path exists
        if (!fs.existsSync(data.output_path)) {
            diagnostics.push({
                range: new vscode.Range(0, 0, 0, 0),
                message: `Output path does not exist: ${data.output_path}`,
                severity: vscode.DiagnosticSeverity.Error
            });
        }

        // Check if project name is valid
        if (!/^[a-zA-Z0-9_-]+$/.test(data.project_name)) {
            diagnostics.push({
                range: new vscode.Range(0, 0, 0, 0),
                message: 'Project name can only contain letters, numbers, underscores, and hyphens',
                severity: vscode.DiagnosticSeverity.Error
            });
        }

        // Update diagnostics
        this.diagnostics.update(uri, diagnostics);
    }

    private async scaffold(panel: vscode.WebviewPanel, data: any) {
        try {
            // Validate scaffold data
            this.validateScaffold(data);

            // Build scaffold command
            let command = 'ksl scaffold';
            
            if (data.component_mode) {
                command += ` --component --component-type ${data.component_type}`;
                command += ` --name ${data.project_name}`;
                command += ` --path ${path.join(this.workspacePath, data.output_path)}`;
                
                if (data.features.length > 0) {
                    command += ` --features ${data.features.join(',')}`;
                }
                
                if (data.generate_tests) {
                    command += ' --generate-tests';
                }
            } else {
                command += ` --name ${data.project_name}`;
                command += ` --template ${data.template}`;
                command += ` --path ${path.join(this.workspacePath, data.output_path)}`;
                
                if (data.sandbox) {
                    command += ' --sandbox';
                }
                
                if (data.generate_abi) {
                    command += ' --generate-abi';
                }
                
                if (data.enable_zk) {
                    command += ' --enable-zk';
                }
                
                if (data.inject) {
                    command += ' --inject';
                    if (data.target_module) {
                        command += ` --target-module ${data.target_module}`;
                    }
                }
            }

            // Execute scaffold command
            this.outputChannel.appendLine(`Executing: ${command}`);
            const { stdout, stderr } = await execAsync(command);
            
            if (stderr) {
                this.outputChannel.appendLine(`Error: ${stderr}`);
                throw new Error(stderr);
            }

            this.outputChannel.appendLine(stdout);
            
            // Show success message
            panel.webview.postMessage({
                command: 'showSuccess',
                message: 'Scaffold completed successfully!'
            });

            // Refresh explorer
            vscode.commands.executeCommand('workbench.files.action.refreshFilesExplorer');
        } catch (error) {
            this.outputChannel.appendLine(`Failed to scaffold: ${error}`);
            panel.webview.postMessage({
                command: 'showError',
                message: `Failed to scaffold: ${error}`
            });
        }
    }

    private async startSimulator(data: any) {
        try {
            const projectPath = path.join(this.workspacePath, data.output_path);
            await this.simulator.start(projectPath);
            
            this.panel?.webview.postMessage({
                command: 'simulatorStatus',
                status: 'running',
                message: 'Simulator is running'
            });
        } catch (error) {
            this.panel?.webview.postMessage({
                command: 'simulatorStatus',
                status: 'error',
                message: `Failed to start simulator: ${error}`
            });
        }
    }

    private stopSimulator() {
        this.simulator.stop();
        
        this.panel?.webview.postMessage({
            command: 'simulatorStatus',
            status: 'stopped',
            message: 'Simulator stopped'
        });
    }

    private async selectTemplate(templateId: string) {
        try {
            // Get template details
            const { stdout } = await execAsync(`ksl scaffold --template-info ${templateId}`);
            const template = JSON.parse(stdout);

            // Update preview
            this.panel?.webview.postMessage({
                command: 'updatePreview',
                fileTree: template.fileTree,
                ignoredFiles: template.ignoredFiles,
                diagnostics: []
            });
        } catch (error) {
            this.outputChannel.appendLine(`Failed to get template info: ${error}`);
            vscode.window.showErrorMessage('Failed to get template info');
        }
    }
}

export function deactivate() {} 