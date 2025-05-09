import * as path from 'path';
import * as vscode from 'vscode';
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient;

interface TypeHint {
    line: number;
    character: number;
    text: string;
}

interface Message {
    command: string;
    [key: string]: any;
}

interface IRFunction {
    name: string;
    gasEstimate: number;
    opcodes: string[];
}

interface IRData {
    functions: IRFunction[];
}

export function activate(context: vscode.ExtensionContext) {
    // Server options - use Rust-based LSP server
    const serverOptions: ServerOptions = {
        command: 'ksl-language-server',
        transport: TransportKind.stdio
    };

    // Client options
    const clientOptions: LanguageClientOptions = {
        documentSelector: [{ scheme: 'file', language: 'ksl' }],
        synchronize: {
            fileEvents: vscode.workspace.createFileSystemWatcher('**/*.ksl')
        }
    };

    // Create and start client
    client = new LanguageClient(
        'kslLanguageServer',
        'KSL Language Server',
        serverOptions,
        clientOptions
    );

    // Start the client
    client.start();

    // Register IR viewer
    const irViewProvider = new IRViewProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('kslIRView', irViewProvider)
    );

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('ksl.exportIR', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showErrorMessage('No active editor');
                return;
            }

            const document = editor.document;
            if (document.languageId !== 'ksl') {
                vscode.window.showErrorMessage('Not a KSL file');
                return;
            }

            try {
                const irContent = await client.sendRequest<string>('ksl/exportIR', document.uri.toString());
                await vscode.workspace.fs.writeFile(
                    vscode.Uri.file(document.uri.fsPath + '.ir.json'),
                    new Uint8Array(Buffer.from(JSON.stringify(irContent, null, 2)))
                );
                vscode.window.showInformationMessage('IR exported successfully');
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to export IR: ${err}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('ksl.exportABI', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showErrorMessage('No active editor');
                return;
            }

            const document = editor.document;
            if (document.languageId !== 'ksl') {
                vscode.window.showErrorMessage('Not a KSL file');
                return;
            }

            try {
                const abiContent = await client.sendRequest<string>('ksl/exportABI', document.uri.toString());
                await vscode.workspace.fs.writeFile(
                    vscode.Uri.file(document.uri.fsPath + '.abi.json'),
                    new Uint8Array(Buffer.from(JSON.stringify(abiContent, null, 2)))
                );
                vscode.window.showInformationMessage('ABI exported successfully');
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to export ABI: ${err}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('ksl.deployToTestnet', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showErrorMessage('No active editor');
                return;
            }

            const document = editor.document;
            if (document.languageId !== 'ksl') {
                vscode.window.showErrorMessage('Not a KSL file');
                return;
            }

            try {
                const result = await client.sendRequest<{ address: string }>('ksl/deploy', {
                    uri: document.uri.toString(),
                    testnetUrl: vscode.workspace.getConfiguration('ksl').get('testnetUrl')
                });
                vscode.window.showInformationMessage(`Contract deployed at: ${result.address}`);
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to deploy contract: ${err}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('ksl.simulateFunction', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showErrorMessage('No active editor');
                return;
            }

            const document = editor.document;
            if (document.languageId !== 'ksl') {
                vscode.window.showErrorMessage('Not a KSL file');
                return;
            }

            const position = editor.selection.active;
            try {
                const result = await client.sendRequest<any>('ksl/simulate', {
                    uri: document.uri.toString(),
                    line: position.line,
                    character: position.character
                });
                
                // Show simulation results in a new editor
                const doc = await vscode.workspace.openTextDocument({
                    content: JSON.stringify(result, null, 2),
                    language: 'json'
                });
                await vscode.window.showTextDocument(doc, { preview: false });
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to simulate function: ${err}`);
            }
        })
    );

    // Register type hint provider
    context.subscriptions.push(
        vscode.languages.registerInlayHintsProvider('ksl', {
            provideInlayHints: async (
                document: vscode.TextDocument,
                range: vscode.Range,
                token: vscode.CancellationToken
            ): Promise<vscode.InlayHint[]> => {
                const hints = await client.sendRequest<TypeHint[]>('ksl/typeHints', {
                    uri: document.uri.toString(),
                    range: {
                        start: { line: range.start.line, character: range.start.character },
                        end: { line: range.end.line, character: range.end.character }
                    }
                });
                
                return hints.map(hint => new vscode.InlayHint(
                    new vscode.Position(hint.line, hint.character),
                    hint.text,
                    vscode.InlayHintKind.Type
                ));
            }
        })
    );
}

export function deactivate(): Promise<void> | undefined {
    if (!client) {
        return undefined;
    }
    return client.stop();
}

class IRViewProvider implements vscode.WebviewViewProvider {
    constructor(private readonly extensionUri: vscode.Uri) {}

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken,
    ): void {
        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this.extensionUri]
        };

        webviewView.webview.html = this.getHtmlForWebview(webviewView.webview);

        // Handle messages from the webview
        webviewView.webview.onDidReceiveMessage(async (message: Message) => {
            switch (message.command) {
                case 'refresh':
                    const editor = vscode.window.activeTextEditor;
                    if (editor && editor.document.languageId === 'ksl') {
                        try {
                            const ir = await client.sendRequest<IRData>('ksl/getIR', editor.document.uri.toString());
                            webviewView.webview.postMessage({ type: 'update', data: ir });
                        } catch (err) {
                            vscode.window.showErrorMessage(`Failed to refresh IR view: ${err}`);
                        }
                    }
                    break;
            }
        });
    }

    private getHtmlForWebview(webview: vscode.Webview): string {
        return `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>KSL IR Viewer</title>
                <style>
                    .function { margin-bottom: 1em; }
                    .function-name { font-weight: bold; }
                    .gas-estimate { color: #666; }
                </style>
            </head>
            <body>
                <div id="content"></div>
                <script>
                    const vscode = acquireVsCodeApi();
                    
                    window.addEventListener('message', event => {
                        const message = event.data;
                        switch (message.type) {
                            case 'update':
                                const content = document.getElementById('content');
                                content.innerHTML = '';
                                
                                // Render functions
                                message.data.functions.forEach(func => {
                                    const div = document.createElement('div');
                                    div.className = 'function';
                                    div.innerHTML = \`
                                        <div class="function-name">\${func.name}</div>
                                        <div class="gas-estimate">Gas: \${func.gasEstimate}</div>
                                        <pre>\${JSON.stringify(func.opcodes, null, 2)}</pre>
                                    \`;
                                    content.appendChild(div);
                                });
                                break;
                        }
                    });

                    // Initial refresh
                    vscode.postMessage({ command: 'refresh' });
                </script>
            </body>
            </html>
        `;
    }
} 