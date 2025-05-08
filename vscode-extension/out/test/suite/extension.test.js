"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const assert = __importStar(require("assert"));
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
suite('KSL Scaffold Extension Test Suite', () => {
    test('Extension should be present', () => {
        assert.ok(vscode.extensions.getExtension('ksl.scaffold'));
    });
    test('Should activate', async () => {
        const ext = vscode.extensions.getExtension('ksl.scaffold');
        await ext?.activate();
        assert.strictEqual(ext?.isActive, true);
    });
    test('Should register all commands', async () => {
        const commands = await vscode.commands.getCommands();
        assert.ok(commands.includes('ksl.scaffold'));
        assert.ok(commands.includes('ksl.scaffold.selectTemplate'));
        assert.ok(commands.includes('ksl.scaffold.refresh'));
        assert.ok(commands.includes('ksl.scaffold.startSimulator'));
        assert.ok(commands.includes('ksl.scaffold.stopSimulator'));
    });
    test('Should show scaffold GUI', async () => {
        await vscode.commands.executeCommand('ksl.scaffold');
        const panels = vscode.window.visibleTextEditors;
        assert.ok(panels.length > 0);
    });
    test('Should show template explorer', async () => {
        const view = await vscode.window.createTreeView('kslScaffoldExplorer', {
            treeDataProvider: {
                getTreeItem: () => new vscode.TreeItem('test'),
                getChildren: () => Promise.resolve([])
            }
        });
        assert.ok(view);
    });
    test('Should validate scaffold data', async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            assert.fail('No workspace folder found');
        }
        const testData = {
            project_name: 'test-project',
            output_path: path.join(workspaceFolder.uri.fsPath, 'test-output'),
            template: 'smart-contract',
            sandbox: true
        };
        // Execute scaffold command
        try {
            await vscode.commands.executeCommand('ksl.scaffold', testData);
            assert.ok(true);
        }
        catch (error) {
            assert.fail('Scaffold command failed');
        }
    });
    test('Should handle simulator', async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            assert.fail('No workspace folder found');
        }
        // Start simulator
        try {
            await vscode.commands.executeCommand('ksl.scaffold.startSimulator', {
                output_path: path.join(workspaceFolder.uri.fsPath, 'test-output')
            });
            assert.ok(true);
        }
        catch (error) {
            assert.fail('Start simulator failed');
        }
        // Stop simulator
        try {
            await vscode.commands.executeCommand('ksl.scaffold.stopSimulator');
            assert.ok(true);
        }
        catch (error) {
            assert.fail('Stop simulator failed');
        }
    });
});
//# sourceMappingURL=extension.test.js.map