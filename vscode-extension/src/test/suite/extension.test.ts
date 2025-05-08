import * as assert from 'assert';
import * as vscode from 'vscode';
import * as path from 'path';

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
        } catch (error) {
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
        } catch (error) {
            assert.fail('Start simulator failed');
        }

        // Stop simulator
        try {
            await vscode.commands.executeCommand('ksl.scaffold.stopSimulator');
            assert.ok(true);
        } catch (error) {
            assert.fail('Stop simulator failed');
        }
    });
}); 