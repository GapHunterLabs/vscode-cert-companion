import * as vscode from 'vscode';
import { decodePemBundle, decodeDer, formatSummary, CertDecodeError } from './certDecode';
import { recordHit } from './reviewPrompt';

const DER_EXTENSIONS = new Set(['.der', '.cer']);
const KEYSTORE_EXTENSIONS = new Set(['.jks', '.p12', '.pfx']);

let outputChannel: vscode.OutputChannel | undefined;

function output(): vscode.OutputChannel {
  if (!outputChannel) {
    outputChannel = vscode.window.createOutputChannel('Cert Companion');
  }
  return outputChannel;
}

async function decodeActiveFile(context: vscode.ExtensionContext): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  const uri = editor?.document.uri ?? (await pickFile());
  if (!uri) {
    return;
  }

  const ext = uri.path.slice(uri.path.lastIndexOf('.')).toLowerCase();
  if (KEYSTORE_EXTENSIONS.has(ext)) {
    void vscode.window.showErrorMessage(
      `Cert Companion: ${ext} keystores are not supported in this v0.1 (Node has no built-in PKCS12/JKS reader). PEM/CRT/CER/DER certificates only.`,
    );
    return;
  }

  let bytes: Uint8Array;
  try {
    bytes = await vscode.workspace.fs.readFile(uri);
  } catch (error) {
    void vscode.window.showErrorMessage(`Cert Companion: could not read the file (${(error as Error).message}).`);
    return;
  }

  const channel = output();
  channel.clear();

  try {
    if (DER_EXTENSIONS.has(ext) && !looksLikePem(bytes)) {
      const summary = decodeDer(Buffer.from(bytes));
      channel.appendLine(formatSummary(summary));
    } else {
      const text = Buffer.from(bytes).toString('utf8');
      const summaries = decodePemBundle(text);
      channel.appendLine(
        summaries.length > 1
          ? `Found ${summaries.length} certificates in this bundle.\n`
          : '',
      );
      summaries.forEach((summary, index) => {
        channel.appendLine(formatSummary(summary, summaries.length > 1 ? index : undefined));
        channel.appendLine('');
      });
    }
    channel.show(true);
    recordHit(context);
  } catch (error) {
    const message = error instanceof CertDecodeError ? error.message : String(error);
    void vscode.window.showErrorMessage(`Cert Companion: ${message}`);
  }
}

function looksLikePem(bytes: Uint8Array): boolean {
  // Cheap check on the first bytes -- PEM is ASCII text starting with
  // "-----BEGIN"; DER is binary and won't decode cleanly as that prefix.
  const head = Buffer.from(bytes.slice(0, 11)).toString('latin1');
  return head === '-----BEGIN ';
}

async function pickFile(): Promise<vscode.Uri | undefined> {
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    filters: { Certificates: ['pem', 'crt', 'cer', 'der'] },
    openLabel: 'Decode certificate',
  });
  return picked?.[0];
}

export function activate(context: vscode.ExtensionContext): void {
  const command = vscode.commands.registerCommand('certCompanion.decodeActiveFile', () => {
    void decodeActiveFile(context);
  });
  context.subscriptions.push(command);
}

export function deactivate(): void {
  outputChannel?.dispose();
}
