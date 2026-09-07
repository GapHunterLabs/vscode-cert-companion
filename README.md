# Cert Companion (VS Code)

Decode X.509 certificates (PEM/CRT/CER/DER) — subject, issuer,
validity window, SHA-256 fingerprint, and an expiry check — no data
leaves your editor.

**v0.1, pilot.** Part of the Gap Hunter Labs VS Code workstream
porting selected niches from the
[IntelliJ-family catalog](https://plugins.jetbrains.com/vendor/gap-hunter-labs).
The IntelliJ-family Cert Companion also decodes `.jks`/`.p12`/`.pfx`
keystores — **this version doesn't (yet)**: Node has no built-in
PKCS12/JKS reader, and adding one means either a third-party
dependency or shelling out to OpenSSL, neither done here. The command
tells you plainly when you hit that gap instead of failing silently.

## What it does

**Command: `Cert Companion: Decode Certificate File`** — run it with a
`.pem`/`.crt`/`.cer`/`.der` file open (or pick one from a file dialog).
Multi-certificate PEM bundles decode one card per certificate, not a
squeezed single view. Output goes to an output channel:

```
=== Certificate #1 ===
Subject:      CN=example.test, O=..., L=Test, ST=Test, C=US
Issuer:       CN=example.test, ...
Serial:       12:34:...
Valid from:   2026-09-07T07:00:07.000Z
Valid to:     2036-09-04T07:00:07.000Z
SHA-256 fpr:  AB:CD:...
Status:       valid
```

Uses Node's built-in `node:crypto` `X509Certificate` — no third-party
crypto library, same "standard-library-only" philosophy as the
IntelliJ-family version (JDK-only there).

## Privacy

See [PRIVACY.md](PRIVACY.md) — zero network calls, decoding happens
entirely in your editor process.

## Development

```bash
npm install
npm run compile   # or: npm run watch
npm test
```

Press F5 (with this folder open) to launch an Extension Development
Host. To build an installable package without publishing:

```bash
npx @vscode/vsce package
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
