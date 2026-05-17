# pqc-audit-italia desktop viewer

Cross-OS read-only viewer for the JSON reports produced by
`pqc-audit-italia`. Built on Tauri v2 (Rust + WebView) so the binary
is small (8–15 MB target), distributable on Windows / macOS / Linux,
and ships with zero runtime dependencies for the end-user.

**Scope (alpha 0.1.0):**

- File picker → load an existing `pqc-audit scan …` JSON report.
- Tabular view of crypto assets and vulnerabilities.
- Summary cards (scan count, asset count, vulnerability count,
  highest severity).
- **No scan capability** — by design. The dashboard never spawns a
  scan, never makes a network request, never touches private keys.
  Audits run via the CLI; the dashboard renders the output.

## Dev loop

```bash
cd dashboard
npm install
npm run tauri dev
```

Vite serves the renderer on `http://localhost:1420` (fixed port). The
Tauri shell wraps it in a native window via WebView2 / WebKitGTK /
WKWebView.

## Build

```bash
npm run tauri build
```

Produces platform-native installers under `src-tauri/target/release/bundle/`.

## File layout

```
dashboard/
├── package.json           # Frontend deps (React + Vite + Tauri JS API)
├── vite.config.ts
├── tsconfig.json
├── index.html
├── src/
│   ├── main.tsx           # React entry point
│   ├── App.tsx            # Single-page viewer
│   ├── types.ts           # Report schema (subset)
│   └── styles.css
└── src-tauri/
    ├── Cargo.toml         # Tauri v2 + dialog plugin
    ├── tauri.conf.json    # Window config, CSP, bundle metadata
    ├── build.rs
    ├── capabilities/
    │   └── default.json   # Permission set (dialog only, no shell/http/fs)
    └── src/
        ├── main.rs
        └── lib.rs         # load_report command
```

## Security posture

- CSP locks scripts to `self`, no remote loading.
- Tauri capabilities are minimal: dialog plugin + `load_report`
  command. No `shell:`, no `http:`, no `fs:` (the only fs read happens
  inside the validated `load_report` handler with a 64 MiB cap).
- `load_report` validates the path is a regular file before reading;
  pointing it at `/etc/passwd` returns an error, not the file content.
