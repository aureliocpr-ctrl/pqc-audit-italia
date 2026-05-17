//! pqc-audit-italia desktop viewer — Tauri v2 backend.
//!
//! The Rust side is intentionally tiny: one IPC command that reads a
//! UTF-8 JSON file from disk and returns its content as a string. The
//! frontend does the parsing and rendering. This split keeps the
//! attack surface narrow — the dashboard never spawns a scan, never
//! makes a network request, never touches private keys.
//!
//! Security note: the file open dialog runs inside Tauri's renderer
//! via the dialog plugin, which uses the OS-native picker. The path
//! returned by the picker is the only input we'll ever ``read_to_string``;
//! we still validate it to refuse non-files and oversize payloads
//! (cap 64 MiB — generous for an audit JSON, paranoid against a
//! mis-pasted path pointing at a system file).

use std::fs;
use std::path::{Path, PathBuf};

const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;

#[tauri::command]
fn load_report(path: String) -> Result<String, String> {
    let pb = PathBuf::from(&path);
    validate_path(&pb).map_err(|e| e.to_string())?;
    fs::read_to_string(&pb).map_err(|e| format!("could not read {path}: {e}"))
}

fn validate_path(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("path does not exist or is unreadable: {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("path is not a regular file: {}", path.display()));
    }
    if metadata.len() > MAX_REPORT_BYTES {
        return Err(format!(
            "report file too large: {} bytes (cap {} bytes)",
            metadata.len(),
            MAX_REPORT_BYTES
        ));
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![load_report])
        .run(tauri::generate_context!())
        .expect("error while running pqc-audit dashboard");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn validate_path_rejects_missing_file() {
        let bogus = PathBuf::from("/nope/nope/nope/does-not-exist.json");
        assert!(validate_path(&bogus).is_err());
    }

    #[test]
    fn validate_path_accepts_regular_file() {
        let dir = tempdir_in_target();
        let path = dir.join("report.json");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"{\"report_id\":\"x\"}").unwrap();
        assert!(validate_path(&path).is_ok());
    }

    #[test]
    fn validate_path_rejects_directory() {
        let dir = tempdir_in_target();
        assert!(validate_path(&dir).is_err());
    }

    fn tempdir_in_target() -> PathBuf {
        // CARGO_TARGET_TMPDIR is only populated for *integration* tests
        // (those in tests/), not for in-source #[cfg(test)] modules. We
        // fall back to OUT_DIR (set during build) and finally to the OS
        // tmp dir so the suite works in all three invocation styles
        // (cargo test --lib, cargo test --tests, cargo nextest).
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .or_else(|| std::env::var_os("OUT_DIR"))
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let mut p = base;
        p.push(format!(
            "pqc_audit_dashboard_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }
}
