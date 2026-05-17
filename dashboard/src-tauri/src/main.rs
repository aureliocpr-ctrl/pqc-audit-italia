// Prevents an extra console window on Windows in release builds; the
// debug build keeps it so panics and println! are visible during dev.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    pqc_audit_dashboard_lib::run()
}
