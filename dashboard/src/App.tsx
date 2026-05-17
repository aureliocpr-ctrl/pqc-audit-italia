import { useCallback, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

import type { AuditReport, Severity } from "./types";
import {
  highestSeverity,
  severityLabel,
  totalAssets,
  totalVulnerabilities,
} from "./types";

const DASHBOARD_VERSION = "0.1.0-alpha";

function App() {
  const [report, setReport] = useState<AuditReport | null>(null);
  const [path, setPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleLoad = useCallback(async () => {
    setError(null);
    const selected = await open({
      multiple: false,
      title: "Select pqc-audit JSON report",
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (!selected || Array.isArray(selected)) return;
    try {
      const json = await invoke<string>("load_report", { path: selected });
      const parsed = JSON.parse(json) as AuditReport;
      setReport(parsed);
      setPath(selected);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
      setReport(null);
      setPath(null);
    }
  }, []);

  return (
    <div className="app">
      <aside className="sidebar">
        <div>
          <h1>pqc-audit viewer</h1>
          <div className="version">v{DASHBOARD_VERSION}</div>
        </div>
        <button onClick={handleLoad} data-testid="load-report">
          Load report…
        </button>
        {path && <div className="meta">{path}</div>}
        {report && (
          <div className="meta">
            <div>
              <strong>Report id</strong>
              <br />
              {report.report_id}
            </div>
            <div style={{ marginTop: 8 }}>
              <strong>Policy</strong>
              <br />
              {report.policy_name}
            </div>
          </div>
        )}
      </aside>

      <main className="main">
        {error && <div className="error">{error}</div>}
        {!report && !error && (
          <div className="empty">
            No report loaded. Use “Load report…” to open a JSON file produced by
            <code style={{ marginLeft: 4 }}>pqc-audit scan …</code>.
          </div>
        )}
        {report && <ReportView report={report} />}
      </main>
    </div>
  );
}

function ReportView({ report }: { report: AuditReport }) {
  const assetCount = totalAssets(report);
  const vulnCount = totalVulnerabilities(report);
  const worst: Severity = highestSeverity(report);

  const allAssets = report.scan_results.flatMap((sr) =>
    sr.assets.map((a) => ({ scanner: sr.scanner_name, ...a })),
  );
  const allVulns = report.scan_results.flatMap((sr) =>
    sr.vulnerabilities.map((v) => ({ scanner: sr.scanner_name, ...v })),
  );

  return (
    <>
      <section className="summary">
        <div className="card">
          <div className="label">Scan results</div>
          <div className="value">{report.scan_results.length}</div>
        </div>
        <div className="card">
          <div className="label">Crypto assets</div>
          <div className="value">{assetCount}</div>
        </div>
        <div className="card">
          <div className="label">Vulnerabilities</div>
          <div className="value">{vulnCount}</div>
        </div>
        <div className="card">
          <div className="label">Highest severity</div>
          <div className="value" style={{ color: severityColor(worst) }}>
            {worst}
          </div>
        </div>
      </section>

      <section>
        <h2>Crypto assets</h2>
        {allAssets.length === 0 ? (
          <div className="empty">No assets discovered.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Scanner</th>
                <th>Asset id</th>
                <th>Algorithm</th>
                <th>Location</th>
              </tr>
            </thead>
            <tbody>
              {allAssets.map((a) => (
                <tr key={a.asset_id}>
                  <td>{a.scanner}</td>
                  <td>
                    <code>{a.asset_id}</code>
                  </td>
                  <td>{algorithmCanonical(a.algorithm)}</td>
                  <td>{a.location}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section>
        <h2>Vulnerabilities</h2>
        {allVulns.length === 0 ? (
          <div className="empty">No vulnerabilities detected.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Scanner</th>
                <th>Title</th>
                <th>CWE</th>
              </tr>
            </thead>
            <tbody>
              {allVulns.map((v, i) => {
                const lbl = severityLabel(v.severity);
                return (
                  <tr key={`${v.title}-${i}`}>
                    <td className={`severity ${lbl}`}>{lbl}</td>
                    <td>{v.scanner}</td>
                    <td>{v.title}</td>
                    <td>{v.cwe ?? "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}

function algorithmCanonical(a: { name: string; key_size_bits: number | null; mode: string | null; curve: string | null }): string {
  const parts: string[] = [a.name];
  // The python side encodes key size in the canonical_name suffix only
  // when it isn't already implied by the algorithm name (e.g. Ed25519).
  if (a.key_size_bits && !/\d/.test(a.name.split("-").pop() ?? "")) {
    parts.push(String(a.key_size_bits));
  }
  if (a.mode) parts.push(a.mode);
  return parts.join("-");
}

function severityColor(s: Severity): string {
  switch (s) {
    case "CRITICAL":
      return "var(--critical)";
    case "HIGH":
      return "var(--high)";
    case "MEDIUM":
      return "var(--medium)";
    case "LOW":
      return "var(--low)";
    default:
      return "var(--info)";
  }
}

export default App;
