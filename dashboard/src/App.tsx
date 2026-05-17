import { useCallback, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

import type { AuditReport, Severity } from "./types";
import { highestSeverity, severityLabel, totalAssets, totalVulnerabilities } from "./types";

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
        <div className="brand">
          <h1>pqc-audit viewer</h1>
          <span className="version">v{DASHBOARD_VERSION}</span>
        </div>
        <div className="tagline">
          Read-only viewer for post-quantum crypto audit reports. NIS2 / ACN /
          AgID / FIPS 203-205 ready.
        </div>
        <button onClick={handleLoad} data-testid="load-report">
          Load report…
        </button>
        {path && (
          <div className="meta">
            <strong>File</strong>
            {path}
          </div>
        )}
        {report && (
          <>
            <div className="meta">
              <strong>Report id</strong>
              {report.report_id}
            </div>
            <div className="meta">
              <strong>Policy</strong>
              {report.policy_name}
            </div>
          </>
        )}
        <div className="footer">
          Offline · airgapped-safe · no network egress from this viewer.
        </div>
      </aside>

      <main className="main">
        {error && <div className="error">{error}</div>}
        {!report && !error && (
          <div className="empty">
            No report loaded. Use “Load report…” to open a JSON file produced by
            <code style={{ marginLeft: 6 }}>pqc-audit scan …</code>.
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

  const generated = report.generated_at ? new Date(report.generated_at) : null;

  return (
    <>
      <section className="topbar">
        <div>
          <h2>Audit summary</h2>
          <div className="subtitle">
            Policy <code>{report.policy_name}</code>
            {generated && (
              <>
                {" · "}
                generated {generated.toLocaleString()}
              </>
            )}
          </div>
        </div>
        <div className="badge-row">
          <span className={`badge severity-${worst}`}>Worst: {worst}</span>
          <span className="badge muted">{report.scan_results.length} scan{report.scan_results.length === 1 ? "" : "s"}</span>
        </div>
      </section>

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
          <div className={`value severity-${worst.toLowerCase()}`}>{worst}</div>
        </div>
      </section>

      <section>
        <h3>Crypto assets</h3>
        {allAssets.length === 0 ? (
          <div className="empty">No assets discovered.</div>
        ) : (
          <div className="table-wrap">
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
                    <td>
                      <span className="badge muted">{a.scanner}</span>
                    </td>
                    <td>
                      <code>{a.asset_id}</code>
                    </td>
                    <td className="mono">{algorithmCanonical(a.algorithm)}</td>
                    <td>{a.location}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section>
        <h3>Vulnerabilities</h3>
        {allVulns.length === 0 ? (
          <div className="empty">No vulnerabilities detected.</div>
        ) : (
          <div className="table-wrap">
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
                      <td>
                        <span className={`badge severity-${lbl}`}>{lbl}</span>
                      </td>
                      <td>
                        <span className="badge muted">{v.scanner}</span>
                      </td>
                      <td>{v.title}</td>
                      <td className="mono">{v.cwe ?? "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

function algorithmCanonical(a: {
  name: string;
  key_size_bits: number | null;
  mode: string | null;
  curve: string | null;
}): string {
  const parts: string[] = [a.name];
  if (a.key_size_bits && !/\d/.test(a.name.split("-").pop() ?? "")) {
    parts.push(String(a.key_size_bits));
  }
  if (a.mode) parts.push(a.mode);
  return parts.join("-");
}

export default App;
