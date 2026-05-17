// Minimum subset of the pqc-audit JSON schema the viewer renders.
//
// We intentionally do not import the full python-side pydantic schema.
// The dashboard is meant to be tolerant of extra fields and forward-
// compatible across minor version bumps of the report format.

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Algorithm {
  name: string;
  key_size_bits: number | null;
  curve: string | null;
  mode: string | null;
}

export interface CryptoAsset {
  asset_id: string;
  category: string;
  algorithm: Algorithm;
  location: string;
  discovered_at: string;
  metadata: Record<string, unknown>;
}

export interface Vulnerability {
  title: string;
  description: string;
  severity: Severity | number;
  cwe: string | null;
  references: string[];
  affected_asset_ids: string[];
}

export interface ScanResult {
  scanner_name: string;
  target: string;
  assets: CryptoAsset[];
  vulnerabilities: Vulnerability[];
  started_at: string;
  finished_at: string;
  errors: string[];
}

export interface AuditReport {
  report_id: string;
  scan_results: ScanResult[];
  policy_name: string;
  generated_at: string;
  metadata: Record<string, unknown>;
  // The python JSON reporter decorates the payload with this — accept
  // it gracefully even though it isn't part of the canonical model.
  summary?: {
    tool?: string;
    tool_version?: string;
    total_assets?: number;
    total_vulnerabilities?: number;
    highest_severity?: Severity;
  };
}

export function severityLabel(s: Severity | number): Severity {
  if (typeof s === "number") {
    return (["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"][s] ?? "INFO") as Severity;
  }
  return s;
}

export function totalAssets(r: AuditReport): number {
  return r.scan_results.reduce((acc, sr) => acc + sr.assets.length, 0);
}

export function totalVulnerabilities(r: AuditReport): number {
  return r.scan_results.reduce((acc, sr) => acc + sr.vulnerabilities.length, 0);
}

export function highestSeverity(r: AuditReport): Severity {
  const order: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
  let max: Severity = "INFO";
  for (const sr of r.scan_results) {
    for (const v of sr.vulnerabilities) {
      const lbl = severityLabel(v.severity);
      if (order.indexOf(lbl) > order.indexOf(max)) max = lbl;
    }
  }
  return max;
}
