# CI/CD examples — `pqc-audit batch` integration

Drop-in workflows that wire `pqc-audit batch` into your delivery
pipeline.  All examples assume:

- A CSV of TLS endpoints at `infra/pqc/targets.csv` (or the path of
  your choice — adjust the `--csv` flag accordingly).
- The policy you want to enforce (`agid_2026`, `pa_critical`,
  `pa_critical_2027`, or `nist_baseline`).

## Common pattern

The same logic powers every example:

1. Install `pqc-audit-italia` in a fresh CI runner (Python 3.11+).
2. Run `pqc-audit batch ... --enforce --fail-on-violations` so the
   exit code feeds the build status: 0 = green, 3 = at least one
   host failed.
3. Upload the `batch_report.md` + `batch_report.json` as a build
   artefact — useful even when the gate trips, so the on-call
   engineer can review what failed without re-running the scan.

## Files

- [`github-actions-pqc-gate.yml`](github-actions-pqc-gate.yml) —
  Weekly cron + on-PR job. Optionally posts the Markdown report as
  a PR comment.
- [`gitlab-ci-pqc-gate.yml`](gitlab-ci-pqc-gate.yml) — Job snippet,
  fits into an existing `.gitlab-ci.yml`. Triggered on schedule, MR
  events touching `infra/`, or manual web run.

## Output snapshot

A successful run prints, on the worker:

```
wrote artefacts/pqc/batch_report.md
wrote artefacts/pqc/batch_report.json
```

A blocked run prints additionally:

```
--fail-on-violations: 2 host(s) failed — exiting 3.
```

…and the job exits 3, surfacing the gate failure in the CI UI.

## Customisation

- **Slow scans**: bump `--concurrency` (range 1..32) for big
  portfolios. 8 is a sensible default; >16 can stress shared DNS.
- **Forward-looking gate**: switch `--policy agid_2026` to
  `--policy pa_critical_2027` to gate against the experimental
  PQC-mandatory profile (12-24 months out).
- **Sensitive data**: pump `--data-sensitivity-years 50` for
  long-retention systems (medical, legal archives) so HNDL tracks
  the right horizon.
