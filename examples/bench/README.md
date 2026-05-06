# Performance benchmark

Reproducible end-to-end benchmark for ``pqc-audit batch``. Sweeps
``--concurrency`` from 1 to 16, runs each setting twice, emits a
Markdown summary + CSV trend file.

## Run it

```bash
cd pqc-audit-italia
python examples/bench/bench_run.py
```

Output lands in ``examples/bench/results/`` (gitignored).

## Reference numbers

Hardware: laptop, residential DNS, Windows Python 3.13.
Target: 30 host PA italiana from ``pa_30hosts.csv``.

| Concurrency | Elapsed avg (s) | Throughput (host/s) |
|---:|---:|---:|
| 1 | 14.0 | 2.14 |
| 4 | 9.7 | 3.10 |
| 8 | 9.3 | 3.24 |
| 16 | 9.1 | 3.29 |

Sweet spot at concurrency=8 — the DNS resolver becomes the
bottleneck above. 1.5× speedup vs sequential, asymptotic plateau
near 3.3 host/sec on commodity hardware.

## Why benchmark a TLS scanner?

Two reasons:

1. **Investor pitch**: "scan 30 host della PA italiana in <10 sec
   con un comando" è una frase verificabile in tempo reale durante
   una demo. La performance va dimostrata, non promessa.

2. **Regression**: la pipeline cresce. Aggiungere un nuovo controllo
   o un nuovo reporter non deve degradare il throughput di base.
   Il CSV ``results/benchmark.csv`` è una baseline trascinabile in
   un grafico tempo-su-tempo.

## Estendere il benchmark

- Cambia ``CONCURRENCIES = (1, 4, 8, 16)`` in cima a ``bench_run.py``
  per altri valori.
- ``REPETITIONS = 2`` può salire (5-10 per misure più stabili).
- Per testare un dataset diverso, sostituisci ``pa_30hosts.csv`` —
  il formato CSV è quello del subcomando batch.
