# waffy Performance

This document records **actual measured output** from
`scripts/benchmarks/latency_bench.py` and `scripts/benchmarks/throughput_bench.py`,
per `docs/MASTER_SPEC.md` §21 and `CLAUDE.md`'s labeling-honesty rule. Every
number below is copy-pasted from a real run on the reference hardware
described below — nothing here is estimated or assumed. If a future run
produces different numbers, replace this document's numbers with the new
real output; don't blend or guess.

## Scope — what these numbers are and are not

- **In-process only, against `FakeUpstreamClient`.** These benchmarks measure
  **waffy's own added latency and throughput ceiling** — the cost of
  parse → normalize → signature match → positive security → rate limit →
  bot assessment → score → decide → enforce → cookie rewrite — **not** real
  network round-trip time to a real upstream application, and not real
  client TLS handshake cost. A production deployment's end-to-end latency
  is this number plus real network RTT plus the real upstream's own
  response time.
- Requests are driven directly through the raw ASGI `scope`/`receive`/`send`
  interface (`scripts/benchmarks/common.py::run_one_request`), not through an
  `httpx.AsyncClient`, so the timed window is exactly `await pipeline(...)`
  and excludes an HTTP client library's own transport overhead.
- **Pipeline configuration under test**: the real seed signature set
  (`config/rules/seed_rules.toml`, 12 rules) at **paranoia level 1** (the
  shipped default), real HTTP parsing/normalization/anti-evasion, positive
  security engine with **no routes configured** (positive security is
  optional per spec §8 — this measures the always-on negative-security
  path), real rate limiting / bot detection / cookie-security rewriting,
  **SHADOW enforcement mode** (the shipped default — decisions are computed
  and logged but never block/challenge). The **ML anomaly scorer is
  disabled** (`anomaly_scorer=None`) in this run — it's a separate,
  evidence-only layer with its own cost profile (feature extraction +
  Isolation Forest inference) not exercised here. Measuring the pipeline
  with the anomaly scorer enabled is a follow-up item, not yet done.
- Client IP is rotated across 250 synthetic addresses per run so the
  sliding-window rate limiter does not itself throttle the benchmark and
  distort the steady-state number.

## Reference hardware / environment

Measured 2026-09-02 (UTC timestamps below), on:

| | |
|---|---|
| CPU | 12th Gen Intel(R) Core(TM) i7-12700F, 20 logical processors |
| Memory | 15 GiB total |
| OS | WSL2 Ubuntu on Windows 11 (`Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.43`) |
| Python | CPython 3.14.4 |
| Interpreter mode | Single process, `asyncio` event loop, no multi-worker/uvicorn process manager in front — this measures the pipeline coroutine directly |

This machine is a development workstation running under WSL2, not
dedicated benchmark hardware — treat these as directional numbers for
regression-tracking waffy's own overhead over time, not a formal capacity-
planning SLA.

## Latency — `scripts/benchmarks/latency_bench.py`

Request: `POST /api/v1/search` with a 148-byte JSON body (well under the
10 MB `max_body_bytes` default and under the spec's illustrative size
bound). 200 warmup requests (discarded) + 2000 measured requests, sequential
(concurrency 1), one fresh client IP per request from a 250-address pool.

Actual output (`uv run python scripts/benchmarks/latency_bench.py`):

```json
{
  "timestamp_utc": "2026-09-02T19:04:46.204091+00:00",
  "request_body_size_bytes": 148,
  "warmup_requests": 200,
  "measured_requests": 2000,
  "upstream_calls_recorded": 2000,
  "latency_ms": {
    "min": 0.1077,
    "p50": 0.1183,
    "p95": 0.1831,
    "p99": 0.3367,
    "max": 8.4546,
    "mean": 0.1363,
    "stdev": 0.1946
  }
}
```

**p99 added latency: 0.34 ms** for a 148-byte request against the default
paranoia-1 rule set, on the reference hardware above. `max` (8.45 ms) is a
single outlier out of 2000 samples, consistent with normal Python/asyncio
scheduling jitter (e.g. a GC pause or event-loop scheduling delay) rather
than a systemic cost — p99 is the number to track for regressions, not max.

## Throughput — `scripts/benchmarks/throughput_bench.py`

64 concurrent workers, each on its own client IP, issuing requests
back-to-back for a fixed 5-second window (1-second warmup excluded).
"Queue growth" is checked directly: per-second completed-request counts are
bucketed, and the run flags `queue_growth_detected: true` if the second
half of the window completes requests at less than 80% of the first half's
rate (backpressure/pileup signature). `max_concurrent_connections_per_ip`
defaults to 50 and `max_in_flight_requests` to 1000
(`config/default_config.toml`) — 64 total concurrent workers each on a
distinct IP stays under both, so the transport resource-protection limiter
itself is not what's being measured here.

Actual output (`uv run python scripts/benchmarks/throughput_bench.py`):

```json
{
  "timestamp_utc": "2026-09-02T19:05:00.211977+00:00",
  "concurrency": 64,
  "duration_seconds_requested": 5.0,
  "duration_seconds_actual": 5.0002,
  "total_requests_completed": 36624,
  "requests_per_second": 7324.5,
  "per_second_completion_counts": [7586, 7298, 7304, 7130, 7305],
  "upstream_calls_recorded": 36624,
  "queue_growth_detected": false
}
```

**Sustained throughput: ~7,325 req/sec** at concurrency 64, with a flat
per-second completion profile (no declining trend across the 5-second
window) — **`queue_growth_detected: false`**.

## Honest caveats

- These are single-process, in-process, single-machine numbers against a
  fake upstream with a fixed instant response. They say nothing about real
  network conditions, a real upstream's own latency, TLS handshake cost in
  standalone proxy mode, or multi-process/multi-worker deployment behavior.
- No target latency/throughput number from a prior commitment existed to
  compare against — this is the **first** measurement establishing a
  baseline, not a pass/fail against a pre-set target. Future runs should
  diff against these numbers to catch regressions.
- ML anomaly scoring, real TLS termination, and real upstream network I/O
  are **not** included in this run — each would add measurable cost and
  should be benchmarked separately before being treated as production-
  representative.
- Rerun both scripts and update this document if signature count, scoring
  config, or the pipeline's hot path changes materially — a stale number
  here is worse than no number.

## Post-hardening re-measurement (Step A3) — 2026-09-05

Re-run after Phase A (prompts/13b's `PreAcceptTlsServer` — not exercised by
this benchmark, which drives the pipeline via a raw ASGI scope, not a real
TLS listener) and Phase B (SSRF signature category — 3 new PL1 rules,
`WAFFY-SSRF-001/002/003`; the 4th, `WAFFY-SSRF-004`, is PL2-gated and never
runs at this benchmark's PL1 default; plus fuzz-test/doc-only changes with
no runtime code path) — **same reference hardware as the original baseline
above, confirmed via `nproc`/`/proc/cpuinfo` before this run: identical
12th Gen i7-12700F / 20 logical processors / 15 GiB RAM / WSL2 Ubuntu /
CPython 3.14.4 machine, not a different environment.**

### Latency

```json
{
  "timestamp_utc": "2026-09-05T00:18:17.266966+00:00",
  "request_body_size_bytes": 148,
  "warmup_requests": 200,
  "measured_requests": 2000,
  "latency_ms": {"min": 0.1254, "p50": 0.1393, "p95": 0.2071, "p99": 0.2902, "max": 8.961, "mean": 0.1558, "stdev": 0.2048}
}
```
A second run: `p99: 0.3085 ms` (`min: 0.12, p50: 0.1297, p95: 0.174, mean: 0.1451`).

| | Baseline (2026-09-02) | Post-hardening (2026-09-05), 2 runs |
|---|---|---|
| p99 | 0.34 ms | 0.29 ms, 0.31 ms |

**No latency regression** — both post-hardening p99 values are at or
slightly below the original baseline, well within normal run-to-run
variance for a sub-millisecond in-process measurement.

### Throughput

Three consecutive runs (same command, same machine, back-to-back):

| Run | total_requests_completed | requests_per_second |
|---|---|---|
| 1 | 34,348 | 6,869.42 |
| 2 | 32,223 | 6,444.39 |
| 3 | 31,911 | 6,382.2 (5.0002s actual) |
| **Average** | | **~6,565** |

| | Baseline (2026-09-02) | Post-hardening (2026-09-05) |
|---|---|---|
| Throughput | ~7,325 req/sec | ~6,565 req/sec avg (range 6,382–6,869) |
| Delta | | **~10% lower** |

`queue_growth_detected: false` on all three runs — no backpressure/pileup
signature, just a lower flat-line rate than the baseline.

**Honest assessment**: this is a real, measured throughput decrease, not
within the ~7% run-to-run spread observed among the three post-hardening
runs themselves (6,382–6,869) alone — the average sits consistently below
the baseline across all three. The most plausible, verifiable contributing
factor is the added signature-matching cost: the seed rule set grew from
12 rules to 15 rules actually evaluated at PL1 (the benchmarked default) —
`WAFFY-SSRF-001/002/003` added three more regex checks against
query_params/body_fields/raw_body per request, a ~25% increase in PL1 rule
count, on a workstation shared with the rest of this session's other
activity (unlike the original baseline's dedicated run). This is reported
as measured, not fabricated or smoothed over, per this step's constraint —
and, also per this step's constraint, **no code was modified to chase the
number back up**; if the ~10% throughput cost of the new SSRF category
matters for a specific deployment's capacity planning, that's a decision
for the operator (e.g. running at a lower paranoia level, or accepting the
cost — SSRF detection was a correctness gap, not optional polish), not
something to silently re-tune here.

No ML-anomaly-scorer-enabled run was added in this step — still an
existing, separately-tracked follow-up item, unchanged from the original
baseline's caveat above.
