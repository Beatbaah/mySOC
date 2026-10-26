# Architecture

## Processes

| Process | What it does | Scales by |
|---|---|---|
| **sensor** (`python -m mysoc.sensor`) | Reads traffic (demo generator or Scapy capture) and syslog, aggregates packets into flows, runs detection, writes flows/logs/alerts, reports a heartbeat. Runs whether or not anyone is signed in. | One per network segment; each reports under its hostname. |
| **api** (`uvicorn mysoc.main:app`) | Authentication, the REST API and the live-update stream. Stateless apart from the database. | Horizontally. |
| **web** (nginx) | Serves the built console and proxies `/api` on the same origin. | Horizontally. |
| **db** | PostgreSQL in Docker, SQLite for local runs. | — |

The sensor and API share nothing but the database. Configuration the analyst changes in the console (rule
thresholds, rule on/off, indicators) is re-read by the sensor every 5–30 seconds.

## Sensor pipeline

```
source ─► FlowRecord ─► enrich (country) ─► DetectionEngine ─┐
                                         ─► AnomalyModel ────┼─► Findings ─► AlertWriter ─► alerts
syslog ─► LogLine ─────────────────────► DetectionEngine ────┘   (dedup + risk score)   └─► notifier
```

- **Flows, not packets.** Packets are grouped by 5-tuple with NetFlow-style active (10 s) and idle (2 s)
  timeouts. Every network detection works on flows, which keeps storage small and makes detections replayable.
- **Event time.** Detectors use the flow's own timestamps, never the wall clock, so live traffic, the 24-hour
  demo backfill and the unit tests all behave identically.
- **Windows and quiet periods.** Each windowed rule keeps per-key deques trimmed to its window. After firing
  for a key it stays quiet for one window; further repeats fold into the existing alert anyway.
- **Deduplication.** A finding's dedup key is its rule plus the entities that make it "the same thing"
  (e.g. source+target for a scan, target only for a flood). A matching open alert seen within
  `MYSOC_ALERT_DEDUP_MINUTES` gets its count and last-seen updated and can only be escalated, never downgraded.
- **Risk score.** Severity base + log-scaled repetition + target asset criticality + IOC hit, capped at 100.
- **Anomaly model.** Isolation Forest over nine flow features, trained on a reservoir sample of the network's
  own traffic, retrained every 30 minutes and scored per batch. Reported at low severity: it's context.

## Data model

`flows`, `log_events` (telemetry, retention-pruned) · `alerts` (deduplicated detections) · `cases` and
`case_events` (investigations and their timeline) · `rules` (detection config, live-reloaded) · `indicators`,
`intel_cache` · `assets` (auto-discovered internal hosts plus analyst context) · `users`, `auth_sessions`,
`login_attempts`, `audit_log` · `secrets` (encrypted) · `handovers` · `sensor_status`.

All timestamps are timezone-aware UTC (stored naive UTC on SQLite) and compared as datetimes in SQL.

## API conventions

JSON in camelCase, ISO-8601 UTC times. Every route declares its minimum role. Lists are bounded (`limit`
caps). The console refetches on server-sent "pulse" events instead of polling every view.

## Console

React 18 + TypeScript + Vite, TanStack Query for server state, Recharts and d3-geo for charts and the map.
Pages are code-split. Dark and light themes share one token set. No third-party requests at runtime.
