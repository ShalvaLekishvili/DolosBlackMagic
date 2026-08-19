# Testing and quality gates

The repository requires Node.js 24+ but has no npm package dependencies.

```bash
npm test
```

The command runs the following suites sequentially:

- `core.test.mjs` — artifact-analysis primitives.
- `log-engine.test.mjs` — format detection, malformed-record preservation, CSV/syslog parsing, Unicode, timestamp quality, normalization, defensive detections, threshold boundaries and correlation.
- `soc.test.mjs` — browser-state migration, custom rule operators/lifecycle, import reports, triage history and incident persistence/reporting.
- `ops.test.mjs` — deduplication, suppression validation, enrichment, investigation graph, workspace validation/restore and dashboard health.
- `security.test.mjs` — analyst-controlled regex safety guard.
- `check-static.mjs` — deployable asset existence, HTML references, duplicate static IDs, navigation targets, service-worker cache membership, PWA subpath safety, release version and Netlify CSP.

## CI

Both `.github/workflows/ci.yml` and the GitHub Pages workflow run `npm test` on Node 24. Pages deploy is gated by a successful test job.

## Manual smoke test

After serving `site/`, verify: Overview loads without errors; artifact sample analysis works; Event Explorer ingests JSON/syslog and displays parse quality; evidence inspector opens; filters/pivots work; Detection Studio creates/tests rules; incidents persist; SOC Operations export/restore validation works; mobile navigation remains usable; exports download locally.

## Performance checks

v0.5 uses sliding-window correlation, cached normalized search text, debounced filtering, bounded event-table rendering (750 rows) and bounded investigation graphs. Large log parsing itself is still performed on the main thread and remains a tracked limitation rather than being hidden by synthetic benchmarks.
