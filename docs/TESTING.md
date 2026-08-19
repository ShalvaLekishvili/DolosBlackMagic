# Testing and quality gates

DolosBlackMagic requires Node.js 24+ and intentionally has no runtime npm package dependencies.

```bash
npm test
```

The command runs the following suites sequentially:

- `core.test.mjs` — artifact-analysis primitives.
- `log-engine.test.mjs` — format detection, malformed-record preservation, CSV/syslog parsing, Unicode, timestamp quality, normalization, defensive detections and correlation boundaries.
- `soc.test.mjs` — browser-state migration, custom rule operators/lifecycle, import reports, triage history and incident persistence/reporting.
- `ops.test.mjs` — deduplication, suppression validation, enrichment, investigation graph, workspace validation/restore and dashboard health.
- `security.test.mjs` — analyst-controlled regex safety guard.
- `platform.test.mjs` — v0.7 investigation lifecycle, evidence provenance retention, snapshot validation and Detection Engine v3 grouped/sequence behavior.
- `streaming.test.mjs` — worker protocol v2 tokens, bounded Blob slicing, UTF-8 streaming decode, cross-chunk carry and evidence-provenance invariants.
- `check-static.mjs` — deployable asset existence, HTML references, duplicate static IDs, navigation targets, service-worker cache membership, PWA subpath safety, release version, bilingual README alignment, release documentation and Netlify CSP.

## CI

Both `.github/workflows/ci.yml` and the GitHub Pages workflow run `npm test` on Node 24. Pages deployment is gated by a successful test job.

## Manual browser smoke test

After serving `site/`, verify:

1. Overview loads without console errors.
2. Artifact sample analysis works.
3. Event Explorer ingests pasted telemetry and displays parse quality.
4. File ingestion uses the v0.7 streaming path and reports measurable byte/record progress.
5. Cancel stops the active file analysis without committing a partial result.
6. Event rows are keyboard-selectable and open the evidence drawer.
7. Normalized/raw comparison and provenance render as text.
8. Bookmarking creates or updates the active v0.7 investigation.
9. Entity pivots filter loaded telemetry.
10. Detection Studio legacy rules continue to work.
11. v0.7 Detection Engine threshold/sequence tests remain green.
12. Investigation snapshot export/import validates schema before restore.
13. Ctrl/Cmd+K focuses the local global search and grouped results navigate correctly.
14. Mobile sidebar, evidence drawer and investigation workspace remain usable.
15. Markdown/JSON/print exports continue to work.

## Performance model

v0.7 adds a bounded chunked file reader and dedicated worker protocol. The main thread no longer needs to read a streamed file through a single `File.text()` call. The worker reconstructs line boundaries, processes batches and reports measured bytes/records.

Additional existing controls remain in place:

- sliding-window correlation;
- cached event search strings in the compatibility Event Explorer;
- debounced filtering;
- bounded DOM event rendering;
- bounded investigation graphs;
- bounded streamed normalized-event retention.

Performance tests deliberately avoid brittle millisecond pass/fail thresholds. Correctness and bounded behavior are hard gates; elapsed time is reported for analyst visibility and future regression comparison.

## Known test boundary

The repository currently relies primarily on Node regression and static-integrity tests. Full automated browser interaction coverage remains limited; browser smoke validation is therefore still required for UI-heavy changes.
