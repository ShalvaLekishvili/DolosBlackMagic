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
- `platform.test.mjs` — investigation lifecycle, evidence provenance retention, snapshot validation and Detection Engine v3 grouped/sequence behavior.
- `streaming.test.mjs` — worker protocol tokens, bounded Blob slicing, UTF-8 streaming decode, cross-chunk carry and evidence-provenance invariants.
- `storage.test.mjs` — Dataset Vault sanitization, schema validation, event-count bounds, cyclic raw-event handling, portable import rebinding and long-field truncation.
- `check-static.mjs` — deployable asset existence, production JavaScript syntax parsing, HTML references, duplicate static IDs, navigation targets, service-worker cache membership, PWA subpath safety, release version, bilingual README alignment, release documentation and Netlify CSP.

## CI

Both `.github/workflows/ci.yml` and the GitHub Pages workflow run `npm test` on Node 24. Pages deployment is gated by a successful test job.

## Manual browser smoke test

After serving `site/`, verify:

1. Overview loads without console errors.
2. Artifact sample analysis works.
3. Event Explorer ingests pasted telemetry and displays parse quality.
4. Line-oriented file ingestion uses the streaming path and reports measurable byte/record progress.
5. Cancel stops active file analysis without committing a partial result.
6. Event rows are keyboard-selectable and open the evidence drawer.
7. Normalized/raw comparison and provenance render as text.
8. Bookmarking creates or updates the active investigation.
9. Entity pivots filter loaded telemetry.
10. Detection Studio rules continue to work and Detection Engine v3 regression tests remain green.
11. Investigation snapshot export/import validates schema before restore.
12. Ctrl/Cmd+K focuses local global search and grouped results navigate correctly.
13. In Investigations, saving current telemetry creates a Dataset Vault entry in IndexedDB.
14. Opening a saved dataset returns it to Event Explorer and preserves findings/summary context.
15. Exporting a saved dataset downloads a local JSON package without network access.
16. Importing a valid dataset revalidates/re-sanitizes it and binds it to the active investigation; malformed or unsupported schemas are rejected.
17. Deleting a saved dataset does not delete investigation metadata or evidence bookmarks.
18. Browser storage usage/quota renders when `navigator.storage.estimate()` is supported.
19. Mobile sidebar, evidence drawer, investigation workspace and Dataset Vault remain usable.
20. Markdown/JSON/print exports continue to work.

## Performance model

The chunked file reader and worker protocol keep line-oriented telemetry parsing off the main thread. The Dataset Vault is opt-in and bounded to 50,000 events / approximately 24 MB per collection so persistence cannot grow without limit through normal UI flows.

Additional controls include:

- sliding-window correlation;
- cached event search strings;
- debounced filtering;
- bounded DOM event rendering;
- bounded investigation graphs;
- bounded streamed normalized-event retention;
- bounded persisted raw previews and long fields;
- 30 MB UI guard on portable dataset import files.

Performance tests deliberately avoid brittle millisecond pass/fail thresholds. Correctness and bounded behavior are hard gates.

## Known test boundary

The repository relies primarily on Node regression and static-integrity tests. IndexedDB transaction behavior and full UI interaction still require browser smoke validation because Node does not provide the browser storage implementation used in production.
