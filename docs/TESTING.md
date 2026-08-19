# Testing and quality gates

DolosBlackMagic requires Node.js 24+ and intentionally has no runtime npm package dependencies.

```bash
npm test
```

The command runs these suites sequentially:

- `core.test.mjs` — artifact-analysis primitives.
- `log-engine.test.mjs` — format detection, malformed-record preservation, CSV/syslog parsing, Unicode, timestamp quality, normalization and defensive correlations.
- `soc.test.mjs` — browser-state migration, custom rules, import reports, triage and incident persistence/reporting.
- `ops.test.mjs` — deduplication, suppression, enrichment, graph, workspace validation and dashboard health.
- `security.test.mjs` — analyst-controlled regex safety.
- `platform.test.mjs` — investigation lifecycle, evidence provenance, Detection Engine v3 grouped/sequence behavior and canonical finding integration.
- `streaming.test.mjs` — worker protocol, bounded Blob slicing, UTF-8 streaming decode and provenance invariants.
- `storage.test.mjs` — Dataset Vault sanitization, bounds, cyclic raw-event handling and portable import rebinding.
- `detection-pipeline.test.mjs` — v0.9 merge/deduplication, classification, event back-linking, repeated-stage sequences and missing-group safeguards.
- `check-static.mjs` — deployable asset existence, production JavaScript syntax parsing, HTML references, duplicate IDs, navigation targets, PWA cache membership, version alignment, bilingual README and Netlify CSP.

## CI

Both `.github/workflows/ci.yml` and the GitHub Pages workflow run `npm test` on Node 24. Pages deployment is gated by a successful test job.

## Manual browser smoke test

After serving `site/`, verify:

1. Overview loads without console errors.
2. Artifact sample analysis works.
3. Event Explorer ingests telemetry and displays parse quality.
4. Line-oriented file ingestion uses the streaming path and reports measurable progress.
5. Cancel stops active analysis without committing a partial result.
6. Event rows open the evidence drawer and render raw/normalized context safely.
7. Detection Engine v3 findings appear automatically alongside BlackLog findings.
8. Finding evidence event IDs link back to normalized events.
9. Missing correlation group keys do not create unrelated findings.
10. Repeated-failure → success sequences require the configured failure burst.
11. Investigation snapshots validate before restore.
12. Dataset Vault save/open/export/import/delete flows work without network access.
13. Imported datasets are revalidated and re-sanitized.
14. Mobile sidebar, evidence drawer, investigation workspace and Dataset Vault remain usable.
15. Markdown/JSON/print exports continue to work.

## Performance model

The chunked file reader and worker protocol keep line-oriented telemetry parsing off the main thread. Dataset persistence is opt-in and bounded. Correlations use bounded windows and explicit grouping rather than unbounded cross-product scans.

Additional controls include:

- sliding-window correlation;
- cached event search strings;
- debounced filtering;
- bounded DOM rendering;
- bounded investigation graphs;
- bounded streamed event retention;
- bounded persisted previews and long fields;
- 30 MB portable dataset import guard.

## Known test boundary

The repository relies primarily on Node regression and static-integrity tests. IndexedDB transaction behavior and full UI interaction still require browser smoke validation because Node does not provide the production browser storage implementation.
