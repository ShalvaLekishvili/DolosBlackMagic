# DolosBlackMagic v0.7 Architecture

DolosBlackMagic is a static, local-first browser application. `site/` is the deployable artifact; no mandatory server runtime is required for the core product.

## Architectural direction

v0.7 introduces a semantic `site/platform/` layer instead of adding more release-named patch files. Existing v0.6 modules remain compatibility layers while stable cross-workspace behavior is consolidated behind explicit APIs.

## Layers

1. **Artifact core** — `core.js` performs hashing, type detection, strings/entropy, IOC extraction, artifact heuristics, decoding, graph/timeline preparation and report generation.
2. **BlackLog compatibility engine** — `log-engine.js` detects formats, parses records, normalizes events and applies built-in defensive detections. `log-ui.js` remains the v0.6 Event Explorer shell.
3. **v0.7 platform bus** — `platform/app-bus.js` provides a dependency-free event contract for sticky/current workspace state and cross-module notifications.
4. **Investigation model** — `platform/investigation-engine.js` defines first-class investigations containing data sources, evidence bookmarks, findings, entities, notes, actions, timeline state and incident references.
5. **Detection Engine v3** — `platform/detection-v3.js` adds nested declarative conditions, grouped thresholds, distinct counts and bounded sequences without executing custom JavaScript.
6. **Streaming telemetry pipeline** — `platform/log-stream-client.js` reads bounded Blob slices and sends chunks to `platform/log-stream-worker.js`. The worker reconstructs line boundaries, analyzes batches and returns progress, partial-result counters and a final bounded event collection.
7. **Evidence interaction** — `platform/event-explorer-v2.js` adds stable event references, raw/normalized comparison, provenance display, entity pivoting and evidence bookmarks to the Event Explorer.
8. **Deterministic bootstrap** — `platform/bootstrap.js` initializes v0.7 bridging and streaming behavior after the compatibility UI modules have created their workspaces. Optional feature failure is isolated so it does not prevent the entire shell from loading.
9. **Detection/SOC compatibility** — `soc-engine.js`, `soc-ui.js` and existing SOC enhancement modules retain rule import, triage and incident behavior during incremental consolidation.
10. **Operations compatibility** — `ops-engine.js` and `ops-ui.js` retain deduplication, suppression, risk context, entity graph and workspace tools.
11. **PWA/deployment** — `sw.js`, `manifest.webmanifest`, GitHub Actions and `netlify.toml` provide static deployment and offline application-shell behavior.

## Normalized event contract

The established BlackLog event schema continues to include timestamp, format/source, host, event ID, provider/channel, severity, message, identity, process lineage, network fields, action/status, URL/HTTP metadata, hashes, quality flags, raw data and attached detections.

v0.7 may additionally attach:

```text
stableId
provenance.sourceFile
provenance.recordIndex
provenance.lineNumber
provenance.byteStart
provenance.byteEnd
provenance.parser
provenance.rawPreview
```

A provenance field is only populated when it can be determined accurately. Unknown byte ranges are represented as `null`, not invented values.

## Streaming protocol v2

```text
Main thread                    Worker
    │                            │
    ├──── START ────────────────►│
    ├──── CHUNK ────────────────►│
    │◄─── PROGRESS ──────────────┤
    │◄─── PARTIAL_RESULT ────────┤
    ├──── CHUNK ... ────────────►│
    ├──── END ──────────────────►│
    │◄─── COMPLETE ──────────────┤
    │                            │
    └──── CANCEL ───────────────►│ (alternative termination)
```

Progress reports only measurable values such as processed bytes and records. Cancellation terminates the active result without committing unfinished analyst state.

## Detection Engine v3

Rules remain declarative data. The v3 API supports nested `all`, `any` and `not` groups, safe regex, numeric comparisons, threshold counts, time windows, group-by keys, distinct-value counting and ordered sequence stages.

The v3 engine is additive to the existing BlackLog/SOC detection content during migration. This avoids a high-risk all-at-once rewrite.

## Investigation model

The first-class investigation object is intentionally compact:

```text
metadata
artifacts
dataSources
bookmarks
findings
entities
notes
timeline
incidents
savedFilters
analyst actions
created/updated timestamps
```

Large raw telemetry collections are not automatically persisted. The default model keeps telemetry memory-resident and allows the analyst to retain selected evidence subsets.

## Persistence boundaries

- LocalStorage remains appropriate for compact investigation metadata, rules, triage state, saved views and preferences.
- imported large telemetry remains ephemeral unless future explicit persistence modes are selected;
- investigation snapshots are schema-versioned and validate their shape before restore;
- existing SOC v1/v2 namespaces remain untouched by the v0.7 investigation store.

## Data flow

```text
Artifact / Telemetry
       ↓
Parse / Normalize
       ↓
Stable Event + Provenance
       ↓
Built-in / v3 Detection
       ↓
Finding + Evidence References
       ↓
Bookmark / Entity Pivot
       ↓
Investigation → Incident → Report
```

## Privacy boundary

No v0.7 platform module automatically transmits artifacts, hashes, IPs, domains, URLs, rules or logs to third parties. The worker is same-origin and browser-local. There is no mandatory cloud backend, analytics SDK or remote execution service.

## Remaining consolidation debt

Release-specific compatibility files such as `v05.css`, `v06-ui.css`, `soc-v05-ui.js`, `dashboard-v06.js` and `log-normalize-fixes.js` still exist. They are intentionally not deleted until their stable behavior has been absorbed under tests into canonical semantic modules.
