# DolosBlackMagic v0.8 Architecture

DolosBlackMagic is a static, local-first browser application. `site/` is the deployable artifact; no mandatory server runtime is required for the core product.

## Architectural direction

v0.8 keeps the semantic `site/platform/` layer introduced in v0.7 and adds an explicit storage boundary. Existing compatibility modules remain in place while stable behavior is moved behind tested platform APIs.

## Layers

1. **Artifact core** — `core.js` performs hashing, type detection, strings/entropy, IOC extraction, artifact heuristics, decoding, graph/timeline preparation and report generation.
2. **BlackLog compatibility engine** — `log-engine.js` detects formats, parses records, normalizes events and applies built-in defensive detections. `log-ui.js` remains the compatibility Event Explorer shell.
3. **Platform bus** — `platform/app-bus.js` provides a dependency-free event contract for current workspace state and cross-module notifications.
4. **Investigation model** — `platform/investigation-engine.js` defines compact first-class investigations containing sources, evidence bookmarks, findings, entities, notes, actions, timeline state and incident references.
5. **Detection Engine v3** — `platform/detection-v3.js` provides nested declarative conditions, grouped thresholds, distinct counts and bounded sequences without executing custom JavaScript.
6. **Streaming telemetry pipeline** — `platform/log-stream-client.js` reads bounded Blob slices and sends chunks to `platform/log-stream-worker.js`, which reconstructs line boundaries and returns measurable progress plus a bounded event collection.
7. **Evidence interaction** — `platform/event-explorer-v2.js` adds stable event references, provenance, raw/normalized comparison, entity pivots and evidence bookmarks.
8. **Workspace storage service** — `platform/workspace-store.js` owns IndexedDB dataset persistence, schema validation, sanitization, size/event bounds and browser quota helpers.
9. **Dataset Vault UI** — `platform/dataset-vault-ui.js` exposes explicit save/open/delete operations for selected telemetry and reconnects saved data to Event Explorer through the canonical renderer.
10. **Bootstrap** — `platform/bootstrap.js` initializes cross-workspace behavior, streaming analysis and the shared telemetry renderer.
11. **SOC/Operations compatibility** — existing SOC and Operations engines remain operational while consolidation continues.
12. **PWA/deployment** — `sw.js`, `manifest.webmanifest`, GitHub Actions and `netlify.toml` provide static deployment and offline application-shell behavior.

## Normalized event contract

The BlackLog event schema includes timestamp, source/format, host, event ID, provider/channel, severity, message, identity, process lineage, network fields, action/status, URL/HTTP metadata, hashes, quality flags and attached detections.

Platform events may additionally attach deterministic evidence metadata:

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

Unknown byte ranges remain `null`; offsets are never fabricated.

## Persistence model

Persistence is intentionally split by data class:

- **LocalStorage** — compact preferences, investigation metadata, rules, triage state and saved views.
- **IndexedDB Dataset Vault** — opt-in persistence for selected normalized telemetry collections.
- **Memory** — newly imported telemetry remains ephemeral unless the analyst explicitly saves it.

A saved dataset uses schema version 1 and is sanitized before persistence. Arbitrary raw event objects are not retained. Long fields and raw previews are bounded, a dataset may contain at most 50,000 events, and the serialized approximation is capped at roughly 24 MB.

The vault does not silently migrate or delete legacy LocalStorage investigation state. Browsers without IndexedDB keep the rest of the application functional and surface the vault as unavailable.

## Streaming protocol

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
    └──── CANCEL ───────────────►│
```

Line-oriented telemetry uses this bounded worker path. Large single-object JSON and CSV continue to use the compatibility parser path to preserve parsing semantics.

## Detection Engine v3

Rules remain declarative data. The v3 API supports nested `all`, `any` and `not` groups, safe regex, numeric comparisons, threshold counts, time windows, group-by keys, distinct-value counting and ordered sequence stages.

## Investigation data flow

```text
Artifact / Telemetry
       ↓
Parse / Normalize
       ↓
Stable Event + Provenance
       ↓
Detection / Correlation
       ↓
Finding + Evidence References
       ↓
Bookmark / Entity Pivot
       ↓
Investigation ──────► Incident ──────► Report
       │
       └── optional save ──► IndexedDB Dataset Vault
```

## Privacy boundary

No platform module automatically transmits artifacts, hashes, IPs, domains, URLs, rules or logs to third parties. Workers and IndexedDB are browser-local. There is no mandatory backend, analytics SDK or remote execution service.

## Remaining consolidation debt

Release-specific compatibility files such as `v05.css`, `v06-ui.css`, `soc-v05-ui.js`, `dashboard-v06.js` and `log-normalize-fixes.js` still exist. They are intentionally retained until their stable behavior is fully absorbed into semantic modules under regression tests.
