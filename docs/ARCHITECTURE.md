# DolosBlackMagic v0.9 Architecture

DolosBlackMagic is a static, local-first browser application. `site/` is the deployable artifact; no mandatory server runtime is required for the core product.

## Architectural direction

v0.9 keeps the semantic `site/platform/` layer and makes Detection Engine v3 part of the canonical telemetry path instead of an isolated capability. Existing compatibility modules remain in place while stable behavior is consolidated behind tested platform APIs.

## Layers

1. **Artifact core** — `core.js` performs hashing, type detection, strings/entropy, IOC extraction, artifact heuristics, decoding, graph/timeline preparation and report generation.
2. **BlackLog compatibility engine** — `log-engine.js` detects formats, parses records, normalizes events and applies built-in defensive detections.
3. **Platform bus** — `platform/app-bus.js` provides dependency-free cross-workspace state/event contracts.
4. **Investigation model** — `platform/investigation-engine.js` stores compact investigations, evidence bookmarks, findings, entities, notes, actions and source references.
5. **Detection Engine v3** — `platform/detection-v3.js` provides nested declarative conditions, thresholds, distinct counts, grouped correlations and bounded sequences.
6. **Canonical detection pipeline** — `platform/detection-pipeline.js` combines existing BlackLog findings with v3 findings, deduplicates equivalent evidence, links detections back to events and assigns analyst-facing finding classifications.
7. **Streaming telemetry pipeline** — `platform/log-stream-client.js` reads bounded Blob slices and sends chunks to `platform/log-stream-worker.js`, which reconstructs line boundaries and returns measurable progress plus a bounded event collection.
8. **Evidence interaction** — `platform/event-explorer-v2.js` adds stable event references, provenance, raw/normalized comparison, entity pivots and evidence bookmarks.
9. **Workspace storage service** — `platform/workspace-store.js` owns IndexedDB dataset persistence, schema validation, sanitization, size/event bounds and browser quota helpers.
10. **Dataset Vault UI** — `platform/dataset-vault-ui.js` exposes explicit save/open/export/import/delete actions for selected telemetry.
11. **Bootstrap** — `platform/bootstrap.js` initializes cross-workspace behavior, streaming analysis and the shared renderer. Before telemetry is rendered, it applies the canonical detection pipeline.
12. **SOC/Operations compatibility** — existing SOC and Operations engines remain operational while consolidation continues.
13. **PWA/deployment** — `sw.js`, `manifest.webmanifest`, GitHub Actions and `netlify.toml` provide static deployment and offline application-shell behavior.

## Canonical telemetry flow

```text
Artifact / Telemetry
       ↓
Parse / Normalize
       ↓
Stable Event + Provenance
       ↓
BlackLog findings ─┐
                   ├──► Detection Pipeline ──► Canonical Findings
Detection v3 ──────┘            │
                                ├──► Event detection back-links
                                ├──► Evidence IDs / confidence / MITRE
                                └──► Finding classification
                                              ↓
                               Investigation → Incident → Report
                                              │
                                              └──► optional IndexedDB Vault
```

## Finding contract

Canonical findings may include:

```text
id
ruleId
name
severity
confidence
sourceEngine
kind
mitre[]
tags[]
why
falsePositive
remediation
eventIds[]
evidence[]
correlation metadata
```

`kind` is analyst context (`informational`, `suspicious`, `correlated`, `high-confidence`), not a malicious verdict.

## Correlation safeguards

Grouped threshold and sequence rules require meaningful grouping values. Events missing the required group key are not combined into a shared placeholder bucket.

Sequence stages can declare a repeat count. This allows rules such as repeated authentication failures followed by success to require an actual failure burst before advancing to the success stage.

## Normalized event contract

The BlackLog event schema includes timestamp, source/format, host, event ID, provider/channel, severity, message, identity, process lineage, network fields, action/status, URL/HTTP metadata, hashes, quality flags and attached detections.

Platform events may additionally attach:

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

Persistence is split by data class:

- **LocalStorage** — compact preferences, investigation metadata, rules, triage state and saved views.
- **IndexedDB Dataset Vault** — opt-in persistence for selected normalized telemetry collections.
- **Memory** — newly imported telemetry remains ephemeral unless explicitly saved.

Saved datasets are sanitized, bounded to 50,000 events and roughly 24 MB, and can be exported/imported as validated local JSON.

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

Line-oriented telemetry uses this bounded worker path. Large single-object JSON and CSV remain on the bounded compatibility parser path to preserve parsing semantics.

## Privacy boundary

No platform module automatically transmits artifacts, hashes, IPs, domains, URLs, rules or logs to third parties. Workers and IndexedDB are browser-local. There is no mandatory backend, analytics SDK or remote execution service.

## Remaining consolidation debt

Release-specific compatibility files such as `v05.css`, `v06-ui.css`, `soc-v05-ui.js`, `dashboard-v06.js` and `log-normalize-fixes.js` still exist. They are retained until their stable behavior is absorbed into semantic modules under regression tests.
