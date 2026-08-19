# DolosBlackMagic v0.10 Architecture

DolosBlackMagic remains a static, local-first browser application. `site/` is the deployable artifact and no mandatory server runtime is required for the core product. v0.10 adds an **optional analyst-side Python Wazuh companion** for deeper parsing and correlation while preserving browser-only operation.

## Architectural direction

The browser platform remains canonical for artifact analysis, investigations, SOC operations, persistence and reporting. The Python engine is a bounded local service that specializes in Wazuh exports and returns normalized events/findings to a dedicated Event Explorer panel.

## Browser layers

1. **Artifact core** — `core.js` performs hashing, type detection, strings/entropy, IOC extraction, artifact heuristics, decoding, graph/timeline preparation and report generation.
2. **BlackLog compatibility engine** — `log-engine.js` detects formats, parses records, normalizes events and applies built-in defensive detections.
3. **Wazuh browser adapter** — `wazuh-adapter.js` unwraps common Wazuh/Indexer structures and preserves Wazuh-specific metadata.
4. **Platform bus** — `platform/app-bus.js` provides dependency-free cross-workspace contracts.
5. **Investigation model** — `platform/investigation-engine.js` stores compact investigations, evidence bookmarks, findings, entities, notes, actions and source references.
6. **Detection Engine v3** — `platform/detection-v3.js` provides nested declarative conditions, thresholds, distinct counts, grouped correlations and bounded sequences.
7. **Canonical browser detection pipeline** — `platform/detection-pipeline.js` merges existing BlackLog findings with v3 findings and links detections back to events.
8. **Streaming telemetry pipeline** — `platform/log-stream-client.js` + `platform/log-stream-worker.js` process line-oriented telemetry in bounded chunks.
9. **Evidence interaction** — `platform/event-explorer-v2.js` adds stable event references, provenance, raw/normalized comparison, pivots and bookmarks.
10. **Workspace storage service** — `platform/workspace-store.js` owns IndexedDB dataset persistence, validation, sanitization and bounds.
11. **Dataset Vault UI** — `platform/dataset-vault-ui.js` exposes explicit save/open/export/import/delete actions.
12. **Python engine client** — `platform/python-engine-client.js` detects the local companion, sends analyst-selected Wazuh payloads to localhost, and renders Python findings without making the hosted application backend-dependent.
13. **SOC/Operations compatibility** — existing SOC and Operations engines remain operational while consolidation continues.
14. **PWA/deployment** — `sw.js`, `manifest.webmanifest`, GitHub Actions and `netlify.toml` provide static deployment and offline application-shell behavior.

## Python Wazuh companion

`python-engine/dbm_wazuh/` contains a dependency-light local analysis service:

```text
payload
  ↓
parser.py
  ├─ direct JSON / arrays
  ├─ NDJSON / JSONL
  ├─ Wazuh API wrappers
  └─ Indexer/OpenSearch _source / hits.hits
  ↓
normalize.py
  ├─ Windows EventChannel
  ├─ Linux authentication
  ├─ Wazuh manager / agent lifecycle
  ├─ FIM
  ├─ network / firewall
  ├─ web
  └─ generic Wazuh alerts
  ↓
detections.py
  ├─ single-event defensive rules
  └─ bounded cross-event correlation
  ↓
engine.py
  ↓
server.py / cli.py
```

The local HTTP service binds to `127.0.0.1:8765` by default. It is optional and processes telemetry on the analyst machine.

## Hybrid telemetry flow

```text
                    Analyst telemetry
                           │
                ┌──────────┴──────────┐
                │                     │
                ▼                     ▼
        Browser BlackLog       Python Wazuh Engine
        + Detection v3         localhost :8765
                │                     │
                ▼                     ▼
        Browser findings       Python findings
                │                     │
                └──────────┬──────────┘
                           ▼
                 Investigation workflow
                  Evidence / SOC / Report
```

The Python result is intentionally not required for the browser pipeline to function. If the service is offline, the hosted application remains usable.

## Wazuh semantic safeguards

The Python normalizer explicitly separates fields that are often incorrectly collapsed:

- Wazuh `rule.id` is not a Windows Event ID;
- Windows Event ID is sourced from `data.win.system.eventID` only;
- `agent.ip` is endpoint/agent context and is not automatically treated as the attack/source IP;
- target and subject/requesting Windows identities are kept separately;
- Windows event time and Wazuh alert time remain distinct;
- Wazuh source MITRE metadata is preserved as source context rather than an automatic DolosBlackMagic verdict.

## Finding contract

Canonical browser and Python findings use the same analyst-facing shape where practical:

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

A finding is analyst context, not an automatic malicious verdict.

## Persistence model

- **LocalStorage** — compact preferences, investigation metadata, rules, triage state and saved views.
- **IndexedDB Dataset Vault** — explicit opt-in persistence for selected normalized browser telemetry.
- **Memory** — newly imported telemetry remains ephemeral unless explicitly saved.
- **Python service** — stateless per request; it does not persist uploaded telemetry by default.

## Performance boundaries

Browser line-oriented telemetry uses Web Worker chunking. Python HTTP requests are capped at 64 MB. Correlation uses bounded time windows and grouping rather than unbounded all-pairs comparisons.

## Privacy boundary

No module automatically transmits artifacts, hashes, IPs, domains, URLs, rules or logs to third parties. The Python service is loopback-only by default. There is no mandatory backend, analytics SDK or remote execution service.

## Remaining consolidation debt

Release-specific compatibility files such as `v05.css`, `v06-ui.css`, `soc-v05-ui.js`, `dashboard-v06.js` and `log-normalize-fixes.js` still exist. They are retained until their stable behavior is absorbed into semantic modules under regression tests.
