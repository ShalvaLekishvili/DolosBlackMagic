# DolosBlackMagic v0.5 Architecture

DolosBlackMagic is a static, local-first browser application. `site/` is the deployable artifact; no server runtime is required for the core product.

## Layers

1. **Artifact core** — `core.js` performs hashing, type detection, strings/entropy, IOC extraction, artifact heuristics, decoding, graph/timeline preparation and report generation.
2. **BlackLog** — `log-engine.js` detects log format, parses records, normalizes events, applies built-in defensive rules and performs bounded sliding-window correlation. `log-ui.js` owns ingestion/search/evidence UI.
3. **Detection/SOC** — `soc-engine.js` manages custom rule data, v1→v2 browser-state migration, import translation, triage, incidents, views and reporting. `soc-ui.js` preserves the base interface; `soc-v05-ui.js` progressively adds v0.5 rule testing/lifecycle and richer incident interactions.
4. **Operations** — `ops-engine.js` provides finding deduplication, suppression, lightweight context enrichment, investigation graph construction, health/dashboard summaries and versioned workspace backup/restore. `ops-ui.js` renders those operations.
5. **Security/UI hardening** — `security-runtime.js` guards analyst-supplied regex execution. `ui-hardening.js` aligns navigation, keyboard behavior, ARIA state and loads optional v0.5 SOC enhancements.
6. **PWA/deployment** — `sw.js`, `manifest.webmanifest`, GitHub Actions and `netlify.toml` provide static deployment/offline shell behavior.

## Normalized event contract

BlackLog events use a consistent object with core fields including `id`, `timestamp`, `timestampValid`, `format`, `source`, `host`, `eventId`, `channel`, `provider`, `severity`, `message`, identity/domain, process/parent/PID/command line, source/destination IP/port, protocol, action/status, URL/HTTP metadata, hashes, `quality`, `raw`, and `detections`.

Unknown fields remain available in `raw`. Missing data is represented explicitly rather than fabricated.

## Finding contract

Built-in findings contain a rule ID/name, severity, confidence, score, ATT&CK techniques, firing explanation, remediation guidance, false-positive context, source event IDs, evidence previews and correlation flag. Custom findings use the same analyst-facing concepts where available.

## Persistence

Simple browser state is stored in namespaced LocalStorage. SOC v0.5 writes `dbm.soc.*.v2` and migrates from v1 without deleting legacy data. Workspace exports are versioned and restore only allowed DolosBlackMagic namespaces. Event collections themselves are currently memory-resident; this avoids silently persisting potentially sensitive logs.

## Data flow

`Telemetry → Parse quality → Normalized event → Built-in/custom finding → Evidence → Triage → Incident → Entity pivot/report`.

Artifact investigations remain separate but share the same local-first/privacy model. A future storage change must preserve migration and export compatibility rather than overwriting analyst state.

## Constraints

The application intentionally avoids mandatory backends, analytics, remote fonts/CDNs and framework/runtime dependencies. Browser memory is therefore the practical limit for large event collections; v0.5 bounds rendered event rows and correlation graph size and reduces expensive repeated filtering, but parsing very large files remains a main-thread limitation documented in the release notes.
