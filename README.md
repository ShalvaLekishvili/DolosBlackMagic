# DolosBlackMagic

**Turn artifacts and logs into answers.** DolosBlackMagic v0.5.0 is a local-first browser DFIR, log-intelligence, detection-engineering, investigation and SOC-operations workbench designed for static hosting.

## v0.5 highlights

- Resilient BlackLog ingestion with content-based detection for JSON, NDJSON/JSONL, CSV, RFC3164/RFC5424 Syslog, CEF, LEEF, key=value and plaintext.
- Zero-silent-drop goal: malformed and partial records are preserved with parse-quality metadata instead of silently disappearing.
- Richer normalized event schema covering channel/provider, identity/domain, process lineage/PID, network protocol, HTTP fields, hashes and raw-event reference.
- Evidence-driven findings with severity, confidence, ATT&CK mapping, firing explanation, remediation guidance and false-positive context.
- Sliding-window brute-force and port-scan correlation.
- Detection Studio rule lifecycle: Draft → Enabled → Disabled → Archived, rule testing, NOT and numeric operators, safe regex validation, Sigma-like and Wazuh import translation reports.
- Triage history, disposition, severity override, richer incident state and entity pivots.
- Safer workspace backup/restore with version metadata, namespace allow-listing and import validation.
- Responsive/keyboard/accessibility hardening, bounded event rendering and debounced indexed filtering.
- Netlify CSP/security headers, subpath-safe PWA manifest and synchronized service-worker assets.

## Core capabilities

### Artifact analysis

Local file/text intake, SHA-256/SHA-1, file-type signatures, entropy, printable strings, IOC extraction/defanging, heuristic behavior scoring, safe Base64 decoding, artifact timeline/graph, browser-local case storage and Markdown/JSON/print reporting.

### Event Explorer / BlackLog

- best-effort heterogeneous log ingestion without relying only on file extensions;
- normalized searchable events and CSV/JSON export;
- parse statistics: total, parsed, partial, malformed and dropped;
- built-in defensive detections for Windows, Sysmon-style telemetry, Linux authentication/cron, network scanning and common web probes;
- evidence inspector explaining why a finding fired and which source events caused it.

“Any log” means broad **best-effort ingestion**, not vendor-perfect semantic support. Unknown or malformed telemetry is retained where safe and clearly marked.

### Detection Studio

Custom rules remain data, never executable code. Supported rule operators include equals/not-equals, contains, starts/ends, regex, existence, membership and numeric comparisons. Rules can be tested against currently loaded events. Sigma-like YAML and Wazuh XML importers translate only supported constructs and report partial/unsupported content.

### SOC operations

Triage, incident creation, analyst notes/status history, entity correlation, saved views, suppression/deduplication, risk context, data-quality health and versioned workspace export/restore all work browser-side.

## Privacy and security model

The application has no mandatory backend, accounts, telemetry or analytics. Artifacts, logs, rules and investigation state stay in the browser unless the analyst explicitly exports them. Uploaded artifacts are never executed. Imported rules are parsed as data; there is no `eval` or `new Function` rule execution.

Treat the browser profile and endpoint as part of the security boundary. DolosBlackMagic is analyst-assistance software, **not** an antivirus, EDR, malware sandbox, full SIEM backend or authoritative threat-intelligence verdict system.

## Run locally

```bash
python3 -m http.server 8080 -d site
```

Open `http://127.0.0.1:8080`.

## Test

Node.js 24+; no npm package dependencies are required.

```bash
npm test
```

The suite covers artifact analysis, parsers/normalization, detection/correlation, rule lifecycle/imports, SOC persistence, operations/workspace validation, regex safety and static deployment integrity.

## Deploy

### GitHub Pages

`.github/workflows/pages.yml` runs `npm test`, uploads `site/` and deploys through GitHub Pages. The app uses relative paths and is designed to work under `/DolosBlackMagic/`.

Live project URL: `https://shalvalekishvili.github.io/DolosBlackMagic/`

### Netlify

`netlify.toml` publishes `site/` and applies CSP plus baseline security/privacy headers.

## Structure

```text
DolosBlackMagic/
├── site/
│   ├── index.html
│   ├── app.css / log.css / soc.css / ops.css / v05.css
│   ├── core.js / app.js
│   ├── log-engine.js / log-ui.js
│   ├── soc-engine.js / soc-ui.js / soc-v05-ui.js
│   ├── ops-engine.js / ops-ui.js
│   ├── security-runtime.js / ui-hardening.js
│   ├── manifest.webmanifest / sw.js / favicon.svg
├── tests/
│   ├── core.test.mjs
│   ├── log-engine.test.mjs
│   ├── soc.test.mjs
│   ├── ops.test.mjs
│   └── security.test.mjs
├── scripts/check-static.mjs
├── docs/
├── .github/workflows/{ci.yml,pages.yml}
├── netlify.toml
└── package.json
```

## Documentation

See `docs/ARCHITECTURE.md`, `docs/LOG_FORMATS.md`, `docs/DETECTIONS.md`, `docs/SECURITY.md`, `docs/PRIVACY.md`, `docs/TESTING.md` and `docs/V0.5.md`.

## License

MIT
