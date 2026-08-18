# DolosBlackMagic

**Turn artifacts and logs into answers.** DolosBlackMagic is a local-first browser DFIR, threat investigation, log-intelligence and detection-engineering workbench designed to run on free static hosting such as GitHub Pages or Netlify.

## v0.3 — Detection Studio / SOC Workflow

The v0.3 upgrade extends BlackLog into an analyst workflow with ten integrated capabilities:

1. **Custom detection-rule builder** — create local rules against the normalized BlackLog schema using equals, contains, starts-with, ends-with and regex operators.
2. **Sigma-like import** — import common Sigma YAML selections and translate supported fields into normalized DolosBlackMagic fields.
3. **Wazuh XML import** — import supported `<rule>` blocks, `<field>` conditions, `<match>` clauses and severity levels.
4. **Windows/Sysmon Event Knowledge Base** — contextual reference for high-value Windows Security and Sysmon event IDs with ATT&CK hints.
5. **Alert triage** — mark findings as new, investigating, benign, escalated or closed and store analyst notes locally.
6. **Incident creation** — convert current BlackLog findings/events into durable local incidents with severity, entities and status workflow.
7. **Entity correlation graph** — correlate incident hosts, users, IP addresses, processes and findings in a relationship view.
8. **Saved analyst views** — preserve reusable search, severity, source and detections-only filters and re-apply them to BlackLog.
9. **Incident reporting** — export incidents as Markdown or JSON with findings, entities, timeline and analyst notes.
10. **Regression + deployment hardening** — Node 24 CI now covers artifact, BlackLog and SOC-engine behavior; PWA cache v3 includes all Detection Studio assets.

All Detection Studio persistence uses browser LocalStorage. Imported rules and telemetry are parsed as data and are never executed.

## BlackLog Intelligence

DolosBlackMagic includes a browser-side log pipeline for heterogeneous security telemetry:

- Automatic format detection: JSON, NDJSON/JSONL, CSV, RFC-style Syslog, CEF, LEEF, key=value and plain text
- Common event normalization for timestamp, source, host, event ID, user, process, command line, source/destination IP and port, action, URL and message
- Built-in detections for Windows Security, Sysmon-like telemetry, Linux SSH/sudo activity, web attack probes, firewall denies, encoded PowerShell, credential dumping and security-control tampering
- MITRE ATT&CK mappings on detections
- Correlation for repeated authentication failures and multi-port scanning behavior
- Searchable normalized event console
- Severity, source and detections-only filtering
- Findings queue and telemetry entity summary
- CSV normalized-event export and full JSON analysis export
- Up to 35 MB single-file browser ingestion in the BlackLog UI
- Generic fallback for unknown log lines instead of silently dropping data

“Any log” means broad best-effort ingestion. Vendor-perfect semantics still require source-specific adapters as those sources are added.

## Artifact / DFIR features

- Local file and text intake (20 MB artifact UI limit)
- SHA-256 and SHA-1 via Web Crypto
- PE / ELF / ZIP / Office / PDF / script signature classification
- Shannon entropy and printable-string extraction
- IOC extraction for URLs, domains, IPv4, email addresses and common hashes
- Defanged IOC copy view
- Suspicious command/behavior heuristics with risk score
- MITRE ATT&CK technique hints
- JSON / NDJSON event normalization into a chronological timeline
- Draggable investigation relationship graph (BlackGraph)
- Safe layered Base64 decoder (no payload execution)
- Browser LocalStorage case library (Grimoire)
- Markdown and JSON report export plus Print/Save-as-PDF
- Responsive desktop, tablet and mobile interface
- PWA/service-worker caching
- GitHub Actions CI and GitHub Pages deployment
- Netlify static deployment configuration

## Privacy model

The core application has **no backend**. Artifact bytes, imported logs, custom detection rules, triage state, saved views and incidents remain in the browser unless you explicitly export them.

> Treat the browser itself as part of your security boundary. Do not analyze highly sensitive or dangerous samples in an untrusted browser profile or on an unmanaged endpoint.

## Run locally

```bash
python3 -m http.server 8080 -d site
```

Open `http://127.0.0.1:8080`.

Regression tests require Node.js 24+ and no npm package dependencies:

```bash
npm test
```

The suite covers artifact analysis, BlackLog parsing/detection/correlation, Detection Studio rule matching/imports, event knowledge, incidents, entity graphs, saved views and static asset integrity.

## GitHub Pages

The included `.github/workflows/pages.yml` tests and deploys `site/` from `main`. Repository Pages source must be configured as **GitHub Actions**.

Typical project URL:

`https://<username>.github.io/DolosBlackMagic/`

## Structure

```text
DolosBlackMagic/
├── site/
│   ├── index.html
│   ├── app.css
│   ├── log.css
│   ├── soc.css
│   ├── app.js
│   ├── core.js
│   ├── log-engine.js
│   ├── log-ui.js
│   ├── soc-engine.js
│   ├── soc-ui.js
│   ├── favicon.svg
│   ├── manifest.webmanifest
│   └── sw.js
├── tests/
│   ├── core.test.mjs
│   ├── log-engine.test.mjs
│   └── soc.test.mjs
├── scripts/check-static.mjs
├── .github/workflows/
│   ├── ci.yml
│   └── pages.yml
├── netlify.toml
├── package.json
├── LICENSE
└── README.md
```

## Security scope

DolosBlackMagic is a **static-analysis and investigation-assistance interface**. It does not execute submitted scripts/binaries and is not a malware sandbox, antivirus engine, EDR, full SIEM backend or authoritative threat-intelligence verdict system. Built-in and custom detections are analyst-assistance content and should be validated before operational use.

## License

MIT
