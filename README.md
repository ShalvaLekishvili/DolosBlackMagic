# DolosBlackMagic

**Turn artifacts and logs into answers.** DolosBlackMagic is a local-first browser DFIR, threat investigation and log-intelligence workbench designed to run on free static hosting such as GitHub Pages or Netlify.

## v0.2 — BlackLog Intelligence

DolosBlackMagic now includes a browser-side log pipeline for heterogeneous security telemetry:

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
- No backend required for the log-analysis pipeline

The parser is intentionally extensible. A generic fallback preserves unknown log lines as normalized messages instead of silently dropping data. “Any log” therefore means broad best-effort ingestion; vendor-perfect semantic parsing still requires vendor-specific adapters as those sources are added.

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
- GitHub Actions CI and GitHub Pages deploy workflow
- Netlify static deployment configuration

## Privacy model

The core app has **no backend**. Artifact bytes and imported logs are read by the browser and are not uploaded by DolosBlackMagic. Saved investigations use browser LocalStorage. External reputation enrichment is intentionally not claimed in this version.

> Treat the browser itself as part of your security boundary. Do not analyze highly sensitive or dangerous samples in an untrusted browser profile or on an unmanaged endpoint.

## Run locally

No application dependencies are required:

```bash
python3 -m http.server 8080 -d site
```

Open `http://127.0.0.1:8080`.

For regression tests, Node.js 24+ is used and there are no npm package dependencies:

```bash
npm test
```

The test suite covers the artifact core plus BlackLog format detection, normalization, detection and correlation behavior.

## Deploy to GitHub Pages

1. Use a public repository with `main` as the default branch.
2. In **Settings → Pages → Build and deployment → Source**, choose **GitHub Actions**.
3. `.github/workflows/pages.yml` runs tests and deploys `site/`.

Typical project URL:

`https://<username>.github.io/DolosBlackMagic/`

## Deploy to Netlify

Import the repository into Netlify. `netlify.toml` sets the publish directory to `site` and adds baseline security headers.

## Structure

```text
DolosBlackMagic/
├── site/
│   ├── index.html
│   ├── app.css
│   ├── log.css
│   ├── app.js
│   ├── core.js
│   ├── log-engine.js
│   ├── log-ui.js
│   ├── favicon.svg
│   ├── manifest.webmanifest
│   └── sw.js
├── tests/
│   ├── core.test.mjs
│   └── log-engine.test.mjs
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

DolosBlackMagic is a **static-analysis and investigation-assistance interface**. It does not execute submitted scripts/binaries and should not be treated as a malware sandbox, antivirus engine, EDR, full SIEM backend, or authoritative threat-intelligence verdict system. BlackLog detections are analyst-assistance heuristics and correlation rules; they are not a substitute for validated production detection content.

## License

MIT
