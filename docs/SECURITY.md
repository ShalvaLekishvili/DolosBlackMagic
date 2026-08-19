# Security model

DolosBlackMagic v0.10 has two execution modes: a static browser workstation and an optional local Python Wazuh companion. The Python service is not required for hosted operation.

## Browser controls

- Uploaded files are read as bytes/text and are never executed.
- Imported detection content is data; there is no `eval` or `new Function` rule execution path.
- UI modules escape untrusted telemetry before rendering generated HTML.
- Analyst-controlled regex is length/structure guarded before execution.
- Investigation and Dataset Vault restore paths validate schema and namespace before state replacement.
- IndexedDB persistence is explicit opt-in and bounded.
- Arbitrary raw event objects are not persisted by the Dataset Vault; bounded previews are used for context.
- Service-worker fetch handling is same-origin only.
- Netlify supplies CSP and static response hardening.
- Core browser mode has no analytics, tracking, telemetry upload or mandatory external API.

## Python Wazuh companion boundary

The Python engine is designed as a localhost analyst tool.

- binds to `127.0.0.1` by default;
- uses only Python standard-library runtime dependencies for normal operation;
- caps request bodies at 64 MB;
- treats telemetry as data and never executes imported Python, JavaScript, binaries or commands;
- does not persist submitted logs by default;
- limits browser CORS to the DolosBlackMagic GitHub Pages origin and localhost development origins;
- returns structured JSON only;
- exposes only `/health` and `/analyze` in the current service;
- preserves malformed input as partial evidence where safe rather than attempting code interpretation.

The analyst endpoint, OS account and browser profile remain part of the trust boundary. Running the Python service on `0.0.0.0` is possible via CLI arguments but is not recommended unless the analyst deliberately applies host firewall/access controls.

## Wazuh semantic safety

To reduce false correlations and misleading evidence, the Wazuh normalizers keep these values distinct:

- Wazuh rule ID vs Windows Event ID;
- Wazuh alert ID vs Indexer document ID;
- endpoint/agent IP vs observed source IP;
- target account vs subject/requesting account;
- Windows event time vs Wazuh alert/ingest time.

Wazuh source MITRE mappings are retained as source metadata, not converted into an unquestionable malicious verdict.

## IndexedDB boundary

IndexedDB is origin-scoped browser storage, not an encrypted evidence vault. DolosBlackMagic does not claim encryption-at-rest beyond the browser/OS profile. Highly sensitive telemetry should be handled on a trusted managed endpoint.

## CSP

Netlify uses self-contained script/worker resources, `object-src 'none'`, restrictive referrer/permissions policy and other static hardening. GitHub Pages does not provide repository-controlled response headers; application code remains self-contained there.

The hosted application's optional localhost connection is initiated only by the Python companion client and targets loopback endpoints. If the browser blocks local-network access by policy, browser-only mode remains functional.

## Regex safety

`security-runtime.js` rejects invalid, excessively long and common pathological analyst-controlled regex structures. This is a pragmatic browser denial-of-service guard, not a formal regex complexity proof.

## Reporting a security issue

Do not put sensitive production logs, credentials or malware samples in a public issue. Reproduce problems with sanitized telemetry whenever possible.
