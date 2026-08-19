# Testing and quality gates

DolosBlackMagic v0.10 validates both the static browser workstation and the optional Python Wazuh companion.

## Browser/core tests

Requires Node.js 24+:

```bash
npm test
```

The browser suite covers artifact primitives, BlackLog parsing/normalization, Wazuh browser adapters, authentication correlations, SOC state, Operations, regex safety, investigation/evidence provenance, streaming, Dataset Vault, Detection Engine v3 and static/PWA integrity.

`check-static.mjs` additionally parses every production JavaScript file for syntax errors and verifies required assets, HTML references, PWA cache membership, version alignment, bilingual README content and Netlify CSP presence.

## Python Wazuh engine tests

Requires Python 3.11+; CI uses Python 3.12.

```bash
npm run test:python
```

Equivalent direct command:

```bash
cd python-engine
python3 -m unittest discover -s tests -v
```

The Python suite currently verifies:

- OpenSearch `_source` Wazuh agent-stopped alert handling;
- strict separation of Wazuh alert ID / Wazuh rule ID / Windows Event ID;
- Windows Event 4625 target-vs-subject identity normalization;
- agent IP vs observed authentication source IP semantics;
- password-spray correlation;
- malformed NDJSON preservation with zero silent drops;
- multi-port scan correlation.

## CI

`.github/workflows/ci.yml` runs:

1. Node.js 24 browser regression/static-integrity tests;
2. Python 3.12 Wazuh-engine unit tests.

A failed browser or Python suite blocks the CI job.

## Manual browser smoke test

After serving `site/`, verify:

1. Overview loads without console errors.
2. Artifact sample analysis works.
3. Event Explorer ingests telemetry and displays parse quality.
4. Browser Wazuh normalization works with direct alerts and Indexer exports.
5. Python Engine panel reports `OFFLINE` when the local service is not running and does not break browser analysis.
6. Start `python3 -m dbm_wazuh.server`; panel changes to `ONLINE`.
7. **Deep analyze current log** returns Python-normalized event/finding metrics.
8. Python finding inspection shows explanation, remediation, false-positive context and evidence.
9. Python result JSON export works.
10. Line-oriented browser ingestion still uses the streaming path.
11. Investigation, Dataset Vault and report exports remain functional.
12. Mobile layout remains usable with the Python panel present.

## Performance model

Browser line-oriented telemetry uses bounded Blob slices and Web Workers. Python HTTP requests are capped at 64 MB. Correlations use bounded windows and explicit grouping, avoiding unbounded all-pairs analysis.

## Known test boundary

Full localhost-browser networking, IndexedDB transaction behavior and responsive interaction remain browser smoke-test concerns; Node/Python unit suites do not emulate a production browser security model.
