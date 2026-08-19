# DolosBlackMagic Python Wazuh Engine

Optional local companion for deeper Wazuh analysis. It does **not** replace the static browser application and does not upload telemetry anywhere.

## What it analyzes

The engine accepts direct Wazuh alert JSON, JSON arrays, NDJSON/JSONL, Wazuh API wrappers, and Wazuh Indexer/OpenSearch `hits.hits` / `_source` exports. It normalizes Windows EventChannel, Sysmon-style telemetry, Linux authentication, Wazuh manager/agent lifecycle alerts, FIM events, firewall/network events, web telemetry and generic Wazuh alerts.

Detection content is defensive analyst assistance. Findings include confidence, ATT&CK context, evidence references, remediation and false-positive guidance. The engine does not execute uploaded content and is not an antivirus, EDR, malware sandbox or authoritative threat-intelligence system.

## Start the local API

```bash
cd python-engine
python3 -m dbm_wazuh.server
```

Default endpoint: `http://127.0.0.1:8765`

Then open the DolosBlackMagic Event Explorer. The **Python Wazuh Engine** panel will show `ONLINE` and enable **Deep analyze current log**.

## CLI

```bash
cd python-engine
python3 -m dbm_wazuh.cli /path/to/wazuh-export.json --pretty
```

or:

```bash
cat alerts.jsonl | python3 -m dbm_wazuh.cli --pretty
```

## Tests

```bash
cd python-engine
python3 -m unittest discover -s tests -v
```

## Privacy and limits

- processing stays on the local machine;
- API binds to `127.0.0.1` by default;
- request size is capped at 64 MB;
- CORS is limited to the DolosBlackMagic GitHub Pages origin and localhost development origins;
- malformed NDJSON records are preserved as partial evidence rather than silently discarded;
- imported rules or telemetry are never evaluated as Python or JavaScript code.
