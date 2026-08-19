# Privacy

DolosBlackMagic is designed to work without an account, analytics service, mandatory API or application backend.

## Browser-local data

Artifact bytes, pasted telemetry, imported logs, custom rules, triage state, incidents, saved views, suppression rules and workspace settings are processed locally by the browser. The core application does not upload this data.

Compact analyst state uses DolosBlackMagic LocalStorage namespaces. Imported telemetry is memory-resident by default. The opt-in Dataset Vault can persist selected normalized telemetry in IndexedDB after sanitization and bounds checks.

## Optional Python Wazuh analysis

v0.10 adds an optional local Python companion. When the analyst explicitly uses **Deep analyze current log**, the current Event Explorer text is sent to `http://127.0.0.1:8765` or `http://localhost:8765` on the same analyst workstation.

The Python service:

- runs locally;
- does not forward telemetry to a cloud service;
- does not persist submitted payloads by default;
- returns normalized events/findings as JSON to the browser;
- is not required for browser-only operation.

If local-network/browser policy prevents the hosted page from reaching loopback, the static application continues to operate in browser-only mode.

## Dataset Vault limits

Normal UI saves are limited to 50,000 events and approximately 24 MB per dataset. These are product safety bounds, not browser quota guarantees. The browser/OS controls actual storage quota.

## Exports

JSON, CSV, Markdown, printable reports, workspace snapshots and Python-analysis JSON exports are generated locally. Investigation snapshot restore validates schema before replacing compatible DolosBlackMagic-owned state.

## Browser and endpoint boundary

The browser profile, extensions, local Python runtime, operating system and endpoint-management controls are outside the application boundary. Sensitive investigations should be conducted on a trusted managed endpoint/profile. Clearing browser storage can remove LocalStorage/IndexedDB analyst data unless exports exist.

## Network behavior

Core browser functionality uses same-origin static resources. No hidden telemetry or third-party tracking is added. The only new optional connection in v0.10 is the analyst-initiated localhost Python companion connection described above.
