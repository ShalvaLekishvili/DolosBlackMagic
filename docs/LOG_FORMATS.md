# Log formats and normalization

DolosBlackMagic has two complementary ingestion paths: the browser BlackLog engine and the optional local Python Wazuh engine.

## Browser BlackLog

Content heuristics are preferred over file extensions. Browser ingestion supports:

- JSON objects/arrays and common event/data arrays;
- NDJSON / JSONL with malformed-line preservation;
- CSV with quoted values;
- RFC3164/RFC5424-style syslog;
- CEF;
- LEEF;
- `key=value` telemetry;
- generic plaintext fallback.

## Python Wazuh engine

The v0.10 Python companion specializes in Wazuh JSON-oriented exports:

- direct Wazuh alert objects;
- JSON arrays of Wazuh alerts;
- NDJSON / JSONL;
- Wazuh Indexer / OpenSearch `_source` documents;
- OpenSearch `hits.hits` result wrappers;
- Wazuh API `data.affected_items`, `data.items`, `alerts`, `affected_items` and similar item wrappers.

The parser records wrapper types and parse statistics. Malformed NDJSON lines are preserved as partial evidence; the target remains zero silent drops.

## Wazuh event families

Normalized Python events are classified into a best-effort family such as:

- `windows-event`;
- `agent-lifecycle`;
- `manager-alert`;
- `linux-auth`;
- `fim`;
- `network`;
- `web`;
- `wazuh-alert`.

Family classification is used to route defensive detection logic. Unknown events remain generic rather than being forced into an incorrect vendor family.

## Wazuh normalized fields

The Python normalizer preserves:

- Windows event time and Wazuh alert time separately;
- Windows Event ID;
- Wazuh rule ID, level, description and groups;
- Wazuh source MITRE IDs/techniques/tactics;
- agent ID/name/IP;
- manager name;
- decoder name/parent and location;
- host/computer/provider/channel;
- target user/domain and subject/requesting user/domain;
- logon type, auth package, logon process, status/substatus/failure reason;
- process, parent process, PID and command line;
- source/destination IP and ports;
- protocol/action/status;
- URL, HTTP method/status and user agent;
- hashes;
- Indexer `_index` and document `_id`;
- Wazuh alert ID;
- raw source record.

## Semantic safeguards

The engine does not infer fields from unrelated metadata merely to fill gaps:

- `agent.ip` is not substituted for missing source IP;
- Wazuh `rule.id` is not treated as Windows Event ID;
- Wazuh root alert `id` is not treated as Windows Event ID;
- missing Windows source address `-` normalizes to empty, not agent IP;
- target and requesting identities remain separate.

## Parse-quality contract

Every Python analysis reports total records, parsed, partial, malformed, unsupported, dropped and wrapper counts. Parser errors include bounded record/preview context.

## Known limitations

The Python engine is Wazuh-focused rather than a universal SIEM parser. Vendor-specific nested structures outside known Wazuh schemas remain available in `raw` and may require future adapters. The local HTTP request is capped at 64 MB. Browser and Python paths intentionally prioritize semantic correctness over pretending unsupported structures are fully normalized.
