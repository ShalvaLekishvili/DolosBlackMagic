# Detection model

DolosBlackMagic detections are analyst-assistance rules, not malware verdicts. Findings must be interpreted with confidence, evidence, surrounding telemetry and false-positive context.

## Browser canonical detection pipeline

Normalized browser telemetry is evaluated by a shared pipeline that combines BlackLog findings and Detection Engine v3 findings, deduplicates equivalent evidence, links rules back to events, sorts by severity and classifies analyst signals.

Detection Engine v3 supports nested declarative conditions, safe regex, grouped thresholds, distinct counts, bounded time windows and ordered sequences with repeated-stage counts. Imported content remains data; no custom JavaScript is executed.

## Python Wazuh detection pipeline

v0.10 introduces a separate localhost Python engine specialized for Wazuh exports. Its finding contract intentionally mirrors the browser model where practical:

- rule ID and stable finding ID;
- severity;
- analyst-facing confidence;
- ATT&CK context;
- tags;
- `why` explanation;
- remediation guidance;
- false-positive context;
- contributing event IDs;
- bounded evidence previews;
- correlation marker.

### Current single-event coverage

**Wazuh / manager**

- agent stopped / disconnected / removed;
- agent restored / connected / restarted;
- high-severity source Wazuh alerts;
- file-integrity changes.

**Windows Security**

- Event 4625 authentication failure;
- Event 4740 account lockout;
- Event 1102 audit-log clearing;
- Event 7045 / 4697 service installation;
- Event 4698 scheduled task creation;
- Event 4720 account creation;
- Event 4728 / 4732 / 4756 security-group membership changes.

**Sysmon-style telemetry**

- suspicious process creation context for commonly abused administrative/scripting binaries;
- process access involving LSASS with confidence/false-positive guidance.

**Linux**

- SSH/authentication failures;
- sudo failures / unauthorized sudo context;
- account creation activity;
- cron/crontab changes.

**Web**

- SQL injection probes;
- path traversal probes;
- command-injection probes.

**Network**

- attempts to commonly administered remote-service ports;
- source Wazuh firewall/network metadata preserved for correlation.

### Current Python correlations

- repeated authentication failures against one source/account pair;
- password spray across multiple accounts from one source;
- local/service authentication failure bursts without a recorded network source;
- repeated RDP failures;
- repeated Windows network-logon failures;
- successful logon after a failure burst;
- multi-port scan-style activity;
- repeated Wazuh agent disconnect/reconnect state changes.

Correlation is bounded by explicit time windows and meaningful grouping keys. Missing grouping values are not collapsed into a shared placeholder bucket.

## Wazuh source semantics

Wazuh source rules and MITRE mappings are useful evidence, but they are not automatically converted into DolosBlackMagic malicious verdicts. The Python engine can emit a separate `WAZUH-HIGH-SEVERITY` finding when the source rule level is high while retaining the source rule description and ATT&CK metadata for analyst review.

The engine explicitly avoids these common semantic mistakes:

- Wazuh `rule.id` is not treated as Windows Event ID;
- Wazuh alert/root `id` is not treated as Windows Event ID;
- `agent.ip` is not treated as attack/source IP when the event does not contain a real source address;
- Windows target account and subject/requesting account are not collapsed into one identity;
- Wazuh source MITRE metadata does not overwrite DolosBlackMagic detection context.

## Finding classifications

Browser findings may use `informational`, `suspicious`, `correlated` and `high-confidence` kinds. Python findings use the same general analyst-assistance framing. Classification describes evidence strength/context, not certainty of compromise.

## Custom rule lifecycle

Detection Studio custom rules retain `draft`, `enabled`, `disabled` and `archived` lifecycle states. Imported Sigma-like YAML and Wazuh XML are translated only for known fields/operators; unsupported syntax is not silently treated as equivalent logic.

Invalid or browser-risky regex is rejected or disabled by the security runtime.
