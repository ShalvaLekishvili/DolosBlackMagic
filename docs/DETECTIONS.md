# Detection model

DolosBlackMagic detections are analyst-assistance rules, not malware verdicts. A finding should be interpreted together with its confidence, evidence, surrounding telemetry and false-positive context.

## Built-in coverage

Current BlackLog rules include defensive coverage for Windows failed logons, audit-log clearing, suspicious PowerShell, scheduled tasks, service installation, account/group changes, RDP-related authentication, Sysmon-style LOLBin/process-access telemetry, Linux SSH/sudo/cron indicators, web SQL injection/path traversal/scanner probes, encoded PowerShell, credential-access indicators and security-control tampering.

Correlations currently include repeated authentication failures within five minutes and multi-port activity within two minutes. Correlation uses bounded sliding windows rather than assigning malicious intent to a single weak signal.

## Finding fields

Built-in findings include severity, confidence, numeric risk score, ATT&CK mapping, explanation of why the rule fired, remediation guidance, possible false positives, source event IDs and evidence previews.

## Custom rule lifecycle

Custom rules support `draft`, `enabled`, `disabled`, and `archived`. Supported condition operators include equality/inequality, contains, starts/ends, regex, existence, membership, numeric comparisons and per-condition NOT. Rule groups currently support all/any semantics.

Rules can be tested against loaded events before operational use. Invalid or browser-risky regex is rejected or disabled by the security runtime.

## Imports

Sigma-like YAML and Wazuh XML are translated only for known fields/operators. Detailed import APIs classify output as fully translated, partially translated, unsupported, or invalid through a report. Unsupported fields are named; rule meaning is not intentionally rewritten silently.

Imported content is data. DolosBlackMagic never evaluates imported JavaScript and does not execute scripts/binaries.
