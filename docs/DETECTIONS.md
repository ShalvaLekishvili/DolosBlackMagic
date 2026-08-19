# Detection model

DolosBlackMagic detections are analyst-assistance rules, not malware verdicts. Findings must be interpreted with confidence, evidence, surrounding telemetry and false-positive context.

## Canonical detection pipeline

From v0.9 onward, normalized telemetry is evaluated by a shared detection pipeline. Existing BlackLog findings and Detection Engine v3 findings are normalized into one analyst-facing collection.

The pipeline:

1. preserves existing built-in findings;
2. evaluates Detection Engine v3 rules against chronologically ordered events;
3. deduplicates equivalent rule/evidence combinations;
4. links rule IDs back to contributing events;
5. sorts findings by severity;
6. classifies findings as `informational`, `suspicious`, `correlated`, or `high-confidence`.

Classification is descriptive analyst context, not a malicious verdict.

## Built-in defensive coverage

BlackLog and platform rules include defensive coverage for Windows failed logons, audit-log clearing, suspicious PowerShell, scheduled tasks, service installation, account/group changes, RDP-related authentication, Sysmon-style process/network/process-access telemetry, Linux SSH/sudo/cron indicators, web SQL injection/path traversal/scanner probes, credential-access indicators and security-control tampering.

Detection Engine v3 correlations include:

- authentication spray from one source against multiple accounts;
- repeated authentication failures followed by a successful authentication;
- service installation followed by process execution on the same host;
- multi-port firewall/network activity;
- repeated access attempts to administrative-service ports;
- repeated web authentication denial patterns.

Grouped correlations do not combine unrelated events when required grouping fields are missing.

## Correlation semantics

Correlation uses bounded time windows and explicit grouping. Sequence stages may specify a repeat count, allowing a rule to require multiple matching events before advancing to the next stage.

For example, the success-after-failure correlation requires a failure burst before a subsequent successful authentication rather than treating one failed attempt followed by one success as equivalent evidence.

## Finding fields

Normalized findings may include:

- stable ID and rule ID;
- severity and analyst-facing confidence;
- source engine;
- classification/kind;
- ATT&CK techniques;
- tags;
- explanation of why the rule fired;
- remediation guidance;
- false-positive context;
- source event IDs;
- bounded evidence previews;
- correlation metadata such as group, observed count and time window.

## Detection Engine v3

The engine is declarative and does not execute custom JavaScript.

Supported concepts include:

- nested `all`, `any`, and `not` conditions;
- equals / not-equals / contains / startsWith / endsWith;
- existence and membership checks;
- numeric comparisons;
- browser-safe regex validation;
- grouped thresholds;
- distinct-value counts;
- bounded time windows;
- ordered sequences with repeated-stage counts.

## Custom rule lifecycle

Custom Detection Studio rules support `draft`, `enabled`, `disabled`, and `archived`. Existing rule testing and import workflows remain separate from the platform v3 correlation engine during incremental consolidation.

Invalid or browser-risky regex is rejected or disabled by the security runtime.

## Sigma-like / Wazuh imports

Sigma-like YAML and Wazuh XML are translated only for known fields/operators. Import reports classify output as fully translated, partially translated, unsupported, or invalid where supported by the importer.

Unsupported syntax is not silently treated as equivalent logic.

Imported content is data. DolosBlackMagic never evaluates imported JavaScript and does not execute imported scripts or binaries.
