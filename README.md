<div align="center">

<img src="docs/assets/dolosblackmagic-readme-banner.svg" alt="DolosBlackMagic — Local-first DFIR and SOC workbench" width="100%" />

# DolosBlackMagic

**Local-first DFIR · Wazuh Log Intelligence · Detection Engineering · Evidence · Investigation · SOC Operations**

[![Version](https://img.shields.io/badge/version-0.10.0-2b3645?style=flat-square)](package.json)
[![Node](https://img.shields.io/badge/Node.js-%3E%3D24-2b3645?style=flat-square)](package.json)
[![Python](https://img.shields.io/badge/Python-%3E%3D3.11-2b3645?style=flat-square)](python-engine/pyproject.toml)
[![CI](https://img.shields.io/github/actions/workflow/status/ShalvaLekishvili/DolosBlackMagic/ci.yml?branch=main&style=flat-square&label=CI)](.github/workflows/ci.yml)
[![Pages](https://img.shields.io/badge/GitHub%20Pages-live-2b3645?style=flat-square)](https://shalvalekishvili.github.io/DolosBlackMagic/)
[![License](https://img.shields.io/badge/license-MIT-2b3645?style=flat-square)](LICENSE)

**[Live Application](https://shalvalekishvili.github.io/DolosBlackMagic/)** · **[ქართული განმარტება](#-ქართული-განმარტება)** · **[Python Wazuh Engine](python-engine/README.md)** · **[Architecture](docs/ARCHITECTURE.md)** · **[Detections](docs/DETECTIONS.md)** · **[Security](docs/SECURITY.md)** · **[v0.10 Release](docs/V0.10.md)**

</div>

---

## What is DolosBlackMagic?

DolosBlackMagic **0.10.0** is a privacy-first DFIR/SOC workstation for artifact inspection, Wazuh and heterogeneous telemetry analysis, evidence-driven detections, investigation continuity, incident handling and reporting.

The product keeps its static-hosting advantage while adding an **optional local Python Wazuh analysis companion**. GitHub Pages, Netlify and local static hosting continue to work without a backend. When the Python companion is running on the analyst workstation, Event Explorer can use it for deeper Wazuh parsing, normalization and correlation.

> DolosBlackMagic is analyst-assistance software. It is not an antivirus, EDR, malware sandbox, exploit framework, full SIEM backend, or authoritative threat-intelligence verdict engine.

## v0.10 — Python Wazuh Analysis Companion

### Browser mode

The browser engine remains the default and supports local parsing, Web Worker processing, normalization, filtering, detections, investigation state and reporting.

### Python deep-analysis mode

The optional Python engine adds a dedicated Wazuh-aware analysis pipeline for:

- direct Wazuh alert JSON;
- JSON arrays;
- NDJSON / JSONL;
- Wazuh API `data.affected_items` / item wrappers;
- Wazuh Indexer / OpenSearch `hits.hits` and `_source` exports;
- Windows EventChannel and Windows Security events;
- Sysmon-style process/network/process-access telemetry;
- Linux authentication and sudo activity;
- Wazuh manager and agent lifecycle events;
- Wazuh FIM / integrity-change telemetry;
- firewall and network events;
- web telemetry and common defensive web-probe patterns;
- generic Wazuh alerts with source-rule metadata preserved.

The engine preserves the distinction between **Wazuh rule ID** and **Windows Event ID**, between **agent IP** and **actual source IP**, and between Windows **target** and **subject/requesting** identities.

## Hybrid architecture

```text
                    DolosBlackMagic v0.10

       ┌─────────────────────────────────────┐
       │ Static browser workstation          │
       │ GitHub Pages / Netlify / localhost  │
       └─────────────────┬───────────────────┘
                         │
               browser-native analysis
                         │
             ┌───────────▼───────────┐
             │ BlackLog + Detection  │
             │ Investigation / SOC   │
             └───────────┬───────────┘
                         │ optional localhost
                         ▼
       ┌─────────────────────────────────────┐
       │ Python Wazuh Engine :8765           │
       │ parser → normalizer → detections    │
       │ → correlation → evidence            │
       └─────────────────────────────────────┘
```

No cloud backend is required. The Python service binds to `127.0.0.1` by default and processes telemetry locally.

## Wazuh normalization model

The Python engine normalizes important fields without collapsing semantically different identities:

| Area | Preserved fields |
|---|---|
| Event time | Windows `systemTime`, Wazuh alert timestamp, validity flags |
| Agent | ID, name, endpoint IP |
| Manager | manager name, decoder, location |
| Wazuh rule | rule ID, level, description, groups, source MITRE metadata |
| Windows | Event ID, provider, channel, computer |
| Authentication | target user/domain, subject user/domain, logon type, auth package, status/substatus |
| Process | image/process, parent, PID, command line |
| Network | true source/destination IP and ports; agent IP is kept separate |
| Web | URL, method, status, user agent |
| Evidence | Indexer `_index`, document `_id`, alert ID, raw record |

Unknown or malformed telemetry degrades gracefully. NDJSON lines that fail parsing are preserved as partial records rather than silently discarded.

## Detection coverage

The current defensive detection content includes, among other rules:

- Windows failed authentication, account lockout, audit-log clearing;
- service installation and scheduled-task creation;
- user creation and privileged-group changes;
- suspicious Sysmon process execution and LSASS process-access context;
- Linux SSH/authentication failures, sudo failures, account changes and cron persistence indicators;
- Wazuh agent stopped/disconnected/restored signals;
- Wazuh file-integrity changes;
- SQL injection, path traversal and command-injection probes;
- administrative-service network attempts;
- high-severity source Wazuh alerts;
- password guessing and password spray correlation;
- repeated RDP/network logon failures;
- failure → success authentication sequences;
- multi-port scan correlation;
- repeated Wazuh agent connectivity changes.

Every finding is analyst assistance: confidence, evidence, explanation, ATT&CK context where available, remediation and false-positive guidance are preferred over automatic malicious verdicts.

## Start the Python engine

No third-party runtime dependency is required for normal operation.

```bash
cd python-engine
python3 -m dbm_wazuh.server
```

Default service:

```text
http://127.0.0.1:8765
```

Then open **Event Explorer**. The **Python Wazuh Engine** panel will report `ONLINE` and enable **Deep analyze current log**.

CLI usage:

```bash
cd python-engine
python3 -m dbm_wazuh.cli /path/to/wazuh-export.json --pretty
```

## Workstation map

| Workspace | Analyst purpose | Key capabilities |
|---|---|---|
| **Overview** | Workspace state | local workspace pulse and quick actions |
| **Artifact Analysis** | Inspect evidence | hashes, signatures, strings, entropy, IOC extraction |
| **Event Explorer / BlackLog** | Analyze telemetry | browser parsing + optional Python Wazuh deep analysis |
| **Detection Studio** | Engineer rules | lifecycle, testing, safe regex, Sigma-like/Wazuh import |
| **SOC Operations** | Triage | findings, suppression, incidents, entity correlation |
| **Investigation Graph** | Explore relationships | hosts, users, IPs, processes, domains, URLs, hashes |
| **Case Timeline** | Order evidence | telemetry and analyst chronology |
| **Investigations** | Preserve context | notes, bookmarks, findings, entities, Dataset Vault |
| **Reports** | Handoff | Markdown, JSON and print/PDF-ready output |

## Local Dataset Vault

Telemetry persistence is **opt-in**. Selected normalized datasets can be stored locally in IndexedDB and reopened later. Large arbitrary raw Wazuh exports are not automatically persisted.

## Privacy & security

- core browser analysis has no upload pipeline;
- Python deep analysis is localhost-only by default;
- no mandatory account, telemetry, tracking or analytics;
- no `eval()` or `new Function()` for imported rules;
- uploaded artifacts and logs are never executed;
- Python API request size is bounded;
- browser storage restore/import is namespace-restricted and validated;
- Wazuh source MITRE metadata is preserved as source context, not treated as an unquestionable verdict.

## Testing

Browser/core suite:

```bash
npm test
```

Python engine:

```bash
npm run test:python
```

or:

```bash
cd python-engine
python3 -m unittest discover -s tests -v
```

CI validates both Node.js 24 and Python 3.12 paths.

## Static hosting

### GitHub Pages

The `site/` directory remains the deployable static application. The Python engine does not run on GitHub Pages itself; it is an optional companion on the analyst machine.

### Netlify

`netlify.toml` continues to publish `site/` and applies the project's static security headers.

### Local browser-only mode

```bash
npm run serve
```

### Local browser + Python mode

Terminal 1:

```bash
npm run serve
```

Terminal 2:

```bash
npm run serve:wazuh
```

---

# 🇬🇪 ქართული განმარტება

## რას წარმოადგენს DolosBlackMagic?

**DolosBlackMagic 0.10.0** არის local-first DFIR/SOC სამუშაო გარემო, რომელიც განკუთვნილია არტეფაქტების, Wazuh-ის ლოგების, უსაფრთხოების ტელემეტრიის, დეტექციების, გამოძიებებისა და ინციდენტების დასამუშავებლად.

პროექტი კვლავ შეიძლება ჩვეულებრივად განთავსდეს **GitHub Pages-ზე ან Netlify-ზე**. Python backend სავალდებულო არ არის. ახალი Python Wazuh Engine არის დამატებითი, ლოკალურად გასაშვები მოდული უფრო ღრმა ანალიზისთვის.

## რას აკეთებს Python Wazuh Engine?

Engine ამუშავებს არა მხოლოდ ორ კონკრეტულ Wazuh rule-ს, არამედ Wazuh-ის სხვადასხვა ტიპის export-სა და alert family-ს:

- პირდაპირ Wazuh alert JSON-ს;
- JSON array-ს;
- NDJSON / JSONL-ს;
- Wazuh API response wrapper-ებს;
- Wazuh Indexer / OpenSearch `_source` და `hits.hits` export-ებს;
- Windows Security / EventChannel მოვლენებს;
- Sysmon telemetry-ს;
- Linux authentication/sudo მოვლენებს;
- Wazuh agent stopped/disconnected/reconnected ტიპის manager alerts-ს;
- File Integrity Monitoring მოვლენებს;
- firewall/network telemetry-ს;
- web server/security მოვლენებს;
- სხვა generic Wazuh alert-ებს.

## რატომ არის ეს მნიშვნელოვანი?

Wazuh-ის ლოგებში ერთნაირი მნიშვნელობა არ აქვს ყველა `id` ველს. მაგალითად:

- `rule.id` არის **Wazuh rule ID**;
- `data.win.system.eventID` არის **Windows Event ID**;
- `agent.ip` არის endpoint/Wazuh agent-ის IP და ყოველთვის არ არის თავდამსხმელის/source IP;
- `targetUserName` და `subjectUserName` სხვადასხვა როლს აღწერს.

Python engine ამ განსხვავებებს ცალ-ცალკე ინარჩუნებს, რათა correlation და timeline არ აირიოს.

## დეტექციები და correlation

Engine ამჟამად აკეთებს Windows, Sysmon, Linux, Wazuh manager/FIM, network და web telemetry-ის rule-based ანალიზს. ასევე შეუძლია რამდენიმე source event-ის გაერთიანება, მაგალითად:

- ერთ ანგარიშზე მრავალჯერადი authentication failure;
- ერთი IP-დან რამდენიმე მომხმარებელზე password spray;
- RDP/network logon failure burst;
- რამდენიმე failure-ის შემდეგ successful logon;
- ერთ წყაროს მიერ მრავალ port-ზე კავშირის მცდელობა;
- Wazuh agent-ის ხშირი disconnect/reconnect.

Finding არ ნიშნავს ავტომატურად, რომ მოვლენა მავნეა. სისტემა აჩვენებს **severity-ს, confidence-ს, evidence-ს, მიზეზს, MITRE context-ს, remediation-ს და შესაძლო false-positive მიზეზებს**.

## როგორ გავუშვათ?

```bash
cd python-engine
python3 -m dbm_wazuh.server
```

შემდეგ გახსენი DolosBlackMagic → **Event Explorer**. Python Engine-ის ბლოკში უნდა გამოჩნდეს `ONLINE` და ღილაკი **Deep analyze current log** გახდება აქტიური.

CLI რეჟიმიც შესაძლებელია:

```bash
cd python-engine
python3 -m dbm_wazuh.cli wazuh-export.json --pretty
```

## კონფიდენციალურობა

Python service ნაგულისხმევად უსმენს მხოლოდ `127.0.0.1`-ს. ლოგები cloud-ში არ იგზავნება. თუ Python engine არ არის გაშვებული, DolosBlackMagic ჩვეულებრივ აგრძელებს browser-only რეჟიმში მუშაობას.

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Detection model](docs/DETECTIONS.md)
- [Log formats](docs/LOG_FORMATS.md)
- [Privacy](docs/PRIVACY.md)
- [Security](docs/SECURITY.md)
- [Testing](docs/TESTING.md)
- [Python Wazuh Engine](python-engine/README.md)
- [v0.10 release notes](docs/V0.10.md)

## License

MIT — see [LICENSE](LICENSE).
