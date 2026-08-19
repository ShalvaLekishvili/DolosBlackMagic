<div align="center">

<img src="docs/assets/dolosblackmagic-readme-banner.svg" alt="DolosBlackMagic — Local-first DFIR and SOC workbench" width="100%" />

# DolosBlackMagic

**Local-first browser DFIR · Log Intelligence · Detection Engineering · Evidence · Investigation · SOC Operations**

[![Version](https://img.shields.io/badge/version-0.9.0-2b3645?style=flat-square)](package.json)
[![Node](https://img.shields.io/badge/Node.js-%3E%3D24-2b3645?style=flat-square)](package.json)
[![CI](https://img.shields.io/github/actions/workflow/status/ShalvaLekishvili/DolosBlackMagic/ci.yml?branch=main&style=flat-square&label=CI)](.github/workflows/ci.yml)
[![Pages](https://img.shields.io/badge/GitHub%20Pages-live-2b3645?style=flat-square)](https://shalvalekishvili.github.io/DolosBlackMagic/)
[![License](https://img.shields.io/badge/license-MIT-2b3645?style=flat-square)](LICENSE)

**[Live Application](https://shalvalekishvili.github.io/DolosBlackMagic/)** · **[ქართული განმარტება](#-ქართული-განმარტება)** · **[Architecture](docs/ARCHITECTURE.md)** · **[Detections](docs/DETECTIONS.md)** · **[Security](docs/SECURITY.md)** · **[v0.9 Release](docs/V0.9.md)**

</div>

---

## What is DolosBlackMagic?

DolosBlackMagic 0.9.0 is a **privacy-first, browser-based DFIR/SOC analyst workstation** for local artifact inspection, heterogeneous telemetry analysis, evidence-driven detections, investigation continuity, incident handling and reporting.

The core product remains static-hosting friendly and browser-local: no mandatory backend, account, telemetry collector, paid dependency or hidden analytics service is required.

> DolosBlackMagic is analyst-assistance software. It is not an antivirus, EDR, malware sandbox, exploit framework, full SIEM backend, or authoritative threat-intelligence verdict engine.

## v0.9 — Detection Integration

v0.9 turns Detection Engine v3 from an isolated capability into part of the canonical telemetry workflow.

### Added / improved

- automatic Detection Engine v3 evaluation for fresh, streamed and reopened telemetry;
- merged BlackLog + v3 finding pipeline with stable source-engine metadata;
- evidence references linked back to contributing normalized events;
- finding classification into informational, suspicious, correlated and high-confidence analyst signals;
- safer grouped correlation behavior when required entity keys are missing;
- repeated-stage sequence semantics so “success after repeated failures” requires an actual failure burst;
- additional defensive correlations for authentication spray, service-install/process sequences, firewall multi-port activity, administrative-service sweeps and repeated web authentication denial patterns;
- v0.8 IndexedDB Dataset Vault retained as the explicit opt-in telemetry persistence layer;
- static/PWA integrity now requires the detection integration asset.

## Workstation map

| Workspace | Analyst purpose | Key capabilities |
|---|---|---|
| **Overview** | Workspace state | local workspace pulse and quick actions |
| **Artifact Analysis** | Inspect evidence | hashes, signatures, strings, entropy, IOC extraction |
| **Event Explorer / BlackLog** | Analyze telemetry | parsing, normalization, streaming, filtering, evidence inspection |
| **Detection Studio** | Engineer rules | lifecycle, testing, safe regex, Sigma-like/Wazuh import |
| **SOC Operations** | Triage | findings, suppression, incidents, entity correlation |
| **Investigation Graph** | Explore relationships | hosts, users, IPs, processes, domains, URLs, hashes |
| **Case Timeline** | Order evidence | telemetry and analyst chronology |
| **Investigations** | Preserve context | notes, bookmarks, findings, entities, Dataset Vault |
| **Reports** | Handoff | Markdown, JSON and print/PDF-ready output |

## Architecture

```text
Local artifact / telemetry
          │
          ▼
Parse / Normalize / Provenance
          │
          ├──────────────► BlackLog built-in detections
          │
          └──────────────► Detection Engine v3
                                │
                                ▼
                    Canonical finding pipeline
                                │
                 Evidence IDs · confidence · MITRE
                                │
                                ▼
                 Investigation → Incident → Report
                                │
                                ▼
                 Optional IndexedDB Dataset Vault
```

The application intentionally keeps the older workstation engines as compatibility layers while stable cross-workspace behavior is consolidated under `site/platform/` modules.

## Log intelligence

Supported ingestion paths include JSON, NDJSON/JSONL, CSV, syslog-style text, CEF/LEEF, key/value telemetry and generic plaintext. Unknown records degrade gracefully rather than being silently dropped.

Line-oriented large files use bounded `Blob.slice()` chunks plus a Web Worker. JSON/CSV compatibility paths remain bounded where parser semantics require full-file context.

## Detection model

Detection content is defensive and rule-based. Findings include severity, confidence, explanation, evidence references, ATT&CK context, remediation guidance and false-positive context where available.

Detection Engine v3 supports:

- nested `all` / `any` / `not` conditions;
- equality, contains, prefix/suffix, membership and numeric comparisons;
- browser-safe regex validation;
- grouped thresholds and distinct counts;
- bounded time windows;
- ordered sequences with repeated-stage counts.

A finding is not automatically a malicious verdict. Analyst validation remains required.

## Local Dataset Vault

Telemetry persistence is **opt-in**. Selected datasets can be saved locally in IndexedDB and reopened later.

Safety controls include:

- 50,000-event maximum per saved collection;
- approximately 24 MB serialized-size bound;
- sanitized normalized events rather than arbitrary raw objects;
- bounded raw previews and long fields;
- portable JSON export/import with schema validation and re-sanitization;
- browser quota/usage visibility where supported;
- no network upload.

## Privacy & security

- no mandatory backend or account;
- no third-party analytics;
- no automatic sample/hash/IOC submission;
- uploaded artifacts are not executed;
- imported rules remain declarative data;
- no `eval()` or `new Function()` detection execution;
- custom regex receives browser safety validation;
- IndexedDB persistence is explicit and browser-local;
- Netlify deployment includes CSP and restrictive browser-security headers.

## Run locally

```bash
python3 -m http.server 8080 -d site
```

Open `http://127.0.0.1:8080`.

## Test

Node.js 24+ is required. Runtime npm dependencies are not required.

```bash
npm test
```

The quality gate covers artifact analysis, parsing/normalization, detections/correlation, SOC state, operations, regex safety, investigation behavior, streaming protocol, Dataset Vault behavior, JavaScript syntax and static/PWA deployment integrity.

## Deploy

### GitHub Pages

`.github/workflows/pages.yml` runs `npm test` before publishing `site/`.

Live: **https://shalvalekishvili.github.io/DolosBlackMagic/**

### Netlify

`netlify.toml` publishes `site/` and applies CSP plus browser security/privacy headers.

---

# 🇬🇪 ქართული განმარტება

## რა არის DolosBlackMagic?

**DolosBlackMagic 0.9.0** არის local-first ტიპის, ბრაუზერზე დაფუძნებული **DFIR / SOC ანალიტიკოსის სამუშაო გარემო**. პროექტი აერთიანებს არტეფაქტების ანალიზს, სხვადასხვა ტიპის ლოგების დამუშავებას, detection engineering-ს, evidence provenance-ს, investigation-ს, incident workflow-სა და ანგარიშგებას.

მთავარი პრინციპია **კონფიდენციალურობა და ლოკალური დამუშავება** — core ფუნქციონალს არ სჭირდება სავალდებულო cloud backend, ანგარიში, analytics ან ფასიანი API.

## რა შეიცვალა v0.9-ში?

v0.9-ის მთავარი ცვლილებაა **Detection Integration**. Detection Engine v3 ახლა აღარ არის იზოლირებული მოდული — ის ავტომატურად მონაწილეობს telemetry-ის canonical analysis flow-ში.

ახალი pipeline:

```text
ლოგი / telemetry
      ↓
parse + normalize
      ↓
BlackLog detections + Detection Engine v3
      ↓
ერთიანი findings
      ↓
evidence + confidence + MITRE
      ↓
investigation / incident / report
```

### კორელაციები

v0.9-ში გაუმჯობესებულია defensive correlation logic, მათ შორის:

- authentication spray;
- repeated failures → successful authentication;
- service installation → process execution;
- firewall multi-port activity;
- administrative service sweep;
- web authentication abuse patterns.

Missing group field-ის მქონე unrelated event-ები აღარ ერთიანდება ერთ საერთო correlation bucket-ში. Success-after-failure sequence-იც ახლა რეალურად მოითხოვს განმეორებით failure-ებს success-მდე.

## Local Dataset Vault

v0.8-ში დამატებული Dataset Vault შენარჩუნებულია და v0.9-ში სრულად ინტეგრირებულია analyst workflow-ში.

შეგიძლია:

- მიმდინარე telemetry შეინახო IndexedDB-ში;
- მოგვიანებით ისევ გახსნა Event Explorer-ში;
- export/import გააკეთო JSON ფაილად;
- imported dataset schema validation და sanitization გაიაროს;
- browser storage quota ნახო, თუ browser მხარს უჭერს.

შენახვა **არ ხდება ავტომატურად**.

## უსაფრთხოება

DolosBlackMagic:

- არ ასრულებს ატვირთულ ფაილებს;
- არ აგზავნის telemetry-ს მესამე მხარეს;
- არ იყენებს `eval()`-ს ან `new Function()`-ს detection rule-ებისთვის;
- imported detection content-ს data-დ განიხილავს;
- regex rules-ს უსაფრთხოების validation-ს უკეთებს;
- IndexedDB-ში მხოლოდ bounded და sanitized მონაცემებს ინახავს.

## ლოკალურად გაშვება

```bash
python3 -m http.server 8080 -d site
```

შემდეგ გახსენი `http://127.0.0.1:8080`.

## ტესტირება

```bash
npm test
```

საჭიროა **Node.js 24+**.

## Project structure

```text
DolosBlackMagic/
├── site/
│   ├── platform/
│   │   ├── app-bus.js
│   │   ├── investigation-engine.js
│   │   ├── detection-v3.js
│   │   ├── detection-pipeline.js
│   │   ├── workspace-store.js
│   │   ├── log-stream-client.js
│   │   ├── log-stream-worker.js
│   │   ├── event-explorer-v2.js
│   │   ├── investigation-ui.js
│   │   └── dataset-vault-ui.js
│   ├── core.js
│   ├── log-engine.js
│   ├── soc-engine.js
│   ├── ops-engine.js
│   └── sw.js
├── tests/
├── docs/
├── scripts/check-static.mjs
├── .github/workflows/
├── netlify.toml
└── package.json
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Detections](docs/DETECTIONS.md)
- [Log formats](docs/LOG_FORMATS.md)
- [Privacy](docs/PRIVACY.md)
- [Security](docs/SECURITY.md)
- [Testing](docs/TESTING.md)
- [v0.8 release](docs/V0.8.md)
- [v0.9 release](docs/V0.9.md)

## License

MIT
