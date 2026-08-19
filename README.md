<div align="center">

<img src="docs/assets/dolosblackmagic-readme-banner.svg" alt="DolosBlackMagic — Local-first DFIR and SOC workbench" width="100%" />

# DolosBlackMagic

**Local-first browser DFIR · Log Intelligence · Detection Engineering · Evidence · Investigation · SOC Operations**

[![Version](https://img.shields.io/badge/version-0.7.0-2b3645?style=flat-square)](package.json)
[![Node](https://img.shields.io/badge/Node.js-%3E%3D24-2b3645?style=flat-square)](package.json)
[![CI](https://img.shields.io/github/actions/workflow/status/ShalvaLekishvili/DolosBlackMagic/ci.yml?branch=main&style=flat-square&label=CI)](.github/workflows/ci.yml)
[![Pages](https://img.shields.io/badge/GitHub%20Pages-live-2b3645?style=flat-square)](https://shalvalekishvili.github.io/DolosBlackMagic/)
[![License](https://img.shields.io/badge/license-MIT-2b3645?style=flat-square)](LICENSE)

**[Live Application](https://shalvalekishvili.github.io/DolosBlackMagic/)** · **[ქართული განმარტება](#-ქართული-განმარტება)** · **[Architecture](docs/ARCHITECTURE.md)** · **[Security](docs/SECURITY.md)** · **[v0.7 Release](docs/V0.7.md)**

</div>

---

## What is DolosBlackMagic?

DolosBlackMagic 0.7.0 is a **privacy-first, browser-based DFIR/SOC analyst workstation** for local artifact inspection, heterogeneous telemetry analysis, evidence-driven detections, investigation continuity, incident handling and reporting.

Core analysis remains local to the browser. The project does **not** require a mandatory backend, account, telemetry service, analytics platform or paid dependency.

> DolosBlackMagic is analyst-assistance software. It is not an antivirus, EDR, malware sandbox, full SIEM backend, exploit framework or authoritative threat-intelligence verdict engine.

## v0.7 — Analyst Data Platform

v0.7 moves the product beyond isolated workspaces and focuses on **data scale, evidence provenance and investigation continuity**.

### Added in v0.7

- chunked `File`/`Blob` ingestion using bounded slices instead of `File.text()` for streamed file analysis;
- explicit worker protocol: `START → CHUNK → PROGRESS → PARTIAL_RESULT → COMPLETE / CANCEL / ERROR`;
- UTF-8-safe `TextDecoder` chunk reconstruction and line-boundary carry handling;
- stable evidence references such as `EVT-0000124` for streamed events;
- evidence provenance: source file, record index, line number when known, parser and raw preview;
- first-class investigation model with data sources, bookmarks, findings, entities, notes, actions and timeline state;
- Event Explorer evidence drawer with normalized/raw comparison and analyst bookmarks;
- query history chips and keyboard-accessible event inspection;
- Detection Engine v3 primitives for nested conditions, grouped thresholds, distinct counts and bounded sequences;
- defensive correlation examples for authentication spray, success-after-failure and service-install/process sequences;
- versioned investigation snapshots with schema validation;
- centralized dependency-free application event bus and deterministic v0.7 bootstrap boundary.

## Workstation map

| Workspace | Analyst purpose | Key capabilities |
|---|---|---|
| **Overview** | Current workspace state | local workspace pulse and quick actions |
| **Artifact Analysis** | Inspect local evidence | hashes, signatures, entropy, strings, IOC extraction, heuristic context |
| **Event Explorer / BlackLog** | Analyze telemetry | parsing, streaming ingestion, normalization, filters, evidence drawer |
| **Detection Studio** | Engineer rules | lifecycle, testing, safe regex, Sigma-like and Wazuh imports |
| **SOC Operations** | Triage and organize | findings, suppression, incidents, entity correlation, snapshots |
| **Investigation Graph** | Explore relationships | hosts, users, IPs, processes, domains, URLs, hashes and findings |
| **Case Timeline** | Order evidence | source telemetry and investigation chronology |
| **Indicators** | Review IOCs | extraction, defanging and pivots |
| **Investigations** | Preserve analyst context | browser-local cases plus v0.7 evidence bookmarks |
| **Reports** | Handoff findings | Markdown, JSON and print/PDF-ready output |

## Architecture at a glance

```text
Local artifact / file / log / text
              │
              ▼
┌────────────────────────────────────┐
│        Browser analyst shell       │
│ Artifact · Events · Detection · SOC│
└───────────────┬────────────────────┘
                │
       ┌────────▼─────────┐
       │ v0.7 Platform API│
       │ Event bus        │
       │ Investigations   │
       │ Detection v3     │
       │ Streaming client │
       └───────┬──────────┘
               │
     ┌─────────▼───────────┐
     │ Chunked log worker  │
     │ parse → normalize   │
     │ detect → correlate  │
     │ provenance          │
     └─────────┬───────────┘
               │
     Findings + Evidence IDs
               │
 Investigation → Incident → Report

No mandatory backend · No analytics · No automatic sample upload
```

The legacy v0.6 engines remain a compatibility layer while stable capabilities are progressively consolidated into semantic `site/platform/` modules. This avoids a risky rewrite while reducing future patch stacking.

## Large telemetry processing

For file ingestion, the v0.7 streaming client reads bounded `Blob.slice()` chunks and sends decoded text incrementally to a dedicated worker. The worker reconstructs line boundaries, analyzes batches and emits measurable progress based on bytes and records processed.

Cancellation terminates the active analysis and **does not commit an unfinished investigation result**.

Current streamed event retention is intentionally bounded. DolosBlackMagic does not automatically persist entire imported security log files into browser storage.

## Evidence provenance

Streamed events can carry deterministic investigation-local references:

```text
EVT-0000124
sourceFile: security.jsonl
recordIndex: 124
lineNumber: 124
parser: ndjson
rawPreview: ...
```

Byte ranges are only populated when accurately available; DolosBlackMagic does not fabricate offsets.

Evidence can be bookmarked into the active investigation and is then retained as a compact subset containing normalized context plus provenance, rather than silently persisting the complete telemetry source.

## Detection Engine v3

The v0.7 platform adds declarative correlation primitives without executing user JavaScript.

Supported concepts include:

- nested `all` / `any` / `not` conditions;
- equals / not-equals / contains / prefix / suffix;
- safe regex validation;
- numeric comparisons;
- grouped thresholds;
- time windows;
- distinct-value counts;
- bounded multi-stage sequences.

Example defensive correlations include:

```text
same source IP
  → repeated authentication failures
  → >= 3 distinct usernames
  → within 3 minutes
```

and:

```text
failed authentication
  → successful authentication
  → same source
  → bounded time window
```

Findings remain analyst-assistance signals and should be validated against environment context.

## Privacy & security model

- no mandatory backend or user account;
- no third-party analytics;
- no automatic IOC/hash/file submission;
- uploaded artifacts are not executed;
- imported rules remain declarative data;
- no `eval()` or `new Function()` for detection logic;
- custom regex receives browser-safety validation;
- investigation persistence stores compact analyst-selected state rather than entire log files by default;
- Netlify deployment includes CSP and baseline privacy/security headers.

## Run locally

```bash
python3 -m http.server 8080 -d site
```

Open:

```text
http://127.0.0.1:8080
```

## Test

Node.js 24+ is required. Runtime dependencies are not required.

```bash
npm test
```

The regression gate covers artifact analysis, parsing/normalization, detection/correlation, SOC/operations state, regex safety, v0.7 investigation behavior, worker protocol invariants and static/PWA deployment integrity.

## Deploy

### GitHub Pages

`.github/workflows/pages.yml` runs the complete `npm test` gate before publishing `site/`.

**Live:** https://shalvalekishvili.github.io/DolosBlackMagic/

Relative paths keep the project compatible with the `/DolosBlackMagic/` GitHub Pages subpath.

### Netlify

`netlify.toml` publishes `site/` and applies CSP plus browser security/privacy headers.

---

# 🇬🇪 ქართული განმარტება

## რა არის DolosBlackMagic?

**DolosBlackMagic 0.7.0** არის ბრაუზერზე დაფუძნებული, local-first ტიპის **DFIR / SOC ანალიტიკოსის სამუშაო გარემო**. პროექტი აერთიანებს არტეფაქტის ანალიზს, სხვადასხვა ტიპის ლოგების დამუშავებას, დეტექციებს, evidence-ს, IOC-ებს, entity correlation-ს, investigation-ს, incident workflow-სა და ანგარიშგებას.

მთავარი პრინციპი რჩება **მონაცემების ლოკალურად დამუშავება** — უსაფრთხოების ფაილები და ლოგები არ საჭიროებს სავალდებულო cloud backend-ზე ატვირთვას.

## რა შეიცვალა v0.7-ში?

v0.7-ის მთავარი თემა არის **Analyst Data Platform** — ანუ სისტემის ცალკეული მოდულები უფრო მჭიდროდ უკავშირდება ერთმანეთს და evidence-ის წარმოშობა უფრო მკაფიო ხდება.

### დიდი ლოგების chunked დამუშავება

ფაილის ანალიზისას ახალი pipeline აღარ არის დამოკიდებული მხოლოდ მთლიანი ფაილის ერთ დიდ JavaScript string-ად გარდაქმნაზე. ბრაუზერი ფაილს კითხულობს ნაწილებად (`Blob.slice()`), `TextDecoder` ინარჩუნებს UTF-8 სიმბოლოების საზღვრებს, worker კი აღადგენს record/line საზღვრებს.

worker protocol მოიცავს:

```text
START
CHUNK
PROGRESS
PARTIAL_RESULT
COMPLETE
CANCEL
ERROR
```

Progress ეფუძნება რეალურად დამუშავებულ byte-ებსა და record-ებს — fake პროცენტები არ გამოიყენება.

### Evidence Provenance

streamed event-ებს ეძლევა სტაბილური reference, მაგალითად:

```text
EVT-0000124
```

და შესაძლებელია შესაბამისი provenance-ის შენახვა:

- source file;
- record index;
- line number — როდესაც ზუსტად ვიცით;
- parser;
- raw preview.

byte range არ იწერება, თუ მისი ზუსტად დადგენა შეუძლებელია.

### Event Explorer v2

Event row-ის არჩევისას იხსნება evidence drawer, სადაც ჩანს:

- normalized event;
- raw/original preview;
- source metadata;
- parse context;
- related findings;
- evidence bookmark action;
- entity pivot.

bookmarked event ინახება აქტიურ investigation-ში compact evidence-ის სახით და არა მთელი log source-ის ასლად.

### Investigation Model

v0.7-ში investigation გახდა პირველი კლასის ობიექტი და შეუძლია შეინახოს:

- data sources;
- bookmarked evidence;
- findings;
- entities;
- notes;
- timeline;
- analyst actions;
- incident references;
- saved filters.

### Detection Engine v3

დაემატა უფრო ძლიერი declarative correlation logic:

- nested AND / OR / NOT;
- threshold;
- time window;
- group-by;
- distinct count;
- sequence stages;
- safe regex validation.

მაგალითად შესაძლებელია ერთ finding-ად გაერთიანდეს ერთი source IP-დან რამდენიმე სხვადასხვა მომხმარებლის წინააღმდეგ მოკლე დროში განმეორებული failed authentication.

## კონფიდენციალურობა

DolosBlackMagic:

- არ მოითხოვს ანგარიშს;
- არ აგზავნის telemetry-ს analytics პლატფორმაზე;
- ავტომატურად არ აგზავნის hash/IP/domain/file მონაცემებს მესამე მხარეს;
- არ ასრულებს ატვირთულ ფაილებს;
- არ იყენებს `eval()`-ს custom detection logic-ისთვის;
- არ ინახავს მთელ დიდ log file-ს browser storage-ში ავტომატურად.

## ლოკალურად გაშვება

```bash
python3 -m http.server 8080 -d site
```

შემდეგ გახსენი:

```text
http://127.0.0.1:8080
```

## ტესტირება

```bash
npm test
```

საჭიროა Node.js 24 ან უფრო ახალი.

---

## Project structure

```text
DolosBlackMagic/
├── site/
│   ├── platform/
│   │   ├── app-bus.js
│   │   ├── investigation-engine.js
│   │   ├── detection-v3.js
│   │   ├── log-stream-client.js
│   │   ├── log-stream-worker.js
│   │   ├── event-explorer-v2.js
│   │   ├── bootstrap.js
│   │   └── platform.css
│   ├── core.js / app.js
│   ├── log-engine.js / log-ui.js / log-worker.js
│   ├── soc-engine.js / soc-ui.js
│   ├── ops-engine.js / ops-ui.js
│   ├── sw.js / manifest.webmanifest
├── tests/
│   ├── platform.test.mjs
│   ├── streaming.test.mjs
│   └── existing regression suites
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
- [v0.6 release](docs/V0.6.md)
- [v0.7 release](docs/V0.7.md)

## License

MIT
