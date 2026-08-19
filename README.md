<div align="center">

<img src="docs/assets/dolosblackmagic-readme-banner.svg" alt="DolosBlackMagic — Local-first DFIR and SOC workbench" width="100%" />

# DolosBlackMagic

**Local-first browser DFIR · Log Intelligence · Detection Engineering · Investigation · SOC Operations**

[![Version](https://img.shields.io/badge/version-0.5.0-2b3645?style=flat-square)](package.json)
[![Node](https://img.shields.io/badge/Node.js-%3E%3D24-2b3645?style=flat-square)](package.json)
[![CI](https://img.shields.io/github/actions/workflow/status/ShalvaLekishvili/DolosBlackMagic/ci.yml?branch=main&style=flat-square&label=CI)](.github/workflows/ci.yml)
[![Pages](https://img.shields.io/badge/GitHub%20Pages-live-2b3645?style=flat-square)](https://shalvalekishvili.github.io/DolosBlackMagic/)
[![License](https://img.shields.io/badge/license-MIT-2b3645?style=flat-square)](LICENSE)

**[Live Application](https://shalvalekishvili.github.io/DolosBlackMagic/)** · **[ქართული განმარტება](#-ქართული-განმარტება)** · **[Architecture](docs/ARCHITECTURE.md)** · **[Security](docs/SECURITY.md)**

</div>

---

## What is DolosBlackMagic?

DolosBlackMagic is a **privacy-first, browser-based security investigation workbench** designed for analysts who need to inspect artifacts, normalize heterogeneous logs, evaluate rule-based detections, correlate evidence and preserve investigation state without sending data to a mandatory backend.

It is intentionally lightweight and static-hosting friendly. Core analysis happens in the browser, making the project suitable for **GitHub Pages, Netlify and local HTTP hosting**.

> **Important:** DolosBlackMagic is analyst-assistance software. It is not an antivirus, EDR, malware sandbox, full SIEM backend, exploit framework or authoritative threat-intelligence verdict system.

---

## Product map

| Workspace | Purpose | Key capabilities |
|---|---|---|
| **Overview** | Analyst landing workspace | local workspace health, quick actions, investigation status |
| **Artifact Analysis** | Local artifact inspection | SHA-256/SHA-1, signatures, entropy, strings, IOC extraction, behavior heuristics |
| **Event Explorer / BlackLog** | Heterogeneous telemetry analysis | format detection, normalization, search, filtering, data-quality accounting |
| **Detection Studio** | Rule engineering | custom rules, lifecycle, testing, Sigma-like and Wazuh imports |
| **SOC Operations** | Analyst operations | deduplication, suppression, triage, risk context, workspace portability |
| **Investigation Graph** | Relationship analysis | hosts, users, IPs, processes, domains, URLs, hashes and findings |
| **Case Timeline** | Chronological analysis | normalized investigation events and evidence ordering |
| **Indicators** | IOC review | URL, domain, IP, email and hash extraction/defanging |
| **Investigations** | Local case library | browser-local persistence and analyst workflow |
| **Reports** | Case handoff | Markdown, JSON and printable/PDF-ready reporting |

---

## Architecture at a glance

```text
                    ┌──────────────────────────┐
                    │     Browser / Analyst    │
                    └────────────┬─────────────┘
                                 │
                  Local files / logs / text / JSON
                                 │
          ┌──────────────────────▼──────────────────────┐
          │             DolosBlackMagic UI             │
          │  Artifact • Events • Detection • SOC Ops   │
          └──────────────┬───────────────┬──────────────┘
                         │               │
              ┌──────────▼──────┐  ┌────▼─────────────┐
              │ Analysis Engines│  │ Browser Storage  │
              │ Core / BlackLog │  │ Cases / Rules /  │
              │ SOC / Operations│  │ Triage / Views   │
              └──────────┬──────┘  └──────────────────┘
                         │
                 Findings / Evidence
                         │
        ┌────────────────▼────────────────┐
        │ Investigation → Incident → Report│
        └─────────────────────────────────┘

             No mandatory cloud backend
             No analytics / telemetry
             No automatic sample upload
```

The engines and UI are deliberately separated. Imported artifacts and rules are treated as **data**, not executable content.

---

## BlackLog — supported ingestion

DolosBlackMagic uses **content heuristics**, not only file extensions, to classify telemetry.

Supported or best-effort formats include:

- JSON
- NDJSON / JSONL
- CSV
- RFC3164 Syslog
- RFC5424 Syslog
- CEF
- LEEF
- `key=value` telemetry
- Windows-style exported events
- Wazuh-style JSON
- Linux authentication logs
- firewall/network logs
- common web/access logs
- generic plaintext

Unknown or malformed records degrade gracefully where possible. The ingestion pipeline tracks:

`total → parsed → partial → malformed → dropped`

The design goal is **zero silent drops**. Unsupported records should remain visible to the analyst instead of disappearing without explanation.

> “Any log” means broad **best-effort ingestion**. DolosBlackMagic does not claim vendor-perfect semantic support for every proprietary log source.

---

## Detection engineering

Built-in defensive detection content covers practical analyst-assistance patterns across:

**Windows / Sysmon** — failed authentication, suspicious PowerShell, encoded commands, audit clearing, service installation, account/group changes, scheduled tasks, LOLBins, credential-access indicators and process/network telemetry.

**Linux** — SSH authentication abuse, sudo failures, cron persistence indicators and unusual authentication behavior.

**Network / Firewall** — repeated denies, multi-port scanning behavior and suspicious administrative-service activity.

**Web** — SQL injection probes, path traversal and common command/web-shell style probes.

Findings can include:

- severity;
- analyst-friendly confidence;
- MITRE ATT&CK mapping;
- explanation of **why the finding fired**;
- source event references/evidence;
- remediation guidance;
- likely false-positive context.

A heuristic match is not automatically labelled as confirmed malicious activity.

---

## Detection Studio

Custom rules remain declarative data and are never dynamically executed as JavaScript.

Rule lifecycle:

```text
Draft → Test → Enabled → Disabled → Archived
```

Supported condition concepts include:

- equals / not equals
- contains
- starts with / ends with
- regex with browser-safety validation
- existence checks
- numeric comparisons
- membership checks
- NOT logic

Rules can be tested against currently loaded telemetry before they are enabled.

### Sigma-like / Wazuh import

Imports are classified instead of silently changing meaning:

- **fully translated**
- **partially translated**
- **unsupported**
- **invalid**

Imported Sigma-like YAML and Wazuh XML are parsed as data. Unsupported constructs are surfaced to the analyst.

---

## Privacy model

DolosBlackMagic is intentionally **local-first**.

- No mandatory user account
- No mandatory backend
- No third-party analytics
- No telemetry collection
- No hidden file upload
- No automatic threat-intelligence submission
- Uploaded artifacts are never executed
- Detection rules are never evaluated with `eval` or `new Function`

Analyst state is stored in browser-controlled storage and can be explicitly exported/restored through the workspace tools.

The browser profile and endpoint remain part of the security boundary. Highly sensitive investigations should be performed in a trusted browser profile on a managed endpoint.

---

# 🇬🇪 ქართული განმარტება

## რა არის DolosBlackMagic?

**DolosBlackMagic** არის ბრაუზერზე დაფუძნებული, local-first ტიპის **DFIR / SOC სამუშაო გარემო**, რომლის მთავარი მიზანია უსაფრთხოების ანალიტიკოსს მისცეს ერთ სივრცეში არტეფაქტების, ლოგების, დეტექციების, IOC-ების, ინციდენტებისა და გამოძიებების დამუშავების შესაძლებლობა.

პროექტის ერთ-ერთი მთავარი პრინციპია **მონაცემების ლოკალურად დამუშავება**. ჩვეულებრივ სამუშაო პროცესში ფაილები და ლოგები არ იგზავნება სავალდებულო cloud backend-ზე — ანალიზის ძირითადი ნაწილი უშუალოდ ბრაუზერში სრულდება.

ეს განსაკუთრებით გამოსადეგია:

- SOC Analyst-ისთვის;
- DFIR გამოძიებებისთვის;
- Wazuh / Sysmon / Windows Event ლოგების საწყისი ანალიზისთვის;
- Detection Engineering სწავლებისა და პრაქტიკისთვის;
- ინციდენტის evidence-ის დასალაგებლად;
- უსაფრთხოების ლაბორატორიული გარემოსთვის;
- მცირე local-first SOC tooling-ისთვის.

### რას **არ** წარმოადგენს პროექტი

DolosBlackMagic არ არის სრული SIEM backend, EDR, ანტივირუსი, malware sandbox ან ავტომატური malware verdict სისტემა. მისი დეტექციები წარმოადგენს **ანალიტიკოსის დამხმარე წესებსა და ჰეურისტიკებს**, ამიტომ საბოლოო გადაწყვეტილება ყოველთვის კონტექსტისა და evidence-ის გადამოწმებას საჭიროებს.

---

## ძირითადი მოდულები

### 1. Artifact Analysis

შეგიძლია ბრაუზერში დაამუშაო ფაილი ან ტექსტური არტეფაქტი და მიიღო:

- SHA-256 / SHA-1 hash;
- ფაილის ტიპის signature კლასიფიკაცია;
- entropy შეფასება;
- printable strings;
- IOC extraction;
- URL/IP/domain/email/hash defanging;
- საეჭვო command/behavior heuristic scoring;
- MITRE ATT&CK hint-ები;
- JSON/NDJSON timeline;
- investigation graph;
- Markdown / JSON / PDF-ready report.

არტეფაქტი **არ სრულდება** და კოდი ავტომატურად არ ეშვება.

### 2. Event Explorer / BlackLog

BlackLog არის heterogeneous log ingestion და normalization engine.

მისი ამოცანაა სხვადასხვა ტიპის ლოგი გადაიყვანოს საერთო schema-ში, რათა შემდეგ შესაძლებელი გახდეს ძებნა, filtering, detection და correlation.

სისტემა ცდილობს ამოიცნოს და დაამუშაოს:

`JSON · NDJSON · CSV · Syslog · CEF · LEEF · key=value · Windows/Wazuh-style telemetry · Linux auth · firewall · web logs · plaintext`

არასწორი ჩანაწერის აღმოჩენისას მთელი ფაილი აღარ უნდა ჩავარდეს. parse-quality counters გვაჩვენებს რამდენი ჩანაწერია სრულად დამუშავებული, ნაწილობრივ ნორმალიზებული, malformed ან დაკარგული.

### 3. Detection Studio

Detection Studio-ში შესაძლებელია საკუთარი წესების შექმნა და არსებული telemetry-ის წინააღმდეგ გამოცდა.

Rule lifecycle:

`Draft → Test → Enabled → Disabled → Archived`

მხარდაჭერილია equality, contains, prefix/suffix, regex, existence, numeric comparison და NOT ტიპის პირობები.

Regex წესებზე დამატებულია browser-safety შემოწმება, რათა აშკარად პრობლემურმა expression-მა ინტერფეისი არ დაბლოკოს.

### 4. Alert Triage და Incident Workflow

Finding-ებისთვის შესაძლებელია სტატუსების გამოყენება:

`New · Investigating · Benign · Escalated · Closed`

ასევე ინახება analyst note, status history, disposition და severity override metadata.

Finding-ები და შესაბამისი event-ები შეიძლება გადაიქცეს incident-ად, სადაც ინახება evidence, entities, timeline, MITRE context და analyst notes.

### 5. SOC Operations

Operations workspace გამოიყენება:

- repeated finding deduplication-ისთვის;
- suppression rule-ებისთვის;
- noise reduction-ისთვის;
- data quality health-ისთვის;
- high-interest event enrichment-ისთვის;
- investigation entity correlation-ისთვის;
- workspace backup / restore-ისთვის.

### 6. Investigation Graph

Graph layer აკავშირებს გამოძიებაში მნიშვნელოვან entity-ებს:

`Host ↔ User ↔ IP ↔ Process ↔ Domain ↔ URL ↔ Hash ↔ Finding ↔ Incident`

Graph intentionally bounded არის, რათა დიდი telemetry-ის დროს UI უსარგებლო node clutter-ად არ გადაიქცეს.

---

## უსაფრთხოება და კონფიდენციალურობა

პროექტი შექმნილია privacy-first მიდგომით:

- არ აქვს სავალდებულო backend;
- არ აქვს analytics/tracking;
- არ ითხოვს ანგარიშს;
- არ აგზავნის ფაილებს ავტომატურად გარე API-ზე;
- imported HTML/log content უნდა გამოჩნდეს როგორც ტექსტი და არა executable markup;
- არ გამოიყენება `eval` ან `new Function` imported detection rule-ებისთვის;
- workspace restore მხოლოდ DolosBlackMagic-ის საკუთარ namespace-ებს იღებს;
- Netlify deployment-ზე დამატებულია CSP და browser permission restrictions.

---

## სწრაფი გაშვება

### Local HTTP

```bash
git clone https://github.com/ShalvaLekishvili/DolosBlackMagic.git
cd DolosBlackMagic
npm run serve
```

შემდეგ გახსენი:

```text
http://127.0.0.1:8080
```

Node.js **24 ან უფრო ახალი** ვერსიაა რეკომენდებული ტესტებისთვის.

### ტესტირება

```bash
npm test
```

ტესტები ამოწმებს artifact analysis-ს, log parsers/normalization-ს, detection/correlation-ს, SOC persistence-ს, operations logic-ს, regex safety-სა და static deployment integrity-ს.

---

## Run locally

```bash
git clone https://github.com/ShalvaLekishvili/DolosBlackMagic.git
cd DolosBlackMagic
npm run serve
```

Open:

```text
http://127.0.0.1:8080
```

No npm runtime dependencies are required for the application itself.

---

## Test

Node.js **24+**:

```bash
npm test
```

The regression suite covers:

- artifact analysis;
- malformed and valid log parsing;
- normalization;
- Unicode / Georgian text handling;
- correlation boundaries;
- detection rule lifecycle/imports;
- SOC incident persistence;
- operations/workspace validation;
- regex safety;
- static asset / PWA integrity.

---

## Deployment

### GitHub Pages

The repository includes a Pages workflow that tests the project before deployment.

```text
.github/workflows/pages.yml
```

Production:

**https://shalvalekishvili.github.io/DolosBlackMagic/**

The application uses relative asset paths so the GitHub Pages project subpath `/DolosBlackMagic/` remains supported.

### Netlify

`netlify.toml` publishes the `site/` directory and applies baseline CSP/security/privacy headers.

---

## Repository structure

```text
DolosBlackMagic/
├── site/
│   ├── index.html
│   ├── app.css
│   ├── log.css
│   ├── soc.css
│   ├── ops.css
│   ├── v05.css
│   ├── v06-ui.css
│   ├── core.js
│   ├── log-engine.js
│   ├── soc-engine.js
│   ├── ops-engine.js
│   ├── security-runtime.js
│   ├── app.js
│   ├── log-ui.js
│   ├── soc-ui.js
│   ├── ops-ui.js
│   ├── ui-hardening.js
│   ├── dashboard-v06.js
│   ├── manifest.webmanifest
│   └── sw.js
├── tests/
│   ├── core.test.mjs
│   ├── log-engine.test.mjs
│   ├── soc.test.mjs
│   ├── ops.test.mjs
│   └── security.test.mjs
├── scripts/
│   └── check-static.mjs
├── docs/
│   ├── assets/
│   ├── ARCHITECTURE.md
│   ├── DETECTIONS.md
│   ├── LOG_FORMATS.md
│   ├── PRIVACY.md
│   ├── SECURITY.md
│   ├── TESTING.md
│   └── V0.5.md
├── .github/workflows/
│   ├── ci.yml
│   └── pages.yml
├── netlify.toml
├── package.json
├── LICENSE
└── README.md
```

---

## Professional documentation

| Document | Content |
|---|---|
| [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) | runtime boundaries, engines, storage and state flow |
| [`LOG_FORMATS.md`](docs/LOG_FORMATS.md) | supported log formats and normalization expectations |
| [`DETECTIONS.md`](docs/DETECTIONS.md) | detection model, confidence and analyst guidance |
| [`SECURITY.md`](docs/SECURITY.md) | client-side hardening and trust boundaries |
| [`PRIVACY.md`](docs/PRIVACY.md) | local-first privacy model |
| [`TESTING.md`](docs/TESTING.md) | regression and static integrity testing |
| [`V0.5.md`](docs/V0.5.md) | v0.5 release notes |

---

## Engineering principles

DolosBlackMagic follows a few strict product rules:

**Evidence over visual noise.** Findings should explain why they exist.

**Privacy over unnecessary connectivity.** Local analysis is the default.

**Best-effort parsing over silent loss.** Unknown telemetry should degrade gracefully.

**Detections assist analysts.** Weak heuristics are not presented as confirmed compromise.

**No fake AI.** Deterministic scoring is described as heuristic/risk/correlation scoring.

**No placeholder SOC data.** Empty workspaces stay honestly empty until real telemetry is loaded.

---

## License

Released under the [MIT License](LICENSE).

<div align="center">

### DolosBlackMagic

**Turn artifacts and logs into answers — locally.**

</div>
