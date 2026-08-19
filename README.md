<div align="center">

<img src="docs/assets/dolosblackmagic-readme-banner.svg" alt="DolosBlackMagic — Local-first DFIR and SOC workbench" width="100%" />

# DolosBlackMagic

**Local-first browser DFIR · Log Intelligence · Detection Engineering · Investigation · SOC Operations**

[![Version](https://img.shields.io/badge/version-0.6.0-2b3645?style=flat-square)](package.json)
[![Node](https://img.shields.io/badge/Node.js-%3E%3D24-2b3645?style=flat-square)](package.json)
[![CI](https://img.shields.io/github/actions/workflow/status/ShalvaLekishvili/DolosBlackMagic/ci.yml?branch=main&style=flat-square&label=CI)](.github/workflows/ci.yml)
[![Pages](https://img.shields.io/badge/GitHub%20Pages-live-2b3645?style=flat-square)](https://shalvalekishvili.github.io/DolosBlackMagic/)
[![License](https://img.shields.io/badge/license-MIT-2b3645?style=flat-square)](LICENSE)

**[Live Application](https://shalvalekishvili.github.io/DolosBlackMagic/)** · **[ქართული განმარტება](#-ქართული-განმარტება)** · **[Architecture](docs/ARCHITECTURE.md)** · **[Security](docs/SECURITY.md)** · **[v0.6 Release](docs/V0.6.md)**

</div>

---

## What is DolosBlackMagic?

DolosBlackMagic 0.6.0 is a **privacy-first, browser-based DFIR/SOC analyst workstation** for local artifact inspection, heterogeneous log normalization, evidence-driven detections, investigation correlation, incident handling and reporting. It remains lightweight and static-hosting friendly: core analysis happens in the browser and no mandatory cloud backend, account, telemetry or analytics service is required.

> DolosBlackMagic is analyst-assistance software — not an antivirus, EDR, malware sandbox, full SIEM backend, exploit framework or authoritative threat-intelligence verdict system.

## Workstation map

| Workspace | Analyst purpose | Key capabilities |
|---|---|---|
| **Overview** | Current workspace state | investigation pulse, quick actions, local state |
| **Artifact Analysis** | Inspect local evidence | hashes, signatures, entropy, strings, IOC extraction, heuristic context |
| **Event Explorer / BlackLog** | Analyze telemetry | content-based parsing, normalization, filtering, data-quality accounting |
| **Detection Studio** | Engineer rules | lifecycle, testing, safe regex, Sigma-like and Wazuh imports |
| **SOC Operations** | Triage and organize | findings, suppression, incidents, entity correlation, snapshots |
| **Investigation Graph** | Explore relationships | hosts, users, IPs, processes, domains, URLs, hashes, findings |
| **Case Timeline** | Order evidence | normalized event chronology and investigation context |
| **Indicators** | Review IOCs | extraction and defanging |
| **Investigations** | Preserve local cases | browser-local analyst workflow |
| **Reports** | Handoff findings | Markdown, JSON and print/PDF-ready output |

## v0.6 workstation release

0.6.0 stabilizes the current workstation generation. It includes the premium SOC/DFIR visual layer, analyst-oriented overview, background Web Worker analysis for larger log payloads, cancellable analysis, bounded event rendering, debounced filtering, stronger deployment integrity and a bilingual project landing page.

The release also removes an important consistency problem: `package.json` is now the canonical release source used by static integrity checks, while PWA and README release references are validated against it. See [`docs/V0.6.md`](docs/V0.6.md).

## Architecture at a glance

```text
Local artifact / log / text
          │
          ▼
┌──────────────────────────────┐
│   Browser analyst workspace  │
│ Artifact · Events · SOC Ops  │
└──────────────┬───────────────┘
               │
      ┌────────▼────────┐
      │ Analysis engines│
      │ Core / BlackLog │
      │ SOC / Operations│
      └────────┬────────┘
               │
      Findings + Evidence
               │
 Investigation → Incident → Report

No mandatory backend · No telemetry · No automatic sample upload
```

For large pasted telemetry, Event Explorer can move analysis to `log-worker.js`, keeping the main UI responsive. The current worker is a background full-payload analyzer; true chunked/streaming file ingestion is a v0.7 engineering target and is not overclaimed here.

## BlackLog ingestion

Content heuristics are used in addition to file extensions. Supported or best-effort telemetry includes JSON, NDJSON/JSONL, CSV, RFC3164/RFC5424 Syslog, CEF, LEEF, `key=value`, Windows-style events, Wazuh-style JSON, Linux authentication, firewall/network logs, common web access logs and generic plaintext.

The parser tracks `total → parsed → partial → malformed → dropped`, with a design goal of **zero silent drops**. Unknown telemetry is preserved where safe and clearly classified instead of being silently discarded.

## Detection engineering

Built-in defensive rules cover Windows/Sysmon, Linux authentication, network/firewall and common web-abuse patterns. Findings can carry severity, confidence, MITRE ATT&CK context, firing explanation, evidence, remediation guidance and false-positive notes. A heuristic match is not treated as a confirmed malicious verdict.

Detection Studio keeps custom rules declarative. Rules are never executed as JavaScript and the project does not use `eval()` or `new Function()` for detection logic. Sigma-like YAML and Wazuh XML importers expose unsupported or partial translation instead of silently changing rule meaning.

## Privacy & security model

- no mandatory account or backend;
- no analytics or hidden telemetry;
- no automatic hash/IP/domain/file submission;
- uploaded artifacts are not executed;
- imported rules remain data;
- browser-local analyst state can be explicitly exported/restored;
- Netlify deployment includes CSP and baseline privacy/security headers.

The browser profile and endpoint remain part of the trust boundary.

---

# 🇬🇪 ქართული განმარტება

## რა არის DolosBlackMagic?

**DolosBlackMagic 0.6.0** არის ბრაუზერზე დაფუძნებული, local-first ტიპის **DFIR / SOC ანალიტიკოსის სამუშაო გარემო**. მისი მიზანია ერთ სივრცეში გააერთიანოს არტეფაქტის ანალიზი, სხვადასხვა ტიპის ლოგების დამუშავება, დეტექციები, evidence, IOC-ები, entity correlation, ინციდენტები და ანგარიშგება.

პროექტის მთავარი პრინციპია **კონფიდენციალურობა და ლოკალური დამუშავება**: ჩვეულებრივ სამუშაო პროცესში უსაფრთხოების მონაცემები არ საჭიროებს სავალდებულო cloud backend-ზე ატვირთვას. ძირითადი ანალიზი მომხმარებლის ბრაუზერში სრულდება.

### ძირითადი შესაძლებლობები

**Artifact Analysis** — SHA-256/SHA-1, ფაილის signature, entropy, printable strings, IOC extraction/defanging, heuristic behavior context, timeline/graph და ანგარიშის მომზადება.

**BlackLog / Event Explorer** — JSON, NDJSON, CSV, Syslog, CEF, LEEF, key=value, Wazuh, Windows, Linux, firewall, web-access და generic plaintext ლოგების best-effort ამოცნობა, normalization, ძებნა და filtering. malformed ჩანაწერები შეძლებისდაგვარად ინახება და parse quality ცალკე ჩანს.

**Detection Studio** — defensive detection rule-ების შექმნა, ტესტირება და lifecycle მართვა. მხარდაჭერილია safe regex validation და Sigma-like/Wazuh import-ის ნაწილობრივი თარგმნის მკაფიო ანგარიში. წესები JavaScript კოდად არ სრულდება.

**SOC Operations** — finding triage, suppression/deduplication, incident workflow, entity correlation, data-quality context და workspace snapshot export/restore.

**Investigation workflow** — ანალიტიკოსს შეუძლია artifact/log evidence-ის დალაგება, IOC-ზე pivot, finding-ის evidence-ის ნახვა, incident-ის შექმნა და Markdown/JSON/Print-PDF ანგარიშის მომზადება.

### v0.6-ში რა შეიცვალა?

v0.6 არის workstation თაობის სტაბილიზებული release: გაუმჯობესებულია პროფესიონალური SOC/DFIR ინტერფეისი, Overview, დიდი log payload-ის background Web Worker analysis, cancellation, bounded rendering, debounced filtering, PWA/static integrity და GitHub README. release metadata ახლა `package.json`-ის ვერსიას ეყრდნობა და integrity test ამოწმებს, რომ README/PWA მას არ აცდეს.

### რას არ წარმოადგენს პროექტი?

DolosBlackMagic **არ არის** ანტივირუსი, EDR, malware sandbox, სრული SIEM backend ან exploit framework. დეტექციები არის ანალიტიკოსის დამხმარე წესები და ჰეურისტიკები; საბოლოო შეფასება ყოველთვის evidence-სა და გარემოს კონტექსტს უნდა დაეყრდნოს.

### უსაფრთხოება და კონფიდენციალურობა

პროექტი არ აგზავნის ლოგებს, ფაილებს, hash-ებს, IP-ებს ან domain-ებს მესამე მხარეს ავტომატურად. არ არის სავალდებულო account, analytics ან telemetry. მიუხედავად ამისა, browser profile და endpoint თვითონაც უსაფრთხოების საზღვრის ნაწილია, ამიტომ მგრძნობიარე გამოძიებისთვის გამოყენებული გარემო სანდო უნდა იყოს.

---

## Run locally

Requires **Node.js 24+** for tests. Runtime itself is static browser content.

```bash
python3 -m http.server 8080 -d site
```

Open `http://127.0.0.1:8080`.

## Test

```bash
npm test
```

The regression entry point covers artifact analysis, log parsing/normalization, detections/correlation, SOC persistence, operations/workspace validation, regex safety and static deployment integrity.

## Deploy

### GitHub Pages

`.github/workflows/pages.yml` runs the regression suite before deploying `site/`. Relative asset paths keep the application compatible with `/DolosBlackMagic/`.

### Netlify

`netlify.toml` publishes `site/` and applies CSP plus baseline security/privacy headers.

## Project structure

```text
DolosBlackMagic/
├── site/
│   ├── index.html
│   ├── app.css / log.css / soc.css / ops.css
│   ├── v05.css / v06-ui.css
│   ├── core.js / app.js
│   ├── log-engine.js / log-ui.js / log-worker.js
│   ├── soc-engine.js / soc-ui.js / soc-v05-ui.js
│   ├── ops-engine.js / ops-ui.js
│   ├── security-runtime.js / ui-hardening.js
│   ├── dashboard-v06.js / log-normalize-fixes.js
│   └── manifest.webmanifest / sw.js / favicon.svg
├── tests/
├── scripts/check-static.mjs
├── docs/
├── .github/workflows/
├── netlify.toml
└── package.json
```

Version-specific enhancement files are still present in 0.6.0. They are being consolidated incrementally rather than removed through a risky rewrite.

## Documentation

- [`ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`LOG_FORMATS.md`](docs/LOG_FORMATS.md)
- [`DETECTIONS.md`](docs/DETECTIONS.md)
- [`SECURITY.md`](docs/SECURITY.md)
- [`PRIVACY.md`](docs/PRIVACY.md)
- [`TESTING.md`](docs/TESTING.md)
- [`V0.6.md`](docs/V0.6.md)

## License

MIT
