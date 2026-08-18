# DolosBlackMagic

**Turn artifacts into answers.** DolosBlackMagic is a local-first browser DFIR and threat investigation workbench designed to run on free static hosting such as GitHub Pages or Netlify.

## What works

- Local file and text intake (20 MB UI limit)
- SHA-256 and SHA-1 via Web Crypto
- PE / ELF / ZIP / Office / PDF / script signature classification
- Shannon entropy and printable-string extraction
- IOC extraction for URLs, domains, IPv4, email addresses and common hashes
- Defanged IOC copy view
- Suspicious command/behavior heuristics with risk score
- MITRE ATT&CK technique hints
- JSON / NDJSON event normalization into a chronological timeline
- Draggable investigation relationship graph (BlackGraph)
- Safe layered Base64 decoder (no payload execution)
- Browser LocalStorage case library (Grimoire)
- Markdown and JSON report export plus Print/Save-as-PDF
- Responsive desktop, tablet and mobile interface
- PWA/service-worker caching
- GitHub Actions CI and GitHub Pages deploy workflow
- Netlify static deployment configuration

## Privacy model

The core app has **no backend**. Artifact bytes are read by the browser and are not uploaded by DolosBlackMagic. Saved investigations use browser LocalStorage. External reputation enrichment is intentionally not claimed in this version.

> Treat the browser itself as part of your security boundary. Do not analyze highly sensitive or dangerous samples in an untrusted browser profile or on an unmanaged endpoint.

## Run locally

No install is required:

```bash
python3 -m http.server 8080 -d site
```

Open `http://127.0.0.1:8080`.

For tests, Node.js 20+ is enough and there are no npm dependencies:

```bash
npm test
```

## Deploy to GitHub Pages

1. Create a public repository named `DolosBlackMagic`.
2. Upload/push the **contents of this folder** to the repository root.
3. Ensure the default branch is `main`.
4. In **Settings → Pages → Build and deployment → Source**, choose **GitHub Actions**.
5. The included `.github/workflows/pages.yml` runs tests and deploys `site/`.

The typical URL will be:

`https://<username>.github.io/DolosBlackMagic/`

## Deploy to Netlify

Import the repository into Netlify. `netlify.toml` already sets the publish directory to `site` and adds baseline security headers.

## Structure

```text
DolosBlackMagic/
├── site/
│   ├── index.html
│   ├── app.css
│   ├── app.js
│   ├── core.js
│   ├── favicon.svg
│   ├── manifest.webmanifest
│   └── sw.js
├── tests/core.test.mjs
├── scripts/check-static.mjs
├── .github/workflows/
│   ├── ci.yml
│   └── pages.yml
├── netlify.toml
├── package.json
├── LICENSE
└── README.md
```

## Security scope

DolosBlackMagic v0.1 is a **static-analysis and investigation-assistance interface**. It does not execute submitted scripts/binaries and should not be treated as a malware sandbox, antivirus engine, EDR, or authoritative threat-intelligence verdict system.

## License

MIT
