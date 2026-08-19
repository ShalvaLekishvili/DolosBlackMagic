# Security model

DolosBlackMagic is a static browser application. Its security boundary includes the browser profile and endpoint on which it runs.

## Controls

- Uploaded files are read as bytes/text and are never executed by the application.
- Imported detection content is parsed as data; there is no `eval` or `new Function` rule execution path.
- UI modules escape untrusted telemetry before inserting it into generated HTML.
- Custom regex is validated and guarded against excessive length and common nested/overlapping quantifier patterns before execution.
- Workspace restore validates format/version and only restores DolosBlackMagic-owned storage namespaces.
- Service-worker fetch handling is same-origin only and caches successful responses.
- Netlify configuration supplies CSP, `nosniff`, restrictive referrer/permissions policy, clickjacking protection and no-cache rules for the service worker.
- No analytics, telemetry, remote fonts or mandatory external APIs are used by the core application.

## CSP

Netlify uses `script-src 'self'`, self-only connections/resources and `object-src 'none'`. `style-src 'unsafe-inline'` remains required because graph/risk UI uses runtime inline style values. GitHub Pages does not provide repository-controlled response headers, so the strongest response-header policy is available on Netlify; application code remains self-contained on Pages.

## Regex safety

Regex rules are analyst-controlled and can otherwise create browser denial-of-service risk. `security-runtime.js` rejects patterns over 256 characters and common nested/overlapping quantifier structures, rejects invalid expressions, filters unsafe persisted rules before evaluation and disables unsafe Sigma-imported rules. This is a pragmatic browser guard, not a formal regex complexity proof.

## Reporting a security issue

Do not include sensitive production logs, credentials or malware samples in a public GitHub issue. Reproduce issues with sanitized telemetry whenever possible.
