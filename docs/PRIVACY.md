# Privacy

DolosBlackMagic is designed to work without an account, analytics service, mandatory API, or application backend.

## What stays local

Artifact bytes, pasted telemetry, imported logs, custom rules, triage state, incidents, saved views, suppression rules and workspace settings are processed in the browser. The core application does not upload this data.

Browser-local state uses DolosBlackMagic namespaces in LocalStorage. Log collections are currently memory-resident and are not automatically persisted. Workspace backups occur only when the analyst explicitly exports a JSON file.

## Exports

JSON, CSV, Markdown, printable reports and workspace snapshots are created locally. A workspace snapshot contains version metadata and only DolosBlackMagic-owned storage keys. Restore rejects foreign keys instead of blindly writing arbitrary LocalStorage content.

## Browser boundary

The browser profile, installed extensions, operating system and endpoint management are outside the application boundary. Highly sensitive investigations should be performed on a trusted managed endpoint/profile. Clearing browser storage can remove locally stored analyst state unless a workspace export exists.

## Network behavior

The application is self-contained. The service worker only handles same-origin application requests. There is no hidden telemetry or third-party tracking in the core product.
