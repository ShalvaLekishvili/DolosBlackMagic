# Privacy

DolosBlackMagic is designed to work without an account, analytics service, mandatory API, or application backend.

## What stays local

Artifact bytes, pasted telemetry, imported logs, custom rules, triage state, incidents, saved views, suppression rules and workspace settings are processed in the browser. The core application does not upload this data.

Compact analyst state uses DolosBlackMagic LocalStorage namespaces. Imported telemetry is memory-resident by default. v0.8 adds an **opt-in Local Dataset Vault** backed by IndexedDB so an analyst may explicitly persist selected normalized telemetry in the current browser profile.

The vault never auto-saves imported logs. Before persistence, events are sanitized and long fields/raw previews are bounded. Arbitrary raw objects are not retained.

## Dataset Vault limits

A normal UI save is limited to 50,000 events and approximately 24 MB per dataset. These are product safety bounds rather than browser quota guarantees. The actual quota is controlled by the browser and operating system.

Where available, DolosBlackMagic can display `navigator.storage.estimate()` usage/quota and can request durable storage. The browser may deny that request.

## Exports

JSON, CSV, Markdown, printable reports and workspace snapshots are created locally. Investigation snapshots contain version metadata and only DolosBlackMagic-owned state. Restore validates schema before replacing compatible investigation metadata.

Saved IndexedDB datasets are intentionally separate from investigation JSON snapshots in v0.8; exporting an investigation snapshot does not silently copy large telemetry collections into the exported file.

## Browser boundary

The browser profile, installed extensions, operating system and endpoint management are outside the application boundary. Highly sensitive investigations should be performed on a trusted managed endpoint/profile. Clearing browser storage can remove LocalStorage and IndexedDB analyst data unless relevant exports exist.

## Network behavior

The application is self-contained. Workers, LocalStorage and IndexedDB operate in the same browser origin. The service worker only handles same-origin application requests. There is no hidden telemetry or third-party tracking in the core product.
