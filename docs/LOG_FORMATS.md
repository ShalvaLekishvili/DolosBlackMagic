# Log formats and normalization

BlackLog uses content heuristics first and file extensions only as a browser file-picker convenience.

## Supported ingestion modes

- JSON objects, arrays, and common `events` / `data` arrays
- NDJSON / JSONL, including mixed valid and malformed lines
- CSV with quoted values and escaped quotes
- RFC3164-style Syslog
- RFC5424-style Syslog
- CEF
- LEEF
- whitespace-delimited `key=value` telemetry
- generic plaintext fallback

## Parse-quality contract

Every ingestion returns statistics for total records, parsed records, partial records, malformed records, unsupported content, dropped records and parser errors. The design target is **zero silent drops**. When a line cannot be parsed structurally, BlackLog preserves it as a marked record when safe.

The Event Explorer exposes parsed/partial/malformed/dropped counters. Individual normalized events can carry `quality` flags such as `invalid-timestamp`, `missing-timestamp`, `malformed-record`, and `partial-record`.

## Normalized fields

BlackLog attempts to map common vendor and ECS-like names into:

- timestamp and validity
- source/dataset
- host
- event ID
- channel/provider
- severity
- user and domain
- process, parent process, PID and command line
- source/destination IP and port
- protocol
- action/status
- URL, HTTP method and user agent
- hashes
- message
- raw event reference

Unknown telemetry remains in `raw`; semantic meaning is not invented when a field cannot be confidently mapped.

## Known limitations

“Supported” does not mean full vendor schema coverage. Vendor-specific nested structures may remain primarily in `raw` until an adapter is added. CSV delimiter support is currently comma-oriented. CEF/LEEF extensions are handled conservatively and do not implement every escaping rule in every product variant. Very large files are memory-bound because event collections are currently processed in browser memory.
