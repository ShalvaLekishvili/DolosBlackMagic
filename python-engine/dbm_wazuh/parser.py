from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable


@dataclass(slots=True)
class ParseStats:
    total_records: int = 0
    parsed: int = 0
    partial: int = 0
    malformed: int = 0
    unsupported: int = 0
    dropped: int = 0
    wrappers: dict[str, int] = field(default_factory=dict)

    def mark_wrapper(self, name: str) -> None:
        self.wrappers[name] = self.wrappers.get(name, 0) + 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "totalRecords": self.total_records,
            "parsed": self.parsed,
            "partial": self.partial,
            "malformed": self.malformed,
            "unsupported": self.unsupported,
            "dropped": self.dropped,
            "wrappers": self.wrappers,
        }


def _unwrap_hit(value: Any) -> Any:
    if isinstance(value, dict) and isinstance(value.get("_source"), dict):
        source = dict(value["_source"])
        source["__index"] = value.get("_index", "")
        source["__document_id"] = value.get("_id", "")
        source["__sort"] = value.get("sort")
        return source
    return value


def _extract_container(value: Any) -> tuple[list[Any], str]:
    if isinstance(value, list):
        return [_unwrap_hit(v) for v in value], "array"
    if not isinstance(value, dict):
        return [value], "scalar"
    hits = value.get("hits")
    if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
        return [_unwrap_hit(v) for v in hits["hits"]], "opensearch-hits"
    data = value.get("data")
    if isinstance(data, dict):
        for key in ("affected_items", "items", "alerts"):
            if isinstance(data.get(key), list):
                return [_unwrap_hit(v) for v in data[key]], f"wazuh-api-{key}"
    for key in ("affected_items", "alerts", "items"):
        if isinstance(value.get(key), list):
            return [_unwrap_hit(v) for v in value[key]], key
    if isinstance(value.get("_source"), dict):
        return [_unwrap_hit(value)], "opensearch-source"
    return [value], "object"


def _safe_json(line: str) -> tuple[Any | None, str | None]:
    try:
        return json.loads(line), None
    except json.JSONDecodeError as exc:
        return None, f"JSON decode error at column {exc.colno}: {exc.msg}"


def parse_payload(payload: str | bytes) -> tuple[list[dict[str, Any]], ParseStats, list[dict[str, Any]]]:
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    text = str(payload).lstrip("\ufeff")
    stats = ParseStats()
    errors: list[dict[str, Any]] = []
    if not text.strip():
        return [], stats, errors

    records: list[Any] = []
    try:
        parsed = json.loads(text)
        extracted, wrapper = _extract_container(parsed)
        stats.mark_wrapper(wrapper)
        records.extend(extracted)
    except json.JSONDecodeError:
        stats.mark_wrapper("ndjson")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            value, error = _safe_json(line)
            if error:
                stats.total_records += 1
                stats.malformed += 1
                errors.append({"record": line_no, "reason": error, "preview": line[:500]})
                # Preserve malformed input as a generic event rather than silently dropping it.
                records.append({"message": line, "__parse_error": error, "__line": line_no})
                continue
            extracted, wrapper = _extract_container(value)
            stats.mark_wrapper(wrapper)
            records.extend(extracted)

    output: list[dict[str, Any]] = []
    for idx, record in enumerate(records, start=1):
        # malformed NDJSON records were counted above already
        if not (isinstance(record, dict) and "__parse_error" in record):
            stats.total_records += 1
        if isinstance(record, dict):
            output.append(record)
            if record.get("__parse_error"):
                stats.partial += 1
            else:
                stats.parsed += 1
        else:
            stats.unsupported += 1
            output.append({"message": str(record), "__unsupported_type": type(record).__name__, "__record": idx})
            stats.partial += 1
    return output, stats, errors


def parse_timestamp(value: Any) -> tuple[str, bool]:
    if value in (None, ""):
        return "", False
    raw = str(value).strip()
    normalized = raw
    # Python's fromisoformat accepts +04:00 but not +0400 consistently across older versions.
    if len(raw) >= 5 and raw[-5] in "+-" and raw[-3] != ":":
        normalized = raw[:-2] + ":" + raw[-2:]
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
        return dt.isoformat(), True
    except ValueError:
        return raw, False
