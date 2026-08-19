from __future__ import annotations

from collections import Counter
from typing import Any

from .parser import parse_payload
from .normalize import normalize_record
from .detections import analyze_detections


class WazuhAnalysisEngine:
    VERSION = "1.0.0"

    def analyze(self, payload: str | bytes) -> dict[str, Any]:
        records, stats, errors = parse_payload(payload)
        events = [normalize_record(record, i) for i, record in enumerate(records, start=1)]
        findings = analyze_detections(events)

        family_counts = Counter(e.get("family", "unknown") for e in events)
        source_counts = Counter(e.get("source", "unknown") for e in events)
        host_counts = Counter(e.get("host") or "unknown" for e in events)
        severity_counts = Counter(f.get("severity", "informational") for f in findings)
        rule_counts = Counter(f.get("ruleId", "unknown") for f in findings)
        data_quality = Counter(flag for e in events for flag in e.get("quality", []))

        return {
            "engine": {
                "name": "DolosBlackMagic Python Wazuh Engine",
                "version": self.VERSION,
                "mode": "local-first",
            },
            "events": events,
            "findings": findings,
            "summary": {
                "total": len(events),
                "findings": len(findings),
                "findingSeverity": dict(severity_counts),
                "families": dict(family_counts),
                "sources": dict(source_counts),
                "topHosts": host_counts.most_common(15),
                "topDetections": rule_counts.most_common(15),
                "parse": stats.as_dict(),
                "dataQuality": dict(data_quality),
                "parserErrors": errors[:100],
            },
        }
