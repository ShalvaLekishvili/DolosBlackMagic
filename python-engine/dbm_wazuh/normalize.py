from __future__ import annotations

from copy import deepcopy
from typing import Any

from .parser import parse_timestamp


def get(obj: dict[str, Any], path: str, default: Any = "") -> Any:
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def first(obj: dict[str, Any], *paths: str, default: Any = "") -> Any:
    for path in paths:
        value = get(obj, path, None)
        if value not in (None, ""):
            return value
    return default


def clean(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    return "" if text.lower() in {"-", "n/a", "null", "none", "unknown"} else text


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x) for x in value if x not in (None, "")]
    if value in (None, ""):
        return []
    return [str(value)]


def classify_family(raw: dict[str, Any]) -> str:
    if get(raw, "data.win.system"):
        return "windows-event"
    desc = str(first(raw, "rule.description", "message", "full_log")).lower()
    decoder = str(first(raw, "decoder.name", "decoder.parent")).lower()
    location = str(raw.get("location", "")).lower()
    groups = {x.lower() for x in as_list(get(raw, "rule.groups"))}
    if "agent" in desc and any(token in desc for token in ("stopped", "disconnected", "removed", "started", "connected", "restarted")):
        return "agent-lifecycle"
    if "syscheck" in groups or decoder == "syscheck_integrity_changed" or "integrity" in desc:
        return "fim"
    if {"sshd", "pam", "sudo"} & groups or decoder in {"sshd", "pam", "sudo"}:
        return "linux-auth"
    if "web" in groups or any(x in decoder for x in ("apache", "nginx", "iis")):
        return "web"
    if "firewall" in groups or any(x in decoder for x in ("firewall", "iptables", "fortigate", "paloalto", "cisco")):
        return "network"
    if decoder == "ossec" or location.startswith("wazuh-"):
        return "manager-alert"
    return "wazuh-alert"


def lifecycle_action(raw: dict[str, Any]) -> str:
    hay = " ".join(str(first(raw, "rule.description", "full_log", "message")).lower().split())
    for action in ("disconnected", "reconnected", "restarted", "stopped", "removed", "started", "connected"):
        if f"agent {action}" in hay or f"agent was {action}" in hay:
            return action
    return ""


def _severity_from_level(level: int) -> str:
    if level >= 14:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "informational"


def normalize_record(raw: dict[str, Any], record_index: int) -> dict[str, Any]:
    raw = deepcopy(raw)
    family = classify_family(raw)
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
    manager = raw.get("manager") if isinstance(raw.get("manager"), dict) else {}
    decoder = raw.get("decoder") if isinstance(raw.get("decoder"), dict) else {}
    win_system = get(raw, "data.win.system", {}) or {}
    win_data = get(raw, "data.win.eventdata", {}) or {}

    event_time_raw = first(raw, "data.win.system.systemTime", "@timestamp", "timestamp", "data.timestamp")
    alert_time_raw = first(raw, "timestamp", "@timestamp")
    event_time, event_time_valid = parse_timestamp(event_time_raw)
    alert_time, alert_time_valid = parse_timestamp(alert_time_raw)

    windows_event_id = clean(first(raw, "data.win.system.eventID", "data.win.system.eventId", "data.win.system.event_id"))
    target_user = clean(first(raw, "data.win.eventdata.targetUserName", "data.dstuser", "data.user", "user.name", "username"))
    target_domain = clean(first(raw, "data.win.eventdata.targetDomainName", "data.domain", "user.domain"))
    subject_user = clean(first(raw, "data.win.eventdata.subjectUserName", "data.srcuser"))
    subject_domain = clean(first(raw, "data.win.eventdata.subjectDomainName"))
    user = target_user or clean(first(raw, "data.dstuser", "data.srcuser", "user.name", "username")) or subject_user

    src_ip = clean(first(raw, "data.win.eventdata.ipAddress", "data.srcip", "srcip", "source.ip", "src_ip"))
    src_port = clean(first(raw, "data.win.eventdata.ipPort", "data.srcport", "srcport", "source.port", "src_port"))
    dst_ip = clean(first(raw, "data.dstip", "dstip", "destination.ip", "dst_ip"))
    dst_port = clean(first(raw, "data.dstport", "dstport", "destination.port", "dst_port"))

    level = int(rule.get("level", 0) or 0)
    process = clean(first(raw, "data.win.eventdata.image", "data.win.eventdata.newProcessName", "data.win.eventdata.processName", "data.process.name", "process.name"))
    parent_process = clean(first(raw, "data.win.eventdata.parentImage", "data.win.eventdata.parentProcessName", "data.process.parent.name", "process.parent.name"))
    command_line = clean(first(raw, "data.win.eventdata.commandLine", "data.commandLine", "process.command_line", "commandLine"))
    message = str(first(raw, "data.win.system.message", "full_log", "message", "rule.description", "data.message", default=""))
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}

    event = {
        "id": record_index,
        "stableId": f"PY-EVT-{record_index:07d}",
        "timestamp": event_time,
        "eventTimestamp": event_time,
        "alertTimestamp": alert_time,
        "timestampValid": event_time_valid,
        "alertTimestampValid": alert_time_valid,
        "eventId": windows_event_id,
        "family": family,
        "source": clean(decoder.get("name")) or clean(raw.get("location")) or "wazuh",
        "host": clean(agent.get("name")) or clean(win_system.get("computer")) or clean(first(raw, "host.name", "hostname")),
        "computer": clean(win_system.get("computer")),
        "provider": clean(win_system.get("providerName")),
        "channel": clean(win_system.get("channel")),
        "user": user,
        "domain": target_domain or subject_domain,
        "targetUser": target_user,
        "targetDomain": target_domain,
        "subjectUser": subject_user,
        "subjectDomain": subject_domain,
        "srcIp": src_ip,
        "srcPort": src_port,
        "dstIp": dst_ip,
        "dstPort": dst_port,
        "protocol": clean(first(raw, "data.protocol", "data.proto", "network.transport")),
        "process": process,
        "parentProcess": parent_process,
        "pid": clean(first(raw, "data.win.eventdata.processId", "data.win.system.processID", "process.pid")),
        "commandLine": command_line,
        "action": clean(first(raw, "data.action", "data.event.action", "event.action")),
        "status": clean(first(raw, "data.win.system.severityValue", "data.status", "event.outcome")),
        "url": clean(first(raw, "data.url", "data.http.url", "url.full")),
        "httpMethod": clean(first(raw, "data.httpMethod", "data.http.method", "http.request.method")),
        "httpStatus": clean(first(raw, "data.status", "data.http.status", "http.response.status_code")),
        "userAgent": clean(first(raw, "data.userAgent", "data.http.user_agent", "user_agent.original")),
        "hashes": clean(first(raw, "data.win.eventdata.hashes", "data.hashes", "syscheck.sha256_after", "syscheck.sha1_after", "syscheck.md5_after")),
        "message": message,
        "severity": _severity_from_level(level),
        "detections": [],
        "quality": [],
        "logonType": clean(first(raw, "data.win.eventdata.logonType", "data.logonType")),
        "authenticationPackage": clean(first(raw, "data.win.eventdata.authenticationPackageName")),
        "logonProcess": clean(first(raw, "data.win.eventdata.logonProcessName")),
        "failureStatus": clean(first(raw, "data.win.eventdata.status", "data.status")),
        "failureSubStatus": clean(first(raw, "data.win.eventdata.subStatus")),
        "failureReason": clean(first(raw, "data.win.eventdata.failureReason")),
        "workstation": clean(first(raw, "data.win.eventdata.workstationName", "data.workstation")),
        "agentId": clean(agent.get("id")),
        "agentIp": clean(agent.get("ip")),
        "managerName": clean(manager.get("name")),
        "wazuhRuleId": clean(rule.get("id")),
        "wazuhRuleLevel": level,
        "wazuhRuleDescription": clean(rule.get("description")),
        "wazuhRuleGroups": as_list(rule.get("groups")),
        "wazuhMitreIds": as_list(mitre.get("id")),
        "wazuhMitreTechniques": as_list(mitre.get("technique")),
        "wazuhMitreTactics": as_list(mitre.get("tactic")),
        "lifecycleAction": lifecycle_action(raw),
        "location": clean(raw.get("location")),
        "decoder": clean(decoder.get("name")),
        "decoderParent": clean(decoder.get("parent")),
        "index": clean(raw.get("__index")),
        "documentId": clean(raw.get("__document_id")),
        "alertId": clean(raw.get("id")),
        "extraData": clean(first(raw, "data.extra_data")),
        "raw": raw,
    }

    if raw.get("__parse_error"):
        event["quality"].append("malformed-json-preserved")
    if event_time_raw and not event_time_valid:
        event["quality"].append("invalid-event-timestamp")
    if family == "windows-event" and not windows_event_id:
        event["quality"].append("windows-event-id-missing")
    if family == "agent-lifecycle" and not event["agentId"]:
        event["quality"].append("agent-id-missing")
    return event
