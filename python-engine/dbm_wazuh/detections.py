from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Callable, Iterable
import re

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}


def _dt(value: str) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _finding(rule_id: str, name: str, severity: str, confidence: str, events: list[dict[str, Any]], *,
             mitre: list[str] | None = None, tags: list[str] | None = None, why: str = "",
             remediation: str = "", false_positive: str = "", correlation: bool = False,
             source: str = "python-wazuh") -> dict[str, Any]:
    ids = [e["stableId"] for e in events]
    return {
        "id": f"{source}-{rule_id}-{'-'.join(ids)}",
        "ruleId": rule_id,
        "name": name,
        "severity": severity,
        "confidence": confidence,
        "mitre": mitre or [],
        "tags": tags or [],
        "why": why,
        "remediation": remediation,
        "falsePositive": false_positive,
        "eventIds": ids,
        "evidence": [evidence_view(e) for e in events[:20]],
        "correlation": correlation,
        "sourceEngine": source,
        "kind": "correlated" if correlation else ("high-confidence" if confidence == "high" and severity in {"critical", "high"} else "suspicious"),
    }


def evidence_view(e: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": e.get("stableId"), "timestamp": e.get("timestamp"), "host": e.get("host"),
        "user": e.get("user"), "srcIp": e.get("srcIp"), "dstIp": e.get("dstIp"),
        "eventId": e.get("eventId"), "process": e.get("process"), "message": e.get("message", "")[:600],
        "wazuhRuleId": e.get("wazuhRuleId"), "family": e.get("family"),
    }


def _single_rules(e: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    eid = e.get("eventId", "")
    msg = _text(e.get("message")).lower()
    cmd = f"{e.get('process','')} {e.get('commandLine','')}".lower()
    family = e.get("family")
    level = int(e.get("wazuhRuleLevel") or 0)

    if family == "agent-lifecycle" and e.get("lifecycleAction") in {"stopped", "disconnected", "removed"}:
        out.append(_finding("WAZUH-AGENT-STOPPED", "Wazuh agent stopped or disconnected", "critical" if level >= 14 else "high", "high", [e],
            mitre=e.get("wazuhMitreIds") or ["T1562.001"], tags=["wazuh", "agent-health", "telemetry-gap"],
            why=f"Wazuh reported agent lifecycle action '{e.get('lifecycleAction')}' for {e.get('host') or e.get('agentId') or 'an endpoint'}.",
            remediation="Confirm whether the endpoint was intentionally stopped or decommissioned. If not, restore agent connectivity and review host activity immediately before telemetry stopped.",
            false_positive="Planned maintenance, host shutdown, agent upgrade or intentional decommissioning."))
    if family == "agent-lifecycle" and e.get("lifecycleAction") in {"started", "connected", "reconnected", "restarted"}:
        out.append(_finding("WAZUH-AGENT-RESTORED", "Wazuh agent connectivity restored", "informational", "high", [e], tags=["wazuh", "agent-health"],
            why="Wazuh reported that an agent became available again.", remediation="Review any telemetry gap between disconnect and restore if the outage was unexpected."))

    if eid == "4625":
        out.append(_finding("WIN-4625", "Windows authentication failure", "low", "high", [e], mitre=["T1110"], tags=["windows", "authentication"],
            why="Windows Security Event 4625 records a failed logon attempt.", remediation="Use surrounding events and correlation findings to determine whether the failure is benign, service-related or part of password guessing.",
            false_positive="User password mistakes, stale service credentials and expected authentication failures."))
    if eid == "4740":
        out.append(_finding("WIN-4740", "Account locked out", "medium", "high", [e], mitre=["T1110"], tags=["windows", "account-lockout"],
            why="Windows Event 4740 reports that an account was locked out.", remediation="Identify the source of repeated authentication failures and validate whether the affected account is under attack."))
    if eid == "1102":
        out.append(_finding("WIN-1102", "Windows audit log cleared", "high", "high", [e], mitre=["T1070.001"], tags=["windows", "defense-evasion"],
            why="Windows Security Event 1102 indicates the audit log was cleared.", remediation="Confirm authorized administrative activity and inspect nearby process/account activity."))
    if eid in {"7045", "4697"}:
        out.append(_finding("WIN-SERVICE-INSTALL", "New Windows service installed", "medium", "high", [e], mitre=["T1543.003"], tags=["windows", "persistence"],
            why=f"Windows event {eid} records service installation.", remediation="Validate service image path, signer, account and change-management context."))
    if eid == "4698":
        out.append(_finding("WIN-SCHEDULED-TASK", "Scheduled task created", "medium", "high", [e], mitre=["T1053.005"], tags=["windows", "persistence"],
            why="Windows Security Event 4698 records scheduled task creation.", remediation="Review task action, author, trigger and execution path."))
    if eid == "4720":
        out.append(_finding("WIN-ACCOUNT-CREATED", "Local/domain user account created", "medium", "high", [e], mitre=["T1136"], tags=["windows", "account-management"],
            why="Windows Security Event 4720 records user creation.", remediation="Validate the account creation against approved administrative activity."))
    if eid in {"4728", "4732", "4756"}:
        out.append(_finding("WIN-PRIV-GROUP-CHANGE", "Account added to security group", "high", "high", [e], mitre=["T1098"], tags=["windows", "privilege"],
            why=f"Windows Security Event {eid} records group membership change.", remediation="Confirm the target group and account were approved; inspect the actor account and surrounding authentication activity."))

    if eid == "1" and family == "windows-event" and e.get("provider", "").lower().startswith("microsoft-windows-sysmon"):
        suspicious = re.search(r"(?:powershell|cmd|rundll32|regsvr32|mshta|certutil|bitsadmin|wmic|wscript|cscript)\.exe", cmd)
        if suspicious:
            out.append(_finding("SYSMON-PROC-SUSPICIOUS", "Suspicious process execution telemetry", "medium", "medium", [e], mitre=["T1059"], tags=["sysmon", "process"],
                why="Sysmon process creation contains a commonly abused administrative/scripting binary.", remediation="Review command line, parent process, user and file reputation before escalating.",
                false_positive="Legitimate administration, software deployment and support tooling frequently use these binaries."))
    if eid == "10" and family == "windows-event" and "lsass" in msg + cmd:
        out.append(_finding("SYSMON-LSASS-ACCESS", "Process access involving LSASS", "high", "medium", [e], mitre=["T1003.001"], tags=["sysmon", "credential-access"],
            why="Sysmon process access telemetry references LSASS.", remediation="Review source process, granted access mask, signer and endpoint context.",
            false_positive="Security products and diagnostic tools can legitimately access LSASS."))

    if family == "linux-auth":
        if re.search(r"failed password|authentication failure|invalid user", msg):
            out.append(_finding("LINUX-AUTH-FAIL", "Linux authentication failure", "low", "high", [e], mitre=["T1110"], tags=["linux", "authentication"],
                why="Linux authentication telemetry records a failed login attempt.", remediation="Use correlation to determine whether failures form a brute-force pattern."))
        if "sudo" in msg and re.search(r"authentication failure|incorrect password|not in the sudoers", msg):
            out.append(_finding("LINUX-SUDO-FAIL", "Suspicious sudo failure", "medium", "medium", [e], mitre=["T1548.003"], tags=["linux", "privilege"],
                why="The event records failed or unauthorized sudo use.", remediation="Review the initiating account, terminal/session and nearby privilege activity."))
        if re.search(r"(?:useradd|adduser|new user)", msg):
            out.append(_finding("LINUX-ACCOUNT-CREATED", "Linux account creation activity", "medium", "medium", [e], mitre=["T1136.001"], tags=["linux", "account-management"],
                why="Linux telemetry indicates an account creation operation.", remediation="Confirm the account and actor were authorized."))
        if re.search(r"cron|crontab", msg) and re.search(r"create|modify|install|write|changed", msg):
            out.append(_finding("LINUX-CRON-CHANGE", "Cron persistence-related change", "medium", "medium", [e], mitre=["T1053.003"], tags=["linux", "persistence"],
                why="Telemetry indicates a cron/crontab change.", remediation="Review the scheduled command, owner and change context."))

    if family == "fim":
        path = _text(e.get("message"))
        severity = "medium" if re.search(r"(?:/etc/passwd|/etc/shadow|system32|startup|authorized_keys|sudoers)", path, re.I) else "low"
        out.append(_finding("WAZUH-FIM-CHANGE", "File integrity change detected", severity, "high", [e], mitre=["T1565.001"], tags=["wazuh", "fim"],
            why="Wazuh file-integrity monitoring reported a file change.", remediation="Review the changed path, hashes, actor/process context and expected maintenance activity."))

    if family == "web":
        hay = f"{msg} {e.get('url','')}"
        if re.search(r"(?:union(?:\s+all)?\s+select|or\s+1=1|sleep\s*\(|benchmark\s*\(|information_schema)", hay, re.I):
            out.append(_finding("WEB-SQLI-PROBE", "SQL injection probe", "medium", "medium", [e], mitre=["T1190"], tags=["web", "sqli"],
                why="Request content matches common SQL injection probe syntax.", remediation="Validate whether the request reached the application and review nearby requests from the same source."))
        if re.search(r"(?:\.\./|\.\.\\|%2e%2e|/etc/passwd|boot\.ini)", hay, re.I):
            out.append(_finding("WEB-PATH-TRAVERSAL", "Path traversal probe", "medium", "medium", [e], mitre=["T1190"], tags=["web", "path-traversal"],
                why="Request content contains traversal markers or sensitive file paths.", remediation="Confirm application response and review source behavior."))
        if re.search(r"(?:;|\||&&|%3b)\s*(?:id|whoami|uname|cmd|powershell|curl|wget)\b", hay, re.I):
            out.append(_finding("WEB-CMD-INJECTION", "Command injection probe", "high", "medium", [e], mitre=["T1190"], tags=["web", "command-injection"],
                why="Request content matches common command-injection syntax.", remediation="Inspect the application response, backend process telemetry and nearby requests."))

    if family == "network" or e.get("action", "").lower() in {"deny", "blocked", "drop", "dropped"}:
        if e.get("dstPort") in {"22", "23", "3389", "445", "5985", "5986", "5900"}:
            out.append(_finding("NET-ADMIN-PORT-ATTEMPT", "Connection attempt to administrative service", "low", "medium", [e], mitre=["T1021"], tags=["network", "admin-service"],
                why="Network telemetry targets a commonly administered remote-service port.", remediation="Correlate with source reputation, allow-list context and repeated connection patterns.",
                false_positive="Normal administration and monitoring traffic."))

    if level >= 12 and family not in {"agent-lifecycle"}:
        out.append(_finding("WAZUH-HIGH-SEVERITY", "High-severity Wazuh alert", "high" if level < 15 else "critical", "high", [e],
            mitre=e.get("wazuhMitreIds") or [], tags=["wazuh", "source-rule"],
            why=f"The source Wazuh rule fired at level {level}: {e.get('wazuhRuleDescription') or e.get('message')}.",
            remediation="Review the Wazuh source rule context and the normalized evidence before escalation.",
            false_positive="Depends on the originating Wazuh rule and local tuning."))
    return out


def _threshold(events: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool], group_fields: tuple[str, ...], count: int,
               window_s: int, factory: Callable[[list[dict[str, Any]]], dict[str, Any]], distinct_field: str | None = None) -> list[dict[str, Any]]:
    groups: dict[tuple[str, ...], deque[dict[str, Any]]] = defaultdict(deque)
    emitted: set[tuple[str, ...]] = set()
    findings: list[dict[str, Any]] = []
    for e in sorted(events, key=lambda x: (_dt(x.get("timestamp", "")) is None, _dt(x.get("timestamp", "")) or 0, x.get("id", 0))):
        if not predicate(e):
            continue
        key = tuple(_text(e.get(f)).strip() for f in group_fields)
        if any(not part for part in key):
            continue
        ts = _dt(e.get("timestamp", ""))
        if ts is None:
            continue
        q = groups[key]
        while q and (ts - (_dt(q[0].get("timestamp", "")) or ts)) > window_s:
            q.popleft()
        q.append(e)
        metric = len({_text(x.get(distinct_field)).strip() for x in q if _text(x.get(distinct_field)).strip()}) if distinct_field else len(q)
        if metric >= count:
            signature = key + (str(int((_dt(q[0].get("timestamp", "")) or ts) // window_s)),)
            if signature not in emitted:
                emitted.add(signature)
                findings.append(factory(list(q)))
    return findings


def correlate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    is_failure = lambda e: e.get("eventId") == "4625" or bool(re.search(r"failed password|authentication failure|invalid user", _text(e.get("message")), re.I))
    findings += _threshold(events, is_failure, ("srcIp", "user"), 5, 300,
        lambda ev: _finding("CORR-AUTH-GUESSING", "Repeated authentication failures against one account", "high", "high", ev, mitre=["T1110.001"], tags=["authentication", "correlation"], correlation=True,
            why="At least five authentication failures targeted the same account from the same source within five minutes.", remediation="Validate source ownership, targeted account and nearby successful logons.", false_positive="Stale credentials or repeated user mistakes."))
    findings += _threshold(events, is_failure, ("srcIp",), 3, 300,
        lambda ev: _finding("CORR-AUTH-SPRAY", "Authentication spray across multiple accounts", "high", "high", ev, mitre=["T1110.003"], tags=["authentication", "spray"], correlation=True,
            why="One source generated failures against at least three distinct accounts within five minutes.", remediation="Investigate the source and targeted users; look for a later successful authentication."), distinct_field="user")
    findings += _threshold(events, lambda e: is_failure(e) and not e.get("srcIp"), ("host", "user"), 5, 300,
        lambda ev: _finding("CORR-LOCAL-AUTH-FAIL", "Repeated local/service authentication failures", "medium", "medium", ev, mitre=["T1110"], tags=["authentication", "service"], correlation=True,
            why="Repeated failures occurred on the same host/account without a recorded network source.", remediation="Inspect requesting service/process identity and stored credentials.", false_positive="Application pools and services with stale credentials."))
    findings += _threshold(events, lambda e: e.get("eventId") == "4625" and e.get("logonType") == "10", ("srcIp", "user"), 5, 300,
        lambda ev: _finding("CORR-RDP-FAIL", "Repeated RDP authentication failures", "high", "high", ev, mitre=["T1110", "T1021.001"], tags=["rdp", "authentication"], correlation=True,
            why="At least five Logon Type 10 failures came from the same source/account within five minutes.", remediation="Validate the remote source and inspect for a successful RDP session."))
    findings += _threshold(events, lambda e: e.get("eventId") == "4625" and e.get("logonType") == "3", ("host", "user"), 5, 300,
        lambda ev: _finding("CORR-NETWORK-LOGON-FAIL", "Repeated Windows network logon failures", "medium", "medium", ev, mitre=["T1110"], tags=["network-logon", "authentication"], correlation=True,
            why="At least five Logon Type 3 failures targeted the same host/account within five minutes.", remediation="Review caller process/service identity and network source if present.", false_positive="IIS/SMB/services with stale credentials."))

    # Port-scan style correlation: one source touches many distinct destination ports in a short window.
    findings += _threshold(events, lambda e: bool(e.get("srcIp") and e.get("dstPort")), ("srcIp", "dstIp"), 10, 120,
        lambda ev: _finding("CORR-PORT-SCAN", "Multi-port connection pattern", "medium", "medium", ev, mitre=["T1046"], tags=["network", "discovery"], correlation=True,
            why="One source contacted at least ten distinct destination ports on the same target within two minutes.", remediation="Validate scanner ownership and inspect whether connections were allowed or denied.", false_positive="Authorized vulnerability scanning or monitoring."), distinct_field="dstPort")

    # Agent lifecycle flapping.
    findings += _threshold(events, lambda e: e.get("family") == "agent-lifecycle" and e.get("lifecycleAction") in {"stopped", "disconnected", "restarted", "reconnected"}, ("agentId",), 3, 900,
        lambda ev: _finding("CORR-AGENT-FLAPPING", "Repeated Wazuh agent connectivity changes", "high", "high", ev, mitre=["T1562.001"], tags=["wazuh", "agent-health"], correlation=True,
            why="The same Wazuh agent changed connectivity state at least three times within fifteen minutes.", remediation="Check endpoint stability, network path, service logs and potential security-tool tampering.", false_positive="Agent upgrades, host reboot loops or unstable network connectivity."))

    # Failure -> success sequence keyed by source and account.
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("srcIp") and e.get("user") and e.get("eventId") in {"4625", "4624"}:
            by_key[(e["srcIp"], e["user"])].append(e)
    for key, seq in by_key.items():
        seq.sort(key=lambda x: _dt(x.get("timestamp", "")) or 0)
        failures: deque[dict[str, Any]] = deque()
        for e in seq:
            ts = _dt(e.get("timestamp", ""))
            if ts is None:
                continue
            while failures and ts - (_dt(failures[0].get("timestamp", "")) or ts) > 300:
                failures.popleft()
            if e.get("eventId") == "4625":
                failures.append(e)
            elif e.get("eventId") == "4624" and len(failures) >= 3:
                evidence = list(failures)[-3:] + [e]
                findings.append(_finding("CORR-AUTH-SUCCESS-AFTER-FAIL", "Successful logon after repeated failures", "high", "medium", evidence, mitre=["T1110", "T1078"], tags=["authentication", "sequence"], correlation=True,
                    why="Three or more failed logons were followed by a successful logon for the same source/account inside five minutes.", remediation="Validate whether the successful session belongs to the legitimate user and inspect post-authentication activity.", false_positive="A legitimate user can succeed after repeated password mistakes."))
                failures.clear()
    return findings


def analyze_detections(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for event in events:
        findings.extend(_single_rules(event))
    findings.extend(correlate(events))
    seen: set[tuple[str, tuple[str, ...]]] = set()
    deduped: list[dict[str, Any]] = []
    for finding in sorted(findings, key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f["ruleId"])):
        key = (finding["ruleId"], tuple(sorted(finding["eventIds"])))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
        for event in events:
            if event["stableId"] in finding["eventIds"] and finding["ruleId"] not in event["detections"]:
                event["detections"].append(finding["ruleId"])
    return deduped
