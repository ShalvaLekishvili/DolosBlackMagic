import json
import unittest

from dbm_wazuh.engine import WazuhAnalysisEngine


class WazuhEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = WazuhAnalysisEngine()

    def test_opensearch_agent_stopped(self):
        payload = {
            "_index": "wazuh-alerts-4.x-test",
            "_id": "doc-1",
            "_source": {
                "agent": {"ip": "10.22.42.11", "name": "SERVER01", "id": "056"},
                "manager": {"name": "wazuh-manager"},
                "data": {"extra_data": "SERVER01->any"},
                "rule": {"level": 15, "description": "Wazuh agent stopped.", "groups": ["ossec"], "id": "506", "mitre": {"id": ["T1562.001"]}},
                "location": "wazuh-remoted",
                "decoder": {"parent": "ossec", "name": "ossec"},
                "id": "1787141023.1848832136",
                "full_log": "ossec: Agent stopped: 'SERVER01->any'.",
                "timestamp": "2026-08-19T16:03:43.018+0400",
            },
        }
        result = self.engine.analyze(json.dumps(payload))
        event = result["events"][0]
        self.assertEqual(event["family"], "agent-lifecycle")
        self.assertEqual(event["eventId"], "")
        self.assertEqual(event["wazuhRuleId"], "506")
        self.assertEqual(event["lifecycleAction"], "stopped")
        self.assertTrue(any(f["ruleId"] == "WAZUH-AGENT-STOPPED" for f in result["findings"]))

    def test_windows_4625_normalization(self):
        alert = {
            "agent": {"ip": "10.22.42.11", "name": "SERVER01", "id": "056"},
            "rule": {"level": 5, "description": "Logon Failure - Unknown user or bad password", "id": "60122", "groups": ["windows", "authentication_failed"]},
            "decoder": {"name": "windows_eventchannel"},
            "location": "EventChannel",
            "timestamp": "2026-08-19T12:07:27.604+0400",
            "data": {"win": {"system": {"eventID": "4625", "systemTime": "2026-08-19T08:29:03.590033+00:00", "channel": "Security", "providerName": "Microsoft-Windows-Security-Auditing"}, "eventdata": {"targetUserName": "administrator", "subjectUserName": "RDWebAccess", "subjectDomainName": "IIS APPPOOL", "logonType": "3", "processName": "C:\\Windows\\System32\\inetsrv\\w3wp.exe", "status": "0xc000006d", "subStatus": "0xc000006a", "ipAddress": "-", "ipPort": "-"}}},
        }
        result = self.engine.analyze(json.dumps(alert))
        event = result["events"][0]
        self.assertEqual(event["eventId"], "4625")
        self.assertEqual(event["user"], "administrator")
        self.assertEqual(event["subjectUser"], "RDWebAccess")
        self.assertEqual(event["srcIp"], "")
        self.assertEqual(event["agentIp"], "10.22.42.11")
        self.assertTrue(any(f["ruleId"] == "WIN-4625" for f in result["findings"]))

    def test_password_spray_correlation(self):
        alerts = []
        for i, user in enumerate(("alice", "bob", "carol")):
            alerts.append({
                "agent": {"name": "DC01", "id": "001"},
                "rule": {"level": 5, "description": "Logon Failure", "id": "60122"},
                "decoder": {"name": "windows_eventchannel"},
                "timestamp": f"2026-08-19T10:00:{i:02d}+00:00",
                "data": {"win": {"system": {"eventID": "4625", "systemTime": f"2026-08-19T10:00:{i:02d}+00:00"}, "eventdata": {"targetUserName": user, "ipAddress": "203.0.113.10"}}},
            })
        result = self.engine.analyze(json.dumps(alerts))
        self.assertTrue(any(f["ruleId"] == "CORR-AUTH-SPRAY" for f in result["findings"]))

    def test_ndjson_malformed_record_is_preserved(self):
        payload = '{"rule":{"level":3,"id":"1"},"agent":{"name":"a"},"message":"ok"}\n{bad json}\n'
        result = self.engine.analyze(payload)
        self.assertEqual(result["summary"]["parse"]["dropped"], 0)
        self.assertGreaterEqual(result["summary"]["parse"]["malformed"], 1)
        self.assertEqual(len(result["events"]), 2)

    def test_port_scan_correlation(self):
        alerts = []
        for port in range(20, 30):
            alerts.append({
                "agent": {"name": "fw01", "id": "002"},
                "rule": {"level": 4, "description": "Firewall deny", "id": "100100", "groups": ["firewall"]},
                "decoder": {"name": "firewall"},
                "timestamp": f"2026-08-19T10:01:{port-20:02d}+00:00",
                "data": {"srcip": "198.51.100.23", "dstip": "10.0.0.15", "dstport": str(port), "action": "deny"},
            })
        result = self.engine.analyze(json.dumps(alerts))
        self.assertTrue(any(f["ruleId"] == "CORR-PORT-SCAN" for f in result["findings"]))


if __name__ == "__main__":
    unittest.main()
