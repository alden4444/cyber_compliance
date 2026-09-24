"""End-to-end integration tests for Cyber Compliance Server and Agent."""

from http.server import HTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.request

from agent.client import ComplianceClient
from agent.collector import collect_telemetry
from server.app import ComplianceAPIHandler
from server.db import ComplianceDatabase


class TestServerAndAgentIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create a temp database
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_compliance.db"
        cls.db = ComplianceDatabase(db_path=cls.db_path)

        # Set up test server on loopback port
        ComplianceAPIHandler.db = cls.db
        cls.server = HTTPServer(("127.0.0.1", 0), ComplianceAPIHandler)
        cls.port = cls.server.server_port
        cls.api_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.temp_dir.cleanup()

    def test_health_check(self):
        req = urllib.request.Request(f"{self.api_url}/api/v1/health")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "healthy")

    def test_dashboard_page(self):
        req = urllib.request.Request(f"{self.api_url}/")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            body = resp.read().decode("utf-8")
            self.assertIn("Cyber Compliance", body)

    def test_end_to_end_device_lifecycle(self):
        client_dir = tempfile.TemporaryDirectory()
        cfg_file = Path(client_dir.name) / "config.json"
        queue_file = Path(client_dir.name) / "queue.json"

        client = ComplianceClient(config_path=cfg_file, queue_path=queue_file)

        # 1. Device Enrollment
        org_token = "org_demo_pattern_labs_2026"
        enroll_res = client.enroll(
            api_url=self.api_url,
            org_token=org_token,
            device_id="robot-unit-boulder-42",
            hostname="pattern-bot-01",
            mode="robot",
            fleet_tag="boulder-depot-fleet",
        )
        self.assertEqual(enroll_res.get("status"), "enrolled")
        device_token = enroll_res.get("device_token")
        self.assertTrue(device_token.startswith("dev_tok_"))

        # 2. Telemetry Dispatch
        telemetry = collect_telemetry(mode="robot", device_id="robot-unit-boulder-42")
        res = client.send_telemetry(telemetry)
        self.assertEqual(res.get("status"), "sent")
        self.assertEqual(res["response"].get("status"), "received")

        # 3. Query Device Inventory
        req = urllib.request.Request(f"{self.api_url}/api/v1/devices?org_token={org_token}")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["count"], 1)
            dev = data["devices"][0]
            self.assertEqual(dev["device_id"], "robot-unit-boulder-42")
            self.assertEqual(dev["fleet_tag"], "boulder-depot-fleet")
            self.assertIn(dev["last_posture"], ["compliant", "non_compliant", "warning"])

        # 4. Query SOC 2 Auditor Evidence
        req_soc2 = urllib.request.Request(f"{self.api_url}/api/v1/evidence/soc2?org_token={org_token}")
        with urllib.request.urlopen(req_soc2) as resp:
            soc2 = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(soc2["framework"], "SOC 2 Type 1 / Type 2")
            self.assertEqual(soc2["asset_summary"]["robots"], 1)
            self.assertEqual(len(soc2["trust_services_criteria"]), 4)

        # 5. Test Simulated Posture Toggle Endpoint
        toggle_data = json.dumps({"device_id": "robot-unit-boulder-42", "posture": "compliant"}).encode("utf-8")
        req_toggle = urllib.request.Request(
            f"{self.api_url}/api/v1/devices/toggle-test",
            data=toggle_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_toggle) as resp:
            toggle_res = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(toggle_res["status"], "updated")
        # 6. Test Instant On-Demand Re-Audit Endpoint
        reaudit_data = json.dumps({"device_id": "robot-unit-boulder-42"}).encode("utf-8")
        req_reaudit = urllib.request.Request(
            f"{self.api_url}/api/v1/devices/re-audit",
            data=reaudit_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_reaudit) as resp:
            reaudit_res = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(reaudit_res["status"], "verified")
            self.assertIn("posture", reaudit_res)

        client_dir.cleanup()

    def test_zero_payload_enforcement_on_server(self):
        """Server must strictly reject payloads containing camera or proprietary sensor streams."""
        device = self.db.enroll_device(
            org_id="org_pattern_labs",
            device_id="violation-test-robot",
            hostname="test-bot",
            mode="robot"
        )
        token = device["device_token"]

        forbidden_payload = {
            "device": {"device_id": "violation-test-robot"},
            "camera": "data:image/jpeg;base64,...",  # PROHIBITED
            "controls": {}
        }
        data_bytes = json.dumps(forbidden_payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.api_url}/api/v1/telemetry",
            data=data_bytes,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST",
        )

        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)
        ctx.exception.close()

    def test_user_management_and_onboarding(self):
        org_token = "org_demo_pattern_labs_2026"

        # 1. Invite a new engineer
        user_data = json.dumps({
            "org_token": org_token,
            "email": "test.engineer@patternlabs.com",
            "name": "Test Engineer",
            "role": "engineer"
        }).encode("utf-8")
        req_add = urllib.request.Request(
            f"{self.api_url}/api/v1/users",
            data=user_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_add) as resp:
            self.assertEqual(resp.status, 200)
            created_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(created_data["user"]["email"], "test.engineer@patternlabs.com")
            user_id = created_data["user"]["id"]

        # 2. List users
        req_list = urllib.request.Request(f"{self.api_url}/api/v1/users?org_token={org_token}")
        with urllib.request.urlopen(req_list) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            emails = [u["email"] for u in data["users"]]
            self.assertIn("test.engineer@patternlabs.com", emails)

        # 3. Update Org Onboarding
        onboarding_data = json.dumps({
            "org_token": org_token,
            "framework": "ISO 27001",
            "target_audit_date": "2026-12-31"
        }).encode("utf-8")
        req_onboard = urllib.request.Request(
            f"{self.api_url}/api/v1/org/onboarding",
            data=onboarding_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_onboard) as resp:
            self.assertEqual(resp.status, 200)
            org_res = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(org_res["org"]["framework"], "ISO 27001")
            self.assertEqual(org_res["org"]["target_audit_date"], "2026-12-31")

        # 4. Get Org Details
        req_org = urllib.request.Request(f"{self.api_url}/api/v1/org?org_token={org_token}")
        with urllib.request.urlopen(req_org) as resp:
            self.assertEqual(resp.status, 200)
            org_info = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(org_info["framework"], "ISO 27001")

        # 5. Delete User
        del_data = json.dumps({
            "org_token": org_token,
            "user_id": user_id
        }).encode("utf-8")
        req_del = urllib.request.Request(
            f"{self.api_url}/api/v1/users/delete",
            data=del_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_del) as resp:
            self.assertEqual(resp.status, 200)
            del_res = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(del_res["status"], "deleted")


if __name__ == "__main__":
    unittest.main()
