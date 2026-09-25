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
        org_token = "org_demo_roam_compliance_2026"
        enroll_res = client.enroll(
            api_url=self.api_url,
            org_token=org_token,
            device_id="robot-unit-boulder-42",
            hostname="roam-bot-01",
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
            self.assertIn("SOC 2", soc2["framework"])
            self.assertEqual(soc2["asset_summary"]["robots"], 1)
            self.assertGreaterEqual(len(soc2["trust_services_criteria"]), 4)

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
            org_id="org_roam_compliance",
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
        org_token = "org_demo_roam_compliance_2026"

        # 1. Invite a new engineer
        user_data = json.dumps({
            "org_token": org_token,
            "email": "test.engineer@company.internal",
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
            self.assertEqual(created_data["user"]["email"], "test.engineer@company.internal")
            user_id = created_data["user"]["id"]

        # 2. List users
        req_list = urllib.request.Request(f"{self.api_url}/api/v1/users?org_token={org_token}")
        with urllib.request.urlopen(req_list) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            emails = [u["email"] for u in data["users"]]
            self.assertIn("test.engineer@company.internal", emails)

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

    def test_policies_and_scope_and_installer(self):
        org_token = "org_demo_roam_compliance_2026"

        # 1. Dynamic 1-line installer endpoint
        req_sh = urllib.request.Request(f"{self.api_url}/install.sh?token={org_token}&mode=workstation")
        with urllib.request.urlopen(req_sh) as resp:
            self.assertEqual(resp.status, 200)
            sh_body = resp.read().decode("utf-8")
            self.assertIn("ROAM FLEET COMPLIANCE", sh_body)
            self.assertIn("install-service", sh_body)

        # 2. Agent bundle tarball
        req_bundle = urllib.request.Request(f"{self.api_url}/api/v1/agent/bundle.tar.gz")
        with urllib.request.urlopen(req_bundle) as resp:
            self.assertEqual(resp.status, 200)
            bundle_bytes = resp.read()
            self.assertGreater(len(bundle_bytes), 1000)

        # 3. List statutory policies
        req_pol = urllib.request.Request(f"{self.api_url}/api/v1/policies?org_token={org_token}")
        with urllib.request.urlopen(req_pol) as resp:
            self.assertEqual(resp.status, 200)
            pol_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(pol_data["count"], 4)
            keys = [p["policy_key"] for p in pol_data["policies"]]
            self.assertIn("infosec", keys)

        # 4. Adopt statutory policy
        adopt_data = json.dumps({
            "org_token": org_token,
            "policy_key": "infosec",
            "user_name": "Security Officer"
        }).encode("utf-8")
        req_adopt = urllib.request.Request(
            f"{self.api_url}/api/v1/policies/adopt",
            data=adopt_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_adopt) as resp:
            self.assertEqual(resp.status, 200)
            adopt_res = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(adopt_res["status"], "adopted")
            self.assertEqual(adopt_res["policy"]["status"], "adopted")
            self.assertEqual(adopt_res["policy"]["adopted_by"], "Security Officer")

        # 5. Toggle Fleet Scope
        scope_data = json.dumps({
            "org_token": org_token,
            "fleet_scope": "full_fleet"
        }).encode("utf-8")
        req_scope = urllib.request.Request(
            f"{self.api_url}/api/v1/org/scope",
            data=scope_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_scope) as resp:
            self.assertEqual(resp.status, 200)
            scope_res = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(scope_res["org"]["fleet_scope"], "full_fleet")

        # 6. Audit packet HTML endpoint
        req_packet = urllib.request.Request(f"{self.api_url}/audit-packet?org_token={org_token}")
        with urllib.request.urlopen(req_packet) as resp:
            self.assertEqual(resp.status, 200)
            html_content = resp.read().decode("utf-8")
            self.assertIn("ROAM FLEET COMPLIANCE", html_content)
            self.assertIn("Compliance Attestation", html_content)
            self.assertIn("Independent Auditor Notice", html_content)

        # 7. Automated Remediation CLI script & security checks
        req_fix = urllib.request.Request(f"{self.api_url}/fix.sh?control=firewall")
        with urllib.request.urlopen(req_fix) as resp:
            self.assertEqual(resp.status, 200)
            fix_body = resp.read().decode("utf-8")
            self.assertIn("Automated Remediation", fix_body)
            self.assertIn("ufw allow 22/tcp", fix_body)  # Lockout protection test

        req_fix_admin = urllib.request.Request(f"{self.api_url}/fix.sh?control=admin_separation")
        with urllib.request.urlopen(req_fix_admin) as resp:
            self.assertEqual(resp.status, 200)
            fix_admin_body = resp.read().decode("utf-8")
            self.assertIn("Administrative Root Password Is Not Yet Set", fix_admin_body)

        # 8. CSV Exports
        req_csv_dev = urllib.request.Request(f"{self.api_url}/api/v1/export/devices.csv")
        with urllib.request.urlopen(req_csv_dev) as resp:
            self.assertEqual(resp.status, 200)
            csv_text = resp.read().decode("utf-8")
            self.assertIn("Device ID,Hostname,Mode", csv_text)

        req_csv_ctl = urllib.request.Request(f"{self.api_url}/api/v1/export/controls.csv?framework=iso27001")
        with urllib.request.urlopen(req_csv_ctl) as resp:
            self.assertEqual(resp.status, 200)
            csv_ctl_text = resp.read().decode("utf-8")
            self.assertIn("Criteria ID,Control Name", csv_ctl_text)
            self.assertIn("A.8.20", csv_ctl_text)

        # 9. Multi-Certification Frameworks
        req_fws = urllib.request.Request(f"{self.api_url}/api/v1/frameworks")
        with urllib.request.urlopen(req_fws) as resp:
            self.assertEqual(resp.status, 200)
            fws_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(fws_data["count"], 5)
            fw_ids = [f["id"] for f in fws_data["frameworks"]]
            self.assertIn("soc2", fw_ids)
            self.assertIn("iso27001", fw_ids)
            self.assertIn("hipaa", fw_ids)
            self.assertIn("nist800_171", fw_ids)
            self.assertIn("cra", fw_ids)

        # 10. Switch Organization Target Framework
        fw_post = json.dumps({"org_token": org_token, "framework": "hipaa"}).encode("utf-8")
        req_fw_update = urllib.request.Request(
            f"{self.api_url}/api/v1/org/framework",
            data=fw_post,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_fw_update) as resp:
            self.assertEqual(resp.status, 200)
            updated_org = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(updated_org["framework"], "hipaa")

        # 11. Framework-Specific Evidence Query (HIPAA)
        req_hipaa_ev = urllib.request.Request(f"{self.api_url}/api/v1/evidence?framework=hipaa&org_token={org_token}")
        with urllib.request.urlopen(req_hipaa_ev) as resp:
            self.assertEqual(resp.status, 200)
            hipaa_ev = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(hipaa_ev["framework_id"], "hipaa")
            crit_ids = [c["criteria_id"] for c in hipaa_ev["criteria"]]
            self.assertIn("§ 164.312(e)(1)", crit_ids)


if __name__ == "__main__":
    unittest.main()
