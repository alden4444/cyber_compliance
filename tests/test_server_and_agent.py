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

    def setUp(self):
        with self.db.connection() as conn:
            conn.execute("DELETE FROM devices;")
            conn.execute("DELETE FROM telemetry_records;")
            conn.commit()

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
            self.assertEqual(pol_data["count"], 5)
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

    def test_authentication_and_gatekeeping(self):
        # 1. Unauthenticated /dashboard redirects to /?signin=1
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect())
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            opener.open(f"{self.api_url}/dashboard")
        self.assertEqual(ctx.exception.code, 302)
        self.assertIn("/?signin=1", ctx.exception.headers.get("Location"))

        # 2. Login with bad credentials -> 401
        bad_login = json.dumps({"email": "aldentmcqueen@gmail.com", "password": "WrongPassword!"}).encode("utf-8")
        req_bad = urllib.request.Request(
            f"{self.api_url}/api/v1/auth/login",
            data=bad_login,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req_bad)
        self.assertEqual(ctx.exception.code, 401)

        # 3. Login with valid credentials -> 200, returns token and sets cookie
        good_login = json.dumps({"email": "aldentmcqueen@gmail.com", "password": "Roam-Vault-2026!Security"}).encode("utf-8")
        req_good = urllib.request.Request(
            f"{self.api_url}/api/v1/auth/login",
            data=good_login,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_good) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("token", data)
            self.assertEqual(data["user"]["email"], "aldentmcqueen@gmail.com")
            token = data["token"]
            set_cookie = resp.headers.get("Set-Cookie")
            self.assertIn("roam_session=", set_cookie)

        # 4. Check /api/v1/auth/me with Bearer token
        req_me = urllib.request.Request(
            f"{self.api_url}/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req_me) as resp:
            self.assertEqual(resp.status, 200)
            me_data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(me_data["authenticated"])
            self.assertEqual(me_data["user"]["email"], "aldentmcqueen@gmail.com")

        # 5. Access /dashboard with cookie -> 200
        req_auth_dash = urllib.request.Request(
            f"{self.api_url}/dashboard",
            headers={"Cookie": f"roam_session={token}"}
        )
        with urllib.request.urlopen(req_auth_dash) as resp:
            self.assertEqual(resp.status, 200)
            html = resp.read().decode("utf-8")
            self.assertIn("ROAM", html)

        # 6. Request access endpoint
        req_access_data = json.dumps({
            "name": "Jane Tester",
            "email": "jane@robotics.co",
            "company": "Apex Robotics",
            "fleet_size": "10-50",
            "goal": "soc2"
        }).encode("utf-8")
        req_access = urllib.request.Request(
            f"{self.api_url}/api/v1/auth/request-access",
            data=req_access_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_access) as resp:
            self.assertEqual(resp.status, 200)
            acc_res = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(acc_res["status"], "received")

        # 7. Logout
        req_logout = urllib.request.Request(
            f"{self.api_url}/api/v1/auth/logout",
            headers={"Cookie": f"roam_session={token}"},
            method="POST"
        )
        with urllib.request.urlopen(req_logout) as resp:
            self.assertEqual(resp.status, 200)

        # 8. Check /api/v1/auth/me after logout -> 401
        req_me_after = urllib.request.Request(
            f"{self.api_url}/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req_me_after)
        self.assertEqual(ctx.exception.code, 401)

    def test_add_and_remove_node(self):
        org_token = "org_demo_roam_compliance_2026"

        # 1. Add a new robot node
        add_body = json.dumps({
            "org_token": org_token,
            "hostname": "husky-rover-test-01",
            "mode": "robot",
            "fleet_tag": "field-testing",
            "owner_email": "robotics-lead@roamcompliance.com",
            "initial_posture": "compliant",
            "os_distro": "Ubuntu 22.04 LTS"
        }).encode("utf-8")
        req_add = urllib.request.Request(
            f"{self.api_url}/api/v1/devices/add",
            data=add_body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_add) as resp:
            self.assertEqual(resp.status, 201)
            add_res = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(add_res["status"], "created")
            new_dev = add_res["device"]
            dev_id = new_dev["device_id"]
            self.assertIn("husky-rover-test-01", dev_id)

        # 2. Verify it is returned in list_devices
        req_devs = urllib.request.Request(f"{self.api_url}/api/v1/devices?org_token={org_token}")
        with urllib.request.urlopen(req_devs) as resp:
            self.assertEqual(resp.status, 200)
            devs_data = json.loads(resp.read().decode("utf-8"))
            device_ids = [d["device_id"] for d in devs_data["devices"]]
            self.assertIn(dev_id, device_ids)

        # 3. Delete the node
        del_body = json.dumps({
            "org_token": org_token,
            "device_id": dev_id
        }).encode("utf-8")
        req_del = urllib.request.Request(
            f"{self.api_url}/api/v1/devices/delete",
            data=del_body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_del) as resp:
            self.assertEqual(resp.status, 200)
            del_res = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(del_res["status"], "deleted")
            self.assertEqual(del_res["device_id"], dev_id)

        # 4. Verify it is no longer in list_devices
        with urllib.request.urlopen(req_devs) as resp:
            devs_data_after = json.loads(resp.read().decode("utf-8"))
            device_ids_after = [d["device_id"] for d in devs_data_after["devices"]]
            self.assertNotIn(dev_id, device_ids_after)

    def test_tenant_company_provisioning_and_installer(self):
        """Test complete company tenant onboarding, custom installer generation, and node enrollment."""
        # 1. Pilot access request submission
        req_res = self.db.create_access_request(
            email="founder@robotics-pilot.com",
            name="Pilot Founder",
            company="Acme Autonomous Robots",
            fleet_size="10-50",
            goal="SOC 2 Type II"
        )
        self.assertEqual(req_res["status"], "pending")
        req_id = req_res["id"]

        # 2. Admin approval provisions isolated tenant organization
        approval = self.db.approve_access_request(req_id)
        self.assertIsNotNone(approval)
        new_org = approval["organization"]
        new_token = new_org["org_token"]
        self.assertTrue(new_token.startswith("org_tok_"))
        self.assertEqual(new_org["name"], "Acme Autonomous Robots")

        # Verify tenant policies were automatically seeded
        policies = self.db.list_policies(new_org["id"])
        self.assertEqual(len(policies), 5)

        # 3. Verify customized 1-line installer script generation
        install_url = f"{self.api_url}/install.sh?token={new_token}&mode=workstation&owner=engineer@acme.com"
        with urllib.request.urlopen(install_url) as resp:
            self.assertEqual(resp.status, 200)
            script_text = resp.read().decode("utf-8")
            self.assertIn(f'ORG_TOKEN="{new_token}"', script_text)
            self.assertIn('OWNER_EMAIL="engineer@acme.com"', script_text)
            self.assertIn('/usr/local/bin/cyber-compliance', script_text)
            self.assertIn('install_dir = "/opt/roam-compliance"', script_text)

        # 4. Verify customized remediation fix.sh script generation
        fix_url = f"{self.api_url}/fix.sh?token={new_token}&control=firewall&device_id=inspiron-15"
        with urllib.request.urlopen(fix_url) as resp:
            self.assertEqual(resp.status, 200)
            fix_text = resp.read().decode("utf-8")
            self.assertIn(f'ORG_TOKEN="{new_token}"', fix_text)
            self.assertIn('DEVICE_ID="inspiron-15"', fix_text)
            self.assertIn("'org_token': org_token", fix_text)

        # 5. Enroll device for this new company tenant
        client = ComplianceClient(api_url=self.api_url)
        enroll_res = client.enroll(
            api_url=self.api_url,
            org_token=new_token,
            device_id="acme-workstation-inspiron",
            hostname="acme-inspiron",
            mode="workstation",
            owner_email="engineer@acme.com"
        )
        self.assertEqual(enroll_res["status"], "enrolled")
        self.assertEqual(enroll_res["org_id"], new_org["id"])

        # 6. Verify tenant isolation: newly enrolled device only appears in this tenant's inventory
        devs_url = f"{self.api_url}/api/v1/devices?org_token={new_token}"
        with urllib.request.urlopen(devs_url) as resp:
            tenant_devs = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(tenant_devs["count"], 1)
            self.assertEqual(tenant_devs["devices"][0]["hostname"], "acme-inspiron")

    def test_hostname_sanitization(self):
        """Verify generic localhost hostnames are sanitized into clean, professional titles."""
        from agent.collector import get_friendly_hostname
        from server.db import sanitize_hostname

        # 1. Test collector friendly hostname resolution
        friendly_alden = get_friendly_hostname(owner_email="aldentmcqueen@gmail.com", mode="workstation")
        self.assertNotIn("localhost", friendly_alden.lower())
        self.assertTrue("inspiron" in friendly_alden.lower() or "alden" in friendly_alden.lower())

        # 2. Test server db sanitize_hostname
        sanitized_generic = sanitize_hostname("localhost", owner_email="aldentmcqueen@gmail.com")
        self.assertNotIn("localhost", sanitized_generic.lower())
        self.assertIn("alden", sanitized_generic.lower())

        # 3. Legitimate hostnames should be preserved
        real_host = sanitize_hostname("flight-controller-01", owner_email="robotics@co.com")
        self.assertEqual(real_host, "flight-controller-01")

        # 4. Enrolling with localhost should sanitize in the database
        org_token = "org_demo_roam_compliance_2026"
        org = self.db.get_org_by_token(org_token)
        dev = self.db.enroll_device(
            org_id=org["id"],
            device_id="hw-inspiron-test-serial",
            hostname="localhost",
            mode="workstation",
            owner_email="aldentmcqueen@gmail.com"
        )
        self.assertNotIn("localhost", dev["hostname"].lower())
        self.assertIn("alden", dev["hostname"].lower())

    def test_team_user_reset_and_delete(self):
        """Verify team member deletion and organization team reset endpoints."""
        org_token = "org_demo_roam_compliance_2026"
        org = self.db.get_org_by_token(org_token)
        org_id = org["id"]

        # 1. Add team members
        u1 = self.db.create_user(org_id, "engineer1@example.com", "Engineer One", "engineer")
        u2 = self.db.create_user(org_id, "auditor@example.com", "CPA Auditor", "auditor")
        users = self.db.list_users(org_id)
        user_emails = [u["email"].lower() for u in users]
        self.assertIn("engineer1@example.com", user_emails)
        self.assertIn("auditor@example.com", user_emails)

        # 2. Test single user deletion endpoint
        del_req = urllib.request.Request(
            f"{self.api_url}/api/v1/users/delete",
            data=json.dumps({"org_token": org_token, "user_id": u2["id"]}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(del_req) as resp:
            self.assertEqual(resp.status, 200)
            res_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(res_data["status"], "deleted")

        users_after_del = self.db.list_users(org_id)
        self.assertNotIn("auditor@example.com", [u["email"].lower() for u in users_after_del])
        self.assertIn("engineer1@example.com", [u["email"].lower() for u in users_after_del])

        # 3. Test team reset endpoint (keeps only primary admin)
        reset_req = urllib.request.Request(
            f"{self.api_url}/api/v1/users/reset",
            data=json.dumps({"org_token": org_token, "keep_email": "aldentmcqueen@gmail.com"}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(reset_req) as resp:
            self.assertEqual(resp.status, 200)
            res_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(res_data["status"], "ok")

        users_after_reset = self.db.list_users(org_id)
        remaining_emails = [u["email"].lower() for u in users_after_reset]
        self.assertEqual(remaining_emails, ["aldentmcqueen@gmail.com"])

    def test_onboarding_persistence(self):
        """Verify onboarding status can be marked and persisted cleanly."""
        org_token = "org_demo_roam_compliance_2026"
        org = self.db.get_org_by_token(org_token)
        org_id = org["id"]

        req = urllib.request.Request(
            f"{self.api_url}/api/v1/org/onboarding",
            data=json.dumps({
                "org_token": org_token,
                "name": "Updated Org",
                "onboarding_completed": 1
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)

        updated_org = self.db.get_org_by_id(org_id)
        self.assertEqual(updated_org["onboarding_completed"], 1)

    def test_cyber_compliance_certificate(self):
        """Verify printable Cyber Compliance Certificate generation and SHA256 digest."""
        org_token = "org_demo_roam_compliance_2026"
        cert_url = f"{self.api_url}/certificate?org_token={org_token}&framework=soc2"
        with urllib.request.urlopen(cert_url) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            html_text = resp.read().decode("utf-8")
            self.assertIn("Certificate of Cyber Compliance", html_text)
            self.assertIn("SHA256:", html_text)
            self.assertIn("AICPA", html_text)
            self.assertIn("Master Services Agreement", html_text)


if __name__ == "__main__":
    unittest.main()

