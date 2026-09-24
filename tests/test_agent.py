"""Unit and integration tests for Cyber Compliance Agent modules."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent.client import ComplianceClient
from agent.collector import (
    collect_telemetry,
    get_interfaces,
    get_open_ports,
    is_dummy_identifier,
)
from agent.daemon import generate_systemd_unit


class TestCollector(unittest.TestCase):

    def test_dummy_identifier_filtering(self):
        self.assertTrue(is_dummy_identifier("To Be Filled By O.E.M."))
        self.assertTrue(is_dummy_identifier("Default string"))
        self.assertTrue(is_dummy_identifier("00000000"))
        self.assertTrue(is_dummy_identifier("System Serial Number"))
        self.assertFalse(is_dummy_identifier("SN-98234-XYZ-2026"))
        self.assertFalse(is_dummy_identifier("d89e5a10-234b-4f9e-a841-f21e8790b4d9"))

    def test_robot_open_ports_parsing(self):
        sample_ss_output = """tcp    LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
tcp    LISTEN 0      128        127.0.0.1:11311      0.0.0.0:*
udp    UNCONN 0      0               [::]:8080          [::]:*
"""
        with patch("subprocess.check_output", return_value=sample_ss_output):
            ports = get_open_ports()
            self.assertEqual(len(ports), 3)
            # Port 22 exposed on 0.0.0.0
            self.assertTrue(ports[0]["exposed"])
            self.assertEqual(ports[0]["port"], "22")
            # Port 11311 internal on 127.0.0.1
            self.assertFalse(ports[1]["exposed"])
            self.assertEqual(ports[1]["port"], "11311")
            # Port 8080 exposed on ::
            self.assertTrue(ports[2]["exposed"])
            self.assertEqual(ports[2]["port"], "8080")

    def test_robot_interfaces_parsing(self):
        sample_ip_json = json.dumps([
            {
                "ifname": "eth0",
                "addr_info": [{"family": "inet", "local": "192.168.1.50"}]
            },
            {
                "ifname": "can0",
                "addr_info": []
            }
        ])
        with patch("subprocess.check_output", return_value=sample_ip_json):
            interfaces = get_interfaces()
            self.assertEqual(len(interfaces), 2)
            self.assertEqual(interfaces[0]["name"], "eth0")
            self.assertEqual(interfaces[0]["ips"], ["192.168.1.50"])
            self.assertEqual(interfaces[1]["name"], "can0")
            self.assertEqual(interfaces[1]["ips"], [])

    def test_zero_payload_schema_compliance(self):
        """Verify telemetry contains only structured metadata and no binary sensor payloads."""
        telemetry = collect_telemetry(mode="robot", device_id="test-robot-1", org_id="org_test")
        self.assertEqual(telemetry["schema_version"], "1.0.0")
        self.assertEqual(telemetry["device"]["mode"], "robot")
        self.assertIn("controls", telemetry)
        self.assertIn("firewall", telemetry["controls"])
        self.assertIn("antivirus", telemetry["controls"])
        self.assertIn("admin_separation", telemetry["controls"])
        self.assertIn("patch_management", telemetry["controls"])
        self.assertIn("robot_specific", telemetry)
        self.assertIn("posture", telemetry)

        # Prohibit sensor payloads or proprietary fields
        forbidden_keys = {"camera", "lidar", "pointcloud", "slam_map", "source_code", "ros_messages"}
        self.assertTrue(forbidden_keys.isdisjoint(telemetry.keys()))
        self.assertTrue(forbidden_keys.isdisjoint(telemetry["robot_specific"].keys()))


class TestClientOfflineQueue(unittest.TestCase):

    def test_offline_telemetry_queueing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.json"
            queue_file = Path(tmpdir) / "queue.json"

            client = ComplianceClient(config_path=config_file, queue_path=queue_file)

            # When no API configured, send_telemetry should queue
            sample_payload = {"device": {"device_id": "robot-01"}, "posture": "compliant"}
            res = client.send_telemetry(sample_payload)
            self.assertEqual(res["status"], "queued")
            self.assertTrue(queue_file.exists())

            # Read queue file
            with open(queue_file, "r") as f:
                queued_items = json.load(f)
            self.assertEqual(len(queued_items), 1)
            self.assertEqual(queued_items[0]["device"]["device_id"], "robot-01")

    def test_config_saving_and_loading(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.json"
            queue_file = Path(tmpdir) / "queue.json"

            client = ComplianceClient(config_path=config_file, queue_path=queue_file)
            client.save_config(
                api_url="https://api.testcompliance.io",
                device_token="dev_tok_12345",
                device_id="robot-alpha",
                org_id="org_abc",
                mode="robot",
                fleet_tag="boulder-warehouse"
            )

            # Create new client loading same file
            new_client = ComplianceClient(config_path=config_file, queue_path=queue_file)
            self.assertEqual(new_client.api_url, "https://api.testcompliance.io")
            self.assertEqual(new_client.device_token, "dev_tok_12345")


class TestDaemon(unittest.TestCase):

    def test_systemd_unit_generation(self):
        unit = generate_systemd_unit(mode="robot", python_bin="/usr/bin/python3", script_path="/opt/agent/cli.py")
        self.assertIn("ExecStart=/usr/bin/python3 /opt/agent/cli.py --daemon --mode robot", unit)
        self.assertIn("Restart=always", unit)
        self.assertIn("WantedBy=multi-user.target", unit)


if __name__ == "__main__":
    unittest.main()
