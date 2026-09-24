"""Lightweight REST API server for Cyber Compliance platform.

Uses Python standard library only (http.server, json, sqlite3).
Zero external dependencies required.
"""

import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import urllib.parse

from server.db import ComplianceDatabase


class ComplianceAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for cyber compliance ingestion and auditor endpoints."""

    db = None  # Injected by server startup

    def _send_json(self, status_code, payload):
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def _read_json_body(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        raw = self.rfile.read(content_length).decode("utf-8")
        return json.loads(raw)

    def _get_bearer_token(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth.split(" ", 1)[1].strip()
        return None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path in ["/", "/dashboard"]:
            dashboard_file = Path(__file__).resolve().parent.parent / "dashboard.html"
            if dashboard_file.exists():
                content = dashboard_file.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        if path == "/api/v1/health":
            self._send_json(HTTPStatus.OK, {
                "status": "healthy",
                "service": "CyberComplianceAPI",
                "version": "1.0.0"
            })
            return

        if path == "/api/v1/devices":
            token = self._get_bearer_token()
            org_token = query.get("org_token", [None])[0] or token
            org = self.db.get_org_by_token(org_token) if org_token else None
            org_id = org["id"] if org else "org_pattern_labs"

            devices = self.db.list_devices(org_id)
            self._send_json(HTTPStatus.OK, {
                "organization_id": org_id,
                "count": len(devices),
                "devices": devices
            })
            return

        if path == "/api/v1/evidence/soc2":
            token = self._get_bearer_token()
            org_token = query.get("org_token", [None])[0] or token
            org = self.db.get_org_by_token(org_token) if org_token else None
            org_id = org["id"] if org else "org_pattern_labs"

            evidence = self.db.get_soc2_evidence(org_id)
            self._send_json(HTTPStatus.OK, evidence)
            return

        if path == "/api/v1/users":
            token = self._get_bearer_token()
            org_token = query.get("org_token", [None])[0] or token
            org = self.db.get_org_by_token(org_token) if org_token else None
            org_id = org["id"] if org else "org_pattern_labs"

            users = self.db.list_users(org_id)
            self._send_json(HTTPStatus.OK, {
                "organization_id": org_id,
                "count": len(users),
                "users": users
            })
            return

        if path == "/api/v1/org":
            token = self._get_bearer_token()
            org_token = query.get("org_token", [None])[0] or token
            org = self.db.get_org_by_token(org_token) if org_token else None
            if not org:
                org = self.db.get_org_by_id("org_pattern_labs")
            self._send_json(HTTPStatus.OK, org or {})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/v1/enroll":
            try:
                body = self._read_json_body()
            except Exception as e:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON body: {str(e)}"})
                return

            org_token = body.get("org_token")
            device_id = body.get("device_id")
            if not org_token or not device_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing 'org_token' or 'device_id'"})
                return

            org = self.db.get_org_by_token(org_token)
            if not org:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid organization enrollment token"})
                return

            device = self.db.enroll_device(
                org_id=org["id"],
                device_id=device_id,
                hostname=body.get("hostname"),
                mode=body.get("mode", "workstation"),
                fleet_tag=body.get("fleet_tag"),
                owner_email=body.get("owner_email"),
            )
            self._send_json(HTTPStatus.OK, {
                "status": "enrolled",
                "org_id": org["id"],
                "device_id": device["device_id"],
                "device_token": device["device_token"],
            })
            return

        if path == "/api/v1/telemetry":
            token = self._get_bearer_token()
            if not token:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Missing Bearer Authorization header"})
                return

            device = self.db.get_device_by_token(token)
            if not device:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid or unrecognized device token"})
                return

            try:
                telemetry = self._read_json_body()
            except Exception as e:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON body: {str(e)}"})
                return

            # Enforce zero-payload schema safety check
            forbidden = {"camera", "lidar", "pointcloud", "slam_map", "source_code"}
            if not forbidden.isdisjoint(telemetry.keys()):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Prohibited payload detected: Zero-Payload violation."})
                return

            result = self.db.record_telemetry(device, telemetry)
            self._send_json(HTTPStatus.OK, {
                "status": "received",
                "recorded_at": telemetry.get("collected_at"),
                "posture": result["posture"],
            })
            return

        if path == "/api/v1/devices/toggle-test":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            device_id = body.get("device_id")
            posture = body.get("posture", "compliant")
            org_token = body.get("org_token", "org_demo_pattern_labs_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_pattern_labs"
            self.db.set_device_posture_test(org_id, device_id, posture)
            self._send_json(HTTPStatus.OK, {
                "status": "updated",
                "device_id": device_id,
                "posture": posture
            })
            return

        if path == "/api/v1/devices/re-audit":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            device_id = body.get("device_id")
            org_token = body.get("org_token", "org_demo_pattern_labs_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_pattern_labs"

            devices = self.db.list_devices(org_id)
            target = next((d for d in devices if d["device_id"] == device_id), None)
            if not target and devices:
                target = devices[0]

            if not target:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Device not found"})
                return

            from agent.collector import collect_telemetry
            telemetry = collect_telemetry(mode=target.get("mode", "robot"), device_id=target["device_id"], org_id=org_id)
            self.db.record_telemetry(target, telemetry)

            self._send_json(HTTPStatus.OK, {
                "status": "verified",
                "device_id": target["device_id"],
                "posture": telemetry["posture"],
                "controls": telemetry["controls"],
                "collected_at": telemetry["collected_at"]
            })
            return

        if path == "/api/v1/fleet/seed-demo":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            org_token = body.get("org_token", "org_demo_pattern_labs_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_pattern_labs"
            result = self.db.seed_demo_fleet(org_id)
            self._send_json(HTTPStatus.OK, result)
            return

        if path == "/api/v1/fleet/reset":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            org_token = body.get("org_token", "org_demo_pattern_labs_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_pattern_labs"
            result = self.db.clear_demo_fleet(org_id)
            self._send_json(HTTPStatus.OK, result)
            return

        if path == "/api/v1/users":
            try:
                body = self._read_json_body()
            except Exception as e:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON body: {str(e)}"})
                return

            email = body.get("email")
            name = body.get("name", "Team Member")
            role = body.get("role", "engineer")
            org_token = body.get("org_token", "org_demo_pattern_labs_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_pattern_labs"

            if not email:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing 'email' field"})
                return

            user = self.db.create_user(org_id, email, name, role)
            self._send_json(HTTPStatus.OK, {"status": "created", "user": user})
            return

        if path == "/api/v1/users/delete":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            user_id = body.get("user_id")
            org_token = body.get("org_token", "org_demo_pattern_labs_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_pattern_labs"
            result = self.db.delete_user(org_id, user_id)
            self._send_json(HTTPStatus.OK, result)
            return

        if path == "/api/v1/org/onboarding":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            name = body.get("name")
            framework = body.get("framework")
            target_date = body.get("target_audit_date")
            completed = body.get("onboarding_completed", 1)
            org_token = body.get("org_token", "org_demo_pattern_labs_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_pattern_labs"

            updated = self.db.update_org_onboarding(org_id, name=name, framework=framework, target_audit_date=target_date, onboarding_completed=completed)
            self._send_json(HTTPStatus.OK, {"status": "updated", "org": updated})
            return

        if path == "/api/v1/demo/reset":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            org_token = body.get("org_token", "org_demo_pattern_labs_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_pattern_labs"
            result = self.db.reset_account_for_demo(org_id)
            self._send_json(HTTPStatus.OK, {"status": "reset", "org": result})
            return

        if path == "/api/v1/demo/enroll-local-host":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            org_token = body.get("org_token", "org_demo_pattern_labs_2026")
            owner_email = body.get("owner_email")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_pattern_labs"
            device = self.db.enroll_local_host(org_id, owner_email=owner_email)
            self._send_json(HTTPStatus.OK, {"status": "enrolled", "device": device})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def log_message(self, format, *args):
        # Override default noisy stderr logging for cleaner tests
        pass


def run_server(host="127.0.0.1", port=8000, db_path="compliance.db"):
    db = ComplianceDatabase(db_path=db_path)
    ComplianceAPIHandler.db = db
    server = HTTPServer((host, port), ComplianceAPIHandler)
    print(f"Cyber Compliance API server listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server cleanly.")
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Compliance Central SaaS API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host address to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    parser.add_argument("--db", default="compliance.db", help="Path to SQLite database file")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port, db_path=args.db)
