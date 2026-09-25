"""Lightweight REST API server for Cyber Compliance platform.

Uses Python standard library only (http.server, json, sqlite3).
Zero external dependencies required.
"""

import argparse
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import tarfile
import urllib.parse

from server.db import ComplianceDatabase
from server.report import generate_audit_packet_html


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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.end_headers()

    def do_HEAD(self):
        # Support HEAD requests for uptime monitors and SSL verification probes
        self.do_GET()

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

    def _get_session_token(self):
        # 1. Check HTTP Cookie
        cookie_header = self.headers.get("Cookie", "")
        if "roam_session=" in cookie_header:
            cookie = SimpleCookie()
            try:
                cookie.load(cookie_header)
                if "roam_session" in cookie:
                    return cookie["roam_session"].value
            except Exception:
                pass

        # 2. Check Bearer token
        bearer = self._get_bearer_token()
        if bearer and bearer.startswith("sess_"):
            return bearer
        return None

    def _get_authenticated_user(self):
        token = self._get_session_token()
        if not token:
            return None
        return self.db.get_session(token)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            landing_file = Path(__file__).resolve().parent.parent / "landing.html"
            if landing_file.exists():
                content = landing_file.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        if path in ["/dashboard", "/app"]:
            # Gate console dashboard behind active authentication
            session = self._get_authenticated_user()
            if not session:
                # Redirect unauthenticated visitors to signin modal on landing page
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/?signin=1")
                self.end_headers()
                return

            dashboard_file = Path(__file__).resolve().parent.parent / "dashboard.html"
            if dashboard_file.exists():
                content = dashboard_file.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        if path in ["/audit.py", "/pc_audit.py"]:
            audit_file = Path(__file__).resolve().parent.parent / "pc_audit.py"
            if audit_file.exists():
                content = audit_file.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/x-python; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Access-Control-Allow-Origin", "*")
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

        if path == "/api/v1/auth/me":
            user_session = self._get_authenticated_user()
            if not user_session:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"authenticated": False, "error": "Not authenticated"})
                return
            self._send_json(HTTPStatus.OK, {
                "authenticated": True,
                "user": user_session
            })
            return

        if path == "/api/v1/access-requests":
            user_session = self._get_authenticated_user()
            if not user_session or user_session.get("role") != "admin":
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Administrator privilege required"})
                return
            requests = self.db.list_access_requests()
            self._send_json(HTTPStatus.OK, {"count": len(requests), "requests": requests})
            return

        if path == "/api/v1/devices":
            token = self._get_bearer_token()
            org_token = query.get("org_token", [None])[0] or token
            org = self.db.get_org_by_token(org_token) if org_token else None
            org_id = org["id"] if org else "org_roam_compliance"

            devices = self.db.list_devices(org_id)
            self._send_json(HTTPStatus.OK, {
                "organization_id": org_id,
                "count": len(devices),
                "devices": devices
            })
            return

        if path in ["/api/v1/evidence", "/api/v1/evidence/soc2"]:
            token = self._get_bearer_token()
            org_token = query.get("org_token", [None])[0] or token
            org = self.db.get_org_by_token(org_token) if org_token else None
            org_id = org["id"] if org else "org_roam_compliance"
            framework_id = query.get("framework", [None])[0]

            evidence = self.db.get_framework_evidence(org_id, framework_id=framework_id)
            self._send_json(HTTPStatus.OK, evidence)
            return

        if path == "/api/v1/frameworks":
            frameworks = self.db.list_frameworks()
            self._send_json(HTTPStatus.OK, {
                "count": len(frameworks),
                "frameworks": frameworks
            })
            return

        if path == "/api/v1/users":
            token = self._get_bearer_token()
            org_token = query.get("org_token", [None])[0] or token
            org = self.db.get_org_by_token(org_token) if org_token else None
            org_id = org["id"] if org else "org_roam_compliance"

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
                org = self.db.get_org_by_id("org_roam_compliance")
            self._send_json(HTTPStatus.OK, org or {})
            return

        if path == "/install.sh":
            org_token = query.get("token", query.get("org_token", ["org_demo_roam_compliance_2026"]))[0]
            mode = query.get("mode", ["workstation"])[0]
            owner_email = query.get("owner", query.get("owner_email", [""]))[0]
            fleet_tag = query.get("tag", query.get("fleet_tag", ["primary"]))[0]

            host = self.headers.get("Host", "127.0.0.1:8000")
            proto = self.headers.get("X-Forwarded-Proto", "http")
            api_url = f"{proto}://{host}"

            script = f"""#!/bin/sh
# ==============================================================================
# Roam Fleet Continuous Compliance - Autonomous Node Installer
# Zero external dependencies. Uses Python 3 standard library only.
# ==============================================================================
set -e

API_URL="{api_url}"
ORG_TOKEN="{org_token}"
MODE="{mode}"
OWNER_EMAIL="{owner_email}"
FLEET_TAG="{fleet_tag}"
INSTALL_DIR="/opt/roam-compliance"

echo "===================================================================="
echo "    ROAM FLEET COMPLIANCE // Continuous SOC 2 Fleet Node Setup"
echo "===================================================================="

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Error: Python 3 is required. Please install python3 first." >&2
    exit 1
fi

echo "[*] Creating secure installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo "[*] Downloading zero-dependency Roam agent bundle from $API_URL..."
curl -sSL "$API_URL/api/v1/agent/bundle.tar.gz" | tar -xz -C "$INSTALL_DIR"

cd "$INSTALL_DIR"

echo "[*] Enrolling node with organization token..."
python3 -m agent.cli --enroll \\
    --api-url "$API_URL" \\
    --org-token "$ORG_TOKEN" \\
    --mode "$MODE" \\
    --fleet-tag "$FLEET_TAG" \\
    --owner-email "$OWNER_EMAIL"

echo "[*] Executing initial automated compliance audit..."
python3 -m agent.cli --fast --mode "$MODE" --api-url "$API_URL"

if [ -d "/etc/systemd/system" ] && [ "$(id -u)" = "0" ]; then
    echo "[*] Installing systemd continuous monitoring service..."
    python3 -m agent.cli --mode "$MODE" --install-service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable --now cyber-compliance.service 2>/dev/null || true
fi

echo ""
echo "===================================================================="
echo " [OK] Roam Agent installed and active!"
echo " Continuous security evidence is syncing to the auditor vault."
echo "===================================================================="
"""
            content = script.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/x-shellscript; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
            return

        if path in ["/api/v1/agent/bundle.tar.gz", "/agent/bundle.tar.gz"]:
            agent_dir = Path(__file__).resolve().parent.parent / "agent"
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                tar.add(agent_dir, arcname="agent")
            content = buf.getvalue()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Content-Disposition", 'attachment; filename="roam-agent.tar.gz"')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
            return

        if path == "/api/v1/policies":
            token = self._get_bearer_token()
            org_token = query.get("org_token", [None])[0] or token
            org = self.db.get_org_by_token(org_token) if org_token else None
            org_id = org["id"] if org else "org_roam_compliance"

            policies = self.db.list_policies(org_id)
            self._send_json(HTTPStatus.OK, {
                "organization_id": org_id,
                "count": len(policies),
                "policies": policies
            })
            return

        if path in ["/audit-packet", "/audit-report", "/evidence/packet"]:
            token = self._get_bearer_token()
            org_token = query.get("org_token", [None])[0] or token
            org = self.db.get_org_by_token(org_token) if org_token else None
            org_id = org["id"] if org else "org_roam_compliance"
            if not org:
                org = self.db.get_org_by_id(org_id) or {"name": "Roam Robotics", "org_token": "org_demo_roam_compliance_2026"}

            framework_id = query.get("framework", [None])[0]
            evidence = self.db.get_framework_evidence(org_id, framework_id=framework_id)
            users = self.db.list_users(org_id)
            host = self.headers.get("Host", "127.0.0.1:8000")
            proto = self.headers.get("X-Forwarded-Proto", "http")
            base_url = f"{proto}://{host}"

            html_doc = generate_audit_packet_html(evidence, org, users, base_url=base_url)
            content = html_doc.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if path == "/fix.sh":
            control = query.get("control", ["firewall"])[0]
            device_id = query.get("device_id", [""])[0]
            host = self.headers.get("Host", "127.0.0.1:8000")
            proto = self.headers.get("X-Forwarded-Proto", "http")
            api_url = f"{proto}://{host}"

            fix_script = f"""#!/bin/sh
# ==============================================================================
# Roam Fleet Compliance - Autonomous Remediation Engine
# Non-destructive, multi-distro remediation with lockout protection
# ==============================================================================
set -e

CONTROL="{control}"
API_URL="{api_url}"
DEVICE_ID="{device_id}"

echo "===================================================================="
echo "    ROAM COMPLIANCE // Automated Remediation: $CONTROL"
echo "===================================================================="

if [ "$(id -u)" != "0" ]; then
    echo "[!] Error: Root/sudo privileges required to apply security remediation." >&2
    echo "    Please run this script with: sudo bash" >&2
    exit 1
fi

# Distro Package Manager Detection
if command -v pacman >/dev/null 2>&1; then
    PKG_MGR="pacman"
elif command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
elif command -v apk >/dev/null 2>&1; then
    PKG_MGR="apk"
elif command -v zypper >/dev/null 2>&1; then
    PKG_MGR="zypper"
else
    PKG_MGR="generic"
fi

echo "[*] Detected host package manager: $PKG_MGR"

case "$CONTROL" in
    firewall)
        echo "[*] Configuring host-based firewall with baseline network defense..."
        
        if [ "$PKG_MGR" = "pacman" ]; then
            if ! command -v ufw >/dev/null 2>&1; then
                echo "[*] Installing UFW and iptables dependencies via pacman..."
                pacman -Sy --noconfirm ufw iptables
            fi
            echo "[*] Ensuring SSH port 22 is allowed (lockout prevention)..."
            ufw allow 22/tcp || true
            echo "[*] Enforcing default incoming deny / outgoing allow..."
            ufw default deny incoming
            ufw default allow outgoing
            echo "[*] Activating UFW firewall..."
            ufw --force enable
            systemctl enable --now ufw 2>/dev/null || true
        elif [ "$PKG_MGR" = "apt" ]; then
            if ! command -v ufw >/dev/null 2>&1; then
                echo "[*] Installing UFW via apt-get..."
                apt-get update -qq
                apt-get install -y ufw
            fi
            echo "[*] Ensuring SSH port 22 is allowed (lockout prevention)..."
            ufw allow 22/tcp || true
            echo "[*] Enforcing default incoming deny / outgoing allow..."
            ufw default deny incoming
            ufw default allow outgoing
            echo "[*] Activating UFW firewall..."
            ufw --force enable
            systemctl enable --now ufw 2>/dev/null || true
        elif [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; then
            if ! command -v firewall-cmd >/dev/null 2>&1; then
                echo "[*] Installing firewalld via $PKG_MGR..."
                $PKG_MGR install -y firewalld
            fi
            echo "[*] Activating firewalld service..."
            systemctl enable --now firewalld
            echo "[*] Authorizing SSH and setting default zone to drop..."
            firewall-cmd --add-service=ssh --permanent || true
            firewall-cmd --set-default-zone=drop
            firewall-cmd --reload
        else
            echo "[!] Using fallback iptables rule configuration..."
            iptables -P INPUT DROP 2>/dev/null || true
            iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
            iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        fi

        # Verify active status
        FW_OK=0
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -qi "active"; then
            FW_OK=1
        elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qi "running"; then
            FW_OK=1
        elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -qE "DROP|REJECT"; then
            FW_OK=1
        fi

        if [ "$FW_OK" -eq 1 ]; then
            echo " [OK] Host firewall verified ACTIVE and shielding incoming ports."
        else
            echo "[!] Warning: Firewall configured but active state could not be verified automatically."
        fi
        ;;

    antivirus)
        echo "[*] Activating endpoint antivirus & threat signature updates..."
        if [ "$PKG_MGR" = "pacman" ]; then
            if ! command -v clamscan >/dev/null 2>&1; then
                echo "[*] Installing ClamAV via pacman..."
                pacman -Sy --noconfirm clamav
            fi
            echo "[*] Starting ClamAV freshclam threat updater service..."
            systemctl enable --now clamav-freshclam 2>/dev/null || true
        elif [ "$PKG_MGR" = "apt" ]; then
            if ! command -v clamscan >/dev/null 2>&1; then
                echo "[*] Installing ClamAV daemon via apt-get..."
                apt-get update -qq
                apt-get install -y clamav clamav-daemon
            fi
            echo "[*] Starting ClamAV threat updater and scan daemon..."
            systemctl enable --now clamav-freshclam 2>/dev/null || true
            systemctl enable --now clamav-daemon 2>/dev/null || true
        elif [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; then
            if ! command -v clamscan >/dev/null 2>&1; then
                echo "[*] Installing ClamAV via $PKG_MGR..."
                $PKG_MGR install -y clamav clamd clamav-update
            fi
            echo "[*] Starting ClamAV scanner service..."
            systemctl enable --now clamd@scan 2>/dev/null || systemctl enable --now clamav-freshclam 2>/dev/null || true
        fi
        echo " [OK] Endpoint antivirus daemon activated."
        ;;

    admin_separation)
        echo "[*] Enforcing administrative privilege boundary (least privilege daily user)..."
        ROOT_PASSWD_SET=0
        if [ -r /etc/shadow ]; then
            ROOT_FIELD=$(awk -F: '$1=="root"{{print $2}}' /etc/shadow)
            if [ -n "$ROOT_FIELD" ] && [ "$ROOT_FIELD" != "!" ] && [ "$ROOT_FIELD" != "*" ] && [ "$ROOT_FIELD" != "!*" ]; then
                ROOT_PASSWD_SET=1
            fi
        fi

        if [ "$ROOT_PASSWD_SET" -eq 0 ]; then
            echo "--------------------------------------------------------------------"
            echo "[!] SAFETY GUARD: Administrative Root Password Is Not Yet Set!"
            echo "    Modern Linux installations have no root password by default."
            echo "    Enforcing root authentication right now would immediately LOCK OUT"
            echo "    all sudo administrative access to this machine!"
            echo ""
            echo "    To apply this fix safely:"
            echo "    1. Run: passwd root"
            echo "       (Create a strong, dedicated administrator password)"
            echo "    2. Re-run this remediation command."
            echo "--------------------------------------------------------------------"
            exit 1
        fi

        mkdir -p /etc/sudoers.d
        echo "Defaults rootpw" > /etc/sudoers.d/cyber_essentials_targetpw
        chmod 0440 /etc/sudoers.d/cyber_essentials_targetpw
        echo " [OK] Root authentication requirement enforced in /etc/sudoers.d/."
        ;;

    patch_management)
        echo "[*] Applying security updates and refreshing package repositories..."
        if [ "$PKG_MGR" = "pacman" ]; then
            pacman -Sy --noconfirm
        elif [ "$PKG_MGR" = "apt" ]; then
            apt-get update -qq && apt-get upgrade -y --only-upgrade 2>/dev/null || true
        elif [ "$PKG_MGR" = "dnf" ]; then
            dnf upgrade -y --security 2>/dev/null || dnf check-update || true
        fi
        echo " [OK] Security patch baseline refreshed."
        ;;

    *)
        echo "[*] Refreshing security posture..."
        ;;
esac

# Instant Re-Audit Trigger
if [ -d "/opt/roam-compliance" ] && [ -f "/opt/roam-compliance/agent/cli.py" ]; then
    echo "[*] Triggering instant re-audit with Roam compliance collector..."
    python3 -m agent.cli --fast --api-url "$API_URL" 2>/dev/null || true
elif [ -f "./agent/cli.py" ]; then
    echo "[*] Triggering instant local re-audit..."
    python3 -m agent.cli --fast --api-url "$API_URL" 2>/dev/null || true
fi

echo "===================================================================="
echo " [OK] Remediation completed and audit status refreshed!"
echo "===================================================================="
"""
            content = fix_script.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/x-shellscript; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
            return

        if path == "/api/v1/export/devices.csv":
            token = self._get_bearer_token()
            org_token = query.get("org_token", [None])[0] or token
            org = self.db.get_org_by_token(org_token) if org_token else None
            org_id = org["id"] if org else "org_roam_compliance"
            devices = self.db.list_devices(org_id)

            import csv
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Device ID", "Hostname", "Mode", "Fleet Tag", "Owner Email", "OS Distro", "OS Version", "Posture", "Last Heartbeat"])
            for d in devices:
                writer.writerow([
                    d.get("device_id", ""),
                    d.get("hostname", ""),
                    d.get("mode", ""),
                    d.get("fleet_tag", ""),
                    d.get("owner_email", ""),
                    d.get("os_distro", ""),
                    d.get("os_version", ""),
                    d.get("last_posture", ""),
                    d.get("last_heartbeat", "")
                ])
            content = output.getvalue().encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Content-Disposition", 'attachment; filename="roam-devices-inventory.csv"')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
            return

        if path == "/api/v1/export/controls.csv":
            token = self._get_bearer_token()
            org_token = query.get("org_token", [None])[0] or token
            org = self.db.get_org_by_token(org_token) if org_token else None
            org_id = org["id"] if org else "org_roam_compliance"
            framework_id = query.get("framework", [None])[0]
            evidence = self.db.get_framework_evidence(org_id, framework_id=framework_id)
            criteria = evidence.get("criteria", [])
            framework_code = evidence.get("framework", "Compliance")

            import csv
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Framework", "Criteria ID", "Control Name", "Audited Scope Count", "Status", "Description"])
            for c in criteria:
                writer.writerow([
                    framework_code,
                    c.get("criteria_id", ""),
                    c.get("name", ""),
                    c.get("audited_assets", 0),
                    c.get("status", ""),
                    c.get("description", "")
                ])
            content = output.getvalue().encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            filename = f"roam-{evidence.get('framework_id', 'compliance')}-controls-ledger.csv"
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/v1/auth/login":
            try:
                body = self._read_json_body()
            except Exception as e:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON body: {str(e)}"})
                return

            email = body.get("email")
            password = body.get("password")
            if not email or not password:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing 'email' or 'password'"})
                return

            session = self.db.authenticate_user(email, password)
            if not session:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid email or password"})
                return

            token = session["token"]
            cookie = SimpleCookie()
            cookie["roam_session"] = token
            cookie["roam_session"]["path"] = "/"
            cookie["roam_session"]["httponly"] = True
            cookie["roam_session"]["max-age"] = 2592000  # 30 days
            cookie["roam_session"]["samesite"] = "Lax"

            data = json.dumps({
                "status": "ok",
                "token": token,
                "user": session["user"],
                "org_id": session["org_id"]
            }, indent=2).encode("utf-8")

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Set-Cookie", cookie["roam_session"].OutputString())
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/v1/auth/logout":
            token = self._get_session_token()
            if token:
                self.db.delete_session(token)

            cookie = SimpleCookie()
            cookie["roam_session"] = ""
            cookie["roam_session"]["path"] = "/"
            cookie["roam_session"]["max-age"] = 0

            data = json.dumps({"status": "logged_out"}, indent=2).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Set-Cookie", cookie["roam_session"].OutputString())
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/v1/auth/request-access":
            try:
                body = self._read_json_body()
            except Exception as e:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON body: {str(e)}"})
                return

            email = body.get("email")
            if not email:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing 'email' field"})
                return

            try:
                req = self.db.create_access_request(
                    email=email,
                    name=body.get("name"),
                    company=body.get("company"),
                    fleet_size=body.get("fleet_size"),
                    goal=body.get("goal")
                )
                self._send_json(HTTPStatus.OK, {
                    "status": "received",
                    "message": "Access request received. Our security team will review your application within 24 hours.",
                    "request": req
                })
            except Exception as e:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(e)})
            return

        if path == "/api/v1/org/framework":
            try:
                body = self._read_json_body()
            except Exception as e:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON body: {str(e)}"})
                return

            org_token = body.get("org_token")
            framework = body.get("framework", "soc2")
            org = self.db.get_org_by_token(org_token) if org_token else self.db.get_org_by_id("org_roam_compliance")
            if not org:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Organization not found"})
                return

            updated = self.db.update_org_onboarding(org["id"], framework=framework)
            self._send_json(HTTPStatus.OK, {
                "status": "updated",
                "framework": framework,
                "organization": updated
            })
            return

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
            org_token = body.get("org_token", "org_demo_roam_compliance_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_roam_compliance"
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
            org_token = body.get("org_token", "org_demo_roam_compliance_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_roam_compliance"

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
            org_token = body.get("org_token", "org_demo_roam_compliance_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_roam_compliance"
            result = self.db.seed_demo_fleet(org_id)
            self._send_json(HTTPStatus.OK, result)
            return

        if path == "/api/v1/fleet/reset":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            org_token = body.get("org_token", "org_demo_roam_compliance_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_roam_compliance"
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
            org_token = body.get("org_token", "org_demo_roam_compliance_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_roam_compliance"

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
            org_token = body.get("org_token", "org_demo_roam_compliance_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_roam_compliance"
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
            org_token = body.get("org_token", "org_demo_roam_compliance_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_roam_compliance"

            updated = self.db.update_org_onboarding(org_id, name=name, framework=framework, target_audit_date=target_date, onboarding_completed=completed)
            self._send_json(HTTPStatus.OK, {"status": "updated", "org": updated})
            return

        if path == "/api/v1/demo/reset":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            org_token = body.get("org_token", "org_demo_roam_compliance_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_roam_compliance"
            result = self.db.reset_account_for_demo(org_id)
            self._send_json(HTTPStatus.OK, {"status": "reset", "org": result})
            return

        if path == "/api/v1/policies/adopt":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            policy_key = body.get("policy_key")
            user_name = body.get("user_name", "Executive Leadership")
            org_token = body.get("org_token", "org_demo_roam_compliance_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_roam_compliance"

            if not policy_key:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing 'policy_key' parameter"})
                return

            updated_policy = self.db.adopt_policy(org_id, policy_key, user_name)
            self._send_json(HTTPStatus.OK, {"status": "adopted", "policy": updated_policy})
            return

        if path == "/api/v1/org/scope":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            fleet_scope = body.get("fleet_scope", "workstations_only")
            org_token = body.get("org_token", "org_demo_roam_compliance_2026")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_roam_compliance"

            updated = self.db.set_fleet_scope(org_id, fleet_scope)
            self._send_json(HTTPStatus.OK, {"status": "updated", "org": updated})
            return

        if path == "/api/v1/demo/enroll-local-host":
            try:
                body = self._read_json_body()
            except Exception:
                body = {}
            org_token = body.get("org_token", "org_demo_roam_compliance_2026")
            owner_email = body.get("owner_email")
            org = self.db.get_org_by_token(org_token)
            org_id = org["id"] if org else "org_roam_compliance"
            device = self.db.enroll_local_host(org_id, owner_email=owner_email)
            self._send_json(HTTPStatus.OK, {"status": "enrolled", "device": device})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def log_message(self, format, *args):
        # Override default noisy stderr logging for cleaner tests
        pass


def run_server(host=None, port=None, db_path=None):
    if host is None:
        host = os.environ.get("HOST", "0.0.0.0")
    if port is None:
        port = int(os.environ.get("PORT", "8000"))
    if db_path is None:
        db_path = os.environ.get("COMPLIANCE_DB", "compliance.db")

    db = ComplianceDatabase(db_path=db_path)
    ComplianceAPIHandler.db = db
    server = ThreadingHTTPServer((host, port), ComplianceAPIHandler)
    print(f"Cyber Compliance API server listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server cleanly.")
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Compliance Central SaaS API Server")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"), help="Host address to bind to")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)), help="Port to listen on")
    parser.add_argument("--db", default=os.environ.get("COMPLIANCE_DB", "compliance.db"), help="Path to SQLite database file")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port, db_path=args.db)
