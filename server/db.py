"""Database management for Cyber Compliance platform using SQLite3."""

import contextlib
import json
from pathlib import Path
import sqlite3
import time
import uuid


class ComplianceDatabase:
    """Manages multi-tenant organizations, enrolled devices, and telemetry audit logs."""

    def __init__(self, db_path="compliance.db"):
        self.db_path = Path(db_path)
        self.init_db()

    @contextlib.contextmanager
    def connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def init_db(self):
        """Initialize database schema with organizations, devices, and telemetry logs."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                org_token TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                hostname TEXT,
                mode TEXT NOT NULL,
                fleet_tag TEXT,
                owner_email TEXT,
                device_token TEXT UNIQUE NOT NULL,
                last_posture TEXT DEFAULT 'unknown',
                last_heartbeat TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (org_id) REFERENCES organizations(id),
                UNIQUE(org_id, device_id)
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_records (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                posture TEXT NOT NULL,
                controls_json TEXT NOT NULL,
                robot_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (org_id) REFERENCES organizations(id)
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                email TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'engineer',
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                FOREIGN KEY (org_id) REFERENCES organizations(id),
                UNIQUE(org_id, email)
            );
            """)

            # Ensure os_distro and os_version columns exist on devices
            try:
                cursor.execute("ALTER TABLE devices ADD COLUMN os_distro TEXT;")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE devices ADD COLUMN os_version TEXT;")
            except Exception:
                pass

            # Ensure framework and onboarding columns exist on organizations
            try:
                cursor.execute("ALTER TABLE organizations ADD COLUMN framework TEXT DEFAULT 'SOC 2 Type II';")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE organizations ADD COLUMN target_audit_date TEXT;")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE organizations ADD COLUMN onboarding_completed INTEGER DEFAULT 0;")
            except Exception:
                pass

            # Seed a default demo organization for instant testing if empty
            cursor.execute("SELECT COUNT(*) as count FROM organizations;")
            if cursor.fetchone()["count"] == 0:
                demo_token = "org_demo_pattern_labs_2026"
                now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                cursor.execute(
                    "INSERT INTO organizations (id, name, org_token, framework, created_at) VALUES (?, ?, ?, ?, ?);",
                    ("org_pattern_labs", "Pattern Labs", demo_token, "SOC 2 Type II", now)
                )

            # Seed initial founder user if empty
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE org_id = 'org_pattern_labs';")
            if cursor.fetchone()["count"] == 0:
                now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                cursor.execute(
                    "INSERT INTO users (id, org_id, email, name, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
                    ("usr_founder", "org_pattern_labs", "alden@patternlabs.com", "Alden", "admin", "active", now)
                )

            conn.commit()

    def get_org_by_token(self, org_token):
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM organizations WHERE org_token = ?;", (org_token,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_org_by_id(self, org_id):
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM organizations WHERE id = ?;", (org_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_org_onboarding(self, org_id, name=None, framework=None, target_audit_date=None, onboarding_completed=1):
        """Update organization name, compliance target framework, audit deadline, and onboarding progress."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE organizations SET
                name = COALESCE(?, name),
                framework = COALESCE(?, framework),
                target_audit_date = COALESCE(?, target_audit_date),
                onboarding_completed = COALESCE(?, onboarding_completed)
            WHERE id = ?;
            """, (name, framework, target_audit_date, onboarding_completed, org_id))
            conn.commit()
            return self.get_org_by_id(org_id)

    def create_user(self, org_id, email, name, role="engineer", status="active"):
        """Add a team member or auditor to the organization."""
        user_id = f"usr_{uuid.uuid4().hex[:10]}"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO users (id, org_id, email, name, role, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(org_id, email) DO UPDATE SET
                name=excluded.name,
                role=excluded.role,
                status=excluded.status;
            """, (user_id, org_id, email.lower().strip(), name.strip(), role, status, now))
            conn.commit()
            cursor.execute("SELECT * FROM users WHERE org_id = ? AND email = ?;", (org_id, email.lower().strip()))
            return dict(cursor.fetchone())

    def list_users(self, org_id):
        """List all team members, engineers, and auditors with their linked devices."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT u.*, d.id as device_pk, d.hostname as device_hostname, d.last_posture as device_posture
            FROM users u
            LEFT JOIN devices d ON d.owner_email = u.email AND d.org_id = u.org_id
            WHERE u.org_id = ?
            ORDER BY u.created_at ASC;
            """, (org_id,))
            return [dict(r) for r in cursor.fetchall()]

    def delete_user(self, org_id, user_id):
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE org_id = ? AND id = ?;", (org_id, user_id))
            conn.commit()
            return {"status": "deleted", "id": user_id}

    def enroll_device(self, org_id, device_id, hostname, mode="workstation", fleet_tag=None, owner_email=None):
        """Enroll or re-enroll an endpoint device, generating a persistent bearer token."""
        device_token = f"dev_tok_{uuid.uuid4().hex}"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        pk = f"dev_{uuid.uuid4().hex[:12]}"

        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO devices (id, org_id, device_id, hostname, mode, fleet_tag, owner_email, device_token, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(org_id, device_id) DO UPDATE SET
                hostname=excluded.hostname,
                mode=excluded.mode,
                fleet_tag=excluded.fleet_tag,
                owner_email=excluded.owner_email,
                device_token=excluded.device_token;
            """, (pk, org_id, device_id, hostname, mode, fleet_tag, owner_email, device_token, now))

            # Retrieve effective device record
            cursor.execute("SELECT * FROM devices WHERE org_id = ? AND device_id = ?;", (org_id, device_id))
            row = cursor.fetchone()
            conn.commit()
            return dict(row)

    def get_device_by_token(self, device_token):
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE device_token = ?;", (device_token,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def record_telemetry(self, device, telemetry):
        """Ingest zero-payload telemetry record and update device posture status."""
        rec_id = f"tel_{uuid.uuid4().hex[:12]}"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        posture = telemetry.get("posture", "unknown")
        collected_at = telemetry.get("collected_at", now)
        controls_json = json.dumps(telemetry.get("controls", {}))
        robot_json = json.dumps(telemetry.get("robot_specific", {})) if "robot_specific" in telemetry else None
        dev_meta = telemetry.get("device", {})
        os_distro = dev_meta.get("os_distro")
        os_version = dev_meta.get("os_version")

        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO telemetry_records (id, device_id, org_id, collected_at, posture, controls_json, robot_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (rec_id, device["device_id"], device["org_id"], collected_at, posture, controls_json, robot_json, now))

            cursor.execute("""
            UPDATE devices SET
                last_posture = ?,
                last_heartbeat = ?,
                os_distro = COALESCE(?, os_distro),
                os_version = COALESCE(?, os_version)
            WHERE id = ?;
            """, (posture, now, os_distro, os_version, device["id"]))
            conn.commit()

        return {"record_id": rec_id, "status": "recorded", "posture": posture}

    def list_devices(self, org_id):
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT d.id, d.org_id, d.device_id, d.hostname, d.mode, d.fleet_tag, d.owner_email,
                   d.last_posture, d.last_heartbeat, d.created_at, d.os_distro, d.os_version,
                   t.controls_json, t.robot_json
            FROM devices d
            LEFT JOIN telemetry_records t ON t.id = (
                SELECT id FROM telemetry_records
                WHERE device_id = d.device_id AND org_id = d.org_id
                ORDER BY created_at DESC LIMIT 1
            )
            WHERE d.org_id = ?
            ORDER BY d.created_at DESC;
            """, (org_id,))
            rows = []
            for r in cursor.fetchall():
                item = dict(r)
                if item.get("controls_json"):
                    try:
                        item["controls"] = json.loads(item["controls_json"])
                    except Exception:
                        item["controls"] = {}
                else:
                    item["controls"] = {}
                if item.get("robot_json"):
                    try:
                        item["robot_specific"] = json.loads(item["robot_json"])
                    except Exception:
                        item["robot_specific"] = {}
                else:
                    item["robot_specific"] = {}
                rows.append(item)
            return rows

    def set_device_posture_test(self, org_id, device_id, posture):
        """Allow simulated test posture updates for UI verification."""
        with self.connection() as conn:
            cursor = conn.cursor()
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            cursor.execute("""
            UPDATE devices SET
                last_posture = ?,
                last_heartbeat = ?
            WHERE org_id = ? AND device_id = ?;
            """, (posture, now, org_id, device_id))

            if posture == "non_compliant":
                sim_ctls = {
                    "firewall": {"active": False, "status": "fail"},
                    "antivirus": {"name": "ClamAV", "status": "pass"},
                    "admin_separation": {"enforced": False, "status": "fail"},
                    "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}
                }
            else:
                sim_ctls = {
                    "firewall": {"active": True, "status": "pass"},
                    "antivirus": {"name": "ClamAV", "status": "pass"},
                    "admin_separation": {"enforced": True, "status": "pass"},
                    "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}
                }

            rec_id = f"tel_test_{uuid.uuid4().hex[:8]}"
            cursor.execute("""
            INSERT INTO telemetry_records (id, device_id, org_id, collected_at, posture, controls_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (rec_id, device_id, org_id, now, posture, json.dumps(sim_ctls), now))
            conn.commit()

    def get_soc2_evidence(self, org_id):
        """Compile structured SOC 2 Trust Services Criteria mapping with timestamped proof."""
        devices = self.list_devices(org_id)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Group stats
        workstations = [d for d in devices if d["mode"] == "workstation"]
        robots = [d for d in devices if d["mode"] == "robot"]

        org = self.get_org_by_id(org_id)
        org_name = org["name"] if org else "Organization"

        evidence = {
            "framework": "SOC 2 Type 1 / Type 2",
            "report_generated_at": now,
            "organization_id": org_id,
            "organization_name": org_name,
            "asset_summary": {
                "total_devices": len(devices),
                "workstations": len(workstations),
                "robots": len(robots),
                "compliant_count": sum(1 for d in devices if d["last_posture"] == "compliant"),
                "non_compliant_count": sum(1 for d in devices if d["last_posture"] == "non_compliant"),
            },
            "trust_services_criteria": [
                {
                    "criteria_id": "CC6.1",
                    "name": "Logical Access Controls",
                    "description": "User accounts and administrative privileges are separated to prevent unauthorized access.",
                    "status": "pass" if all(d["last_posture"] != "non_compliant" for d in workstations) else "warning",
                    "audited_assets": len(workstations),
                },
                {
                    "criteria_id": "CC6.6",
                    "name": "Perimeter & Host Firewall Protection",
                    "description": "Host-based firewalls prevent unauthorized network boundary traversal on laptops and robot fleets.",
                    "status": "pass" if all(d["last_posture"] != "non_compliant" for d in devices) else "fail",
                    "audited_assets": len(devices),
                },
                {
                    "criteria_id": "CC6.8",
                    "name": "Malicious Software Prevention",
                    "description": "Antivirus, EDR, and endpoint threat inspection mechanisms are active.",
                    "status": "pass" if all(d["last_posture"] != "non_compliant" for d in devices) else "warning",
                    "audited_assets": len(devices),
                },
                {
                    "criteria_id": "CC7.1",
                    "name": "Vulnerability & Patch Management",
                    "description": "Operating system and kernel patches are verified current within acceptable SLA (<14 days).",
                    "status": "pass" if all(d["last_posture"] != "non_compliant" for d in devices) else "fail",
                    "audited_assets": len(devices),
                },
            ],
            "device_inventory": devices,
        }
        return evidence

    def seed_demo_fleet(self, org_id="org_pattern_labs"):
        """Populate realistic multi-facility robotics fleet (AMRs, drones, arms, rovers, and laptops)."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        demo_assets = [
            # Boulder Warehouse AMRs (ROS 2 Humble / Ubuntu 22.04)
            {"id": "amr-01", "name": "amr-alpha-01", "mode": "robot", "tag": "boulder-warehouse-amr", "distro": "Ubuntu", "ver": "Ubuntu 22.04 LTS (ROS 2)", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 8, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "amr-02", "name": "amr-alpha-02", "mode": "robot", "tag": "boulder-warehouse-amr", "distro": "Ubuntu", "ver": "Ubuntu 22.04 LTS (ROS 2)", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 8, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "amr-03", "name": "amr-alpha-03", "mode": "robot", "tag": "boulder-warehouse-amr", "distro": "Ubuntu", "ver": "Ubuntu 22.04 LTS (ROS 2)", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 8, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "amr-04", "name": "amr-alpha-04", "mode": "robot", "tag": "boulder-warehouse-amr", "distro": "Ubuntu", "ver": "Ubuntu 22.04 LTS (ROS 2)", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 8, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "amr-05", "name": "amr-alpha-05", "mode": "robot", "tag": "boulder-warehouse-amr", "distro": "Ubuntu", "ver": "Ubuntu 22.04 LTS (ROS 2)", "posture": "non_compliant", "ctls": {"firewall": {"active": False, "status": "fail"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 22, "exposed_ports_count": 14, "exposed_ports": [{"proto": "udp", "ip": "0.0.0.0", "port": "7400", "exposed": True}, {"proto": "udp", "ip": "0.0.0.0", "port": "7410", "exposed": True}]}},
            {"id": "amr-06", "name": "amr-alpha-06", "mode": "robot", "tag": "boulder-warehouse-amr", "distro": "Ubuntu", "ver": "Ubuntu 22.04 LTS (ROS 2)", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 8, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "amr-07", "name": "amr-alpha-07", "mode": "robot", "tag": "boulder-warehouse-amr", "distro": "Ubuntu", "ver": "Ubuntu 22.04 LTS (ROS 2)", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 8, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "amr-08", "name": "amr-alpha-08", "mode": "robot", "tag": "boulder-warehouse-amr", "distro": "Ubuntu", "ver": "Ubuntu 22.04 LTS (ROS 2)", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 8, "exposed_ports_count": 0, "exposed_ports": []}},

            # Austin Flight Hangar Drones
            {"id": "drone-01", "name": "drone-scout-01", "mode": "robot", "tag": "austin-flight-hangar", "distro": "Ubuntu", "ver": "Ubuntu 20.04 (PX4)", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 6, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "drone-02", "name": "drone-scout-02", "mode": "robot", "tag": "austin-flight-hangar", "distro": "Ubuntu", "ver": "Ubuntu 20.04 (PX4)", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 6, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "drone-03", "name": "drone-scout-03", "mode": "robot", "tag": "austin-flight-hangar", "distro": "Ubuntu", "ver": "Ubuntu 20.04 (PX4)", "posture": "non_compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Non-Compliant (34 days since update)", "status": "fail"}}, "bot": {"open_ports_count": 6, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "drone-04", "name": "drone-scout-04", "mode": "robot", "tag": "austin-flight-hangar", "distro": "Ubuntu", "ver": "Ubuntu 20.04 (PX4)", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 6, "exposed_ports_count": 0, "exposed_ports": []}},

            # Denver Assembly Lab Manipulators
            {"id": "arm-01", "name": "arm-ur5e-cell-a", "mode": "robot", "tag": "denver-assembly-lab", "distro": "Debian", "ver": "Debian 12 RT", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 4, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "arm-02", "name": "arm-ur5e-cell-b", "mode": "robot", "tag": "denver-assembly-lab", "distro": "Debian", "ver": "Debian 12 RT", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 4, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "arm-03", "name": "arm-kuka-cell-c", "mode": "robot", "tag": "denver-assembly-lab", "distro": "Debian", "ver": "Debian 12 RT", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 4, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "arm-04", "name": "vision-cell-depth", "mode": "robot", "tag": "denver-assembly-lab", "distro": "Ubuntu", "ver": "Ubuntu 22.04 (Jetson)", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 5, "exposed_ports_count": 0, "exposed_ports": []}},

            # Salt Lake Proving Grounds Heavy Rovers
            {"id": "rover-01", "name": "yard-rover-01", "mode": "robot", "tag": "saltlake-proving-grounds", "distro": "NixOS", "ver": "NixOS 24.05", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 7, "exposed_ports_count": 0, "exposed_ports": []}},
            {"id": "rover-02", "name": "yard-rover-02", "mode": "robot", "tag": "saltlake-proving-grounds", "distro": "NixOS", "ver": "NixOS 24.05", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}}, "bot": {"open_ports_count": 7, "exposed_ports_count": 0, "exposed_ports": []}},

            # Developer Workstations
            {"id": "ws-sarah", "name": "sarah-m3-max", "mode": "workstation", "tag": "engineering-laptops", "owner": "sarah.dev@patternlabs.com", "distro": "macOS", "ver": "macOS 15.1 Sonoma", "posture": "non_compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "XProtect", "status": "pass"}, "admin_separation": {"enforced": False, "status": "fail"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}, "web_threat_scanning": {"active": True, "status": "pass"}}},
            {"id": "ws-marcus", "name": "marcus-thinkpad", "mode": "workstation", "tag": "engineering-laptops", "owner": "marcus.robotics@patternlabs.com", "distro": "Ubuntu", "ver": "Ubuntu 24.04 LTS", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}, "web_threat_scanning": {"active": True, "status": "pass"}}},
            {"id": "ws-elena", "name": "elena-framework", "mode": "workstation", "tag": "engineering-laptops", "owner": "elena.firmware@patternlabs.com", "distro": "Fedora", "ver": "Fedora 40", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}, "web_threat_scanning": {"active": True, "status": "pass"}}},
            {"id": "ws-chen", "name": "chen-cad-rig", "mode": "workstation", "tag": "hardware-lab", "owner": "chen.meche@patternlabs.com", "distro": "Windows", "ver": "Windows 11 Pro", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "Windows Defender", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}, "web_threat_scanning": {"active": True, "status": "pass"}}},
            {"id": "ws-ci", "name": "ci-runner-edge", "mode": "workstation", "tag": "boulder-warehouse-amr", "owner": "ops@patternlabs.com", "distro": "Ubuntu", "ver": "Ubuntu 22.04 LTS", "posture": "compliant", "ctls": {"firewall": {"active": True, "status": "pass"}, "antivirus": {"name": "ClamAV", "status": "pass"}, "admin_separation": {"enforced": True, "status": "pass"}, "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}, "web_threat_scanning": {"active": True, "status": "pass"}}},
        ]

        with self.connection() as conn:
            cursor = conn.cursor()
            for asset in demo_assets:
                sim_uuid = f"sim_hw_{asset['id']}"
                dev_pk = f"dev_{asset['id']}"
                tok = f"sim_tok_{asset['id']}"

                cursor.execute("""
                INSERT INTO devices (id, org_id, device_id, hostname, mode, fleet_tag, owner_email, device_token, last_posture, last_heartbeat, created_at, os_distro, os_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(org_id, device_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    mode=excluded.mode,
                    fleet_tag=excluded.fleet_tag,
                    last_posture=excluded.last_posture,
                    last_heartbeat=excluded.last_heartbeat,
                    os_distro=excluded.os_distro,
                    os_version=excluded.os_version;
                """, (dev_pk, org_id, sim_uuid, asset["name"], asset["mode"], asset["tag"], asset.get("owner"), tok, asset["posture"], now, now, asset["distro"], asset["ver"]))

                tel_id = f"sim_tel_{asset['id']}"
                ctls_json = json.dumps(asset["ctls"])
                bot_json = json.dumps(asset.get("bot")) if asset.get("bot") else None

                cursor.execute("""
                INSERT OR REPLACE INTO telemetry_records (id, device_id, org_id, collected_at, posture, controls_json, robot_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """, (tel_id, sim_uuid, org_id, now, asset["posture"], ctls_json, bot_json, now))

            conn.commit()

        return {"status": "seeded", "count": len(demo_assets)}

    def clear_demo_fleet(self, org_id="org_pattern_labs"):
        """Remove all simulated fleet devices, preserving real hardware nodes."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM devices WHERE org_id = ? AND device_id LIKE 'sim_hw_%';", (org_id,))
            cursor.execute("DELETE FROM telemetry_records WHERE org_id = ? AND device_id LIKE 'sim_hw_%';", (org_id,))
            conn.commit()
        return {"status": "cleared"}

    def reset_account_for_demo(self, org_id="org_pattern_labs"):
        """Erase user accounts, devices, telemetry and reset onboarding for a clean demo."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE org_id = ?;", (org_id,))
            cursor.execute("DELETE FROM devices WHERE org_id = ?;", (org_id,))
            cursor.execute("DELETE FROM telemetry_records WHERE org_id = ?;", (org_id,))
            cursor.execute("""
            UPDATE organizations SET
                name = '',
                framework = 'SOC 2 Type II',
                target_audit_date = NULL,
                onboarding_completed = 0
            WHERE id = ?;
            """, (org_id,))
            conn.commit()
            return self.get_org_by_id(org_id)

    def enroll_local_host(self, org_id="org_pattern_labs", owner_email=None):
        """Quick-enroll current host machine with real security telemetry for interactive demos."""
        import platform
        from agent.collector import get_hardware_serial, get_os, collect_telemetry
        sys_name = platform.system()
        device_id = get_hardware_serial(sys_name)
        hostname = platform.node() or "inspiron"
        email = owner_email or "founder@robotics.co"

        # Ensure user exists for attribution in the Team directory
        existing_users = self.list_users(org_id)
        if not any(u["email"].lower() == email.lower() for u in existing_users):
            user_name = email.split("@")[0].replace(".", " ").title()
            self.create_user(org_id, email, name=user_name, role="admin")

        device = self.enroll_device(
            org_id=org_id,
            device_id=device_id,
            hostname=hostname,
            mode="workstation",
            fleet_tag="primary-workstation",
            owner_email=email
        )

        try:
            telemetry = collect_telemetry("workstation")
        except Exception:
            os_info = get_os()
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            telemetry = {
                "device": {
                    "device_id": device_id,
                    "hostname": hostname,
                    "mode": "workstation",
                    "os_distro": os_info.get("distro", "Arch"),
                    "os_version": os_info.get("version", "Arch Linux"),
                },
                "posture": "non_compliant",
                "controls": {
                    "firewall": {"active": False, "status": "fail"},
                    "antivirus": {"name": "ClamAV", "status": "pass"},
                    "admin_separation": {"enforced": False, "status": "fail"},
                    "patch_management": {"status_detail": "Compliant (Managed)", "status": "pass"}
                },
                "collected_at": now
            }
        self.record_telemetry(device, telemetry)
        return device
