"""Database management for Cyber Compliance platform using SQLite3."""

import contextlib
import json
from pathlib import Path
import sqlite3
import time
import uuid


DEFAULT_POLICIES = [
    {
        "key": "infosec",
        "title": "Information Security Policy",
        "category": "CC1.1, CC1.2, CC5.1",
        "summary": "Establishes baseline encryption, MFA, workstation currency, and cloud infrastructure security standards.",
        "content": """# Information Security Policy (SOC 2 CC1.1, CC5.1)

1. Purpose & Scope: This policy applies to all personnel, workstations, cloud infrastructure, and repositories within the organization.
2. Endpoint Encryption: All corporate workstations, laptops, and edge devices containing source code or cloud access must enforce full disk encryption (LUKS, FileVault, or BitLocker).
3. Access Controls: Multi-factor authentication (MFA) is strictly mandatory on all identity providers, GitHub repositories, and cloud management consoles (AWS/GCP).
4. Patch Management: Operating systems and software packages must be updated within a 14-day SLA of security releases.
5. Code Security: Direct pushes to main branches are prohibited; code reviews and automated security scans are enforced before production deployments."""
    },
    {
        "key": "asset_management",
        "title": "Hardware Asset Management Policy",
        "category": "CC6.1, ISO 27001 A.8.1",
        "summary": "Governs tracking, attribution, and secure decommissioning of developer workstations and robot nodes.",
        "content": """# Hardware Asset Management Policy (SOC 2 CC6.1)

1. Purpose & Scope: Governs all physical computing hardware, including developer workstations, field edge nodes, single-board computers, and autonomous robotics fleet units.
2. Central Inventory: Every hardware device must be uniquely identified by hardware UUID or machine serial and attributed to a verified team member or fleet facility.
3. Zero-Payload Isolation: Compliance collectors operating on hardware assets must restrict telemetry to operational and security metadata only. No camera video, point clouds, SLAM maps, or customer proprietary data may be collected.
4. Disposal & Reassignment: Hardware retired from production must undergo cryptographic data sanitization before reassignment or disposal."""
    },
    {
        "key": "access_control",
        "title": "Logical Access & Privilege Policy",
        "category": "CC6.1, CC6.2, CC6.3",
        "summary": "Enforces principle of least privilege, strict admin separation, and 24h offboarding revocation.",
        "content": """# Logical Access & Privilege Separation Policy (SOC 2 CC6.1, CC6.2)

1. Principle of Least Privilege: Personnel are granted access strictly necessary to perform assigned engineering and operational duties.
2. Administrator Separation: Daily user accounts on developer workstations and field nodes must not operate with persistent unrestricted root privileges. Root escalation requires explicit password authentication.
3. Access Reviews: Logical access permissions are reviewed quarterly by the Security Lead or System Administrator.
4. Offboarding SLA: Access to all cloud services, repositories, and device management tokens must be revoked within 24 hours of personnel termination."""
    },
    {
        "key": "incident_response",
        "title": "Incident Response & Operational Safety Plan",
        "category": "CC7.3, CC7.4",
        "summary": "Standard operating procedures for security incidents, stolen hardware, and robot fleet network isolation.",
        "content": """# Incident Response & Operational Safety Plan (SOC 2 CC7.3, CC7.4)

1. Incident Classification: Security incidents are classified as Low (single endpoint alert), Medium (potential credential compromise), or High (unauthorized production access or lost hardware with active session tokens).
2. Containment Protocol: In the event of a lost device or compromised edge node, the administrator must immediately revoke the device bearer token and apply host firewall drop rules.
3. Notification SLA: Affected customers and external regulatory authorities will be notified within 72 hours of verified security breaches involving sensitive data.
4. Post-Incident Review: A written post-mortem analyzing root cause, blast radius, and preventative controls must be completed within 5 business days."""
    }
]


COMPLIANCE_FRAMEWORKS = {
    "soc2": {
        "id": "soc2",
        "code": "SOC 2 Type II",
        "name": "SOC 2 Type II (AICPA Trust Services Criteria)",
        "authority": "American Institute of CPAs (AICPA)",
        "badge": "SOC 2 Type II",
        "regulatory_ref": "AICPA TSP Section 100",
        "criteria": [
            {
                "id": "CC1.1",
                "name": "Control Environment & Security Governance",
                "description": "Formally approved written policies governing info security, access, and asset management.",
                "control_key": "policies"
            },
            {
                "id": "CC6.1",
                "name": "Logical Access Controls & Privilege Separation",
                "description": "User accounts and administrative privileges are separated to prevent unauthorized access.",
                "control_key": "admin_separation"
            },
            {
                "id": "CC6.6",
                "name": "Perimeter & Host Firewall Protection",
                "description": "Host-based firewalls prevent unauthorized network boundary traversal on laptops and edge devices.",
                "control_key": "firewall"
            },
            {
                "id": "CC6.8",
                "name": "Malicious Software & Web Threat Prevention",
                "description": "Antivirus, EDR, and domain-level protective threat filtering mechanisms are active.",
                "control_key": "antivirus"
            },
            {
                "id": "CC7.1",
                "name": "Vulnerability & Patch Management",
                "description": "Operating system and kernel patches are verified current within acceptable SLA (<14 days).",
                "control_key": "patch_management"
            }
        ]
    },
    "iso27001": {
        "id": "iso27001",
        "code": "ISO/IEC 27001:2022",
        "name": "ISO/IEC 27001:2022 Information Security Management",
        "authority": "International Organization for Standardization (ISO)",
        "badge": "ISO 27001:2022",
        "regulatory_ref": "ISO/IEC 27001:2022 Annex A Controls",
        "criteria": [
            {
                "id": "A.5.1",
                "name": "Policies for Information Security",
                "description": "Information security policy and topic-specific policies are defined and approved by management.",
                "control_key": "policies"
            },
            {
                "id": "A.5.15",
                "name": "Access Control & Privilege Management",
                "description": "Allocation and use of privileged access rights are restricted and strictly controlled.",
                "control_key": "admin_separation"
            },
            {
                "id": "A.8.20",
                "name": "Network Security & Boundary Segregation",
                "description": "Networks and network devices are secured, managed, and controlled to protect information.",
                "control_key": "firewall"
            },
            {
                "id": "A.8.7",
                "name": "Protection Against Malware & Endpoint Security",
                "description": "Protection against malware is implemented and supported by appropriate threat prevention.",
                "control_key": "antivirus"
            },
            {
                "id": "A.8.8",
                "name": "Management of Technical Vulnerabilities",
                "description": "Information about technical vulnerabilities is obtained in a timely fashion and patched.",
                "control_key": "patch_management"
            }
        ]
    },
    "hipaa": {
        "id": "hipaa",
        "code": "HIPAA Security Rule",
        "name": "HIPAA Security Rule (45 CFR § 164.308 / § 164.312)",
        "authority": "U.S. Dept of Health & Human Services (HHS)",
        "badge": "HIPAA Security",
        "regulatory_ref": "45 CFR Part 160 & Part 164 Subparts A & C",
        "criteria": [
            {
                "id": "§ 164.308(a)(1)(i)",
                "name": "Security Management Process & Policies",
                "description": "Implement policies and procedures to prevent, detect, contain, and correct security violations.",
                "control_key": "policies"
            },
            {
                "id": "§ 164.312(a)(1)",
                "name": "Access Control & Unique User Identification",
                "description": "Assign unique name/number for identifying and tracking user identity and separate admin privileges.",
                "control_key": "admin_separation"
            },
            {
                "id": "§ 164.312(e)(1)",
                "name": "Transmission Security & Boundary Protection",
                "description": "Guard against unauthorized network access to ePHI transmitted over electronic communications.",
                "control_key": "firewall"
            },
            {
                "id": "§ 164.312(c)(1)",
                "name": "Data Integrity & Malicious Software Protection",
                "description": "Implement procedures for guarding against, detecting, and reporting malicious software.",
                "control_key": "antivirus"
            },
            {
                "id": "§ 164.308(a)(1)(ii)(B)",
                "name": "Risk Management & Vulnerability Mitigation",
                "description": "Implement security measures sufficient to reduce risks and vulnerabilities to a reasonable level.",
                "control_key": "patch_management"
            }
        ]
    },
    "nist800_171": {
        "id": "nist800_171",
        "code": "NIST SP 800-171 / CMMC",
        "name": "NIST SP 800-171 Rev 2 / CMMC Level 2",
        "authority": "National Institute of Standards and Technology (NIST)",
        "badge": "NIST SP 800-171",
        "regulatory_ref": "NIST Special Publication 800-171 Rev 2 / DFARS 252.204-7012",
        "criteria": [
            {
                "id": "3.1.2",
                "name": "Organizational Security Policies & Governance",
                "description": "Establish and maintain baseline organizational security policies and operational controls.",
                "control_key": "policies"
            },
            {
                "id": "3.1.1",
                "name": "Authorized Access Enforcement & Least Privilege",
                "description": "Limit system access to authorized users and processes acting on behalf of authorized users.",
                "control_key": "admin_separation"
            },
            {
                "id": "3.13.1",
                "name": "Boundary Protection & Interface Segregation",
                "description": "Monitor, control, and protect organizational communications at external boundaries and key internal boundaries.",
                "control_key": "firewall"
            },
            {
                "id": "3.14.2",
                "name": "Malicious Code Protection & Threat Updating",
                "description": "Provide protection from malicious code at system entry and exit points and update signatures.",
                "control_key": "antivirus"
            },
            {
                "id": "3.14.1",
                "name": "System Flaw Remediation & Timely Patching",
                "description": "Identify, report, and correct system flaws in a timely manner according to risk SLAs.",
                "control_key": "patch_management"
            }
        ]
    },
    "cra": {
        "id": "cra",
        "code": "EU Cyber Resilience Act",
        "name": "EU Cyber Resilience Act (CRA) / ETSI EN 303 645",
        "authority": "European Union / European Standards Organisation",
        "badge": "EU CRA / ETSI",
        "regulatory_ref": "Regulation (EU) 2024/2847 / ETSI EN 303 645 V2.1.1",
        "criteria": [
            {
                "id": "5.13-1",
                "name": "Documentation & Security Policy Maintenance",
                "description": "Maintain technical documentation, statutory security policies, and vulnerability disclosure policies.",
                "control_key": "policies"
            },
            {
                "id": "5.1-1",
                "name": "No Default Universal Passwords & Privilege Escalation",
                "description": "All device passwords must be unique or set by user, and root escalation must be verified.",
                "control_key": "admin_separation"
            },
            {
                "id": "5.5-1",
                "name": "Network Interface Minimization & Perimeter Firewall",
                "description": "Minimize unnecessary exposed network ports and enforce default incoming drop rules.",
                "control_key": "firewall"
            },
            {
                "id": "5.3-2",
                "name": "Software Integrity & Automated Threat Defense",
                "description": "Protect against unauthorized modification of software and enforce endpoint malware protection.",
                "control_key": "antivirus"
            },
            {
                "id": "5.2-1",
                "name": "Vulnerability Management & Timely Patch Updates",
                "description": "Continuously identify security vulnerabilities and deploy security updates without delay.",
                "control_key": "patch_management"
            }
        ]
    }
}


class ComplianceDatabase:
    """Manages multi-tenant organizations, enrolled devices, and telemetry audit logs."""

    def __init__(self, db_path="compliance.db"):
        self.db_path = Path(db_path)
        self.init_db()

    @contextlib.contextmanager
    def connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=ON;")
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

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                policy_key TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                summary TEXT NOT NULL,
                version TEXT NOT NULL DEFAULT '1.0',
                status TEXT NOT NULL DEFAULT 'draft',
                content TEXT NOT NULL,
                adopted_by TEXT,
                adopted_at TEXT,
                FOREIGN KEY (org_id) REFERENCES organizations(id),
                UNIQUE(org_id, policy_key)
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

            # Ensure framework, fleet_scope and onboarding columns exist on organizations
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
            try:
                cursor.execute("ALTER TABLE organizations ADD COLUMN fleet_scope TEXT DEFAULT 'workstations_only';")
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

    def set_fleet_scope(self, org_id, fleet_scope):
        """Update organization compliance fleet scope ('workstations_only' vs 'full_fleet')."""
        if fleet_scope not in ["workstations_only", "full_fleet"]:
            fleet_scope = "workstations_only"
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE organizations SET fleet_scope = ? WHERE id = ?;", (fleet_scope, org_id))
            conn.commit()
            return self.get_org_by_id(org_id)

    def seed_default_policies(self, org_id="org_pattern_labs"):
        """Seed the 4 mandatory SOC 2 compliance policies for an organization if not present."""
        with self.connection() as conn:
            cursor = conn.cursor()
            for p in DEFAULT_POLICIES:
                pk = f"pol_{uuid.uuid4().hex[:10]}"
                cursor.execute("""
                INSERT INTO policies (id, org_id, policy_key, title, category, summary, content, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'draft')
                ON CONFLICT(org_id, policy_key) DO NOTHING;
                """, (pk, org_id, p["key"], p["title"], p["category"], p["summary"], p["content"]))
            conn.commit()

    def list_policies(self, org_id):
        """List all core compliance policies with adoption status."""
        self.seed_default_policies(org_id)
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM policies WHERE org_id = ? ORDER BY id ASC;", (org_id,))
            return [dict(r) for r in cursor.fetchall()]

    def adopt_policy(self, org_id, policy_key, user_name="Executive Leadership"):
        """Sign and adopt a policy on behalf of the company executive leadership."""
        self.seed_default_policies(org_id)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE policies SET
                status = 'adopted',
                adopted_by = ?,
                adopted_at = ?
            WHERE org_id = ? AND policy_key = ?;
            """, (user_name, now, org_id, policy_key))
            conn.commit()
            cursor.execute("SELECT * FROM policies WHERE org_id = ? AND policy_key = ?;", (org_id, policy_key))
            row = cursor.fetchone()
            return dict(row) if row else None

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

    def list_frameworks(self):
        """Return metadata for all supported compliance frameworks."""
        return [
            {
                "id": f["id"],
                "code": f["code"],
                "name": f["name"],
                "authority": f["authority"],
                "badge": f["badge"],
                "regulatory_ref": f["regulatory_ref"],
                "criteria_count": len(f["criteria"])
            }
            for f in COMPLIANCE_FRAMEWORKS.values()
        ]

    def get_framework_evidence(self, org_id, framework_id=None):
        """Compile structured compliance criteria mapping with timestamped proof for any framework."""
        devices = self.list_devices(org_id)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Group stats
        workstations = [d for d in devices if d["mode"] == "workstation"]
        robots = [d for d in devices if d["mode"] == "robot"]

        org = self.get_org_by_id(org_id)
        org_name = org["name"] if org else "Organization"
        fleet_scope = (org.get("fleet_scope") if org else None) or "workstations_only"

        # Resolve requested framework
        if not framework_id:
            raw_fw = (org.get("framework") if org else "") or "soc2"
            framework_id = "soc2"
            for fid, fdef in COMPLIANCE_FRAMEWORKS.items():
                if fid == raw_fw.lower() or fdef["code"].lower() in raw_fw.lower() or fid in raw_fw.lower():
                    framework_id = fid
                    break

        fw_def = COMPLIANCE_FRAMEWORKS.get(framework_id, COMPLIANCE_FRAMEWORKS["soc2"])

        audited_scope_devices = workstations if fleet_scope == "workstations_only" else devices
        audited_pass_count = sum(1 for d in audited_scope_devices if d["last_posture"] == "compliant")
        audited_fail_count = sum(1 for d in audited_scope_devices if d["last_posture"] == "non_compliant")

        policies = self.list_policies(org_id)
        adopted_policies_count = sum(1 for p in policies if p["status"] == "adopted")

        # Dynamically build mapped criteria
        criteria_list = []
        for item in fw_def["criteria"]:
            ckey = item.get("control_key")
            if ckey == "policies":
                crit_status = "pass" if adopted_policies_count >= 4 else "warning"
                crit_assets = adopted_policies_count
            elif ckey == "admin_separation":
                crit_status = "pass" if all(d["last_posture"] != "non_compliant" for d in workstations) else "warning"
                crit_assets = len(workstations)
            elif ckey == "firewall":
                crit_status = "pass" if all(d["last_posture"] != "non_compliant" for d in audited_scope_devices) else "fail"
                crit_assets = len(audited_scope_devices)
            elif ckey == "antivirus":
                crit_status = "pass" if all(d["last_posture"] != "non_compliant" for d in audited_scope_devices) else "warning"
                crit_assets = len(audited_scope_devices)
            elif ckey == "patch_management":
                crit_status = "pass" if all(d["last_posture"] != "non_compliant" for d in audited_scope_devices) else "fail"
                crit_assets = len(audited_scope_devices)
            else:
                crit_status = "pass"
                crit_assets = len(audited_scope_devices)

            criteria_list.append({
                "criteria_id": item["id"],
                "name": item["name"],
                "description": item["description"],
                "control_key": ckey,
                "status": crit_status,
                "audited_assets": crit_assets,
                "framework_id": fw_def["id"],
                "framework_name": fw_def["name"],
                "authority": fw_def["authority"]
            })

        evidence = {
            "framework": fw_def["code"],
            "framework_id": fw_def["id"],
            "framework_name": fw_def["name"],
            "authority": fw_def["authority"],
            "regulatory_ref": fw_def["regulatory_ref"],
            "report_generated_at": now,
            "organization_id": org_id,
            "organization_name": org_name,
            "fleet_scope": fleet_scope,
            "fleet_scope_label": "Workstations Only (Pattern Labs Mode)" if fleet_scope == "workstations_only" else "Full Robotics Fleet Mode",
            "asset_summary": {
                "total_devices": len(devices),
                "workstations": len(workstations),
                "robots": len(robots),
                "audited_in_scope_devices": len(audited_scope_devices),
                "compliant_count": audited_pass_count,
                "non_compliant_count": audited_fail_count,
                "overall_posture": "compliant" if audited_fail_count == 0 and len(audited_scope_devices) > 0 else "action_required"
            },
            "policy_summary": {
                "total_policies": len(policies),
                "adopted_count": adopted_policies_count,
                "all_adopted": adopted_policies_count == len(policies)
            },
            "criteria": criteria_list,
            "trust_services_criteria": criteria_list,  # Backwards compatibility alias
            "policies": policies,
            "device_inventory": devices,
            "workstations": workstations,
            "hardware_asset_inventory": robots if fleet_scope == "workstations_only" else []
        }
        return evidence

    def get_soc2_evidence(self, org_id, framework_id=None):
        """Compile structured compliance criteria mapping (defaults to SOC 2 or org's target)."""
        return self.get_framework_evidence(org_id, framework_id=framework_id)

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
