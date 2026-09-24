# Cyber Compliance for Robotics & Hardware Startups

Continuous SOC 2 compliance monitoring for robotics companies, hardware startups, and developer workstations. A specialized, lightweight alternative to Drata designed specifically for Linux, ROS/ROS 2, embedded fleets, and engineering laptops.

---

## Architecture Overview

- **Lightweight Unified Agent (`agent/`)**:
  - Python standard library only (zero external pip dependencies).
  - Inspects firewalls, listening ports, OS patch currency, antivirus/EDR, and admin privilege separation.
  - Supports both **Workstations** (Mac, Windows, Linux) and **Robot Fleets** (Ubuntu, NixOS, Yocto, ROS/ROS 2).
  - Built-in offline queueing: buffers heartbeats locally when robots lose Wi-Fi/LTE connectivity and automatically resynchronizes once reconnected.
  - **Zero-Payload Guarantee**: Never accesses or transmits camera feeds, LiDAR data, SLAM maps, or proprietary code.
- **Central Compliance & Auditor Server (`server/`)**:
  - Zero-dependency REST API for headless device enrollment (`/api/v1/enroll`) and telemetry ingestion (`/api/v1/telemetry`).
  - Automated SOC 2 Trust Services Criteria mapping (`/api/v1/evidence/soc2`) ready for CPA auditors (CC6.1, CC6.6, CC6.8, CC7.1).
- **Legal Liability Shield (`legal/`)**:
  - Master Services Agreement template ([MASTER_SERVICES_AGREEMENT.md](file:///home/alden/cyber_compliance/legal/MASTER_SERVICES_AGREEMENT.md)) with 12-month fee liability caps, audit disclaimers, and robotics hardware waivers.

## Usage (Workstation Audit)

### For Linux/Mac OS:
```bash
curl -sSL https://raw.githubusercontent.com/alden4444/cyber_compliance/main/pc_audit.py -o /tmp/audit.py && python3 /tmp/audit.py
```

### For Windows (PowerShell as admin):
```powershell
irm https://raw.githubusercontent.com/alden4444/cyber_compliance/main/pc_audit.py -OutFile "$env:TEMP\audit.py"; python "$env:TEMP\audit.py"
```

---

## Fleet & SaaS Platform Quickstart

### 1. Run Workstation Audit (Interactive / CLI)

```bash
# Workstation audit summary
python3 -m agent.cli --mode workstation --fast

# Output structured zero-payload metadata JSON
python3 -m agent.cli --mode workstation --json
```

### 2. Run Robot Fleet Audit (Headless)

```bash
# Robot fleet inspection (open ports, exposed interfaces, iptables, patch currency)
python3 -m agent.cli --mode robot --fast

# Output robot telemetry JSON
python3 -m agent.cli --mode robot --json
```

### 3. Continuous Background Daemon (`systemd`)

Run the agent in continuous monitoring mode (e.g. heartbeat every 6 hours):

```bash
# Run daemon in foreground
python3 -m agent.cli --mode robot --daemon --interval 21600

# Install as systemd service on Linux/Robots (requires sudo)
sudo python3 -m agent.cli --mode robot --install-service
```

---

## Central SaaS Server & Auditor API

Start the local API server (SQLite multi-tenant backend, zero pip dependencies):

```bash
python3 -m server.app --port 8000
```

### Endpoints:
- `GET  /api/v1/health` - Server health check.
- `POST /api/v1/enroll` - Enroll a new robot or laptop with an organization token.
- `POST /api/v1/telemetry` - Receive heartbeat telemetry from enrolled devices.
- `GET  /api/v1/devices` - List enrolled fleet and workstation inventory with compliance posture.
- `GET  /api/v1/evidence/soc2` - Download structured SOC 2 Trust Services Criteria evidence bundle for independent auditors.

### Enroll a Device via CLI:
```bash
python3 -m agent.cli --enroll \
  --api-url "http://localhost:8000" \
  --org-token "org_demo_pattern_labs_2026" \
  --mode robot \
  --fleet-tag "boulder-depot-fleet"
```

---

## Running Automated Tests

```bash
# Run all agent and integration tests
python3 -m unittest discover tests

# Run legacy pc_audit tests
python3 -m unittest test_pc_audit.py
```

---

## Legacy Quickstart (Backwards Compatibility)

For existing manual audit runs:
```bash
# Linux / macOS
sudo python3 pc_audit.py

# Robot inspection
python3 bot_audit.py
```
