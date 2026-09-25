"""Unified CLI entrypoint for Cyber Compliance Agent.

Supports interactive desktop audits, headless robot audits, continuous daemon operation,
and platform enrollment.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import sys

from agent.client import ComplianceClient
from agent.collector import (
    collect_telemetry,
    get_friendly_hostname,
    get_hardware_serial,
    get_os,
    is_admin,
)
from agent.daemon import ComplianceDaemon, generate_systemd_unit


def print_banner(mode, system):
    print("=" * 60)
    print(f"   CYBER COMPLIANCE AGENT v1.0.0 ({mode.upper()} - {system.upper()})")
    print("=" * 60)


def print_human_table(telemetry):
    print("\n" + "=" * 60)
    print(f"      COMPLIANCE CHECK SUMMARY ({telemetry['device']['mode'].upper()})")
    print("=" * 60)
    dev = telemetry["device"]
    print(f"{'Device ID (Serial)':<26}: {dev['device_id']}")
    print(f"{'OS Distribution':<26}: {dev['os_distro']} ({dev['os_version']})")
    print(f"{'Host Name':<26}: {dev['hostname']}")

    print("-" * 60)
    for name, ctl in telemetry["controls"].items():
        label = name.replace("_", " ").title()
        status = ctl.get("status", "unknown").upper()
        detail = ctl.get("name") or ctl.get("status_detail") or ("Active" if ctl.get("active") or ctl.get("enforced") else "Inactive")
        tag = " [OK]" if status == "PASS" else " [FAIL]"
        print(f"{label:<26}: {detail}{tag}")

    if "robot_specific" in telemetry:
        print("-" * 60)
        bot = telemetry["robot_specific"]
        print(f"{'Open Ports (Total)':<26}: {bot['open_ports_count']}")
        print(f"{'Exposed to Public (0.0.0.0)':<26}: {bot['exposed_ports_count']}")
        print(f"{'Default Passwords':<26}: {bot['default_passwords_check']}")

    print("=" * 60)
    posture_tag = telemetry.get("posture", "unknown").upper()
    print(f"OVERALL POSTURE STATUS    : {posture_tag}")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Cyber Compliance Endpoint & Robot Fleet Agent")
    parser.add_argument("--mode", choices=["workstation", "robot"], default="workstation",
                        help="Operation mode: 'workstation' for employee PCs, 'robot' for edge/fleet nodes")
    parser.add_argument("--daemon", action="store_true",
                        help="Run continuously in background daemon mode")
    parser.add_argument("--interval", type=int, default=21600,
                        help="Heartbeat sync interval in seconds (default: 21600s / 6 hours)")
    parser.add_argument("--json", action="store_true",
                        help="Output structured zero-payload metadata JSON to stdout")
    parser.add_argument("--audit-only", "--test", action="store_true",
                        help="Perform single audit inspection without prompting or enrolling")
    parser.add_argument("--fast", action="store_true",
                        help="Execute checks without human-readable delays")
    parser.add_argument("--api-url", type=str, default=None,
                        help="Central SaaS API base URL (e.g. https://api.compliance.io)")
    parser.add_argument("--token", type=str, default=None,
                        help="Pre-configured device authentication token")
    parser.add_argument("--enroll", action="store_true",
                        help="Enroll this node with the SaaS platform using an organization token")
    parser.add_argument("--org-token", type=str, default=None,
                        help="Organization enrollment secret")
    parser.add_argument("--fleet-tag", type=str, default=None,
                        help="Fleet group or facility tag for robot assets (e.g. boulder-warehouse-a)")
    parser.add_argument("--owner-email", type=str, default=None,
                        help="Employee email address for workstation attribution")
    parser.add_argument("--install-service", action="store_true",
                        help="Install and enable systemd background service on Linux")

    args = parser.parse_args()
    system = get_os()

    # Systemd Service Installation Helper
    if args.install_service:
        if not is_admin():
            print("Error: --install-service requires root/sudo privileges.", file=sys.stderr)
            sys.exit(1)
        unit_content = generate_systemd_unit(mode=args.mode)
        unit_path = Path("/etc/systemd/system/cyber-compliance.service")
        unit_path.write_text(unit_content)
        print(f"Systemd service installed to {unit_path}.")
        print("Enable and start with:")
        print("  sudo systemctl daemon-reload")
        print("  sudo systemctl enable --now cyber-compliance")
        return

    # Platform Enrollment Flow
    if args.enroll:
        if not args.api_url or not args.org_token:
            print("Error: --enroll requires both --api-url and --org-token.", file=sys.stderr)
            sys.exit(1)
        client = ComplianceClient(api_url=args.api_url)
        device_id = get_hardware_serial(system)
        hostname = get_friendly_hostname(owner_email=args.owner_email, mode=args.mode)
        print(f"Enrolling device '{hostname}' ({device_id}) with {args.api_url}...")
        result = client.enroll(
            api_url=args.api_url,
            org_token=args.org_token,
            device_id=device_id,
            hostname=hostname,
            mode=args.mode,
            fleet_tag=args.fleet_tag,
            owner_email=args.owner_email,
        )
        if "error" in result:
            print(f"Enrollment failed: {result['error']}", file=sys.stderr)
            sys.exit(1)
        print("Device enrollment successful!")
        print(f"Device Token saved to: {client.config_path}")
        return

    # Daemon Execution Mode
    if args.daemon:
        daemon = ComplianceDaemon(
            mode=args.mode,
            interval_seconds=args.interval,
            api_url=args.api_url,
            device_token=args.token,
        )
        daemon.start()
        return

    # Single Inspection / CLI Mode
    telemetry = collect_telemetry(mode=args.mode)

    if args.json:
        print(json.dumps(telemetry, indent=2))
        return

    print_banner(args.mode, system)
    print_human_table(telemetry)

    # If configured with API, dispatch heartbeat
    client = ComplianceClient(api_url=args.api_url, device_token=args.token)
    if client.api_url and client.device_token:
        res = client.send_telemetry(telemetry)
        print(f"Telemetry Dispatch Status: {res.get('status', 'unknown').upper()}")


if __name__ == "__main__":
    main()
