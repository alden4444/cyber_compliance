#!/usr/bin/env python3

import json
from pathlib import Path
import platform
import subprocess
import time
import urllib.request

def get_data():
    data = {
        "node": platform.node(),
        "release": platform.release(),
        "machine_id": "unknown",
        "distro": "unknown"
    }

    try:
        with open("/etc/machine-id") as f:
            data["machine_id"] = f.read().strip()
    except Exception:
        pass

    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("NAME="):
                    data["distro"] = line.strip().split("=")[1].strip('"\'')
                    break
    except Exception:
        pass

    return data


def get_interfaces():
    interfaces = []
    try:
        raw = subprocess.check_output(["ip", "-j", "addr"], text=True)
        data = json.loads(raw)

        for iface in data:
            name = iface.get("ifname", "unknown")
            ips = []

            for addr in iface.get("addr_info", []):
                if addr.get("family") == "inet":
                    ips.append(addr.get("local"))

            interfaces.append({"name": name, "ips": ips})
    except Exception:
        pass

    return interfaces


def get_open_ports():
    ports = []
    try:
        raw = subprocess.check_output(["ss", "-tulnH"], text=True)

        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                protocol = parts[0]
                socket = parts[4]
                ip, port = socket.rsplit(":", 1)
                is_exposed = ip in ["0.0.0.0", "::", "*"]

                ports.append({
                    "proto": protocol,
                    "ip": ip,
                    "port": port,
                    "exposed": is_exposed
                })
    except Exception:
        pass

    return ports


def get_firewall_status():
    try:
        raw = subprocess.check_output(["iptables", "-S", "INPUT"], text=True)
        if "nixos-fw" in raw:
            return "active"
        return "inactive"
    except Exception:
        return "inactive"


def check_os_patch_status():
    try:
        profile_path = Path("/nix/var/nix/profiles/system")
        if profile_path.exists():
            last_built = profile_path.stat().st_mtime
            age_days = (time.time() - last_built) / 86400
            if age_days <= 14:
                return "Yes (<14d rebuild)"
            return f"Fail (Rebuild {int(age_days)}d ago)"

        raw = subprocess.check_output(["nixos-version"], text=True).strip()
        return f"Yes ({raw.split()[0]})"
    except Exception:
        return "Unknown"


def check_default_passwords():
    try:
        with open("/etc/shadow", "r") as f:
            shadow_lines = f.readlines()

        default_accounts = ["root", "nixos", "admin"]
        for line in shadow_lines:
            parts = line.strip().split(":")
            user = parts[0]
            pwd_hash = parts[1] if len(parts) > 1 else ""

            if user in default_accounts:
                if pwd_hash.startswith("!") or pwd_hash.startswith("*"):
                    continue
                if len(pwd_hash) > 10:
                    continue
                return f"Fail ({user} has default/empty password)"

        return "Yes (Key-only/Hashed)"
    except PermissionError:
        return "Manual check (requires sudo)"
    except Exception:
        return "Unknown"

def main():
    report = {
        "identity": get_data(),
        "interfaces": get_interfaces(),
        "open_ports": get_open_ports(),
        "firewall": get_firewall_status(),
        "os_patch_status": check_os_patch_status(),
        "default_passwords": check_default_passwords()
    }
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
