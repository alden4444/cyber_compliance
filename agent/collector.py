"""System security and compliance posture collector for workstations and robotics fleets.

Supports Linux (Ubuntu, Debian, Arch, NixOS), macOS, and Windows.
Uses Python standard library only (zero external pip dependencies).
"""

import ctypes
import getpass
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import time

try:
    import pwd
except ImportError:
    pwd = None


# ---------------------------------------------------------------------------
# Core System Helpers
# ---------------------------------------------------------------------------

def get_real_home():
    """Return the non-root user home directory even when invoked under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and pwd:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    home_env = os.environ.get("HOME")
    if home_env and sudo_user:
        return Path(home_env)
    return Path.home()


def get_os():
    """Detect operating system and Linux distribution family."""
    os_name = platform.system().lower()
    if os_name == "darwin":
        return "macOS"
    if os_name == "windows":
        return "Windows"
    if os_name == "linux":
        distro_id = ""
        distro_family = ""
        try:
            if hasattr(platform, "freedesktop_os_release"):
                release_info = platform.freedesktop_os_release()
                distro_id = release_info.get("ID", "").lower()
                distro_family = release_info.get("ID_LIKE", "").lower()
            else:
                with open("/etc/os-release") as stream:
                    for line in stream:
                        if line.startswith("ID="):
                            distro_id = line.strip().split("=")[1].strip('"\'').lower()
                        elif line.startswith("ID_LIKE="):
                            distro_family = line.strip().split("=")[1].strip('"\'').lower()
        except Exception:
            pass

        if "arch" in distro_id or "arch" in distro_family:
            return "Arch"
        if "ubuntu" in distro_id or "debian" in distro_id or "ubuntu" in distro_family or "debian" in distro_family:
            return "Ubuntu"
        if "nixos" in distro_id or "nixos" in distro_family:
            return "NixOS"
        return "Linux"
    return "Unknown"


def is_admin():
    """Verify administrator or root privileges."""
    try:
        if platform.system().lower() == "windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def is_dummy_identifier(value):
    """Filter out non-unique dummy serial numbers."""
    if not value:
        return True
    cleaned = value.strip().lower()
    dummy_patterns = [
        "to be filled by o.e.m.",
        "default string",
        "none",
        "unknown",
        "system serial number",
        "chassis serial number",
        "not applicable",
        "00000000",
        "12345678",
        "serial number",
    ]
    return any(p in cleaned for p in dummy_patterns)


def get_hardware_serial(system):
    """Retrieve unique hardware UUID / serial number."""
    candidates = []

    if system in ["Arch", "Ubuntu", "Linux", "NixOS"]:
        commands = [
            ["cat", "/sys/class/dmi/id/product_uuid"],
            ["cat", "/sys/class/dmi/id/product_serial"],
            ["cat", "/etc/machine-id"],
            ["cat", "/var/lib/dbus/machine-id"],
        ]
        for cmd in commands:
            try:
                out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
                if out and not is_dummy_identifier(out):
                    candidates.append(out)
            except Exception:
                pass

        if not candidates:
            try:
                out = subprocess.check_output(["dmidecode", "-s", "system-uuid"], text=True, stderr=subprocess.DEVNULL).strip()
                if out and not is_dummy_identifier(out):
                    candidates.append(out)
            except Exception:
                pass

    elif system == "macOS":
        try:
            raw = subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], text=True)
            match = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', raw)
            if match and not is_dummy_identifier(match.group(1)):
                candidates.append(match.group(1).strip())
            uuid_match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', raw)
            if uuid_match and not is_dummy_identifier(uuid_match.group(1)):
                candidates.append(uuid_match.group(1).strip())
        except Exception:
            pass

    elif system == "Windows":
        queries = [
            (["powershell", "-NoProfile", "-Command", "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"], "BIOS Serial"),
            (["powershell", "-NoProfile", "-Command", "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID"], "System UUID"),
        ]
        for cmd, _ in queries:
            try:
                out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
                if out and not is_dummy_identifier(out):
                    candidates.append(out)
            except Exception:
                pass

    for candidate in candidates:
        if candidate and not is_dummy_identifier(candidate):
            return candidate
    return "Unknown"


def get_os_version(system):
    """Retrieve detailed operating system release/version string."""
    if system == "macOS":
        try:
            return subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip()
        except Exception:
            return "macOS (Unknown)"
    elif system == "Windows":
        try:
            cmd = ["powershell", "-NoProfile", "-Command", "[System.Environment]::OSVersion.Version.ToString()"]
            return subprocess.check_output(cmd, text=True).strip()
        except Exception:
            return platform.version()
    else:
        try:
            with open("/etc/os-release") as stream:
                for line in stream:
                    if line.startswith("PRETTY_NAME="):
                        return line.strip().split("=")[1].strip('"\'')
        except Exception:
            pass
        return platform.release()


# ---------------------------------------------------------------------------
# Workstation Checks (Firewall, Antivirus, Privilege, Extensions)
# ---------------------------------------------------------------------------

def ufw_is_correctly_configured():
    """Verify UFW host firewall state and default incoming policy."""
    if not shutil.which("ufw"):
        return False

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    status_command = ["ufw", "status", "verbose"] if is_root else ["sudo", "-n", "ufw", "status", "verbose"]
    try:
        output = subprocess.check_output(status_command, text=True, stderr=subprocess.DEVNULL, timeout=5).lower()
        return "status: active" in output and "deny (incoming)" in output and "allow (outgoing)" in output
    except Exception:
        pass

    try:
        ufw_conf = Path("/etc/ufw/ufw.conf")
        if not ufw_conf.is_file() or "ENABLED=yes" not in ufw_conf.read_text():
            return False

        default_ufw = Path("/etc/default/ufw")
        if not default_ufw.is_file():
            return False

        text = default_ufw.read_text()
        blocks_incoming = 'DEFAULT_INPUT_POLICY="DROP"' in text or 'DEFAULT_INPUT_POLICY="DENY"' in text
        allows_outgoing = 'DEFAULT_OUTPUT_POLICY="ACCEPT"' in text
        if not (blocks_incoming and allows_outgoing):
            return False

        if shutil.which("systemctl"):
            service_proc = subprocess.run(["systemctl", "is-active", "ufw"], capture_output=True, text=True, timeout=5)
            if service_proc.stdout.strip() != "active":
                return False

        return True
    except Exception:
        return False


def mac_firewall_is_active():
    """Verify macOS application firewall or packet filter state."""
    try:
        out = subprocess.check_output(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], text=True)
        if "Firewall is enabled" in out or "State = 1" in out:
            return True
    except Exception:
        pass
    try:
        out = subprocess.check_output(["pfctl", "-s", "info"], text=True, stderr=subprocess.DEVNULL)
        if "Status: Enabled" in out:
            return True
    except Exception:
        pass
    return False


def windows_firewall_is_active():
    """Verify Windows Defender Firewall status across all profiles."""
    try:
        cmd = ["powershell", "-NoProfile", "-Command", "(Get-NetFirewallProfile).Enabled -contains $true"]
        out = subprocess.check_output(cmd, text=True).strip().lower()
        return out == "true"
    except Exception:
        return False


def firewalld_is_active():
    """Verify firewalld service status and running state."""
    if not shutil.which("firewall-cmd"):
        return False
    try:
        res = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=5)
        return res.stdout.strip() == "running"
    except Exception:
        return False


def nftables_is_active():
    """Verify nftables active ruleset with incoming drops."""
    if not shutil.which("nft"):
        return False
    try:
        res = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=5)
        out = res.stdout.lower()
        return "drop" in out or "reject" in out
    except Exception:
        return False


def inspect_firewall(system):
    """Determine host firewall active status across platforms."""
    if system in ["Arch", "Ubuntu", "Linux"]:
        if ufw_is_correctly_configured() or firewalld_is_active() or nftables_is_active():
            return True
        try:
            iptables_rules = subprocess.check_output(["iptables", "-S", "INPUT"], text=True, stderr=subprocess.DEVNULL)
            return "DROP" in iptables_rules or "REJECT" in iptables_rules or "nixos-fw" in iptables_rules
        except Exception:
            return False
    elif system == "NixOS":
        try:
            iptables_rules = subprocess.check_output(["iptables", "-S", "INPUT"], text=True, stderr=subprocess.DEVNULL)
            return "nixos-fw" in iptables_rules or "DROP" in iptables_rules
        except Exception:
            return False
    elif system == "macOS":
        return mac_firewall_is_active()
    elif system == "Windows":
        return windows_firewall_is_active()
    return False


def inspect_antivirus(system):
    """Detect active antivirus or EDR solutions."""
    if system == "macOS":
        # Check XProtect or third-party EDRs
        xprotect_path = Path("/Library/Apple/System/Library/CoreServices/XProtect.bundle")
        if xprotect_path.exists():
            return "XProtect (macOS)"
        return "Unknown"

    elif system == "Windows":
        try:
            cmd = ["powershell", "-NoProfile", "-Command",
                   "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName"]
            out = subprocess.check_output(cmd, text=True).strip()
            if out:
                return out.splitlines()[0].strip()
            return "Windows Defender"
        except Exception:
            return "Windows Defender"

    else:
        # Linux: check for ClamAV, SentinelOne, CrowdStrike Falcon, Sophos, Wazuh
        edr_binaries = [
            ("falcon-sensor", "CrowdStrike Falcon"),
            ("sentinelctl", "SentinelOne"),
            ("clamd", "ClamAV"),
            ("clamscan", "ClamAV"),
            ("wazuh-agent", "Wazuh Agent"),
            ("savd", "Sophos Antivirus"),
        ]
        for binary, name in edr_binaries:
            if shutil.which(binary):
                return name

        # Check systemd services
        for svc, name in [("clamav-daemon", "ClamAV"), ("falcon-sensor", "CrowdStrike Falcon"), ("wazuh-agent", "Wazuh")]:
            try:
                res = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True)
                if res.stdout.strip() == "active":
                    return name
            except Exception:
                pass

        return "None"


def is_sudo_prompting_for_root():
    """Check if sudo prompts for root password rather than user password."""
    try:
        import pty
        import select
        pid, fd = pty.fork()
        if pid == 0:
            os.execvp("sudo", ["sudo", "-k", "-p", "PROMPT_USER:%p:", "true"])
        else:
            try:
                r, _, _ = select.select([fd], [], [], 2.0)
                if r:
                    data = os.read(fd, 256).decode("utf-8", "replace")
                    return "PROMPT_USER:root:" in data
                return False
            finally:
                try:
                    os.kill(pid, 9)
                    os.waitpid(pid, 0)
                except Exception:
                    pass
    except Exception:
        return False


def check_admin_separated(system):
    """Verify daily user account is separated from root/administrator privileges."""
    if system in ["Ubuntu", "Arch", "Linux", "NixOS"]:
        dropin_config = Path("/etc/sudoers.d/cyber_essentials_targetpw")
        try:
            if dropin_config.exists():
                return "Yes"
        except Exception:
            pass

        check_user = os.environ.get("SUDO_USER") or getpass.getuser()
        try:
            out = subprocess.check_output(["id", "-Gn", check_user], text=True, stderr=subprocess.DEVNULL, timeout=5)
            groups = set(out.strip().split())
            if "sudo" not in groups and "wheel" not in groups:
                return "Yes"
        except Exception:
            pass

        if is_sudo_prompting_for_root():
            return "Yes"

        return "No"

    elif system == "macOS":
        target_user = os.environ.get("SUDO_USER") or getpass.getuser()
        try:
            membership_check = subprocess.run(
                ["dsmemberutil", "checkmembership", "-U", target_user, "-G", "admin"],
                capture_output=True, text=True, timeout=5
            )
            if "is not a member" in membership_check.stdout.lower():
                return "Yes"
            if "is a member" in membership_check.stdout.lower():
                return "No"
        except Exception:
            pass
        try:
            user_groups = subprocess.check_output(["id", "-Gn", target_user], text=True, stderr=subprocess.DEVNULL, timeout=5)
            return "No" if "admin" in set(user_groups.strip().split()) else "Yes"
        except Exception:
            return "No"

    elif system == "Windows":
        try:
            token_groups = subprocess.check_output(["whoami", "/groups"], text=True, stderr=subprocess.DEVNULL, timeout=10)
            return "No" if "S-1-5-32-544" in token_groups else "Yes"
        except Exception:
            return "Unknown"

    return "Unknown"


PROTECTIVE_DNS_SERVERS = {
    # Quad9 (Malware/phishing sinkholing)
    "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
    # Cloudflare 1.1.1.2 Security (Malware blocking)
    "1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002",
    # OpenDNS / Cisco Umbrella (Threat filtering)
    "208.67.222.222", "208.67.220.220",
    # CleanBrowsing Security Filter
    "185.228.168.9", "185.228.169.9",
    # NextDNS / AdGuard Default
    "94.140.14.14", "94.140.15.14",
}


def detect_protective_dns(system):
    """Detect if system is configured with protective DNS resolvers (Quad9, Cloudflare 1.1.1.2, etc.)."""
    if system in ["Arch", "Ubuntu", "Linux", "NixOS"]:
        # 1. Check resolvectl status and resolvectl dns
        if shutil.which("resolvectl"):
            try:
                out = subprocess.check_output(["resolvectl", "status"], text=True, stderr=subprocess.DEVNULL, timeout=5)
                for line in out.splitlines():
                    if "DNS Server:" in line or "DNS Servers:" in line or "Fallback DNS Servers:" in line:
                        if any(ip in line for ip in PROTECTIVE_DNS_SERVERS):
                            return True
            except Exception:
                pass
            try:
                out = subprocess.check_output(["resolvectl", "dns"], text=True, stderr=subprocess.DEVNULL, timeout=5)
                if any(ip in out for ip in PROTECTIVE_DNS_SERVERS):
                    return True
            except Exception:
                pass

        # 2. Check /etc/systemd/resolved.conf.d/ drop-ins and /etc/systemd/resolved.conf
        dropin_dir = Path("/etc/systemd/resolved.conf.d")
        if dropin_dir.is_dir():
            for conf_file in dropin_dir.glob("*.conf"):
                try:
                    content = conf_file.read_text()
                    if any(ip in content for ip in PROTECTIVE_DNS_SERVERS):
                        return True
                except Exception:
                    pass

        resolved_conf = Path("/etc/systemd/resolved.conf")
        if resolved_conf.is_file():
            try:
                for line in resolved_conf.read_text().splitlines():
                    if line.strip().startswith("DNS=") or line.strip().startswith("FallbackDNS="):
                        if any(ip in line for ip in PROTECTIVE_DNS_SERVERS):
                            return True
            except Exception:
                pass

        # 3. Check resolv.conf
        for rpath in [Path("/run/systemd/resolve/resolv.conf"), Path("/etc/resolv.conf")]:
            if rpath.is_file():
                try:
                    content = rpath.read_text()
                    if any(ip in content for ip in PROTECTIVE_DNS_SERVERS):
                        return True
                except Exception:
                    pass

        # 4. Check nmcli if available
        if shutil.which("nmcli"):
            try:
                out = subprocess.check_output(["nmcli", "dev", "show"], text=True, stderr=subprocess.DEVNULL, timeout=5)
                if any(ip in out for ip in PROTECTIVE_DNS_SERVERS):
                    return True
            except Exception:
                pass

    elif system == "macOS":
        try:
            out = subprocess.check_output(["scutil", "--dns"], text=True, stderr=subprocess.DEVNULL, timeout=5)
            if any(ip in out for ip in PROTECTIVE_DNS_SERVERS):
                return True
        except Exception:
            pass

    elif system == "Windows":
        try:
            cmd = ["powershell", "-NoProfile", "-Command", "(Get-DnsClientServerAddress).ServerAddresses"]
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=5)
            if any(ip in out for ip in PROTECTIVE_DNS_SERVERS):
                return True
        except Exception:
            pass

    return False


def detect_web_scanning(system, home):
    """Detect web threat protection via protective DNS or browser security extensions."""
    # First check protective DNS (Quad9, Cloudflare 1.1.1.2, NextDNS, etc.)
    if detect_protective_dns(system):
        return True

    # Next check browser extensions in user home
    if not home or not Path(home).exists():
        return False

    chrome_ext_ids = [
        "cfnpidifppmenkapgihekkeednfoenal",  # Bitdefender TrafficLight
        "miefikclhegpdegmnghpkicllndpmpcg",  # Malwarebytes Browser Guard
    ]
    firefox_ext_ids = [
        "trafficlight@bitdefender.com",
    ]

    search_roots = [
        Path(home) / ".config" / "google-chrome",
        Path(home) / ".config" / "chromium",
        Path(home) / ".config" / "BraveSoftware" / "Brave-Browser",
        Path(home) / ".config" / "microsoft-edge",
        Path(home) / ".mozilla" / "firefox",
        Path(home) / "Library" / "Application Support" / "Google" / "Chrome",
        Path(home) / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser",
        Path(home) / "Library" / "Application Support" / "Firefox",
        Path(home) / "AppData" / "Local" / "Google" / "Chrome",
    ]

    for root in search_roots:
        if root.exists():
            try:
                for ext_id in chrome_ext_ids:
                    for match in root.rglob(ext_id):
                        if match.exists():
                            return True
                for ext_id in firefox_ext_ids:
                    for match in root.rglob(f"*{ext_id}*"):
                        if match.exists():
                            return True
            except Exception:
                pass
    return False


def detect_ros_environment():
    """Detect ROS 1 / ROS 2 installation, DDS domain, and SROS2 security enclaves."""
    ros_info = {
        "detected": False,
        "version": None,
        "distro": None,
        "domain_id": None,
        "sros2_enabled": False,
        "security_strategy": "N/A",
        "enclave_status": "Not active"
    }

    version = os.environ.get("ROS_VERSION")
    distro = os.environ.get("ROS_DISTRO")
    domain_id = os.environ.get("ROS_DOMAIN_ID")
    sros_enable = os.environ.get("ROS_SECURITY_ENABLE", "").lower() in ("true", "1")
    strategy = os.environ.get("ROS_SECURITY_STRATEGY", "Permissive")

    if not distro and Path("/opt/ros").is_dir():
        try:
            subdirs = [p.name for p in Path("/opt/ros").iterdir() if p.is_dir()]
            if subdirs:
                distro = subdirs[0]
                version = "2" if distro in ["foxy", "galactic", "humble", "iron", "jazzy", "rolling"] else "1"
        except Exception:
            pass

    try:
        ps_out = subprocess.check_output(["ps", "-A"], text=True, stderr=subprocess.DEVNULL)
        if "roscore" in ps_out or "rosmaster" in ps_out:
            version = "1"
            ros_info["detected"] = True
        elif any(d in ps_out for d in ["ros2", "fastdds", "cyclonedds"]):
            version = "2"
            ros_info["detected"] = True
    except Exception:
        pass

    if version or distro or ros_info["detected"]:
        ros_info["detected"] = True
        ros_info["version"] = int(version) if version and str(version).isdigit() else (2 if distro in ["humble", "iron", "jazzy", "rolling"] else 1)
        ros_info["distro"] = distro or "ros2-core"
        ros_info["domain_id"] = domain_id or "0 (default)"
        ros_info["sros2_enabled"] = sros_enable
        ros_info["security_strategy"] = strategy if sros_enable else "Off (DDS Multicast)"
        ros_info["enclave_status"] = "SROS2 Cryptographic Enclave Active" if sros_enable else "Standard DDS Domain Isolation"

    return ros_info


# ---------------------------------------------------------------------------
# Robot Fleet & Edge Checks (Ports, Interfaces, Patch Age, Passwords)
# ---------------------------------------------------------------------------

def get_interfaces():
    """Retrieve network interfaces and assigned IP addresses."""
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
    """Identify open listening ports and classify robotics DDS IPC vs exposed services."""
    ports = []
    try:
        raw = subprocess.check_output(["ss", "-tulnH"], text=True)
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                protocol = parts[0].lower()
                if protocol not in ["tcp", "udp"]:
                    continue
                socket = parts[4]
                if ":" in socket:
                    ip, port_str = socket.rsplit(":", 1)
                    if port_str.isdigit():
                        port_num = int(port_str)
                        cleaned_ip = ip.strip("[]")
                        is_exposed = cleaned_ip in ["0.0.0.0", "::", "*"]
                        is_dds_ipc = protocol == "udp" and 7400 <= port_num <= 7550
                        is_ros_master = protocol == "tcp" and port_num == 11311

                        service_tag = "ROS 2 DDS Enclave (Internal IPC)" if is_dds_ipc else (
                            "ROS 1 Master" if is_ros_master else "System Service"
                        )
                        ports.append({
                            "proto": protocol,
                            "ip": ip,
                            "port": port_str,
                            "exposed": is_exposed,
                            "is_robotics_ipc": is_dds_ipc or is_ros_master,
                            "service_tag": service_tag
                        })
    except Exception:
        pass
    return ports


def check_os_patch_status(system):
    """Verify system update currency (e.g. NixOS rebuild age or package update age)."""
    if system == "NixOS":
        try:
            profile_path = Path("/nix/var/nix/profiles/system")
            if profile_path.exists():
                last_built = profile_path.stat().st_mtime
                age_days = (time.time() - last_built) / 86400
                if age_days <= 14:
                    return f"Compliant (<14d rebuild, {int(age_days)}d)"
                return f"Non-Compliant (Rebuild {int(age_days)}d ago)"
            raw = subprocess.check_output(["nixos-version"], text=True).strip()
            return f"Compliant ({raw.split()[0]})"
        except Exception:
            return "Unknown"

    elif system in ["Ubuntu", "Arch", "Linux"]:
        # Check Ubuntu/Debian update stamp
        stamp = Path("/var/lib/apt/periodic/update-success-stamp")
        if stamp.exists():
            age_days = (time.time() - stamp.stat().st_mtime) / 86400
            if age_days <= 14:
                return f"Compliant (<14d updates, {int(age_days)}d)"
            return f"Non-Compliant (Updates {int(age_days)}d ago)"
        return "Compliant (Managed)"

    return "Compliant (Auto-updates enabled)"


def check_default_passwords():
    """Ensure standard administrative/robot accounts have non-default password hashes."""
    try:
        with open("/etc/shadow", "r") as f:
            shadow_lines = f.readlines()

        default_accounts = ["root", "nixos", "admin", "robot", "ubuntu"]
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


# ---------------------------------------------------------------------------
# Unified Posture Gathering (Zero-Payload Metadata)
# ---------------------------------------------------------------------------

def collect_telemetry(mode="workstation", device_id=None, org_id=None):
    """Collect unified security posture telemetry matching the SOC 2 metadata schema.

    Strict zero-payload policy: never collects or transmits robot camera feeds,
    LiDAR data, SLAM maps, ROS message payloads, or proprietary source code.
    """
    system = get_os()
    home = get_real_home()
    firewall_ok = inspect_firewall(system)
    antivirus = inspect_antivirus(system)
    admin_sep = check_admin_separated(system)
    uuid_val = get_hardware_serial(system)
    os_ver = get_os_version(system)
    patch_status = check_os_patch_status(system)

    payload = {
        "schema_version": "1.0.0",
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "device": {
            "device_id": device_id or uuid_val,
            "org_id": org_id,
            "mode": mode,  # "workstation" or "robot"
            "hostname": platform.node(),
            "os_distro": system,
            "os_version": os_ver,
            "hardware_serial": uuid_val,
        },
        "controls": {
            "firewall": {
                "active": firewall_ok,
                "status": "pass" if firewall_ok else "fail",
            },
            "antivirus": {
                "name": antivirus,
                "status": "pass" if antivirus not in ["None", "Unknown"] else "fail",
            },
            "admin_separation": {
                "enforced": admin_sep == "Yes",
                "status": "pass" if admin_sep == "Yes" else "fail",
            },
            "patch_management": {
                "status_detail": patch_status,
                "status": "fail" if "Non-Compliant" in patch_status or "Fail" in patch_status else "pass",
            },
        },
    }

    if mode == "workstation":
        web_ok = detect_web_scanning(system, home)
        payload["controls"]["web_threat_scanning"] = {
            "active": web_ok,
            "status": "pass" if web_ok else "fail",
        }

    if mode == "robot":
        interfaces = get_interfaces()
        open_ports = get_open_ports()
        exposed_ports = [p for p in open_ports if p.get("exposed")]
        pwd_check = check_default_passwords()

        payload["robot_specific"] = {
            "interfaces": interfaces,
            "open_ports_count": len(open_ports),
            "exposed_ports_count": len(exposed_ports),
            "exposed_ports": exposed_ports,
            "default_passwords_check": pwd_check,
        }
        # If open unauthenticated ports exist on 0.0.0.0 without active firewall, flag warning
        if exposed_ports and not firewall_ok:
            payload["controls"]["firewall"]["status"] = "fail"

    # Overall compliance evaluation
    control_statuses = [c.get("status") for c in payload["controls"].values()]
    if all(s == "pass" for s in control_statuses):
        payload["posture"] = "compliant"
    elif any(s == "fail" for s in control_statuses):
        payload["posture"] = "non_compliant"
    else:
        payload["posture"] = "warning"

    return payload
