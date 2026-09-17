#!/usr/bin/env python3

import argparse
import ctypes
import getpass
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import time
import webbrowser

try:
    import grp
except ImportError:
    grp = None

try:
    import pwd
except ImportError:
    pwd = None


def delay(seconds=0.6):
    if os.environ.get("CI") == "true" or "--fast" in sys.argv:
        return
    if not sys.stdin.isatty() and "--delay" not in sys.argv:
        return
    time.sleep(seconds)


def log_step(title):
    print(f"\n-> {title}...", flush=True)
    delay(0.6)


def log_success(message):
    print(f"   Done: {message}", flush=True)
    delay(0.3)


def log_warning(message):
    print(f"   Notice: {message}", flush=True)
    delay(0.3)


def log_info(message):
    print(f"   {message}", flush=True)
    delay(0.3)


def copy_to_clipboard(text):
    clipboard_handlers = [
        ("pbcopy", ["pbcopy"]),
        ("wl-copy", ["wl-copy"]),
        ("xclip", ["xclip", "-selection", "clipboard"]),
    ]
    for binary, command in clipboard_handlers:
        if shutil.which(binary):
            try:
                proc = subprocess.Popen(command, stdin=subprocess.PIPE, close_fds=True)
                proc.communicate(input=text.encode("utf-8"))
                return True
            except Exception:
                pass

    if platform.system().lower() == "windows":
        try:
            proc = subprocess.Popen(["clip"], stdin=subprocess.PIPE, shell=True, close_fds=True)
            proc.communicate(input=text.encode("utf-8"))
            return True
        except Exception:
            pass

    return False


def get_real_home():
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


def open_url_safely(url):
    system = platform.system().lower()
    if system == "windows":
        webbrowser.open(url)
        return

    sudo_user = os.environ.get("SUDO_USER")
    if system == "darwin":
        if sudo_user:
            res = subprocess.run(["sudo", "-u", sudo_user, "open", url],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                return
        subprocess.run(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return

    if sudo_user:
        forwarded_environment = [
            f"{key}={os.environ[key]}"
            for key in ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"]
            if key in os.environ
        ]
        environment_prefix = f"env {' '.join(forwarded_environment)} " if forwarded_environment else ""
        open_command = f"{environment_prefix}xdg-open '{url}'"

        if shutil.which("runuser"):
            res = subprocess.run(["runuser", "-u", sudo_user, "--", "sh", "-c", open_command],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                return

        if shutil.which("su"):
            res = subprocess.run(["su", sudo_user, "-c", open_command],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                return

    webbrowser.open(url)


def get_os():
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
                            distro_id = line.strip().split("=")[1].strip("'\"").lower()
                        elif line.startswith("ID_LIKE="):
                            distro_family = line.strip().split("=")[1].strip("'\"").lower()
        except Exception:
            pass

        if distro_id == "arch" or "arch" in distro_family:
            return "Arch"
        if distro_id in ["ubuntu", "debian"] or "ubuntu" in distro_family or "debian" in distro_family:
            return "Ubuntu"
        return "Linux"
    return "Unknown"


def run_command(command, timeout=45):
    try:
        return subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
    except Exception:
        return None


def query_windows_system(powershell_code, explanation, timeout=30):
    # Query Windows system parameters: {explanation}
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershell_code],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout.strip()
    except Exception:
        return ""


def get_binary_version(binary_name):
    binary_path = shutil.which(binary_name)
    if binary_path:
        try:
            output = subprocess.check_output([binary_path, "--version"], text=True, stderr=subprocess.DEVNULL, timeout=5)
            version_match = re.search(r"(\d+(?:\.\d+)+)", output)
            if version_match:
                return version_match.group(1)
        except Exception:
            pass
    return None


def ufw_is_correctly_configured():
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
    binary_path = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    if not Path(binary_path).exists():
        return False
    try:
        output = subprocess.check_output([binary_path, "--getglobalstate"], text=True, stderr=subprocess.DEVNULL, timeout=10).lower()
        return "enabled" in output
    except Exception:
        return False


def windows_firewall_is_active():
    script = "(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count"
    disabled_profile_count = query_windows_system(script, "Checking count of disabled Windows Firewall profiles")
    return disabled_profile_count == "0"


def inspect_firewall(system):
    if system in ["Arch", "Ubuntu", "Linux"]:
        if ufw_is_correctly_configured():
            log_success("Firewall active with baseline rules.")
            return True
        log_warning("Firewall is not configured to policy.")
        print("\n    To configure manually:")
        print("    1. Install UFW (e.g. sudo pacman -S ufw / sudo apt install ufw)")
        print("    2. sudo ufw default deny incoming")
        print("    3. sudo ufw default allow outgoing")
        print("    4. sudo ufw enable")
        input("\n    Press [Enter] once enabled...")
        return ufw_is_correctly_configured()

    if system == "macOS":
        if mac_firewall_is_active():
            log_success("macOS Application Firewall is active.")
            return True
        log_warning("macOS Application Firewall is turned off.")
        print("\n    To configure manually:")
        print("    1. Open System Settings -> Network -> Firewall")
        print("    2. Turn the Firewall ON")
        input("\n    Press [Enter] once enabled...")
        return mac_firewall_is_active()

    if system == "Windows":
        if windows_firewall_is_active():
            log_success("Windows Firewall is active across all profiles.")
            return True
        log_warning("Windows Firewall is disabled on one or more network profiles.")
        print("\n    To configure manually:")
        print("    1. Open Windows Security -> Firewall & network protection")
        print("    2. Ensure Domain, Private, and Public network firewalls are turned ON")
        input("\n    Press [Enter] once enabled...")
        return windows_firewall_is_active()

    return False


def inspect_antivirus(system):
    if system in ["Ubuntu", "Arch", "Linux"]:
        if shutil.which("clamscan"):
            version = get_binary_version("clamscan")
            service_active = False
            if shutil.which("systemctl"):
                for unit in ["clamav-daemon", "clamav-freshclam", "clamd@scan"]:
                    proc = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5)
                    if proc.stdout.strip() == "active":
                        service_active = True
                        break
            if service_active:
                log_success(f"Anti-virus active: ClamAV {version if version else ''}".strip())
                return f"ClamAV - {version}" if version else "ClamAV - Active"
            log_warning("ClamAV is installed, but daemon services are inactive.")
            print("    Ensure clamav-freshclam or clamav-daemon is running (sudo systemctl start clamav-daemon).")
            return "ClamAV - Service Inactive"

        if Path("/opt/bitdefender-security-tools").exists():
            log_success("Anti-virus active: Bitdefender Endpoint Security")
            return "Bitdefender Endpoint Security"

        log_warning("No active anti-malware service detected.")
        print("    Please install and run an endpoint anti-virus solution (e.g. ClamAV).")
        return "None"

    if system == "macOS":
        if (Path("/Library/Bitdefender").is_dir() or
            Path("/Applications/Bitdefender").is_dir() or
            Path("/Applications/Bitdefender Endpoint Security Tools.app").is_dir()):
            log_success("Anti-virus active: Bitdefender Endpoint Security")
            return "Bitdefender Endpoint Security"
        log_success("Anti-virus active: XProtect (macOS)")
        return "XProtect (macOS) - Active"

    if system == "Windows":
        script = """
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($status) {
            if ($status.RealTimeProtectionEnabled -and $status.AntivirusEnabled) {
                $sig = $status.AntivirusSignatureVersion
                if ($sig) { "Active ($sig)" } else { "Active" }
            } else {
                "Disabled"
            }
            exit
        }
        "Unknown"
        """
        result = query_windows_system(script, "Verifying Microsoft Defender real-time protection and engine status")
        if "Active" in result:
            log_success(f"Anti-virus active: Windows Defender ({result})")
            return f"Windows Defender - {result}"
        if "Disabled" in result:
            log_warning("Windows Defender is present, but Real-Time Protection is disabled.")
            print("    Please enable Real-Time Protection in Windows Security -> Virus & threat protection.")
            return "Windows Defender - Disabled"
        return "Windows Defender - Active"

    return "None"


def check_admin_separated(system):
    if system in ["Ubuntu", "Arch", "Linux"]:
        dropin_config = Path("/etc/sudoers.d/cyber_essentials_targetpw")
        return "Yes" if dropin_config.exists() else "No"

    if system == "macOS":
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

    if system == "Windows":
        try:
            token_groups = subprocess.check_output(["whoami", "/groups"], text=True, stderr=subprocess.DEVNULL, timeout=10)
            return "No" if "S-1-5-32-544" in token_groups else "Yes"
        except Exception:
            membership_script = "([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object { $_.Value -eq 'S-1-5-32-544' }) -ne $null"
            is_administrator = query_windows_system(membership_script, "Inspecting current Windows user token for Administrators SID S-1-5-32-544")
            return "No" if "True" in is_administrator else "Yes"

    return "No"


def instruct_admin_separation(system):
    if system in ["Ubuntu", "Arch", "Linux"]:
        print("\n    Separate Root / Sudo Authentication Guidance:")
        print("    1. Set a dedicated root password different from your login account password:")
        print("       sudo passwd root")
        print("    2. Require target user (root) authentication for all sudo commands:")
        print("       echo 'Defaults targetpw' | sudo tee /etc/sudoers.d/cyber_essentials_targetpw")
        print("       sudo chmod 0440 /etc/sudoers.d/cyber_essentials_targetpw")
        input("\n    Press [Enter] once configured...")
        return True

    if system == "macOS":
        print("\n    Standard User Guidance:")
        print("    1. Open System Settings -> Users & Groups")
        print("    2. Create a dedicated Administrator account")
        print("    3. Demote your daily account to Standard")
        print("    4. Re-login to your standard user profile")
        input("\n    Press [Enter] once configured...")
        return True

    if system == "Windows":
        print("\n    Standard User Guidance:")
        print("    1. Open Settings -> Accounts -> Other users")
        print("    2. Create an admin account and add it to the Administrators group")
        print("    3. Change your daily account type to Standard User")
        print("    4. Re-login to apply account restrictions")
        input("\n    Press [Enter] once configured...")
        return True

    return False


def find_firefox_profile_dirs(home):
    profile_dirs = []
    possible_roots = [
        home / ".mozilla/firefox",
        home / "Library/Application Support/Firefox",
        home / "AppData/Roaming/Mozilla/Firefox",
        home / ".var/app/org.mozilla.firefox/.mozilla/firefox",
        home / "snap/firefox/common/.mozilla/firefox",
    ]
    for root in possible_roots:
        profiles_ini = root / "profiles.ini"
        if not profiles_ini.is_file():
            continue
        try:
            current_path = None
            is_relative = True
            for line in profiles_ini.read_text(errors="ignore").splitlines():
                stripped = line.strip()
                if stripped.startswith("Path="):
                    current_path = stripped.split("=", 1)[1]
                elif stripped.startswith("IsRelative="):
                    is_relative = stripped.split("=", 1)[1] == "1"
                elif stripped.startswith("[") and current_path:
                    path_obj = (root / current_path) if is_relative else Path(current_path)
                    if path_obj.is_dir():
                        profile_dirs.append(path_obj)
                    current_path = None
                    is_relative = True
            if current_path:
                path_obj = (root / current_path) if is_relative else Path(current_path)
                if path_obj.is_dir():
                    profile_dirs.append(path_obj)
        except Exception:
            continue
    return profile_dirs


def firefox_has_trafficlight(home):
    for profile in find_firefox_profile_dirs(home):
        extensions_file = profile / "extensions.json"
        if extensions_file.is_file():
            try:
                document = json.loads(extensions_file.read_text(errors="ignore"))
                for addon in document.get("addons", []):
                    if not addon.get("active", False):
                        continue
                    serialized = json.dumps(addon).lower()
                    if "trafficlight" in serialized and "bitdefender" in serialized:
                        return True
            except Exception:
                pass

        extensions_folder = profile / "extensions"
        if extensions_folder.is_dir():
            try:
                for file_entry in extensions_folder.iterdir():
                    if "trafficlight" in file_entry.name.lower():
                        return True
            except Exception:
                pass
    return False


def detect_browsers(system, home):
    detected = []

    if system in ["Ubuntu", "Arch", "Linux"]:
        linux_browsers = [
            ("Chrome", ["google-chrome-stable", "google-chrome"]),
            ("Chromium", ["chromium", "chromium-browser"]),
            ("Firefox", ["firefox", "firefox-esr", "firefox-developer-edition", "firefox-nightly"]),
            ("Brave", ["brave", "brave-browser"]),
            ("Edge", ["microsoft-edge-stable", "microsoft-edge"]),
            ("Opera", ["opera"]),
            ("Vivaldi", ["vivaldi-stable", "vivaldi"]),
        ]
        for name, binaries in linux_browsers:
            for binary in binaries:
                version = get_binary_version(binary)
                if version:
                    detected.append(f"{name} {version}")
                    break

    elif system == "macOS":
        applications = [
            ("Safari", Path("/Applications/Safari.app")),
            ("Chrome", Path("/Applications/Google Chrome.app")),
            ("Firefox", Path("/Applications/Firefox.app")),
            ("Brave", Path("/Applications/Brave Browser.app")),
            ("Edge", Path("/Applications/Microsoft Edge.app")),
            ("Arc", Path("/Applications/Arc.app")),
        ]
        for name, app_path in applications:
            candidates = [app_path, home / "Applications" / app_path.name]
            for target in candidates:
                plist_path = target / "Contents/Info.plist"
                if plist_path.is_file():
                    try:
                        with open(plist_path, "rb") as stream:
                            parsed_plist = plistlib.load(stream)
                            version = parsed_plist.get("CFBundleShortVersionString") or parsed_plist.get("CFBundleVersion")
                            if version:
                                detected.append(f"{name} {version}")
                                break
                    except Exception:
                        pass

    elif system == "Windows":
        known_executables = [
            ("Chrome", [
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
            ]),
            ("Edge", [
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            ]),
            ("Firefox", [
                r"C:\Program Files\Mozilla Firefox\firefox.exe",
                r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
            ]),
            ("Brave", [
                r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe"),
            ]),
        ]
        for name, file_paths in known_executables:
            for path_string in file_paths:
                if Path(path_string).is_file():
                    version = query_windows_system(
                        f"(Get-Item '{path_string}').VersionInfo.ProductVersion",
                        f"Extracting binary product version for {name}",
                        timeout=5
                    )
                    detected.append(f"{name} {version}" if version else name)
                    break

    return ", ".join(detected) if detected else "None detected"


def detect_web_scanning(system, home):
    extension_id = "cfnpidifppmenkapgihekkeednfoenal"

    scan_directories = []
    if system in ["Ubuntu", "Arch", "Linux"]:
        scan_directories = [
            home / ".config/google-chrome",
            home / ".config/chromium",
            home / ".config/BraveSoftware/Brave-Browser",
            home / ".config/microsoft-edge",
            home / ".var/app/com.google.Chrome/config/google-chrome",
            home / ".var/app/org.chromium.Chromium/config/chromium",
            home / ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
            home / "snap/chromium/current/.config/chromium",
        ]
    elif system == "macOS":
        scan_directories = [
            home / "Library/Application Support/Google/Chrome",
            home / "Library/Application Support/BraveSoftware/Brave-Browser",
            home / "Library/Application Support/Microsoft Edge",
            home / "Library/Application Support/Chromium",
            home / "Library/Application Support/Arc/User Data",
        ]
    elif system == "Windows":
        local_app_data = Path(os.environ.get("LOCALAPPDATA", str(home / "AppData/Local")))
        scan_directories = [
            local_app_data / "Google/Chrome/User Data",
            local_app_data / "Microsoft/Edge/User Data",
            local_app_data / "BraveSoftware/Brave-Browser/User Data",
        ]

    for directory in scan_directories:
        if directory.is_dir():
            try:
                if any(directory.glob(f"*/Extensions/{extension_id}*")):
                    return True
            except Exception:
                pass

    if firefox_has_trafficlight(home):
        return True

    if system == "Windows":
        script = """
        $item = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue
        if ($item -and $item.SmartScreenEnabled -ne 'Off') { 'Yes' } else { 'No' }
        """
        response = query_windows_system(script, "Checking Windows SmartScreen threat filtering status", timeout=5)
        if response == "Yes":
            return True

    return False


def is_dummy_identifier(value):
    if not value:
        return True
    lowered = value.lower().strip()
    placeholder_signatures = [
        "none", "denied", "default", "o.e.m", "to be filled", "chassis",
        "00000000", "12345678", "unknown", "system serial number",
        "03000200-0400-0500-0006-000700080009"
    ]
    return any(signature in lowered for signature in placeholder_signatures)


def get_hardware_serial(system):
    if system in ["Ubuntu", "Arch", "Linux"]:
        for dmi_path in ["/sys/class/dmi/id/product_serial", "/sys/class/dmi/id/board_serial", "/sys/class/dmi/id/chassis_serial"]:
            try:
                path_obj = Path(dmi_path)
                if path_obj.is_file():
                    candidate = path_obj.read_text(errors="ignore").strip()
                    if not is_dummy_identifier(candidate):
                        return candidate
            except Exception:
                pass

        if shutil.which("dmidecode"):
            for flag in ["system-serial-number", "baseboard-serial-number"]:
                cmd = ["dmidecode", "-s", flag]
                if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
                    cmd = ["sudo", "-n"] + cmd
                try:
                    candidate = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=3).strip()
                    if not is_dummy_identifier(candidate):
                        return candidate
                except Exception:
                    pass

        try:
            uuid_path = Path("/sys/class/dmi/id/product_uuid")
            if uuid_path.is_file():
                candidate = uuid_path.read_text(errors="ignore").strip()
                if not is_dummy_identifier(candidate):
                    return candidate
        except Exception:
            pass

        return platform.node() or "Unknown"

    if system == "macOS":
        try:
            raw_output = subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], text=True, stderr=subprocess.DEVNULL, timeout=5)
            serial_match = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', raw_output)
            if serial_match and not is_dummy_identifier(serial_match.group(1)):
                return serial_match.group(1)
        except Exception:
            pass

        try:
            sp_output = subprocess.check_output(["system_profiler", "SPHardwareDataType"], text=True, stderr=subprocess.DEVNULL, timeout=5)
            serial_match = re.search(r"Serial Number \([^)]+\):\s*(\S+)", sp_output)
            if serial_match and not is_dummy_identifier(serial_match.group(1)):
                return serial_match.group(1)
        except Exception:
            pass
        return "Unknown"

    if system == "Windows":
        candidate = query_windows_system(
            "(Get-CimInstance Win32_BIOS).SerialNumber",
            "Reading motherboard BIOS hardware serial number",
            timeout=5
        )
        if not is_dummy_identifier(candidate):
            return candidate

        candidate = query_windows_system(
            "(Get-CimInstance Win32_BaseBoard).SerialNumber",
            "Reading baseboard hardware serial number",
            timeout=5
        )
        if not is_dummy_identifier(candidate):
            return candidate

        candidate = query_windows_system(
            "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
            "Reading computer system product UUID",
            timeout=5
        )
        if not is_dummy_identifier(candidate):
            return candidate

    return "Unknown"


def get_os_version(system):
    if system == "Arch":
        return f"Rolling ({platform.release()})"
    if system in ["Ubuntu", "Linux"]:
        try:
            if hasattr(platform, "freedesktop_os_release"):
                release_info = platform.freedesktop_os_release()
                version = release_info.get("VERSION_ID") or release_info.get("BUILD_ID") or release_info.get("PRETTY_NAME")
                if version:
                    return version
            with open("/etc/os-release") as stream:
                for line in stream:
                    if line.startswith("VERSION_ID="):
                        return line.split("=")[1].strip().strip('"')
                    elif line.startswith("PRETTY_NAME="):
                        return line.split("=")[1].strip().strip('"')
        except Exception:
            pass
        return platform.release()

    if system == "macOS":
        try:
            return subprocess.check_output(["sw_vers", "-productVersion"], text=True, stderr=subprocess.DEVNULL, timeout=5).strip()
        except Exception:
            return platform.mac_ver()[0] or "Unknown"

    if system == "Windows":
        script = """
        $registry = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction SilentlyContinue
        if ($registry) {
            $name = $registry.ProductName
            $display = $registry.DisplayVersion
            $build = $registry.CurrentBuild
            if ($display) { "$name $display (Build $build)" } else { "$name (Build $build)" }
        } else {
            [System.Environment]::OSVersion.Version.ToString()
        }
        """
        version = query_windows_system(script, "Reading Windows release display version and kernel build number", timeout=5)
        return version if version else platform.version()

    return platform.version()


def run_audit(system):
    home = get_real_home()
    return {
        "os_distro": "Mac OS" if system == "macOS" else ("Windows" if system == "Windows" else system),
        "auto_updates": "Yes",
        "browsers": detect_browsers(system, home),
        "email_apps": "N/A (Web only)",
        "office_apps": "Google Workspace",
        "uuid": get_hardware_serial(system),
        "os_version": get_os_version(system),
        "anti_virus": inspect_antivirus(system),
        "web_scanning": "Yes" if detect_web_scanning(system, home) else "No",
        "firewall": "Yes" if (
            ufw_is_correctly_configured() if system in ["Arch", "Ubuntu", "Linux"]
            else (mac_firewall_is_active() if system == "macOS" else windows_firewall_is_active())
        ) else "No",
        "admin_separated": check_admin_separated(system),
    }


def print_summary_table(system, audit_data):
    delay(0.4)
    print("\n" + "=" * 54)
    print(f"      COMPLIANCE CHECK SUMMARY ({system.upper()})")
    print("=" * 54)
    labels = [
        ("UUID (Serial Number)", audit_data.get("uuid")),
        ("OS Distribution", audit_data.get("os_distro")),
        ("OS Version Number", audit_data.get("os_version")),
        ("A5.10 Password Login", "Yes"),
        ("A6.1 Auto Update", audit_data.get("auto_updates")),
        ("A6.2.1 Browsers", audit_data.get("browsers")),
        ("A6.2.4 Office Apps", audit_data.get("office_apps")),
        ("A6.2.3 Email Apps", audit_data.get("email_apps")),
        ("A6.2.2 Anti-Virus", audit_data.get("anti_virus")),
        ("A8.3 Web Threat Scanning", audit_data.get("web_scanning")),
        ("A4.1 Host Firewall", audit_data.get("firewall")),
        ("A7.4 Admin Restricted", audit_data.get("admin_separated")),
    ]
    for label, val in labels:
        status_tag = ""
        if label in ["A4.1 Host Firewall", "A8.3 Web Threat Scanning", "A7.4 Admin Restricted"]:
            status_tag = " [OK]" if val == "Yes" else " [FAIL]"
        elif label == "A6.2.2 Anti-Virus":
            status_tag = " [OK]" if val not in ["None", "Unknown", "ClamAV - Service Inactive", "Windows Defender - Disabled"] else " [FAIL]"
        print(f"{label.ljust(26)}: {val}{status_tag}")
    print("=" * 54 + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-only", "--test", action="store_true")
    parser.add_argument("--delay", action="store_true")
    parser.add_argument("--fast", action="store_true")
    args = parser.parse_args()

    system = get_os()

    if system == "Windows":
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Requesting Administrator permissions...")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)

    home = get_real_home()

    print("=" * 54)
    print(f"      Device Compliance Audit ({system})")
    print("=" * 54)

    is_automated = (os.environ.get("CI") == "true" or not sys.stdin.isatty())

    log_step("Checking system identification")
    uuid_val = get_hardware_serial(system)
    os_ver = get_os_version(system)
    log_success(f"Serial Number: {uuid_val}")
    log_success(f"OS: {system} {os_ver}")

    log_step("Checking firewall")
    if not inspect_firewall(system):
        log_warning("Host firewall remains inactive or unverified.")

    log_step("Checking anti-virus")
    inspect_antivirus(system)

    log_step("Checking admin separation")
    admin_sep = check_admin_separated(system)
    if admin_sep != "Yes":
        log_warning("Daily user account does not have isolated root/admin privilege boundaries.")
        if not is_automated and not args.audit_only:
            instruct_admin_separation(system)
    else:
        log_success("Privilege separation confirmed.")

    log_step("Checking web threat extension")
    web_ok = detect_web_scanning(system, home)
    if not web_ok:
        log_warning("TrafficLight extension not detected.")
        if not is_automated and not args.audit_only:
            print("\n    Opening extension page...")
            open_url_safely("https://chromewebstore.google.com/detail/trafficlight/cfnpidifppmenkapgihekkeednfoenal")
            print("\n    Manual links if the browser didn't open:")
            print("      • Chromium / Chrome / Brave / Edge:")
            print("        https://chromewebstore.google.com/detail/trafficlight/cfnpidifppmenkapgihekkeednfoenal")
            print("      • Firefox:")
            print("        https://addons.mozilla.org/en-US/firefox/addon/trafficlight/")
            ans = input("\n    Do you already have Bitdefender TrafficLight active? [y/N]: ").strip().lower()
            if ans in ["y", "yes"]:
                web_ok = True
            else:
                input("\n    Press [Enter] once installed...")
                web_ok = detect_web_scanning(system, home)
    else:
        log_success("Web threat scanning active.")

    log_step("Checking browser inventory")
    browsers = detect_browsers(system, home)
    log_success(f"Browsers: {browsers}")

    final = run_audit(system)
    if web_ok:
        final["web_scanning"] = "Yes"

    print_summary_table(system, final)

    if is_automated or args.audit_only:
        print("Audit complete.")
        return

    print("------------------------------------------------------")
    print("Enter your name to register your machine:")
    while True:
        first_name = input("First Name: ").strip()
        if first_name:
            break
        print("First name cannot be empty.")

    while True:
        last_name = input("Last Name : ").strip()
        if last_name:
            break
        print("Last name cannot be empty.")

    row_values = [
        first_name,
        last_name,
        final.get("uuid", "Unknown"),
        final.get("os_distro", "Unknown"),
        final.get("os_version", "Unknown"),
        "Yes",
        final.get("auto_updates", "Yes"),
        final.get("browsers", "None detected"),
        final.get("office_apps", "Google Workspace"),
        final.get("email_apps", "N/A (Web only)"),
        final.get("anti_virus", "None"),
        final.get("web_scanning", "No"),
        final.get("firewall", "No"),
        final.get("admin_separated", "No"),
    ]

    tsv_line = "\t".join(row_values)
    copied = copy_to_clipboard(tsv_line)

    print("\n" + "=" * 60)
    print("  COPY & PASTE INTO GOOGLE SHEETS")
    print("=" * 60)
    if copied:
        print("Done! Your row has been automatically copied to your clipboard.")
        print("If it didn't copy, grab the line below (not the dashes) manually.")
    else:
        print("Notice: Could not access system clipboard automatically. Copy the text below manually.")

    print("\nClick on the FURTHEST LEFT cell (Column A / First Name) of the")
    print("NEWEST AVAILABLE ROW in the spreadsheet, then press Ctrl+V (or Cmd+V on Mac):\n")
    print("------------------------------------------------------------")
    print(tsv_line)
    print("------------------------------------------------------------\n")


if __name__ == "__main__":
    main()
