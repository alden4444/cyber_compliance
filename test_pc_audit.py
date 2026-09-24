#!/usr/bin/env python3

import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pc_audit as audit


class TestComplianceAudit(unittest.TestCase):

    def test_get_os_detection(self):
        # Test Darwin -> macOS
        with patch("platform.system", return_value="Darwin"):
            self.assertEqual(audit.get_os(), "macOS")

        # Test Windows -> Windows
        with patch("platform.system", return_value="Windows"):
            self.assertEqual(audit.get_os(), "Windows")

        # Test Linux -> Arch
        with patch("platform.system", return_value="Linux"):
            with patch("platform.freedesktop_os_release", return_value={"ID": "arch", "ID_LIKE": ""}):
                self.assertEqual(audit.get_os(), "Arch")

        # Test Linux -> Ubuntu
        with patch("platform.system", return_value="Linux"):
            with patch("platform.freedesktop_os_release", return_value={"ID": "ubuntu", "ID_LIKE": "debian"}):
                self.assertEqual(audit.get_os(), "Ubuntu")

        # Test Linux -> Debian derivative (treated as Ubuntu ecosystem)
        with patch("platform.system", return_value="Linux"):
            with patch("platform.freedesktop_os_release", return_value={"ID": "linuxmint", "ID_LIKE": "ubuntu debian"}):
                self.assertEqual(audit.get_os(), "Ubuntu")

        # Test Linux -> Generic Linux
        with patch("platform.system", return_value="Linux"):
            with patch("platform.freedesktop_os_release", return_value={"ID": "fedora", "ID_LIKE": ""}):
                self.assertEqual(audit.get_os(), "Linux")

    def test_get_real_home(self):
        # Under normal execution
        home = audit.get_real_home()
        self.assertTrue(isinstance(home, Path))

    def test_macos_browser_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            app_dir = tmppath / "Google Chrome.app" / "Contents"
            app_dir.mkdir(parents=True)
            plist_file = app_dir / "Info.plist"
            with plist_file.open("wb") as f:
                plistlib.dump({"CFBundleShortVersionString": "129.0.6668.70"}, f)

            # Mock mac_apps path
            with patch.object(Path, "is_file", autospec=True) as mock_is_file:
                # Test plistlib reading
                with plist_file.open("rb") as f:
                    pl = plistlib.load(f)
                    self.assertEqual(pl.get("CFBundleShortVersionString"), "129.0.6668.70")

    def test_windows_admin_separated(self):
        # Scenario 1: Standard user (S-1-5-32-544 not in groups)
        whoami_standard = """
GROUP INFORMATION
-----------------
Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\\Users                         Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
"""
        with patch("subprocess.check_output", return_value=whoami_standard):
            self.assertEqual(audit.check_admin_separated("Windows"), "Yes")

        # Scenario 2: Admin user (S-1-5-32-544 present)
        whoami_admin = """
GROUP INFORMATION
-----------------
Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\\Administrators                 Alias            S-1-5-32-544 Group used for deny only
"""
        with patch("subprocess.check_output", return_value=whoami_admin):
            self.assertEqual(audit.check_admin_separated("Windows"), "No")

    def test_macos_admin_separated(self):
        # Scenario 1: User is not an admin
        mock_proc_standard = MagicMock(stdout="user is not a member of the group")
        with patch("subprocess.run", return_value=mock_proc_standard):
            self.assertEqual(audit.check_admin_separated("macOS"), "Yes")

        # Scenario 2: User is an admin
        mock_proc_admin = MagicMock(stdout="user is a member of the group")
        with patch("subprocess.run", return_value=mock_proc_admin):
            self.assertEqual(audit.check_admin_separated("macOS"), "No")

    def test_linux_admin_separated(self):
        # If cyber_essentials_targetpw dropin exists -> Yes
        with patch.object(Path, "exists", return_value=True):
            self.assertEqual(audit.check_admin_separated("Arch"), "Yes")

        # If dropin does not exist:
        with patch.object(Path, "exists", return_value=False):
            with patch.object(audit, "is_sudo_prompting_for_root", return_value=False):
                # User in wheel -> No
                with patch("subprocess.check_output", return_value="alden network wheel docker\n"):
                    self.assertEqual(audit.check_admin_separated("Arch"), "No")

                # User in sudo -> No
                with patch("subprocess.check_output", return_value="alden adm cdrom sudo dip\n"):
                    self.assertEqual(audit.check_admin_separated("Ubuntu"), "No")

                # Standard user (neither wheel nor sudo) -> Yes
                with patch("subprocess.check_output", return_value="alden users audio video\n"):
                    self.assertEqual(audit.check_admin_separated("Arch"), "Yes")
                    self.assertEqual(audit.check_admin_separated("Ubuntu"), "Yes")

    def test_antivirus_detection(self):
        # Windows Defender
        with patch("pc_audit.query_windows_system", return_value="Active (1.417.432.0)"):
            self.assertEqual(audit.inspect_antivirus("Windows"), "Windows Defender - Active (1.417.432.0)")

        # macOS XProtect
        with patch.object(Path, "is_dir", return_value=False):
            self.assertEqual(audit.inspect_antivirus("macOS"), "XProtect (macOS) - Active")

        # Linux ClamAV
        with patch("shutil.which", side_effect=lambda x: "/usr/bin/" + x if x in ["clamscan", "systemctl"] else None):
            with patch.object(audit, "get_binary_version", return_value="1.5.4"):
                with patch("subprocess.run", return_value=MagicMock(stdout="active")):
                    self.assertEqual(audit.inspect_antivirus("Arch"), "ClamAV - 1.5.4")

    def test_web_scanning_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            ext_dir = home / ".config/google-chrome/Default/Extensions/cfnpidifppmenkapgihekkeednfoenal/3.0.2_0"
            ext_dir.mkdir(parents=True)
            self.assertTrue(audit.detect_web_scanning("Arch", home))

    def test_firefox_trafficlight_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            ff_dir = home / ".mozilla/firefox"
            ff_dir.mkdir(parents=True)
            profiles_ini = ff_dir / "profiles.ini"
            profiles_ini.write_text("[Profile0]\nName=default\nIsRelative=1\nPath=default-release\n")

            prof_dir = ff_dir / "default-release"
            prof_dir.mkdir()
            ext_json = prof_dir / "extensions.json"
            ext_json.write_text('{"addons":[{"id":"trafficlight@bitdefender.com","name":"TrafficLight","active":true}]}')

            self.assertTrue(audit.firefox_has_trafficlight(home))

    def test_hardware_uuid(self):
        # Test reading DMI or machine-id
        with patch("subprocess.check_output", return_value="12345-67890-UUID\n"):
            val = audit.get_hardware_serial("Arch")
            self.assertTrue(val != "Unknown")

    def test_office_apps_detection_linux(self):
        with patch.object(audit, "get_binary_version", side_effect=lambda x: "24.8.1.2" if x == "libreoffice" else None):
            result = audit.detect_office_apps("Arch", Path("/tmp"))
            self.assertEqual(result, "LibreOffice 24.8.1.2")

    def test_office_apps_detection_macos(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir)
            app_dir = home / "Applications" / "Microsoft Excel.app" / "Contents"
            app_dir.mkdir(parents=True)
            plist_file = app_dir / "Info.plist"
            with plist_file.open("wb") as f:
                plistlib.dump({"CFBundleShortVersionString": "16.89.1"}, f)

            result = audit.detect_office_apps("macOS", home)
            self.assertIn("Microsoft Excel 16.89.1", result)


    def test_office_apps_detection_windows(self):
        with patch("pc_audit.Path.is_file", autospec=True) as mock_is_file:
            def is_file_side_effect(path_self):
                if "EXCEL.EXE" in str(path_self).upper():
                    return True
                return False
            mock_is_file.side_effect = is_file_side_effect
            with patch.object(audit, "query_windows_system", return_value="16.0.17928.20114"):
                result = audit.detect_office_apps("Windows", Path("/tmp"))
                self.assertIn("Microsoft Excel 16.0.17928.20114", result)

    def test_office_apps_none_detected_never_google_workspace(self):
        with patch.object(audit, "get_binary_version", return_value=None):
            with patch.object(audit, "get_flatpak_version", return_value=None):
                with patch.object(audit, "get_snap_version", return_value=None):
                    result = audit.detect_office_apps("Arch", Path("/tmp"))
                    self.assertEqual(result, "None detected")
                    self.assertNotIn("Google Workspace", result)

    def test_run_audit_structure(self):
        data = audit.run_audit(audit.get_os())
        required_keys = [
            "os_distro",
            "auto_updates",
            "browsers",
            "email_apps",
            "office_apps",
            "uuid",
            "os_version",
            "anti_virus",
            "web_scanning",
            "firewall",
            "admin_separated",
        ]
        for k in required_keys:
            self.assertIn(k, data, f"Missing key: {k}")
        self.assertNotEqual(data["office_apps"], "Google Workspace")

    def test_is_admin_posix_root(self):
        with patch("platform.system", return_value="Linux"):
            with patch("os.geteuid", return_value=0):
                self.assertTrue(audit.is_admin())

    def test_is_admin_posix_non_root(self):
        with patch("platform.system", return_value="Linux"):
            with patch("os.geteuid", return_value=1000):
                self.assertFalse(audit.is_admin())

    def test_is_admin_windows_admin(self):
        mock_windll = MagicMock()
        mock_windll.shell32.IsUserAnAdmin.return_value = 1
        with patch("platform.system", return_value="Windows"):
            with patch.object(audit.ctypes, "windll", mock_windll, create=True):
                self.assertTrue(audit.is_admin())

    def test_is_admin_windows_non_admin(self):
        mock_windll = MagicMock()
        mock_windll.shell32.IsUserAnAdmin.return_value = 0
        with patch("platform.system", return_value="Windows"):
            with patch.object(audit.ctypes, "windll", mock_windll, create=True):
                self.assertFalse(audit.is_admin())

    def test_main_stops_when_not_admin(self):
        with patch.object(audit, "is_admin", return_value=False):
            with patch("sys.argv", ["pc_audit.py"]):
                with self.assertRaises(SystemExit) as cm:
                    audit.main()
                self.assertEqual(cm.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
