"""HTTP/HTTPS client and offline buffering manager for the compliance agent.

Uses Python standard library only (urllib.request).
Supports offline queueing, local caching, and automatic replay when connectivity returns.
"""

import json
import os
from pathlib import Path
import ssl
import sys
import time
import urllib.error
import urllib.request


def get_default_config_path():
    """Return platform-appropriate configuration file path."""
    if os.geteuid() == 0 if hasattr(os, "geteuid") else False:
        return Path("/etc/cyber-compliance/config.json")
    home = Path.home()
    return home / ".config" / "cyber-compliance" / "config.json"


def get_default_queue_path():
    """Return platform-appropriate offline telemetry queue path."""
    if os.geteuid() == 0 if hasattr(os, "geteuid") else False:
        return Path("/var/lib/cyber-compliance/queue.json")
    home = Path.home()
    return home / ".cache" / "cyber-compliance" / "queue.json"


class ComplianceClient:
    """Manages secure communication between agent and central SaaS API."""

    def __init__(self, api_url=None, device_token=None, config_path=None, queue_path=None):
        self.config_path = Path(config_path) if config_path else get_default_config_path()
        self.queue_path = Path(queue_path) if queue_path else get_default_queue_path()
        self.api_url = (api_url or os.environ.get("COMPLIANCE_API_URL") or "").rstrip("/")
        self.device_token = device_token or os.environ.get("COMPLIANCE_DEVICE_TOKEN")
        self.load_config()

    def load_config(self):
        """Load stored device credentials from local config if present."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if not self.api_url:
                        self.api_url = data.get("api_url", "").rstrip("/")
                    if not self.device_token:
                        self.device_token = data.get("device_token")
            except Exception:
                pass

    def save_config(self, api_url, device_token, device_id, org_id, mode="workstation", fleet_tag=None):
        """Save enrollment state to local configuration file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "api_url": api_url,
            "device_token": device_token,
            "device_id": device_id,
            "org_id": org_id,
            "mode": mode,
            "fleet_tag": fleet_tag,
            "enrolled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        # Set restrictive permissions if on POSIX
        try:
            os.chmod(self.config_path, 0o600)
        except Exception:
            pass
        self.api_url = api_url.rstrip("/")
        self.device_token = device_token

    def enroll(self, api_url, org_token, device_id, hostname, mode="workstation", fleet_tag=None, owner_email=None):
        """Enroll this node with the central SaaS platform."""
        endpoint = f"{api_url.rstrip('/')}/api/v1/enroll"
        payload = {
            "org_token": org_token,
            "device_id": device_id,
            "hostname": hostname,
            "mode": mode,
            "fleet_tag": fleet_tag,
            "owner_email": owner_email,
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "CyberComplianceAgent/1.0",
            },
            method="POST",
        )

        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                token = result.get("device_token")
                org_id = result.get("org_id")
                if token:
                    self.save_config(api_url, token, device_id, org_id, mode, fleet_tag)
                return result
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8") if e.fp else str(e)
            return {"error": f"Enrollment HTTP {e.code}: {err_msg}"}
        except Exception as e:
            return {"error": f"Enrollment failed: {str(e)}"}

    def send_telemetry(self, telemetry_payload):
        """Dispatch telemetry payload to central SaaS API, queueing if offline."""
        if not self.api_url or not self.device_token:
            self._queue_telemetry(telemetry_payload)
            return {"status": "queued", "reason": "No API credentials configured"}

        endpoint = f"{self.api_url}/api/v1/telemetry"
        data_bytes = json.dumps(telemetry_payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.device_token}",
                "User-Agent": "CyberComplianceAgent/1.0",
            },
            method="POST",
        )

        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                # Telemetry sent successfully; flush any pending offline queue items
                self._flush_queue()
                return {"status": "sent", "response": resp_data}
        except Exception as e:
            # Buffer locally for automatic replay
            self._queue_telemetry(telemetry_payload)
            return {"status": "queued", "error": str(e)}

    def _queue_telemetry(self, payload):
        """Append an unsendable payload to the local offline disk queue."""
        self.queue_path.parent.mkdir(parents=True, exist_ok=True)
        queue = []
        if self.queue_path.exists():
            try:
                with open(self.queue_path, "r", encoding="utf-8") as f:
                    queue = json.load(f)
            except Exception:
                queue = []

        # Keep maximum 50 buffered heartbeats to prevent unbounded disk growth
        if len(queue) >= 50:
            queue.pop(0)

        queue.append(payload)
        with open(self.queue_path, "w", encoding="utf-8") as f:
            json.dump(queue, f, indent=2)

    def _flush_queue(self):
        """Replay queued telemetry records in FIFO order once connectivity resumes."""
        if not self.queue_path.exists():
            return
        try:
            with open(self.queue_path, "r", encoding="utf-8") as f:
                queue = json.load(f)
        except Exception:
            return

        if not queue:
            return

        remaining = []
        ctx = ssl.create_default_context()
        endpoint = f"{self.api_url}/api/v1/telemetry"

        for item in queue:
            try:
                data_bytes = json.dumps(item).encode("utf-8")
                req = urllib.request.Request(
                    endpoint,
                    data=data_bytes,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.device_token}",
                        "User-Agent": "CyberComplianceAgent/1.0",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                    pass
            except Exception:
                remaining.append(item)

        with open(self.queue_path, "w", encoding="utf-8") as f:
            json.dump(remaining, f, indent=2)
