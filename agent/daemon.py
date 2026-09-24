"""Background continuous monitoring daemon and service installer for Linux/macOS/Windows."""

import os
from pathlib import Path
import signal
import sys
import time

from agent.client import ComplianceClient
from agent.collector import collect_telemetry, get_hardware_serial, get_os


class ComplianceDaemon:
    """Continuous posture monitoring daemon with configurable heartbeat intervals."""

    def __init__(self, mode="workstation", interval_seconds=21600, api_url=None, device_token=None):
        self.mode = mode
        self.interval = interval_seconds
        self.running = True
        self.client = ComplianceClient(api_url=api_url, device_token=device_token)

        # Register signal handlers for clean daemon shutdown
        signal.signal(signal.SIGINT, self._handle_exit)
        signal.signal(signal.SIGTERM, self._handle_exit)

    def _handle_exit(self, signum, frame):
        print("\n[Compliance Daemon] Shutting down cleanly...", flush=True)
        self.running = False

    def run_once(self):
        """Execute a single telemetry gathering and dispatch cycle."""
        device_id = get_hardware_serial(get_os())
        payload = collect_telemetry(mode=self.mode, device_id=device_id)
        result = self.client.send_telemetry(payload)
        return payload, result

    def start(self):
        """Start the persistent daemon monitoring loop."""
        print(f"[Compliance Daemon] Started in '{self.mode}' mode. Heartbeat interval: {self.interval}s.", flush=True)
        while self.running:
            try:
                payload, result = self.run_once()
                status = result.get("status", "unknown")
                posture = payload.get("posture", "unknown")
                print(f"[Heartbeat] Time: {payload['collected_at']} | Posture: {posture.upper()} | Sync: {status.upper()}", flush=True)
            except Exception as e:
                print(f"[Heartbeat Error] Failed execution: {e}", file=sys.stderr, flush=True)

            # Sleep in 1-second slices so termination signals break out immediately
            elapsed = 0
            while elapsed < self.interval and self.running:
                time.sleep(1)
                elapsed += 1


def generate_systemd_unit(mode="robot", python_bin=None, script_path=None):
    """Generate a production systemd service definition for Linux robot fleets or workstations."""
    py = python_bin or sys.executable
    script = script_path or "/usr/local/bin/cyber-compliance"
    return f"""[Unit]
Description=Cyber Compliance Continuous Monitoring Daemon ({mode.title()})
After=network.target

[Service]
Type=simple
User=root
ExecStart={py} {script} --daemon --mode {mode}
Restart=always
RestartSec=60
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
"""
