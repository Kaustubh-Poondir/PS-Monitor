"""
Collectors/service_collector.py
Gathers systemd service status using `systemctl`.
Falls back gracefully if systemd is not available.
"""

import subprocess
import shutil
from dataclasses import dataclass, field
from typing import List


@dataclass
class ServiceInfo:
    name: str
    load_state: str   = "unknown"
    active_state: str = "unknown"
    sub_state: str    = "unknown"
    description: str  = ""
    pid: int          = 0
    memory_mb: float  = 0.0
    extra: dict       = field(default_factory=dict)

    @property
    def is_running(self):
        return self.active_state == "active" and self.sub_state == "running"

    @property
    def status_label(self):
        if self.is_running:
            return "RUNNING"
        if self.active_state == "failed":
            return "FAILED"
        if self.active_state == "inactive":
            return "STOPPED"
        return self.active_state.upper()


def _systemctl_available():
    return shutil.which("systemctl") is not None


def _run(cmd):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip()
    except Exception:
        return ""


def collect_services(unit_filter: str = "") -> List[ServiceInfo]:
    """
    Return a list of ServiceInfo objects for all (or filtered) systemd units.
    unit_filter: optional substring to match against service name.
    """
    if not _systemctl_available():
        return []

    # List units in machine-readable format
    raw = _run(
        ["systemctl", "list-units", "--type=service",
         "--all", "--no-pager", "--no-legend",
         "--output=json"]
    )

    services = []

    if raw and raw.startswith("["):
        # JSON output (systemd >= 245)
        import json
        try:
            units = json.loads(raw)
        except Exception:
            units = []

        for u in units:
            name = u.get("unit", "")
            if unit_filter and unit_filter.lower() not in name.lower():
                continue
            svc = ServiceInfo(
                name=name,
                load_state=u.get("load", ""),
                active_state=u.get("active", ""),
                sub_state=u.get("sub", ""),
                description=u.get("description", ""),
            )
            services.append(svc)
    else:
        # Fallback: parse plain text output
        raw_plain = _run(
            ["systemctl", "list-units", "--type=service",
             "--all", "--no-pager", "--no-legend"]
        )
        for line in raw_plain.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4:
                continue
            name = parts[0].strip()
            if unit_filter and unit_filter.lower() not in name.lower():
                continue
            svc = ServiceInfo(
                name=name,
                load_state=parts[1],
                active_state=parts[2],
                sub_state=parts[3],
                description=parts[4] if len(parts) > 4 else "",
            )
            services.append(svc)

    return services


def get_service_detail(service_name: str) -> dict:
    """
    Return detailed properties for one service via `systemctl show`.
    """
    if not _systemctl_available():
        return {}

    raw = _run(["systemctl", "show", service_name, "--no-pager"])
    props = {}
    for line in raw.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            props[k.strip()] = v.strip()
    return props
