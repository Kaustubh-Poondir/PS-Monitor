"""
Collectors/process_collector.py
Gathers raw process data from the OS using psutil.
Returns structured dicts that the rule engine can evaluate.
"""

import psutil
import os
from datetime import datetime


def _safe(fn, default=None):
    """Call fn(); return default on any exception (AccessDenied, NoSuchProcess…)."""
    try:
        return fn()
    except Exception:
        return default


def collect_all_processes():
    """
    Iterate over every running process and return a list of info dicts.
    Each dict contains fields needed by the rule engine.
    """
    processes = []

    attrs = ["pid", "name", "username", "status", "ppid",
             "create_time", "nice", "num_threads"]

    for proc in psutil.process_iter(attrs, ad_value=None):
        info = proc.info.copy()

        # Fields that require a separate call (may raise exceptions)
        info["exe"]        = _safe(proc.exe, "N/A")
        info["cmdline"]    = _safe(lambda: " ".join(proc.cmdline()), "N/A")
        info["cpu_percent"]= _safe(lambda: proc.cpu_percent(interval=0.05), 0.0)
        info["mem_percent"]= _safe(proc.memory_percent, 0.0)
        info["mem_rss_mb"] = _safe(lambda: round(proc.memory_info().rss / 1024 / 1024, 2), 0.0)
        info["connections"]= _safe(lambda: proc.connections(kind="inet"), [])
        info["open_files_count"] = _safe(lambda: len(proc.open_files()), 0)

        # Resolve create_time to human-readable
        ct = info.get("create_time")
        info["started_at"] = (
            datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S") if ct else "N/A"
        )

        # Keep the live proc object so rules can do extra queries
        info["_proc"] = proc

        processes.append(info)

    return processes


def collect_system_stats():
    """
    Return a snapshot of overall system health metrics.
    Used for the dashboard header.
    """
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()

    return {
        "cpu_percent":      psutil.cpu_percent(interval=0.5),
        "cpu_count":        psutil.cpu_count(logical=True),
        "mem_total_gb":     round(vm.total / 1024**3, 2),
        "mem_used_gb":      round(vm.used / 1024**3, 2),
        "mem_percent":      vm.percent,
        "disk_total_gb":    round(disk.total / 1024**3, 2),
        "disk_used_gb":     round(disk.used / 1024**3, 2),
        "disk_percent":     disk.percent,
        "net_bytes_sent":   net.bytes_sent,
        "net_bytes_recv":   net.bytes_recv,
        "boot_time":        datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        "process_count":    len(psutil.pids()),
    }
