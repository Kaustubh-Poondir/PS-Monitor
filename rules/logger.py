"""
rules/logger.py
Writes structured scan results to a rotating log file.
Log format: human-readable with machine-parseable section headers.
"""

import os
import json
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler


# ---------------------------------------------------------------------------
# Structured text logger (scan events)
# ---------------------------------------------------------------------------

class ScanLogger:
    """
    Writes scan summaries and individual process alerts to a log file.
    Each scan is separated by a header block for easy grep/parsing.
    Rotates at 5 MB, keeps 5 backups.
    """

    def __init__(self, log_path: str = "logs/monitor.log"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path) if os.path.dirname(log_path) else ".", exist_ok=True)

        # Python logging backend (handles rotation)
        self._logger = logging.getLogger("psguard")
        self._logger.setLevel(logging.DEBUG)

        if not self._logger.handlers:
            handler = RotatingFileHandler(
                log_path, maxBytes=5 * 1024 * 1024, backupCount=5
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def _write(self, text: str):
        self._logger.info(text)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_scan_start(self, system_stats: dict):
        """Write a scan-start header with system snapshot."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write(
            f"\n{'='*60}\n"
            f"SCAN START  {ts}\n"
            f"{'='*60}\n"
            f"  Host CPU : {system_stats.get('cpu_percent', '?')}%  "
            f"(cores: {system_stats.get('cpu_count', '?')})\n"
            f"  Memory   : {system_stats.get('mem_used_gb', '?')} / "
            f"{system_stats.get('mem_total_gb', '?')} GB  "
            f"({system_stats.get('mem_percent', '?')}%)\n"
            f"  Disk     : {system_stats.get('disk_used_gb', '?')} / "
            f"{system_stats.get('disk_total_gb', '?')} GB  "
            f"({system_stats.get('disk_percent', '?')}%)\n"
            f"  Processes: {system_stats.get('process_count', '?')}\n"
        )

    def log_process_alert(self, evaluation):
        """Log a flagged process evaluation."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write(
            f"[{ts}] ALERT  level={evaluation.level}  score={evaluation.score}\n"
            f"  PID      : {evaluation.pid}\n"
            f"  Name     : {evaluation.name}\n"
            f"  User     : {evaluation.username}\n"
            f"  Path     : {evaluation.exe}\n"
            f"  CPU      : {evaluation.cpu_percent:.1f}%  "
            f"MEM: {evaluation.mem_percent:.1f}% ({evaluation.mem_rss_mb} MB)\n"
            f"  Started  : {evaluation.started_at}\n"
            f"  Alerts   : {', '.join(evaluation.alerts)}\n"
            f"  {'- '*28}\n"
        )

    def log_scan_summary(self, total: int, low: int, suspicious: int, risky: int):
        """Write end-of-scan summary line."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write(
            f"SCAN END    {ts}\n"
            f"  Scanned={total}  Low={low}  Suspicious={suspicious}  Risky={risky}\n"
            f"{'='*60}\n"
        )

    def log_action(self, action: str, detail: str):
        """Log a user-triggered action (kill, inspect, etc.)."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write(f"[{ts}] ACTION  {action}: {detail}")

    def log_error(self, message: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write(f"[{ts}] ERROR   {message}")

    def log_crawler_event(self, event_type: str, detail: str):
        """Log a crawler-specific event (NEW_ALERT, RESOLVED, DUPLICATE, etc.)."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write(f"[{ts}] CRAWLER {event_type:<16} {detail}")
