"""
The Crawler is a background daemon thread that continuously watches
processes and services — like a blockchain, it tracks a chain of events
and ensures the SAME alert is NEVER recorded twice (deduplication).

HOW IT WORKS:
  1. Every N seconds (default 15) it collects all running processes
  2. For each SUSPICIOUS or RISKY process it builds a "fingerprint":
       fingerprint = hash(pid + process_name + start_time + alert_type)
     This fingerprint is stored in a seen_fingerprints set
  3. If the fingerprint already exists → DUPLICATE → silently skipped
  4. If it is NEW → logged ONCE and added to seen_fingerprints
  5. If a previously flagged process disappears → logged as RESOLVED
"""

import threading
import time
import hashlib
import datetime
from typing import Dict, Set

from Collectors import collect_all_processes
from engine.rule_engine import scan_all


# One alert entry

class CrawlerAlert:
    def __init__(self, pid, name, level, score, alerts, username, exe, timestamp):
        self.pid       = pid
        self.name      = name
        self.level     = level
        self.score     = score
        self.alerts    = alerts
        self.username  = username
        self.exe       = exe
        self.timestamp = timestamp


# Crawler

class Crawler:
    """
    Background deduplication crawler.

    Usage:
        crawler = Crawler(config=monitor.config, logger=monitor.logger)
        crawler.start()
        ...
        crawler.stop()
        summary = crawler.get_summary()
    """

    def __init__(self, config: dict, logger, interval: int = 15):
        self.config   = config
        self.logger   = logger
        self.interval = interval

        self._lock    = threading.Lock()
        self._thread  = None
        self._running = False

        #deduplication state: fingerprints we've already logged — an alert only gets written once its fingerprint shows up here
         
        self._seen_fingerprints: Set[str] = set()

        # maps each pid to the alert messages currently active for it
        self._active: Dict[int, Set[str]] = {}

        # maps each pid to its start time, so a reused pid isn't mistaken for the same process
         
        self._active_start: Dict[int, str] = {}

        # every new alert found this session, kept for the dashboard
        self._alert_log: list = []

        # running totals shown on the dashboard
        self.total_scans      = 0
        self.new_alert_count  = 0
        self.duplicate_count  = 0
        self.resolved_count   = 0

    # Fingerprinting

    def _fingerprint(self, pid: int, name: str, start: str, alert_msg: str) -> str:
        """
        Build a unique hash for one specific alert on one specific process.
        Same process + same alert = same hash = duplicate = skip.
        Process that reused a PID after restart = different start_time
        = different hash = treated as new.
        """
        raw = f"{pid}|{name}|{start}|{alert_msg}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    #Control

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="PS-Monitor-Crawler"
        )
        self._thread.start()
        self.logger.log_crawler_event(
            "CRAWLER_START",
            f"Background crawler started (interval={self.interval}s)"
        )

    def stop(self):
        with self._lock:
            self._running = False
        if self._thread:
            self._thread.join(timeout=self.interval + 2)
        self.logger.log_crawler_event(
            "CRAWLER_STOP",
            f"Crawler stopped — scans={self.total_scans} "
            f"new={self.new_alert_count} dupes={self.duplicate_count} "
            f"resolved={self.resolved_count}"
        )

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    # Main loop

    def _loop(self):
        while True:
            with self._lock:
                if not self._running:
                    break
            self._scan_once()
            for _ in range(self.interval * 10):
                with self._lock:
                    if not self._running:
                        return
                time.sleep(0.1)

    def _scan_once(self):
        try:
            processes   = collect_all_processes()
            evaluations = scan_all(processes, self.config)
            ts          = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with self._lock:
                self.total_scans += 1
                current_pids = {ev.pid for ev in evaluations}

                # step 1: figure out if any flagged process has since ended
                for pid in list(self._active.keys()):
                    if pid not in current_pids:
                        name = "unknown"
                        self.logger.log_crawler_event(
                            "RESOLVED",
                            f"PID {pid} disappeared — alerts cleared"
                        )
                        del self._active[pid]
                        self._active_start.pop(pid, None)
                        self.resolved_count += 1

                # step 2: look at everything still flagged as risky
                for ev in evaluations:
                    if ev.level not in ("SUSPICIOUS", "RISKY"):
                        continue

                    start = ev.started_at  # fingerprint same as the process instance

                    for alert_msg in ev.alerts:
                        fp = self._fingerprint(ev.pid, ev.name, start, alert_msg)

                        if fp in self._seen_fingerprints:
                            # already logged this , so skipping it quietly
                            self.duplicate_count += 1
                            continue

                        # first time seeing this alert, so record and log it
                        self._seen_fingerprints.add(fp)
                        self.new_alert_count += 1

                        # remember this pid as currently flagged
                        if ev.pid not in self._active:
                            self._active[ev.pid] = set()
                        self._active[ev.pid].add(alert_msg)
                        self._active_start[ev.pid] = start

                        # write the alert out to the log file
                        self.logger.log_crawler_event(
                            "NEW_ALERT",
                            f"[{ev.level}] PID={ev.pid} name={ev.name} "
                            f"user={ev.username} score={ev.score} "
                            f"fp={fp} | {alert_msg}"
                        )

                        # keep a copy around for the live dashboard
                        self._alert_log.append(CrawlerAlert(
                            pid=ev.pid, name=ev.name, level=ev.level,
                            score=ev.score, alerts=[alert_msg],
                            username=ev.username, exe=ev.exe,
                            timestamp=ts
                        ))

        except Exception as e:
            self.logger.log_error(f"Crawler error: {e}")

    # Data access

    def get_summary(self) -> dict:
        """Thread-safe snapshot for the UI."""
        with self._lock:
            return {
                "running":          self._running,
                "total_scans":      self.total_scans,
                "new_alert_count":  self.new_alert_count,
                "duplicate_count":  self.duplicate_count,
                "resolved_count":   self.resolved_count,
                "active_flagged":   len(self._active),
                "recent_alerts":    list(self._alert_log[-20:]),
            }

    def get_active_flagged(self) -> dict:
        with self._lock:
            return {pid: set(alerts) for pid, alerts in self._active.items()}

    def reset(self):
        """Clear all deduplication state (manual refresh)."""
        with self._lock:
            self._seen_fingerprints.clear()
            self._active.clear()
            self._active_start.clear()
            self._alert_log.clear()
            self.new_alert_count  = 0
            self.duplicate_count  = 0
            self.resolved_count   = 0
