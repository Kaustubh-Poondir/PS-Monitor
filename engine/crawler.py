"""
engine/crawler.py
─────────────────
The Crawler is a background daemon thread that continuously watches
processes and services — like a blockchain, it tracks a chain of events
and ensures the SAME alert is NEVER recorded twice (deduplication).

HOW IT WORKS (explain this in viva):
  1. Every N seconds (default 15) it collects all running processes
  2. For each SUSPICIOUS or RISKY process it builds a "fingerprint":
       fingerprint = hash(pid + process_name + start_time + alert_type)
     This fingerprint is stored in a seen_fingerprints set
  3. If the fingerprint already exists → DUPLICATE → silently skipped
  4. If it is NEW → logged ONCE and added to seen_fingerprints
  5. If a previously flagged process disappears → logged as RESOLVED

  Like blockchain:
    - Each alert has a unique hash (fingerprint)
    - Once recorded it is immutable — never re-logged
    - The chain of fingerprints grows only with genuinely NEW events
"""

import threading
import time
import hashlib
import datetime
from typing import Dict, Set

from Collectors import collect_all_processes
from engine.rule_engine import scan_all


# ── One alert entry ────────────────────────────────────────────────────────

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


# ── Crawler ────────────────────────────────────────────────────────────────

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

        # ── Deduplication state ────────────────────────────────────────
        # Set of fingerprint hashes — an alert is only logged if its
        # fingerprint is NOT already in this set
        self._seen_fingerprints: Set[str] = set()

        # pid → set of alert strings currently active for that pid
        self._active: Dict[int, Set[str]] = {}

        # pid → process start_time (used in fingerprint to distinguish
        # a new process that reused an old PID)
        self._active_start: Dict[int, str] = {}

        # All new alerts found this session (for the dashboard)
        self._alert_log: list = []

        # Counters
        self.total_scans      = 0
        self.new_alert_count  = 0
        self.duplicate_count  = 0
        self.resolved_count   = 0

    # ── Fingerprinting ─────────────────────────────────────────────────

    def _fingerprint(self, pid: int, name: str, start: str, alert_msg: str) -> str:
        """
        Build a unique hash for one specific alert on one specific process.
        Same process + same alert = same hash = duplicate = skip.
        Process that reused a PID after restart = different start_time
        = different hash = treated as new.
        """
        raw = f"{pid}|{name}|{start}|{alert_msg}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ── Control ────────────────────────────────────────────────────────

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="PSGuard-Crawler"
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

    # ── Main loop ──────────────────────────────────────────────────────

    def _loop(self):
        while True:
            with self._lock:
                if not self._running:
                    break
            self._scan_once()
            # Sleep in 0.1s chunks so stop() is responsive
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

                # ── Step 1: Check resolved (process no longer running) ──
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

                # ── Step 2: Evaluate flagged processes ──────────────────
                for ev in evaluations:
                    if ev.level not in ("SUSPICIOUS", "RISKY"):
                        continue

                    start = ev.started_at  # ties fingerprint to this
                                           # specific process instance

                    for alert_msg in ev.alerts:
                        fp = self._fingerprint(ev.pid, ev.name, start, alert_msg)

                        if fp in self._seen_fingerprints:
                            # DUPLICATE — already logged, skip silently
                            self.duplicate_count += 1
                            continue

                        # NEW alert — record fingerprint and log it
                        self._seen_fingerprints.add(fp)
                        self.new_alert_count += 1

                        # Track this pid as active
                        if ev.pid not in self._active:
                            self._active[ev.pid] = set()
                        self._active[ev.pid].add(alert_msg)
                        self._active_start[ev.pid] = start

                        # Log to file
                        self.logger.log_crawler_event(
                            "NEW_ALERT",
                            f"[{ev.level}] PID={ev.pid} name={ev.name} "
                            f"user={ev.username} score={ev.score} "
                            f"fp={fp} | {alert_msg}"
                        )

                        # Store for dashboard
                        self._alert_log.append(CrawlerAlert(
                            pid=ev.pid, name=ev.name, level=ev.level,
                            score=ev.score, alerts=[alert_msg],
                            username=ev.username, exe=ev.exe,
                            timestamp=ts
                        ))

        except Exception as e:
            self.logger.log_error(f"Crawler error: {e}")

    # ── Data access ────────────────────────────────────────────────────

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
