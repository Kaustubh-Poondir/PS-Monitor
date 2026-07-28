import threading
import time
import hashlib
import datetime
from typing import Dict, Set

from Collectors import collect_all_processes
from engine.rule_engine import scan_all



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

    
        self._seen_fingerprints: Set[str] = set()

        self._active: Dict[int, Set[str]] = {}

        
        self._active_start: Dict[int, str] = {}

        self._alert_log: list = []

        self.total_scans      = 0
        self.new_alert_count  = 0
        self.duplicate_count  = 0
        self.resolved_count   = 0


    def _fingerprint(self, pid: int, name: str, start: str, alert_msg: str) -> str:
        """
        Build a unique hash for one specific alert on one specific process.
        Same process + same alert = same hash = duplicate = skip.
        Process that reused a PID after restart = different start_time
        = different hash = treated as new.
        """
        raw = f"{pid}|{name}|{start}|{alert_msg}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


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

                for ev in evaluations:
                    if ev.level not in ("SUSPICIOUS", "RISKY"):
                        continue

                    start = ev.started_at  
                              

                    for alert_msg in ev.alerts:
                        fp = self._fingerprint(ev.pid, ev.name, start, alert_msg)

                        if fp in self._seen_fingerprints:
                            self.duplicate_count += 1
                            continue

                        self._seen_fingerprints.add(fp)
                        self.new_alert_count += 1

                        if ev.pid not in self._active:
                            self._active[ev.pid] = set()
                        self._active[ev.pid].add(alert_msg)
                        self._active_start[ev.pid] = start

                        self.logger.log_crawler_event(
                            "NEW_ALERT",
                            f"[{ev.level}] PID={ev.pid} name={ev.name} "
                            f"user={ev.username} score={ev.score} "
                            f"fp={fp} | {alert_msg}"
                        )

                        self._alert_log.append(CrawlerAlert(
                            pid=ev.pid, name=ev.name, level=ev.level,
                            score=ev.score, alerts=[alert_msg],
                            username=ev.username, exe=ev.exe,
                            timestamp=ts
                        ))

        except Exception as e:
            self.logger.log_error(f"Crawler error: {e}")


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
