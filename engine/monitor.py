"""
engine/monitor.py
The Monitor class orchestrates data collection, rule evaluation,
display rendering, logging, and user-triggered actions.
Also manages the background Crawler instance.
"""

import os
import sys
import signal
import psutil

from Collectors import collect_all_processes, collect_system_stats, collect_services
from engine.rule_engine import scan_all, DEFAULT_CONFIG
from rules import (
    ScanLogger,
    render_header, render_process_table, render_summary,
    render_process_detail, render_service_table, set_color,
    kill_process as _kill, process_exists,
)
from rules.formatter import color_level, bold, cyan, green, red, yellow, grey


class Monitor:
    def __init__(
        self,
        log_path: str = "logs/monitor.log",
        interval: int = 10,
        use_color: bool = True,
        threshold_overrides: dict = None,
    ):
        self.log_path   = log_path
        self.interval   = interval
        self.scan_count = 0
        self.logger     = ScanLogger(log_path)
        self.config     = {**DEFAULT_CONFIG, **(threshold_overrides or {})}
        self.crawler    = None   # set by start_crawler()

        set_color(use_color)
        signal.signal(signal.SIGINT, self._handle_interrupt)
        self._running = True

    def _handle_interrupt(self, *_):
        self._running = False
        if self.crawler and self.crawler.is_running():
            self.crawler.stop()
        print("\n\n  Shutting down. Goodbye!\n")
        sys.exit(0)

    def start_crawler(self, interval: int = 15):
        from engine.crawler import Crawler
        self.crawler = Crawler(
            config=self.config,
            logger=self.logger,
            interval=interval
        )
        self.crawler.start()

    def stop_crawler(self):
        if self.crawler and self.crawler.is_running():
            self.crawler.stop()

    # ── Core scan ──────────────────────────────────────────────────────

    def _do_scan(self):
        self.scan_count += 1
        system_stats = collect_system_stats()
        self.logger.log_scan_start(system_stats)
        processes    = collect_all_processes()
        evaluations  = scan_all(processes, self.config)

        low        = [e for e in evaluations if e.level == "LOW"]
        suspicious = [e for e in evaluations if e.level == "SUSPICIOUS"]
        risky      = [e for e in evaluations if e.level == "RISKY"]

        for ev in suspicious + risky:
            self.logger.log_process_alert(ev)

        self.logger.log_scan_summary(
            len(evaluations), len(low), len(suspicious), len(risky))

        return system_stats, evaluations, len(evaluations), len(low), len(suspicious), len(risky)

    def run_once(self):
        print(grey("  Collecting system stats..."))
        system_stats, evaluations, total, low, suspicious, risky = self._do_scan()
        print(render_header(system_stats, self.scan_count))
        print(f"\n  {bold('Flagged Processes')} {grey('(NORMAL processes hidden)')}\n")
        print(render_process_table(evaluations))
        print(render_summary(total, low, suspicious, risky, self.log_path))

    def run_services_view(self):
        services = collect_services()
        print(bold(cyan("\n  SystemD Services\n")))
        print(render_service_table(services))

    def inspect_pid(self, pid: int):
        if not process_exists(pid):
            print(red(f"\n  PID {pid} not found.\n"))
            return
        try:
            proc = psutil.Process(pid)
            info = {
                "pid":              proc.pid,
                "name":             proc.name(),
                "username":         proc.username(),
                "exe":              self._safe(proc.exe, "N/A"),
                "cmdline":          self._safe(lambda: " ".join(proc.cmdline()), ""),
                "cpu_percent":      proc.cpu_percent(interval=0.2),
                "mem_percent":      proc.memory_percent(),
                "mem_rss_mb":       round(proc.memory_info().rss / 1024**2, 2),
                "connections":      self._safe(lambda: proc.connections(kind="inet"), []),
                "open_files_count": self._safe(lambda: len(proc.open_files()), 0),
                "status":           proc.status(),
                "num_threads":      proc.num_threads(),
                "ppid":             proc.ppid(),
                "nice":             self._safe(proc.nice, None),
                "create_time":      proc.create_time(),
                "started_at":       self._safe(
                    lambda: __import__("datetime").datetime.fromtimestamp(
                        proc.create_time()
                    ).strftime("%Y-%m-%d %H:%M:%S"), "N/A"
                ),
            }
        except psutil.AccessDenied:
            print(red(f"\n  Access denied for PID {pid}. Try sudo.\n"))
            return

        from engine.rule_engine import evaluate_process
        evaluation = evaluate_process(info, self.config)
        self.logger.log_action("INSPECT", f"PID={pid} name={info['name']}")
        print(render_process_detail(evaluation, info))

    def kill_process(self, pid: int):
        if not process_exists(pid):
            print(red(f"\n  PID {pid} not found.\n"))
            return
        try:
            proc = psutil.Process(pid)
            name = proc.name()
        except Exception:
            name = "?"

        confirm = input(yellow(f"\n  Kill PID {pid} ({name})? [y/N] ")).strip().lower()
        if confirm == "y":
            success, msg = _kill(pid)
            if success:
                self.logger.log_action("KILL", f"PID={pid} name={name}")
                print(green(f"  ✓ {msg}\n"))
            else:
                self.logger.log_error(f"Kill failed: {msg}")
                print(red(f"  ✗ {msg}\n"))
        else:
            print(grey("  Cancelled.\n"))

    def show_history(self):
        if not os.path.exists(self.log_path):
            print(yellow(f"\n  Log file not found: {self.log_path}\n"))
            return
        print(bold(cyan(f"\n  === Scan History: {self.log_path} ===\n")))
        with open(self.log_path) as f:
            for line in f:
                line = line.rstrip()
                if "RISKY"       in line: print(red(line))
                elif "SUSPICIOUS"in line: print(yellow(line))
                elif "NEW_ALERT" in line: print(yellow(line))
                elif "RESOLVED"  in line: print(green(line))
                elif "CRAWLER"   in line: print(cyan(line))
                elif "ALERT"     in line: print(yellow(line))
                elif "ERROR"     in line: print(red(line))
                elif "SCAN START"in line or "SCAN END" in line: print(cyan(line))
                else: print(line)

    @staticmethod
    def _safe(fn, default=None):
        try:
            return fn()
        except Exception:
            return default
