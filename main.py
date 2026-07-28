
"""
CLI Based Process and Service Monitoring Tool
Arrow-key menu + paged output + background deduplication crawler.
"""

import os
import sys
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import menu
from engine.monitor import Monitor
from rules.formatter import bold, cyan, green, red, yellow, grey, white

monitor = Monitor(log_path="logs/monitor.log")

PAGE_SIZE = 10


#pager
def pager(lines):
    term_h = shutil.get_terminal_size((80, 24)).lines
    page_h = term_h - 6
    total  = len(lines)
    pos    = 0
    while pos < total:
        os.system("clear")
        print("\n".join(lines[pos : pos + page_h]))
        pos += page_h
        if pos < total:
            print()
            print(cyan("  ─────────────────────────────────────────────────────"))
            print(cyan(f"  Showing lines {pos - page_h + 1}–{min(pos, total)} of {total}"))
            ans = input(grey("  Enter = next page   q = stop   a = show all: ")).strip().lower()
            if ans == "q":
                break
            elif ans == "a":
                os.system("clear")
                print("\n".join(lines[pos:]))
                break
        else:
            print()
            print(cyan("  ─── End of output ───────────────────────────────────"))


def pause():
    print()
    input(grey("  ↩  Press Enter to return to the Main Menu..."))


#ui integration
def tip(text):
    print(cyan("  ┌─ 💡 TIP " + "─" * 50))
    for line in text.strip().split("\n"):
        print(cyan("  │ ") + grey(line.strip()))
    print(cyan("  └" + "─" * 59))
    print()

def info_box(lines):
    print(cyan("  ┌" + "─" * 59))
    for line in lines:
        print(cyan("  │ ") + line)
    print(cyan("  └" + "─" * 59))
    print()

def section_header(title, subtitle=""):
    os.system("clear")
    BOX_INNER = 58 

    title_text    = f"   PS Monitor — {title}"
    subtitle_text = f"   {subtitle}" if subtitle else ""

    #padding based on visible length not raw string length    
    title_padded    = title_text    + " " * (BOX_INNER - len(title_text))
    subtitle_padded = subtitle_text + " " * (BOX_INNER - len(subtitle_text))

    border = "═" * BOX_INNER

    print()
    print(cyan(f"  ╔{border}╗"))
    print(cyan("  ║") + bold(title_padded) + cyan("║"))
    if subtitle:
        print(cyan("  ║") + grey(subtitle_padded) + cyan("║"))
    print(cyan(f"  ╚{border}╝"))
    print()

def crawler_status_line():
    """Single line showing crawler state — shown at top of main menu."""
    if monitor.crawler and monitor.crawler.is_running():
        s = monitor.crawler.get_summary()
        return (
            green("  ● CRAWLER ACTIVE") +
            grey(f"   scans={s['total_scans']}  "
                 f"new alerts={s['new_alert_count']}  "
                 f"duplicates blocked={s['duplicate_count']}  "
                 f"resolved={s['resolved_count']}")
        )
    return grey("  ○ Crawler not running  (start it from Crawler menu)")


#full process scan

def menu_scan():
    section_header("Full Process Scan", "Checking every running process on this system")

    tip(
        "Processes are colour-coded by risk level:\n"
        "  GREEN  = Normal     — safe, nothing unusual\n"
        "  CYAN   = Low        — minor flag, worth knowing\n"
        "  YELLOW = Suspicious — investigate this\n"
        "  RED    = Risky      — take action immediately!"
    )

    print(grey("  Scanning... this may take a few seconds.\n"))

    from Collectors import collect_all_processes, collect_system_stats
    from engine.rule_engine import scan_all
    from rules.formatter import (render_header, render_summary,
                                  _LEVEL_ICON, _LEVEL_EXPLAIN,
                                  _ALERT_EXPLAIN, LEVEL_COLOR)

    system_stats = collect_system_stats()
    monitor.scan_count += 1
    evaluations  = scan_all(collect_all_processes(), monitor.config)

    low        = [e for e in evaluations if e.level == "LOW"]
    suspicious = [e for e in evaluations if e.level == "SUSPICIOUS"]
    risky      = [e for e in evaluations if e.level == "RISKY"]
    flagged    = sorted(risky + suspicious + low, key=lambda e: e.score, reverse=True)

    monitor.logger.log_scan_start(system_stats)
    for ev in suspicious + risky:
        monitor.logger.log_process_alert(ev)
    monitor.logger.log_scan_summary(
        len(evaluations), len(low), len(suspicious), len(risky))

    out = []
    out += render_header(system_stats, monitor.scan_count).split("\n")
    out += ["", f"  {bold('Scan Results')}  {grey(f'({len(evaluations)} processes scanned)')}", ""]

    if not flagged:
        out.append(green("  ✓  All clear! Every process passed the security checks."))
    else:
        shown = flagged[:PAGE_SIZE]
        out.append(f"  Showing top {len(shown)} flagged processes  "
                   + grey(f"({len(flagged)} total flagged, sorted by risk)"))
        out.append("")

        for ev in shown:
            icon    = _LEVEL_ICON.get(ev.level, "?")
            color   = LEVEL_COLOR.get(ev.level, lambda x: x)
            explain = _LEVEL_EXPLAIN.get(ev.level, "")

            out.append(color("  " + "─" * 60))
            out.append(
                "  " + color(bold(f"{icon}  {ev.level}")) +
                "  " + bold(ev.name) +
                "  " + grey(f"(PID {ev.pid})  Risk score: {ev.score}")
            )
            out.append(f"  {grey(explain)}")
            out.append("")
            out.append(f"    {grey('User:'):<18} {ev.username}")
            out.append(
                f"    {grey('CPU:'):<18} {ev.cpu_percent:.1f}%   "
                f"{grey('RAM:'):<18} {ev.mem_percent:.1f}% ({ev.mem_rss_mb} MB)"
            )
            out.append(f"    {grey('Path:'):<18} {ev.exe}")
            out.append(f"    {grey('Started:'):<18} {ev.started_at}")

            if ev.alerts:
                out.append("")
                out.append(f"    {bold('Why it was flagged:')}")
                for alert in ev.alerts:
                    found = next(
                        (v for k, v in _ALERT_EXPLAIN.items() if k in alert.lower()), "")
                    out.append(f"      {color('⚑')} {color(alert)}")
                    if found:
                        out.append(f"        {grey('→ ' + found)}")
            out.append("")

        if len(flagged) > PAGE_SIZE:
            out.append(yellow(f"  … {len(flagged) - PAGE_SIZE} more flagged processes not shown."))
            out.append(grey("  Use option 2 (Inspect a process) to examine any PID directly."))

    out.append("")
    out += render_summary(
        len(evaluations), len(low), len(suspicious), len(risky),
        monitor.log_path).split("\n")

    info_box([
        bold("  Quick column guide:"),
        "",
        cyan("  PID       ") + grey("— Unique number Linux assigns to each running process"),
        cyan("  CPU%      ") + grey("— % of processor being used"),
        cyan("  RAM%      ") + grey("— % of total memory being used"),
        cyan("  Score     ") + grey("— Risk points from every rule that fired"),
        cyan("  RISKY     ") + grey("— Score 7+, multiple rules triggered"),
        cyan("  SUSPICIOUS") + grey(" — Score 4–6, one significant rule fired"),
        cyan("  LOW       ") + grey("— Score 1–3, minor flag only"),
    ])

    pager(out)
    pause()


#inspect process

def menu_inspect():
    section_header("Inspect a Process", "Deep-dive into one process using its PID")

    tip(
        "A PID is the unique number Linux assigns to every running program.\n"
        "Run a scan first (option 1) to see PIDs, or run:\n"
        "  ps aux | grep programname   in another terminal."
    )

    pid_str = input(cyan("  Enter the PID you want to inspect: ")).strip()
    if not pid_str.isdigit():
        print(red("\n  ✗  That's not a valid PID — please enter a number only."))
        pause()
        return

    section_header(f"Process Detail — PID {pid_str}", "Full security and resource analysis")
    monitor.inspect_pid(int(pid_str))

    print()
    info_box([
        bold("  Reading this output:"),
        "",
        cyan("  Executable  ") + grey("— The actual file on disk that is running"),
        cyan("  Command     ") + grey("— The full command used to launch this process"),
        cyan("  PPID        ") + grey("— Parent PID: the process that started this one"),
        cyan("  Nice        ") + grey("— Scheduling priority (lower = more CPU time)"),
        cyan("  Threads     ") + grey("— How many parallel sub-tasks this process runs"),
        cyan("  Connections ") + grey("— Active network connections (IP:port)"),
    ])
    pause()


#kill process

def menu_kill():
    section_header("Kill a Process", "Force-stop a process by its PID")

    info_box([
        yellow("  ⚠  WARNING — Read before you proceed:"),
        "",
        grey("  Killing a process force-stops it immediately."),
        grey("  Killing the wrong process can crash services or lose data."),
        grey("  If unsure, use Inspect (option 2) to research it first."),
    ])

    pid_str = input(cyan("  Enter the PID to kill (or press Enter to cancel): ")).strip()
    if not pid_str:
        print(grey("\n  Cancelled."))
        pause()
        return
    if not pid_str.isdigit():
        print(red("\n  ✗  Invalid PID — must be a number."))
        pause()
        return

    monitor.kill_process(int(pid_str))
    pause()


#system service status

def menu_services():
    section_header("System Service Status", "Background services managed by systemd")

    tip(
        "Services are background programs that start automatically.\n"
        "  RUNNING = active and working\n"
        "  STOPPED = installed but not currently running\n"
        "  FAILED  = crashed or hit an error — investigate!"
    )

    from Collectors import collect_services
    from rules.formatter import render_service_table
    pager(render_service_table(collect_services()).split("\n"))
    pause()

#scan history

def menu_history():
    section_header("Scan History", "All past scans saved in logs/monitor.log")

    tip(
        "Every scan is saved automatically. Crawler events are also\n"
        "logged here — look for CRAWLER NEW_ALERT and CRAWLER RESOLVED."
    )

    if not os.path.exists(monitor.log_path):
        print(yellow(f"  No log file found yet at: {monitor.log_path}"))
        print(grey("  Run a scan first (option 1) to create it."))
        pause()
        return

    lines = []
    with open(monitor.log_path) as f:
        for raw in f:
            line = raw.rstrip()
            if   "RISKY"       in line: lines.append(red(line))
            elif "SUSPICIOUS"  in line: lines.append(yellow(line))
            elif "NEW_ALERT"   in line: lines.append(yellow(line))
            elif "RESOLVED"    in line: lines.append(green(line))
            elif "CRAWLER"     in line: lines.append(cyan(line))
            elif "ALERT"       in line: lines.append(yellow(line))
            elif "ERROR"       in line: lines.append(red(line))
            elif "SCAN START"  in line or "SCAN END" in line: lines.append(cyan(line))
            else: lines.append(line)

    pager(lines)
    pause()


#crawler everything

def menu_crawler():
    while True:
        is_running = monitor.crawler and monitor.crawler.is_running()
        status_label = "Stop Crawler" if is_running else "Start Crawler"
        status_desc  = "Click to stop the background watcher" if is_running \
                       else "Click to start background deduplication crawler"

        choice = menu.show(
            "Crawler — Background Monitor",
            "Watches continuously and blocks duplicate alerts",
            [
                (status_label, status_desc),
                ("View crawler dashboard", "See live stats and recent unique alerts"),
                ("View crawler log entries", "Read all CRAWLER events from the log file"),
                ("Reset crawler state", "Clear all fingerprints and start fresh"),
                ("Back to Main Menu", ""),
            ]
        )

        if choice == 0:
            if is_running:
                section_header("Stopping Crawler")
                monitor.stop_crawler()
                print(yellow("  ● Crawler stopped.\n"))
            else:
                section_header("Starting Crawler")
                monitor.start_crawler(interval=15)
                print(green("  ● Crawler started — scanning every 15 seconds in background.\n"))
                print(grey("  It will automatically:\n"))
                print(grey("    • Detect NEW suspicious/risky processes and log them once"))
                print(grey("    • Block DUPLICATE alerts using SHA-256 fingerprinting"))
                print(grey("    • Mark processes as RESOLVED when they stop running\n"))
            pause()

        elif choice == 1:
            section_header("Crawler Dashboard", "Live deduplication statistics")

            if not monitor.crawler:
                print(yellow("  Crawler has not been started yet."))
                print(grey("  Go back and select 'Start Crawler' first."))
                pause()
                continue

            s = monitor.crawler.get_summary()

            info_box([
                bold("  CRAWLER STATUS"),
                "",
                (green("  ● RUNNING") if s["running"] else red("  ○ STOPPED")),
                "",
                cyan("  Total background scans  : ") + bold(str(s["total_scans"])),
                cyan("  NEW alerts logged       : ") + bold(str(s["new_alert_count"])),
                cyan("  Duplicates blocked      : ") + bold(str(s["duplicate_count"])),
                cyan("  Resolved (process gone) : ") + bold(str(s["resolved_count"])),
                cyan("  Currently flagged PIDs  : ") + bold(str(s["active_flagged"])),
            ])

            active = monitor.crawler.get_active_flagged()
            if active:
                print(bold("  Currently active flagged processes:\n"))
                for pid, alerts in active.items():
                    print(f"    {yellow('⚑')} PID {bold(str(pid))}")
                    for a in alerts:
                        print(f"        {grey('→')} {a}")
                print()
            else:
                print(green("  ✓  No currently active flagged processes.\n"))

            recent = s["recent_alerts"]
            if recent:
                print(bold(f"  Last {len(recent)} unique alerts found by crawler:\n"))
                out = []
                for a in reversed(recent):
                    from rules.formatter import LEVEL_COLOR
                    color = LEVEL_COLOR.get(a.level, lambda x: x)
                    out.append(color(f"  [{a.timestamp}] {a.level}  {a.name}  PID={a.pid}"))
                    for msg in a.alerts:
                        out.append(grey(f"    → {msg}"))
                    out.append("")
                pager(out)
            else:
                print(grey("  No alerts recorded yet — crawler may still be in its first scan.\n"))

            pause()

        elif choice == 2:
            section_header("Crawler Log Entries", "All CRAWLER events from monitor.log")
            if not os.path.exists(monitor.log_path):
                print(yellow("  No log file found yet."))
                pause()
                continue
            lines = []
            with open(monitor.log_path) as f:
                for raw in f:
                    line = raw.rstrip()
                    if "CRAWLER" not in line:
                        continue
                    if   "NEW_ALERT"      in line: lines.append(yellow(line))
                    elif "RESOLVED"       in line: lines.append(green(line))
                    elif "CRAWLER_START"  in line: lines.append(cyan(line))
                    elif "CRAWLER_STOP"   in line: lines.append(cyan(line))
                    else: lines.append(line)
            if not lines:
                print(grey("  No crawler log entries yet. Start the crawler and wait for a scan."))
            else:
                pager(lines)
            pause()

        elif choice == 3:
            section_header("Reset Crawler State")
            if not monitor.crawler:
                print(yellow("  Crawler has not been started yet."))
                pause()
                continue
            confirm = input(cyan("  Reset all fingerprints and alert history? [y/N]: ")).strip().lower()
            if confirm == "y":
                monitor.crawler.reset()
                print(green("  ✓  Crawler state cleared. All alerts will be treated as new again."))
            else:
                print(grey("  Cancelled."))
            pause()

        elif choice == 4:
            break


#settings for resources configuration

def menu_settings():
    while True:
        cfg = monitor.config
        choice = menu.show(
            "Settings",
            "Adjust thresholds and view configuration",
            [
                ("CPU alert threshold",
                 f"Currently {cfg['cpu_threshold']}%"),
                ("Memory alert threshold",
                 f"Currently {cfg['mem_threshold']}%"),
                ("Log file location",
                 f"Currently: {monitor.log_path}"),
                ("View suspicious keywords",
                 "Names/commands that trigger security alerts"),
                ("View root process whitelist",
                 "Root processes that are considered safe"),
                ("Back to Main Menu", ""),
            ]
        )

        if choice == 0:
            section_header("CPU Threshold")
            tip("Default 70%. Raise to 85 to reduce false alarms.\nLower to 50 to catch moderate usage.")
            val = input(cyan(f"  New CPU threshold (current: {cfg['cpu_threshold']}%, Enter to keep): ")).strip()
            if val:
                try:
                    monitor.config["cpu_threshold"] = float(val)
                    print(green(f"\n  ✓  Updated to {val}%"))
                except ValueError:
                    print(red("  ✗  Enter a number like 75 or 80."))
            else:
                print(grey("  No change."))
            pause()

        elif choice == 1:
            section_header("Memory Threshold")
            tip("Default 60%. On high-RAM systems try raising to 80%.")
            val = input(cyan(f"  New memory threshold (current: {cfg['mem_threshold']}%, Enter to keep): ")).strip()
            if val:
                try:
                    monitor.config["mem_threshold"] = float(val)
                    print(green(f"\n  ✓  Updated to {val}%"))
                except ValueError:
                    print(red("  ✗  Enter a number like 75 or 80."))
            else:
                print(grey("  No change."))
            pause()

        elif choice == 2:
            section_header("Log File Location")
            val = input(cyan(f"  New log path (current: {monitor.log_path}, Enter to keep): ")).strip()
            if val:
                monitor.log_path = val
                from rules.logger import ScanLogger
                monitor.logger = ScanLogger(val)
                print(green(f"\n  ✓  Updated to: {val}"))
            else:
                print(grey("  No change."))
            pause()

        elif choice == 3:
            section_header("Suspicious Keywords")
            explanations = {
                "nc":"netcat — opens raw network connections",
                "ncat":"netcat variant",
                "netcat":"raw TCP/UDP tool, common in attacks",
                "nmap":"network scanner",
                "miner":"likely a crypto miner",
                "xmrig":"popular crypto miner malware",
                "crypto":"may indicate mining activity",
                "backdoor":"always investigate immediately",
                "reverse_shell":"gives attacker remote access",
                "mkfifo":"creates named pipes, used in attacks",
                "bash_shell":"suspiciously named shell",
                "hydra":"password brute-force tool",
                "sqlmap":"SQL injection attack tool",
            }
            lines = [bold("  Keyword           Why it's suspicious"), ""]
            for kw in cfg["suspicious_names"]:
                lines.append(f"  {yellow('⚑')}  {yellow(kw):<18} {grey(explanations.get(kw, 'flagged'))}")
            pager(lines)
            pause()

        elif choice == 4:
            section_header("Root Process Whitelist")
            wl_explain = {
                "systemd":"main system and service manager",
                "init":"first process at boot",
                "kthreadd":"manages kernel threads",
                "sshd":"listens on port 22 for SSH",
                "cron":"runs scheduled tasks",
                "dbus-daemon":"inter-process communication bus",
                "rsyslogd":"system log daemon",
                "agetty":"manages terminal login prompts",
                "login":"handles user login sessions",
                "NetworkManager":"manages network connections",
                "polkitd":"handles permission escalation",
                "udevd":"manages hardware device events",
            }
            lines = [bold("  Process           Why it needs root"), ""]
            for name in cfg["whitelist_root"]:
                lines.append(f"  {green('✓')}  {green(name):<18} {grey(wl_explain.get(name, 'trusted system process'))}")
            pager(lines)
            pause()

        elif choice == 5:
            break


#basic glossary
def menu_help():
    topics = [
        ("What is a Process?", ""),
        ("Risk Levels  (NORMAL / LOW / SUSPICIOUS / RISKY)", ""),
        ("The 10 Detection Rules", ""),
        ("What is a PID?", ""),
        ("What does 'root' mean?", ""),
        ("CPU% and RAM% explained", ""),
        ("Service vs Process", ""),
        ("What is the Crawler?", ""),
        ("Back to Main Menu", ""),
    ]

    HELP_PAGES = {
        0: [
            bold("  What is a Process?"), "",
            grey("  A process is any running program. Every process has"),
            grey("  a unique PID, a user account that owns it, and resource usage."),
            grey("  PS Monitor scans ALL of them and runs security checks on each one."),
        ],
        1: [
            bold("  Risk Levels"), "",
            green(bold("  NORMAL")) + grey("     Score 0   — safe"),
            cyan(bold("  LOW")) + grey("        Score 1–3 — minor flag"),
            yellow(bold("  SUSPICIOUS")) + grey("  Score 4–6 — investigate"),
            red(bold("  RISKY")) + grey("      Score 7+  — act immediately"),
        ],
        2: [
            bold("  The 10 Detection Rules"), "",
            f"  {cyan('Rule  1')}  {yellow('+2')}  High CPU usage",
            f"  {cyan('Rule  2')}  {yellow('+2')}  High memory usage",
            f"  {cyan('Rule  3')}  {yellow('+3')}  Unexpected root process",
            f"  {cyan('Rule  4')}  {yellow('+4')}  Suspicious name/command keyword",
            f"  {cyan('Rule  5')}  {yellow('+5')}  Executable in /tmp or /dev/shm",
            f"  {cyan('Rule  6')}  {yellow('+4')}  External network connection",
            f"  {cyan('Rule  7')}  {yellow('+3')}  Listening on sensitive port",
            f"  {cyan('Rule  8')}  {yellow('+1')}  Zombie process",
            f"  {cyan('Rule  9')}  {yellow('+2')}  Over 200 open file descriptors",
            f"  {cyan('Rule 10')}  {yellow('+2')}  Nice value below -10",
        ],
        3: [
            bold("  What is a PID?"), "",
            grey("  PID = Process ID — a unique number for every running program."),
            grey("  PID 1 is always systemd. Find a PID with:"),
            cyan("    ps aux | grep processname"),
        ],
        4: [
            bold("  What does 'root' mean?"), "",
            grey("  root = the Linux superuser. Root processes can do anything."),
            grey("  PS Monitor flags unexpected root processes as suspicious."),
            yellow("  Unknown process running as root = investigate immediately."),
        ],
        5: [
            bold("  CPU% and RAM% Explained"), "",
            grey("  CPU%: Normal process = 0.1–2%. Crypto miner = 90–100% constantly."),
            grey("  RAM%: 60%+ from one process = flagged. RSS = actual MB used."),
        ],
        6: [
            bold("  Service vs Process"), "",
            grey("  A process = any running program."),
            grey("  A service = a process managed by systemd (starts at boot,"),
            grey("  auto-restarts on failure). Examples: nginx, sshd, cron."),
        ],
        7: [
            bold("  What is the Crawler?"), "",
            grey("  The Crawler runs in the background and watches your system"),
            grey("  continuously — you don't need to keep pressing Scan manually."), "",
            bold("  Deduplication (like blockchain):"),
            grey("  Every alert gets a unique SHA-256 fingerprint built from:"),
            cyan("    fingerprint = hash(PID + name + start_time + alert_type)"), "",
            grey("  If the fingerprint already exists → DUPLICATE → silently skipped."),
            grey("  If it is new → logged ONCE and fingerprint saved forever."),
            grey("  If the process disappears → logged as RESOLVED."), "",
            bold("  Why this matters:"),
            grey("  Without the crawler, the same risky process gets logged"),
            grey("  every single scan (every 10 seconds = 360 duplicate log"),
            grey("  entries per hour). The crawler reduces that to exactly 1."),
        ],
    }

    while True:
        choice = menu.show("Help & Glossary", "Pick a topic", topics)
        if choice == 8:
            break
        elif choice in HELP_PAGES:
            section_header(topics[choice][0])
            pager(HELP_PAGES[choice])
            pause()


#main menu layout

MAIN_OPTIONS = [
    ("Scan all processes",      "Check every running process and flag anything suspicious"),
    ("Inspect a process",       "Deep-dive into one specific process using its PID"),
    ("Kill a process",          "Force-stop a process — use with caution!"),
    ("Service status",          "Check which background systemd services are running"),
    ("View scan history",       "Read past scan logs saved to disk"),
    ("Crawler",                 "Start/stop background watcher + deduplication dashboard"),
    ("Settings",                "Adjust alert thresholds and view configuration"),
    ("Help & Glossary",         "Learn what PID, CPU%, RISKY, root, and the Crawler mean"),
    ("Exit",                    ""),
]

HANDLERS = [
    menu_scan, menu_inspect, menu_kill,
    menu_services, menu_history, menu_crawler,
    menu_settings, menu_help,
]


def main():
    if sys.platform == "win32":
        print("This tool only runs on Linux.")
        sys.exit(1)

    while True:
        print(crawler_status_line())

        choice = menu.show(
            "Main Menu",
            "CLI Based Process and Service Monitoring Tool",
            MAIN_OPTIONS
        )

        if choice == len(MAIN_OPTIONS) - 1:
            if monitor.crawler and monitor.crawler.is_running():
                monitor.stop_crawler()
            os.system("clear")
            print()
            print(cyan("  Thanks for using the CLI Monitor. Stay secure!\n"))
            sys.exit(0)
        elif choice < len(HANDLERS):
            HANDLERS[choice]()


if __name__ == "__main__":
    main()
