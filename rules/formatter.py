"""
rules/formatter.py
ANSI color helpers and CLI table/dashboard rendering functions.
"""

import os
import shutil
from datetime import datetime


# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"
    BG_RED  = "\033[41m"
    BG_YELLOW = "\033[43m"


_USE_COLOR = True


def set_color(enabled: bool):
    global _USE_COLOR
    _USE_COLOR = enabled


def _c(code: str, text: str) -> str:
    if _USE_COLOR:
        return f"{code}{text}{Colors.RESET}"
    return text


def bold(t):   return _c(Colors.BOLD, t)
def red(t):    return _c(Colors.RED, t)
def yellow(t): return _c(Colors.YELLOW, t)
def green(t):  return _c(Colors.GREEN, t)
def cyan(t):   return _c(Colors.CYAN, t)
def grey(t):   return _c(Colors.GREY, t)
def white(t):  return _c(Colors.WHITE, t)
def magenta(t):return _c(Colors.MAGENTA, t)


# ---------------------------------------------------------------------------
# Level coloring
# ---------------------------------------------------------------------------

LEVEL_COLOR = {
    "NORMAL":     green,
    "LOW":        cyan,
    "SUSPICIOUS": yellow,
    "RISKY":      red,
}


def color_level(level: str) -> str:
    fn = LEVEL_COLOR.get(level, lambda x: x)
    return fn(bold(level))


# ---------------------------------------------------------------------------
# Terminal width
# ---------------------------------------------------------------------------

def term_width() -> int:
    return shutil.get_terminal_size((100, 40)).columns


# ---------------------------------------------------------------------------
# Dashboard header
# ---------------------------------------------------------------------------

def render_header(system_stats: dict, scan_count: int) -> str:
    w = term_width()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cpu  = system_stats.get("cpu_percent", 0)
    mem  = system_stats.get("mem_percent", 0)
    disk = system_stats.get("disk_percent", 0)
    procs= system_stats.get("process_count", 0)

    cpu_bar  = _bar(cpu,  20)
    mem_bar  = _bar(mem,  20)
    disk_bar = _bar(disk, 20)

    lines = [
        bold(cyan("=" * w)),
        bold(cyan(f"  CLI Based Process and Service Monitoring Tool".center(w))),
        bold(cyan("=" * w)),
        f"  {grey('Time:')} {ts}   {grey('Scan #:')} {scan_count}   "
        f"{grey('Processes:')} {procs}   {grey('Boot:')} {system_stats.get('boot_time','')}",
        "",
        f"  CPU  [{cpu_bar}] {_pct_color(cpu,70,90):<6}  "
        f"MEM  [{mem_bar}] {_pct_color(mem,70,90):<6}  "
        f"DISK [{disk_bar}] {_pct_color(disk,80,95):<6}",
        bold(cyan("-" * w)),
    ]
    return "\n".join(lines)


def _bar(pct: float, width: int) -> str:
    filled = int(pct / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    if pct >= 90:
        return red(bar)
    elif pct >= 70:
        return yellow(bar)
    return green(bar)


def _pct_color(pct: float, warn: float, crit: float) -> str:
    s = f"{pct:.1f}%"
    if pct >= crit:
        return red(s)
    elif pct >= warn:
        return yellow(s)
    return green(s)


# ---------------------------------------------------------------------------
# Process table — beginner-friendly card layout
# ---------------------------------------------------------------------------

_LEVEL_ICON = {
    "NORMAL":     "✓",
    "LOW":        "●",
    "SUSPICIOUS": "⚠",
    "RISKY":      "✖",
}

_LEVEL_EXPLAIN = {
    "NORMAL":     "No issues found — this process looks safe.",
    "LOW":        "Minor flag raised — low priority but worth noting.",
    "SUSPICIOUS": "This process triggered a security rule — investigate it.",
    "RISKY":      "Multiple rules fired — take action on this process!",
}

_ALERT_EXPLAIN = {
    "high cpu":                     "Using a lot of processor power — could be a miner or runaway process.",
    "high memory":                  "Using a lot of RAM — could be a memory leak or resource hog.",
    "unexpected root":              "Running as the all-powerful root user without being a known system process.",
    "suspicious keyword":           "The process name or command contains a known hacker tool name.",
    "suspicious process name":      "The process name or command contains a known hacker tool name.",
    "temp director":                "Running from /tmp or /dev/shm — malware often hides here.",
    "external connection":          "Connected to an IP address outside this machine.",
    "sensitive port":               "Listening on a port reserved for databases, SSH, or other services.",
    "zombie":                       "The process finished but was never cleaned up by its parent.",
    "open file":                    "Unusually large number of files open — possible file scan or leak.",
    "elevated priority":            "Running at high scheduling priority, claiming extra CPU time.",
}


def render_process_table(evaluations: list, show_normal: bool = False) -> str:
    rows = [ev for ev in evaluations if show_normal or ev.level != "NORMAL"]
    rows.sort(key=lambda e: e.score, reverse=True)

    if not rows:
        return (
            green("  \u2713  All clear! No suspicious or risky processes detected.\n") +
            grey("     Every process passed the security checks.\n")
        )

    lines = []
    for ev in rows:
        icon    = _LEVEL_ICON.get(ev.level, "?")
        color   = LEVEL_COLOR.get(ev.level, lambda x: x)
        explain = _LEVEL_EXPLAIN.get(ev.level, "")

        lines.append(color("  " + chr(8212)*60))
        lines.append(
            "  " + color(bold(icon + "  " + ev.level)) + "  " +
            bold(ev.name) + "  " +
            grey("(PID " + str(ev.pid) + ")  Risk score: " + str(ev.score))
        )
        lines.append("  " + grey(explain))
        lines.append("")
        lines.append("    " + grey("User:").ljust(18)    + str(ev.username))
        lines.append(
            "    " + grey("CPU:").ljust(18) + str(round(ev.cpu_percent, 1)) + "%   " +
            grey("RAM:").ljust(18) + str(round(ev.mem_percent, 1)) + "% (" + str(ev.mem_rss_mb) + " MB)"
        )
        lines.append("    " + grey("Path:").ljust(18)    + str(ev.exe))
        lines.append("    " + grey("Started:").ljust(18) + str(ev.started_at))

        if ev.alerts:
            lines.append("")
            lines.append("    " + bold("Why it was flagged:"))
            for alert in ev.alerts:
                found = ""
                al = alert.lower()
                for key, val in _ALERT_EXPLAIN.items():
                    if key in al:
                        found = val
                        break
                lines.append("      " + color("\u2691") + " " + color(alert))
                if found:
                    lines.append("        " + grey("\u2192 " + found))

    lines.append(grey("  " + chr(8212)*60))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Summary bar
# ---------------------------------------------------------------------------

def render_summary(total: int, low: int, suspicious: int, risky: int,
                   log_path: str) -> str:
    w = term_width()
    return (
        bold(cyan("-" * w)) + "\n"
        f"  Scanned: {bold(str(total))}   "
        f"Low: {cyan(bold(str(low)))}   "
        f"Suspicious: {yellow(bold(str(suspicious)))}   "
        f"Risky: {red(bold(str(risky)))}\n"
        f"  Log: {grey(log_path)}\n"
        + bold(cyan("=" * w))
    )


# ---------------------------------------------------------------------------
# Process detail (--pid)
# ---------------------------------------------------------------------------

def render_process_detail(evaluation, info: dict) -> str:
    w = term_width()
    lines = [
        bold(cyan("=" * w)),
        bold(f"  Process Detail — PID {evaluation.pid}"),
        bold(cyan("-" * w)),
        f"  {'Name':<16} {evaluation.name}",
        f"  {'User':<16} {evaluation.username}",
        f"  {'Executable':<16} {evaluation.exe}",
        f"  {'Command':<16} {evaluation.cmdline[:80]}",
        f"  {'Started':<16} {evaluation.started_at}",
        f"  {'CPU':<16} {evaluation.cpu_percent:.2f}%",
        f"  {'Memory':<16} {evaluation.mem_percent:.2f}% ({evaluation.mem_rss_mb} MB RSS)",
        f"  {'Status':<16} {info.get('status','?')}",
        f"  {'Threads':<16} {info.get('num_threads','?')}",
        f"  {'PPID':<16} {info.get('ppid','?')}",
        f"  {'Nice':<16} {info.get('nice','?')}",
        bold(cyan("-" * w)),
        f"  Risk Score : {bold(str(evaluation.score))}   Level: {color_level(evaluation.level)}",
    ]
    if evaluation.alerts:
        lines.append(f"  Alerts:")
        for a in evaluation.alerts:
            lines.append(f"    {yellow('⚠')}  {a}")
    else:
        lines.append(f"  {green('✓')}  No issues detected.")

    conns = evaluation.connections or []
    if conns:
        lines.append(bold(cyan("-" * w)))
        lines.append(f"  Network Connections ({len(conns)}):")
        for c in conns[:10]:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?"
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            lines.append(f"    {laddr:<24} -> {raddr:<24}  {c.status}")

    lines.append(bold(cyan("=" * w)))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Service table
# ---------------------------------------------------------------------------

def render_service_table(services: list) -> str:
    if not services:
        return yellow("  No services found (systemd may not be running).\n")

    STATUS_COLOR = {
        "RUNNING": green,
        "FAILED":  red,
        "STOPPED": yellow,
    }

    lines = [
        "  " + bold("NAME".ljust(40)) + "  " + bold("ACTIVE".ljust(12)) +
        "  " + bold("SUB".ljust(12)) + "  " + bold("LOAD"),
        grey("  " + "-" * 80),
    ]
    for svc in services:
        color_fn = STATUS_COLOR.get(svc.status_label, lambda x: x)
        lines.append(
            f"  {svc.name[:38].ljust(40)}"
            f"  {color_fn(svc.active_state[:10].ljust(12))}"
            f"  {svc.sub_state[:10].ljust(12)}"
            f"  {svc.load_state}"
        )
    return "\n".join(lines) + "\n"
