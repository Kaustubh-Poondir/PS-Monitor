"""
engine/rule_engine.py
Evaluates each process against a set of security/performance rules.
"""

from dataclasses import dataclass, field
from typing import List, Callable, Tuple
import re

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "cpu_threshold":        20.0,   # Catch stress-ng easily
    "mem_threshold":        60.0,
    "suspicious_names": [
        "nc", "ncat", "netcat", "nmap", "miner", "xmrig",
        "crypto", "backdoor", "reverse_shell", "mkfifo",
        "bash_shell", "hydra", "sqlmap", "stress-ng",
    ],
    "temp_paths": [
        "/tmp", "/dev/shm", "/var/tmp", "/run/shm",
    ],
    "whitelist_root": [
        "systemd", "init", "kthreadd", "sshd", "cron",
        "dbus-daemon", "rsyslogd", "agetty", "login",
        "NetworkManager", "polkitd", "udevd",
        "kworker", "ksoftirqd", "migration", "rcu_sched",
        "rcu_bh", "rcu_preempt", "watchdog", "kdevtmpfs",
        "netns", "kauditd", "khungtaskd", "oom_reaper",
        "writeback", "kcompactd", "ksmd", "khugepaged",
        "kswapd", "jbd2", "ext4-rsv-conver", "kthrotld",
        "scsi_eh", "scsi_tmf", "ipv6_addrconf", "kstrp",
        "zswap-shrink", "irq", "idle_inject", "cpuhp",
        "charger_manager", "deferwq", "kblockd", "md",
        "edac-poller", "devfreq_wq",
    ],
    "trusted_ips": [
        "127.0.0.1", "::1", "0.0.0.0",
    ],
    "sensitive_ports": [21, 22, 23, 3306, 5432, 6379, 27017, 9200],
}

@dataclass
class RuleResult:
    triggered: bool
    score: int
    message: str
    rule_name: str

@dataclass
class ProcessEvaluation:
    pid: int
    name: str
    username: str
    exe: str
    cmdline: str
    cpu_percent: float
    mem_percent: float
    mem_rss_mb: float
    started_at: str
    connections: list
    score: int
    level: str
    alerts: List[str] = field(default_factory=list)
    rule_results: List[RuleResult] = field(default_factory=list)

def cpu_rule(info: dict, cfg: dict) -> RuleResult:
    cpu = info.get("cpu_percent", 0.0) or 0.0
    if cpu > cfg["cpu_threshold"]:
        return RuleResult(True, 5, f"High CPU: {cpu:.1f}%", "cpu_rule")
    return RuleResult(False, 0, "", "cpu_rule")

def memory_rule(info: dict, cfg: dict) -> RuleResult:
    mem = info.get("mem_percent", 0.0) or 0.0
    if mem > cfg["mem_threshold"]:
        return RuleResult(True, 2, f"High Memory: {mem:.1f}%", "memory_rule")
    return RuleResult(False, 0, "", "memory_rule")

def root_rule(info: dict, cfg: dict) -> RuleResult:
    user = info.get("username") or ""
    name = (info.get("name") or "").lower()
    exe  = info.get("exe") or ""
    if user != "root" or exe in ("N/A", "", None):
        return RuleResult(False, 0, "", "root_rule")
    whitelist = [w.lower() for w in cfg["whitelist_root"]]
    if any(name.startswith(w) for w in whitelist):
        return RuleResult(False, 0, "", "root_rule")
    return RuleResult(True, 3, f"Unexpected root process: {name}", "root_rule")

def suspicious_name_rule(info: dict, cfg: dict) -> RuleResult:
    name = (info.get("name") or "").lower()
    cmdline = (info.get("cmdline") or "").lower()
    for keyword in cfg["suspicious_names"]:
        pattern = r'\b' + re.escape(keyword) + r'\b'
        if re.search(pattern, name) or re.search(pattern, cmdline):
            return RuleResult(True, 4, f"Suspicious keyword '{keyword}' in process", "suspicious_name_rule")
    return RuleResult(False, 0, "", "suspicious_name_rule")

def temp_exec_rule(info: dict, cfg: dict) -> RuleResult:
    exe = info.get("exe") or ""
    for path in cfg["temp_paths"]:
        if exe.startswith(path):
            return RuleResult(True, 5, f"Executable in temp directory: {exe}", "temp_exec_rule")
    return RuleResult(False, 0, "", "temp_exec_rule")

def network_rule(info: dict, cfg: dict) -> RuleResult:
    connections = info.get("connections") or []
    trusted = cfg["trusted_ips"]
    for conn in connections:
        raddr = getattr(conn, "raddr", None)
        if raddr and raddr.ip and raddr.ip not in trusted:
            return RuleResult(True, 4, f"External connection to {raddr.ip}:{raddr.port}", "network_rule")
    return RuleResult(False, 0, "", "network_rule")

def listening_port_rule(info: dict, cfg: dict) -> RuleResult:
    connections = info.get("connections") or []
    sensitive = cfg["sensitive_ports"]
    for conn in connections:
        status = getattr(conn, "status", "")
        laddr = getattr(conn, "laddr", None)
        if status == "LISTEN" and laddr and laddr.port in sensitive:
            return RuleResult(True, 3, f"Listening on sensitive port {laddr.port}", "listening_port_rule")
    return RuleResult(False, 0, "", "listening_port_rule")

def zombie_rule(info: dict, cfg: dict) -> RuleResult:
    status = info.get("status") or ""
    if status == "zombie":
        return RuleResult(True, 1, "Zombie process detected", "zombie_rule")
    return RuleResult(False, 0, "", "zombie_rule")

def high_fd_rule(info: dict, cfg: dict) -> RuleResult:
    count = info.get("open_files_count") or 0
    if count > 200:
        return RuleResult(True, 2, f"High open file count: {count}", "high_fd_rule")
    return RuleResult(False, 0, "", "high_fd_rule")

def nice_priority_rule(info: dict, cfg: dict) -> RuleResult:
    nice = info.get("nice")
    exe  = info.get("exe") or ""
    if exe in ("N/A", "", None):
        return RuleResult(False, 0, "", "nice_priority_rule")
    if nice is not None and nice < -10:
        return RuleResult(True, 2, f"Elevated priority (nice={nice})", "nice_priority_rule")
    return RuleResult(False, 0, "", "nice_priority_rule")

ALL_RULES: List[Callable] = [
    cpu_rule, memory_rule, root_rule, suspicious_name_rule,
    temp_exec_rule, network_rule, listening_port_rule,
    zombie_rule, high_fd_rule, nice_priority_rule,
]

def classify(score: int) -> str:
    if score == 0: return "NORMAL"
    elif score <= 3: return "LOW"
    elif score <= 6: return "SUSPICIOUS"
    else: return "RISKY"

def evaluate_process(info: dict, config: dict = None) -> ProcessEvaluation:
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    total_score = 0
    alerts = []
    rule_results = []
    for rule_fn in ALL_RULES:
        result = rule_fn(info, cfg)
        rule_results.append(result)
        if result.triggered:
            total_score += result.score
            alerts.append(result.message)
    level = classify(total_score)
    return ProcessEvaluation(
        pid=info.get("pid", 0), name=info.get("name") or "?",
        username=info.get("username") or "?", exe=info.get("exe") or "N/A",
        cmdline=info.get("cmdline") or "N/A", cpu_percent=info.get("cpu_percent") or 0.0,
        mem_percent=info.get("mem_percent") or 0.0, mem_rss_mb=info.get("mem_rss_mb") or 0.0,
        started_at=info.get("started_at") or "N/A", connections=info.get("connections") or [],
        score=total_score, level=level, alerts=alerts, rule_results=rule_results,
    )

def scan_all(process_list: list, config: dict = None) -> List[ProcessEvaluation]:
    results = []
    for info in process_list:
        try:
            ev = evaluate_process(info, config)
            results.append(ev)
        except Exception: continue
    return results
