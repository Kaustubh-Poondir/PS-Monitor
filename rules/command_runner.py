"""
rules/command_runner.py
Helpers for performing actions on processes (kill, renice, etc.)
"""

import os
import signal
import psutil


def kill_process(pid: int, force: bool = False) -> tuple:
    """
    Send SIGTERM (or SIGKILL if force=True) to a process.
    Returns (success: bool, message: str).
    """
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        sig = signal.SIGKILL if force else signal.SIGTERM
        proc.send_signal(sig)
        action = "SIGKILL" if force else "SIGTERM"
        return True, f"Sent {action} to PID {pid} ({name})"
    except psutil.NoSuchProcess:
        return False, f"PID {pid} does not exist"
    except psutil.AccessDenied:
        return False, f"Permission denied — try running as root"
    except Exception as e:
        return False, str(e)


def renice_process(pid: int, nice_value: int) -> tuple:
    """
    Change the nice (priority) value of a process.
    Returns (success: bool, message: str).
    """
    try:
        proc = psutil.Process(pid)
        proc.nice(nice_value)
        return True, f"Set nice={nice_value} for PID {pid} ({proc.name()})"
    except psutil.NoSuchProcess:
        return False, f"PID {pid} does not exist"
    except psutil.AccessDenied:
        return False, f"Permission denied — try running as root"
    except Exception as e:
        return False, str(e)


def process_exists(pid: int) -> bool:
    return psutil.pid_exists(pid)
