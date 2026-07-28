"""
menu.py
Simple, clean arrow-key menu.
Redraws the full screen on every keypress — no partial redraw corruption.
No descriptions shown in the menu. No colour bleed.
"""

import sys
import os
import tty
import termios
import shutil   #the moost important library, for importing process and service data.


def _read_key():
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.buffer.read(1)
            if ch in (b'\r', b'\n'):
                return 'ENTER'
            if ch == b'\x03':
                raise KeyboardInterrupt
            if ch == b'\x1b':
                ch2 = sys.stdin.buffer.read(1)
                if ch2 == b'[':
                    ch3 = sys.stdin.buffer.read(1)
                    if ch3 == b'A': return 'UP'
                    if ch3 == b'B': return 'DOWN'
                    while ch3 and not (b'A' <= ch3 <= b'Z' or b'a' <= ch3 <= b'z'):
                        ch3 = sys.stdin.buffer.read(1)
                continue   # ignore all other escape sequences
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def show(title, subtitle, options):
    """
    Show a clean arrow-key menu.
    options: list of (label, _description) tuples — description is ignored in display.
    Returns the index of the chosen option.
    """
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    CYAN   = "\033[96m"
    RED    = "\033[91m"
    GREY   = "\033[90m"
    INVERT = "\033[7m"

    selected = 0
    total    = len(options)

    def draw():
        os.system("clear")
        print()
        print(f"{CYAN}{BOLD} PS Monitor — {title}{RESET}")
        print(f"{GREY} {subtitle}{RESET}")
        print(f"{GREY} ↑ ↓  to move   Enter  to select{RESET}")
        print(f"{CYAN} {'─' * 40}{RESET}")
        print()
        for i, (label, _) in enumerate(options):
            if i == selected:
                print(f"{INVERT}{BOLD}  ▶  {label}  {RESET}")
            else:
                is_exit = label.lower() in ("exit", "back to main menu")
                color = RED if is_exit else CYAN
                print(f"{color}     {label}{RESET}")
        print()

    sys.stdout.write("\033[?25l")   # hiding cursor
    sys.stdout.flush()

    try:
        draw()
        while True:
            key = _read_key()
            if key == 'UP':
                selected = (selected - 1) % total
                draw()
            elif key == 'DOWN':
                selected = (selected + 1) % total
                draw()
            elif key == 'ENTER':
                return selected
    finally:
        sys.stdout.write("\033[?25h")   # always restore cursor
        sys.stdout.flush()
