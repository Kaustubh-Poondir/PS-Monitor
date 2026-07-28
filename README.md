# PS-Monitor
Python CLI-based Linux process and service monitoring tool that analyzes running processes, services, and network activity using rule-based security checks. Detects suspicious behavior, classifies risk levels, logs alerts with SHA-256 deduplication, and provides real-time monitoring.

# PS Guard — Linux Process & Service Monitor

A CLI-based security and performance monitoring tool for Linux.

## Quick Start

```bash
pip install -r requirements.txt
python main.py                  # Live dashboard (Ctrl+C to exit)
python main.py --scan           # One-shot scan
python main.py --pid 1234       # Inspect a process
python main.py --kill 1234      # Kill a process
python main.py --services       # systemd service overview
python main.py --history        # View scan log
python main.py --threshold cpu=80 mem=75  # Custom thresholds
python main.py --watch 5        # Refresh every 5 seconds
python main.py --no-color       # Disable ANSI colors
```

## Project Structure

```
process_monitor/
├── main.py                     # CLI entry point
├── requirements.txt
├── logs/
│   └── monitor.log             # Rotating scan log (auto-created)
├── Collectors/
│   ├── process_collector.py    # Gathers per-process data via psutil
│   └── service_collector.py    # Reads systemd service status
├── engine/
│   ├── rule_engine.py          # All detection rules + scoring
│   └── monitor.py              # Orchestrator (scan → display → log)
├── rules/
│   ├── formatter.py            # ANSI color + table rendering
│   ├── logger.py               # Rotating log writer
│   └── command_runner.py       # kill / renice helpers
└── tests/
    ├── test_process.py         # Rule engine unit tests
    └── test_services.py        # Service collector unit tests
```

## Risk Levels

| Level      | Score | Color  |
|------------|-------|--------|
| NORMAL     | 0     | —      |
| LOW        | 1–3   | Cyan   |
| SUSPICIOUS | 4–6   | Yellow |
| RISKY      | 7+    | Red    |

## Running Tests

```bash
python -m pytest tests/ -v
```
