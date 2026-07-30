# PS-Monitor : CLI Based Process and Service Monitoring Tool for Linux systems
Python CLI-based Linux process and service monitoring tool that analyzes running processes, services, and network activity using rule-based security checks. Detects suspicious behavior, classifies risk levels, logs alerts with SHA-256 deduplication, and provides real-time monitoring.

A CLI-based security and performance monitoring tool for Linux.

## Quick Start

Open the folder in terminal in your Linux machine.
```bash
pip install -r requirements.txt


```
To run the program:
```bash
python3 main.py                  # Live dashboard (Ctrl+C to exit)
```

## Project Structure

```
PS-Monitor/
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
