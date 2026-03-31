"""Scheduled scanning with cron-based daemon for active projects."""

from __future__ import annotations

import json
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "security-scanner"
SCHEDULES_FILE = CONFIG_DIR / "schedules.json"
RESULTS_DIR = CONFIG_DIR / "results"


def cron_matches(cron_expr: str, dt: datetime) -> bool:
    """Check if a datetime matches a 5-field cron expression.

    Supports: *, */N, N, N-M, N,M,O
    Fields: minute hour day-of-month month day-of-week
    """
    fields = cron_expr.strip().split()
    if len(fields) != 5:
        return False

    values = [dt.minute, dt.hour, dt.day, dt.month, dt.weekday()]
    # Cron weekday: 0=Sunday, Python weekday: 0=Monday
    values[4] = (values[4] + 1) % 7  # Convert to cron convention

    for field, value in zip(fields, values):
        if not _field_matches(field, value):
            return False
    return True


def _field_matches(field: str, value: int) -> bool:
    if field == "*":
        return True
    for part in field.split(","):
        if "/" in part:
            base, step = part.split("/", 1)
            try:
                step = int(step)
                if base == "*":
                    if value % step == 0:
                        return True
                else:
                    base_val = int(base)
                    if value >= base_val and (value - base_val) % step == 0:
                        return True
            except ValueError:
                continue
        elif "-" in part:
            try:
                low, high = part.split("-", 1)
                if int(low) <= value <= int(high):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(part) == value:
                    return True
            except ValueError:
                continue
    return False


class ScheduleManager:
    def __init__(self, config_dir: Path = None, results_dir: Path = None):
        self.config_dir = config_dir or CONFIG_DIR
        self.results_dir = results_dir or RESULTS_DIR
        self.schedules_file = self.config_dir / "schedules.json"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def load_schedules(self) -> list[dict]:
        if not self.schedules_file.exists():
            return []
        try:
            return json.loads(self.schedules_file.read_text())
        except (json.JSONDecodeError, OSError):
            return []

    def save_schedules(self, schedules: list[dict]) -> None:
        self.schedules_file.write_text(json.dumps(schedules, indent=2))

    def add(self, path: str, cron: str, name: str) -> None:
        path = str(Path(path).resolve())
        if not Path(path).is_dir():
            raise ValueError(f"Not a directory: {path}")

        # Validate cron
        fields = cron.strip().split()
        if len(fields) != 5:
            raise ValueError(f"Invalid cron expression: '{cron}' (expected 5 fields)")

        schedules = self.load_schedules()
        if any(s["name"] == name for s in schedules):
            raise ValueError(f"Schedule '{name}' already exists")

        schedules.append({
            "name": name,
            "path": path,
            "cron": cron,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        self.save_schedules(schedules)

    def remove(self, name: str) -> bool:
        schedules = self.load_schedules()
        new_schedules = [s for s in schedules if s["name"] != name]
        if len(new_schedules) == len(schedules):
            return False
        self.save_schedules(new_schedules)
        return True

    def list_schedules(self) -> list[dict]:
        return self.load_schedules()


class ScheduleDaemon:
    def __init__(self, manager: ScheduleManager):
        self.manager = manager
        self.running = True
        self._last_fired: dict[str, str] = {}

    def run(self):
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "running", False))
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "running", False))

        while self.running:
            now = datetime.now()
            now_key = now.strftime("%Y%m%d%H%M")
            schedules = self.manager.load_schedules()

            for sched in schedules:
                fire_key = f"{sched['name']}_{now_key}"
                if fire_key in self._last_fired:
                    continue
                if cron_matches(sched["cron"], now):
                    self._execute_scan(sched, now)
                    self._last_fired[fire_key] = now_key

            time.sleep(60)

    def _execute_scan(self, sched: dict, now: datetime):
        from repo_security_scanner.scanner import SecurityScanner
        from repo_security_scanner.vulndb.osv import OSVDatabase
        from repo_security_scanner.reports.json_report import generate_json_report

        print(f"[{now.isoformat()}] Scanning {sched['name']} ({sched['path']})...")

        scanner = SecurityScanner(vuln_sources=[OSVDatabase()])
        try:
            report = scanner.scan(sched["path"])
        except Exception as e:
            self._write_alert(sched["name"], f"Scan failed: {e}")
            return

        # Save result
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        result_file = RESULTS_DIR / f"{sched['name']}_{timestamp}.json"
        result_file.write_text(generate_json_report(report))

        status = f"{report.total_vulns} vulns ({report.critical_count} critical, {report.high_count} high)"
        print(f"[{now.isoformat()}] {sched['name']}: {status} -> {result_file.name}")

        if report.has_critical_or_high:
            self._write_alert(
                sched["name"],
                f"ALERT: {report.critical_count} critical, {report.high_count} high vulnerabilities in {sched['path']}",
            )

    def _write_alert(self, name: str, message: str):
        alert_file = CONFIG_DIR / "alerts.log"
        try:
            with open(alert_file, "a") as f:
                f.write(f"[{datetime.now(timezone.utc).isoformat()}] [{name}] {message}\n")
        except OSError:
            pass
