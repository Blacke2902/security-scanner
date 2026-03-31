"""Tests for cron expression parsing and schedule management."""

import tempfile
from datetime import datetime
from pathlib import Path

from repo_security_scanner.scheduler import cron_matches, ScheduleManager


class TestCronMatches:
    def test_every_minute(self):
        assert cron_matches("* * * * *", datetime(2026, 3, 31, 10, 30)) is True

    def test_specific_minute(self):
        assert cron_matches("30 * * * *", datetime(2026, 3, 31, 10, 30)) is True
        assert cron_matches("15 * * * *", datetime(2026, 3, 31, 10, 30)) is False

    def test_specific_hour(self):
        assert cron_matches("0 8 * * *", datetime(2026, 3, 31, 8, 0)) is True
        assert cron_matches("0 9 * * *", datetime(2026, 3, 31, 8, 0)) is False

    def test_step(self):
        assert cron_matches("*/5 * * * *", datetime(2026, 3, 31, 10, 0)) is True
        assert cron_matches("*/5 * * * *", datetime(2026, 3, 31, 10, 3)) is False

    def test_range(self):
        assert cron_matches("0 10 * * 1-5", datetime(2026, 3, 31, 10, 0)) is True

    def test_list(self):
        assert cron_matches("0 8,12,18 * * *", datetime(2026, 3, 31, 8, 0)) is True
        assert cron_matches("0 9,12,18 * * *", datetime(2026, 3, 31, 8, 0)) is False

    def test_specific_day_of_month(self):
        assert cron_matches("0 0 15 * *", datetime(2026, 3, 15, 0, 0)) is True
        assert cron_matches("0 0 1 * *", datetime(2026, 3, 15, 0, 0)) is False

    def test_specific_month(self):
        assert cron_matches("0 0 1 3 *", datetime(2026, 3, 1, 0, 0)) is True
        assert cron_matches("0 0 1 6 *", datetime(2026, 3, 1, 0, 0)) is False

    def test_invalid_cron(self):
        assert cron_matches("bad", datetime(2026, 3, 31, 10, 0)) is False
        assert cron_matches("* * *", datetime(2026, 3, 31, 10, 0)) is False


class TestScheduleManager:
    def test_add_and_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScheduleManager(
                config_dir=Path(tmpdir) / "config",
                results_dir=Path(tmpdir) / "results",
            )
            manager.add(tmpdir, "0 8 * * *", "test-project")
            schedules = manager.list_schedules()
            assert len(schedules) == 1
            assert schedules[0]["name"] == "test-project"
            assert schedules[0]["cron"] == "0 8 * * *"

    def test_remove(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScheduleManager(
                config_dir=Path(tmpdir) / "config",
                results_dir=Path(tmpdir) / "results",
            )
            manager.add(tmpdir, "0 8 * * *", "test-project")
            assert manager.remove("test-project") is True
            assert manager.remove("nonexistent") is False
            assert len(manager.list_schedules()) == 0

    def test_duplicate_name_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScheduleManager(
                config_dir=Path(tmpdir) / "config",
                results_dir=Path(tmpdir) / "results",
            )
            manager.add(tmpdir, "0 8 * * *", "my-project")
            try:
                manager.add(tmpdir, "0 9 * * *", "my-project")
                assert False, "Should have raised ValueError"
            except ValueError:
                pass
