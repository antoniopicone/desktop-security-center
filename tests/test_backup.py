"""TDD tests for the Backup module (spec §3.6) — Snapper-only placeholder.

The spec is explicit: real offsite backup doesn't exist yet, so this
module is honest about being a local-snapshot placeholder, not a
substitute for real backup coverage.
"""

from command_runner import CommandResult
from modules.backup import build_status_report, parse_snapper_configs, parse_snapper_last_snapshot, refresh
from models import Severity

SNAPPER_LIST_CONFIGS = "root\nhome\n"

SNAPPER_LIST_SNAPSHOTS = (
    "   # | Type   | Pre # | Date                     | User | Description\n"
    "-----+--------+-------+--------------------------+------+-------------\n"
    "0    | single |       |                          | root | current\n"
    "42   | single |       | Mon 15 Sep 2026 10:00:00 | root | timeline\n"
)


class TestParseSnapperConfigs:
    def test_parses_configured_volumes(self):
        assert parse_snapper_configs(SNAPPER_LIST_CONFIGS) == ["root", "home"]

    def test_empty_output_means_no_configs(self):
        assert parse_snapper_configs("") == []

    def test_parses_real_table_output_with_header_and_separator(self):
        text = "Config | Subvolume\n-------+----------\nroot   | /\nhome   | /home\n"
        assert parse_snapper_configs(text) == ["root", "home"]


class TestParseSnapperLastSnapshot:
    def test_returns_the_most_recent_dated_snapshot(self):
        assert parse_snapper_last_snapshot(SNAPPER_LIST_SNAPSHOTS) == "Mon 15 Sep 2026 10:00:00"

    def test_no_dated_snapshots_returns_none(self):
        text = "0 | single | | | root | current\n"
        assert parse_snapper_last_snapshot(text) is None

    def test_empty_input_returns_none(self):
        assert parse_snapper_last_snapshot("") is None


class TestBuildStatusReport:
    def test_no_configs_is_a_warning_not_an_error(self):
        # honest placeholder: no real backup exists yet regardless, spec §3.6
        report = build_status_report(configs={})
        assert report.severity == Severity.WARNING

    def test_configured_snapshots_are_ok(self):
        report = build_status_report(configs={"root": "Mon 15 Sep 2026 10:00:00", "home": "Mon 15 Sep 2026 10:05:00"})
        assert report.severity == Severity.OK

    def test_summary_is_explicit_about_not_being_offsite_backup(self):
        report = build_status_report(configs={"root": "Mon 15 Sep 2026 10:00:00"})
        assert "snapshot" in report.summary.lower()
        assert "offsite" not in report.summary.lower() or "not" in report.summary.lower()


class TestRefresh:
    def test_fetches_configs_then_snapshots_per_config(self):
        call_count = [0]

        def fake_run_many(argvs, callback):
            call_count[0] += 1
            if call_count[0] == 1:
                callback([CommandResult(0, SNAPPER_LIST_CONFIGS, "")])
            else:
                assert len(argvs) == 2  # one snapshot listing per configured volume
                callback(
                    [
                        CommandResult(0, SNAPPER_LIST_SNAPSHOTS, ""),
                        CommandResult(0, SNAPPER_LIST_SNAPSHOTS, ""),
                    ]
                )

        reports = []
        refresh(reports.append, run_many=fake_run_many)

        assert call_count[0] == 2
        assert reports[0].severity == Severity.OK
