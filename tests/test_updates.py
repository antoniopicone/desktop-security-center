"""TDD tests for the Updates & vulnerabilities module (spec §3.5)."""

import json

from command_runner import CommandResult
from modules.updates import (
    build_status_report,
    parse_apt_upgradable,
    parse_fwupd_updates,
    parse_pro_status,
    refresh,
)
from models import Severity

APT_UPGRADABLE = (
    "Listing...\n"
    "firefox/noble-updates 128.0 amd64 [upgradable from: 127.0]\n"
    "libc6/noble-security 2.39 amd64 [upgradable from: 2.38]\n"
)

FWUPD_UPDATES_TEXT = "org.fwupd.hughski.ColorHug: no updates available\n" "UEFI dbx: 1 update available\n"

PRO_STATUS_ATTACHED = json.dumps({"attached": True, "services": [{"name": "esm-infra", "status": "enabled"}]})
PRO_STATUS_UNATTACHED = json.dumps({"attached": False})


class TestParseAptUpgradable:
    def test_counts_upgradable_packages(self):
        packages = parse_apt_upgradable(APT_UPGRADABLE)
        assert packages == ["firefox", "libc6"]

    def test_listing_header_is_ignored(self):
        packages = parse_apt_upgradable(APT_UPGRADABLE)
        assert "Listing..." not in packages

    def test_no_updates_returns_empty_list(self):
        assert parse_apt_upgradable("Listing...\n") == []


class TestParseProStatus:
    def test_attached_reports_enabled_services(self):
        status = parse_pro_status(PRO_STATUS_ATTACHED)
        assert status.attached is True
        assert status.enabled_services == ["esm-infra"]

    def test_unattached(self):
        status = parse_pro_status(PRO_STATUS_UNATTACHED)
        assert status.attached is False
        assert status.enabled_services == []

    def test_missing_or_invalid_json_is_treated_as_unavailable(self):
        status = parse_pro_status("")
        assert status.attached is None


class TestParseFwupdUpdates:
    def test_counts_lines_with_available_updates(self):
        assert parse_fwupd_updates(FWUPD_UPDATES_TEXT) == 1

    def test_no_output_means_no_updates(self):
        assert parse_fwupd_updates("") == 0


class TestBuildStatusReport:
    def test_no_pending_updates_is_ok(self):
        report = build_status_report(
            upgradable_packages=[],
            unattended_upgrades_enabled=True,
            pro_attached=None,
            pro_enabled_services=[],
            firmware_updates_count=0,
        )
        assert report.severity == Severity.OK

    def test_many_pending_updates_is_a_warning(self):
        report = build_status_report(
            upgradable_packages=[f"pkg{i}" for i in range(15)],
            unattended_upgrades_enabled=True,
            pro_attached=None,
            pro_enabled_services=[],
            firmware_updates_count=0,
        )
        assert report.severity == Severity.WARNING

    def test_unattended_upgrades_disabled_is_a_warning(self):
        report = build_status_report(
            upgradable_packages=[],
            unattended_upgrades_enabled=False,
            pro_attached=None,
            pro_enabled_services=[],
            firmware_updates_count=0,
        )
        assert report.severity == Severity.WARNING

    def test_firmware_updates_available_is_reported(self):
        report = build_status_report(
            upgradable_packages=[],
            unattended_upgrades_enabled=True,
            pro_attached=None,
            pro_enabled_services=[],
            firmware_updates_count=2,
        )
        assert any("firmware" in f.label.lower() for f in report.findings)


class TestRefresh:
    def test_fetches_expected_commands_and_builds_report(self):
        captured = []

        def fake_run_many(argvs, callback):
            captured.append(argvs)
            callback(
                [
                    CommandResult(0, APT_UPGRADABLE, ""),
                    CommandResult(0, "enabled\n", ""),
                    CommandResult(-1, "", "not found"),
                    CommandResult(-1, "", "not found"),
                ]
            )

        reports = []
        refresh(reports.append, run_many=fake_run_many)

        assert len(reports) == 1
        assert len(captured[0]) == 4
