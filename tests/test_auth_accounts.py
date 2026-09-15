"""TDD tests for the Authentication & local access module (spec §3.4)."""

from command_runner import CommandResult
from modules.auth_accounts import (
    build_status_report,
    parse_gsettings_bool,
    parse_gsettings_uint,
    parse_howdy_enrolled,
    parse_passwd_login_accounts,
    parse_sudo_group_members,
    refresh,
)
from models import Severity

PASSWD_TEXT = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "antonio:x:1000:1000:Antonio,,,:/home/antonio:/usr/bin/zsh\n"
    "guest:x:1001:1001:Guest:/home/guest:/bin/bash\n"
)

SUDO_GROUP_TEXT = "sudo:x:27:antonio\n"


class TestParsePasswdLoginAccounts:
    def test_only_accounts_with_a_real_shell_are_returned(self):
        accounts = parse_passwd_login_accounts(PASSWD_TEXT)
        assert accounts == ["root", "antonio", "guest"]

    def test_nologin_shell_is_excluded(self):
        accounts = parse_passwd_login_accounts(PASSWD_TEXT)
        assert "daemon" not in accounts

    def test_empty_input_returns_no_accounts(self):
        assert parse_passwd_login_accounts("") == []


class TestParseSudoGroupMembers:
    def test_extracts_comma_separated_members(self):
        assert parse_sudo_group_members(SUDO_GROUP_TEXT) == ["antonio"]

    def test_no_members_returns_empty_list(self):
        assert parse_sudo_group_members("sudo:x:27:\n") == []

    def test_multiple_members(self):
        assert parse_sudo_group_members("sudo:x:27:a,b,c\n") == ["a", "b", "c"]


class TestParseGsettingsBool:
    def test_true_value(self):
        assert parse_gsettings_bool("true\n") is True

    def test_false_value(self):
        assert parse_gsettings_bool("false\n") is False

    def test_unparseable_value_is_none(self):
        assert parse_gsettings_bool("") is None


class TestParseGsettingsUint:
    def test_extracts_uint32_value(self):
        assert parse_gsettings_uint("uint32 300\n") == 300

    def test_plain_integer_value(self):
        assert parse_gsettings_uint("0\n") == 0

    def test_unparseable_value_is_none(self):
        assert parse_gsettings_uint("nonsense\n") is None


class TestParseHowdyEnrolled:
    def test_numbered_entry_means_enrolled(self):
        text = "Known faces for antonio:\n1 - Face model (added on 2026-01-01)\n"
        assert parse_howdy_enrolled(text) is True

    def test_no_known_faces_means_not_enrolled(self):
        assert parse_howdy_enrolled("No known faces\n") is False

    def test_empty_output_means_not_enrolled(self):
        assert parse_howdy_enrolled("") is False


class TestBuildStatusReport:
    def _report(self, **overrides):
        defaults = dict(
            login_accounts=["antonio"],
            sudo_members=["antonio"],
            howdy_installed=True,
            howdy_enrolled=True,
            screen_lock_enabled=True,
            idle_delay_seconds=300,
            failed_login_count=0,
        )
        defaults.update(overrides)
        return build_status_report(**defaults)

    def test_all_good_is_ok(self):
        assert self._report().severity == Severity.OK

    def test_screen_lock_disabled_is_a_warning(self):
        report = self._report(screen_lock_enabled=False)
        assert report.severity == Severity.WARNING

    def test_idle_delay_zero_never_locks_is_a_warning(self):
        report = self._report(idle_delay_seconds=0)
        assert report.severity == Severity.WARNING

    def test_many_failed_logins_is_a_warning(self):
        report = self._report(failed_login_count=10)
        assert report.severity == Severity.WARNING

    def test_howdy_not_installed_does_not_lower_severity(self):
        report = self._report(howdy_installed=False, howdy_enrolled=False)
        assert report.severity == Severity.OK

    def test_sudo_members_are_listed_as_a_finding(self):
        report = self._report(sudo_members=["antonio", "guest"])
        assert any("guest" in f.value for f in report.findings)


class TestRefresh:
    def test_fetches_expected_commands(self):
        captured = []

        def fake_run_many(argvs, callback):
            captured.append(argvs)
            callback(
                [
                    CommandResult(0, PASSWD_TEXT, ""),
                    CommandResult(0, SUDO_GROUP_TEXT, ""),
                    CommandResult(0, "No known faces\n", ""),
                    CommandResult(0, "true\n", ""),
                    CommandResult(0, "uint32 300\n", ""),
                    CommandResult(0, "", ""),
                ]
            )

        reports = []
        refresh(reports.append, run_many=fake_run_many)

        assert len(reports) == 1
        assert reports[0].severity == Severity.OK
        assert len(captured[0]) == 6
