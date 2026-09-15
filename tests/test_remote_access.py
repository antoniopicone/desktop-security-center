"""TDD tests for the Remote access module (spec §3.2)."""

from command_runner import CommandResult
from modules.remote_access import (
    DetectedTool,
    SshdConfig,
    THIRD_PARTY_TOOLS,
    build_status_report,
    detect_third_party_tools,
    load_sshd_config_files,
    parse_sshd_config,
    refresh,
)
from models import Severity

SSHD_CONFIG_SAFE = """
Port 22
PermitRootLogin no
PasswordAuthentication no
"""

SSHD_CONFIG_WEAK = """
# default config, nothing overridden
Port 22
"""

SSHD_CONFIG_EXPLICIT_WEAK = """
Port 2222
PermitRootLogin yes
PasswordAuthentication yes
"""


class TestParseSshdConfig:
    def test_parses_explicit_safe_values(self):
        config = parse_sshd_config([("sshd_config", SSHD_CONFIG_SAFE)])
        assert config.password_authentication is False
        assert config.permit_root_login == "no"
        assert config.port == 22

    def test_parses_explicit_weak_values(self):
        config = parse_sshd_config([("sshd_config", SSHD_CONFIG_EXPLICIT_WEAK)])
        assert config.password_authentication is True
        assert config.permit_root_login == "yes"
        assert config.port == 2222

    def test_unset_password_authentication_is_none(self):
        config = parse_sshd_config([("sshd_config", SSHD_CONFIG_WEAK)])
        assert config.password_authentication is None

    def test_comments_are_ignored(self):
        config = parse_sshd_config([("sshd_config", SSHD_CONFIG_WEAK)])
        assert config.port == 22

    def test_first_file_wins_over_later_ones(self):
        # OpenSSH semantics: first obtained value for a keyword is used.
        main = ("sshd_config", "PasswordAuthentication no\n")
        override = ("sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
        config = parse_sshd_config([main, override])
        assert config.password_authentication is False

    def test_default_port_when_unset(self):
        config = parse_sshd_config([("sshd_config", "PermitRootLogin no\n")])
        assert config.port == 22


class TestDetectThirdPartyTools:
    def test_detects_active_known_tool(self):
        is_active = {"teamviewerd.service": True}.get
        detected = detect_third_party_tools(lambda unit: bool(is_active(unit)))
        names = {tool.name for tool in detected}
        assert "TeamViewer" in names

    def test_inactive_tools_are_not_reported(self):
        detected = detect_third_party_tools(lambda unit: False)
        assert detected == []

    def test_covers_all_whitelisted_tools(self):
        detected = detect_third_party_tools(lambda unit: True)
        assert len(detected) == len(THIRD_PARTY_TOOLS)


class TestBuildStatusReport:
    def test_password_auth_enabled_is_a_warning(self):
        config = SshdConfig(password_authentication=True, permit_root_login="no", port=22)
        report = build_status_report(ssh_active=True, sshd_config=config, third_party_tools=[])
        assert report.severity in (Severity.WARNING, Severity.ERROR)

    def test_root_login_and_password_auth_both_enabled_is_an_error(self):
        config = SshdConfig(password_authentication=True, permit_root_login="yes", port=22)
        report = build_status_report(ssh_active=True, sshd_config=config, third_party_tools=[])
        assert report.severity == Severity.ERROR

    def test_hardened_config_is_ok(self):
        config = SshdConfig(password_authentication=False, permit_root_login="no", port=22)
        report = build_status_report(ssh_active=True, sshd_config=config, third_party_tools=[])
        assert report.severity == Severity.OK

    def test_ssh_inactive_is_ok_regardless_of_config(self):
        config = SshdConfig(password_authentication=True, permit_root_login="yes", port=22)
        report = build_status_report(ssh_active=False, sshd_config=config, third_party_tools=[])
        assert report.severity == Severity.OK

    def test_detected_third_party_tool_is_a_finding(self):
        config = SshdConfig(password_authentication=False, permit_root_login="no", port=22)
        tool = DetectedTool(name="AnyDesk", unit="anydesk.service")
        report = build_status_report(ssh_active=False, sshd_config=config, third_party_tools=[tool])
        assert any("AnyDesk" in f.value for f in report.findings)


class TestLoadSshdConfigFiles:
    def test_reads_main_config_and_drop_in_fragments(self, tmp_path):
        (tmp_path / "sshd_config").write_text("Port 22\n")
        drop_in_dir = tmp_path / "sshd_config.d"
        drop_in_dir.mkdir()
        (drop_in_dir / "50-cloud-init.conf").write_text("PasswordAuthentication yes\n")

        files = load_sshd_config_files(base_dir=str(tmp_path))

        assert files[0] == ("sshd_config", "Port 22\n")
        assert files[1][1] == "PasswordAuthentication yes\n"

    def test_missing_directory_returns_only_main_config(self, tmp_path):
        (tmp_path / "sshd_config").write_text("Port 22\n")
        files = load_sshd_config_files(base_dir=str(tmp_path))
        assert len(files) == 1

    def test_missing_main_config_returns_empty_list(self, tmp_path):
        assert load_sshd_config_files(base_dir=str(tmp_path)) == []


class TestRefresh:
    def test_active_ssh_with_safe_config_is_ok(self):
        def fake_run_many(argvs, callback):
            callback([CommandResult(0, "", "")] + [CommandResult(3, "", "") for _ in argvs[1:]])

        reports = []
        refresh(reports.append, run_many=fake_run_many, config_files=[("sshd_config", SSHD_CONFIG_SAFE)])

        assert reports[0].severity == Severity.OK

    def test_detected_tool_via_run_many_is_reported(self):
        def fake_run_many(argvs, callback):
            # ssh inactive, teamviewerd active (first entry in THIRD_PARTY_TOOLS)
            results = [CommandResult(3, "", "")]
            for unit, _name in THIRD_PARTY_TOOLS:
                results.append(CommandResult(0 if unit == "teamviewerd.service" else 3, "", ""))
            callback(results)

        reports = []
        refresh(reports.append, run_many=fake_run_many, config_files=[])

        assert any("TeamViewer" in f.value for f in reports[0].findings)
