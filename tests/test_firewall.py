"""TDD tests for the Firewall module (spec §3.1) — written before the implementation."""

from command_runner import CommandResult
from modules.firewall import (
    ListeningPort,
    UfwStatus,
    build_status_report,
    parse_listening_ports,
    parse_ufw_status,
    refresh,
    resolve_process_name,
)
from models import Severity

UFW_ACTIVE_VERBOSE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""

UFW_INACTIVE = "Status: inactive\n"


class TestParseUfwStatus:
    def test_active_is_enabled(self):
        status = parse_ufw_status(UFW_ACTIVE_VERBOSE)
        assert status.enabled is True

    def test_inactive_is_disabled(self):
        status = parse_ufw_status(UFW_INACTIVE)
        assert status.enabled is False

    def test_default_policy_is_parsed(self):
        status = parse_ufw_status(UFW_ACTIVE_VERBOSE)
        assert status.default_incoming == "deny"
        assert status.default_outgoing == "allow"

    def test_rules_are_collected(self):
        status = parse_ufw_status(UFW_ACTIVE_VERBOSE)
        assert any("22/tcp" in rule for rule in status.rules)

    def test_inactive_has_no_default_policy(self):
        status = parse_ufw_status(UFW_INACTIVE)
        assert status.default_incoming is None
        assert status.default_outgoing is None

    def test_empty_input_is_not_enabled(self):
        status = parse_ufw_status("")
        assert status.enabled is False


SS_TCP_WITH_PROCESS = (
    "State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port  Process\n"
    'LISTEN  0       128            0.0.0.0:22          0.0.0.0:*      users:(("sshd",pid=1234,fd=3))\n'
    'LISTEN  0       4096         127.0.0.1:631          0.0.0.0:*      users:(("cupsd",pid=999,fd=7))\n'
    'LISTEN  0       128               [::]:22             [::]:*      users:(("sshd",pid=1234,fd=4))\n'
)

SS_TCP_WITHOUT_PROCESS = (
    "State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port\n"
    "LISTEN  0       128            0.0.0.0:22          0.0.0.0:*\n"
)


class TestParseListeningPorts:
    def test_extracts_pid_and_process_name(self):
        ports = parse_listening_ports(SS_TCP_WITH_PROCESS, "")
        by_port = {(p.address, p.port) for p in ports}
        assert ("0.0.0.0", 22) in by_port
        sshd = next(p for p in ports if p.address == "0.0.0.0" and p.port == 22)
        assert sshd.pid == 1234
        assert sshd.process_name == "sshd"

    def test_public_vs_local_address(self):
        ports = parse_listening_ports(SS_TCP_WITH_PROCESS, "")
        sshd = next(p for p in ports if p.address == "0.0.0.0")
        cupsd = next(p for p in ports if p.address == "127.0.0.1")
        assert sshd.public is True
        assert cupsd.public is False

    def test_ipv6_all_interfaces_is_public(self):
        ports = parse_listening_ports(SS_TCP_WITH_PROCESS, "")
        ipv6 = next(p for p in ports if p.address == "[::]")
        assert ipv6.public is True

    def test_proto_is_set_from_argument(self):
        tcp_ports = parse_listening_ports(SS_TCP_WITH_PROCESS, "")
        assert all(p.proto == "tcp" for p in tcp_ports)

    def test_udp_ports_are_tagged_udp(self):
        ports = parse_listening_ports("", SS_TCP_WITH_PROCESS)
        assert all(p.proto == "udp" for p in ports)

    def test_missing_process_column_is_handled_gracefully(self):
        ports = parse_listening_ports(SS_TCP_WITHOUT_PROCESS, "")
        assert len(ports) == 1
        assert ports[0].pid is None
        assert ports[0].process_name is None

    def test_empty_input_returns_no_ports(self):
        assert parse_listening_ports("", "") == []


class TestResolveProcessName:
    def test_reads_comm_file(self, tmp_path):
        proc_dir = tmp_path / "1234"
        proc_dir.mkdir()
        (proc_dir / "comm").write_text("sshd\n")
        assert resolve_process_name(1234, proc_root=str(tmp_path)) == "sshd"

    def test_missing_pid_returns_none(self, tmp_path):
        assert resolve_process_name(9999, proc_root=str(tmp_path)) is None

    def test_none_pid_returns_none(self, tmp_path):
        assert resolve_process_name(None, proc_root=str(tmp_path)) is None


class TestBuildStatusReport:
    def test_disabled_firewall_is_an_error(self):
        report = build_status_report(UfwStatus(enabled=False), [])
        assert report.severity == Severity.ERROR

    def test_enabled_firewall_with_no_public_ports_is_ok(self):
        report = build_status_report(UfwStatus(enabled=True, default_incoming="deny", default_outgoing="allow"), [])
        assert report.severity == Severity.OK

    def test_public_port_is_flagged_but_does_not_override_ok(self):
        port = ListeningPort(proto="tcp", address="0.0.0.0", port=22, pid=1234, process_name="sshd", public=True)
        report = build_status_report(UfwStatus(enabled=True), [port])
        assert report.severity == Severity.OK
        port_findings = [f for f in report.findings if "22" in f.label]
        assert port_findings and port_findings[0].severity == Severity.WARNING

    def test_disabled_firewall_summary_mentions_inactive(self):
        report = build_status_report(UfwStatus(enabled=False), [])
        assert "inactive" in report.summary.lower()


class TestRefresh:
    def test_fetches_three_commands_and_builds_a_report(self):
        captured_argvs = []

        def fake_run_many(argvs, callback):
            captured_argvs.append(argvs)
            callback(
                [
                    CommandResult(0, UFW_ACTIVE_VERBOSE, ""),
                    CommandResult(0, SS_TCP_WITH_PROCESS, ""),
                    CommandResult(0, "", ""),
                ]
            )

        reports = []
        refresh(reports.append, run_many=fake_run_many)

        assert len(reports) == 1
        assert reports[0].severity == Severity.OK
        assert captured_argvs[0] == [
            ["ufw", "status", "verbose"],
            ["ss", "-tlnp"],
            ["ss", "-ulnp"],
        ]

    def test_missing_ufw_binary_reports_unknown_with_error_banner(self):
        def fake_run_many(argvs, callback):
            callback(
                [
                    CommandResult(-1, "", "No such file or directory"),
                    CommandResult(0, "", ""),
                    CommandResult(0, "", ""),
                ]
            )

        reports = []
        refresh(reports.append, run_many=fake_run_many)

        assert reports[0].severity == Severity.UNKNOWN
        assert reports[0].errors
