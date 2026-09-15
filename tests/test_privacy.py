"""TDD tests for the Privacy module (spec §3.9)."""

from command_runner import CommandResult
from modules.privacy import build_status_report, list_custom_ca_certificates, refresh
from models import Severity


class TestListCustomCaCertificates:
    def test_lists_installed_certificate_files(self, tmp_path):
        ca_dir = tmp_path / "ca-certificates"
        ca_dir.mkdir()
        (ca_dir / "company-vpn.crt").write_text("-----BEGIN CERTIFICATE-----\n")
        (ca_dir / "readme.txt").write_text("not a cert")

        certs = list_custom_ca_certificates(ca_dir=str(ca_dir))

        assert certs == ["company-vpn.crt"]

    def test_missing_directory_returns_no_certificates(self, tmp_path):
        assert list_custom_ca_certificates(ca_dir=str(tmp_path / "does-not-exist")) == []


class TestBuildStatusReport:
    def test_no_custom_ca_and_privacy_features_off_is_ok(self):
        report = build_status_report(
            location_enabled=False, remember_recent_files=False, custom_ca_certificates=[]
        )
        assert report.severity == Severity.OK

    def test_custom_ca_present_is_informational_not_an_error(self):
        # spec: could be legitimate (corporate VPN) — no automatic judgment
        report = build_status_report(
            location_enabled=False, remember_recent_files=False, custom_ca_certificates=["company-vpn.crt"]
        )
        assert report.severity == Severity.OK
        assert any("company-vpn.crt" in f.value for f in report.findings)

    def test_location_services_enabled_is_reported(self):
        report = build_status_report(
            location_enabled=True, remember_recent_files=False, custom_ca_certificates=[]
        )
        assert any(f.label == "Location services" and f.value == "Enabled" for f in report.findings)


class TestRefresh:
    def test_fetches_expected_gsettings(self):
        captured = []

        def fake_run_many(argvs, callback):
            captured.append(argvs)
            callback([CommandResult(0, "false\n", ""), CommandResult(0, "true\n", "")])

        reports = []
        refresh(reports.append, run_many=fake_run_many, ca_dir="/nonexistent")

        assert len(reports) == 1
        assert len(captured[0]) == 2
