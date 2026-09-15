"""TDD tests for the Hardware & peripherals module (spec §3.7).

Webcam/mic "in use" detection is explicitly flagged in the spec as
needing investigation into a stable GNOME/PipeWire D-Bus API before
committing to it — left out of this module, not faked.
"""

from command_runner import CommandResult
from modules.hardware_peripherals import (
    build_status_report,
    parse_secure_boot_state,
    parse_usbguard_devices,
    refresh,
)
from models import Severity

USBGUARD_DEVICES = (
    '1: allow id 1d6b:0002 serial "" name "xHCI Host Controller" hash "abc" parent-hash "def" via-port "usb1" with-interface {09:00:00}\n'
    '2: block id 0781:5581 serial "" name "Suspicious USB" hash "ghi" parent-hash "def" via-port "usb2" with-interface {08:06:50}\n'
)

MOKUTIL_ENABLED = "SecureBoot enabled\n"
MOKUTIL_DISABLED = "SecureBoot disabled\n"


class TestParseUsbguardDevices:
    def test_counts_allowed_and_blocked(self):
        result = parse_usbguard_devices(USBGUARD_DEVICES)
        assert result.allowed == 1
        assert result.blocked == 1

    def test_empty_output_means_no_devices(self):
        result = parse_usbguard_devices("")
        assert result.allowed == 0
        assert result.blocked == 0


class TestParseSecureBootState:
    def test_enabled(self):
        assert parse_secure_boot_state(MOKUTIL_ENABLED) is True

    def test_disabled(self):
        assert parse_secure_boot_state(MOKUTIL_DISABLED) is False

    def test_unparseable_is_none(self):
        assert parse_secure_boot_state("") is None


class TestBuildStatusReport:
    def test_blocked_usb_device_is_ok_it_means_it_was_stopped(self):
        report = build_status_report(
            usbguard_installed=True, allowed=1, blocked=1, secure_boot=True, tpm_present=True
        )
        assert report.severity == Severity.OK

    def test_secure_boot_disabled_is_informational_not_an_error(self):
        # spec: shown as a deliberate recipe choice (unsigned Limine), not a bare red flag
        report = build_status_report(
            usbguard_installed=True, allowed=0, blocked=0, secure_boot=False, tpm_present=True
        )
        assert report.severity == Severity.OK
        assert any("Secure Boot" in f.label for f in report.findings)

    def test_usbguard_not_installed_is_reported(self):
        report = build_status_report(
            usbguard_installed=False, allowed=0, blocked=0, secure_boot=None, tpm_present=None
        )
        assert any("USBGuard" in f.label and "not installed" in f.value.lower() for f in report.findings)


class TestRefresh:
    def test_fetches_expected_commands(self):
        captured = []

        def fake_run_many(argvs, callback):
            captured.append(argvs)
            callback(
                [
                    CommandResult(0, USBGUARD_DEVICES, ""),
                    CommandResult(0, MOKUTIL_ENABLED, ""),
                    CommandResult(0, "", ""),
                ]
            )

        reports = []
        refresh(reports.append, run_many=fake_run_many)

        assert len(reports) == 1
        assert len(captured[0]) == 3
