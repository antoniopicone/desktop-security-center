"""Hardware and peripherals module — spec §3.7 (P1).

Webcam/microphone "in use" detection is intentionally not implemented:
the spec flags it as needing investigation into a stable GNOME/PipeWire
D-Bus API first — better to omit it than fake it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from command_runner import CommandResult
from models import Finding, Severity, StatusReport


@dataclass(frozen=True)
class UsbguardDevices:
    allowed: int
    blocked: int


def parse_usbguard_devices(text: str) -> UsbguardDevices:
    allowed = 0
    blocked = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # "<id>: allow ..." / "<id>: block ..."
        _prefix, _sep, rest = line.partition(":")
        action = rest.strip().split(" ", 1)[0] if rest.strip() else ""
        if action == "allow":
            allowed += 1
        elif action == "block":
            blocked += 1
    return UsbguardDevices(allowed=allowed, blocked=blocked)


def parse_secure_boot_state(text: str) -> Optional[bool]:
    value = text.strip().lower()
    if "enabled" in value:
        return True
    if "disabled" in value:
        return False
    return None


def build_status_report(
    usbguard_installed: bool,
    allowed: int,
    blocked: int,
    secure_boot: Optional[bool],
    tpm_present: Optional[bool],
) -> StatusReport:
    findings: list[Finding] = []
    severity = Severity.OK
    summary = "Hardware and peripherals look fine"

    if usbguard_installed:
        findings.append(Finding("USBGuard — authorized devices", str(allowed), Severity.OK))
        findings.append(Finding("USBGuard — blocked devices", str(blocked), Severity.OK))
    else:
        findings.append(Finding("USBGuard", "Not installed", Severity.WARNING))
        severity = Severity.WARNING
        summary = "USBGuard is not installed"

    if secure_boot is not None:
        findings.append(
            Finding(
                "Secure Boot",
                "Enabled" if secure_boot else "Disabled (deliberate recipe choice — unsigned Limine bootloader)",
                Severity.OK,
            )
        )

    if tpm_present is not None:
        findings.append(Finding("TPM", "Present" if tpm_present else "Not present", Severity.OK))

    return StatusReport(severity=severity, summary=summary, findings=tuple(findings))


def refresh(
    on_result: Callable[[StatusReport], None],
    run_many: Callable[[list[list[str]], Callable[[list[CommandResult]], None]], None],
) -> None:
    def handle(results: list[CommandResult]) -> None:
        usbguard_result, secure_boot_result, tpm_result = results

        usbguard_installed = usbguard_result.returncode != -1
        devices = parse_usbguard_devices(usbguard_result.stdout) if usbguard_installed else UsbguardDevices(0, 0)

        secure_boot = parse_secure_boot_state(secure_boot_result.stdout) if secure_boot_result.returncode != -1 else None
        tpm_present = tpm_result.returncode == 0

        on_result(
            build_status_report(
                usbguard_installed=usbguard_installed,
                allowed=devices.allowed,
                blocked=devices.blocked,
                secure_boot=secure_boot,
                tpm_present=tpm_present,
            )
        )

    run_many(
        [
            ["usbguard", "list-devices"],
            ["mokutil", "--sb-state"],
            ["test", "-e", "/sys/class/tpm/tpm0"],
        ],
        handle,
    )
