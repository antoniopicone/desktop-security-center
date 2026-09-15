"""Updates and vulnerabilities module — spec §3.5 (P1).

Read-only: reads the apt cache without invoking ``apt update`` (no side
effects from a status refresh, per spec). Actions (trigger a manual
unattended-upgrade, open Software Updater) are backlog for this pass.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Optional

from command_runner import CommandResult
from models import Finding, Severity, StatusReport

_MANY_UPDATES_WARNING_THRESHOLD = 10


@dataclass(frozen=True)
class ProStatus:
    attached: Optional[bool]
    enabled_services: list[str]


def parse_apt_upgradable(text: str) -> list[str]:
    packages = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line == "Listing..." or line.startswith("Listing"):
            continue
        name = line.split("/", 1)[0]
        if name:
            packages.append(name)
    return packages


def parse_pro_status(text: str) -> ProStatus:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return ProStatus(attached=None, enabled_services=[])

    attached = data.get("attached")
    enabled_services = [
        service["name"]
        for service in data.get("services", [])
        if service.get("status") == "enabled"
    ]
    return ProStatus(attached=attached, enabled_services=enabled_services)


def parse_fwupd_updates(text: str) -> int:
    return sum(1 for line in text.splitlines() if "update available" in line and not line.strip().startswith("no updates"))


def build_status_report(
    upgradable_packages: list[str],
    unattended_upgrades_enabled: Optional[bool],
    pro_attached: Optional[bool],
    pro_enabled_services: list[str],
    firmware_updates_count: int,
) -> StatusReport:
    findings: list[Finding] = []
    severity = Severity.OK
    summary = "System is up to date"

    pending = len(upgradable_packages)
    many_pending = pending >= _MANY_UPDATES_WARNING_THRESHOLD
    findings.append(
        Finding("Pending package updates", str(pending), Severity.WARNING if many_pending else Severity.OK)
    )
    if many_pending:
        severity = Severity.WARNING
        summary = f"{pending} package updates are pending"

    unattended_on = unattended_upgrades_enabled is not False
    findings.append(
        Finding(
            "unattended-upgrades",
            "Enabled" if unattended_on else "Disabled",
            Severity.OK if unattended_on else Severity.WARNING,
        )
    )
    if not unattended_on and severity == Severity.OK:
        severity = Severity.WARNING
        summary = "unattended-upgrades is disabled"

    if pro_attached is not None:
        findings.append(
            Finding(
                "Ubuntu Pro",
                f"Attached ({', '.join(pro_enabled_services)})" if pro_attached else "Not attached",
                Severity.OK,
            )
        )

    if firmware_updates_count:
        findings.append(Finding("Firmware updates available", str(firmware_updates_count), Severity.WARNING))
        if severity == Severity.OK:
            severity = Severity.WARNING
            summary = f"{firmware_updates_count} firmware update(s) available"

    return StatusReport(severity=severity, summary=summary, findings=tuple(findings))


def refresh(
    on_result: Callable[[StatusReport], None],
    run_many: Callable[[list[list[str]], Callable[[list[CommandResult]], None]], None],
) -> None:
    def handle(results: list[CommandResult]) -> None:
        apt_result, unattended_result, pro_result, fwupd_result = results

        upgradable_packages = parse_apt_upgradable(apt_result.stdout)
        unattended_enabled = unattended_result.stdout.strip() == "enabled"
        pro_status = parse_pro_status(pro_result.stdout) if pro_result.returncode != -1 else ProStatus(None, [])
        firmware_updates_count = parse_fwupd_updates(fwupd_result.stdout) if fwupd_result.returncode != -1 else 0

        on_result(
            build_status_report(
                upgradable_packages=upgradable_packages,
                unattended_upgrades_enabled=unattended_enabled,
                pro_attached=pro_status.attached,
                pro_enabled_services=pro_status.enabled_services,
                firmware_updates_count=firmware_updates_count,
            )
        )

    run_many(
        [
            ["apt", "list", "--upgradable"],
            ["systemctl", "is-enabled", "unattended-upgrades.timer"],
            ["pro", "status", "--format", "json"],
            ["fwupdmgr", "get-updates"],
        ],
        handle,
    )
