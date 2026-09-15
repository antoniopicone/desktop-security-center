"""Privacy module — spec §3.9 (P2).

Custom CA certificates are reported for awareness only, without
automatic judgment — the spec is explicit that they could be entirely
legitimate (e.g. a corporate VPN).
"""

from __future__ import annotations

import os
from typing import Callable

from command_runner import CommandResult
from models import Finding, Severity, StatusReport
from modules.auth_accounts import parse_gsettings_bool

_DEFAULT_CA_DIR = "/usr/local/share/ca-certificates"


def list_custom_ca_certificates(ca_dir: str = _DEFAULT_CA_DIR) -> list[str]:
    try:
        return sorted(f for f in os.listdir(ca_dir) if f.endswith((".crt", ".pem")))
    except OSError:
        return []


def build_status_report(
    location_enabled: bool | None,
    remember_recent_files: bool | None,
    custom_ca_certificates: list[str],
) -> StatusReport:
    findings = [
        Finding(
            "Location services",
            "Enabled" if location_enabled else "Disabled",
            Severity.OK,
        ),
        Finding(
            "Remember recent files",
            "Enabled" if remember_recent_files else "Disabled",
            Severity.OK,
        ),
    ]

    for cert in custom_ca_certificates:
        findings.append(
            Finding(
                "Custom CA certificate installed",
                f"{cert} (verify this is expected, e.g. a corporate VPN)",
                Severity.OK,
            )
        )

    return StatusReport(severity=Severity.OK, summary="No privacy concerns flagged", findings=tuple(findings))


def refresh(
    on_result: Callable[[StatusReport], None],
    run_many: Callable[[list[list[str]], Callable[[list[CommandResult]], None]], None],
    ca_dir: str = _DEFAULT_CA_DIR,
) -> None:
    def handle(results: list[CommandResult]) -> None:
        location_result, recent_files_result = results
        on_result(
            build_status_report(
                location_enabled=parse_gsettings_bool(location_result.stdout),
                remember_recent_files=parse_gsettings_bool(recent_files_result.stdout),
                custom_ca_certificates=list_custom_ca_certificates(ca_dir),
            )
        )

    run_many(
        [
            ["gsettings", "get", "org.gnome.system.location", "enabled"],
            ["gsettings", "get", "org.gnome.desktop.privacy", "remember-recent-files"],
        ],
        handle,
    )
