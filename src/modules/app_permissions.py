"""App permissions & software surface module — spec §3.8 (P2).

Read-only, deliberately: Flatpak permissions are shown for awareness
only (with a pointer to Flatseal for actual management), not managed
here, to avoid duplicating a tool that already exists and is mature.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from command_runner import CommandResult
from models import Finding, Severity, StatusReport

RISKY_FLATPAK_PERMISSIONS = {"filesystem=home", "filesystem=host", "socket=x11"}
_PERMISSION_KEY_SINGULAR = {"sockets": "socket", "filesystems": "filesystem", "devices": "device"}
_DEFAULT_AUTOSTART_DIR = os.path.expanduser("~/.config/autostart")


@dataclass(frozen=True)
class AutostartEntry:
    filename: str
    no_display: bool


def parse_flatpak_apps(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def parse_flatpak_permissions(text: str) -> list[str]:
    risky = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if "=" not in line or line.startswith("["):
            continue
        key, _sep, values = line.partition("=")
        singular = _PERMISSION_KEY_SINGULAR.get(key.strip(), key.strip())
        for value in values.strip().rstrip(";").split(";"):
            value = value.strip()
            if not value:
                continue
            entry = f"{singular}={value}"
            if entry in RISKY_FLATPAK_PERMISSIONS:
                risky.append(entry)
    return risky


def parse_snap_connections(text: str) -> list[str]:
    interfaces = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("Interface"):
            continue
        columns = line.split()
        if columns:
            interfaces.append(columns[0])
    return interfaces


def list_autostart_entries(autostart_dir: str = _DEFAULT_AUTOSTART_DIR) -> list[AutostartEntry]:
    try:
        filenames = sorted(f for f in os.listdir(autostart_dir) if f.endswith(".desktop"))
    except OSError:
        return []

    entries = []
    for filename in filenames:
        no_display = False
        try:
            with open(os.path.join(autostart_dir, filename), encoding="utf-8") as handle:
                no_display = any(line.strip().lower() == "nodisplay=true" for line in handle)
        except OSError:
            pass
        entries.append(AutostartEntry(filename=filename, no_display=no_display))
    return entries


def build_status_report(
    risky_flatpaks: dict[str, list[str]],
    snap_interfaces: list[str],
    autostart_entries: list[AutostartEntry],
) -> StatusReport:
    findings: list[Finding] = []

    for app_id, permissions in sorted(risky_flatpaks.items()):
        findings.append(
            Finding("Flatpak app with broad permissions", f"{app_id}: {', '.join(permissions)}", Severity.WARNING)
        )

    findings.append(
        Finding(
            "Snap interfaces granted",
            ", ".join(sorted(set(snap_interfaces))) or "none",
            Severity.OK,
        )
    )
    findings.append(Finding("Autostart entries (incl. hidden)", str(len(autostart_entries)), Severity.OK))

    if risky_flatpaks:
        severity = Severity.WARNING
        summary = f"{len(risky_flatpaks)} Flatpak app(s) have broad filesystem/X11 access"
    else:
        severity = Severity.OK
        summary = "No overly broad Flatpak permissions detected"

    return StatusReport(severity=severity, summary=summary, findings=tuple(findings))


def refresh(
    on_result: Callable[[StatusReport], None],
    run_many: Callable[[list[list[str]], Callable[[list[CommandResult]], None]], None],
) -> None:
    def handle_apps(results: list[CommandResult]) -> None:
        flatpak_result, snap_result = results
        apps = parse_flatpak_apps(flatpak_result.stdout) if flatpak_result.returncode != -1 else []
        snap_interfaces = parse_snap_connections(snap_result.stdout) if snap_result.returncode != -1 else []
        autostart_entries = list_autostart_entries()

        if not apps:
            on_result(build_status_report({}, snap_interfaces, autostart_entries))
            return

        def handle_permissions(permission_results: list[CommandResult]) -> None:
            risky_flatpaks = {
                app_id: risky
                for app_id, result in zip(apps, permission_results)
                for risky in [parse_flatpak_permissions(result.stdout)]
                if risky
            }
            on_result(build_status_report(risky_flatpaks, snap_interfaces, autostart_entries))

        run_many(
            [["flatpak", "info", "--show-permissions", app_id] for app_id in apps],
            handle_permissions,
        )

    run_many(
        [
            ["flatpak", "list", "--app", "--columns=application"],
            ["snap", "connections"],
        ],
        handle_apps,
    )
