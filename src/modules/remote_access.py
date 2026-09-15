"""Remote access module — spec §3.2 (P0).

Reads SSH daemon status/config and detects a whitelisted set of known
remote-access tools by systemd unit name. Read-only for the MVP: no
privileged actions are wired yet (config editing is backlog).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Callable, Optional

from command_runner import CommandResult
from models import Finding, Severity, StatusReport

# (systemd unit, friendly name) — checked via `systemctl is-active <unit>`.
THIRD_PARTY_TOOLS = (
    ("teamviewerd.service", "TeamViewer"),
    ("anydesk.service", "AnyDesk"),
    ("rustdesk.service", "RustDesk"),
    ("x11vnc.service", "x11vnc"),
    ("xrdp.service", "xrdp"),
)

_DEFAULT_PORT = 22
_BOOL_VALUES = {"yes": True, "no": False}
_DIRECTIVE_RE = re.compile(r"^(\S+)\s+(.+)$")


@dataclass(frozen=True)
class SshdConfig:
    password_authentication: Optional[bool]
    permit_root_login: Optional[str]
    port: int


@dataclass(frozen=True)
class DetectedTool:
    name: str
    unit: str


def parse_sshd_config(files: list[tuple[str, str]]) -> SshdConfig:
    """Parse sshd_config + sshd_config.d/* fragments.

    OpenSSH uses "first obtained value wins" semantics, so *files* must be
    given in the order sshd would read them (main config first).
    """
    password_authentication: Optional[bool] = None
    permit_root_login: Optional[str] = None
    port: Optional[int] = None

    for _name, text in files:
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            match = _DIRECTIVE_RE.match(line)
            if not match:
                continue
            keyword, value = match.group(1).lower(), match.group(2).strip()

            if keyword == "passwordauthentication" and password_authentication is None:
                password_authentication = _BOOL_VALUES.get(value.lower())
            elif keyword == "permitrootlogin" and permit_root_login is None:
                permit_root_login = value.lower()
            elif keyword == "port" and port is None:
                try:
                    port = int(value)
                except ValueError:
                    pass

    return SshdConfig(
        password_authentication=password_authentication,
        permit_root_login=permit_root_login,
        port=port if port is not None else _DEFAULT_PORT,
    )


def detect_third_party_tools(is_active: Callable[[str], bool]) -> list[DetectedTool]:
    return [
        DetectedTool(name=name, unit=unit)
        for unit, name in THIRD_PARTY_TOOLS
        if is_active(unit)
    ]


def build_status_report(
    ssh_active: bool,
    sshd_config: SshdConfig,
    third_party_tools: list[DetectedTool],
) -> StatusReport:
    findings: list[Finding] = [
        Finding("SSH service", "Active" if ssh_active else "Inactive", Severity.OK),
    ]

    severity = Severity.OK
    summary = "No remote-access exposure detected"

    if ssh_active:
        findings.append(Finding("SSH port", str(sshd_config.port), Severity.OK))

        password_auth = sshd_config.password_authentication
        password_auth_on = password_auth is not False  # None (unset) defaults to OpenSSH's "yes"
        findings.append(
            Finding(
                "Password authentication",
                "Enabled" if password_auth_on else "Disabled",
                Severity.WARNING if password_auth_on else Severity.OK,
            )
        )

        root_login = sshd_config.permit_root_login
        root_login_on = root_login not in ("no", "prohibit-password", "without-password")
        findings.append(
            Finding(
                "Root login",
                root_login or "unknown",
                Severity.WARNING if root_login_on else Severity.OK,
            )
        )

        if password_auth_on and root_login_on:
            severity = Severity.ERROR
            summary = "SSH allows password login as root — high risk"
        elif password_auth_on:
            severity = Severity.WARNING
            summary = "SSH password authentication is enabled"

    for tool in third_party_tools:
        findings.append(Finding("Remote-access tool detected", tool.name, Severity.WARNING))
        if severity == Severity.OK:
            severity = Severity.WARNING
            summary = f"{tool.name} is running"

    return StatusReport(severity=severity, summary=summary, findings=tuple(findings))


def load_sshd_config_files(base_dir: str = "/etc/ssh") -> list[tuple[str, str]]:
    """Read sshd_config + sshd_config.d/*.conf, in the order sshd reads them."""
    files: list[tuple[str, str]] = []
    main_path = os.path.join(base_dir, "sshd_config")
    try:
        with open(main_path, encoding="utf-8") as handle:
            files.append(("sshd_config", handle.read()))
    except OSError:
        return []

    drop_in_dir = os.path.join(base_dir, "sshd_config.d")
    try:
        entries = sorted(os.listdir(drop_in_dir))
    except OSError:
        entries = []

    for entry in entries:
        if not entry.endswith(".conf"):
            continue
        path = os.path.join(drop_in_dir, entry)
        try:
            with open(path, encoding="utf-8") as handle:
                files.append((f"sshd_config.d/{entry}", handle.read()))
        except OSError:
            continue

    return files


def refresh(
    on_result: Callable[[StatusReport], None],
    run_many: Callable[[list[list[str]], Callable[[list[CommandResult]], None]], None],
    config_files: list[tuple[str, str]],
) -> None:
    """Fetch live systemctl status and hand the built :class:`StatusReport` to *on_result*.

    *run_many* is injected for testability (see firewall.refresh); the app
    wires it to ``command_runner.run_many_async``. *config_files* is the
    already-read result of :func:`load_sshd_config_files`.
    """
    units = ["ssh.service"] + [unit for unit, _name in THIRD_PARTY_TOOLS]

    def handle(results: list[CommandResult]) -> None:
        ssh_active = results[0].returncode == 0
        active_by_unit = {unit: result.returncode == 0 for unit, result in zip(units[1:], results[1:])}
        tools = detect_third_party_tools(lambda unit: active_by_unit.get(unit, False))
        sshd_config = parse_sshd_config(config_files)
        on_result(build_status_report(ssh_active, sshd_config, tools))

    run_many([["systemctl", "is-active", unit] for unit in units], handle)
