"""Authentication and local access module — spec §3.4 (P1).

Read-only for this iteration: no privileged actions are wired (config
editing, e.g. forcing screen lock on, is backlog). ``passwd -S`` (which
flags accounts with no password) needs privileges, so it's left out of
the unprivileged read — the spec explicitly allows this trade-off.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

from command_runner import CommandResult
from models import Finding, Severity, StatusReport

_NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""}
_FAILED_LOGIN_WARNING_THRESHOLD = 5
_HOWDY_ENTRY_RE = re.compile(r"^\d+\s*-")


def parse_passwd_login_accounts(text: str) -> list[str]:
    accounts = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 7:
            continue
        username, shell = fields[0], fields[6]
        if shell not in _NOLOGIN_SHELLS:
            accounts.append(username)
    return accounts


def parse_sudo_group_members(text: str) -> list[str]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split(":")
        if len(fields) < 4:
            continue
        members = fields[3].strip()
        return [m for m in members.split(",") if m] if members else []
    return []


def parse_gsettings_bool(text: str) -> Optional[bool]:
    value = text.strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def parse_gsettings_uint(text: str) -> Optional[int]:
    value = text.strip()
    match = re.search(r"(-?\d+)\s*$", value)
    return int(match.group(1)) if match else None


def parse_howdy_enrolled(text: str) -> bool:
    return any(_HOWDY_ENTRY_RE.match(line.strip()) for line in text.splitlines())


def build_status_report(
    login_accounts: list[str],
    sudo_members: list[str],
    howdy_installed: bool,
    howdy_enrolled: bool,
    screen_lock_enabled: Optional[bool],
    idle_delay_seconds: Optional[int],
    failed_login_count: int,
) -> StatusReport:
    findings: list[Finding] = [
        Finding("Login-capable accounts", str(len(login_accounts)), Severity.OK),
        Finding("Members of sudo group", ", ".join(sudo_members) or "none", Severity.OK),
    ]

    severity = Severity.OK
    summary = "Local authentication looks fine"

    lock_on = screen_lock_enabled is not False
    findings.append(
        Finding("Screen lock", "Enabled" if lock_on else "Disabled", Severity.OK if lock_on else Severity.WARNING)
    )
    if not lock_on:
        severity = Severity.WARNING
        summary = "Screen lock is disabled"

    never_locks = idle_delay_seconds == 0
    findings.append(
        Finding(
            "Idle delay before locking",
            "Never" if never_locks else (f"{idle_delay_seconds}s" if idle_delay_seconds is not None else "unknown"),
            Severity.WARNING if never_locks else Severity.OK,
        )
    )
    if never_locks and severity == Severity.OK:
        severity = Severity.WARNING
        summary = "The screen never locks automatically"

    if howdy_installed:
        findings.append(
            Finding("Howdy face enrollment", "Enrolled" if howdy_enrolled else "Not enrolled", Severity.OK)
        )

    findings.append(
        Finding(
            "Recent failed SSH logins",
            str(failed_login_count),
            Severity.WARNING if failed_login_count >= _FAILED_LOGIN_WARNING_THRESHOLD else Severity.OK,
        )
    )
    if failed_login_count >= _FAILED_LOGIN_WARNING_THRESHOLD and severity == Severity.OK:
        severity = Severity.WARNING
        summary = f"{failed_login_count} recent failed SSH login attempts"

    return StatusReport(severity=severity, summary=summary, findings=tuple(findings))


def refresh(
    on_result: Callable[[StatusReport], None],
    run_many: Callable[[list[list[str]], Callable[[list[CommandResult]], None]], None],
) -> None:
    def handle(results: list[CommandResult]) -> None:
        passwd_result, sudo_result, howdy_result, lock_result, idle_result, journal_result = results

        login_accounts = parse_passwd_login_accounts(passwd_result.stdout)
        sudo_members = parse_sudo_group_members(sudo_result.stdout)

        howdy_installed = howdy_result.returncode != -1
        howdy_enrolled = parse_howdy_enrolled(howdy_result.stdout) if howdy_installed else False

        screen_lock_enabled = parse_gsettings_bool(lock_result.stdout)
        idle_delay_seconds = parse_gsettings_uint(idle_result.stdout)

        failed_login_count = sum(
            1 for line in journal_result.stdout.splitlines() if "Failed password" in line
        )

        on_result(
            build_status_report(
                login_accounts=login_accounts,
                sudo_members=sudo_members,
                howdy_installed=howdy_installed,
                howdy_enrolled=howdy_enrolled,
                screen_lock_enabled=screen_lock_enabled,
                idle_delay_seconds=idle_delay_seconds,
                failed_login_count=failed_login_count,
            )
        )

    run_many(
        [
            ["getent", "passwd"],
            ["getent", "group", "sudo"],
            ["howdy", "list"],
            ["gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"],
            ["gsettings", "get", "org.gnome.desktop.session", "idle-delay"],
            ["journalctl", "-u", "ssh.service", "-p", "warning", "--no-pager", "-n", "200"],
        ],
        handle,
    )
