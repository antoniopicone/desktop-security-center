"""Firewall module — spec §3.1 (P0, flagship demo module).

Reads ``ufw status verbose`` and ``ss -tlnp`` / ``ss -ulnp`` as an
unprivileged user. The only privileged action wired for the MVP is
"Enable ufw", executed through the ``pkexec`` helper.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from command_runner import CommandResult
from models import Finding, Severity, StatusReport

FRIENDLY_NAMES = {
    "sshd": "SSH remote access",
    "cupsd": "Printing (CUPS)",
    "cups-browsed": "Printing (CUPS)",
    "smbd": "File sharing (Samba)",
    "gnome-remote-desktop-daemon": "GNOME Remote Desktop",
}

_PUBLIC_ADDRESSES = {"0.0.0.0", "*", "::", "[::]"}

_DEFAULT_RE = re.compile(r"(\w+)\s*\((\w+)\)")
_PID_RE = re.compile(r"pid=(\d+)")
_NAME_RE = re.compile(r'\(\("([^"]+)"')
_ADDR_PORT_RE = re.compile(r"^(\S+):(\d+|\*)$")


@dataclass(frozen=True)
class UfwStatus:
    enabled: bool
    default_incoming: Optional[str] = None
    default_outgoing: Optional[str] = None
    rules: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ListeningPort:
    proto: str
    address: str
    port: int
    pid: Optional[int]
    process_name: Optional[str]
    public: bool


def parse_ufw_status(text: str) -> UfwStatus:
    enabled = False
    default_incoming: Optional[str] = None
    default_outgoing: Optional[str] = None
    rules: list[str] = []
    in_rules = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Status:"):
            enabled = line.split(":", 1)[1].strip().lower() == "active"
        elif line.startswith("Default:"):
            body = line.split(":", 1)[1]
            for part in body.split(","):
                match = _DEFAULT_RE.search(part)
                if not match:
                    continue
                policy, direction = match.group(1), match.group(2)
                if direction == "incoming":
                    default_incoming = policy
                elif direction == "outgoing":
                    default_outgoing = policy
        elif line.startswith("To") and "Action" in line:
            in_rules = True
        elif line.startswith("--"):
            continue
        elif in_rules:
            rules.append(line)

    return UfwStatus(
        enabled=enabled,
        default_incoming=default_incoming,
        default_outgoing=default_outgoing,
        rules=tuple(rules),
    )


def _parse_ss_output(text: str, proto: str) -> list[ListeningPort]:
    ports: list[ListeningPort] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("State"):
            continue
        columns = line.split()
        if len(columns) < 4:
            continue
        local = columns[3]
        match = _ADDR_PORT_RE.match(local)
        if not match:
            continue
        address, port_str = match.group(1), match.group(2)
        if port_str == "*":
            continue
        port = int(port_str)

        pid: Optional[int] = None
        process_name: Optional[str] = None
        if len(columns) > 5:
            process_field = columns[5]
            pid_match = _PID_RE.search(process_field)
            name_match = _NAME_RE.search(process_field)
            if pid_match:
                pid = int(pid_match.group(1))
            if name_match:
                process_name = name_match.group(1)

        ports.append(
            ListeningPort(
                proto=proto,
                address=address,
                port=port,
                pid=pid,
                process_name=process_name,
                public=address in _PUBLIC_ADDRESSES,
            )
        )
    return ports


def parse_listening_ports(ss_tcp: str, ss_udp: str) -> list[ListeningPort]:
    return _parse_ss_output(ss_tcp, "tcp") + _parse_ss_output(ss_udp, "udp")


def resolve_process_name(pid: Optional[int], proc_root: str = "/proc") -> Optional[str]:
    if pid is None:
        return None
    try:
        with open(f"{proc_root}/{pid}/comm", encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def friendly_name(process_name: Optional[str]) -> Optional[str]:
    if process_name is None:
        return None
    return FRIENDLY_NAMES.get(process_name, process_name)


def build_status_report(ufw: UfwStatus, ports: list[ListeningPort]) -> StatusReport:
    findings: list[Finding] = [
        Finding(
            "Firewall status",
            "Active" if ufw.enabled else "Inactive",
            Severity.OK if ufw.enabled else Severity.ERROR,
        )
    ]

    if ufw.enabled and (ufw.default_incoming or ufw.default_outgoing):
        findings.append(
            Finding(
                "Default policy",
                f"incoming: {ufw.default_incoming or 'unknown'}, "
                f"outgoing: {ufw.default_outgoing or 'unknown'}",
                Severity.OK,
            )
        )

    for port in sorted(ports, key=lambda p: (p.proto, p.port)):
        name = friendly_name(port.process_name) or "unknown process"
        exposure = "all interfaces" if port.public else "localhost only"
        severity = Severity.WARNING if port.public else Severity.OK
        findings.append(
            Finding(
                f"{port.proto.upper()} port {port.port}",
                f"{name} ({exposure})",
                severity,
            )
        )

    if ufw.enabled:
        severity = Severity.OK
        summary = "Firewall (ufw) is active"
    else:
        severity = Severity.ERROR
        summary = "Firewall (ufw) is inactive — the system is not filtering incoming connections"

    return StatusReport(severity=severity, summary=summary, findings=tuple(findings))


def refresh(
    on_result: Callable[[StatusReport], None],
    run_many: Callable[[list[list[str]], Callable[[list[CommandResult]], None]], None],
) -> None:
    """Fetch live ufw/ss output and hand the built :class:`StatusReport` to *on_result*.

    *run_many* is injected so this orchestration can be unit tested without
    a GLib main loop; in the running app it is ``command_runner.run_many_async``.
    """

    def handle(results: list[CommandResult]) -> None:
        ufw_result, tcp_result, udp_result = results
        if ufw_result.returncode == -1:
            on_result(
                StatusReport(
                    severity=Severity.UNKNOWN,
                    summary="ufw is not installed",
                    errors=(f"ufw command not found: {ufw_result.stderr}",),
                )
            )
            return
        ufw = parse_ufw_status(ufw_result.stdout)
        ports = parse_listening_ports(tcp_result.stdout, udp_result.stdout)
        on_result(build_status_report(ufw, ports))

    run_many(
        [["ufw", "status", "verbose"], ["ss", "-tlnp"], ["ss", "-ulnp"]],
        handle,
    )
