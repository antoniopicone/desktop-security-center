"""Wi-Fi / local network module — spec §3.3 (P0).

Targets NetworkManager only (`nmcli`) — this is Ubuntu Desktop, not a
netplan-minimal server image, so no iwd fallback is implemented (see
spec rationale). Read-only for the MVP.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from command_runner import CommandResult
from models import Finding, Severity, StatusReport

_WEAK_SECURITY = {"", "WEP"}
_WIFI_CONNECTION_TYPE = "802-11-wireless"
_KEY_MGMT_SECURITY = {
    "": "",
    "none": "WEP",
    "wpa-psk": "WPA2",
    "sae": "WPA3",
    "wpa-eap": "WPA2 Enterprise",
}


@dataclass(frozen=True)
class ActiveWifi:
    ssid: str
    security: str


@dataclass(frozen=True)
class WifiConnection:
    name: str
    security: str


def parse_active_wifi(text: str) -> Optional[ActiveWifi]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        active, ssid, security = parts
        if active.lower() == "yes":
            return ActiveWifi(ssid=ssid, security=security)
    return None


def classify_security(security: str) -> str:
    return security if security else "Open"


def is_weak_security(security: str) -> bool:
    return security in _WEAK_SECURITY


def parse_wifi_connection_names(text: str) -> list[str]:
    names: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        name, _sep, conn_type = line.rpartition(":")
        if conn_type == _WIFI_CONNECTION_TYPE and name:
            names.append(name)
    return names


def parse_bluetooth_discoverable(text: str) -> bool:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("Discoverable:"):
            return line.split(":", 1)[1].strip().lower() == "yes"
    return False


def build_status_report(
    nm_available: bool,
    active_wifi: Optional[ActiveWifi],
    weak_profiles: list[WifiConnection],
    bluetooth_discoverable: bool,
) -> StatusReport:
    if not nm_available:
        return StatusReport(
            severity=Severity.ERROR,
            summary="NetworkManager is not available",
            findings=(Finding("NetworkManager", "Not available", Severity.ERROR),),
        )

    findings: list[Finding] = []
    severity = Severity.OK
    summary = "Wi-Fi and Bluetooth look fine"

    if active_wifi is not None:
        label = classify_security(active_wifi.security)
        weak = is_weak_security(active_wifi.security)
        findings.append(
            Finding("Current network", f"{active_wifi.ssid} ({label})", Severity.WARNING if weak else Severity.OK)
        )
        if weak:
            severity = Severity.WARNING
            summary = f"Connected to an open/weakly-secured network ({active_wifi.ssid})"
    else:
        findings.append(Finding("Current network", "Not connected", Severity.OK))

    for profile in weak_profiles:
        findings.append(
            Finding(
                "Saved network with weak security",
                f"{profile.name} ({classify_security(profile.security)})",
                Severity.WARNING,
            )
        )
        if severity == Severity.OK:
            severity = Severity.WARNING
            summary = "One or more saved Wi-Fi profiles use weak security"

    findings.append(
        Finding(
            "Bluetooth discoverable",
            "Yes" if bluetooth_discoverable else "No",
            Severity.WARNING if bluetooth_discoverable else Severity.OK,
        )
    )
    if bluetooth_discoverable and severity == Severity.OK:
        severity = Severity.WARNING
        summary = "Bluetooth is discoverable"

    return StatusReport(severity=severity, summary=summary, findings=tuple(findings))


def parse_key_mgmt(text: str) -> str:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("802-11-wireless-security.key-mgmt:"):
            return line.split(":", 1)[1].strip()
    return ""


def key_mgmt_to_security(key_mgmt: str) -> str:
    return _KEY_MGMT_SECURITY.get(key_mgmt.strip(), key_mgmt)


def refresh(
    on_result: Callable[[StatusReport], None],
    run_many: Callable[[list[list[str]], Callable[[list[CommandResult]], None]], None],
) -> None:
    """Fetch live nmcli/bluetoothctl output and hand a :class:`StatusReport` to *on_result*.

    Runs in two phases: first NetworkManager availability, the active
    network and the list of saved Wi-Fi connection names; then, only for
    those names, one follow-up call each to read their security setting.
    *run_many* is injected for testability, as in firewall.refresh.
    """

    def phase_one(results: list[CommandResult]) -> None:
        nm_result, active_result, names_result, bluetooth_result = results
        nm_available = nm_result.returncode == 0
        if not nm_available:
            on_result(build_status_report(False, None, [], False))
            return

        active_wifi = parse_active_wifi(active_result.stdout)
        names = parse_wifi_connection_names(names_result.stdout)
        bluetooth_discoverable = parse_bluetooth_discoverable(bluetooth_result.stdout)

        if not names:
            on_result(build_status_report(True, active_wifi, [], bluetooth_discoverable))
            return

        def phase_two(security_results: list[CommandResult]) -> None:
            weak_profiles = [
                WifiConnection(name=name, security=security)
                for name, result in zip(names, security_results)
                for security in [key_mgmt_to_security(parse_key_mgmt(result.stdout))]
                if is_weak_security(security)
            ]
            on_result(build_status_report(True, active_wifi, weak_profiles, bluetooth_discoverable))

        run_many(
            [
                ["nmcli", "-t", "-f", "802-11-wireless-security.key-mgmt", "connection", "show", name]
                for name in names
            ],
            phase_two,
        )

    run_many(
        [
            ["systemctl", "is-active", "NetworkManager.service"],
            ["nmcli", "-t", "-f", "active,ssid,security", "dev", "wifi"],
            ["nmcli", "-t", "-f", "name,type", "connection", "show"],
            ["bluetoothctl", "show"],
        ],
        phase_one,
    )
