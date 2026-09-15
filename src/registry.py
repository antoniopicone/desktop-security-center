"""Module registry (spec §2) — adding a category means adding one entry here.

P0 modules (Firewall, Remote access, Wi-Fi) are fully wired with live
checks. Everything else is listed so the full 9-category vision is
visible in the sidebar, but shows an "in development" banner instead of
fabricated data — see spec §7, roadmap item 4.
"""

from __future__ import annotations

import os
from typing import Callable, Optional

from command_runner import CommandResult, build_pkexec_argv, run_command_async, run_many_async
from models import ActionResult, ModuleAction, Priority, SecurityModule, StatusReport
from modules import (
    app_permissions,
    auth_accounts,
    backup,
    firewall,
    hardware_peripherals,
    network_wifi,
    privacy,
    remote_access,
    updates,
)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPER_PATH = os.environ.get(
    "DESKTOP_SECURITY_CENTER_HELPER",
    os.path.join(_PROJECT_ROOT, "helpers", "desktop-security-center-helper"),
)

RunMany = Callable[[list[list[str]], Callable[[list[CommandResult]], None]], None]
RunCommand = Callable[[list[str]], None]


def _run_helper_action(
    subcommand: str,
    run_command: Callable[[list[str], Callable[[CommandResult], None]], None],
    helper_path: str,
) -> Callable[[Callable[[ActionResult], None]], None]:
    def run(on_result: Callable[[ActionResult], None]) -> None:
        argv = build_pkexec_argv(helper_path, subcommand)

        def handle(result: CommandResult) -> None:
            if result.returncode == 0:
                on_result(ActionResult(True, f"{subcommand} completed successfully"))
            else:
                message = result.stderr.strip() or f"{subcommand} failed (exit code {result.returncode})"
                on_result(ActionResult(False, message))

        run_command(argv, handle)

    return run


def _build_firewall_module(run_many: RunMany, run_command, helper_path: str) -> SecurityModule:
    def check(on_result: Callable[[StatusReport], None]) -> None:
        firewall.refresh(on_result, run_many=run_many)

    enable_action = ModuleAction(
        id="enable-ufw",
        label="Enable ufw",
        requires_privilege=True,
        run=_run_helper_action("ufw-enable", run_command, helper_path),
        enabled=True,
        description="Turns on ufw with its default policy (deny incoming, allow outgoing).",
    )
    disable_action = ModuleAction(
        id="disable-ufw",
        label="Disable ufw",
        requires_privilege=True,
        enabled=False,
        description="Coming soon.",
    )
    add_rule_action = ModuleAction(
        id="add-rule",
        label="Add port rule",
        requires_privilege=True,
        enabled=False,
        description="Coming soon.",
    )

    return SecurityModule(
        id="firewall",
        title="Firewall",
        icon_name="network-firewall-symbolic",
        priority=Priority.P0,
        implemented=True,
        check=check,
        actions=(enable_action, disable_action, add_rule_action),
    )


def _build_remote_access_module(run_many: RunMany) -> SecurityModule:
    def check(on_result: Callable[[StatusReport], None]) -> None:
        config_files = remote_access.load_sshd_config_files()
        remote_access.refresh(on_result, run_many=run_many, config_files=config_files)

    return SecurityModule(
        id="remote_access",
        title="Remote Access",
        icon_name="network-server-symbolic",
        priority=Priority.P0,
        implemented=True,
        check=check,
    )


def _build_network_wifi_module(run_many: RunMany) -> SecurityModule:
    def check(on_result: Callable[[StatusReport], None]) -> None:
        network_wifi.refresh(on_result, run_many=run_many)

    return SecurityModule(
        id="network_wifi",
        title="Wi-Fi & Local Network",
        icon_name="network-wireless-symbolic",
        priority=Priority.P0,
        implemented=True,
        check=check,
    )


def _build_simple_module(
    module_id: str,
    title: str,
    icon_name: str,
    priority: Priority,
    module_refresh: Callable[..., None],
    run_many: RunMany,
) -> SecurityModule:
    """Wire a module whose refresh() only needs (on_result, run_many=...)."""

    def check(on_result: Callable[[StatusReport], None]) -> None:
        module_refresh(on_result, run_many=run_many)

    return SecurityModule(
        id=module_id,
        title=title,
        icon_name=icon_name,
        priority=priority,
        implemented=True,
        check=check,
    )


def build_registry(
    run_many: RunMany = run_many_async,
    run_command: Callable[[list[str], Callable[[CommandResult], None]], None] = run_command_async,
    helper_path: str = HELPER_PATH,
) -> list[SecurityModule]:
    """Build the full, ordered list of modules shown in the sidebar.

    All I/O is injected so this — and everything it wires together — can
    be unit tested without touching the real system or a GLib main loop.
    """
    return [
        _build_firewall_module(run_many, run_command, helper_path),
        _build_remote_access_module(run_many),
        _build_network_wifi_module(run_many),
        _build_simple_module(
            "auth_accounts",
            "Authentication & Local Access",
            "dialog-password-symbolic",
            Priority.P1,
            auth_accounts.refresh,
            run_many,
        ),
        _build_simple_module(
            "updates",
            "Updates & Vulnerabilities",
            "software-update-available-symbolic",
            Priority.P1,
            updates.refresh,
            run_many,
        ),
        _build_simple_module(
            "backup",
            "Backup",
            "drive-harddisk-symbolic",
            Priority.P2,
            backup.refresh,
            run_many,
        ),
        _build_simple_module(
            "hardware_peripherals",
            "Hardware & Peripherals",
            "video-display-symbolic",
            Priority.P1,
            hardware_peripherals.refresh,
            run_many,
        ),
        _build_simple_module(
            "app_permissions",
            "App Permissions & Surface",
            "application-x-executable-symbolic",
            Priority.P2,
            app_permissions.refresh,
            run_many,
        ),
        _build_simple_module(
            "privacy",
            "Privacy",
            "view-reveal-symbolic",
            Priority.P2,
            privacy.refresh,
            run_many,
        ),
    ]
