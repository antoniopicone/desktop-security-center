"""Backup module — spec §3.6 (P2, Snapper placeholder for the demo).

The spec is explicit that real incremental offsite backup doesn't exist
yet: this module only reports local Snapper snapshots, honestly labeled
as a placeholder, not a substitute for real backup coverage.
"""

from __future__ import annotations

from typing import Callable

from command_runner import CommandResult
from models import Finding, Severity, StatusReport


def parse_snapper_configs(text: str) -> list[str]:
    """Parse `snapper list-configs` table output (also accepts a bare name-per-line list)."""
    configs = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("-") or line.lower().startswith("config"):
            continue
        name = line.split("|", 1)[0].strip()
        if name:
            configs.append(name)
    return configs


def parse_snapper_last_snapshot(text: str) -> str | None:
    last_date: str | None = None
    for raw_line in text.splitlines():
        if "|" not in raw_line or raw_line.strip().startswith("-"):
            continue
        columns = [c.strip() for c in raw_line.split("|")]
        if len(columns) < 4 or not columns[0].isdigit():
            continue
        date = columns[3]
        if date:
            last_date = date
    return last_date


def build_status_report(configs: dict[str, str | None]) -> StatusReport:
    if not configs:
        return StatusReport(
            severity=Severity.WARNING,
            summary="No local Snapper snapshot configured — no backup coverage at all",
            findings=(Finding("Snapper configs", "None found", Severity.WARNING),),
        )

    findings = [
        Finding(f"Last snapshot ({volume})", last_snapshot or "never", Severity.OK if last_snapshot else Severity.WARNING)
        for volume, last_snapshot in sorted(configs.items())
    ]
    any_missing = any(last_snapshot is None for last_snapshot in configs.values())

    return StatusReport(
        severity=Severity.WARNING if any_missing else Severity.OK,
        summary=(
            "Local Snapper snapshots found — this is not a real offsite backup, "
            "just a local-recovery placeholder until the real backup process exists (spec §3.6)"
        ),
        findings=tuple(findings),
    )


def refresh(
    on_result: Callable[[StatusReport], None],
    run_many: Callable[[list[list[str]], Callable[[list[CommandResult]], None]], None],
) -> None:
    def handle_configs(results: list[CommandResult]) -> None:
        (configs_result,) = results
        configs = parse_snapper_configs(configs_result.stdout)

        if not configs:
            on_result(build_status_report({}))
            return

        def handle_snapshots(snapshot_results: list[CommandResult]) -> None:
            by_volume = {
                volume: parse_snapper_last_snapshot(result.stdout)
                for volume, result in zip(configs, snapshot_results)
            }
            on_result(build_status_report(by_volume))

        run_many(
            [["snapper", "-c", volume, "list"] for volume in configs],
            handle_snapshots,
        )

    run_many([["snapper", "list-configs"]], handle_configs)
