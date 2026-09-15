"""Core logic for the single privileged helper (spec §5).

Invoked exclusively as ``pkexec desktop-security-center-helper <subcommand>``.
There is a fixed, hard-coded allowlist of subcommands — no subcommand ever
evaluates or forwards free-form user input to a shell.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Callable, Sequence

# subcommand -> exact argv to execute. No shell, no interpolation.
ALLOWED_SUBCOMMANDS: dict[str, list[str]] = {
    "ufw-enable": ["ufw", "--force", "enable"],
    "ufw-disable": ["ufw", "disable"],
}


class HelperError(Exception):
    pass


def build_command(subcommand: str, args: Sequence[str]) -> list[str]:
    if args:
        raise HelperError(f"unexpected arguments for {subcommand!r}: {list(args)}")
    try:
        return list(ALLOWED_SUBCOMMANDS[subcommand])
    except KeyError as exc:
        raise HelperError(f"unknown subcommand: {subcommand!r}") from exc


def _real_runner(argv: list[str]) -> int:
    return subprocess.run(argv, check=False).returncode


def main(argv: list[str], runner: Callable[[list[str]], int] = _real_runner) -> int:
    if not argv:
        print("usage: desktop-security-center-helper <subcommand>", file=sys.stderr)
        return 2

    subcommand, *rest = argv
    try:
        command = build_command(subcommand, rest)
    except HelperError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return runner(command)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
