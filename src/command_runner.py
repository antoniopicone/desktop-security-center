"""Non-blocking subprocess execution for the GTK main loop (spec §2).

Reads always run as the current user via ``Gio.Subprocess`` async
(never blocking the UI thread). Privileged actions go through this same
wrapper but with argv built by :func:`build_pkexec_argv`, which always
targets the single allowlisted helper binary — never a free-form shell.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

import gi

gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")
from gi.repository import Gio, GLib  # noqa: E402


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def build_pkexec_argv(helper_path: str, subcommand: str) -> list[str]:
    return ["pkexec", helper_path, subcommand]


def run_command_async(
    argv: list[str],
    callback: Callable[[CommandResult], None],
    cancellable: Optional[Gio.Cancellable] = None,
) -> None:
    """Run *argv* without blocking the caller; *callback* fires with the result."""
    try:
        process = Gio.Subprocess.new(
            argv,
            Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE,
        )
    except GLib.Error as exc:
        callback(CommandResult(returncode=-1, stdout="", stderr=str(exc)))
        return

    def on_communicate(proc: Gio.Subprocess, result: Gio.AsyncResult) -> None:
        try:
            _ok, stdout, stderr = proc.communicate_utf8_finish(result)
        except GLib.Error as exc:
            callback(CommandResult(returncode=-1, stdout="", stderr=str(exc)))
            return
        callback(
            CommandResult(
                returncode=proc.get_exit_status(),
                stdout=stdout or "",
                stderr=stderr or "",
            )
        )

    process.communicate_utf8_async(None, cancellable, on_communicate)


def run_many_async(
    argvs: list[list[str]],
    callback: Callable[[list[CommandResult]], None],
) -> None:
    """Run every argv in *argvs* concurrently; *callback* fires once with
    all results, in the same order as *argvs*, once every one has finished."""
    if not argvs:
        callback([])
        return

    results: list[Optional[CommandResult]] = [None] * len(argvs)
    remaining = len(argvs)

    def make_handler(index: int) -> Callable[[CommandResult], None]:
        def handler(result: CommandResult) -> None:
            nonlocal remaining
            results[index] = result
            remaining -= 1
            if remaining == 0:
                callback(results)  # type: ignore[arg-type]

        return handler

    for index, argv in enumerate(argvs):
        run_command_async(argv, make_handler(index))
