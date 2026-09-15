"""Shared data model used by every security module.

Kept dependency-free (no ``gi``/GTK imports) on purpose so it can be
imported from unit tests without a display or PyGObject available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Severity(Enum):
    """Traffic-light severity used by the sidebar status dot."""

    OK = "ok"
    WARNING = "warning"
    ERROR = "error"
    UNKNOWN = "unknown"

    @staticmethod
    def worst(severities: "list[Severity]") -> "Severity":
        """Return the most severe value in *severities* (ERROR beats WARNING beats OK)."""
        order = [Severity.ERROR, Severity.WARNING, Severity.UNKNOWN, Severity.OK]
        for candidate in order:
            if candidate in severities:
                return candidate
        return Severity.UNKNOWN


class Priority(Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"


@dataclass(frozen=True)
class Finding:
    """A single reported fact shown as a row in the module's content pane."""

    label: str
    value: str
    severity: Severity = Severity.OK
    detail: Optional[str] = None


@dataclass(frozen=True)
class StatusReport:
    """Aggregated result of checking one module."""

    severity: Severity
    summary: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ActionResult:
    success: bool
    message: str


@dataclass(frozen=True)
class ModuleAction:
    """A button the user can press in a module's content pane.

    ``run`` is async/callback-based (``run(on_result)``), never blocking —
    privileged actions go through ``pkexec`` and must not freeze the UI
    while waiting for the polkit prompt.
    """

    id: str
    label: str
    requires_privilege: bool
    run: Optional[Callable[[Callable[["ActionResult"], None]], None]] = None
    enabled: bool = True
    description: str = ""


@dataclass(frozen=True)
class SecurityModule:
    """One entry in the sidebar / registry.

    ``check`` is async/callback-based (``check(on_result)``) for the same
    reason as :class:`ModuleAction`.``run`` — reads must never block the UI.
    """

    id: str
    title: str
    icon_name: str
    priority: Priority
    implemented: bool
    check: Optional[Callable[[Callable[[StatusReport], None]], None]] = None
    actions: tuple[ModuleAction, ...] = field(default_factory=tuple)
    not_implemented_reason: str = "In development — coming in a future update."
