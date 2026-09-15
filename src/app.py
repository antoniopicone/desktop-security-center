"""GApplication + main window (spec §2, §4).

Same architectural pattern as the validated screensaver-settings-app:
Adw.NavigationSplitView, a sidebar built from the module registry, and a
content pane rendering the selected module's live status + actions.
"""

from __future__ import annotations

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk  # noqa: E402

from models import Severity, StatusReport  # noqa: E402
from registry import build_registry  # noqa: E402

APP_ID = "it.antoniopicone.DesktopSecurityCenter"

_STATUS_DOT_CSS = """
.status-dot { border-radius: 9999px; background-color: @borders; }
.status-dot.success { background-color: @success_color; }
.status-dot.warning { background-color: @warning_color; }
.status-dot.error { background-color: @error_color; }
"""

_SEVERITY_CSS_CLASS = {
    Severity.OK: "success",
    Severity.WARNING: "warning",
    Severity.ERROR: "error",
    Severity.UNKNOWN: "dim-label",
}

_SEVERITY_ICON = {
    Severity.OK: "emblem-ok-symbolic",
    Severity.WARNING: "dialog-warning-symbolic",
    Severity.ERROR: "dialog-error-symbolic",
    Severity.UNKNOWN: "dialog-question-symbolic",
}


def _escape(text: str) -> str:
    """Escape text bound for a Pango-markup-consuming widget property.

    Several Adwaita widgets (StatusPage description, NavigationPage
    title, ActionRow title/subtitle, PreferencesGroup title/description)
    interpret their text as markup, and several of our own labels — and
    live system data like an SSID — can legitimately contain "&"/"<".
    """
    return GLib.markup_escape_text(text)


class StatusDot(Gtk.Box):
    """A small coloured dot used as the sidebar's at-a-glance status indicator."""

    def __init__(self) -> None:
        super().__init__()
        self._dot = Gtk.Box(width_request=10, height_request=10)
        self._dot.add_css_class("status-dot")
        self.append(self._dot)
        self.set_severity(Severity.UNKNOWN)

    def set_severity(self, severity: Severity) -> None:
        for css_class in _SEVERITY_CSS_CLASS.values():
            self._dot.remove_css_class(css_class)
        self._dot.add_css_class(_SEVERITY_CSS_CLASS[severity])


class ModuleRow(Gtk.ListBoxRow):
    def __init__(self, module) -> None:
        super().__init__()
        self.module = module

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, margin_top=8, margin_bottom=8, margin_start=12, margin_end=12)
        box.append(Gtk.Image.new_from_icon_name(module.icon_name))
        box.append(Gtk.Label(label=module.title, hexpand=True, xalign=0))
        self.status_dot = StatusDot()
        box.append(self.status_dot)
        self.set_child(box)


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app: "Application") -> None:
        super().__init__(application=app, title="Desktop Security Center", default_width=880, default_height=620)

        self.modules = build_registry()
        self._rows_by_id: dict[str, ModuleRow] = {}
        self._findings_groups: dict[str, Adw.PreferencesGroup] = {}
        self._findings_group_children: dict[str, list[Gtk.Widget]] = {}

        self.split_view = Adw.NavigationSplitView()
        self.toast_overlay = Adw.ToastOverlay(child=self.split_view)
        self.set_content(self.toast_overlay)

        self.split_view.set_sidebar(self._build_sidebar())
        self.split_view.set_content(self._build_content_placeholder())

        if self.modules:
            self._select_module(self.modules[0].id)

    # -- sidebar -----------------------------------------------------

    def _build_sidebar(self) -> Adw.NavigationPage:
        listbox = Gtk.ListBox(css_classes=["navigation-sidebar"])
        listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)

        for module in self.modules:
            row = ModuleRow(module)
            self._rows_by_id[module.id] = row
            listbox.append(row)

        listbox.connect("row-selected", self._on_row_selected)
        self.sidebar_listbox = listbox

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar())
        toolbar_view.set_content(Gtk.ScrolledWindow(child=listbox, vexpand=True))

        return Adw.NavigationPage(title="Desktop Security Center", child=toolbar_view)

    def _on_row_selected(self, _listbox: Gtk.ListBox, row: ModuleRow | None) -> None:
        if row is not None:
            self._select_module(row.module.id)

    # -- content -------------------------------------------------------

    def _build_content_placeholder(self) -> Adw.NavigationPage:
        self.content_stack = Gtk.Stack()
        toolbar_view = Adw.ToolbarView()
        header = Adw.HeaderBar()

        self.refresh_button = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh")
        self.refresh_button.connect("clicked", self._on_refresh_clicked)
        header.pack_end(self.refresh_button)

        toolbar_view.add_top_bar(header)
        toolbar_view.set_content(self.content_stack)

        self.content_page = Adw.NavigationPage(title="Module", child=toolbar_view)
        return self.content_page

    def _select_module(self, module_id: str) -> None:
        self.current_module_id = module_id
        module = next(m for m in self.modules if m.id == module_id)
        self.content_page.set_title(_escape(module.title))

        # Build each module's page exactly once and reuse it: refreshing
        # updates the existing PreferencesGroup's rows in place, it never
        # rebuilds the group (rebuilding while a check is in flight would
        # orphan the rows a pending callback is about to try to remove).
        if self.content_stack.get_child_by_name(module_id) is None:
            page = self._build_module_page(module)
            self.content_stack.add_named(page, module_id)

        self.content_stack.set_visible_child_name(module_id)

        if module.implemented:
            self._refresh_module(module)

    def _build_module_page(self, module) -> Gtk.Widget:
        if not module.implemented:
            description = (
                f"{module.title} is on the roadmap ({module.priority.value}) — {module.not_implemented_reason}"
            )
            status_page = Adw.StatusPage(
                icon_name="applications-development-symbolic",
                title="In development",
                description=_escape(description),
            )
            return status_page

        scrolled = Gtk.ScrolledWindow(vexpand=True)
        clamp = Adw.Clamp(maximum_size=700, margin_top=24, margin_bottom=24, margin_start=12, margin_end=12)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        clamp.set_child(box)
        scrolled.set_child(clamp)

        group = Adw.PreferencesGroup(title=_escape(module.title))
        box.append(group)
        self._findings_groups[module.id] = group
        self._findings_group_children[module.id] = []

        if module.actions:
            actions_group = Adw.PreferencesGroup(title="Actions")
            box.append(actions_group)
            for action in module.actions:
                row = Adw.ActionRow(title=_escape(action.label), subtitle=_escape(action.description))
                button = Gtk.Button(
                    label="Run" if not action.requires_privilege else "Authenticate & Run",
                    valign=Gtk.Align.CENTER,
                    sensitive=action.enabled,
                    css_classes=["suggested-action"] if action.enabled else [],
                )
                if action.enabled and action.run is not None:
                    button.connect("clicked", self._on_action_clicked, module, action)
                row.add_suffix(button)
                actions_group.add(row)

        return scrolled

    # -- refresh ---------------------------------------------------------

    def _on_refresh_clicked(self, _button: Gtk.Button) -> None:
        module = next(m for m in self.modules if m.id == self.current_module_id)
        if module.implemented:
            self._refresh_module(module)

    def _refresh_module(self, module) -> None:
        self.refresh_button.set_sensitive(False)

        def on_result(report: StatusReport) -> None:
            self.refresh_button.set_sensitive(True)
            self._render_report(module, report)

        module.check(on_result)

    def _render_report(self, module, report: StatusReport) -> None:
        row = self._rows_by_id.get(module.id)
        if row is not None:
            row.status_dot.set_severity(report.severity)

        group = self._findings_groups.get(module.id)
        if group is None:
            return

        # AdwPreferencesGroup tracks its own added children separately from
        # the raw widget tree, so only remove widgets we ourselves added.
        for widget in self._findings_group_children.get(module.id, []):
            group.remove(widget)
        added_widgets: list[Gtk.Widget] = []

        group.set_description(_escape(report.summary))

        for error in report.errors:
            banner = Adw.Banner(title=_escape(error), revealed=True)
            group.add(banner)
            added_widgets.append(banner)

        for finding in report.findings:
            row_widget = Adw.ActionRow(title=_escape(finding.label), subtitle=_escape(finding.detail or ""))
            value_label = Gtk.Label(label=finding.value, css_classes=[_SEVERITY_CSS_CLASS[finding.severity]])
            row_widget.add_suffix(value_label)
            group.add(row_widget)
            added_widgets.append(row_widget)

        self._findings_group_children[module.id] = added_widgets

    # -- actions -----------------------------------------------------

    def _on_action_clicked(self, button: Gtk.Button, module, action) -> None:
        button.set_sensitive(False)

        def on_result(result) -> None:
            button.set_sensitive(True)
            toast_text = result.message
            toast = Adw.Toast(title=toast_text, timeout=4)
            self.toast_overlay.add_toast(toast)
            if result.success:
                self._refresh_module(module)

        action.run(on_result)


class Application(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID)
        self.window: MainWindow | None = None

    def do_startup(self) -> None:  # noqa: D102
        Adw.Application.do_startup(self)
        provider = Gtk.CssProvider()
        provider.load_from_string(_STATUS_DOT_CSS)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

    def do_activate(self) -> None:  # noqa: D102
        if self.window is None:
            self.window = MainWindow(self)
        self.window.present()


def main() -> int:
    app = Application()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
