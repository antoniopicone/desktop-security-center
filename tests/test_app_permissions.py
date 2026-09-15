"""TDD tests for the App permissions & software surface module (spec §3.8)."""

from command_runner import CommandResult
from modules.app_permissions import (
    RISKY_FLATPAK_PERMISSIONS,
    build_status_report,
    list_autostart_entries,
    parse_flatpak_apps,
    parse_flatpak_permissions,
    parse_snap_connections,
    refresh,
)
from models import Severity

FLATPAK_LIST = "org.mozilla.firefox\ncom.spotify.Client\n"

FLATPAK_PERMISSIONS_RISKY = (
    "[Context]\n" "shared=network;\n" "sockets=x11;wayland;\n" "filesystems=home;\n"
)

FLATPAK_PERMISSIONS_SAFE = "[Context]\nshared=network;\nsockets=wayland;\n"

SNAP_CONNECTIONS = (
    "Interface  Plug                  Slot                 Notes\n"
    "home       spotify:home          :home                manual\n"
    "network    spotify:network       :network              -\n"
)


class TestParseFlatpakApps:
    def test_parses_app_ids(self):
        assert parse_flatpak_apps(FLATPAK_LIST) == ["org.mozilla.firefox", "com.spotify.Client"]

    def test_empty_output_returns_no_apps(self):
        assert parse_flatpak_apps("") == []


class TestParseFlatpakPermissions:
    def test_detects_risky_permissions(self):
        risky = parse_flatpak_permissions(FLATPAK_PERMISSIONS_RISKY)
        assert "filesystem=home" in risky
        assert "socket=x11" in risky

    def test_safe_config_has_no_risky_permissions(self):
        assert parse_flatpak_permissions(FLATPAK_PERMISSIONS_SAFE) == []

    def test_every_risky_permission_is_in_the_whitelist(self):
        risky = parse_flatpak_permissions(FLATPAK_PERMISSIONS_RISKY)
        assert set(risky).issubset(RISKY_FLATPAK_PERMISSIONS)


class TestParseSnapConnections:
    def test_parses_interface_names(self):
        interfaces = parse_snap_connections(SNAP_CONNECTIONS)
        assert "home" in interfaces
        assert "network" in interfaces

    def test_header_is_excluded(self):
        interfaces = parse_snap_connections(SNAP_CONNECTIONS)
        assert "Interface" not in interfaces


class TestListAutostartEntries:
    def test_lists_desktop_files(self, tmp_path):
        autostart_dir = tmp_path / "autostart"
        autostart_dir.mkdir()
        (autostart_dir / "howdy.desktop").write_text("[Desktop Entry]\nNoDisplay=true\n")
        (autostart_dir / "visible-app.desktop").write_text("[Desktop Entry]\nName=Visible\n")

        entries = list_autostart_entries(autostart_dir=str(autostart_dir))

        names = {e.filename for e in entries}
        assert names == {"howdy.desktop", "visible-app.desktop"}

    def test_no_display_flag_is_detected(self, tmp_path):
        autostart_dir = tmp_path / "autostart"
        autostart_dir.mkdir()
        (autostart_dir / "hidden.desktop").write_text("[Desktop Entry]\nNoDisplay=true\n")

        entries = list_autostart_entries(autostart_dir=str(autostart_dir))
        assert entries[0].no_display is True

    def test_missing_directory_returns_no_entries(self, tmp_path):
        assert list_autostart_entries(autostart_dir=str(tmp_path / "does-not-exist")) == []


class TestBuildStatusReport:
    def test_no_risky_permissions_is_ok(self):
        report = build_status_report(risky_flatpaks={}, snap_interfaces=[], autostart_entries=[])
        assert report.severity == Severity.OK

    def test_risky_flatpak_permission_is_a_warning(self):
        report = build_status_report(
            risky_flatpaks={"com.spotify.Client": ["filesystem=home"]}, snap_interfaces=[], autostart_entries=[]
        )
        assert report.severity == Severity.WARNING
        assert any("com.spotify.Client" in f.value for f in report.findings)


class TestRefresh:
    def test_two_phase_fetch_flags_risky_app(self):
        call_count = [0]

        def fake_run_many(argvs, callback):
            call_count[0] += 1
            if call_count[0] == 1:
                callback([CommandResult(0, FLATPAK_LIST, ""), CommandResult(0, SNAP_CONNECTIONS, "")])
            else:
                assert len(argvs) == 2
                callback([CommandResult(0, FLATPAK_PERMISSIONS_RISKY, ""), CommandResult(0, FLATPAK_PERMISSIONS_SAFE, "")])

        reports = []
        refresh(reports.append, run_many=fake_run_many)

        assert call_count[0] == 2
        assert reports[0].severity == Severity.WARNING
        assert any("org.mozilla.firefox" in f.value for f in reports[0].findings)
