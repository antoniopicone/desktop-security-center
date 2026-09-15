"""TDD tests for the Wi-Fi / local network module (spec §3.3)."""

from command_runner import CommandResult
from modules.network_wifi import (
    ActiveWifi,
    WifiConnection,
    build_status_report,
    classify_security,
    key_mgmt_to_security,
    parse_active_wifi,
    parse_bluetooth_discoverable,
    parse_key_mgmt,
    parse_wifi_connection_names,
    refresh,
)
from models import Severity

ACTIVE_WIFI_LINE = "yes:HomeNet:WPA2\n" "no:Neighbour:WPA2\n"

ACTIVE_WIFI_OPEN = "yes:CoffeeShop:\n"

CONNECTION_SHOW = (
    "HomeNet:802-11-wireless\n" "Neighbour:802-11-wireless\n" "Wired connection 1:802-3-ethernet\n"
)

BLUETOOTH_SHOW_DISCOVERABLE = "Controller AA:BB Alias: laptop\n" "\tDiscoverable: yes\n" "\tPairable: yes\n"

BLUETOOTH_SHOW_HIDDEN = "Controller AA:BB Alias: laptop\n" "\tDiscoverable: no\n"


class TestParseActiveWifi:
    def test_finds_the_active_network(self):
        wifi = parse_active_wifi(ACTIVE_WIFI_LINE)
        assert wifi == ActiveWifi(ssid="HomeNet", security="WPA2")

    def test_no_active_network_returns_none(self):
        assert parse_active_wifi("no:Neighbour:WPA2\n") is None

    def test_empty_security_means_open_network(self):
        wifi = parse_active_wifi(ACTIVE_WIFI_OPEN)
        assert wifi == ActiveWifi(ssid="CoffeeShop", security="")

    def test_empty_input_returns_none(self):
        assert parse_active_wifi("") is None


class TestClassifySecurity:
    def test_empty_string_is_open(self):
        assert classify_security("") == "Open"

    def test_wep_is_flagged_weak(self):
        assert classify_security("WEP") == "WEP"

    def test_wpa2_is_not_weak(self):
        assert classify_security("WPA2") == "WPA2"

    def test_wpa3_is_not_weak(self):
        assert classify_security("WPA3") == "WPA3"


class TestParseWifiConnectionNames:
    def test_only_wifi_type_connections_are_returned(self):
        names = parse_wifi_connection_names(CONNECTION_SHOW)
        assert names == ["HomeNet", "Neighbour"]

    def test_ethernet_is_excluded(self):
        names = parse_wifi_connection_names(CONNECTION_SHOW)
        assert "Wired connection 1" not in names

    def test_empty_input_returns_no_connections(self):
        assert parse_wifi_connection_names("") == []


class TestParseBluetoothDiscoverable:
    def test_discoverable_yes(self):
        assert parse_bluetooth_discoverable(BLUETOOTH_SHOW_DISCOVERABLE) is True

    def test_discoverable_no(self):
        assert parse_bluetooth_discoverable(BLUETOOTH_SHOW_HIDDEN) is False

    def test_missing_field_defaults_to_false(self):
        assert parse_bluetooth_discoverable("Controller AA:BB\n") is False


class TestBuildStatusReport:
    def test_nm_unavailable_is_an_error(self):
        report = build_status_report(
            nm_available=False, active_wifi=None, weak_profiles=[], bluetooth_discoverable=False
        )
        assert report.severity == Severity.ERROR

    def test_open_active_network_is_a_warning(self):
        report = build_status_report(
            nm_available=True,
            active_wifi=ActiveWifi(ssid="CoffeeShop", security=""),
            weak_profiles=[],
            bluetooth_discoverable=False,
        )
        assert report.severity == Severity.WARNING

    def test_secure_active_network_is_ok(self):
        report = build_status_report(
            nm_available=True,
            active_wifi=ActiveWifi(ssid="HomeNet", security="WPA2"),
            weak_profiles=[],
            bluetooth_discoverable=False,
        )
        assert report.severity == Severity.OK

    def test_weak_saved_profile_is_a_warning(self):
        report = build_status_report(
            nm_available=True,
            active_wifi=ActiveWifi(ssid="HomeNet", security="WPA2"),
            weak_profiles=[WifiConnection(name="OldRouter", security="WEP")],
            bluetooth_discoverable=False,
        )
        assert report.severity == Severity.WARNING
        assert any("OldRouter" in f.value for f in report.findings)

    def test_bluetooth_discoverable_is_a_warning(self):
        report = build_status_report(
            nm_available=True, active_wifi=None, weak_profiles=[], bluetooth_discoverable=True
        )
        assert report.severity == Severity.WARNING

    def test_all_clear_is_ok(self):
        report = build_status_report(
            nm_available=True, active_wifi=None, weak_profiles=[], bluetooth_discoverable=False
        )
        assert report.severity == Severity.OK


class TestParseKeyMgmt:
    def test_extracts_key_mgmt_value(self):
        text = "802-11-wireless-security.key-mgmt:wpa-psk\n"
        assert parse_key_mgmt(text) == "wpa-psk"

    def test_missing_field_is_empty(self):
        assert parse_key_mgmt("") == ""


class TestKeyMgmtToSecurity:
    def test_wpa_psk_is_wpa2(self):
        assert key_mgmt_to_security("wpa-psk") == "WPA2"

    def test_sae_is_wpa3(self):
        assert key_mgmt_to_security("sae") == "WPA3"

    def test_none_is_wep(self):
        assert key_mgmt_to_security("none") == "WEP"

    def test_empty_is_open(self):
        assert key_mgmt_to_security("") == ""


class TestRefresh:
    def test_nm_unavailable_short_circuits_without_second_phase(self):
        calls = []

        def fake_run_many(argvs, callback):
            calls.append(argvs)
            callback([CommandResult(3, "", ""), CommandResult(0, "", ""), CommandResult(0, "", ""), CommandResult(0, "", "")])

        reports = []
        refresh(reports.append, run_many=fake_run_many)

        assert reports[0].severity == Severity.ERROR
        assert len(calls) == 1  # no per-connection follow-up when NM is down

    def test_weak_saved_profile_detected_via_second_phase(self):
        call_count = [0]

        def fake_run_many(argvs, callback):
            call_count[0] += 1
            if call_count[0] == 1:
                callback(
                    [
                        CommandResult(0, "", ""),  # NetworkManager active
                        CommandResult(0, "yes:HomeNet:WPA2\n", ""),  # active wifi
                        CommandResult(0, "HomeNet:802-11-wireless\nOldRouter:802-11-wireless\n", ""),
                        CommandResult(0, "Discoverable: no\n", ""),
                    ]
                )
            else:
                # one nmcli connection-show call per wifi connection name
                assert len(argvs) == 2
                callback(
                    [
                        CommandResult(0, "802-11-wireless-security.key-mgmt:wpa-psk\n", ""),
                        CommandResult(0, "802-11-wireless-security.key-mgmt:none\n", ""),
                    ]
                )

        reports = []
        refresh(reports.append, run_many=fake_run_many)

        assert call_count[0] == 2
        assert reports[0].severity == Severity.WARNING
        assert any("OldRouter" in f.value for f in reports[0].findings)
