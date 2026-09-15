"""TDD tests for registry.py — the single place adding a category is wired (spec §2)."""

from command_runner import CommandResult
from models import Priority, Severity
from registry import HELPER_PATH, build_registry

EXPECTED_MODULE_IDS = {
    "firewall",
    "remote_access",
    "network_wifi",
    "auth_accounts",
    "updates",
    "backup",
    "hardware_peripherals",
    "app_permissions",
    "privacy",
}


class TestBuildRegistry:
    def test_has_all_nine_categories(self):
        modules = build_registry()
        assert {m.id for m in modules} == EXPECTED_MODULE_IDS

    def test_p0_modules_are_implemented(self):
        modules = {m.id: m for m in build_registry()}
        for module_id in ("firewall", "remote_access", "network_wifi"):
            assert modules[module_id].implemented is True
            assert modules[module_id].priority == Priority.P0
            assert modules[module_id].check is not None

    def test_every_module_is_now_implemented(self):
        modules = build_registry()
        assert all(m.implemented for m in modules)
        assert all(m.check is not None for m in modules)

    def test_priorities_match_spec(self):
        modules = {m.id: m for m in build_registry()}
        expected = {
            "firewall": Priority.P0,
            "remote_access": Priority.P0,
            "network_wifi": Priority.P0,
            "auth_accounts": Priority.P1,
            "updates": Priority.P1,
            "backup": Priority.P2,
            "hardware_peripherals": Priority.P1,
            "app_permissions": Priority.P2,
            "privacy": Priority.P2,
        }
        for module_id, priority in expected.items():
            assert modules[module_id].priority == priority

    def test_ids_are_unique(self):
        modules = build_registry()
        ids = [m.id for m in modules]
        assert len(ids) == len(set(ids))


class TestFirewallEnableAction:
    def test_enable_ufw_action_is_present_and_privileged(self):
        modules = {m.id: m for m in build_registry()}
        firewall = modules["firewall"]
        action = next(a for a in firewall.actions if a.id == "enable-ufw")
        assert action.requires_privilege is True
        assert action.enabled is True

    def test_running_it_invokes_pkexec_with_the_helper_and_subcommand(self):
        captured = {}

        def fake_run_command(argv, callback):
            captured["argv"] = argv
            callback(CommandResult(returncode=0, stdout="", stderr=""))

        modules = {m.id: m for m in build_registry(run_command=fake_run_command)}
        action = next(a for a in modules["firewall"].actions if a.id == "enable-ufw")

        results = []
        action.run(results.append)

        assert captured["argv"] == ["pkexec", HELPER_PATH, "ufw-enable"]
        assert results[0].success is True

    def test_action_failure_is_reported(self):
        def fake_run_command(argv, callback):
            callback(CommandResult(returncode=1, stdout="", stderr="Authentication failed"))

        modules = {m.id: m for m in build_registry(run_command=fake_run_command)}
        action = next(a for a in modules["firewall"].actions if a.id == "enable-ufw")

        results = []
        action.run(results.append)

        assert results[0].success is False
        assert "Authentication failed" in results[0].message

    def test_disable_and_rule_actions_are_present_but_disabled_for_now(self):
        modules = {m.id: m for m in build_registry()}
        actions_by_id = {a.id: a for a in modules["firewall"].actions}
        assert actions_by_id["disable-ufw"].enabled is False
        assert actions_by_id["add-rule"].enabled is False


class TestFirewallCheck:
    def test_check_delegates_to_module_refresh(self):
        def fake_run_many(argvs, callback):
            callback([CommandResult(0, "Status: active\n", ""), CommandResult(0, "", ""), CommandResult(0, "", "")])

        modules = {m.id: m for m in build_registry(run_many=fake_run_many)}
        reports = []
        modules["firewall"].check(reports.append)

        assert reports[0].severity == Severity.OK
