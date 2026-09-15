"""TDD tests for the pkexec helper (spec §5) — fixed subcommand allowlist, never eval."""

import pytest
from helper_core import ALLOWED_SUBCOMMANDS, HelperError, build_command, main


class TestBuildCommand:
    def test_ufw_enable_maps_to_expected_argv(self):
        assert build_command("ufw-enable", []) == ["ufw", "--force", "enable"]

    def test_ufw_disable_maps_to_expected_argv(self):
        assert build_command("ufw-disable", []) == ["ufw", "disable"]

    def test_unknown_subcommand_is_rejected(self):
        with pytest.raises(HelperError):
            build_command("rm -rf /", [])

    def test_extra_arguments_are_rejected(self):
        with pytest.raises(HelperError):
            build_command("ufw-enable", ["; rm -rf /"])

    def test_every_allowed_subcommand_has_no_shell_metacharacters(self):
        for argv in ALLOWED_SUBCOMMANDS.values():
            for token in argv:
                assert ";" not in token and "|" not in token and "&" not in token


class TestMain:
    def test_no_subcommand_returns_nonzero(self):
        assert main([], runner=lambda argv: 0) != 0

    def test_unknown_subcommand_returns_nonzero_without_running_anything(self):
        calls = []
        assert main(["not-a-real-command"], runner=lambda argv: calls.append(argv) or 0) != 0
        assert calls == []

    def test_known_subcommand_invokes_runner_with_exact_argv(self):
        calls = []

        def fake_runner(argv):
            calls.append(argv)
            return 0

        exit_code = main(["ufw-enable"], runner=fake_runner)
        assert exit_code == 0
        assert calls == [["ufw", "--force", "enable"]]

    def test_runner_failure_propagates_exit_code(self):
        exit_code = main(["ufw-enable"], runner=lambda argv: 1)
        assert exit_code == 1
