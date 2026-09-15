"""TDD tests for command_runner.py.

Pure argv-building is unit tested directly. The actual Gio.Subprocess
async wrapper is exercised with one lightweight integration test that
runs harmless real commands (`echo`, `false`) through a real GLib main
loop — never anything privileged or state-changing.
"""

from command_runner import build_pkexec_argv, run_command_async, run_many_async


class TestBuildPkexecArgv:
    def test_builds_expected_argv(self):
        assert build_pkexec_argv("/opt/app/helper", "ufw-enable") == [
            "pkexec",
            "/opt/app/helper",
            "ufw-enable",
        ]

    def test_never_invokes_a_shell(self):
        argv = build_pkexec_argv("/opt/app/helper", "ufw-enable")
        assert "sh" not in argv and "-c" not in argv


class TestRunCommandAsync:
    def test_successful_command_reports_stdout(self):
        results = []
        loop_ran = _run_until_called(["echo", "-n", "hello"], results)
        assert loop_ran
        assert results[0].returncode == 0
        assert results[0].stdout == "hello"

    def test_failing_command_reports_nonzero_returncode(self):
        results = []
        _run_until_called(["false"], results)
        assert results[0].returncode != 0

    def test_missing_binary_does_not_raise(self):
        results = []
        _run_until_called(["definitely-not-a-real-binary-xyz"], results)
        assert results[0].returncode != 0


class TestRunManyAsync:
    def test_empty_list_calls_back_immediately_with_empty_list(self):
        results = []
        run_many_async([], results.append)
        assert results == [[]]

    def test_results_preserve_input_order(self):
        from gi.repository import GLib

        loop = GLib.MainLoop()
        captured = []

        def on_done(results):
            captured.append(results)
            loop.quit()

        run_many_async([["echo", "-n", "one"], ["echo", "-n", "two"]], on_done)
        GLib.timeout_add_seconds(5, loop.quit)
        loop.run()

        assert [r.stdout for r in captured[0]] == ["one", "two"]


def _run_until_called(argv, results):
    from gi.repository import GLib

    loop = GLib.MainLoop()

    def on_done(result):
        results.append(result)
        loop.quit()

    run_command_async(argv, on_done)
    GLib.timeout_add_seconds(5, loop.quit)
    loop.run()
    return bool(results)
