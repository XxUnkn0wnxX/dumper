"""Local ownership tests for background full-auto processes; no UI or Android."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from Helpers import AutoProcesses as processes


ROOT = Path(__file__).resolve().parents[1]


class AutoProcessTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="auto-process-", dir=ROOT / ".tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.session = self.root / ".tmp" / "session"

    def wait_for(self, process, timeout=5):
        deadline = time.monotonic() + timeout
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIsNotNone(process.poll(), "process did not exit")
        return process.poll()

    def test_launch_records_private_metadata_and_actual_poll_status(self):
        owned = processes.launch_process(
            "dump", [sys.executable, "-c", "raise SystemExit(7)"], ROOT, self.session, {"AUTO_TEST": "1"},
        )
        self.assertEqual(self.wait_for(owned), 7)
        metadata = json.loads(owned.metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["role"], "dump")
        self.assertEqual(metadata["pid"], owned.process.pid)
        self.assertEqual(oct(owned.metadata_path.stat().st_mode & 0o777), "0o600")

    def test_requested_log_collects_raw_stdout_and_stderr_without_a_pipe(self):
        logs = self.root / "logs"
        logs.mkdir()
        log_path = logs / "dump.log"
        source = "import sys; sys.stdout.write('OUT\\n'); sys.stdout.flush(); sys.stderr.write('ERR\\n')"
        owned = processes.launch_process(
            "dump", [sys.executable, "-c", source], ROOT, self.session, {}, log_path=log_path,
        )
        self.assertEqual(self.wait_for(owned), 0)
        self.assertEqual(owned.log_path, log_path)
        self.assertEqual(log_path.read_bytes(), b"OUT\nERR\n")
        self.assertEqual(oct(log_path.stat().st_mode & 0o777), "0o600")

    def test_existing_log_is_safely_truncated_then_retained_after_close(self):
        log_path = self.root / "existing.log"
        log_path.write_text("old output", encoding="utf-8")
        owned = processes.launch_process(
            "dump", [sys.executable, "-c", "print('new output')"], ROOT, self.session, {}, log_path=log_path,
        )
        self.assertEqual(self.wait_for(owned), 0)
        self.assertTrue(owned.close())
        self.assertEqual(log_path.read_text(encoding="utf-8"), "new output\n")

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic-link support is unavailable")
    def test_symbolic_and_nonregular_logs_are_rejected_without_replacement(self):
        target = self.root / "target.log"
        target.write_text("target", encoding="utf-8")
        linked = self.root / "linked.log"
        linked.symlink_to(target)
        directory = self.root / "directory.log"
        directory.mkdir()
        for path in (linked, directory):
            with self.subTest(path=path), self.assertRaisesRegex(processes.ProcessError, "regular file|process log"):
                processes.launch_process(
                    "dump", [sys.executable, "-c", "pass"], ROOT, self.session, {}, log_path=path,
                )
        self.assertEqual(target.read_text(encoding="utf-8"), "target")

    @unittest.skipUnless(os.name == "posix", "POSIX group signalling requires POSIX")
    def test_close_interrupts_and_reaps_a_real_owned_posix_child(self):
        marker = self.root / "interrupted"
        source = (
            "from pathlib import Path; import signal, sys, time; "
            "signal.signal(signal.SIGINT, lambda *_: (Path(sys.argv[1]).write_text('yes'), sys.exit(0))[1]); "
            "time.sleep(60)"
        )
        owned = processes.launch_process(
            "frida", [sys.executable, "-c", source, str(marker)], ROOT, self.session, {},
        )
        time.sleep(0.1)
        self.assertTrue(owned.close())
        self.assertEqual(self.wait_for(owned), 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "yes")

    def test_metadata_write_failure_reaps_spawned_child_before_raising(self):
        created = []
        real_popen = subprocess.Popen

        def remember(*arguments, **keywords):
            child = real_popen(*arguments, **keywords)
            created.append(child)
            return child

        with mock.patch.object(processes.subprocess, "Popen", side_effect=remember), \
                mock.patch.object(processes, "_atomic_write_json", side_effect=processes.ProcessError("disk full")):
            with self.assertRaisesRegex(processes.ProcessError, "disk full"):
                processes.launch_process(
                    "frida", [sys.executable, "-c", "import time; time.sleep(60)"],
                    ROOT, self.session, {},
                )
        self.assertEqual(len(created), 1)
        self.assertIsNotNone(created[0].poll(), "metadata failure left a child running")

    def test_windows_uses_new_process_group_and_ctrl_break(self):
        fake = mock.Mock(pid=500)
        fake.poll.side_effect = [None, None]
        job = mock.Mock()
        with mock.patch.object(processes, "_platform_kind", return_value="windows"), \
                mock.patch.object(processes.subprocess, "Popen", return_value=fake) as popen, \
                mock.patch.object(processes, "_atomic_write_json"), \
                mock.patch.object(processes, "_WindowsJob", return_value=job), \
                mock.patch.object(processes, "_wait", return_value=True):
            owned = processes.launch_process("dump", ["python", "dump.py"], ROOT, self.session, {})
            self.assertTrue(owned.close())
        self.assertEqual(
            popen.call_args.kwargs["creationflags"],
            getattr(processes.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200),
        )
        fake.send_signal.assert_called_once_with(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGINT))
        job.assign.assert_called_once_with(fake)
        job.close.assert_called_once_with()

    def test_windows_job_assignment_precedes_worker_start_token(self):
        fake = mock.Mock(pid=502)
        fake.poll.return_value = None
        job = mock.Mock()
        events = []

        def record_write(path, value):
            events.append((path.name, dict(value)))

        with mock.patch.object(processes, "_platform_kind", return_value="windows"), \
                mock.patch.object(processes.subprocess, "Popen", return_value=fake) as popen, \
                mock.patch.object(processes, "_WindowsJob", return_value=job), \
                mock.patch.object(processes, "_atomic_write_json", side_effect=record_write):
            owned = processes.launch_process("frida", ["python", "setup.py"], ROOT, self.session, {})
        self.assertEqual(
            popen.call_args.args[0][:3], [sys.executable, "-m", "Helpers.AutoProcesses"],
        )
        job.assign.assert_called_once_with(fake)
        self.assertEqual(events[0][0], "frida.worker.json")
        self.assertEqual(events[1][0], "frida.worker-start.json")
        self.assertEqual(events[2][0], "frida.pid.json")
        self.assertEqual(events[1][1]["token"], events[0][1]["token"])
        with mock.patch.object(processes, "_stop_process", return_value=(True, None)), \
                mock.patch.object(processes, "_wait", return_value=True):
            self.assertTrue(owned.close())

    def test_windows_forced_leader_termination_reports_descendant_cleanup_gap(self):
        fake = mock.Mock(pid=501)
        fake.poll.return_value = None
        with mock.patch.object(processes, "_wait", side_effect=[False, True]):
            stopped, gap = processes._stop_process(fake, "windows")
        self.assertTrue(stopped)
        self.assertIn("not descendants", gap)
        fake.terminate.assert_called_once_with()

        owned = processes.OwnedProcess("dump", fake, self.session / "dump.pid.json", "windows", None)
        with mock.patch.object(processes, "_stop_process", return_value=(True, gap)):
            self.assertFalse(owned.close())
        self.assertEqual(owned.error, gap)

    def test_bounded_escalation_uses_only_the_held_process_group(self):
        fake = mock.Mock(pid=123)
        fake.poll.return_value = None
        with mock.patch.object(processes.os, "getpgid", return_value=123), \
                mock.patch.object(processes.os, "killpg") as kill_group, \
                mock.patch.object(processes, "_wait", side_effect=[False, False, True]):
            stopped, gap = processes._stop_process(fake, "posix")
        self.assertTrue(stopped)
        self.assertIsNone(gap)
        self.assertEqual(
            [call.args[1] for call in kill_group.call_args_list],
            [signal.SIGINT, signal.SIGTERM, signal.SIGKILL],
        )
        fake.send_signal.assert_not_called()

    def test_live_posix_group_after_leader_exit_is_reported_without_another_signal(self):
        fake = mock.Mock(pid=700)
        fake.poll.return_value = 0
        owned = processes.OwnedProcess("dump", fake, self.session / "dump.pid.json", "posix", None)
        with mock.patch.object(processes, "_stop_process", return_value=(True, None)), \
                mock.patch.object(processes.os, "killpg") as kill_group:
            self.assertFalse(owned.close())
        kill_group.assert_called_once_with(700, 0)
        self.assertIn("process group remains live", owned.error)

    def test_windows_job_active_process_wait_accepts_zero_and_rejects_timeout(self):
        processes._wait_for_no_active_processes(lambda: 0, timeout=0)
        with self.assertRaisesRegex(processes.ProcessError, "still has active"), \
                mock.patch.object(processes.time, "sleep"):
            processes._wait_for_no_active_processes(lambda: 1, timeout=0)


if __name__ == "__main__":
    unittest.main()
