"""Synthetic fork failures must not continue the inherited test suite."""
import os
import select
import signal
import unittest
from tests.s8_fork_child import child_failure_boundary


@unittest.skipUnless(hasattr(os, "fork"), "fork required")
class ChildBoundaryTests(unittest.TestCase):
    def exercise(self, action, expected):
        reader, writer = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(reader)
            with child_failure_boundary():
                action()
            os.write(writer, b"inherited-suite-continued")
            os._exit(0)
        os.close(writer)
        reaped = False
        try:
            self.assertTrue(select.select([reader], [], [], 5)[0], "child deadline")
            self.assertEqual(os.read(reader, 128), b"")
            status = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
            reaped = True
            self.assertEqual(status, expected)
        finally:
            os.close(reader)
            if not reaped:
                try: os.kill(pid, signal.SIGKILL)
                except ProcessLookupError: pass
                os.waitpid(pid, 0)

    def test_unexpected_exceptions_cannot_escape_to_unittest(self):
        for error in (RuntimeError("synthetic"), AssertionError("synthetic"),
                      SystemExit(0), KeyboardInterrupt()):
            with self.subTest(kind=type(error).__name__):
                def fail(): raise error
                self.exercise(fail, 99)

    def test_intended_exit_codes_are_unchanged(self):
        for code in (0, 3, 77):
            with self.subTest(code=code):
                self.exercise(lambda: os._exit(code), code)

    def test_accidental_return_is_failure(self):
        self.exercise(lambda: None, 98)


if __name__ == "__main__": unittest.main()
