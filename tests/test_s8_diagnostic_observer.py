"""The observer must delegate once and preserve bytes/errors and guard results."""
import io
import struct
import unittest
from unittest.mock import Mock, patch
from tests.s8_diagnostic_once import Trace, decode_events


class ObserverTests(unittest.TestCase):
    def test_read_returns_exact_original_object_without_an_extra_read(self):
        trace = Trace(); raw = struct.pack("iIII", 1, 0x4, 0, 4) + b"x\0\0\0"
        trace.read = Mock(return_value=raw)
        with patch.object(trace, "is_inotify", return_value=True), patch("sys.stdout", new=io.StringIO()):
            self.assertIs(trace.observed_read(3, 65536), raw)
        trace.read.assert_called_once_with(3, 65536)
        self.assertEqual(decode_events(raw)[0]["mask"], "0x4")
        self.assertEqual(decode_events(raw)[0]["event_actor"], "not_in_inotify")

    def test_nonblocking_exception_is_not_replaced_or_retried(self):
        trace = Trace(); error = BlockingIOError(); trace.read = Mock(side_effect=error)
        with patch.object(trace, "is_inotify", return_value=True), patch("sys.stdout", new=io.StringIO()):
            with self.assertRaises(BlockingIOError) as result: trace.observed_read(4, 65536)
        self.assertIs(result.exception, error); trace.read.assert_called_once_with(4, 65536)

    def test_guard_exception_and_success_preserved(self):
        trace = Trace(); target = Mock(events=3, root="/synthetic")
        for error in (None, ValueError("synthetic")):
            original = Mock(return_value=object(), side_effect=error)
            with patch("sys.stdout", new=io.StringIO()):
                if error is None:
                    self.assertIs(trace.checked(original, "journal")(target), original.return_value)
                else:
                    with self.assertRaises(ValueError) as result:
                        trace.checked(original, "journal")(target)
                    self.assertIs(result.exception, error)
            original.assert_called_once_with(target)

    def test_ioctl_fsync_close_delegate_once_and_do_not_retain_fd_labels(self):
        from tests.s8_diagnostic_once import fence
        trace = Trace(); trace.ioctl = Mock(return_value=12)
        trace.fsync = Mock(return_value=None); trace.close = Mock(return_value=None)
        value = [0x80010]; trace.watches[9] = dict(root="/synthetic")
        with patch.object(trace, "identity", return_value=dict(fd=9)), patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(trace.observed_ioctl(9, fence.SET_FLAGS, value), 12)
            self.assertIsNone(trace.observed_fsync(9))
            self.assertIsNone(trace.observed_close(9))
        trace.ioctl.assert_called_once_with(9, fence.SET_FLAGS, value)
        trace.fsync.assert_called_once_with(9); trace.close.assert_called_once_with(9)
        self.assertNotIn(9, trace.watches)


if __name__ == "__main__": unittest.main()
