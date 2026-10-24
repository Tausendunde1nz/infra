"""Synthetic contracts for the finite profile measurement, no Linux privileges."""
import os
import struct
import unittest
from unittest.mock import Mock, patch
from tests import s8_fileattr_profile_probe as probe


class ProfileProbeTests(unittest.TestCase):
    def test_each_profile_requires_a_real_calibrated_metadata_event(self):
        good = {"mask": "0x4", "name": "control.json"}
        probe.require_control_events([good])
        probe.require_control_events([good, good])  # either coalesced or separate
        for bad in ([], [{"mask": "0x4000", "name": ""}],
                    [{"mask": "0x8000", "name": ""}],
                    [{"mask": "0x4", "name": "other.json"}],
                    [good, {"malformed": True}]):
            with self.assertRaisesRegex(RuntimeError, "S8_PROFILE_CONTROL_NOT_OBSERVED"):
                probe.require_control_events(bad)

    def test_sample_reads_only_its_listener_once_and_does_not_infer_an_actor(self):
        raw = struct.pack("iIII", 1, 4, 0, 8) + b"record\0\0"
        trace = Mock()
        with patch.object(probe.os, "read", return_value=raw) as read:
            probe.sample(trace, 9, "immutable_record")
        read.assert_called_once_with(9, 65536)
        event = trace.note.call_args.kwargs["events"][0]
        self.assertEqual(event["mask"], "0x4")
        self.assertEqual(event["event_actor"], "not_in_inotify")

    def test_sample_does_not_retry_eagain_or_hide_other_io_errors(self):
        trace = Mock()
        with patch.object(probe.os, "read", side_effect=BlockingIOError()) as read:
            probe.sample(trace, 9, "before_record_seal")
        read.assert_called_once_with(9, 65536)
        self.assertTrue(trace.note.call_args.kwargs["eagain"])
        error = OSError(5, "synthetic")
        with patch.object(probe.os, "read", side_effect=error) as read:
            with self.assertRaises(OSError) as result: probe.sample(trace, 9, "seal")
        self.assertIs(result.exception, error)
        read.assert_called_once_with(9, 65536)

    def test_one_pair_before_original_suite_and_original_red_remains_red(self):
        with patch.object(probe.sys, "platform", "linux"), \
             patch.object(probe.os, "geteuid", return_value=0), \
             patch.dict(os.environ, {"container": "docker"}), \
             patch.object(probe.Path, "is_file", return_value=True), \
             patch.object(probe.Path, "read_text", return_value="systemd\n"), \
             patch.object(probe.signal, "alarm") as alarm, \
             patch.object(probe, "probe") as measure, \
             patch.object(probe, "guard_measurement", return_value=1) as guards:
            self.assertEqual(probe.main(), 1)
        alarm.assert_called_once_with(90)
        self.assertEqual([str(c.args[0]) for c in measure.call_args_list],
                         ["/var/tmp", "/s8-native-profile"])
        guards.assert_called_once_with(probe.MEASUREMENT)


if __name__ == "__main__": unittest.main()
