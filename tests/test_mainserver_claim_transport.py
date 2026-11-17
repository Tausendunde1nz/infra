"""Synthetic local transport/projection tests; no SSH, sudo or real password."""
import io
import json
import subprocess
import sys
import unittest
from unittest import mock

from scripts import tu1nz_mainserver_claim_transport as transport


class TransportTests(unittest.TestCase):
    def test_visible_password_fallback_aborts_before_input_intent_or_ssh(self):
        def fallback(*_args, **_kwargs):
            return transport.getpass.fallback_getpass(stream=io.StringIO())
        with mock.patch.object(transport, 'validate', return_value=('scope', 'review', b'synthetic', {})), \
             mock.patch.object(transport.resource, 'setrlimit'), \
             mock.patch.object(transport.sys.stdin, 'isatty', return_value=True), \
             mock.patch.object(transport.getpass, 'getpass', side_effect=fallback), \
             mock.patch.object(transport.getpass, '_raw_input') as ordinary_input, \
             mock.patch.object(transport, 'paired_create') as records, \
             mock.patch.object(transport.subprocess, 'Popen') as ssh, \
             mock.patch('builtins.print'):
            with self.assertRaises(transport.getpass.GetPassWarning):
                transport.main()
            ordinary_input.assert_not_called()
            records.assert_not_called()
            ssh.assert_not_called()

    def report(self):
        return {'schema': 'TU1NZ_MAIN_SERVER_R4_EARLY_CLAIM_READ_V1',
                'transaction': 'public-rights-20261014-1',
                'machine_sha256': 'a2166d9d5e0815dc5e452be3d01a1356f4d39e2164446274a43cde5afa7d8aae',
                'boot_id': '00000000-0000-0000-0000-000000000000',
                'namespaces': {name: name+':[123]' for name in ('mnt', 'pid', 'user')},
                'targets': {'/etc/claim': {'state': 'ABSENT', 'first_absent_component': '/etc/claim',
                                          'held_parent': '/etc'}},
                'observed_ancestors': {}, 'result': 'NECESSARY_ABSENCES_OBSERVED',
                'limits': 'METADATA_ONLY_POINT_OBSERVATION_NOT_WRITER_EXCLUSION_OR_EXECUTION_ADMISSION'}

    def test_valid_finite_projection(self):
        report = self.report()
        self.assertEqual(transport.project_report(report, ['/etc/claim']), report)

    def test_extra_fields_and_unknown_paths_cannot_be_saved(self):
        for key, value in (('secret', 'synthetic'), ('observed_ancestors', {'/unrelated': {}}),
                           ('namespaces', {'other': 'text'})):
            report = self.report(); report[key] = value
            with self.assertRaises((RuntimeError, TypeError)):
                transport.project_report(report, ['/etc/claim'])

    def test_false_absence_summary_is_denied(self):
        report = self.report()
        report['targets']['/etc/claim'] = {'state': 'PRESENT', 'device': 1, 'inode': 2,
                                         'type': 16384, 'mode': '0o700', 'uid': 0, 'gid': 0}
        with self.assertRaisesRegex(RuntimeError, 'RESULT_PROJECTION'):
            transport.project_report(report, ['/etc/claim'])

    def test_no_raw_stdout_record_on_invalid_json(self):
        with self.assertRaises(json.JSONDecodeError):
            transport.project_report(json.loads('synthetic invalid output'), ['/etc/claim'])

    def test_bounded_local_pipe_and_secret_wipe(self):
        secret = bytearray(b'synthetic-only\n')
        proc = subprocess.Popen([sys.executable, '-I', '-B', '-c',
                                 "import sys; sys.stdin.buffer.read(); print('bounded')"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = transport.communicate_bounded(proc, secret)
        self.assertEqual(out, b'bounded\n'); self.assertEqual(err, b'')
        self.assertFalse(any(secret))

    def test_output_bound_terminates_only_owned_process(self):
        secret = bytearray(b'synthetic-only\n')
        proc = subprocess.Popen([sys.executable, '-I', '-B', '-c',
                                 "import sys; sys.stdin.buffer.read(); sys.stdout.write('x'*100000)"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with self.assertRaisesRegex(RuntimeError, 'SSH_OUTPUT_BOUND'):
            transport.communicate_bounded(proc, secret)
        self.assertIsNotNone(proc.returncode); self.assertFalse(any(secret))


if __name__ == '__main__':
    unittest.main()
