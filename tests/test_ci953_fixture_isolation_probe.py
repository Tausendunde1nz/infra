import copy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from tests import ci953_fixture_isolation_probe as p


class ProbeTests(unittest.TestCase):
    def result(self):
        return {'schema': p.SCHEMA, 'conditions': dict(zip(p.BOOLS, (True, True, False))),
                'guard_passed': False, 'error_type': 'AssertionError', 'test_failure': dict(p.POINT),
                'source_files': p.source_hashes(), 'host_acceptance': False}

    def test_exact_unit_comparison(self):
        expected = ('[Unit]\nAfter=multi-user.target\n[Service]\nType=simple\n'
            'ExecStart=/usr/bin/python3 -I -B -S /source/tests/ci953_fixture_isolation_probe.py --case original --phase calibration\n'
            'StandardOutput=null\nStandardError=append:/native-private-stderr\nTimeoutStartSec=infinity\n').encode()
        self.assertEqual(p.unit_bytes(False), expected)
        self.assertEqual(p.unit_bytes(True), expected.replace(b'Type=simple\n', b'Type=simple\nEnvironment=container=docker\n'))

    def test_only_expected_failure_allows_second_guest(self):
        self.assertTrue(p.only_missing_environment(self.result()))
        for key in p.BOOLS:
            value = self.result(); value['conditions'][key] = not value['conditions'][key]
            self.assertFalse(p.only_missing_environment(value))
        value = self.result(); value['test_failure'] = dict(p.diagnostics.UNMAPPED)
        self.assertFalse(p.only_missing_environment(value))
        value = self.result(); value['error_type'] = 'RuntimeError'
        self.assertFalse(p.only_missing_environment(value))

    def test_reject_wrong_type_missing_or_extra_fields_source_drift(self):
        original = self.result()
        for operation in ('type', 'missing', 'extra', 'source', 'location', 'error', 'false-pass'):
            with self.subTest(operation=operation):
                value = copy.deepcopy(original)
                if operation == 'type': value['conditions'][p.BOOLS[0]] = 1
                elif operation == 'missing': del value['conditions'][p.BOOLS[0]]
                elif operation == 'extra': value['private'] = 'not publishable'
                elif operation == 'source': value['source_files'][p.BOUND[0]] = '0'*64
                elif operation == 'location': value['test_failure']['line'] += 1
                elif operation == 'error': value['error_type'] = 'not publishable'
                elif operation == 'false-pass': value['guard_passed'] = True
                with self.assertRaises(p.ProbeError): p.validate(value)

    def test_complete_pass_never_counts_as_reproduced_original_failure(self):
        value = self.result(); value['conditions'] = dict.fromkeys(p.BOOLS, True)
        value.update(guard_passed=True, error_type=None, test_failure=None)
        self.assertEqual(p.validate(value), value)
        self.assertFalse(p.only_missing_environment(value))

    def test_unclear_create_ack_cleans_owned_guest_and_preserves_primary_failure(self):
        for cleanup_fails in (False, True):
            with self.subTest(cleanup_fails=cleanup_fails), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory).resolve(); out = io.StringIO()
                def command(argv, **kwargs):
                    if argv[1:3] == ['image', 'inspect']: return b'sha256:'+b'1'*64+b'\n'
                    self.assertEqual(argv[1], 'create')
                    raise TimeoutError('SENSITIVE TEST EXCEPTION MUST NOT APPEAR')
                with mock.patch.dict(os.environ, {'RUNNER_TEMP': str(parent), 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}), \
                     mock.patch.object(p, 'binding', return_value='2'*40), \
                     mock.patch.object(p.ci, 'command', side_effect=command), \
                     mock.patch.object(p.ci.boundary, 'cleanup_container', side_effect=RuntimeError() if cleanup_fails else None) as cleanup, \
                     contextlib.redirect_stdout(out):
                    self.assertEqual(p.driver('tu1nz-ci953-probe:1-1'), 1)
                row = json.loads(out.getvalue())
                self.assertEqual(row['phase'], 'original-unit-create')
                self.assertEqual(row['error_type'], 'TimeoutError')
                self.assertEqual(row['code'], 'PROBE_COMMAND_RED')
                self.assertTrue(row['temporary_inputs_removed'])
                self.assertEqual(row['cleanup_errors'], ['GUEST_CLEANUP_RED'] if cleanup_fails else [])
                self.assertNotIn('SENSITIVE', out.getvalue())
                cleanup.assert_called_once()
                name, owner = cleanup.call_args.args
                self.assertEqual(name, 'tu1nz-ci953-'+owner+'-original-unit')
                self.assertEqual(list(parent.iterdir()), [])


if __name__ == '__main__': unittest.main()
