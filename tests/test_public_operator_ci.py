"""CI transport/privacy boundaries only, NOT substituted Host observations."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator_ci as m
from tests.test_public_operator import native_trace_capable


class PublicOperatorCI(unittest.TestCase):
    def test_exact_private_commit_and_three_blobs_only(self):
        self.assertEqual(m.CONTROL_COMMIT, 'f2979863bbb7043261e9177842503a9b47cdb49f')
        calls = []
        def command(argv, **kw):
            calls.append((argv, dict(kw.get('env', m.boundary.tool_env()))))
            self.assertNotIn('github_pat_SYNTHETIC_CANARY', str(argv))
            if 'rev-parse' in argv: return (m.CONTROL_COMMIT+'\n').encode()
            if 'show' in argv: return ('SYNTHETIC-'+argv[-1]).encode()
            return b''
        with tempfile.TemporaryDirectory() as d, patch.object(m, 'command', command), \
             patch.dict(m.operator.io.CONTROL_PINS, {}, clear=True):
            root, hashes = m.fetch_control(Path(d), 'github_pat_SYNTHETIC_CANARY')
            self.assertEqual(set(hashes), {'entry', 'guard', 'owner'})
            self.assertEqual({str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()},
                             set(m.operator.CONTROL_FILES.values()))
            self.assertEqual({p.name for p in Path(d).iterdir()}, {'control-source'})
            private = [env for argv, env in calls if 'fetch' in argv]
            self.assertEqual(len(private), 1)
            self.assertEqual(private[0]['CONTROL_POLICY_READ_TOKEN'], 'github_pat_SYNTHETIC_CANARY')
            self.assertTrue(all('CONTROL_POLICY_READ_TOKEN' not in env for argv, env in calls if 'fetch' not in argv))

    def test_readonly_network_none_finite_guest_has_no_secret_or_host_socket(self):
        argv = m.native_argv(Path('/public/work'), Path('/private/control-source'), 'image', 'own', 'nonce')
        self.assertEqual(sum(x == '--mount' for x in argv), 2)
        self.assertIn('type=bind,src=/public/work,dst=/source,readonly', argv)
        self.assertIn('type=bind,src=/private/control-source,dst=/control-source,readonly', argv)
        self.assertEqual(argv[argv.index('--network')+1], 'none')
        self.assertIn('--cgroupns=private', argv)
        self.assertNotIn('docker.sock', str(argv)); self.assertNotIn('CONTROL_POLICY_READ_TOKEN', str(argv))

    def test_guest_inspection_rejects_extra_mount_or_rw_source(self):
        value = {'Image': 'sha256:'+'1'*64, 'Config': {'Labels': {'tu1nz.private-ci.owner': 'nonce'}},
                 'HostConfig': {'NetworkMode': 'none', 'CgroupnsMode': 'private'},
                 'Mounts': [{'Type': 'bind', 'Source': '/public', 'Destination': '/source', 'RW': False},
                            {'Type': 'bind', 'Source': '/private', 'Destination': '/control-source', 'RW': False}]}
        def check():
            with patch.object(m, 'command', return_value=json.dumps([value]).encode()):
                m.inspect_guest('own', 'nonce', Path('/public'), Path('/private'), 'sha256:'+'1'*64)
        check()
        value['Mounts'][0]['RW'] = True
        with self.assertRaises(m.CIError): check()
        value['Mounts'][0]['RW'] = False
        value['Mounts'].append({'Type': 'bind', 'Source': '/run/systemd', 'Destination': '/run/systemd', 'RW': False})
        with self.assertRaises(m.CIError): check()

    def test_exact_report_not_generic_green_and_no_source_substitution(self):
        hashes = {'owner': 'b'*64}
        value = {'scenario': 'success', 'status': 'RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED', 'server_exit': 0,
                 'proof': 'a'*64, 'source_files': hashes, 'owner_confirmations': 84, 'actual_root_objects': 88,
                 'actual_faults': [], 'fixture_only_no_host_acceptance': True}
        self.assertEqual(m.validate_report(json.dumps(value).encode(), 'success', hashes)['scenario'], 'success')
        for changed in ({'owner_confirmations': 83}, {'source_files': {'owner': 'c'*64}},
                        {'fixture_only_no_host_acceptance': False}, {'server_exit': 1}, {'green': True}):
            with self.subTest(changed=changed), self.assertRaises((m.CIError, m.operator.io.Hold)):
                m.validate_report(json.dumps({**value, **changed}).encode(), 'success', hashes)

    def test_every_fault_requires_its_own_actual_marker(self):
        self.assertEqual(set(m.FAULTS), set(m.CASES))
        for case in m.CASES:
            if case == 'success': continue
            value = {'scenario': case, 'status': 'HOLD', 'server_exit': 0, 'proof': 'a'*64,
                     'source_files': {}, 'owner_confirmations': 0, 'actual_root_objects': 4,
                     'actual_faults': [], 'fixture_only_no_host_acceptance': True}
            with self.subTest(case=case), self.assertRaisesRegex(m.CIError, 'INTENDED_FAULT_NOT_WITNESSED'):
                m.validate_report(json.dumps(value).encode(), case, {})

    def test_native_failure_and_interrupt_never_leak_private_output_and_cleanup(self):
        for failure in (RuntimeError('PRIVATE_CANARY github_pat_SYNTHETIC'), InterruptedError('PRIVATE_CANARY')):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as d:
                base = Path(d).resolve(); work = base/'work'; work.mkdir(); temp = base/'temp'; temp.mkdir()
                output = io.StringIO()
                env = {'RUNNER_TEMP': str(temp), 'CONTROL_POLICY_READ_TOKEN': 'github_pat_SYNTHETIC',
                       'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
                with patch.dict(os.environ, env), patch.object(m.boundary, 'runtime_binding', return_value='1'*40), \
                     patch.object(m, 'command', return_value=('sha256:'+'a'*64).encode()), \
                     patch.object(m, 'fetch_control', side_effect=failure), contextlib.redirect_stdout(output):
                    self.assertEqual(m.run(work, 'tu1nz-public-operator-private:123-1'), 1)
                self.assertNotIn('CANARY', output.getvalue()); self.assertNotIn('github_pat', output.getvalue())
                self.assertFalse(list(temp.iterdir()))

    def test_missing_credential_never_fetches(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(m.boundary, 'runtime_binding', return_value='1'*40), \
             patch.object(m, 'fetch_control') as fetch, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.run(Path('/public'), 'image'), 1); fetch.assert_not_called()

    def test_failure_diagnostic_allows_only_bounded_source_locations(self):
        value = {'native_failure': {'test_line': 494, 'test_type': 'AssertionError',
                 'production_fault': {'component': '<authenticated-memory:observe>', 'line': 123, 'type': 'Hold'}}}
        self.assertEqual(m.failure_location(json.dumps(value).encode()), value['native_failure'])
        for changed in ({'test_line': True}, {'test_type': 'PRIVATE_CANARY'},
                        {'production_fault': {'component': '/private/CANARY', 'line': 123, 'type': 'Hold'}},
                        {'production_fault': {'component': '<authenticated-memory:observe>', 'line': 123,
                                              'type': 'Hold', 'message': 'PRIVATE_CANARY'}}):
            with self.subTest(changed=changed):
                self.assertIsNone(m.failure_location(json.dumps({'native_failure': {**value['native_failure'], **changed}}).encode()))
        self.assertIsNone(m.failure_location(b'PRIVATE_CANARY github_pat_SYNTHETIC'))
        value['native_failure']['cause_code'] = 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_BROKER_EFFECTIVE_DAC_ACCESS'
        self.assertEqual(m.failure_location(json.dumps(value).encode())['cause_code'], value['native_failure']['cause_code'])
        value['native_failure']['cause_code'] = 'PRIVATE_CANARY'
        self.assertNotIn('PRIVATE_CANARY', json.dumps(m.failure_location(json.dumps(value).encode())))
        value['native_failure']['test_type'] = 'PermissionError'
        self.assertEqual(m.failure_location(json.dumps(value).encode())['test_type'], 'PermissionError')
        value['native_failure'].update(test_type='NativeFSUIDFailure', cause_code='NATIVE_FSUID_CHILD_CONNECT_RED', errno=13)
        self.assertEqual(m.failure_location(json.dumps(value).encode())['errno'], 13)
        value['native_failure']['errno'] = True
        self.assertIsNone(m.failure_location(json.dumps(value).encode()))

    def test_cleanup_preserves_primary_location_and_both_independent_errors(self):
        location = {'test_line': 494, 'test_type': 'AssertionError', 'production_fault': None}
        for container_fails, input_fails in ((True, False), (False, True), (True, True)):
            with self.subTest(container=container_fails, inputs=input_fails):
                original = {'schema': m.SCHEMA, 'green': False, 'stage': 'success',
                            'code': 'NATIVE_CASE_RED', 'failure_location': location}
                with patch.object(m.boundary, 'cleanup_container', side_effect=RuntimeError('PRIVATE_CANARY') if container_fails else None) as container, \
                     patch.object(m.boundary, 'remove_private', side_effect=RuntimeError('PRIVATE_CANARY') if input_fails else None) as inputs:
                    result = m.cleanup_result(original, 'owned', 'nonce', Path('/private/inputs'), Path('/private'))
                container.assert_called_once(); inputs.assert_called_once()
                self.assertFalse(result['green']); self.assertEqual(result['code'], 'NATIVE_CASE_RED')
                self.assertEqual(result['failure_location'], location)
                self.assertEqual(result['cleanup_errors'], (['OWNED_CONTAINER_CLEANUP_RED'] if container_fails else [])+
                                 (['PRIVATE_INPUT_CLEANUP_RED'] if input_fails else []))
                self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
        original = {'schema': m.SCHEMA, 'green': True, 'code': 'PRIVATE_OPERATOR_CI_GREEN', 'cases': []}
        with patch.object(m.boundary, 'remove_private', side_effect=RuntimeError('PRIVATE_CANARY')):
            result = m.cleanup_result(original, None, 'nonce', Path('/private/inputs'), Path('/private'))
        self.assertFalse(result['green']); self.assertEqual(result['code'], 'PRIVATE_OPERATOR_CI_CLEANUP_RED')
        self.assertEqual(result['cases'], []); self.assertNotIn('PRIVATE_CANARY', json.dumps(result))

    def test_finite_failure_codes_and_counters_never_publish_unknown_values(self):
        outcome = {'status': 'HOLD', 'primary': 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_WIRE_DEADLINE',
            'abort': ['PRIVATE_CANARY'], 'cleanup': [], 'client_error_type': 'PRIVATE_CANARY',
            'server_exit': 1, 'owner_confirmations': 7, 'actual_root_objects': 11,
            'last_record_kind': 'owner_object_intent', 'last_record_sequence': 123}
        value = {'native_failure': {'test_line': 476, 'test_type': 'AssertionError',
                 'production_fault': None, 'outcome': outcome}}
        result = m.failure_location(json.dumps(value).encode())
        self.assertEqual(result['outcome']['primary'], outcome['primary'])
        self.assertEqual(result['outcome']['owner_confirmations'], 7)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
        for key, changed in (('owner_confirmations', True), ('actual_root_objects', 89), ('server_exit', 'PRIVATE_CANARY')):
            with self.subTest(key=key):
                value['native_failure']['outcome'] = {**outcome, key: changed}
                self.assertIsNone(m.failure_location(json.dumps(value).encode()))

    def test_native_fsuid_regression_has_exact_root_non_skipped_guest_entry(self):
        argv = m.native_fsuid_argv('owned')
        self.assertEqual(argv[:6], ['/usr/bin/docker', 'exec', 'owned', '/usr/bin/python3', '-I', '-B'])
        self.assertIn('os.geteuid()==0', argv[-1]); self.assertIn('not r.skipped', argv[-1])
        self.assertIn('test_actual_fsuid_socket_owner_', argv[-1])
        self.assertIn('test_actual_child_dac_failure_', argv[-1]); self.assertIn('r.testsRun==3', argv[-1])
        self.assertIn('test_actual_fsgid_not_real_saved_group_', argv[-1])

    def test_zero_uid_without_ptrace_is_not_native_observer_evidence(self):
        with patch('tests.test_public_operator.sys.platform', 'linux'), \
             patch('tests.test_public_operator.os.geteuid', return_value=0), \
             patch('tests.test_public_operator.Path.read_text', return_value='CapEff:\t0000000000000000\n'):
            self.assertFalse(native_trace_capable())
        with patch('tests.test_public_operator.sys.platform', 'linux'), \
             patch('tests.test_public_operator.os.geteuid', return_value=0), \
             patch('tests.test_public_operator.Path.read_text', return_value='CapEff:\t0000000000080000\n'):
            self.assertTrue(native_trace_capable())


if __name__ == '__main__': unittest.main(verbosity=2)
