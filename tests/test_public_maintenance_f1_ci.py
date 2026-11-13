"""One-case orchestration tests, only synthetic local inputs and fake Docker."""
from contextlib import ExitStack, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_maintenance_f1_ci as d
from tests import test_public_maintenance_ci as existing

WORKSPACE = Path(__file__).resolve().parents[1]


class F1DiagnosticTests(unittest.TestCase):
    def environment(self, root):
        event = root/'event.json'
        event.write_text(json.dumps({'number': 241}))
        source = root/d.SOURCE_PATH
        source.parent.mkdir(exist_ok=True)
        source.write_bytes((WORKSPACE/d.SOURCE_PATH).read_bytes())
        return {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_REF': 'refs/pull/241/merge',
            'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_EVENT_PATH': str(event)}

    def delta(self):
        return b''.join(b'M\0'+p.encode()+b'\0' for p in sorted(d.CHANGES))

    def test_binding_accepts_only_five_changes_and_exact_fix_to_fixed_base(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(d.ci.boundary, 'runtime_binding', return_value='a'*40) as bound, \
                    patch.object(d.ci, 'command', side_effect=[b'', self.delta()]) as command:
                self.assertEqual(d.binding(root, self.environment(root)), 'a'*40)
            bound.assert_called_once()
            self.assertEqual(command.call_count, 2)
            self.assertIn(d.BASE, command.call_args_list[0].args[0])
            self.assertIn('--is-ancestor', command.call_args_list[0].args[0])

    def test_wrong_ref_event_attempt_rejected_before_runtime_binding(self):
        for key, value in (('GITHUB_REF', 'refs/pull/242/merge'), ('GITHUB_EVENT_NAME', 'push'),
                ('GITHUB_RUN_ATTEMPT', '2')):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temp:
                env = self.environment(Path(temp)); env[key] = value
                with patch.object(d.ci.boundary, 'runtime_binding') as bound, self.assertRaises(d.ci.CIError):
                    d.binding(Path(temp), env)
                bound.assert_not_called()

    def test_wrong_event_pr_and_nonadditive_or_extra_delta_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); env = self.environment(root)
            Path(env['GITHUB_EVENT_PATH']).write_text('{"number":242}')
            with patch.object(d.ci.boundary, 'runtime_binding', return_value='a'*40), \
                    patch.object(d.ci, 'command') as command, self.assertRaises(d.ci.CIError):
                d.binding(root, env)
            command.assert_not_called()
            env = self.environment(root)
            for delta in (b'', self.delta().replace(b'M\0', b'A\0', 1),
                    self.delta()+b'M\0scripts/tu1nz_public_operator.py\0', self.delta()[:-1],
                    self.delta().replace(b'tests/test_public_maintenance_f1_ci.py', b'tests/other.py')):
                with self.subTest(delta=delta), patch.object(d.ci.boundary, 'runtime_binding', return_value='a'*40), \
                        patch.object(d.ci, 'command', side_effect=[b'', delta]), self.assertRaises(d.ci.CIError):
                    d.binding(root, env)

    def test_changed_production_bytes_rejected_even_with_correct_delta_names(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); env = self.environment(root)
            (root/d.SOURCE_PATH).write_bytes(b'synthetic wrong bytes')
            with patch.object(d.ci.boundary, 'runtime_binding', return_value='a'*40), \
                    patch.object(d.ci, 'command', side_effect=[b'', self.delta()]):
                with self.assertRaisesRegex(d.ci.CIError, 'F1_DIAGNOSTIC_SOURCE_CHANGED'):
                    d.binding(root, env)

    def native_result(self, value, *, cleanup_error=None):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root = Path(temp)
            if value is not None:
                (root/'calibration-recovery_F1-result.json').write_text(json.dumps(value))
            hashes = existing.NativeBoundaryTests().fixture()[0]
            command = stack.enter_context(patch.object(d.ci, 'command'))
            stack.enter_context(patch.object(d.ci, 'inspect_guest'))
            stack.enter_context(patch.object(d.ci, 'ready'))
            stack.enter_context(patch.object(d.maintenance, 'fix_copied_unit_owner'))
            cleanup = stack.enter_context(patch.object(d.ci.boundary, 'cleanup_container', side_effect=cleanup_error))
            output = io.StringIO()
            with redirect_stdout(output):
                result = d.one_case(WORKSPACE, root/'control', 'image', 'sha256:'+'b'*64,
                    'owner', root, root/'inputs', hashes)
            self.assertIs(d.ci.boundary.cleanup_container, cleanup)
            calls = [c.args[0] for c in command.call_args_list]
            self.assertEqual(sum(c[:2] == ['/usr/bin/docker', 'create'] for c in calls), 1)
            self.assertEqual(sum(c[:2] == ['/usr/bin/docker', 'wait'] for c in calls), 1)
            self.assertFalse(any('public_operator_profile_ci.py' in str(c) for c in calls))
            self.assertGreaterEqual(cleanup.call_count, 1)
            self.assertTrue(all(c.args == ('tu1nz-rev4-owner-calibration-recovery-f1', 'owner')
                for c in cleanup.call_args_list))
            return result, output.getvalue()

    def test_pass_is_counterprobe_only_with_84_and_once_history(self):
        value = existing.NativeBoundaryTests().fixture()[2][1]
        result, raw = self.native_result(value)
        self.assertEqual(raw, '')
        self.assertTrue(result['green'])
        self.assertEqual((result['owner_intents'], result['owner_acks']), (84, 84))
        self.assertEqual(result['elapsed_milliseconds']+result['reserve_milliseconds'], 600000)
        self.assertTrue(result['entry_cleanup_complete'])
        self.assertTrue(result['original_failed_hold_preserved'])
        self.assertTrue(result['second_recovery_denied_before_SSH'])
        self.assertFalse(result['native_batch_pass'])
        self.assertFalse(result['host_acceptance'])
        self.assertEqual(result['guest_cleanup'], 'PASS')

    def test_real_synthetic_failure_exposes_first_fault_counts_and_keeps_fail_cleanup(self):
        helper = existing.NativeBoundaryTests()
        fields = helper.counted_native_failure()
        host_result, trace_fields = helper.retained_host_failure()
        value = {'schema': 'TU1NZ_REV4_NATIVE_CASE_V1', 'green': False, 'case': d.CASE,
            'phase': d.PHASE, 'host_acceptance': False, **fields,
            'recovery-once': {'result': {'host_primary': host_result['primary'],
                'host_cleanup': host_result['cleanup'], 'client_cleanup': [
                    'PUBLIC_BOOTSTRAP_MAINTENANCE_CLOSED_CUSTODY_UNCONFIRMED']}, **trace_fields},
            'private': 'SECRET_CANARY'}
        for error in (None, OSError('SECRET_CANARY')):
            with self.subTest(cleanup_error=error is not None):
                result, raw = self.native_result(value, cleanup_error=error)
                self.assertFalse(result['green'])
                failure = result['failure']
                self.assertEqual(failure['test_failure']['checkpoint'], 'REV4_NATIVE_MEASURED_ASSERT_01')
                self.assertEqual(failure['owner_counts'], {'owner_intents': 2, 'owner_acks': 1})
                self.assertEqual(failure['recovery-once']['host_source_fault'], host_result['source_fault'])
                self.assertEqual(failure['recovery-once']['host_cleanup'], host_result['cleanup'])
                self.assertEqual(result['guest_cleanup'], 'PASS' if error is None else 'FAIL')
                self.assertEqual(json.loads(raw)['failure'], failure)
                self.assertNotIn('SECRET_CANARY', raw+json.dumps(result))

    def test_missing_wrong_report_and_failed_cleanup_cannot_pass(self):
        good = existing.NativeBoundaryTests().fixture()[2][1]
        for value in (None, {'green': True}, {**good, 'case': 'original'}):
            with self.subTest(value=value is None):
                result, _ = self.native_result(value)
                self.assertFalse(result['green'])
                self.assertEqual(result['report_status'], 'MISSING_OR_INVALID')
                self.assertNotIn('failure', result)
                self.assertNotIn('owner_acks', result)
        result, _ = self.native_result(good, cleanup_error=OSError('SECRET_CANARY'))
        self.assertFalse(result['green'])
        self.assertEqual(result['guest_cleanup'], 'FAIL')

    def test_report_filter_excludes_invalid_fault_counts_and_oversize(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); path = root/'calibration-recovery_F1-result.json'
            value = {'schema': 'TU1NZ_REV4_NATIVE_CASE_V1', 'case': d.CASE, 'phase': d.PHASE,
                'green': False, 'host_acceptance': False, 'owner_counts': {'owner_acks': True},
                'recovery-once': {'result': {}, 'host_source_fault': {'component': 'SECRET_CANARY'}},
                'code': 'SECRET_CANARY', 'private': 'SECRET_CANARY'}
            path.write_text(json.dumps(value))
            failure = d.failed_report(root)
            self.assertIsNotNone(failure)
            self.assertNotIn('owner_counts', failure)
            self.assertNotIn('SECRET_CANARY', json.dumps(failure))
            for raw in (b'not json', b'x'*(256*1024+1), b'[]'):
                path.write_bytes(raw)
                self.assertIsNone(d.failed_report(root))

    def test_no_cleanup_observation_never_becomes_pass(self):
        hashes, _, records = existing.NativeBoundaryTests().fixture()
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(d.maintenance, 'case_run', return_value=records[1]):
            root = Path(temp)
            result = d.one_case(WORKSPACE, root, 'image', 'sha256:'+'b'*64,
                'owner', root, root, hashes)
        self.assertFalse(result['green'])
        self.assertEqual(result['guest_cleanup'], 'NOT_PROVED')

    def test_preflight_failure_never_fetches_secret_or_starts_guest(self):
        output = io.StringIO()
        with patch.dict(os.environ, {'CONTROL_POLICY_READ_TOKEN': 'github_pat_SYNTHETIC'}), \
                patch.object(d, 'binding', side_effect=RuntimeError('SECRET_CANARY')), \
                patch.object(d.ci, 'fetch_control') as fetch, patch.object(d, 'one_case') as case, \
                redirect_stdout(output):
            self.assertEqual(d.run(WORKSPACE, 'image'), 1)
            self.assertNotIn('CONTROL_POLICY_READ_TOKEN', os.environ)
        fetch.assert_not_called(); case.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertEqual(result['stage'], 'admission')
        self.assertEqual(result['private_input_cleanup'], 'NOT_CREATED')
        self.assertNotIn('SECRET_CANARY', output.getvalue())

    def test_private_cleanup_failure_keeps_primary_failure_and_success_turns_red(self):
        for green in (False, True):
            with self.subTest(green=green), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                root = Path(temp)
                stack.enter_context(patch.dict(os.environ, {'CONTROL_POLICY_READ_TOKEN': 'github_pat_SYNTHETIC',
                    'GITHUB_RUN_ID': '1', 'RUNNER_TEMP': temp}))
                stack.enter_context(patch.object(d, 'binding', return_value='a'*40))
                stack.enter_context(patch.object(d.ci, 'command', return_value=('sha256:'+'b'*64).encode()))
                stack.enter_context(patch.object(d.ci.boundary, 'private_root', return_value=root))
                stack.enter_context(patch.object(d.ci, 'fetch_control', return_value=(root/'control', {})))
                import tu1nz_public_runtime_build as build
                stack.enter_context(patch.object(build, 'fetch', return_value=b'synthetic'))
                expected = {'green': green, 'code': 'F1_DIAGNOSTIC_GREEN' if green else 'F1_DIAGNOSTIC_RED',
                    'failure': {'owner_counts': {'owner_intents': 2, 'owner_acks': 1}}}
                case = stack.enter_context(patch.object(d, 'one_case', return_value=copy.deepcopy(expected)))
                removal = stack.enter_context(patch.object(d.ci.boundary, 'remove_private',
                    side_effect=OSError('SECRET_CANARY')))
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(d.run(WORKSPACE, 'tu1nz-public-operator-private:1-1'), 1)
                result = json.loads(output.getvalue())
                case.assert_called_once(); removal.assert_called_once()
                self.assertEqual(result['private_input_cleanup'], 'FAIL')
                self.assertEqual(result['failure'], expected['failure'])
                self.assertEqual(result['code'], 'PRIVATE_OPERATOR_CI_CLEANUP_RED' if green else 'F1_DIAGNOSTIC_RED')
                self.assertNotIn('SECRET_CANARY', output.getvalue())

    def test_workflow_uses_existing_environment_ref_image_and_single_entry(self):
        text = (WORKSPACE/'.github/workflows/mainserver-f1-diagnostic.yml').read_text()
        self.assertIn('environment: control-private-ci', text)
        self.assertIn("github.ref == 'refs/pull/241/merge' && github.run_attempt == 1", text)
        self.assertIn('runs-on: ubuntu-24.04', text)
        self.assertIn('timeout-minutes: 60', text)
        self.assertIn('tests/public-operator-native.Dockerfile', text)
        self.assertEqual(text.count('python3 -I -B scripts/tu1nz_public_maintenance_f1_ci.py'), 1)
        self.assertNotIn('workflow_dispatch:', text)
        self.assertNotIn('upload-artifact@', text)
        self.assertNotIn('outputs:', text)


if __name__ == '__main__':
    unittest.main()
