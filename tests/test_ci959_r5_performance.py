import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import ci959_r5_performance as p
from tests import ci959_r5_profile as cpu


def metadata(mode='control'):
    return {'mode': mode, 'cpu': {'vendor': 'GenuineIntel', 'family': 6, 'model': 85,
        'stepping': 7, 'affinity_cpus': 2, 'python': [3, 12, 3]},
        'microprobe': [{n: {'cpu_ns': 10, 'wall_ns': 12} for n in ('plain', 'existing_cost', 'with_cpu')} for _ in range(3)],
        'cgroup_before': None, 'cgroup_after': None, 'profile': None}


class CpuAccounting(unittest.TestCase):
    def context(self):
        ns = {'_owner_phase': 'apply'}; exec(cpu.CORE, ns); return ns

    def test_delegate_identity_arguments_and_no_value_capture(self):
        ns = self.context(); value = object(); seen = []
        def actual(a, *, b): seen.append((a, b)); return a
        wrapped = ns['_pc_wrap']('process', actual)
        self.assertIs(wrapped(value, b='SENSITIVE_SENTINEL'), value)
        self.assertEqual(seen, [(value, 'SENSITIVE_SENTINEL')])
        self.assertNotIn('SENSITIVE_SENTINEL', repr(ns['_pc_rows']))
        cpu.validate({'rows': ns['_pc_rows'], 'stack_empty': not ns['_pc_stack']})

    def test_nested_exclusive_costs_not_added_twice(self):
        ns = self.context()
        inner = ns['_pc_wrap']('proc_text', lambda: sum(range(1000)))
        outer = ns['_pc_wrap']('process', inner)
        outer(); rows = ns['_pc_rows']['apply']
        self.assertEqual(rows['process']['calls'], 1)
        self.assertEqual(rows['process']['cpu_ns']-rows['process']['exclusive_cpu_ns'], rows['proc_text']['cpu_ns'])
        cpu.validate({'rows': ns['_pc_rows'], 'stack_empty': not ns['_pc_stack']})

    def test_guard_exception_is_same_instance_and_unwinds(self):
        ns = self.context(); error = TimeoutError('PRIVATE_SENTINEL')
        def fail(): raise error
        with self.assertRaises(TimeoutError) as caught: ns['_pc_wrap']('process', fail)()
        self.assertIs(caught.exception, error); self.assertEqual(ns['_pc_stack'], [])
        self.assertEqual(ns['_pc_rows']['apply']['process']['calls'], 1)
        self.assertNotIn('PRIVATE_SENTINEL', repr(ns['_pc_rows']))

    def test_outside_owner_phase_not_profiled(self):
        ns = self.context(); ns['_owner_phase'] = None
        self.assertEqual(ns['_pc_wrap']('process', lambda: 17)(), 17)
        self.assertEqual(ns['_pc_rows'], {})

    def test_reject_unknown_labels_fields_types_and_bounds(self):
        ns = self.context(); ns['_pc_wrap']('process', lambda: 1)()
        good = {'rows': ns['_pc_rows'], 'stack_empty': True}
        changes = [lambda v: v.update(secret='SENSITIVE'),
            lambda v: v.update(stack_empty=False),
            lambda v: v['rows'].update(secret={}),
            lambda v: v['rows']['apply'].update(secret={}),
            lambda v: v['rows']['apply']['process'].update(calls=True),
            lambda v: v['rows']['apply']['process'].update(cpu_ns=-1),
            lambda v: v['rows']['apply']['process'].update(exclusive_cpu_ns=720_000_000_000)]
        for change in changes:
            v = copy.deepcopy(good); change(v)
            with self.subTest(value=v), self.assertRaises(ValueError): cpu.validate(v)


class NativePreservation(unittest.TestCase):
    def test_exact_current_native_hash_and_no_production_file_change(self):
        raw = (p.ROOT/'tests/public_operator_native.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), p.NATIVE_SHA)
        for mode in p.MODES: p.prepared_native(raw, mode)

    def test_only_wrapper_assignment_changes_original_guard_still_fails(self):
        raw = b'READ_COST_WRAPPER="existing"\ndef guard(x):\n assert x == 84\n return x\n'
        with patch.object(p, 'NATIVE_SHA', hashlib.sha256(raw).hexdigest()):
            control = {}; diag = {}
            exec(p.prepared_native(raw, 'control'), control)
            exec(p.prepared_native(raw, 'profile'), diag)
        self.assertEqual(diag['READ_COST_WRAPPER'], control['READ_COST_WRAPPER']+cpu.WRAPPER)
        self.assertEqual(control['guard'].__code__.co_code, diag['guard'].__code__.co_code)
        for ns in (control, diag):
            self.assertEqual(ns['guard'](84), 84)
            with self.assertRaises(AssertionError): ns['guard'](83)

    def test_wrong_native_bytes_or_mode_denied(self):
        with self.assertRaises(p.ProbeError): p.prepared_native(b'pass', 'control')
        raw = (p.ROOT/'tests/public_operator_native.py').read_bytes()
        with self.assertRaises(p.ProbeError): p.prepared_native(raw, 'third')

    def test_native_microprobe_is_synthetic_only(self):
        raw = (p.ROOT/'tests/public_operator_native.py').read_bytes()
        rows = p.microprobe(raw); self.assertEqual(len(rows), 3)
        value = metadata(); value['microprobe'] = rows; p.validate_metadata(value, 'control')

    def test_fixed_workflow_one_job_private_gate_and_no_rerun(self):
        raw = (p.ROOT/'.github/workflows/ci959-r5-performance.yml').read_text()
        self.assertIn('environment: control-private-ci', raw)
        self.assertIn('github.run_attempt == 1', raw)
        self.assertIn('persist-credentials: false', raw)
        self.assertNotIn('upload-artifact', raw); self.assertNotIn('continue-on-error', raw)
        self.assertEqual(p.MODES, ('control', 'profile'))


class AdmissionAndOutput(unittest.TestCase):
    def test_cpuinfo_usual_whitespace_keys_and_no_model_string(self):
        raw = 'vendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\nstepping : 7\nmodel name : PRIVATE\n\n'
        with patch.object(Path, 'read_text', return_value=raw), \
                patch.object(p.os, 'sched_getaffinity', return_value={0, 1}, create=True):
            value = p.cpu_metadata()
        self.assertEqual({key: value[key] for key in ('vendor', 'family', 'model', 'stepping')},
            {'vendor': 'GenuineIntel', 'family': 6, 'model': 85, 'stepping': 7})
        self.assertNotIn('PRIVATE', repr(value))

    def test_fixed_metadata_and_null_missing_cgroup_accepted(self):
        self.assertEqual(p.validate_metadata(metadata(), 'control'), metadata())

    def test_metadata_rejects_extra_sensitive_value_and_types(self):
        changes = [lambda v: v.update(secret='PRIVATE'), lambda v: v['cpu'].update(hostname='PRIVATE'),
            lambda v: v['cpu'].update(vendor='PRIVATE'), lambda v: v['cpu'].update(model=True),
            lambda v: v['cpu'].update(affinity_cpus=0), lambda v: v['cpu'].update(python='PRIVATE'),
            lambda v: v['microprobe'].append({}), lambda v: v['microprobe'][0]['plain'].update(cpu_ns=-1),
            lambda v: v.update(cgroup_before={'PRIVATE': 1}),
            lambda v: v.update(profile={'rows': {}, 'stack_empty': True})]
        for change in changes:
            value = metadata(); change(value)
            with self.subTest(value=value), self.assertRaises((p.ProbeError, ValueError, TypeError)):
                p.validate_metadata(value, 'control')

    def test_failure_remains_failure_second_guest_only_known_owner_deadline(self):
        record = {'native_result': 'FAIL', 'failure': {'outcome': {'server_terminal_code': 'PUBLIC_OPERATOR_WIRE_DEADLINE',
            'server_exit': 1, 'abort': [], 'cleanup': []}}, 'owner_timing': {'started': True, 'stack_empty': True}}
        self.assertTrue(p.may_continue(record)); self.assertEqual(record['native_result'], 'FAIL')
        for code in (None, 'UNKNOWN', 'PRIVATE'):
            record['failure']['outcome']['server_terminal_code'] = code
            self.assertFalse(p.may_continue(record))
        record['failure']['outcome']['server_terminal_code'] = 'PUBLIC_OPERATOR_WIRE_DEADLINE'
        for key, value in (('server_exit', -9), ('abort', ['UNKNOWN']), ('cleanup', ['UNKNOWN'])):
            v = copy.deepcopy(record); v['failure']['outcome'][key] = value
            self.assertFalse(p.may_continue(v))
        record['owner_timing']['stack_empty'] = False; self.assertFalse(p.may_continue(record))
        record['owner_timing'] = None; self.assertFalse(p.may_continue(record))

    def test_missing_duplicate_invalid_or_exit_mismatched_report_denied(self):
        line = json.dumps({'r5_performance_metadata': metadata()}).encode()
        for code, raw in ((1, b''), (1, line+b'\n'+line), (2, line), (True, line), (1, line+b'\n{}')):
            with self.subTest(code=code, raw=raw), self.assertRaises(p.ProbeError):
                p.parse_guest(code, raw, 'control', {})

    def test_failed_report_still_parsed_at_exit_one(self):
        line = json.dumps({'r5_performance_metadata': metadata()}).encode()
        failure = {'outcome': {'owner_confirmations': 78}, 'owner_timing': None}
        with patch.object(p.ci, 'failure_location', return_value=failure) as read:
            result = p.parse_guest(1, b'PRIVATE_CHILD\n'+line, 'control', {})
        read.assert_called_once_with(b'PRIVATE_CHILD')
        self.assertEqual(result['native_result'], 'FAIL'); self.assertEqual(result['native_exit'], 1)
        self.assertNotIn('PRIVATE_CHILD', repr(result))

    def test_admission_exact_branch_sha_parent_and_only_added_test_files(self):
        sha = 'a'*40
        event = {'ref': 'refs/heads/'+p.BRANCH, 'after': sha, 'repository': {'full_name': p.ci.boundary.REPOSITORY},
            'head_commit': {'message': 'CI959: one bounded R5 performance probe'}}
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp)/'event.json'; f.write_text(json.dumps(event))
            env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': p.ci.boundary.REPOSITORY,
                'CONTROL_PRIVATE_ENVIRONMENT': p.ci.boundary.ENVIRONMENT, 'GITHUB_EVENT_NAME': 'push',
                'GITHUB_REF': 'refs/heads/'+p.BRANCH, 'GITHUB_RUN_ATTEMPT': '1',
                'GITHUB_SHA': sha, 'EXPECTED_SOURCE_SHA': sha, 'GITHUB_EVENT_PATH': str(f)}
            def reads(*args):
                return {('rev-parse', 'HEAD'): sha.encode(), ('rev-parse', 'HEAD^'): p.BASE.encode(),
                    ('diff', '--name-status', p.BASE, 'HEAD'): '\n'.join('A\t'+x for x in p.ADDED).encode()}.get(args, b'')
            with patch.object(p, 'git', side_effect=reads): self.assertEqual(p.binding(env), sha)
            for key, val in (('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_REF', 'refs/heads/control-main'),
                ('GITHUB_EVENT_NAME', 'pull_request'), ('EXPECTED_SOURCE_SHA', 'b'*40),
                ('CONTROL_PRIVATE_ENVIRONMENT', ''), ('GITHUB_REPOSITORY', 'other/repo')):
                with self.subTest(key=key), patch.object(p, 'git', side_effect=reads), self.assertRaises(p.ProbeError):
                    p.binding({**env, key: val})
            with patch.object(p, 'git', return_value=b'unknown'), self.assertRaises(p.ProbeError): p.binding(env)


class ImageCleanup(unittest.TestCase):
    env = {'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
    image = 'tu1nz-ci959-performance:123-1'
    image_id = b'sha256:'+b'a'*64+b'\n'

    def test_exact_run_tag_removed_and_two_successful_queries(self):
        with patch.object(p.ci, 'command', side_effect=[self.image_id, b'', b'']) as command:
            p.cleanup_image(self.image, self.env)
        args = [call.args[0] for call in command.call_args_list]
        self.assertEqual(args[0], args[2])
        self.assertEqual(args[0], ['/usr/bin/docker', 'image', 'ls', '--no-trunc', '--filter',
            'reference='+self.image, '--format', '{{.ID}}'])
        self.assertEqual(args[1], ['/usr/bin/docker', 'image', 'rm', self.image])

    def test_absent_still_requires_two_successful_queries(self):
        with patch.object(p.ci, 'command', return_value=b'') as command:
            p.cleanup_image(self.image, self.env)
        self.assertEqual(command.call_count, 2)

    def test_query_or_remove_error_never_proves_absence(self):
        for answers in ([RuntimeError('PRIVATE')], [b'', RuntimeError('PRIVATE')],
                [self.image_id, RuntimeError('PRIVATE')], [self.image_id, b'', RuntimeError('PRIVATE')]):
            with self.subTest(answers=answers), patch.object(p.ci, 'command', side_effect=answers), \
                    self.assertRaises(RuntimeError):
                p.cleanup_image(self.image, self.env)

    def test_invalid_listing_or_retained_image_denied(self):
        for answers in ([b'PRIVATE'], [self.image_id*2], [self.image_id, b'', self.image_id]):
            with self.subTest(answers=answers), patch.object(p.ci, 'command', side_effect=answers), \
                    self.assertRaises(p.ProbeError):
                p.cleanup_image(self.image, self.env)

    def test_unbound_tag_or_rerun_no_docker_call(self):
        for image, env in (('another-image', self.env), (self.image, {}),
                (self.image, {**self.env, 'GITHUB_RUN_ATTEMPT': '2'}),
                (self.image, {**self.env, 'GITHUB_RUN_ID': '*'})):
            with self.subTest(image=image, env=env), patch.object(p.ci, 'command') as command, \
                    self.assertRaises(p.ProbeError):
                p.cleanup_image(image, env)
            command.assert_not_called()


if __name__ == '__main__': unittest.main()
