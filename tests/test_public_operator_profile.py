"""Local synthetic diagnostics tests, never native/Host acceptance."""
import ast
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator_profile_ci as p
import tu1nz_public_operator_profile_cpu as cpu
import tu1nz_public_operator_ci as ci
from tests import test_public_operator_ci as base_tests


def metadata():
    return {'mode': 'profile', 'cpu': {'vendor': 'GenuineIntel', 'family': 6, 'model': 85,
        'stepping': 7, 'affinity_cpus': 2, 'python': [3, 12, 3]},
        'microprobe': [{n: {'cpu_ns': 10, 'wall_ns': 12} for n in ('plain', 'existing_cost', 'with_cpu')} for _ in range(3)],
        'cgroup_before': None, 'cgroup_after': None,
        'profile': {'rows': {'apply': {'process': {'calls': 1, 'cpu_ns': 10, 'wall_ns': 12,
            'exclusive_cpu_ns': 10, 'exclusive_wall_ns': 12}}}, 'stack_empty': True}}


def metadata_line(value=None):
    return json.dumps({'r5_performance_metadata': metadata() if value is None else value}, sort_keys=True).encode()


def deadline_failure():
    timing = base_tests.PublicOperatorCI.owner_timing_fixture()
    timing.update(elapsed_ns=120_054_096_192, finish_completed=False, finish_owner_acks=0, finish_cleanup_bound=False)
    del timing['phases']['finish']
    return {'test_line': 1376, 'test_type': 'AssertionError', 'production_fault': None,
        'owner_timing': timing, 'outcome': {'status': 'HOLD', 'primary': 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_WIRE_DEADLINE',
        'abort': [], 'cleanup': [], 'client_error_type': None, 'server_exit': 1,
        'owner_confirmations': 79, 'actual_root_objects': 83, 'last_record_kind': 'owner_object_intent',
        'last_record_sequence': 100, 'server_terminal_code': 'PUBLIC_OPERATOR_WIRE_DEADLINE'}}


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

    def test_deadline_unwinds_and_both_actual_save_functions_persist_metrics(self):
        from tests import public_operator_native as native
        # Compile only accounting/save functions; never load or execute Host,
        # DB, native fixture, observations or entry code on the Mac.
        ns = {}
        prefix = native.READ_COST_WRAPPER.split('_observer=s.load("observe")', 1)[0]
        save = native.READ_COST_WRAPPER[native.READ_COST_WRAPPER.index('def _save_read_cost():'):]
        appended_save = cpu.INSTALL[cpu.INSTALL.index('_pc_save_original=_save_read_cost'):]
        exec(prefix+save+cpu.CORE+appended_save, ns)
        ns['_owner_phase'] = 'apply'; error = TimeoutError('PUBLIC_OPERATOR_WIRE_DEADLINE')
        def expire(): raise error
        measured = ns['_pc_wrap']('process', ns['_cost']('process', expire))
        with tempfile.TemporaryDirectory() as directory:
            actual_open = os.open; opened = []
            def mapped(path, flags, mode):
                self.assertIn(path, ('/fixture-r4/read-cost.json', '/fixture-r4/cpu-profile.json'))
                self.assertEqual(flags, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW)
                self.assertEqual(mode, 0o600); opened.append(path)
                return actual_open(Path(directory)/Path(path).name, flags, mode)
            with patch.object(os, 'open', side_effect=mapped), self.assertRaises(TimeoutError) as caught:
                try: measured()
                finally: ns['_save_read_cost']()
            self.assertIs(caught.exception, error)
            self.assertEqual(len(opened), 2)
            old = json.loads((Path(directory)/'read-cost.json').read_bytes())
            profiled = cpu.validate(json.loads((Path(directory)/'cpu-profile.json').read_bytes()))
        self.assertFalse(old['owner_timing']['finish_completed'])
        self.assertEqual(old['read_cost']['process']['calls'], 1)
        self.assertEqual(profiled['rows']['apply']['process']['calls'], 1)
        self.assertEqual(ns['_cost_stack'], []); self.assertEqual(ns['_pc_stack'], [])

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
    def test_reviewed_cpu_wrapper_byte_identical_and_native_hash(self):
        self.assertEqual(hashlib.sha256(Path(cpu.__file__).read_bytes()).hexdigest(),
            'ec1e7c061746050a813de32efb5b5837bc860f9500700866b66b36d478894878')
        raw = (p.ROOT/'tests/public_operator_native.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), p.NATIVE_SHA)
        p.prepared_native(raw, 'profile')

    def test_only_wrapper_changes_all_remaining_ast_and_guards_identical(self):
        raw = (p.ROOT/'tests/public_operator_native.py').read_bytes()
        real_compile = compile; trees = []
        def capture(value, *args, **kwargs):
            if isinstance(value, ast.Module): trees.append(copy.deepcopy(value))
            return real_compile(value, *args, **kwargs)
        with patch('builtins.compile', side_effect=capture): p.prepared_native(raw, 'profile')
        self.assertEqual(len(trees), 1)
        original = ast.parse(raw); changed = trees[0]
        assignment = next(n for n in changed.body if isinstance(n, ast.Assign) and
            any(isinstance(t, ast.Name) and t.id == 'READ_COST_WRAPPER' for t in n.targets))
        self.assertTrue(assignment.value.value.endswith(cpu.WRAPPER))
        assignment.value.value = assignment.value.value[:-len(cpu.WRAPPER)]
        self.assertEqual(ast.dump(original, include_attributes=True), ast.dump(changed, include_attributes=True))
        synthetic = b'READ_COST_WRAPPER="existing"\ndef guard(x):\n assert x == 84\n return x\n'
        with patch.object(p, 'NATIVE_SHA', hashlib.sha256(synthetic).hexdigest()):
            ns = {}; exec(p.prepared_native(synthetic, 'profile'), ns)
        self.assertEqual(ns['guard'](84), 84)
        with self.assertRaises(AssertionError): ns['guard'](83)

    def test_wrong_native_or_mode_denied(self):
        with self.assertRaises(p.ProbeError): p.prepared_native(b'pass', 'profile')
        raw = (p.ROOT/'tests/public_operator_native.py').read_bytes()
        with self.assertRaises(p.ProbeError): p.prepared_native(raw, 'control')

    def test_guest_actual_exit_one_keeps_saved_profile_and_native_failure(self):
        # Only synthetic files/program in a temporary directory; no Docker,
        # production source execution, credentials, DB or Host calls.
        failure = deadline_failure()
        program = compile('print('+repr(json.dumps({'native_failure': failure}))+')\nraise SystemExit(1)', '<synthetic>', 'exec')
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'cpu-profile.json'; target.write_text(json.dumps(metadata()['profile']))
            actual_path = Path
            def mapped(value):
                return target if value in ('/fixture-r4/cpu-profile.json', '/.dockerenv') else actual_path(value)
            out = io.StringIO()
            with patch.object(p, 'Path', side_effect=mapped), patch.object(p.sys, 'platform', 'linux'), \
                    patch.object(p.os, 'geteuid', return_value=0), patch.dict(os.environ, {'container': 'docker'}), \
                    patch.object(p, 'prepared_native', return_value=program), patch.object(p, 'cpu_metadata', return_value=metadata()['cpu']), \
                    patch.object(p, 'microprobe', return_value=metadata()['microprobe']), patch.object(p, 'cgroup_cpu', return_value=None), \
                    patch.object(p.sys, 'argv', []), contextlib.redirect_stdout(out):
                self.assertEqual(p.guest('profile'), 1)
            native, measured = p.extract(out.getvalue().encode())
        self.assertEqual(measured, metadata())
        self.assertEqual(ci.failure_location(native), failure)

    def test_microprobe_and_fixed_cpu_metadata(self):
        value = metadata(); value['microprobe'] = p.microprobe((p.ROOT/'tests/public_operator_native.py').read_bytes())
        self.assertEqual(p.validate_metadata(value, 'profile'), value)
        raw = 'vendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t: 85\nstepping : 7\nmodel name : PRIVATE\n\n'
        with patch.object(Path, 'read_text', return_value=raw), patch.object(p.os, 'sched_getaffinity', return_value={0, 1}, create=True):
            value = p.cpu_metadata()
        self.assertEqual(value['model'], 85); self.assertNotIn('PRIVATE', repr(value))


class StrictOutput(unittest.TestCase):
    def test_extract_only_metadata_and_reject_missing_duplicate_or_sensitive_values(self):
        line = metadata_line(); self.assertEqual(p.extract(b'native\n'+line), (b'native', metadata()))
        for raw in (b'', line+b'\n'+line, b'{"r5_performance_metadata":invalid}', b'x'*262145):
            self.assertIsNone(p.extract(raw)[1])
        mutations = [lambda v: v.update(secret='PRIVATE'), lambda v: v['cpu'].update(hostname='PRIVATE'),
            lambda v: v['cpu'].update(vendor='PRIVATE'), lambda v: v['cpu'].update(model=True),
            lambda v: v['cpu'].update(affinity_cpus=0), lambda v: v['cpu'].update(python='PRIVATE'),
            lambda v: v['microprobe'].append({}), lambda v: v['microprobe'][0]['plain'].update(cpu_ns=-1),
            lambda v: v.update(cgroup_before={'PRIVATE': 1}), lambda v: v['profile'].update(stack_empty=False)]
        for mutate in mutations:
            v = metadata(); mutate(v)
            with self.subTest(value=v): self.assertIsNone(p.extract(metadata_line(v))[1])


class RegularSequence(unittest.TestCase):
    preceding = ('success', 'writer', 'namespace_swap', 'lost_ack', 'interrupt', 'runtime_tamper',
        'restore_fail_return', 'probe_fail_return', 'denied_return', 'owner_return', 'lost_start_ack',
        'first_restart', 'old_restart', 'stop_source_fd', 'stop_source_mapping', 'unknown_actor',
        'thread_authority', 'thread_source_fd')

    def simulate(self, failure=False, malformed=False, missing_profile=False, cleanup_fails=False, external_timeout=False):
        import tu1nz_public_runtime_build as build
        import tu1nz_public_maintenance_ci as maintenance
        events = []; output = io.StringIO(); allowed_codes = ci.diagnostic_codes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); work = base/'work'; root = base/'temp'
            (work/'manifests').mkdir(parents=True); root.mkdir()
            (work/'manifests/public-web-runtime-r5-inputs.json').write_text(json.dumps({'python': {'filename': 'synthetic'}, 'wheels': []}))
            def transport(argv, timeout):
                self.assertIn(timeout, (30, 720))
                if '-c' in argv:
                    return 0, (b'ACTUAL_NATIVE_FSUID_DAC_GREEN' if 'test_public_operator' in argv[-1]
                               else b'ACTUAL_NATIVE_CONTEXT_GREEN')
                case = 'r5_success' if argv[-1].endswith('profile_ci.py') else argv[-1]
                events.append(case)
                self.assertEqual(timeout, 720)
                if case != 'r5_success': return 0, case.encode()
                if external_timeout: raise RuntimeError('PRIVATE_TIMEOUT')
                meta = metadata()
                if malformed: meta['PRIVATE'] = 'PRIVATE'
                if missing_profile: meta['profile'] = None
                native = json.dumps({'native_failure': deadline_failure()}).encode() if failure else b'r5_success'
                return int(failure), native+b'\n'+metadata_line(meta)
            def validate(raw, case, hashes):
                self.assertEqual(raw, case.encode())
                return {'scenario': case, 'owner_timing': base_tests.PublicOperatorCI.owner_timing_fixture()}
            def cleanup(container, owner):
                events.append('cleanup:'+container.rsplit('-', 2)[-2]+'-'+container.rsplit('-', 1)[-1])
                if cleanup_fails and container.endswith('r5-success'): raise RuntimeError('PRIVATE_CLEANUP')
            env = {'RUNNER_TEMP': str(base), 'CONTROL_POLICY_READ_TOKEN': 'github_pat_SYNTHETIC',
                'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
            with patch.dict(os.environ, env), patch.object(ci.boundary, 'runtime_binding', return_value='1'*40), \
                    patch.object(ci.boundary, 'private_root', return_value=root), patch.object(ci, 'fetch_control', return_value=(root, {})), \
                    patch.object(ci.operator, 'INFRA_FILES', {}), patch.object(ci, 'diagnostic_codes', return_value=allowed_codes), \
                    patch.object(build, 'fetch', return_value=b'SYNTHETIC'), \
                    patch.object(ci, 'command', return_value=('sha256:'+'a'*64).encode()), \
                    patch.object(ci, 'inspect_guest'), patch.object(ci, 'ready'), \
                    patch.object(ci.boundary, 'bounded', side_effect=transport), patch.object(ci, 'validate_report', side_effect=validate), \
                    patch.object(ci, 'progress'), patch.object(ci.boundary, 'cleanup_container', side_effect=cleanup), \
                    patch.object(ci.boundary, 'remove_private') as private_cleanup, \
                    patch.object(maintenance, 'run_cases', side_effect=lambda *a: events.append('original-recovery') or {'calibration': {}}), \
                    patch.object(maintenance, 'publish_calibration'), contextlib.redirect_stdout(output):
                result_code = ci.run(work, 'tu1nz-public-operator-private:123-1')
            private_cleanup.assert_called_once()
        self.assertNotIn('PRIVATE', output.getvalue().replace('PRIVATE_OPERATOR_CI_GREEN', '').replace('PRIVATE_OPERATOR_CI_RED', ''))
        return result_code, json.loads(output.getvalue().splitlines()[-1]), events

    def test_order_exact_preceding_18_other_argv_unchanged_and_full_entries_continue(self):
        self.assertEqual(ci.CASES[:18], self.preceding); self.assertEqual(ci.CASES[18], 'r5_success')
        for case in ci.CASES:
            if case == 'r5_success': continue
            self.assertEqual(ci.native_case_argv('owned', case), ['/usr/bin/docker', 'exec', 'owned',
                '/usr/bin/python3', '-I', '-B', '/source/tests/public_operator_native.py', '--scenario', case])
        code, result, events = self.simulate()
        self.assertEqual(code, 0); self.assertTrue(result['green'])
        self.assertEqual([e for e in events if not e.startswith('cleanup:')], [*ci.CASES, 'original-recovery'])
        self.assertEqual(result['r5_measurement']['container_cleanup'], 'PASS')
        self.assertEqual(result['r5_measurement']['private_input_cleanup'], 'PASS')

    def test_deadline_stays_fail_retains_measurements_and_both_cleanup_results(self):
        code, result, events = self.simulate(failure=True)
        self.assertEqual(code, 1); self.assertFalse(result['green'])
        self.assertEqual(result['stage'], 'r5_success-production'); self.assertEqual(result['code'], 'NATIVE_CASE_RED')
        self.assertEqual(result['failure_location'], deadline_failure())
        measured = result['r5_measurement']
        self.assertEqual(measured['native_exit'], 1); self.assertEqual(measured['metadata'], metadata())
        self.assertEqual(measured['owner_timing']['elapsed_ns'], 120_054_096_192)
        self.assertFalse(measured['owner_timing']['finish_completed'])
        self.assertEqual(measured['container_cleanup'], 'PASS'); self.assertEqual(measured['private_input_cleanup'], 'PASS')
        self.assertEqual([e for e in events if not e.startswith('cleanup:')], [*self.preceding, 'r5_success'])

    def test_cleanup_failure_does_not_replace_deadline_or_claim_cleanup_success(self):
        code, result, _ = self.simulate(failure=True, cleanup_fails=True)
        self.assertEqual(code, 1); self.assertEqual(result['failure_location'], deadline_failure())
        self.assertEqual(result['r5_measurement']['container_cleanup'], 'FAIL')
        self.assertEqual(result['cleanup_errors'], ['OWNED_CONTAINER_CLEANUP_RED'])

    def test_invalid_or_missing_profile_fails_closed_but_preserves_native_failure(self):
        for failure, malformed, missing in ((False, True, False), (True, True, False), (False, False, True)):
            with self.subTest(failure=failure, malformed=malformed, missing=missing):
                code, result, events = self.simulate(failure=failure, malformed=malformed, missing_profile=missing)
                self.assertEqual(code, 1); self.assertNotIn('original-recovery', events)
                self.assertEqual(result['r5_measurement']['container_cleanup'], 'PASS')
                if failure: self.assertEqual(result['failure_location'], deadline_failure())

    def test_outer_process_timeout_cannot_fabricate_metrics_cleanup_still_attempted(self):
        code, result, events = self.simulate(external_timeout=True)
        self.assertEqual(code, 1); self.assertNotIn('original-recovery', events)
        self.assertIsNone(result['r5_measurement']['metadata'])
        self.assertEqual(result['r5_measurement']['metadata_status'], 'MISSING_OR_INVALID')
        self.assertEqual(result['r5_measurement']['container_cleanup'], 'PASS')


if __name__ == '__main__': unittest.main()
