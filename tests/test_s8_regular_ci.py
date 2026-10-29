"""Portable regular-CI wiring checks; never native Docker/kernel evidence."""
import ast
import copy
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests import s8_regular_suite as gate

ROOT = Path(__file__).resolve().parents[1]


class RegularS8BindingTests(unittest.TestCase):
    def test_exact_150_unique_cases_preserve_122_original_plus_28_new(self):
        suite, ids, core = gate.collect()
        self.assertEqual(len(ids), 150); self.assertEqual(len(set(ids)), 150)
        self.assertEqual(len(core), 46); self.assertTrue(set(core) <= set(ids))
        self.assertEqual(sum('.NativeSealMetadataTests.' in name for name in ids), 8)
        self.assertEqual(sum(name.startswith('tests.test_s8_seal_metadata.') for name in ids), 28)
        self.assertEqual(sum('test_interruption_after_each_anchor_mutation' in name for name in ids), 1)
        self.assertEqual(tuple(sorted(name for name in ids if '.NativeSealMetadataTests.' in name)), gate.NEW_NATIVE_IDS)

    def test_original_module_selection_retained_and_no_measurement_import(self):
        self.assertEqual(gate.MODULES[:-1], (
            'tests.test_s8_anchor','tests.test_s8_path_policy','tests.test_s8_execution_contract',
            'tests.test_s8_new_stock','tests.test_s8_protected_journal','tests.test_s8_journal_kernel_barrier',
            'tests.test_s8_admission_channel','tests.test_s8_frozen_entry','tests.test_s8_execution_observer',
            'tests.test_s8_historical_capacity','tests.test_s8_history_operator'))
        self.assertEqual(gate.MODULES[-1], 'tests.test_s8_seal_metadata')
        for name in (*gate.MODULES, *gate.CORE_SELECTORS):
            self.assertNotIn('measurement', name); self.assertNotIn('evidence_export', name)

    def test_missing_import_duplicate_missing_core_or_changed_kernel_ids_reject(self):
        suite, ids, core_ids = gate.collect(); cases = list(gate.flatten(suite))
        core = list(gate.flatten(unittest.TestLoader().loadTestsFromNames(gate.CORE_SELECTORS)))
        failed = next(iter(unittest.TestLoader().loadTestsFromName('tests.__missing_regular_s8')))
        for all_cases, core_cases in ((cases[:-1] + [failed], core), (cases[:-1], core),
                                      (cases[:-1] + [cases[0]], core), (cases, core[:-1])):
            loader = Mock(); loader.loadTestsFromNames.side_effect = [unittest.TestSuite(all_cases), unittest.TestSuite(core_cases)]
            with self.assertRaises(ValueError): gate.collect(loader)
        with patch.object(gate, 'NEW_NATIVE_IDS', (*gate.NEW_NATIVE_IDS[:-1], 'other')):
            with self.assertRaisesRegex(ValueError, 'NEW_KERNEL_COLLECTION_RED'): gate.collect()
        with patch.object(gate, 'EXPECTED_IDS_SHA256', '0'*64):
            with self.assertRaisesRegex(ValueError, 'SELECTION_BINDING_RED'): gate.collect()
        with patch.object(gate, 'EXPECTED_CORE_IDS_SHA256', '0'*64):
            with self.assertRaisesRegex(ValueError, 'CORE_BINDING_RED'): gate.collect()

    def result(self):
        _, ids, core = gate.collect()
        return SimpleNamespace(testsRun=len(ids), seen_ids=list(ids), success_ids=list(ids),
                               skipped=[], errors=[], failures=[], expectedFailures=[], unexpectedSuccesses=[]), ids, core

    def test_only_all_actual_pass_is_green(self):
        result, ids, core = self.result()
        v = gate.evaluate(result, ids, core, gate.NEW_NATIVE_IDS)
        self.assertEqual((v['verdict'],v['executed'],v['core_passed'],v['new_kernel_passed']), ('GREEN',150,46,8))
        self.assertEqual(v['codes'], [])

    def test_skip_failure_error_partial_duplicate_or_success_count_drift_are_hold(self):
        good, ids, core = self.result()
        variants = [dict(skipped=[('synthetic','not copied')]), dict(errors=[('synthetic','not copied')]),
                    dict(failures=[('synthetic','not copied')]), dict(testsRun=149),
                    dict(expectedFailures=[('synthetic','not copied')]), dict(unexpectedSuccesses=['synthetic']),
                    dict(seen_ids=ids[:-1]), dict(seen_ids=[*ids[:-1],ids[0]]),
                    dict(success_ids=ids[:-1]), dict(success_ids=[*ids,ids[0]])]
        for fields in variants:
            result = copy.deepcopy(good); result.__dict__.update(fields)
            v = gate.evaluate(result, ids, core, gate.NEW_NATIVE_IDS)
            self.assertEqual(v['verdict'], 'HOLD'); self.assertTrue(v['codes'])
            self.assertNotIn('not copied', json.dumps(v))

    def test_skipped_required_kernel_case_cannot_hide_behind_other_passes(self):
        result, ids, core = self.result()
        missing = gate.NEW_NATIVE_IDS[0]
        result.success_ids.remove(missing); result.skipped = [(missing,'unsupported synthetic kernel')]
        v = gate.evaluate(result, ids, core, gate.NEW_NATIVE_IDS)
        self.assertIn('S8_CI_SKIP_RED', v['codes']); self.assertIn('S8_CI_NEW_KERNEL_NOT_ALL_PASS',v['codes'])
        self.assertEqual(v['new_kernel_passed'],7)

    def test_negative_assertion_is_pass_but_class_cleanup_failure_remains_red(self):
        class Synthetic(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                def cleanup(): raise OSError('synthetic cleanup failure')
                cls.addClassCleanup(cleanup)
            def test_negative(self):
                with self.assertRaises(ValueError): raise ValueError('synthetic guard red')
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Synthetic)
        ids = [test.id() for test in suite]
        result = unittest.TextTestRunner(stream=io.StringIO(), resultclass=gate.Result).run(suite)
        self.assertEqual(result.success_ids, ids)
        v = gate.evaluate(result,ids,ids,ids)
        self.assertIn('S8_CI_ERROR_RED',v['codes']); self.assertEqual(v['verdict'],'HOLD')

    def test_real_result_preserves_expected_negative_assertion_success(self):
        class Synthetic(unittest.TestCase):
            def test_negative(self):
                with self.assertRaises(ValueError): raise ValueError('synthetic')
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Synthetic)
        ids = [test.id() for test in suite]
        result = unittest.TextTestRunner(stream=io.StringIO(), resultclass=gate.Result).run(suite)
        self.assertEqual(gate.evaluate(result,ids,ids,ids)['verdict'],'GREEN')

    def test_collection_only_never_executes_or_claims_native_pass(self):
        output = io.StringIO()
        with (patch.object(gate, 'native_platform', side_effect=AssertionError('must not probe')),
              patch.object(gate.unittest, 'TextTestRunner', side_effect=AssertionError('must not execute')),
              redirect_stdout(output)):
            self.assertEqual(gate.main(['--check']),0)
        v=json.loads(output.getvalue().removeprefix('S8_REGULAR_CI '))
        self.assertEqual(v['execution'],'NOT_RUN_NATIVE_OPEN'); self.assertNotEqual(v.get('verdict'),'GREEN')

    def test_nonisolated_execution_fails_before_running_tests(self):
        output=io.StringIO()
        with patch.object(gate,'native_platform',return_value=False), patch.object(gate.unittest,'TextTestRunner') as run, redirect_stdout(output):
            self.assertEqual(gate.main([]),1)
        run.assert_not_called();self.assertIn('S8_CI_ISOLATED_PID1_REQUIRED',output.getvalue())

    def test_cli_does_not_accept_replacement_test_selection(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            gate.main(['--tests','arbitrary'])
        self.assertEqual(error.exception.code,2)

    def test_existing_three_jobs_permissions_deadlines_and_private_boundary_retained(self):
        raw=(ROOT/'.github/workflows/control-validation.yml').read_text()
        jobs=raw.split('jobs:\n',1)[1]
        self.assertEqual(re.findall(r'^  ([a-z0-9-]+):$',jobs,re.M),
                         ['b-data-handoff','control-private-provenance','restore-contract'])
        before,restore=raw.split('  restore-contract:\n',1)
        for value in ('timeout-minutes: 10','timeout-minutes: 60','environment: control-private-ci',
                      'ref: ${{ github.event.pull_request.head.sha || github.sha }}'):
            self.assertIn(value,before)
        self.assertIn('timeout-minutes: 75',restore);self.assertIn('needs: control-private-provenance',restore)
        self.assertIn('run: bash tests/s8_anchor_native.sh',restore)
        self.assertNotIn('CONTROL_POLICY_READ_TOKEN',restore)
        self.assertNotIn('pull_request_target:',raw)

    def test_launcher_calls_checked_runner_once_and_keeps_historical_ext4_gate(self):
        raw=(ROOT/'tests/s8_anchor_native.sh').read_text()
        self.assertEqual(raw.count('python3 -B -m unittest -v tests.test_s8_regular_ci'),1)
        self.assertEqual(raw.count('docker exec "$native" python3 -B tests/s8_regular_suite.py'),1)
        self.assertNotIn('s8_regular_suite.py --check',raw)
        self.assertIn('docker exec "$native" bash tests/s8_historical_kernel_native.sh',raw)
        for old in ('s8_parent_rebind_counterexample.py','--privileged --cgroupns=private','--network none',
                    '--tmpfs /run','--tmpfs /run/lock','--tmpfs /tmp','dst=/source,readonly','docker stop --time 20'):
            self.assertIn(old,raw)
        for excluded in ('s8_seal_native_once','s8_primary_measurement','s8_evidence_export'):
            self.assertNotIn(excluded,raw)

    def test_changed_guard_modules_are_existing_installer_members_and_dependencies_resolve(self):
        from scripts import tu1nz_s8_frozen_entry as entry
        release = ast.parse((ROOT/'scripts/tu1nz_s8_execution_release.py').read_bytes())
        source_names = next(node.value for node in release.body if isinstance(node,ast.Assign)
                            and any(isinstance(target,ast.Name) and target.id=='SOURCE_NAMES' for target in node.targets))
        names=('tu1nz_s8_anchor_bootstrap','tu1nz_s8_existing_dropin','tu1nz_s8_journal_fence',
               'tu1nz_s8_new_stock','tu1nz_s8_path_policy','tu1nz_s8_protected_journal')
        # This script's bare imports are loaded by the real frozen installer;
        # do not accidentally rely on another test having populated sys.path.
        self.assertIsInstance(source_names,ast.Name);self.assertEqual(source_names.id,'INSTALLER_MODULES')
        self.assertTrue(set(names)<=set(entry.INSTALLER_MODULES))
        for name in names:
            tree=ast.parse((ROOT/'scripts'/(name+'.py')).read_bytes())
            for node in ast.walk(tree):
                if isinstance(node,ast.ImportFrom) and (node.module or '').startswith('tu1nz_s8_'):
                    self.assertIn(node.module,entry.INSTALLER_MODULES)
        for name in entry.INSTALLER_MODULES:
            self.assertTrue((ROOT/'scripts'/(name+'.py')).is_file())


if __name__ == '__main__': unittest.main()
