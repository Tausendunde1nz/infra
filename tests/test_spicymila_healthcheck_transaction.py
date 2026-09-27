import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('health_tx', Path(__file__).parents[1] / 'scripts' / 'tu1nz_spicymila_healthcheck_transaction.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

class Fake:
    def __init__(self, candidate=False, fail=None, rollback_fail=False):
        self.candidate = candidate
        self.fail = fail
        self.rollback_fail = rollback_fail
        self.calls = []
    def preflight(self):
        if self.fail == 'preflight': raise m.Refuse('drift')
        return self.candidate
    def event(self, name, value): self.calls.append(name)
    def write(self, candidate):
        self.calls.append(('write', candidate))
        if self.fail == 'write': raise m.Refuse('write failed')
        self.candidate = candidate
    def recreate(self, candidate):
        self.calls.append(('recreate', candidate))
        if self.fail == 'recreate': raise m.Refuse('recreation failed')
    def observe(self):
        self.calls.append('observe')
        if self.fail == 'observe': raise m.Refuse('healthy timeout')
        return {'stable_seconds': 181, 'container_id': 'synthetic'}
    def rollback(self):
        self.calls.append('rollback')
        if self.rollback_fail: raise m.Refuse('rollback failed')
        self.candidate = False

class FlowTests(unittest.TestCase):
    def test_success_and_idempotent_second_apply(self):
        f = Fake()
        self.assertEqual(m.activate(f), 'APPLIED')
        f.calls.clear()
        self.assertEqual(m.activate(f), 'ALREADY_APPLIED')
        self.assertNotIn(('write', True), f.calls)
        self.assertNotIn(('recreate', True), f.calls)
    def test_precondition_drift_does_not_mutate_or_rollback_foreign_state(self):
        f = Fake(fail='preflight')
        with self.assertRaises(m.Refuse): m.activate(f)
        self.assertEqual(f.calls, [])
    def test_write_recreate_and_health_failures_roll_back(self):
        for failure in ('write', 'recreate', 'observe'):
            with self.subTest(failure=failure):
                f = Fake(fail=failure)
                with self.assertRaisesRegex(m.Refuse, 'original configuration restored'): m.activate(f)
                self.assertFalse(f.candidate)
                self.assertIn('rollback', f.calls)
                self.assertNotIn('SUCCESS', f.calls)
    def test_existing_candidate_health_failure_rolls_back(self):
        f = Fake(candidate=True, fail='observe')
        with self.assertRaises(m.Refuse): m.activate(f)
        self.assertIn('rollback', f.calls)
    def test_failed_rollback_never_reports_success(self):
        f = Fake(fail='observe', rollback_fail=True)
        with self.assertRaisesRegex(m.Refuse, 'manual recovery'): m.activate(f)
        self.assertIn('ROLLBACK_FAILED', f.calls)
        self.assertNotIn('SUCCESS', f.calls)


def container(candidate=False):
    return {'Id': 'a' * 64, 'Image': 'sha256:synthetic', 'Config': {
        'Hostname': 'a' * 12, 'Env': ['B=2', 'A=1'], 'Labels': {'stable': 'yes'},
        'Healthcheck': {'Test': ['CMD', 'curl', '-fsS', m.NEW if candidate else m.OLD]}},
        'HostConfig': {'PortBindings': {'8080/tcp': [{'HostPort': '8090'}]}, 'Memory': 0},
        'Mounts': [], 'NetworkSettings': {'Networks': {'isolated': {'NetworkID': 'network', 'Aliases': ['bot']}},
                                        'Ports': {'8080/tcp': [{'HostPort': '8090'}]}},
        'State': {'Running': True, 'Health': {'Status': 'healthy', 'Log': [{'ExitCode': 0}] * 3}},
        'RestartCount': 0}

class ConfigTests(unittest.TestCase):
    def test_only_health_target_and_generated_identity_are_ignored(self):
        original = container()
        changed = container(True)
        changed['Id'] = 'b' * 64
        changed['Config']['Hostname'] = 'b' * 12
        changed['Config']['Env'].reverse()
        self.assertEqual(m.normalized(original), m.normalized(changed, True))
        mutations = [lambda d: d['HostConfig'].update(Memory=1),
                     lambda d: d.update(Image='different'),
                     lambda d: d['Config']['Env'].append('UNEXPECTED=1'),
                     lambda d: d['Mounts'].append({'Source': '/unexpected'}),
                     lambda d: d['NetworkSettings']['Ports'].update({'9100/tcp': []}),
                     lambda d: d['NetworkSettings']['Networks']['isolated'].update(NetworkID='other')]
        for mutation in mutations:
            d = copy.deepcopy(changed); mutation(d)
            self.assertNotEqual(m.normalized(original), m.normalized(d, True))
    def test_unknown_healthcheck_command_rejected(self):
        d = container(True); d['Config']['Healthcheck']['Test'].append('unexpected')
        with self.assertRaises(m.Refuse): m.normalized(d, True)

class FileTests(unittest.TestCase):
    def test_exact_apply_restore_metadata_and_foreign_edit_refusal(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'compose.yml'
            original = b'healthcheck: old\nports: unchanged\n'
            candidate = b'healthcheck: new\nports: unchanged\n'
            source.write_bytes(original); source.chmod(0o640)
            r = object.__new__(m.Runtime); r.original = original; r.candidate = candidate
            with patch.object(m, 'SOURCE', source):
                r.manifest = r.metadata()
                r.write(True)
                self.assertEqual(source.read_bytes(), candidate)
                self.assertEqual(r.metadata(), r.manifest)
                r.write(False)
                self.assertEqual(source.read_bytes(), original)
                self.assertEqual(r.metadata(), r.manifest)
                source.write_bytes(b'foreign change')
                with self.assertRaises(m.Refuse): r.write(True)
                self.assertEqual(source.read_bytes(), b'foreign change')
    def test_private_read_rejects_symlink_or_open_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'original'; p.write_bytes(b'private'); p.chmod(0o600)
            self.assertEqual(m.read_private(p), b'private')
            link = Path(td) / 'link'; link.symlink_to(p)
            with self.assertRaises(OSError): m.read_private(link)
            p.chmod(0o644)
            with self.assertRaises(m.Refuse): m.read_private(p)
    def test_operator_gate_precedes_any_runtime_access(self):
        with patch('sys.argv', ['tx', '--backup', '/nonexistent', '--manifest-sha256', 'none', '--mode', 'apply']):
            with self.assertRaisesRegex(m.Refuse, 'operator readiness'): m.main()

class ObservationTests(unittest.TestCase):
    def fake(self, healthy=True):
        r = object.__new__(m.Runtime); r.baseline = container()
        d = container(True)
        if not healthy: d['State']['Health']['Status'] = 'starting'
        r.inspect = lambda: copy.deepcopy(d)
        r.probe = lambda *a: copy.deepcopy(d)
        r.check_shared = lambda: None
        return r, d
    def clock(self):
        now = [0.0]
        def sleep(seconds): now[0] += seconds
        return now, sleep
    def test_stability_uses_elapsed_monotonic_time_and_cycles(self):
        r, _ = self.fake(); now, sleep = self.clock()
        with patch.object(m.time, 'monotonic', side_effect=lambda: now[0]), patch.object(m.time, 'sleep', side_effect=sleep):
            result = r.observe()
        self.assertGreaterEqual(result['stable_seconds'], 181)
    def test_no_healthy_status_times_out(self):
        r, _ = self.fake(False); now, sleep = self.clock()
        with patch.object(m.time, 'monotonic', side_effect=lambda: now[0]), patch.object(m.time, 'sleep', side_effect=sleep):
            with self.assertRaisesRegex(m.Refuse, 'deadline'): r.observe()
    def test_restarts_and_failed_health_cycles_are_rejected(self):
        for restart in (True, False):
            r, d = self.fake(); now, sleep = self.clock()
            if restart: d['RestartCount'] = 1
            else: d['State']['Health']['Log'][-1]['ExitCode'] = 7
            with patch.object(m.time, 'monotonic', side_effect=lambda: now[0]), patch.object(m.time, 'sleep', side_effect=sleep):
                with self.assertRaises(m.Refuse): r.observe()

class RecreationTests(unittest.TestCase):
    def test_exact_bounded_compose_command_and_image_guard(self):
        r = object.__new__(m.Runtime)
        r.baseline = container(); r.baseline['Config']['Image'] = 'existing-local-tag'
        r.manifest = {'image_id': 'sha256:synthetic'}
        r.backup = Path('/synthetic')
        r.compose = ['docker', 'compose', '-f', '/synthetic/compose.yml']
        calls = []
        def run(args, timeout=60):
            calls.append(args)
            if 'config' in args: return b'{}'
            if args[:3] == ['docker', 'image', 'inspect']: return b'[{"Id":"sha256:synthetic"}]'
            return b''
        r.run = run
        expected = copy.deepcopy(r.baseline); expected['Config']['Healthcheck']['Test'][-1] = m.NEW
        r.inspect = lambda: expected
        with patch.object(m, 'read_private', return_value=b'{}'):
            r.recreate(True)
        self.assertEqual(calls[-1], r.compose + ['up', '-d', '--no-deps', '--no-build', '--pull', 'never', '--force-recreate', 'spicymila_bot'])
        calls.clear(); r.manifest['image_id'] = 'different'
        with patch.object(m, 'read_private', return_value=b'{}'):
            with self.assertRaises(m.Refuse): r.recreate(True)
        self.assertFalse(any('up' in c for c in calls))
    def test_actual_rollback_control_flow_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'compose.yml'; path.write_bytes(b'candidate')
            r = object.__new__(m.Runtime); r.original = b'original'; r.candidate = b'candidate'
            r.baseline = container(); live = [container(True)]; calls = []
            r.manifest = dict(uid=1, gid=1, mode=0o640, acl='synthetic')
            r.metadata = lambda: dict(r.manifest)
            r.inspect = lambda: live[0]
            r.write = lambda candidate: path.write_bytes(r.candidate if candidate else r.original)
            def recreate(candidate):
                calls.append(candidate); live[0] = container(candidate)
            r.recreate = recreate; r.probe = lambda candidate: live[0]
            r.check_shared = lambda: None; r.event = lambda *args: None
            with patch.object(m, 'SOURCE', path):
                r.rollback(); r.rollback()
            self.assertEqual(calls, [False])
            self.assertEqual(path.read_bytes(), b'original')
    def test_interruption_during_observation_rolls_back(self):
        f = Fake()
        def interrupt(): raise KeyboardInterrupt()
        f.observe = interrupt
        with self.assertRaises(m.Refuse): m.activate(f)
        self.assertIn('rollback', f.calls)

if __name__ == '__main__': unittest.main()
