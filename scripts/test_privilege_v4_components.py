import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import tu1nz_trendwatch_v4 as tw
import tu1nz_codex_broker_v4 as broker
import tu1nz_privilege_readonly_v4 as reader
import tu1nz_privilege_v4_launcher as launcher


class PrivateFixture(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.fail('offline tests must be unprivileged')
        self.tmp = tempfile.TemporaryDirectory(prefix='privilege-v4-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.path.chmod(0o700)

    def state(self):
        state = tw.State(self.path)
        self.addCleanup(state.close)
        return state


class TrendwatchTests(PrivateFixture):
    day = datetime.date(2026, 9, 27)
    credentials = {'token': 'fake-never-network', 'destination': 'fake-target'}

    def execute(self, state, slot='morning', transport=None, credentials=None):
        return tw.run_slot(state, slot, self.day, '<unsafe & title>', 'Musik',
                           transport or (lambda *_: True), credentials or self.credentials)

    def test_four_contexts_exactly_one_attempt(self):
        s = self.state()
        seen = []
        for slot in tw.SLOTS:
            send = lambda body, _: seen.append(body) or True
            self.assertEqual(self.execute(s, slot, send), 'SENT')
            self.assertEqual(self.execute(s, slot, send), 'ALREADY_SENT')
        self.assertEqual(len(seen), 4)
        self.assertNotIn('<unsafe', seen[0])
        self.assertEqual(s.read('today_title.txt'), b'AI Pet Transform\n')

    def test_timeout_is_not_retried(self):
        s = self.state()
        calls = []
        def timeout(*_):
            calls.append(1)
            raise TimeoutError('secret exception must not leak')
        self.assertEqual(self.execute(s, transport=timeout), 'DELIVERY_UNCERTAIN_NO_RETRY')
        self.assertEqual(self.execute(s, transport=timeout), 'DELIVERY_UNCERTAIN_NO_RETRY')
        self.assertEqual(calls, [1])
        self.assertNotIn(b'secret', s.read(tw.slot_key('morning', self.day) + '.json'))

    def test_negative_provider_acknowledgement(self):
        s = self.state()
        self.assertEqual(self.execute(s, transport=lambda *_: False), 'DELIVERY_UNCERTAIN_NO_RETRY')

    def test_missing_credentials_does_not_write_state(self):
        s = self.state()
        with self.assertRaises(tw.UnsafeState):
            tw.run_slot(s, 'morning', self.day, '', 'Musik', lambda *_: True, {})
        self.assertEqual(set(p.name for p in self.path.iterdir()), {'lock'})

    def test_corrupt_state_is_rejected(self):
        s = self.state()
        for raw in [b'not-json', b'[]', b'{}', b'{"state":"SENT"}']:
            with self.subTest(raw=raw):
                with self.assertRaises(tw.UnsafeState):
                    tw.load_record(raw, 'key')

    def test_state_symlink_rejected(self):
        s = self.state()
        target = self.path / 'other'
        target.write_bytes(b'untouched')
        (self.path / 'today_title.txt').symlink_to(target)
        with self.assertRaises(OSError):
            self.execute(s)
        self.assertEqual(target.read_bytes(), b'untouched')

    def test_state_hardlink_rejected(self):
        s = self.state()
        target = self.path / 'other'
        target.write_bytes(b'untouched')
        target.chmod(0o600)
        os.link(target, self.path / 'today_title.txt')
        with self.assertRaises(tw.UnsafeState):
            self.execute(s)
        self.assertEqual(target.read_bytes(), b'untouched')

    def test_parallel_start_rejected(self):
        self.state()
        with self.assertRaises(BlockingIOError):
            tw.State(self.path)

    def test_directory_swap_rejected(self):
        s = self.state()
        moved = self.path.parent / (self.path.name + '-moved')
        self.path.rename(moved)
        self.path.mkdir(mode=0o700)
        try:
            with self.assertRaises(tw.UnsafeState):
                s.write('test', b'test')
        finally:
            self.path.rmdir()
            moved.rename(self.path)

    def test_unexpected_mode_rejected(self):
        self.path.chmod(0o770)
        with self.assertRaises(tw.UnsafeState):
            tw.State(self.path)

    def test_unexpected_file_type_rejected(self):
        s = self.state()
        os.mkfifo(self.path / 'today_title.txt', 0o600)
        with self.assertRaises(tw.UnsafeState):
            self.execute(s)

    def test_unsafe_name_rejected(self):
        s = self.state()
        for name in ['../escape', '/tmp/escape', 'nested/file']:
            with self.assertRaises(tw.UnsafeState):
                s.write(name, b'bad')

    def test_atomic_modes_and_no_temporary_remains(self):
        s = self.state()
        self.execute(s)
        for p in self.path.iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            self.assertFalse(p.name.startswith('.new-'))

    def test_persistent_duplicate_and_missed_slot_reporting(self):
        key = tw.slot_key('morning', self.day)
        self.assertEqual(tw.missed_slots({key}, self.day, 15), ['midday', 'afternoon'])
        s = self.state()
        self.execute(s)
        self.assertEqual(self.execute(s), 'ALREADY_SENT')

    def test_service_templates_do_not_restart_or_change_timers(self):
        for context in tw.SLOTS:
            unit = tw.render_service(context)
            self.assertIn('User=tu1nz-trendwatch\n', unit)
            self.assertIn('NoNewPrivileges=yes\n', unit)
            self.assertIn('StateDirectoryMode=0700\n', unit)
            self.assertNotIn('sudo', unit)
            self.assertNotIn('Persistent=', unit)
            self.assertNotIn('OnCalendar=', unit)
            self.assertIn('Restart=no', unit)
        with self.assertRaises(tw.UnsafeState):
            tw.render_service('../unknown')

    def test_default_acl_is_not_silently_accepted(self):
        import subprocess
        subprocess.run(['/usr/bin/setfacl', '-m', 'd:u::rwx,d:g::rwx,d:o::---', str(self.path)], check=True)
        try:
            with self.assertRaises(tw.UnsafeState):
                tw.State(self.path)
        finally:
            subprocess.run(['/usr/bin/setfacl', '-k', str(self.path)], check=True)

    def test_root_runtime_forbidden(self):
        with mock.patch.object(tw.os, 'geteuid', return_value=0):
            with self.assertRaises(tw.UnsafeState):
                tw.State(self.path)

    def test_exception_after_pending_never_silently_retries(self):
        s = self.state()
        def interrupted(*_):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.execute(s, transport=interrupted)
        self.assertEqual(self.execute(s), 'DELIVERY_UNCERTAIN_NO_RETRY')


class BrokerTests(unittest.TestCase):
    def test_exact_operations(self):
        for op in broker.OPS:
            self.assertEqual(broker.parse([op]), op)

    def test_malicious_or_extra_arguments(self):
        for args in [[], ['status', '--help'], ['containers', 'exec'], ['sh'],
                     ['status;id'], ['../status'], ['status\n'], ['--help']]:
            with self.assertRaises(ValueError):
                broker.parse(args)

    def test_sudoers_has_no_wildcards_or_general_tools(self):
        text = broker.sudoers()
        self.assertEqual(len(text.splitlines()), len(broker.OPS))
        self.assertNotIn('*', text)
        self.assertNotIn('NOPASSWD: ALL', text)
        for line in text.splitlines():
            self.assertTrue(line.startswith('chatops ALL=(root) NOPASSWD: NOSETENV: /usr/local/sbin/tu1nz-codex-ops '))

    def test_environment_has_no_user_values(self):
        with mock.patch.dict(os.environ, {'PATH': '/evil', 'DOCKER_HOST': 'tcp://evil', 'PYTHONPATH': '/evil'}):
            self.assertNotIn('/evil', json.dumps(broker.ENV))
            self.assertNotIn('DOCKER_HOST', broker.ENV)
            for command in broker.COMMANDS.values():
                self.assertTrue(command[0].startswith('/usr/'))

    def test_container_output_suppresses_secrets(self):
        data = [{'Name': '/' + name, 'State': {'Status': 'running', 'Health': {'Status': 'healthy', 'Log': ['SECRET']}},
                 'RestartCount': 0, 'Config': {'Env': ['TOKEN=SECRET']}} for name in broker.CONTAINERS]
        result = broker.sanitize('containers', json.dumps(data).encode())
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(len(result), 3)

    def test_unknown_container_and_duplicates_rejected(self):
        for names in [('unknown',) * 3, (broker.CONTAINERS[0],) * 3]:
            data = [{'Name': n, 'State': {'Status': 'running'}, 'RestartCount': 0} for n in names]
            with self.assertRaises(ValueError):
                broker.sanitize('containers', json.dumps(data).encode())

    def test_journal_never_returns_message(self):
        result = broker.sanitize('journal-counts', b'{"PRIORITY":"3","MESSAGE":"SECRET"}\n')
        self.assertEqual(result['3'], 1)
        self.assertNotIn('SECRET', json.dumps(result))

    def test_invalid_json_rejected(self):
        for op in ['containers', 'journal-counts']:
            with self.assertRaises(ValueError):
                broker.sanitize(op, b'not-json')

    def test_repo_execution_refused(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            self.assertEqual(broker.main(), 77)


class CollectorTests(PrivateFixture):
    def test_suppression_of_tokens_messages_and_values(self):
        fake = b'TOKEN=do-not-leak\ntee /opt/trendwatch/today_title.txt\nmessage=PERSONAL\n'
        out = json.dumps(reader.summary(fake))
        for secret in ['do-not-leak', 'PERSONAL', 'TOKEN=']:
            self.assertNotIn(secret, out)
        self.assertIn('today_title.txt', out)

    def test_atomic_file_and_hash(self):
        store = reader.Store(self.path)
        store.write('result.json', b'{}')
        self.assertEqual(store.hashes['result.json'], hashlib.sha256(b'{}').hexdigest())
        self.assertEqual(stat.S_IMODE((self.path / 'result.json').stat().st_mode), 0o600)
        self.assertEqual(len(list(self.path.iterdir())), 1)

    def test_existing_foreign_output_rejected(self):
        store = reader.Store(self.path)
        store.write('result.json', b'original')
        with self.assertRaises(ValueError):
            store.write('result.json', b'changed')
        self.assertEqual((self.path / 'result.json').read_bytes(), b'original')

    def test_section_failure_preserves_previous_result(self):
        store = reader.Store(self.path)
        store.section('first', lambda: {'ok': True})
        digest = store.hashes['first.json']
        def fail():
            raise PermissionError('SECRET')
        result = store.section('second', fail)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertNotIn('SECRET', (self.path / 'second.json').read_text())
        self.assertEqual(hashlib.sha256((self.path / 'first.json').read_bytes()).hexdigest(), digest)

    def test_timeout_classification(self):
        store = reader.Store(self.path)
        with mock.patch.object(reader.subprocess, 'run', side_effect=TimeoutError('SECRET')):
            result = store.section('units', reader.unit_states)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['exception_class'], 'TimeoutError')

    def test_nonzero_command_rejected(self):
        with mock.patch.object(reader.subprocess, 'run', return_value=mock.Mock(returncode=1, stdout=b'', stderr=b'SECRET')):
            with self.assertRaises(ValueError):
                reader.unit_states()

    def test_unexpected_command_output_fails_closed(self):
        with mock.patch.object(reader.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout=b'Environment=SECRET', stderr=b'')):
            with self.assertRaises(ValueError):
                reader.unit_states()

    def test_missing_program_is_partial(self):
        store = reader.Store(self.path)
        with mock.patch.object(reader.subprocess, 'run', side_effect=FileNotFoundError('SECRET')):
            result = store.section('units', reader.unit_states)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertNotIn('SECRET', json.dumps(result))

    def test_missing_input_is_explicit_absence(self):
        store = reader.Store(self.path)
        self.assertTrue(reader.read_file(self.path / 'missing', store, 0)['absent'])

    def test_input_symlink_rejected(self):
        store = reader.Store(self.path)
        target = self.path / 'target'
        target.write_bytes(b'never read via link')
        link = self.path / 'link'
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            reader.read_file(link, store, 0)

    def test_raw_file_is_private_and_summary_only(self):
        store = reader.Store(self.path)
        source = self.path / 'source'
        source.write_bytes(b'RAW_SECRET')
        result = reader.read_file(source, store, 1)
        self.assertNotIn('RAW_SECRET', json.dumps(result))
        self.assertEqual(stat.S_IMODE((self.path / 'raw-0001.bin').stat().st_mode), 0o600)

    def test_interruption_keeps_section_evidence(self):
        store = reader.Store(self.path)
        store.section('first', lambda: 1)
        def interrupt():
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            store.section('second', interrupt)
        self.assertEqual(len(store.entries), 2)
        self.assertEqual(store.entries[1]['status'], 'INCOMPLETE')

    def test_main_writes_incomplete_manifest_after_interruption(self):
        import contextlib
        import io
        output = io.StringIO()
        with mock.patch.dict(reader.__dict__, {'_VERIFIED_SOURCE_SHA256': 'a' * 64}), \
             mock.patch.object(reader, 'BASE', self.path), \
             mock.patch.object(reader, 'FILES', ('fixture',)), \
             mock.patch.object(reader, 'TREES', ()), \
             mock.patch.object(reader, 'protected_directory'), \
             mock.patch.object(reader, 'read_file', side_effect=KeyboardInterrupt()), \
             mock.patch.object(reader.os, 'getuid', return_value=0), \
             mock.patch.object(reader.os, 'geteuid', return_value=0), \
             mock.patch.object(reader.os, 'umask'), \
             mock.patch.object(reader.signal, 'signal'), \
             mock.patch.object(reader.sys, 'argv', ['fixture']), \
             mock.patch.dict(os.environ, {}, clear=False), \
             contextlib.redirect_stdout(output):
            self.assertEqual(reader.main(), 2)
        report = json.loads(output.getvalue())
        manifest_path = Path(report['directory']) / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest['status'], 'INCOMPLETE')
        self.assertTrue(manifest['interrupted'])
        self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
        for name, expected in manifest['file_hashes'].items():
            self.assertEqual(hashlib.sha256((manifest_path.parent / name).read_bytes()).hexdigest(), expected)

    def test_launcher_rejects_drift_before_sudo(self):
        import shlex
        source = b'pass\n'
        record = launcher.build(source, 'a' * 40)
        remote_code = shlex.split(record['argv'][-1])[-1]
        with mock.patch.object(launcher.Path if hasattr(launcher, 'Path') else Path, 'read_bytes', return_value=b'changed'), \
             mock.patch('subprocess.check_output', return_value='a' * 40 + '\n'), \
             mock.patch('subprocess.call') as invoke:
            with self.assertRaises(AssertionError):
                exec(compile(remote_code, '<offline-launcher-test>', 'exec'), {})
        invoke.assert_not_called()

    def test_launcher_hash_and_invalid_commit(self):
        script = b'print("offline fixture")\n'
        result = launcher.build(script, 'a' * 40)
        self.assertEqual(result['sha256'], hashlib.sha256(script).hexdigest())
        self.assertIn('StrictHostKeyChecking=yes', result['argv'])
        self.assertIn('/usr/bin/sudo', result['shell_line'])
        self.assertIn("-S", result['shell_line'])
        with self.assertRaises(ValueError):
            launcher.build(script, 'bad;command')


if __name__ == '__main__':
    unittest.main()
