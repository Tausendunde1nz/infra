import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/tu1nz_spicymila_dependency_readonly_v2.py'
if not SCRIPT.exists():
    SCRIPT = Path(__file__).with_name('tu1nz_spicymila_dependency_readonly_v2.py')
spec = importlib.util.spec_from_file_location('collector_v2', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SECRET = 'PRIVATE_TOKEN_MESSAGE_MUST_NEVER_APPEAR_93ca'


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        os.chmod(self.base, 0o700)
        self.store = m.Store(self.base, 'collector-v2-20260927T000000Z-0123456789ab')

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def fake(self, source, timeout=2):
        return m.stream([sys.executable, '-c', source], m.journal_record, timeout)

    def read(self, name):
        return json.loads((self.store.path / name).read_text())

    def test_complete_atomic_manifest_modes(self):
        rc = m.Collector(self.store).run([('run', lambda: {'ok': True})])
        self.assertEqual(rc, 0)
        manifest = self.read('manifest.json')
        self.assertEqual(manifest['status'], 'COMPLETE')
        self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode), 0o700)
        self.assertFalse(list(self.store.path.glob('.pending-*')))
        for name, meta in manifest['artifacts'].items():
            p = self.store.path / name
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), meta['sha256'])
        for p in self.store.path.iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)

    def test_journal_timeout_continues_nat_and_preserves_prior(self):
        rc = m.Collector(self.store).run([
            ('protected-files', lambda: {'ok': True}),
            ('journal-000', lambda: self.fake('import time; time.sleep(10)', .1)),
            ('nat', lambda: {'ok': True})])
        self.assertEqual(rc, 2)
        self.assertTrue(self.read('protected-files.json')['data']['ok'])
        self.assertTrue(self.read('nat.json')['data']['ok'])
        self.assertTrue(self.read('journal-000-error.json')['timeout'])
        self.assertEqual(self.read('manifest.json')['status'], 'INCOMPLETE')

    def test_nonzero_exit_stderr_redaction(self):
        r = self.fake('import sys; print(%r,file=sys.stderr); sys.exit(17)' % SECRET)
        self.assertEqual(r['returncode'], 17)
        self.assertGreater(r['stderr_bytes'], 0)
        self.assertNotIn(SECRET, json.dumps(r))

    def test_timeout_kills_child_process_group(self):
        pidfile = self.base / 'fake-child.pid'
        source = ('import subprocess,sys,time; from pathlib import Path; '
                  'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(20)"]); '
                  'Path(%r).write_text(str(p.pid)); time.sleep(20)' % str(pidfile))
        r = self.fake(source, .4)
        self.assertTrue(r['timeout'])
        pid = int(pidfile.read_text())
        status = Path('/proc/%d/stat' % pid)
        if status.exists():
            self.assertEqual(status.read_text().split()[2], 'Z')

    def test_invalid_json(self):
        r = self.fake('print(%r)' % SECRET)
        self.assertEqual(r['errors'][0]['kind'], 'invalid_json')
        self.assertNotIn(SECRET, json.dumps(r))

    def test_missing_program(self):
        r = m.stream([str(self.base / 'missing')], m.journal_record)
        self.assertEqual(r['errors'][0]['exception_class'], 'FileNotFoundError')

    def test_access_error(self):
        with mock.patch.object(m.os, 'open', side_effect=PermissionError(SECRET)):
            r = m.files_metadata([self.base / 'missing'])
        self.assertEqual(r['errors'][0]['exception_class'], 'PermissionError')
        self.assertNotIn(SECRET, json.dumps(r))

    def test_large_lines_are_bounded(self):
        r = self.fake('import sys; sys.stdout.write("x"*2000000+"\\n")')
        self.assertGreater(r['stdout_bytes'], 1000000)
        self.assertEqual(r['records'], [])
        self.assertTrue(any(e['kind'] == 'limit' for e in r['errors']))

    def test_many_records_bounded(self):
        src = 'import json; [print(json.dumps({"__REALTIME_TIMESTAMP":"1","MESSAGE":"spicymila_bot"})) for _ in range(5100)]'
        r = self.fake(src, 5)
        self.assertEqual(len(r['records']), m.MAX_RECORDS)
        self.assertTrue(any(e['kind'] == 'limit' for e in r['errors']))

    def test_secret_suppression_journal_and_exception(self):
        msg = {'__REALTIME_TIMESTAMP': '123', 'MESSAGE': 'spicymila_bot TOKEN=' + SECRET,
               'ENV': SECRET, 'untrusted': SECRET}
        r = self.fake('print(%r)' % json.dumps(msg))
        self.assertEqual(r['records'], [{'timestamp_us': '123', 'terms': ['spicymila_bot']}])
        self.assertNotIn(SECRET, json.dumps(r))
        self.assertNotIn(SECRET, json.dumps(m.safe_error(RuntimeError(SECRET))))

    def test_secret_suppression_file_and_nat(self):
        p = self.base / 'config'
        p.write_text('TOKEN=' + SECRET + '\nspicymila_bot\n')
        r = m.files_metadata([p])
        self.assertNotIn(SECRET, json.dumps(r))
        self.assertEqual(m.nat_record('-A DOCKER --dport 8090 --to-destination 172.21.0.2:8080 --comment '+SECRET),
                         {'host_port': 8090, 'destination': '172.21.0.2:8080'})

    def test_unexpected_exception_manifest(self):
        def fail():
            raise RuntimeError(SECRET)
        rc = m.Collector(self.store).run([('run', lambda: {'ok': True}), ('proxy', fail)])
        self.assertEqual(rc, 2)
        self.assertTrue(self.read('run.json')['data']['ok'])
        self.assertEqual(self.read('manifest.json')['status'], 'INCOMPLETE')
        self.assertNotIn(SECRET, ''.join(p.read_text() for p in self.store.path.iterdir()))

    def test_cleanup_timeout_section_metadata(self):
        def fail():
            raise TimeoutError(SECRET)
        rc = m.Collector(self.store).run([('journal-000', fail), ('nat', lambda: {'ok': True})])
        self.assertEqual(rc, 2)
        self.assertTrue(self.read('journal-000-error.json')['timeout'])
        self.assertEqual(self.read('journal-000-error.json')['errors'][0]['exception_class'], 'TimeoutError')
        self.assertTrue(self.read('nat.json')['data']['ok'])

    def test_atomic_write_failure_keeps_previous(self):
        self.store.write('prior.json', {'ok': True})
        with mock.patch.object(m.os, 'rename', side_effect=OSError('fake failure')):
            with self.assertRaises(OSError):
                self.store.write('next.json', {'ok': True})
        self.assertFalse((self.store.path / 'next.json').exists())
        self.assertEqual(self.read('prior.json'), {'ok': True})
        self.assertFalse(list(self.store.path.glob('.pending-*')))

    def test_fsync_before_rename(self):
        seen = []
        fsync, rename = m.os.fsync, m.os.rename
        def sync(fd):
            seen.append('fsync'); return fsync(fd)
        def move(*a, **kw):
            seen.append('rename'); return rename(*a, **kw)
        with mock.patch.object(m.os, 'fsync', side_effect=sync), mock.patch.object(m.os, 'rename', side_effect=move):
            self.store.write('atomic.json', {'ok': True})
        self.assertEqual(seen, ['fsync', 'rename', 'fsync'])

    def test_existing_directory_refused(self):
        with self.assertRaises(FileExistsError):
            m.Store(self.base, self.store.path.name)

    def test_signal_during_atomic_publish_keeps_valid_manifest(self):
        rename = m.os.rename
        sent = []
        def interrupt(signum, frame):
            raise m.Interrupted()
        def move(*args, **kwargs):
            result = rename(*args, **kwargs)
            if not sent:
                sent.append(True)
                os.kill(os.getpid(), signal.SIGTERM)
            return result
        old = signal.signal(signal.SIGTERM, interrupt)
        try:
            with mock.patch.object(m.os, 'rename', side_effect=move):
                rc = m.Collector(self.store).run([('run', lambda: {'ok': True})])
            self.assertEqual(rc, 2)
            self.assertEqual(self.read('manifest.json')['status'], 'INCOMPLETE')
            self.assertTrue(self.read('run.json')['data']['ok'])
            self.assertFalse(list(self.store.path.glob('.pending-*')))
        finally:
            signal.signal(signal.SIGTERM, old)

    def test_symlink_base_refused(self):
        p = self.base / 'link'; p.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OSError):
            m.Store(p, 'collector-v2-20260927T000000Z-111111111111')

    def test_foreign_artifact_refused(self):
        (self.store.path / 'foreign').write_text('foreign')
        with self.assertRaises(FileExistsError):
            self.store.write('run.json', {})

    def test_artifact_symlink_and_path_escape_refused(self):
        with self.assertRaises(ValueError):
            self.store.write('../escape.json', {})
        (self.store.path / 'run.json').symlink_to(self.base / 'outside')
        with self.assertRaises(FileExistsError):
            self.store.write('run.json', {})
        self.assertFalse((self.base / 'outside').exists())

    def test_fatal_cli_no_sudo(self):
        p = subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), '--invalid'], capture_output=True, text=True)
        self.assertEqual(p.returncode, 3)

    def test_setup_exception_after_store_has_partial_manifest(self):
        import contextlib
        import io
        new = m.Store(self.base, 'collector-v2-20260927T000000Z-eeeeeeeeeeee')
        with mock.patch.object(m.os, 'geteuid', return_value=0), mock.patch.object(m.sys, 'argv', ['collector']), \
             mock.patch.object(m, 'Store', return_value=new), \
             mock.patch.object(m, 'journal_sections', side_effect=RuntimeError(SECRET)), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(), 2)
        self.assertNotIn(SECRET, out.getvalue())
        self.assertEqual(json.loads((new.path / 'manifest.json').read_text())['status'], 'INCOMPLETE')

    def test_fatal_unsafe_store(self):
        import contextlib
        import io
        with mock.patch.object(m.os, 'geteuid', return_value=0), mock.patch.object(m.sys, 'argv', ['collector']), \
             mock.patch.object(m, 'Store', side_effect=PermissionError(SECRET)), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(), 3)
        self.assertNotIn(SECRET, out.getvalue())

    def test_window_bounds(self):
        end = m.dt.datetime(2025, 10, 28, tzinfo=m.dt.timezone.utc)
        windows = list(m.journal_sections(end))
        self.assertEqual(len(windows), 3)
        with mock.patch.object(m, 'stream', return_value={'errors': []}) as fake:
            r = windows[0][1]()
            self.assertEqual(fake.call_args.kwargs['timeout'], 15)
            self.assertIn('--grep', fake.call_args.args[0])
            self.assertTrue(r['window']['inclusive_boundaries'])

    def test_signals_later_section_preserve_results(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            name = 'collector-v2-20260927T000000Z-%012x' % int(sig)
            code = '''import importlib.util,signal,time,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('m',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
store=m.Store(Path(sys.argv[2]),sys.argv[3])
def stop(s,f):raise m.Interrupted()
signal.signal(signal.SIGINT,stop);signal.signal(signal.SIGTERM,stop)
def later():
 print('READY',flush=True)
 return m.stream([sys.executable,'-c','import time;time.sleep(20)'],m.journal_record,30)
try: rc=m.Collector(store).run([('run',lambda:{'ok':True}),('journal-000',later)])
finally:store.close()
sys.exit(rc)
'''
            p = subprocess.Popen([sys.executable, '-I', '-B', '-c', code, str(SCRIPT), str(self.base), name],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(p.stdout.readline().strip(), 'READY')
                time.sleep(.1)
                p.send_signal(sig)
                out, err = p.communicate(timeout=5)
                self.assertEqual(p.returncode, 2, err)
                directory = self.base / name
                manifest = json.loads((directory / 'manifest.json').read_text())
                self.assertEqual(manifest['status'], 'INCOMPLETE')
                self.assertTrue((directory / 'run.json').exists())
                self.assertTrue((directory / 'journal-000-error.json').exists())
            finally:
                if p.poll() is None:
                    p.kill(); p.wait()
                p.stdout.close(); p.stderr.close()


if __name__ == '__main__':
    unittest.main()
