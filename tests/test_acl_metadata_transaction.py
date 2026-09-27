import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('acl_tx', Path(__file__).parents[1] / 'scripts' / 'tu1nz_acl_metadata_transaction.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OfflineMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'OFFLINE_FIXTURE').write_text('No production content\n')
        self.target = self.root / 'state'
        self.target.mkdir()
        subprocess.run(['setfacl', '-m', 'u::rwx,g::rwx,o::---,d:u::rwx,d:g::rwx,d:o::---', str(self.target)], check=True)
        self.before = m.snapshot(self.target)
        self.after = dict(self.before, mode=0o750, acl='user::rwx\ngroup::r-x\nother::---\ndefault:user::rwx\ndefault:group::r-x\ndefault:other::---\n\n')
        # Remove inherited named ACL entries only in this synthetic target.
        self.plan = [{'path': str(self.target), 'before': self.before, 'after': self.after}]
        self.backup = self.root / 'before.json'

    def tearDown(self):
        self.temp.cleanup()

    def test_apply_idempotence_exact_rollback(self):
        self.assertEqual(m.apply(self.plan, self.backup, self.root), 'APPLIED')
        self.assertEqual(m.apply(self.plan, self.backup, self.root), 'ALREADY_APPLIED')
        self.assertEqual(m.rollback(self.backup, self.root), 'APPLIED')
        self.assertEqual(m.snapshot(self.target), self.before)

    def test_injected_failure_restores_exact_metadata(self):
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            m.apply(self.plan, self.backup, self.root, fail_after=0)
        self.assertEqual(m.snapshot(self.target), self.before)

    def test_unexpected_baseline_refuses_mutation(self):
        self.target.chmod(0o700)
        before = m.snapshot(self.target)
        with self.assertRaisesRegex(RuntimeError, 'baseline drift'):
            m.apply(self.plan, self.backup, self.root)
        self.assertEqual(m.snapshot(self.target), before)
        self.assertFalse(self.backup.exists())

    def test_checksum_tampering_rejected(self):
        m.apply(self.plan, self.backup, self.root)
        import json
        saved = json.loads(self.backup.read_text())
        saved['sha256'] = 'bad'
        self.backup.write_text(json.dumps(saved))
        with self.assertRaisesRegex(ValueError, 'checksum'):
            m.rollback(self.backup, self.root)
        self.assertEqual(m.snapshot(self.target), self.after)

    def test_ownership_change_rejected(self):
        plan = copy.deepcopy(self.plan)
        plan[0]['after']['uid'] += 1
        with self.assertRaisesRegex(ValueError, 'ownership'):
            m.apply(plan, self.backup, self.root)

    def test_live_path_is_locked(self):
        with self.assertRaisesRegex(RuntimeError, 'LIVE_LOCKED'):
            m.apply(self.plan, self.backup)
        self.assertEqual(m.snapshot(self.target), self.before)

    def test_symlink_rejected(self):
        link = self.root / 'link'
        link.symlink_to(self.target)
        plan = copy.deepcopy(self.plan)
        plan[0]['path'] = str(link)
        with self.assertRaises(ValueError):
            m.apply(plan, self.backup, self.root)

    def test_log_status_creation_and_inheritance(self):
        m.apply(self.plan, self.backup, self.root)
        subprocess.run(['bash', '-c', 'umask 0027; mkdir "$1/child"; printf "synthetic log\\n" >> "$1/log"; printf "ok\\n" > "$1/status"', '--', str(self.target)], check=True)
        self.assertEqual(m.snapshot(self.target / 'child')['mode'], 0o750)
        for name in ('log', 'status'):
            self.assertEqual(m.snapshot(self.target / name)['mode'], 0o640)


if __name__ == '__main__':
    unittest.main()
