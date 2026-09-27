import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import tu1nz_agentmode_state_init_v2 as stage

class StateProvisioningV2Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(['setfacl', '-b', '-k', str(self.root)], check=True)
        os.chmod(self.root, 0o700)
        self.path = self.root / 'runtime-state'
    def tearDown(self):
        self.temp.cleanup()
    def snapshot(self, p):
        s = p.lstat()
        return (s.st_uid, s.st_gid, s.st_mode, s.st_ino,
            subprocess.check_output(['getfacl', '-cpn', str(p)]))
    def inherited(self):
        uid, gid = os.geteuid(), os.getegid()
        subprocess.run(['setfacl', '-m', f'd:u::rwx,d:u:{uid}:rwx,d:g::rwx,d:g:{gid}:rwx,d:m::rwx,d:o::---', str(self.root)], check=True)
    def test_acl_free_and_default_acl_explicit_0750(self):
        for inherited in (False, True):
            with self.subTest(inherited=inherited):
                if inherited:
                    self.inherited()
                self.assertEqual(stage.initialize_fixture(self.root), 'CREATED')
                self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o750)
                fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    self.assertEqual(stage.acl(fd), stage.expected_acl(os.geteuid(), os.getegid(), False))
                finally:
                    os.close(fd)
                child = self.path / 'control_update_state.json'
                child.write_text('{}')
                self.assertFalse(child.stat().st_mode & 0o020)
                child.unlink()
                self.path.rmdir()
    def test_idempotent_preserves_inode_acl_and_mode(self):
        stage.initialize_fixture(self.root)
        before = self.snapshot(self.path)
        self.assertEqual(stage.initialize_fixture(self.root), 'VALIDATED_UNCHANGED')
        self.assertEqual(self.snapshot(self.path), before)
    def test_setgid_profile_is_exact_2750(self):
        self.inherited()
        stage.initialize_fixture(self.root, setgid=True)
        before = self.snapshot(self.path)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o2750)
        child = self.path / 'notification_state'
        child.write_text('test')
        os.chmod(child, 0o640)
        self.assertEqual(child.stat().st_gid, os.getegid())
        self.assertFalse(child.stat().st_mode & 0o020)
        stage.initialize_fixture(self.root, setgid=True)
        self.assertEqual(self.snapshot(self.path), before)
        with self.assertRaises(stage.UnsafeState):
            stage.initialize_fixture(self.root, setgid=False)
    def test_wrong_owner_and_group_fail_without_repair(self):
        stage.initialize_fixture(self.root)
        before = self.snapshot(self.path)
        for uid, gid in ((os.geteuid()+10000, os.getegid()), (os.geteuid(), os.getegid()+10000)):
            with self.assertRaises(stage.UnsafeState):
                stage.provision(self.path, uid, gid, False, create=True)
            self.assertEqual(self.snapshot(self.path), before)
    def test_wrong_inherited_named_user_refused_and_new_directory_removed(self):
        subprocess.run(['setfacl', '-m', f'd:u:{os.geteuid()+10000}:rwx', str(self.root)], check=True)
        with self.assertRaises(stage.UnsafeState):
            stage.initialize_fixture(self.root)
        self.assertFalse(self.path.exists())
    def test_symlink_and_non_directory_refused(self):
        target = self.root / 'target'
        target.mkdir()
        before = self.snapshot(target)
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            stage.initialize_fixture(self.root)
        self.assertEqual(before, self.snapshot(target))
        self.path.unlink()
        self.path.write_text('untouched')
        with self.assertRaises(OSError):
            stage.initialize_fixture(self.root)
        self.assertEqual(self.path.read_text(), 'untouched')
    def test_group_writable_existing_root_rejected(self):
        stage.initialize_fixture(self.root)
        os.chmod(self.path, 0o770)
        before = self.snapshot(self.path)
        with self.assertRaises(stage.UnsafeState):
            stage.initialize_fixture(self.root)
        self.assertEqual(before, self.snapshot(self.path))
    def test_unknown_and_group_writable_state_file_rejected(self):
        stage.initialize_fixture(self.root)
        for name, mode in [('notification_state', 0o660), ('unknown-state', 0o640)]:
            f = self.path / name
            f.write_text('unchanged')
            os.chmod(f, mode)
            before = self.snapshot(f)
            with self.assertRaises(stage.UnsafeState):
                stage.initialize_fixture(self.root)
            self.assertEqual(before, self.snapshot(f))
            f.unlink()
    def test_known_file_symlink_and_fifo_rejected(self):
        stage.initialize_fixture(self.root)
        f = self.path / 'notification_state'
        f.symlink_to(self.root)
        with self.assertRaises(OSError):
            stage.initialize_fixture(self.root)
        f.unlink()
        os.mkfifo(f, 0o640)
        with self.assertRaises(stage.UnsafeState):
            stage.initialize_fixture(self.root)
    def test_shared_service_paths_outside_write_scope(self):
        self.assertEqual(len(stage.SHARED_READONLY_MATRIX), 4)
        for literal, (_, _, mode) in stage.SHARED_READONLY_MATRIX.items():
            p = self.root / Path(literal).name
            if p.name.startswith('.'):
                p.write_text('shared')
            else:
                p.mkdir(exist_ok=True)
            os.chmod(p, mode)
            before = self.snapshot(p)
            with self.assertRaises(stage.UnsafeState):
                stage.provision(p, os.geteuid(), os.getegid(), False, create=True)
            self.assertEqual(before, self.snapshot(p))
        self.assertFalse(self.path.exists())
    def test_normalization_failure_rolls_back_only_new_empty_directory(self):
        with patch.object(stage.subprocess, 'run', side_effect=RuntimeError('offline injection')):
            with self.assertRaises(RuntimeError):
                stage.initialize_fixture(self.root)
        self.assertFalse(self.path.exists())

class IntegrityProvisioningV2Test(unittest.TestCase):
    setUp = StateProvisioningV2Test.setUp
    tearDown = StateProvisioningV2Test.tearDown
    snapshot = StateProvisioningV2Test.snapshot
    inherited = StateProvisioningV2Test.inherited
    # Dedicated tests use the same private fixture, without re-running inherited
    # base tests as a separate suite class.
    def test_integrity_missing_and_existing_both_parent_profiles(self):
        for inherited in (False, True):
            with self.subTest(inherited=inherited):
                if inherited:
                    self.inherited()
                stage.initialize_fixture(self.root, integrity=True)
                child = self.path / 'integrity'
                self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o2750)
                before = self.snapshot(child)
                for name in stage.INTEGRITY_FILES:
                    f = child / name
                    f.write_text('fixture')
                    os.chmod(f, 0o640)
                stage.initialize_fixture(self.root, integrity=True)
                self.assertEqual(before, self.snapshot(child))
                for f in child.iterdir():
                    self.assertFalse(f.stat().st_mode & 0o020)
                    f.unlink()
                child.rmdir()
                self.path.rmdir()
    def test_integrity_wrong_mode_acl_owner_group_and_unknown_content(self):
        stage.initialize_fixture(self.root, integrity=True)
        child = self.path / 'integrity'
        os.chmod(child, 0o2770)
        before = self.snapshot(child)
        with self.assertRaises(stage.UnsafeState):
            stage.initialize_fixture(self.root, integrity=True)
        self.assertEqual(before, self.snapshot(child))
        os.chmod(child, 0o2750)
        subprocess.run(['setfacl', '-m', f'u:{os.geteuid()+10000}:r-x', str(child)], check=True)
        before = self.snapshot(child)
        with self.assertRaises(stage.UnsafeState):
            stage.initialize_fixture(self.root, integrity=True)
        self.assertEqual(before, self.snapshot(child))
        child.rmdir()
        stage.initialize_fixture(self.root, integrity=True)
        for uid, gid in ((os.geteuid()+10000, os.getegid()), (os.geteuid(), os.getegid()+10000)):
            with self.assertRaises(stage.UnsafeState):
                stage.provision(child, uid, gid, True, create=True)
        unknown = child / 'unknown'
        unknown.write_text('preserve me')
        with self.assertRaises(stage.UnsafeState):
            stage.initialize_fixture(self.root, integrity=True)
        self.assertEqual(unknown.read_text(), 'preserve me')
    def test_integrity_symlink_file_fifo_and_nested_directory_refused(self):
        stage.initialize_fixture(self.root)
        child = self.path / 'integrity'
        child.symlink_to(self.root)
        with self.assertRaises(OSError):
            stage.initialize_fixture(self.root, integrity=True)
        child.unlink()
        child.write_text('keep')
        with self.assertRaises(OSError):
            stage.initialize_fixture(self.root, integrity=True)
        self.assertEqual(child.read_text(), 'keep')
        child.unlink()
        os.mkfifo(child)
        with self.assertRaises(OSError):
            stage.initialize_fixture(self.root, integrity=True)
        child.unlink()
        stage.initialize_fixture(self.root, integrity=True)
        (child / 'unexpected-subdirectory').mkdir()
        with self.assertRaises(stage.UnsafeState):
            stage.initialize_fixture(self.root, integrity=True)

if __name__ == '__main__':
    unittest.main()
