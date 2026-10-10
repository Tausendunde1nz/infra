"""Synthetic native historical-read regressions; no PID1, network or providers."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_s8_execution_contract as c
import tu1nz_s8_execution_observer as o
import tu1nz_s8_historical_read as h
import tu1nz_s8_path_policy as p


class BindingTests(unittest.TestCase):
    def test_missing_role_or_digest_is_not_adopted(self):
        with patch.dict(o.HISTORICAL_ROOTS, {}, clear=True), self.assertRaisesRegex(
                c.ContractError, 'HISTORICAL_BINDING_UNAVAILABLE'):
            o.history()
        with patch.dict(o.HISTORY_HASHES, {}, clear=True), self.assertRaisesRegex(
                c.ContractError, 'HISTORICAL_BINDING_UNAVAILABLE'):
            o.history()
        for identity in (None, (), ('x', 'y'), ('a'*40,)):
            with self.subTest(identity=identity), self.assertRaisesRegex(c.ContractError, 'BINDING_UNAVAILABLE'):
                h.repository(Path('/not-accessed'), identity)

    def test_access_failure_preserves_primary_origin_and_cleanup_not_drift(self):
        error = PermissionError('private credentials must not leave this adapter')
        error._s8_cleanup_errors = [dict(code='UNKNOWN', type='OSError')]
        value = h.unavailable(error)
        self.assertEqual(str(value), 'S8_EXECUTION_HISTORICAL_READ_UNAVAILABLE')
        self.assertEqual(value._s8_read_failure, dict(code='UNKNOWN', type='PermissionError'))
        self.assertEqual(value._s8_cleanup_errors, error._s8_cleanup_errors)

    def test_ordinary_execution_metadata_predicate_unchanged(self):
        self.assertNotIn(Path('/etc/tu1nz/s8-atomic-admission-r1'), p.HISTORICAL_PROFILES)
        with self.assertRaisesRegex(c.ContractError, 'HISTORICAL_CREATION_FORBIDDEN'):
            p.parent_metadata(Path('/not-accessed'), historical=True, creation=True)
        control = Path('/opt/tu1nz_repos/control')
        self.assertEqual(p.HISTORICAL_PROFILES[control/'.git'], (0,0,None,None))
        self.assertEqual(p.HISTORICAL_PROFILES[control/'.git.s12-1-recovery'], (0,0o700,None,None))


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0 and
                    os.environ.get('container') == 'docker', 'isolated native Linux only')
class NativeReadTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(Path('/.dockerenv').exists())
        self.temp = tempfile.TemporaryDirectory(prefix='s8-historical-read-', dir='/etc')
        self.base = Path(self.temp.name)
        self.root = self.base/'repository'; self.root.mkdir()
        self.git(['init', '--quiet', str(self.root)])
        (self.root/'synthetic.txt').write_bytes(b'synthetic historical content\n')
        self.git(['-C', str(self.root), 'add', 'synthetic.txt'])
        self.git(['-C', str(self.root), '-c', 'user.name=Synthetic', '-c', 'user.email=fixture@example.invalid',
                  'commit', '--quiet', '-m', 'synthetic'])
        self.expected = tuple(self.git(['-C', str(self.root), 'rev-parse', ref]).decode().strip()
                              for ref in ('HEAD', 'HEAD^{tree}'))
        (self.root/'.git').rename(self.root/'.git.s12-1-recovery')
        (self.root/'.git').mkdir(mode=0)
        self.real_git = self.root/'.git.s12-1-recovery'
        self.real_git.chmod(0o700)
        os.chown(self.root, 0, 1001); self.root.chmod(0o2550)
        profiles = {self.root: (1001, 0o2550, p.APPLICATION_ACCESS, p.REPOSITORY_DEFAULT),
            self.root/'.git': (0, 0, ((1, 0, p.UNDEFINED), *p.GIT_ACCESS[1:]), p.REPOSITORY_DEFAULT),
            self.real_git: (0, 0o700, p.GIT_ACCESS, p.REPOSITORY_DEFAULT)}
        for path, (_, _, access, default) in profiles.items():
            os.setxattr(path, p.ACCESS, p.acl_bytes(access))
            os.setxattr(path, p.DEFAULT, p.acl_bytes(default))
        self.assertEqual(self.root.stat().st_mode & 0o7777, 0o2550,
                         'native fixture requires FSETID; no weakened metadata predicate')
        self.profiles = patch.dict(p.HISTORICAL_PROFILES, profiles)
        self.profiles.start()

    def git(self, args):
        return subprocess.check_output(['/usr/bin/git', *args], stderr=subprocess.DEVNULL)

    def tearDown(self):
        self.profiles.stop()
        (self.root/'.git').chmod(0o700)
        self.root.chmod(0o700)
        self.temp.cleanup()  # only this case's newly created synthetic stock

    def test_exact_group_acl_reads_preserve_bytes_metadata_and_index(self):
        paths = [self.root, self.real_git, self.root/'.git', self.real_git/'index']
        before = {path:c.fingerprint(path.lstat()) for path in paths}
        index = (self.real_git/'index').read_bytes()
        actual = h.repository(self.root, self.expected)
        self.assertEqual((actual['commit'], actual['tree']), self.expected)
        self.assertEqual(before, {path:c.fingerprint(path.lstat()) for path in paths})
        self.assertEqual(index, (self.real_git/'index').read_bytes())
        with self.assertRaises(c.ContractError): p.parent_metadata(self.root)

    def test_control_group_only_read_profile(self):
        for path in (self.root, self.root/'.git', self.real_git):
            for name in (p.ACCESS,p.DEFAULT): os.removexattr(path,name)
        profiles = {self.root:(1001,0o2550,None,None),
                    self.root/'.git':(0,0,None,None), self.real_git:(0,0o700,None,None)}
        with patch.dict(p.HISTORICAL_PROFILES, profiles):
            self.assertEqual(h.repository(self.root, self.expected)['commit'], self.expected[0])
            (self.root/'.git').chmod(0o700)
            with self.assertRaisesRegex(c.ContractError,'UNSAFE_METADATA'): h.repository(self.root,self.expected)
            (self.root/'.git').chmod(0)
            self.real_git.chmod(0o755)
            with self.assertRaisesRegex(c.ContractError,'UNSAFE_METADATA'): h.repository(self.root,self.expected)
            self.real_git.chmod(0o700)

    def test_effective_write_wrong_owner_group_xattr_or_default_denied(self):
        for kind in ('effective-write', 'owner', 'group', 'xattr', 'default'):
            with self.subTest(kind=kind):
                original = {name:os.getxattr(self.root,name) for name in (p.ACCESS,p.DEFAULT)}
                if kind == 'effective-write':
                    acl = list(p.APPLICATION_ACCESS); acl[4] = (16,7,p.UNDEFINED)
                    os.setxattr(self.root,p.ACCESS,p.acl_bytes(acl))
                elif kind == 'owner': os.chown(self.root,1001,1001)
                elif kind == 'group': os.chown(self.root,0,1002)
                elif kind == 'xattr': os.setxattr(self.root,'user.foreign',b'unknown')
                else: os.setxattr(self.root,p.DEFAULT,p.acl_bytes(p.APPLICATION_ACCESS))
                with self.assertRaises(c.ContractError): h.repository(self.root,self.expected)
                os.chown(self.root,0,1001)
                for name,value in original.items(): os.setxattr(self.root,name,value)
                if kind == 'xattr': os.removexattr(self.root,'user.foreign')

    def test_descendant_writer_symlink_or_hardlink_denied(self):
        path = self.real_git/'HEAD'; original = path.read_bytes()
        path.chmod(0o660)
        with self.assertRaisesRegex(c.ContractError,'UNSAFE_METADATA'): h.repository(self.root,self.expected)
        path.chmod(0o644)
        os.link(path,self.real_git/'foreign-link')
        with self.assertRaisesRegex(c.ContractError,'UNSAFE_METADATA'): h.repository(self.root,self.expected)
        (self.real_git/'foreign-link').unlink()
        path.unlink(); path.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(c.ContractError,'UNSAFE_METADATA'): h.repository(self.root,self.expected)
        path.unlink(); path.write_bytes(original)

    def test_wrong_commit_tree_and_missing_object_not_adopted(self):
        for expected in (('a'*40,self.expected[1]),(self.expected[0],'b'*40)):
            with self.assertRaisesRegex(c.ContractError,'HISTORICAL_CONTENT_RED'):
                h.repository(self.root,expected)
        oid = self.expected[0]; obj = self.real_git/'objects'/oid[:2]/oid[2:]
        obj.rename(obj.with_name('withheld'))
        with self.assertRaisesRegex(c.ContractError,'HISTORICAL_READ_UNAVAILABLE'):
            h.repository(self.root,self.expected)

    def test_indirection_and_unknown_git_config_denied(self):
        config = self.real_git/'config'; original = config.read_bytes()
        config.write_bytes(original+b'\n[include]\npath = /etc/passwd\n')
        with self.assertRaisesRegex(c.ContractError,'UNSAFE_CONFIG'): h.repository(self.root,self.expected)
        config.write_bytes(original)
        (self.real_git/'objects/info/alternates').write_bytes(b'/not-read\n')
        (self.real_git/'objects/info/alternates').chmod(0o600)
        with self.assertRaisesRegex(c.ContractError,'UNSAFE_INDIRECTION'): h.repository(self.root,self.expected)

    def test_native_write_restore_during_git_read_is_rejected(self):
        original = h.git_read; changed = False
        path = self.real_git/'HEAD'; payload = path.read_bytes()
        def racing(args, **options):
            nonlocal changed
            value = original(args, **options)
            if 'rev-parse' in args and not changed:
                changed = True
                path.write_bytes(b'synthetic concurrent change\n'); path.write_bytes(payload)
            return value
        with patch.object(h,'git_read',side_effect=racing), self.assertRaisesRegex(
                c.ContractError,'HISTORICAL_READ_CHANGED'):
            h.repository(self.root,self.expected)
        self.assertTrue(changed)

    def test_interruption_closes_all_watches_no_second_read(self):
        before = len(os.listdir('/proc/self/fd'))
        with patch.object(h,'git_read',side_effect=KeyboardInterrupt) as read:
            with self.assertRaises(KeyboardInterrupt): h.repository(self.root,self.expected)
        self.assertEqual(read.call_count,1)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_existing_descriptor_write_restore_and_ancestor_exchange_deny(self):
        original = h.git_read
        for scenario in ('descriptor', 'ancestor'):
            with self.subTest(scenario=scenario):
                done = False
                path = self.real_git/'HEAD'; payload = path.read_bytes()
                descriptor = os.open(path, os.O_RDWR)
                def racing(args, **options):
                    nonlocal done
                    result = original(args, **options)
                    if 'rev-parse' in args and not done:
                        done = True
                        if scenario == 'descriptor':
                            os.pwrite(descriptor, b'x', 0); os.pwrite(descriptor, payload, 0)
                        else:
                            moved = self.root.with_name('temporarily-moved')
                            self.root.rename(moved); moved.rename(self.root)
                    return result
                try:
                    with patch.object(h,'git_read',side_effect=racing), self.assertRaises(c.ContractError):
                        h.repository(self.root,self.expected)
                    self.assertTrue(done)
                finally: os.close(descriptor)

    def test_permission_failure_and_cleanup_remain_distinct(self):
        before = len(os.listdir('/proc/self/fd'))
        with patch.object(h,'git_read',side_effect=PermissionError('not disclosed')) as read:
            with self.assertRaisesRegex(c.ContractError, 'HISTORICAL_READ_UNAVAILABLE') as failure:
                h.repository(self.root,self.expected)
        self.assertEqual(failure.exception._s8_read_failure['type'],'PermissionError')
        self.assertEqual(read.call_count,1)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_read_interval_watcher_loss_denies(self):
        with h.GitReadWitness(self.real_git) as witness:
            witness.owner = -1
            with self.assertRaisesRegex(c.ContractError, 'WITNESS_LOST'): witness.check()
            witness.owner = os.getpid()


if __name__ == '__main__': unittest.main()
