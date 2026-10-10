"""Synthetic native historical-read regressions; no PID1, network or providers."""
import os
import errno
import hashlib
import mmap
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
import tu1nz_s8_historical_kernel as k


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
        self.assertEqual(os.environ.get('TU1NZ_S8_NATIVE_EXT4_ROOT'), '/proof')
        self.temp = tempfile.TemporaryDirectory(prefix='s8-historical-read-', dir='/proof')
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
        # Test-process isolation only. Production has no signal/attempt reset;
        # the frozen owning process exits on a failed capture.
        while k.LEASE_SIGNAL in k.signal.sigpending():
            k.signal.sigtimedwait({k.LEASE_SIGNAL}, 0)
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

    def test_synthetic_failure_shim_does_not_make_historical_mount_executable(self):
        # The actual chain's initial failed-unit fixture must return 2, not
        # 203/EXEC plus restart. Keep the repository/ext4 mount noexec and
        # prove only the fresh exact synthetic file bind is executable.
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        from s8_provision_native_chain import failure_shim
        blocked = self.base/'blocked-script'
        blocked.write_bytes(b'#!/bin/sh\nexit 2\n'); blocked.chmod(0o755)
        with self.assertRaises(PermissionError): subprocess.run([str(blocked)],check=False)
        target = self.base/'synthetic-bin'/'failure-script'
        with tempfile.TemporaryDirectory(prefix='s8-owned-shim-',dir='/var/tmp') as directory:
            try:
                failure_shim(target,Path(directory)/'exit-two')
                self.assertEqual(subprocess.run([str(target)],check=False).returncode,2)
                options = subprocess.check_output(['findmnt','-n','-o','OPTIONS','-T',str(self.root)]).decode().strip().split(',')
                self.assertIn('noexec',options)
                self.assertEqual(h.repository(self.root,self.expected)['commit'],self.expected[0])
            finally:
                # Only this new exact file bind; never a host/historical mount.
                if target.exists() and subprocess.check_output([
                    'findmnt','-n','-o','TARGET','-T',str(target)]).decode().strip()==str(target):
                    subprocess.run(['umount',str(target)],check=True)
        with self.assertRaises(PermissionError): subprocess.run([str(target)],check=False)

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

    def test_canonical_ssh_and_user_config_are_data_never_child_commands(self):
        config = self.real_git/'config'
        original = config.read_bytes()
        sentinel = self.base/'command-must-not-run'
        for value in ('ssh -i /synthetic-key -o IdentitiesOnly=yes',
                      'touch '+str(sentinel)):
            config.write_bytes(original+b'\tsshCommand = '+value.encode()+
                b'\n[user]\n\tname = Synthetic fixture\n\temail = fixture@example.invalid\n')
            with patch('subprocess.Popen',side_effect=AssertionError('unexpected child')):
                actual = h.repository(self.root,self.expected)
            self.assertEqual((actual['commit'],actual['tree']),self.expected)
            self.assertFalse(sentinel.exists())
        config.write_bytes(original)

    def test_fixture_mount_cleanup_follows_owned_object_not_reused_name(self):
        from tests import s8_historical_fixture_mounts as owned
        source = self.base/'owned-source'; source.mkdir()
        foreign_source = self.base/'foreign-source'; foreign_source.mkdir()
        parent = self.base/'mount-parent'; parent.mkdir()
        target = parent/'binding'; target.mkdir()
        retained = self.base/'mount-retained'
        subprocess.run(['mount','--bind',str(source),str(target)],check=True)
        original = owned.capture(target,(str(target),str(retained/'binding')))
        foreign = None
        try:
            parent.rename(retained); parent.mkdir(); target.mkdir()
            subprocess.run(['mount','--bind',str(foreign_source),str(target)],check=True)
            foreign = owned.capture(target,(str(target),))
            self.assertEqual(owned.current(original),str(retained/'binding'))
            owned.unmount_owned(original)
            self.assertEqual(owned.current(foreign),str(target))
            self.assertNotIn(original['id'],[v['id'] for v in owned.mounts()])
        finally:
            for value in (foreign,original):
                if value is not None and any(v['id']==value['id'] for v in owned.mounts()):
                    owned.unmount_owned(value)

    def test_fixture_mount_unbound_relocation_denied_not_adopted(self):
        from tests import s8_historical_fixture_mounts as owned
        source = self.base/'owned-source'; source.mkdir()
        parent = self.base/'mount-parent'; parent.mkdir()
        target = parent/'binding'; target.mkdir()
        retained = self.base/'unbound-parent'
        subprocess.run(['mount','--bind',str(source),str(target)],check=True)
        binding = owned.capture(target,(str(target),))
        try:
            parent.rename(retained)
            with self.assertRaisesRegex(AssertionError,'TARGET_UNBOUND'):
                owned.unmount_owned(binding)
            self.assertIn(binding['id'],[v['id'] for v in owned.mounts()])
        finally:
            retained.rename(parent)
            owned.unmount_owned(binding)

    def test_fixture_cleanup_preserves_primary_and_attempts_independent_mount(self):
        from tests import s8_historical_fixture_mounts as owned
        source = self.base/'owned-source'; source.mkdir()
        target = self.base/'owned-target'; target.mkdir()
        subprocess.run(['mount','--bind',str(source),str(target)],check=True)
        binding = owned.capture(target,(str(target),))
        missing = {**binding,'id':-1}
        try:
            result,status = owned.release_all((missing,binding),17)
            self.assertEqual(status,17)
            self.assertEqual(result['primary_code'],17)
            self.assertEqual(result['cleanup'],[dict(type='AssertionError',code='S8_NATIVE_FIXTURE_MOUNT_MISSING')])
            self.assertNotIn(binding['id'],[v['id'] for v in owned.mounts()])
            result,status = owned.release_all((missing,),0)
            self.assertEqual(status,2)
            self.assertEqual(len(result['cleanup']),1)
        finally:
            if any(v['id']==binding['id'] for v in owned.mounts()): owned.unmount_owned(binding)

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
        # Mode/ACL are not normalized: writer exclusion, not group trust,
        # now decides whether this current profile can be captured.
        with self.assertRaisesRegex(c.ContractError,'UNSAFE_METADATA'): h.node_metadata(path)
        self.assertEqual(h.repository(self.root,self.expected)['commit'], self.expected[0])
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
        original = h.resolve_head; changed = False
        path = self.real_git/'HEAD'; payload = path.read_bytes()
        def racing(args, **options):
            nonlocal changed
            value = original(args, **options)
            if not changed:
                changed = True
                with self.assertRaises(OSError) as denied:
                    fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
                    os.close(fd)
                self.assertIn(denied.exception.errno, (errno.EAGAIN, errno.EWOULDBLOCK))
            return value
        with patch.object(h,'resolve_head',side_effect=racing), self.assertRaisesRegex(
                c.ContractError,'HISTORICAL_LEASE_BREAK'):
            h.repository(self.root,self.expected)
        self.assertTrue(changed)

    def test_interruption_closes_all_watches_no_second_read(self):
        before = len(os.listdir('/proc/self/fd'))
        with patch.object(h,'resolve_head',side_effect=KeyboardInterrupt) as read:
            with self.assertRaises(KeyboardInterrupt): h.repository(self.root,self.expected)
        self.assertEqual(read.call_count,1)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_existing_descriptor_write_restore_and_ancestor_exchange_deny(self):
        original = h.resolve_head
        for scenario in ('descriptor', 'ancestor'):
            with self.subTest(scenario=scenario):
                done = False
                path = self.real_git/'HEAD'; payload = path.read_bytes()
                descriptor = os.open(path, os.O_RDWR if scenario == 'descriptor' else os.O_RDONLY)
                def racing(args, **options):
                    nonlocal done
                    result = original(args, **options)
                    if not done:
                        done = True
                        if scenario == 'ancestor':
                            moved = self.root.with_name('temporarily-moved')
                            self.root.rename(moved); moved.rename(self.root)
                    return result
                try:
                    with patch.object(h,'resolve_head',side_effect=racing), self.assertRaises(c.ContractError):
                        h.repository(self.root,self.expected)
                    self.assertEqual(done, scenario == 'ancestor')
                finally: os.close(descriptor)

    def test_permission_failure_and_cleanup_remain_distinct(self):
        before = len(os.listdir('/proc/self/fd'))
        with patch.object(h,'resolve_head',side_effect=PermissionError('not disclosed')) as read:
            with self.assertRaisesRegex(c.ContractError, 'HISTORICAL_READ_UNAVAILABLE') as failure:
                h.repository(self.root,self.expected)
        self.assertEqual(failure.exception._s8_read_failure['type'],'PermissionError')
        self.assertEqual(read.call_count,1)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_read_interval_watcher_loss_denies(self):
        witness = h.GitReadWitness(self.real_git)
        try:
            witness.owner = -1
            with self.assertRaisesRegex(c.ContractError, 'WITNESS_LOST'): witness.check()
            witness.owner = os.getpid()
            with self.assertRaisesRegex(c.ContractError, 'WITNESS_LOST'): witness.check()
        finally: witness.close()

    def test_observed_orig_head_acl_and_branches_owner_capture_without_normalization(self):
        orig = self.real_git/'ORIG_HEAD'; orig.write_bytes((self.expected[0]+'\n').encode())
        acl = ((1,6,p.UNDEFINED),*p.GIT_ACCESS[1:4],(16,6,p.UNDEFINED),(32,0,p.UNDEFINED))
        os.setxattr(orig,p.ACCESS,p.acl_bytes(acl))
        branches = self.real_git/'branches'
        os.chown(branches,1001,1001); branches.chmod(0o2775)
        before = {node:(c.fingerprint(node.lstat()), {name:os.getxattr(node,name)
                  for name in os.listxattr(node)}) for node in (orig,branches)}
        for node in (orig,branches):
            with self.assertRaises(c.ContractError): h.node_metadata(node)
        self.assertEqual(h.repository(self.root,self.expected)['commit'],self.expected[0])
        after = {node:(c.fingerprint(node.lstat()), {name:os.getxattr(node,name)
                 for name in os.listxattr(node)}) for node in (orig,branches)}
        self.assertEqual(before,after)

    def test_retained_shared_mapping_denies_before_any_git_use(self):
        path = self.real_git/'HEAD'
        writer = os.open(path,os.O_RDWR)
        mapping = mmap.mmap(writer,0,access=mmap.ACCESS_WRITE)
        os.close(writer)
        try:
            with patch.object(h,'resolve_head') as read, self.assertRaisesRegex(
                    c.ContractError,'WRITER_EXCLUSION_UNAVAILABLE'):
                h.repository(self.root,self.expected)
            read.assert_not_called()
        finally: mapping.close()

    def test_foreign_unprivileged_writer_fd_and_mapping_are_not_permission_exemptions(self):
        child_source = '''import ctypes,mmap,os,sys
fd=int(sys.argv[1]); uid=int(sys.argv[2]); use_map=sys.argv[3]=='map'
if uid:
 os.setgroups([]);os.setgid(uid);os.setuid(uid)
else:
 class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
 class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
 libc=ctypes.CDLL(None,use_errno=True);assert libc.capset(ctypes.byref(Header(0x20080522,0)),(Data*2)())==0
mapping=mmap.mmap(fd,0,access=mmap.ACCESS_WRITE) if use_map else None
if mapping is not None:os.close(fd)
status=open('/proc/self/status').read().splitlines()
assert next(x for x in status if x.startswith('CapEff:')).split()[1]=='0000000000000000'
print('SYNTHETIC_WRITER_READY',flush=True)
sys.stdin.buffer.read(1)
if mapping is not None:mapping.close()
else:os.close(fd)
'''
        for uid in (0,1001):
            for mode in ('fd','map'):
                with self.subTest(uid=uid,mode=mode):
                    writer = os.open(self.real_git/'HEAD',os.O_RDWR)
                    child = subprocess.Popen([sys.executable,'-I','-B','-c',child_source,str(writer),str(uid),mode],
                        pass_fds=(writer,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    os.close(writer)
                    try:
                        self.assertEqual(child.stdout.readline(),b'SYNTHETIC_WRITER_READY\n')
                        with patch.object(h,'resolve_head') as read, self.assertRaisesRegex(
                                c.ContractError,'WRITER_EXCLUSION_UNAVAILABLE'):
                            h.repository(self.root,self.expected)
                        read.assert_not_called()
                    finally:
                        _,error = child.communicate(b'finish',timeout=5)
                    self.assertEqual(child.returncode,0,error.decode())

    def test_unsupported_native_filesystem_never_falls_back_to_permission_only(self):
        with tempfile.TemporaryDirectory(prefix='s8-synthetic-overlay-') as folder:
            path = Path(folder)/'file'; path.write_bytes(b'synthetic')
            fd = os.open(path,os.O_RDONLY)
            try:
                with self.assertRaisesRegex(c.ContractError,'EXT4_REQUIRED'): k.ext4(fd)
            finally: os.close(fd)

    def test_retained_directory_fd_metadata_and_creation_rejected(self):
        branches = self.real_git/'branches'
        os.chown(branches,1001,1001); branches.chmod(0o2775)
        directory = os.open(branches,os.O_RDONLY | os.O_DIRECTORY)
        original = h.resolve_head
        def racing(args, **options):
            result = original(args, **options)
            fd = os.open('synthetic-created',os.O_WRONLY | os.O_CREAT | os.O_EXCL,0o600,dir_fd=directory)
            os.close(fd)
            os.unlink('synthetic-created',dir_fd=directory)
            os.fchmod(directory,0o2700); os.fchmod(directory,0o2775)
            return result
        try:
            with patch.object(h,'resolve_head',side_effect=racing), self.assertRaises(c.ContractError):
                h.repository(self.root,self.expected)
        finally: os.close(directory)

    def test_fixed_evidence_payload_requires_kernel_writer_exclusion(self):
        evidence = self.base/'synthetic-evidence.json'
        payload = b'{"synthetic":true}\n'; evidence.write_bytes(payload); evidence.chmod(0o600)
        digest = hashlib.sha256(payload).hexdigest()
        self.assertEqual(o.file_bytes(evidence,expected=digest,historical_capture=True),payload)
        writer = os.open(evidence,os.O_RDWR)
        try:
            with self.assertRaisesRegex(c.ContractError,'WRITER_EXCLUSION_UNAVAILABLE'):
                o.file_bytes(evidence,expected=digest,historical_capture=True)
        finally: os.close(writer)

    def test_broken_lease_is_latched_no_reclaim_or_capture_resume(self):
        witness = h.GitReadWitness(self.real_git)
        path = self.real_git/'HEAD'
        try:
            with self.assertRaises(OSError): os.open(path,os.O_WRONLY | os.O_NONBLOCK)
            with self.assertRaisesRegex(c.ContractError,'LEASE_BREAK'): witness.check()
            with self.assertRaisesRegex(c.ContractError,'WITNESS_LOST'): witness.check()
            fd = os.open(path,os.O_RDONLY)
            try:
                with patch.object(k.fcntl,'fcntl',wraps=k.fcntl.fcntl) as call:
                    with self.assertRaises(c.ContractError): witness.leases.acquire(fd)
                call.assert_not_called()
            finally: os.close(fd)
        finally: witness.close()

    def test_capture_deadline_loss_fails_without_retry(self):
        witness = h.GitReadWitness(self.real_git)
        try:
            witness.leases.deadline = 0
            with self.assertRaisesRegex(c.ContractError,'CAPTURE_TIMEOUT'): witness.check()
            with self.assertRaisesRegex(c.ContractError,'WITNESS_LOST'): witness.check()
        finally: witness.close()

    def test_native_git_gc_packed_refs_and_objects_match_git_oracle(self):
        args = ['--git-dir='+str(self.real_git),'--work-tree='+str(self.root)]
        for i in range(8):
            (self.root/'synthetic.txt').write_bytes(b'nearly-identical synthetic payload\n'*200+str(i).encode())
            self.git([*args,'add','synthetic.txt'])
            self.git([*args,'-c','user.name=Synthetic','-c','user.email=fixture@example.invalid',
                      'commit','--quiet','-m','synthetic-pack'])
        self.git([*args,'gc','--aggressive','--prune=now'])  # only this test's synthetic fixture
        expected = tuple(self.git([*args,'rev-parse',ref]).decode().strip() for ref in ('HEAD','HEAD^{tree}'))
        self.assertTrue(list((self.real_git/'objects/pack').glob('*.idx')))
        with patch.object(h,'resolve_head',wraps=h.resolve_head) as read:
            actual = h.repository(self.root,expected)
        self.assertEqual((actual['commit'],actual['tree']),expected)
        self.assertEqual(read.call_count,1)
        self.assertFalse(hasattr(h,'git_read'))

    def test_readonly_bind_alias_does_not_hide_foreign_writer(self):
        alias = self.base/'readonly-alias'; alias.mkdir()
        profiles = {alias:(1001,0o2550,p.APPLICATION_ACCESS,p.REPOSITORY_DEFAULT),
            alias/'.git':(0,0,((1,0,p.UNDEFINED),*p.GIT_ACCESS[1:]),p.REPOSITORY_DEFAULT),
            alias/'.git.s12-1-recovery':(0,0o700,p.GIT_ACCESS,p.REPOSITORY_DEFAULT)}
        subprocess.run(['/usr/bin/mount','--bind',str(self.root),str(alias)],check=True)
        try:
            subprocess.run(['/usr/bin/mount','-o','remount,bind,ro',str(alias)],check=True)
            writer = os.open(self.real_git/'HEAD',os.O_RDWR)
            try:
                with patch.dict(p.HISTORICAL_PROFILES,profiles), self.assertRaisesRegex(
                        c.ContractError,'WRITER_EXCLUSION_UNAVAILABLE'):
                    h.repository(alias,self.expected)
            finally: os.close(writer)
            with patch.dict(p.HISTORICAL_PROFILES,profiles):
                self.assertEqual(h.repository(alias,self.expected)['commit'],self.expected[0])
                original = h.resolve_head
                done = False
                def racing(args,**options):
                    nonlocal done
                    result = original(args,**options)
                    if not done:
                        done = True
                        with self.assertRaises(OSError): os.open(self.real_git/'HEAD',os.O_WRONLY | os.O_NONBLOCK)
                    return result
                with patch.object(h,'resolve_head',side_effect=racing), self.assertRaises(c.ContractError):
                    h.repository(alias,self.expected)
                self.assertTrue(done)
        finally: subprocess.run(['/usr/bin/umount',str(alias)],check=True)

    def test_canonical_history_aggregate_validates_inputs_not_cached_success(self):
        history = self.base/'synthetic-history'; history.mkdir(mode=0o700)
        hashes = {}
        for name in o.HISTORY_HASHES:
            payload = ('{"synthetic":"'+name+'"}\n').encode()
            (history/name).write_bytes(payload); (history/name).chmod(0o600)
            hashes[name] = hashlib.sha256(payload).hexdigest()
        role_roots = {name:self.root for name in o.HISTORICAL_ROOTS}
        def mapped_path(text): return role_roots.get(str(text),Path(text))
        with patch.object(o,'HISTORY',history), patch.object(o,'HISTORY_HASHES',hashes), \
             patch.object(c,'HISTORICAL_APPLICATION',self.expected), \
             patch.object(c,'HISTORICAL_CONTROL',self.expected), \
             patch.object(o,'HISTORICAL_ROOTS',{name:self.expected for name in role_roots}), \
             patch.object(o,'Path',side_effect=mapped_path):
            value = o.history()
            self.assertEqual(value['hashes'],hashes)
            self.assertEqual(set(value['repositories']),set(role_roots))
            self.assertEqual(c.SLOT,'s8-same-release-20261004-1')
            (history/next(iter(hashes))).write_bytes(b'{"synthetic":"changed"}\n')
            with self.assertRaisesRegex(c.ContractError,'INPUT_DIGEST_RED'): o.history()

    def test_primary_and_cleanup_failure_both_retained_all_descriptors_closed(self):
        before = len(os.listdir('/proc/self/fd'))
        real_close = os.close
        active = False; failed = False
        def read(*args,**options):
            nonlocal active
            active = True
            raise PermissionError('private synthetic content not disclosed')
        def close(fd):
            nonlocal failed
            real_close(fd)
            if active and not failed:
                failed = True
                raise OSError('private synthetic close acknowledgement')
        with patch.object(h,'resolve_head',side_effect=read), patch.object(c.os,'close',side_effect=close):
            with self.assertRaisesRegex(c.ContractError,'HISTORICAL_READ_UNAVAILABLE') as failure:
                h.repository(self.root,self.expected)
        self.assertTrue(failed)
        self.assertEqual(failure.exception._s8_read_failure['type'],'PermissionError')
        self.assertTrue(failure.exception._s8_cleanup_errors)
        self.assertFalse(hasattr(failure.exception,'_s8_abort_error'))
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_late_evidence_change_or_marker_restore_invalidates_whole_history(self):
        for scenario in ('evidence-writer','marker-restore'):
            with self.subTest(scenario=scenario):
                history = self.base/scenario; history.mkdir(mode=0o700)
                hashes = {}
                for name in o.HISTORY_HASHES:
                    payload = ('{"synthetic":"'+name+'"}\n').encode()
                    (history/name).write_bytes(payload); (history/name).chmod(0o600)
                    hashes[name] = hashlib.sha256(payload).hexdigest()
                roles = {name:self.root for name in o.HISTORICAL_ROOTS}
                def mapped_path(text): return roles.get(str(text),Path(text))
                original = h.resolve_head
                done = False
                def racing(args,**options):
                    nonlocal done
                    result = original(args,**options)
                    if not done:
                        done = True
                        if scenario == 'evidence-writer':
                            with self.assertRaises(OSError):
                                os.open(history/next(iter(hashes)),os.O_WRONLY | os.O_NONBLOCK)
                        else:
                            marker = history/o.ABSENT_MARKERS[0]
                            marker.write_bytes(b'synthetic concurrent marker'); marker.unlink()
                    return result
                with patch.object(o,'HISTORY',history), patch.object(o,'HISTORY_HASHES',hashes), \
                     patch.object(c,'HISTORICAL_APPLICATION',self.expected), \
                     patch.object(c,'HISTORICAL_CONTROL',self.expected), \
                     patch.object(o,'HISTORICAL_ROOTS',{name:self.expected for name in roles}), \
                     patch.object(o,'Path',side_effect=mapped_path), \
                     patch.object(h,'resolve_head',side_effect=racing), self.assertRaises(c.ContractError):
                    o.history()
                self.assertTrue(done)
                while k.LEASE_SIGNAL in k.signal.sigpending():
                    k.signal.sigtimedwait({k.LEASE_SIGNAL},0)  # isolated case teardown only


if __name__ == '__main__': unittest.main()
