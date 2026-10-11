"""Synthetic UID1001 regular-input capture; native ext4, no production data."""
import errno
import fcntl
import mmap
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_s8_execution_contract as c
import tu1nz_s8_historical_read as h
import tu1nz_s8_path_policy as p
from tests import test_s8_historical_read as native_fixture


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0 and
                    os.environ.get('container')=='docker','isolated native Linux only')
class OwnedInputs(unittest.TestCase):
    def setUp(self):
        self.fixture=native_fixture.NativeReadTests('test_exact_group_acl_reads_preserve_bytes_metadata_and_index')
        self.fixture.setUp()
        self.root,self.real_git,self.expected=self.fixture.root,self.fixture.real_git,self.fixture.expected
        self.config=self.real_git/'config'
        os.chown(self.config,1001,1001);self.config.chmod(0o660)
        access=((1,6,p.UNDEFINED),*p.GIT_ACCESS[1:4],(16,6,p.UNDEFINED),(32,0,p.UNDEFINED))
        os.setxattr(self.config,p.ACCESS,p.acl_bytes(access))
        self.extra=self.real_git/'synthetic-observation.json';self.extra.write_bytes(b'{"synthetic":true}\n')
        os.chown(self.extra,1001,1001);self.extra.chmod(0o600)
        for name in os.listxattr(self.extra):os.removexattr(self.extra,name)
        self.before={path:(c.fingerprint(path.lstat()),path.read_bytes(),
            {name:os.getxattr(path,name) for name in os.listxattr(path)}) for path in (self.config,self.extra)}
        self.fd_before=len(os.listdir('/proc/self/fd'))

    def tearDown(self):
        self.assertEqual(len(os.listdir('/proc/self/fd')),self.fd_before)
        self.fixture.tearDown()

    def test_exact_owned_regular_inputs_capture_without_normalization(self):
        value=h.repository(self.root,self.expected)
        self.assertEqual((value['commit'],value['tree']),self.expected)
        after={path:(c.fingerprint(path.lstat()),path.read_bytes(),
            {name:os.getxattr(path,name) for name in os.listxattr(path)}) for path in self.before}
        self.assertEqual(self.before,after)

    def test_descriptor_free_route_still_denies_known_regular_owner(self):
        for path in (self.config,self.extra):
            with self.assertRaisesRegex(c.ContractError,'UNSAFE_METADATA'):h.node_metadata(path)

    def test_no_lease_no_owner_exception(self):
        fd=os.open(self.config,os.O_RDONLY)
        try:
            self.assertEqual(fcntl.fcntl(fd,fcntl.F_GETLEASE),fcntl.F_UNLCK)
            with self.assertRaisesRegex(c.ContractError,'LEASE_BREAK'):
                h.node_metadata(self.config,descriptor=fd)
        finally:os.close(fd)

    def test_unknown_owner_group_and_acl_still_denied(self):
        for case in ('owner','group','acl'):
            with self.subTest(case=case):
                if case=='owner':os.chown(self.config,1002,1001)
                elif case=='group':os.chown(self.config,1001,1002)
                else:
                    acl=((1,6,p.UNDEFINED),(2,7,1002),(4,7,p.UNDEFINED),(16,6,p.UNDEFINED),(32,0,p.UNDEFINED))
                    os.setxattr(self.config,p.ACCESS,p.acl_bytes(acl))
                with patch.object(h,'resolve_head') as read,self.assertRaisesRegex(c.ContractError,'UNSAFE_'):
                    h.repository(self.root,self.expected)
                read.assert_not_called()
                os.chown(self.config,1001,1001)
                os.setxattr(self.config,p.ACCESS,self.before[self.config][2][p.ACCESS])

    def test_retained_owner_writer_fd_or_shared_mapping_denies_before_content(self):
        for use_map in (False,True):
            with self.subTest(use_map=use_map):
                fd=os.open(self.config,os.O_RDWR)
                mapping=mmap.mmap(fd,0,access=mmap.ACCESS_WRITE) if use_map else None
                if mapping is not None:os.close(fd)
                try:
                    with patch.object(h,'resolve_head') as read,self.assertRaisesRegex(
                            c.ContractError,'WRITER_EXCLUSION_UNAVAILABLE'):
                        h.repository(self.root,self.expected)
                    read.assert_not_called()
                finally:
                    if mapping is not None:mapping.close()
                    else:os.close(fd)

    def test_foreign_capability_free_actual_owner_retained_writer_denies(self):
        child_source='''import mmap,os,sys
fd=int(sys.argv[1]); use_map=sys.argv[2]=='map'
os.setgroups([]);os.setgid(1001);os.setuid(1001)
assert next(x for x in open('/proc/self/status') if x.startswith('CapEff:')).split()[1]=='0000000000000000'
assert os.fstat(fd).st_uid==os.geteuid()==1001
mapping=mmap.mmap(fd,0,access=mmap.ACCESS_WRITE) if use_map else None
if mapping is not None:os.close(fd)
print('OWNER_READY',flush=True);sys.stdin.buffer.read(1)
if mapping is not None:mapping.close()
else:os.close(fd)
'''
        for mode in ('fd','map'):
            writer=os.open(self.config,os.O_RDWR)
            child=subprocess.Popen([sys.executable,'-I','-B','-c',child_source,str(writer),mode],
                pass_fds=(writer,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            os.close(writer)
            try:
                self.assertEqual(child.stdout.readline(),b'OWNER_READY\n')
                with patch.object(h,'resolve_head') as read,self.assertRaisesRegex(
                        c.ContractError,'WRITER_EXCLUSION_UNAVAILABLE'):
                    h.repository(self.root,self.expected)
                read.assert_not_called()
            finally:_,error=child.communicate(b'x',timeout=5)
            self.assertEqual(child.returncode,0,error.decode())

    def test_owner_metadata_change_restore_via_retained_read_fd_rejects(self):
        child_source='''import os,sys
fd=int(sys.argv[1]);os.setgroups([]);os.setgid(1001);os.setuid(1001)
assert next(x for x in open('/proc/self/status') if x.startswith('CapEff:')).split()[1]=='0000000000000000'
assert os.fstat(fd).st_uid==os.geteuid()==1001
print('OWNER_READY',flush=True);sys.stdin.buffer.read(1)
os.fchmod(fd,0o600);os.fchmod(fd,0o660);os.close(fd)
'''
        retained=os.open(self.config,os.O_RDONLY)
        child=subprocess.Popen([sys.executable,'-I','-B','-c',child_source,str(retained)],
            pass_fds=(retained,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        os.close(retained);original=h.resolve_head;changed=False
        try:
            self.assertEqual(child.stdout.readline(),b'OWNER_READY\n')
            def racing(witness):
                nonlocal changed
                value=original(witness);changed=True
                _,error=child.communicate(b'x',timeout=5)
                self.assertEqual(child.returncode,0,error.decode())
                return value
            with patch.object(h,'resolve_head',side_effect=racing),self.assertRaisesRegex(
                    c.ContractError,'READ_CHANGED'):
                h.repository(self.root,self.expected)
            self.assertTrue(changed)
        finally:
            if child.poll() is None:child.communicate(b'x',timeout=5)

    def test_new_owner_write_via_fd_alias_breaks_lease_no_retry(self):
        child_source='''import errno,os,sys
fd=int(sys.argv[1]);os.setgroups([]);os.setgid(1001);os.setuid(1001)
assert os.fstat(fd).st_uid==os.geteuid()==1001
assert next(x for x in open('/proc/self/status') if x.startswith('CapEff:')).split()[1]=='0000000000000000'
print('OWNER_READY',flush=True);sys.stdin.buffer.read(1)
try:writer=os.open('/proc/self/fd/'+str(fd),os.O_WRONLY|os.O_NONBLOCK)
except OSError as e:assert e.errno in (errno.EAGAIN,errno.EWOULDBLOCK)
else:os.close(writer);raise SystemExit('unfenced owner write')
os.close(fd)
'''
        retained=os.open(self.config,os.O_RDONLY)
        child=subprocess.Popen([sys.executable,'-I','-B','-c',child_source,str(retained)],
            pass_fds=(retained,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        os.close(retained);original=h.resolve_head;attempted=False
        try:
            self.assertEqual(child.stdout.readline(),b'OWNER_READY\n')
            def racing(witness):
                nonlocal attempted
                value=original(witness);attempted=True
                _,error=child.communicate(b'x',timeout=5);self.assertEqual(child.returncode,0,error.decode())
                return value
            with patch.object(h,'resolve_head',side_effect=racing),self.assertRaisesRegex(
                    c.ContractError,'LEASE_BREAK'):
                h.repository(self.root,self.expected)
            self.assertTrue(attempted)
        finally:
            if child.poll() is None:child.communicate(b'x',timeout=5)
        self.assertEqual(self.config.read_bytes(),self.before[self.config][1])

    def test_hardlink_interruption_and_changed_metadata_not_resumed(self):
        os.link(self.extra,self.real_git/'synthetic-link')
        with self.assertRaisesRegex(c.ContractError,'UNSAFE_METADATA'):h.repository(self.root,self.expected)
        (self.real_git/'synthetic-link').unlink()
        with patch.object(h,'resolve_head',side_effect=KeyboardInterrupt) as read:
            with self.assertRaises(KeyboardInterrupt):h.repository(self.root,self.expected)
        self.assertEqual(read.call_count,1)
        witness=h.GitReadWitness(self.real_git)
        try:
            self.extra.chmod(0o400)
            with self.assertRaisesRegex(c.ContractError,'READ_CHANGED'):witness.check()
            self.extra.chmod(0o600)
            with self.assertRaisesRegex(c.ContractError,'WITNESS_LOST'):witness.check()
        finally:witness.close()


if __name__=='__main__':unittest.main()
