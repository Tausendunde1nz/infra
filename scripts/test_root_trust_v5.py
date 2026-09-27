import errno
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import tu1nz_root_trust_v5 as m

class Tests(unittest.TestCase):
    def test_safe_read(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'x';p.write_bytes(b'fixture')
            self.assertEqual(m.strict_read(str(p)),b'fixture')
    def test_link_and_parent_link_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve();(p/'x').write_text('x');(p/'l').symlink_to(p/'x');(p/'dir').symlink_to(p)
            for target in (p/'l',p/'dir'/'x'):
                with self.assertRaises(OSError):m.strict_read(str(target))
    def test_fifo_size_and_relative_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve();os.mkfifo(p/'f');(p/'x').write_bytes(b'large')
            for target,limit in ((str(p/'f'),100),(str(p/'x'),1),('relative',10)):
                with self.assertRaises(ValueError):m.strict_read(target,limit)
    def test_drift_detected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'x';p.write_text('x');real=m.os.fstat;counter=[0]
            def changed(fd):
                value=real(fd);counter[0]+=1
                if counter[0]==len(p.parts)+1:p.write_text('changed')
                return value
            # Deterministically replace the final pathname after the read begins.
            original=m.os.read
            def swap(fd,n):
                data=original(fd,n)
                if data:p.unlink();p.write_text('new')
                return data
            with patch.object(m.os,'read',side_effect=swap):
                with self.assertRaises(ValueError):m.strict_read(str(p))
    def test_acl_mask(self):
        raw=struct.pack('<I',2)+b''.join(struct.pack('<HHI',*x) for x in [(1,7,0xffffffff),(2,7,1001),(4,7,0xffffffff),(16,5,0xffffffff),(32,0,0xffffffff)])
        acl=m.acl_entries(raw)
        class S:st_uid=0;st_gid=0;st_mode=0o775
        self.assertEqual(m.access_bits(S,1001,{1001},acl),5)
        self.assertEqual(m.access_bits(S,0,{0},acl),7)
    def test_invalid_acl_denied(self):
        for raw in (b'',b'bad!',struct.pack('<IHHI',2,99,7,0)):
            with self.assertRaises(ValueError):m.acl_entries(raw)
    def test_symlink_expected_and_wrong(self):
        safe={'path':'/fixed/link','symlink':True,'uid':0,'chatops_write_bit':True,'mode':'0o777'}
        root={'path':'/','symlink':False,'uid':0,'chatops_write_bit':False,'mode':'0o755'}
        target=dict(root,path='/fixed/target')
        def chain(path,*_):return [root,safe] if path=='/fixed/link' else [root,target]
        with patch.object(m,'components',side_effect=chain),patch.object(m.os.path,'realpath',return_value='/fixed/target'),patch.object(m,'strict_read',return_value=b'x'):
            self.assertEqual(m.safe_symlink('/fixed/link','/fixed/target',1001,{1001})['classification'],'EXPECTED_SAFE_SYMLINK')
            self.assertEqual(m.safe_symlink('/fixed/link','/wrong',1001,{1001})['classification'],'UNSAFE_SYMLINK')
    def test_symlink_swap_rejected(self):
        a={'path':'/link','symlink':True,'uid':0,'chatops_write_bit':True,'mode':'0o777'}
        b={'path':'/target','symlink':False,'uid':0,'chatops_write_bit':False,'mode':'0o644'}
        with patch.object(m,'components',side_effect=[[a],[b],[dict(a,target='changed')]]),patch.object(m.os.path,'realpath',return_value='/target'),patch.object(m,'strict_read',return_value=b'x'):
            self.assertEqual(m.safe_symlink('/link','/target',1001,{1001})['classification'],'REVIEW_REQUIRED')
    def test_missing_symlink_target(self):
        with patch.object(m,'components',side_effect=FileNotFoundError()):
            self.assertEqual(m.safe_symlink('/x','/y',1001,{1001})['classification'],'MISSING_TARGET')
    def test_safe_symlink_writable_target_denied(self):
        a={'path':'/link','symlink':True,'uid':0,'chatops_write_bit':True,'mode':'0o777'}
        b={'path':'/target','symlink':False,'uid':1001,'chatops_write_bit':True,'mode':'0o644'}
        with patch.object(m,'components',side_effect=[[a],[b]]),patch.object(m.os.path,'realpath',return_value='/target'):
            self.assertEqual(m.safe_symlink('/link','/target',1001,{1001})['classification'],'UNSAFE_SYMLINK')
    def test_atomic_store_and_secret_suppression(self):
        with tempfile.TemporaryDirectory() as d:
            s=m.Store(d);s.section('ok',lambda:{'count':1})
            def fail():raise ValueError('SECRET_CANARY')
            s.section('bad',fail)
            self.assertNotIn('SECRET_CANARY',(Path(d)/'bad.json').read_text())
            self.assertEqual((Path(d)/'ok.json').stat().st_mode&0o777,0o600)
            self.assertFalse(list(Path(d).glob('.tmp-*')))
            with self.assertRaises(ValueError):s.write('ok.json',b'overwrite')
    def test_large_output(self):
        with self.assertRaises(ValueError):m.bounded_command([sys.executable,'-I','-c','print("x"*10000)'],limit=100)
    def test_timeout(self):
        with self.assertRaises(TimeoutError):m.bounded_command([sys.executable,'-I','-c','import time;time.sleep(10)'],timeout=.05)
    def test_rc_stderr_missing(self):
        for code in ('raise SystemExit(1)','import sys;sys.stderr.write("SECRET_CANARY")'):
            with self.assertRaises(ValueError) as cm:m.bounded_command([sys.executable,'-I','-c',code])
            self.assertNotIn('SECRET_CANARY',str(cm.exception))
        with self.assertRaises(FileNotFoundError):m.bounded_command(['/not/a/program'])
    def test_no_root_execution_unbound(self):
        with patch.object(m.os,'getuid',return_value=0),patch.object(m.os,'geteuid',return_value=0),patch.object(m.sys,'argv',['collector']):self.assertEqual(m.main(),3)
    def test_graph_never_ready(self):
        c=m.Collector.__new__(m.Collector);c.nodes={};c.edges=[]
        self.assertFalse(c.graph()['activation_ready']);self.assertEqual(c.graph()['status'],'INCOMPLETE')
    def test_journal_no_payload(self):
        row=m.journal_counts(b'{"MESSAGE":"SECRET_CANARY build_system_doc.sh"}\n')
        self.assertEqual(row['known_command_mentions']['build_system_doc.sh'],1)
        self.assertNotIn('SECRET_CANARY',str(row))
    def test_journal_invalid_json_or_schema(self):
        for data in (b'{bad',b'[]',b'{"MESSAGE":123}'):
            with self.assertRaises((ValueError,TypeError)):m.journal_counts(data)
    def test_unit_arguments_not_exported(self):
        with tempfile.TemporaryDirectory() as d:
            c=m.Collector(m.Store(d))
            responses=[b'fixture.service enabled\n',b'fixture.service loaded active running test\n',b'Id=fixture.service\nUser=root\nExecStart={ path=/no/such/fixture; argv[]=/no/such/fixture SECRET_CANARY; }\n']
            with patch.object(m,'bounded_command',side_effect=responses):row=c.units()
            self.assertNotIn('SECRET_CANARY',str(row))
            self.assertEqual(row['units'][0]['executables'],['/no/such/fixture'])
    def test_docker_environment_not_retained(self):
        with tempfile.TemporaryDirectory() as d:
            c=m.Collector(m.Store(d));ident='a'*64
            fixture={'Name':'fixture','Image':'sha256:test','HostConfig':{'Privileged':True},'Config':{'User':'0','Env':['TOKEN=SECRET_CANARY']},'Mounts':[]}
            with patch.object(m,'bounded_command',side_effect=[ident.encode(),json.dumps([fixture]).encode()]):row=c.docker()
            self.assertNotIn('SECRET_CANARY',str(row))
            self.assertNotIn('SECRET_CANARY',(Path(d)/'docker-security.json').read_text())
            self.assertTrue(row['observations'][0]['privileged'])
    def test_candidate_not_automatically_safe(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input';p.write_text('import dynamic_module\n')
            c=m.Collector(m.Store(Path(d)/'evidence'))
            (Path(d)/'evidence').mkdir()
            c.record(str(p),'fixture')
            self.assertEqual(c.nodes[str(p)]['classification'],'REVIEW_REQUIRED')
            self.assertTrue(c.nodes[str(p)]['features']['python_import'])
    def test_root_categories(self):
        for key in ('systemd','cron','at-anacron','sudo','polkit','logrotate','package-hooks','network-hooks','boot-shutdown','docker'):self.assertIn(key,m.ROOTS)
    def test_interrupt_preserves_section(self):
        with tempfile.TemporaryDirectory() as d:
            s=m.Store(d);s.section('first',lambda:True)
            with self.assertRaises(KeyboardInterrupt):s.section('later',lambda:(_ for _ in ()).throw(KeyboardInterrupt()))
            self.assertTrue((Path(d)/'first.json').is_file());self.assertTrue((Path(d)/'later.json').is_file())

if __name__=='__main__':unittest.main()
