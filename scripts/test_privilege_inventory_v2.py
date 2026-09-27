import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('tu1nz_privilege_inventory_v2')
t=load('tu1nz_privilege_migration_model')


class Tests(unittest.TestCase):
    def test_atomic_rename_failure_preserves_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            base=str(Path(d).resolve());os.chmod(base,0o700);store=m.Store(base,'a'*40,'b'*64,uid=os.getuid())
            store.section('first',lambda:1)
            previous=(Path(store.path)/'manifest.json').read_bytes()
            with patch.object(m.os,'rename',side_effect=PermissionError('SECRET_CANARY')):
                with self.assertRaises(PermissionError):store.section('second',lambda:2)
            self.assertEqual((Path(store.path)/'manifest.json').read_bytes(),previous)
            store.close()
    @unittest.skipUnless(sys.platform.startswith('linux'),'Linux process evidence')
    def test_descendant_timeout_cleanup(self):
        code='import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-I","-c","import time;time.sleep(60)"]);print(p.pid,flush=True);time.sleep(60)'
        status,data=m.run((sys.executable,'-I','-c',code),timeout=.3)
        self.assertTrue(status['timeout']);pid=int(data.strip());deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            try:state=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[0]
            except FileNotFoundError:break
            if state=='Z':break
            time.sleep(.02)
        else:self.fail('Descendant still executing')
    def test_fixed_environment(self):
        status,data=m.run((sys.executable,'-I','-c','import os,json;print(json.dumps(dict(os.environ)))'))
        env=json.loads(data)
        self.assertEqual(env['PATH'],m.ENV['PATH']);self.assertNotIn('PYTHONPATH',env);self.assertNotIn('LD_PRELOAD',env)
    def test_hash_binding(self):
        self.assertEqual(m.verified_bytes(b'known',m.digest(b'known')),b'known')
        with self.assertRaises(ValueError):m.verified_bytes(b'changed',m.digest(b'known'))
    def test_include_graph_cycle(self):
        values={'/etc/sudoers':b'@include /etc/child', '/etc/child':b'@include /etc/sudoers'}
        with patch.object(m,'secure_read',side_effect=lambda p:values[p]), patch.object(m,'metadata',side_effect=lambda p:{'path':p}):
            rows=m.sudo_graph()
        self.assertTrue(any(r.get('error')=='ValueError' for r in rows))
    def test_include_relative(self):
        self.assertEqual(m.include_directive('@include "child file"','/etc/sudoers'),('include','/etc/child file'))
    def test_include_directory(self):
        self.assertEqual(m.include_directive('#includedir /etc/sudoers.d','/etc/sudoers'),('includedir','/etc/sudoers.d'))
    def test_include_unresolved_rejected(self):
        for line in ('@include /etc/%h','@include x y'):
            with self.assertRaises(ValueError):m.include_directive(line,'/etc/sudoers')
    def test_unknown_rule_no_secret(self):
        r=m.safe_policy(b'chatops ALL=(root) NOPASSWD: /bin/a SECRET_CANARY')
        self.assertTrue(r[0]['nopasswd']);self.assertNotIn('SECRET_CANARY',str(r))
    def test_symlink_parent_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();(root/'actual').mkdir();(root/'actual'/'x').write_text('x');(root/'link').symlink_to(root/'actual')
            with self.assertRaises(OSError):m.secure_read(str(root/'link'/'x'))
    def test_symlink_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve();(p/'x').write_text('x');(p/'y').symlink_to(p/'x')
            with self.assertRaises(OSError):m.secure_read(str(p/'y'))
    def test_nonregular_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'fifo';os.mkfifo(p)
            with self.assertRaises(ValueError):m.secure_read(str(p))
    def test_size_limit(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'x';p.write_bytes(b'abcd')
            with self.assertRaises(ValueError):m.secure_read(str(p),2)
    def test_process_output_separate(self):
        status,data=m.run((sys.executable,'-I','-c','import sys;print("ok");sys.stderr.write("SECRET_CANARY");sys.exit(7)'))
        self.assertEqual(status['rc'],7);self.assertEqual(data,b'ok\n');self.assertEqual(status['stderr']['bytes'],13)
        self.assertNotIn('SECRET_CANARY',str(status))
    def test_timeout(self):
        status,_=m.run((sys.executable,'-I','-c','import time;time.sleep(10)'),timeout=.05)
        self.assertTrue(status['timeout'])
    def test_large_output(self):
        status,data=m.run((sys.executable,'-I','-c','print("x"*1000000)'),limit=1000)
        self.assertTrue(status['overflow']);self.assertLessEqual(len(data),1000)
    def test_missing_program(self):
        status,_=m.run(('/no/such/program',));self.assertEqual(status['exception'],'FileNotFoundError')
    def test_parser_failure(self):
        with patch.object(m,'run',return_value=({'rc':0},b'{invalid')):
            r=m.fixed_command(('/fixed',),json.loads)
        self.assertEqual(r['parser_error'],'JSONDecodeError')
    def test_atomic_partial_results(self):
        with tempfile.TemporaryDirectory() as d:
            base=str(Path(d).resolve());os.chmod(base,0o700)
            store=m.Store(base,'a'*40,'b'*64,uid=os.getuid())
            store.section('first',lambda:{'ok':True})
            def fail():raise ValueError('SECRET_CANARY')
            store.section('second',fail);store.close()
            out=Path(base)/store.name;r=json.loads((out/'manifest.json').read_text())
            self.assertEqual(r['status'],'INCOMPLETE');self.assertEqual(len(r['entries']),2)
            for e in r['entries']:
                p=out/e['file'];self.assertEqual(m.digest(p.read_bytes()),e['sha256']);self.assertEqual(p.stat().st_mode&0o777,0o600)
            self.assertNotIn('SECRET_CANARY',(out/'second.json').read_text())
            self.assertFalse(list(out.glob('tmp-*')))
    def test_signal_later_preserves_first(self):
        with tempfile.TemporaryDirectory() as d:
            base=str(Path(d).resolve());os.chmod(base,0o700);s=m.Store(base,'a'*40,'b'*64,uid=os.getuid())
            s.section('first',lambda:1)
            with self.assertRaises(InterruptedError):m.interrupt(15,None)
            s.close();self.assertTrue((Path(s.path)/'first.json').exists())
    def test_store_rejects_public_base(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o755)
            with self.assertRaises(ValueError):m.Store(str(Path(d).resolve()),'a'*40,'b'*64,uid=os.getuid())
    def test_migration_each_failure(self):
        gates={k:True for k in t.REQUIRED}
        old={'service_groups':{'s':(1001,987)},'docker_member':True,'old_sessions_present':True,'sudoers':'old','polkit':'old'}
        for step in t.STEPS:
            r=t.simulate(old,gates,fail_at=step)
            self.assertEqual(r['state'],old);self.assertEqual(r['status'],'ROLLED_BACK_MODEL')
    def test_unknown_rules_block(self):
        gates={k:True for k in t.REQUIRED};gates['unknown_rules']=True
        with self.assertRaises(ValueError):t.plan(gates)
    def test_missing_authorization_blocks(self):
        gates={k:True for k in t.REQUIRED};gates['activation_authorized']=False
        with self.assertRaises(ValueError):t.plan(gates)
    def test_rollback_failure_watchdog_stays(self):
        r=t.simulate({}, {k:True for k in t.REQUIRED},fail_at='broker',rollback_fail=True)
        self.assertEqual(r['status'],'RECOVERY_REQUIRED');self.assertTrue(r['watchdog'])

if __name__=='__main__':unittest.main(verbosity=2)
