import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import shlex
import tempfile
import unittest
from unittest.mock import patch


def load(name):
 s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('tu1nz_privilege_followup_v3');lab=load('tu1nz_privilege_fs_simulation');validator=load('tu1nz_privilege_followup_validate');launcher=load('tu1nz_privilege_followup_launcher')

class Tests(unittest.TestCase):
 def test_launcher_binding_and_no_execution(self):
  text=launcher.generate('a'*40,'b'*64)
  remote=shlex.split(text.split('\n',1)[1])[-1];bootstrap=shlex.split(remote)[-1];compile(bootstrap,'bootstrap','exec')
  self.assertIn("'PINNED_COMMIT'",bootstrap);self.assertIn("'PINNED_SUBJECT'",bootstrap)
  self.assertEqual(bootstrap.count("'/usr/bin/sudo'"),1)
  self.assertNotIn('--allow-user-interaction',bootstrap)
 def test_launcher_rejects_injected_binding(self):
  with self.assertRaises(ValueError):launcher.generate('bad; command','b'*64)
 def test_validator_tampering(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();os.chmod(root,0o700);p=root/'raw-000.bin';p.write_bytes(b'private');p.chmod(0o600)
   manifest={'expected_commit':'a'*40,'script_sha256':'b'*64,'file_hashes':{p.name:m.digest(p.read_bytes())},'status':'INCOMPLETE'}
   q=root/'manifest.json';q.write_text(json.dumps(manifest));q.chmod(0o600)
   self.assertTrue(validator.validate(root,'a'*40,'b'*64)['integrity_valid'])
   p.write_bytes(b'changed')
   with self.assertRaises(ValueError):validator.validate(root,'a'*40,'b'*64)
 def test_validator_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();os.chmod(root,0o700);(root/'manifest.json').symlink_to('/etc/passwd')
   with self.assertRaises(OSError):validator.validate(root,'a'*40,'b'*64)
 def test_raw_streams_separate(self):
  r,out,err=m.run((sys.executable,'-I','-c','import sys;print("RAW_SECRET");sys.stderr.write("ERR_SECRET");sys.exit(8)'))
  self.assertEqual(r['rc'],8);self.assertEqual(out,b'RAW_SECRET\n');self.assertEqual(err,b'ERR_SECRET');self.assertNotIn('SECRET',str(r))
 def test_timeout(self):
  r,_,_=m.run((sys.executable,'-I','-c','import time;time.sleep(20)'),timeout=.05);self.assertTrue(r['timeout'])
 def test_missing_program(self):
  r,_,_=m.run(('/missing/program',));self.assertEqual(r['exception'],'FileNotFoundError')
 def test_output_limit(self):
  r,out,_=m.run((sys.executable,'-I','-c','print("a"*100000)'),limit=100);self.assertTrue(r['overflow']);self.assertEqual(len(out),100)
 def test_include_spaces(self):self.assertEqual(m.include_directive('@include "file name"','/etc/sudoers'),('include','/etc/file name'))
 def test_unknown_include(self):
  with self.assertRaises(ValueError):m.include_directive('@include a b','/etc/sudoers')
 def test_private_raw_atomic(self):
  with tempfile.TemporaryDirectory() as d:
   root=str(Path(d).resolve());os.chmod(root,0o700);s=m.Store(root,'a'*40,'b'*64,uid=os.getuid());c=m.Collector(s)
   ref=c.raw(b'PRIVATE_SECRET');s.close();p=Path(s.path)/ref['file']
   self.assertEqual(p.read_bytes(),b'PRIVATE_SECRET');self.assertEqual(p.stat().st_mode&0o777,0o600)
   self.assertNotIn('PRIVATE_SECRET',(Path(s.path)/'manifest.json').read_text())
 def test_partial_survives_error(self):
  with tempfile.TemporaryDirectory() as d:
   root=str(Path(d).resolve());os.chmod(root,0o700);s=m.Store(root,'a'*40,'b'*64,uid=os.getuid());c=m.Collector(s)
   ref=c.raw(b'first');s.section('later',lambda:1/0);s.close()
   self.assertEqual((Path(s.path)/ref['file']).read_bytes(),b'first')
   self.assertEqual(json.loads((Path(s.path)/'later.json').read_text())['exception'],'ZeroDivisionError')
 def test_signal_aborts_section(self):
  with tempfile.TemporaryDirectory() as d:
   root=str(Path(d).resolve());os.chmod(root,0o700);s=m.Store(root,'a'*40,'b'*64,uid=os.getuid())
   s.section('first',lambda:1)
   with self.assertRaises(m.Interrupted):s.section('second',lambda:m.stop(15,None))
   s.close();self.assertTrue((Path(s.path)/'first.json').exists())
 def test_sudo_include_cycle(self):
  with tempfile.TemporaryDirectory() as d:
   root=str(Path(d).resolve());os.chmod(root,0o700);s=m.Store(root,'a'*40,'b'*64,uid=os.getuid());c=m.Collector(s)
   with patch.object(c,'bytes',return_value=b'@include /etc/sudoers'),patch.object(c,'capture',return_value={}):
    with self.assertRaises(ValueError):c.sudo()
   s.close();self.assertTrue((Path(s.path)/'include-graph.json').exists())
 def test_live_paths_rejected_by_lab(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError):lab.Laboratory(d)
 def setup_lab(self):
  temp=tempfile.TemporaryDirectory(prefix='privilege-fixture-');root=Path(temp.name).resolve();os.chmod(root,0o700)
  l=lab.Laboratory(root);l.fixture();return temp,l
 def test_all_failures_restore_actual_files(self):
  for phase in ('broker','sudoers','polkit','group','unit','services','ssh','finalize'):
   for when in ('before','after','watchdog'):
    tmp,l=self.setup_lab()
    try:
     l.backup();old=l.snapshot();self.assertEqual(l.execute(when+':'+phase),'ROLLED_BACK_FIXTURE');self.assertEqual(l.snapshot(),old)
     self.assertFalse(l.watchdog);self.assertTrue(all(x=='active' for x in l.services.values()))
    finally:tmp.cleanup()
 def test_service_failures_and_disconnect(self):
  for fail in ('service:core','service:landing','service:telegram','service:wms','disconnect'):
   tmp,l=self.setup_lab()
   try:l.backup();self.assertEqual(l.execute(fail),'ROLLED_BACK_FIXTURE');self.assertEqual(l.snapshot(),l.original)
   finally:tmp.cleanup()
 def test_success_and_manual_rollback(self):
  tmp,l=self.setup_lab()
  try:
   l.backup();self.assertEqual(l.execute(),'FIXTURE_SUCCESS');self.assertFalse(l.watchdog);l.restore();self.assertEqual(l.snapshot(),l.original)
  finally:tmp.cleanup()
 def test_checksum_failure_blocks_restore(self):
  tmp,l=self.setup_lab()
  try:
   l.backup();(l.root/'before.json').write_text('corrupt')
   with self.assertRaises(ValueError):l.restore()
  finally:tmp.cleanup()
 def test_unknown_baseline_or_missing_file(self):
  for value in ('unknown','missing'):
   tmp,l=self.setup_lab()
   try:
    l.backup()
    if value=='unknown':l.path('etc/sudoers').write_bytes(b'unknown grant')
    else:l.path('etc/sudoers').unlink()
    with self.assertRaises(ValueError):l.execute()
   finally:tmp.cleanup()
 @unittest.skipUnless(sys.platform.startswith('linux'),'Linux ACLs')
 def test_real_acl_rollback(self):
  tmp,l=self.setup_lab()
  try:
   subprocess.run(['/usr/bin/setfacl','-m','u:65534:r--,m::r--',str(l.path('state/state.json'))],check=True)
   subprocess.run(['/usr/bin/setfacl','-m','d:u::rwx,d:g::r-x,d:o::---',str(l.path('state'))],check=True)
   l.path('state').chmod(0o2750)
   l.backup();before=l.snapshot();l.execute('after:group');self.assertEqual(l.snapshot(),before)
  finally:tmp.cleanup()
 def test_auth_rejects_fabricated_subject(self):
  with patch.dict(m.__dict__,{'PINNED_SUBJECT':'bad'}):
   with self.assertRaises(ValueError):m.Collector(None).auth()

if __name__=='__main__':unittest.main(verbosity=2)
