import unittest,os,sys,tempfile,shutil,subprocess
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
HERE=Path(__file__).parent
sys.path[:0]=[str(HERE),str(HERE.parent/'v11_dispatcher'),str(HERE.parent/'v11_guard_recovery')]
from anchor import *
import phase0,base_host,build_validation,decommission
class Edges(unittest.TestCase):
 def setUp(self):
  self.path=Path(tempfile.mkdtemp(prefix='tu1nz-anchor-test-',dir='/tmp'));self.path.rmdir();self.s=None
 def tearDown(self):
  if self.s:self.s.close()
  shutil.rmtree(self.path,ignore_errors=True)
 def prepare(self):
  phase0.prepare(self.path,b'anchor',[b'A',b'B'],'/usr/bin/python3.12','a'*64,['/run/test-payload'],fixture=True);self.s=Store(self.path,fixture=True)
 def test_phase0_paths_and_ancestors_never_in_main_rollback(self):
  for p in (ROOT,VALIDATION_ROOT,'/var/lib','/run','/etc','/etc/systemd/system/tu1nz-v11-anchor-watch.timer','/run/systemd/system/tu1nz-v11-validation-watch.timer'):
   with self.assertRaises(Refused):phase0.prepare(self.path,b'a',[b'b'],'/usr/bin/python3.12','a'*64,[p],fixture=True)
   self.assertFalse(self.path.exists())
 def test_preparation_idempotent_without_rewrite(self):
  self.prepare();before={p.name:(p.stat().st_ino,p.read_bytes()) for p in self.path.iterdir()}
  result=phase0.prepare(self.path,b'anchor',[b'A',b'B'],'/usr/bin/python3.12','a'*64,['/run/test-payload'],fixture=True)
  self.assertFalse(result['changed']);self.assertEqual(before,{p.name:(p.stat().st_ino,p.read_bytes()) for p in self.path.iterdir()})
 def test_parent_default_acl_rejected(self):
  self.path.mkdir(mode=0o700)
  tool=shutil.which('setfacl');self.assertIsNotNone(tool,'ACL tools are required, never skipped')
  subprocess.run([tool,'-m','d:u:65534:r-x',str(self.path)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  with self.assertRaisesRegex(Refused,'METADATA'):Store(self.path,fixture=True)
 def test_slot_access_acl_rejected(self):
  self.prepare();tool=shutil.which('setfacl');self.assertIsNotNone(tool)
  subprocess.run([tool,'-m','u:65534:r--',str(self.path/'slot-A.py')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  with self.assertRaises(Refused):self.s.choose()
 def test_wrong_owner_metadata_refused(self):
  self.prepare();fd=self.s.open('slot-A.py',0o500)
  try:
   with self.assertRaises(Refused):metadata(fd,os.geteuid()+1,0o500)
  finally:os.close(fd)
 def test_creation_identity_recorded_before_first_record(self):
  got=[]
  phase0.prepare(self.path,b'a',[b'b'],'/usr/bin/python3.12','a'*64,['/run/test-payload'],fixture=True,created=lambda x:got.append((x,list(self.path.iterdir()))))
  self.assertEqual(len(got),1);self.assertEqual(got[0][1],[]);self.assertEqual(got[0][0],(self.path.stat().st_dev,self.path.stat().st_ino))
 def test_hard_crash_slot_before_selection_retains_A(self):self.slot_crash('before_select','A')
 def test_hard_crash_slot_after_selection_retains_B(self):self.slot_crash('after_publish:selection.json','B')
 def slot_crash(self,point,expected):
  self.prepare()
  code='import os,sys;sys.path.insert(0,'+repr(str(HERE))+');from anchor import Store;s=Store('+repr(str(self.path))+',fixture=True,inject=lambda p:os._exit(91) if p=='+repr(point)+' else None);s.publish_slot("B",b"B")'
  p=subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.assertEqual(p.returncode,91)
  self.s.close();self.s=Store(self.path,fixture=True);self.assertEqual(self.s.choose()['slot'],expected);self.assertEqual(self.s.read('slot-A.py',0o500),b'A')
 def test_production_host_admission_before_read_or_mutation(self):
  with patch('os.geteuid',return_value=0):
   with self.assertRaisesRegex(Refused,'PRODUCTION_INNER_TRANSACTION_NOT_BOUND'):base_host.RootHost(SimpleNamespace(fixture=False),'production')
 def test_root_validation_artifact_stays_blocked(self):
  v=build_validation.render(HERE,'/usr/bin/python3.12','a'*64,'v11-'+'b'*32)
  self.assertFalse(v['root_validation_ready']);self.assertEqual(digest(v['bytes']),v['sha256'])
  self.assertIn(b"raise SystemExit('WAITING_FOR_CONTROL_HANDOFF')",v['bytes'])
  compile(v['bytes'],'validation','exec')
 def test_decommission_is_separate_and_nonterminal_refused(self):
  self.prepare()
  h=SimpleNamespace(verify_base=lambda:None,confirm_closed=lambda:None,no_worker=lambda:None)
  plan=decommission.plan(self.s,h);self.assertFalse(plan['production_execution_allowed'])
  self.s.write('phase1.json',encode({'transaction':'v11-'+'a'*32,'manifest_sha256':'b'*64,'paths':['/run/test-payload']}),0o600)
  with self.assertRaisesRegex(Refused,'NONTERMINAL'):decommission.plan(self.s,h)
if __name__=='__main__':unittest.main()
