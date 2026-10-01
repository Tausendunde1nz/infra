import hashlib,os,tempfile,unittest
from pathlib import Path
import bootstrap_v11 as b
class BootstrapTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.p=Path(self.t.name);self.p.chmod(0o700);self.payload={'main.py':b'pass\n'};self.pins={n:hashlib.sha256(v).hexdigest() for n,v in self.payload.items()};self.tx='tu1nz-privileged-v11-'+'a'*32
 def run_publish(self,**kw):
  args=dict(parent=self.p,transaction_id=self.tx,payload=self.payload,pins=self.pins,observed_ns=10,deadline_ns=4000_000_000_010,preflight=lambda:True,clock=lambda:10,fixture=True);args.update(kw);return b.publish(**args)
 def test_success_modes_hash_and_marker(self):
  p=self.run_publish();self.assertTrue((p/'ROOT_STARTED').is_file());self.assertEqual((p/'main.py').read_bytes(),b'pass\n')
  self.assertEqual(p.stat().st_mode&0o777,0o700)
  for f in p.iterdir():self.assertEqual(f.stat().st_mode&0o777,0o600)
 def test_short_window_no_effect(self):
  with self.assertRaises(b.Refused):self.run_publish(deadline_ns=20)
  self.assertEqual(list(self.p.iterdir()),[])
 def test_old_precheck_no_effect(self):
  with self.assertRaises(b.Refused):self.run_publish(clock=lambda:121_000_000_010)
  self.assertEqual(list(self.p.iterdir()),[])
 def test_bad_hash_no_effect(self):
  with self.assertRaises(b.Refused):self.run_publish(pins={'main.py':'0'*64})
  self.assertEqual(list(self.p.iterdir()),[])
 def test_bad_path_no_effect(self):
  with self.assertRaises(b.Refused):self.run_publish(payload={'../main.py':b'x'},pins={'../main.py':hashlib.sha256(b'x').hexdigest()})
  self.assertEqual(list(self.p.iterdir()),[])
 def test_drift_no_effect(self):
  with self.assertRaises(b.Refused):self.run_publish(preflight=lambda:False)
  self.assertEqual(list(self.p.iterdir()),[])
 def test_second_start_refused(self):
  self.run_publish()
  with self.assertRaises(b.Refused):self.run_publish()
 def test_old_marker_refused(self):
  (self.p/'.tu1nz-privileged-v11-old.lock').write_text('historical')
  with self.assertRaises(b.Refused):self.run_publish()
  self.assertEqual((self.p/'.tu1nz-privileged-v11-old.lock').read_text(),'historical')
 def test_symlink_parent_refused(self):
  link=self.p/'link';link.symlink_to(self.p,target_is_directory=True)
  with self.assertRaises(b.Refused):self.run_publish(parent=link)
 def test_reserved_manifest_refused_before_creation(self):
  with self.assertRaises(b.Refused):self.run_publish(payload={'manifest.json':b'x'},pins={'manifest.json':hashlib.sha256(b'x').hexdigest()})
  self.assertEqual(list(self.p.iterdir()),[])
 def test_foreign_parent_content_preserved(self):
  (self.p/'unrelated').write_text('foreign');self.run_publish();self.assertEqual((self.p/'unrelated').read_text(),'foreign')
 def test_state_compatible_with_durable_coordinator_store(self):
  import sys
  sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'privileged_v11_offline'))
  from transaction_v11 import Store
  p=self.run_publish();store=Store(p,fixture=True)
  try:self.assertEqual(store.read()['status'],'ROOT_STARTED');self.assertEqual(store.read()['transaction_id'],self.tx)
  finally:store.close()
 def test_concurrent_start_no_new_artifacts(self):
  import fcntl
  fd=os.open(self.p,os.O_RDONLY|os.O_DIRECTORY)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   with self.assertRaisesRegex(b.Refused,'CONCURRENT_BOOTSTRAP'):self.run_publish()
   self.assertEqual(list(self.p.iterdir()),[])
  finally:os.close(fd)
  self.run_publish()
 def test_inputs_frozen_before_callback(self):
  def drift():
   self.payload['main.py']=b'changed';self.pins['main.py']='0'*64;return True
  p=self.run_publish(preflight=drift);self.assertEqual((p/'main.py').read_bytes(),b'pass\n')
 def test_restrictive_umask(self):
  old=os.umask(0o777)
  try:p=self.run_publish()
  finally:os.umask(old)
  self.assertEqual(p.stat().st_mode&0o777,0o700)
  self.assertEqual((p/'main.py').stat().st_mode&0o777,0o600)
 def test_unknown_watchdog_state_refused(self):
  base={'status':'PHASE_INTENT','boot_id':'boot','deadline_ns':90,'sealed':False}
  for key,value in [('status','UNKNOWN'),('sealed',1),('boot_id',''),('deadline_ns',True),('deadline_ns',0)]:
   with self.subTest(key=key,value=value):
    s=dict(base);s[key]=value
    with self.assertRaises(b.Refused):b.watchdog_decision(s,'boot',1)
 def test_watchdog_boundaries(self):
  s={'status':'PHASE_INTENT','boot_id':'boot','deadline_ns':90_000_000_000,'sealed':False}
  self.assertEqual(b.watchdog_decision(s,'boot',89_900_000_000),'WAIT');self.assertEqual(b.watchdog_decision(s,'boot',90_000_000_000),'ROLLBACK_OWNED_CHANGES');s['sealed']=True;self.assertEqual(b.watchdog_decision(s,'other-boot',0),'FAIL_CLOSED_RECOVERY')
 def test_cleanup_does_not_replay(self):
  s={'status':'COMMIT_RECORDED','boot_id':'boot','deadline_ns':1,'sealed':True};self.assertEqual(b.watchdog_decision(s,'boot',5),'FINISH_VERIFIED_CLEANUP');s['status']='ROLLBACK_FAILED';self.assertEqual(b.watchdog_decision(s,'boot',5),'MANUAL_RECOVERY_NO_REPLAY')
if __name__=='__main__':unittest.main()
