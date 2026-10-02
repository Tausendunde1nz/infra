import hashlib,json,os,pathlib,subprocess,sys,tempfile,unittest
from unittest.mock import patch
import forward_recovery_journal as j
class JournalTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=pathlib.Path(self.tmp.name);os.chmod(self.path,0o700)
  self.tx='tu1nz-privileged-v11-'+'a'*32;self.sha='b'*64
  self.s=j.Journal(self.path,self.tx,self.sha,fixture=True)
 def tearDown(self):self.s.close();self.tmp.cleanup()
 def test_initial_reversible(self):self.s.initialize();self.assertTrue(self.s.decision().startswith('ROLLBACK'))
 def test_complete_sequence_forward(self):
  self.s.initialize();self.s.handoff()
  for p in j.PHASES[2:]:self.s.advance(p);self.assertTrue(self.s.decision().startswith('FORWARD'))
 def test_reopen_preserves_barrier(self):
  self.s.initialize();self.s.handoff();other=j.Journal(self.path,self.tx,self.sha,fixture=True)
  try:self.assertTrue(other.decision().startswith('FORWARD'))
  finally:other.close()
 def test_crash_after_barrier_before_state(self):
  self.s.initialize();original=self.s.publish
  def crash(name,*a,**k):
   if name=='rotation.json':raise OSError('injected')
   return original(name,*a,**k)
  with patch.object(self.s,'publish',side_effect=crash):
   with self.assertRaises(OSError):self.s.handoff()
  self.assertTrue(self.s.decision().startswith('FORWARD'));self.s.handoff()
 def test_failure_before_barrier_no_handoff(self):
  self.s.initialize()
  with patch.object(self.s,'publish',side_effect=OSError('injected')):
   with self.assertRaises(OSError):self.s.handoff()
  self.assertTrue(self.s.decision().startswith('ROLLBACK'))
 def test_real_process_exit_after_barrier(self):
  self.s.initialize()
  code="import os,sys;sys.path.insert(0,sys.argv[1]);import forward_recovery_journal as j;s=j.Journal(sys.argv[2],sys.argv[3],sys.argv[4],fixture=True);s.publish('forward-only.json',{**s.binding,'forward_only':True});os._exit(99)"
  p=subprocess.run([sys.executable,'-I','-B','-c',code,str(pathlib.Path(j.__file__).parent),str(self.path),self.tx,self.sha],capture_output=True)
  self.assertEqual(p.returncode,99);self.assertTrue(self.s.decision().startswith('FORWARD'))
 def test_wrong_binding(self):
  self.s.initialize();other=j.Journal(self.path,self.tx,'c'*64,fixture=True)
  try:
   with self.assertRaises(j.Refused):other.decision()
  finally:other.close()
 def test_symlink_refused(self):
  (self.path/'rotation.json').symlink_to('/dev/null')
  with self.assertRaises(OSError):self.s.decision()
 def test_hardlink_refused(self):
  self.s.initialize();os.link(self.path/'rotation.json',self.path/'linked')
  with self.assertRaises(j.Refused):self.s.decision()
 def test_mode_refused(self):
  self.s.initialize();os.chmod(self.path/'rotation.json',0o640)
  with self.assertRaises(j.Refused):self.s.decision()
 def test_corrupt_refused(self):
  self.s.initialize();(self.path/'rotation.json').write_bytes(b'{}')
  with self.assertRaises(j.Refused):self.s.decision()
 def test_skipping_phase_refused(self):
  self.s.initialize();self.s.handoff()
  with self.assertRaises(j.Refused):self.s.advance('COMPLETED')
 def test_missing_barrier_refused(self):
  self.s.initialize();self.s.handoff();(self.path/'forward-only.json').unlink()
  with self.assertRaises(j.Refused):self.s.decision()
 def test_double_initialize_refused(self):
  self.s.initialize()
  with self.assertRaises(j.Refused):self.s.initialize()
 def test_unknown_fields_refused(self):
  self.s.initialize();self.s.publish('rotation.json',{**self.s.binding,'phase':j.PHASES[0],'secret':'synthetic'},replace=True)
  with self.assertRaises(j.Refused):self.s.decision()
 def test_lock_not_lifetime(self):
  self.s.initialize();other=j.Journal(self.path,self.tx,self.sha,fixture=True)
  try:self.assertTrue(other.decision().startswith('ROLLBACK'))
  finally:other.close()
 def test_concurrent_lock_refused(self):
  other=j.Journal(self.path,self.tx,self.sha,fixture=True)
  try:
   with self.s.locked():
    with self.assertRaises(BlockingIOError):other.initialize()
  finally:other.close()
 def test_fsync_failure_never_returns_handoff(self):
  self.s.initialize()
  with patch.object(j.os,'fsync',side_effect=OSError('injected')):
   with self.assertRaises(OSError):self.s.handoff()
 def test_no_payload_or_token_storage(self):
  self.s.initialize();self.s.handoff()
  for p in self.path.glob('*.json'):
   o=json.loads(p.read_bytes());self.assertLessEqual(set(o['payload']),{'transaction','manifest_sha256','phase','forward_only'})
if __name__=='__main__':unittest.main()
