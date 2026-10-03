import json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from state import Store,encode
from preseal import STEPS
from test_fence import BINDING
HERE=Path(__file__).resolve().parent
BOOT2='01234567-89ab-cdef-0123-456789abcdef'
class ProcessReplay(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='tu1nz-fence-test-',dir='/tmp');self.root=Path(self.tmp.name);self.root.chmod(0o700)
  s=Store(self.root,fixture=True);s.initialize(dict(BINDING));s.close()
 def tearDown(self):self.tmp.cleanup()
 def worker(self,point='',bad='',boot=None):
  code='import sys,runpy;sys.path.insert(0,'+repr(str(HERE))+');sys.argv='+repr([str(HERE/'replay_fixture.py'),str(self.root),boot or BINDING['boot'],point,bad])+';runpy.run_path(sys.argv[0],run_name="__main__")'
  return subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
 def assert_closed(self):self.assertTrue(json.loads((self.root/'fixture-fence.json').read_bytes())['closed'])
 def test_unconfirmed_fence_never_claims_safe(self):
  p=self.worker(bad='unconfirmed');self.assertNotEqual(p.returncode,0);self.assertNotIn(b'PRESEAL_SECURED_STOP',p.stdout);self.assertFalse((self.root/'STOP').exists())
 def test_corrupt_initial_state_is_fenced_then_stopped(self):
  p=self.root/'state-000000.json';p.chmod(0o600);p.write_bytes(b'{broken');p.chmod(0o400)
  r=self.worker();self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.strip(),b'PRESEAL_SECURED_STOP');self.assert_closed();self.assertTrue((self.root/'STOP').exists())
 def test_missing_state_is_fenced_then_stopped(self):
  (self.root/'state-000000.json').unlink();r=self.worker();self.assertEqual(r.stdout.strip(),b'PRESEAL_SECURED_STOP');self.assert_closed()
 def test_invalid_boot_is_fenced_then_stopped(self):
  r=self.worker(boot='-'*36);self.assertEqual(r.stdout.strip(),b'PRESEAL_SECURED_STOP');self.assert_closed()
 def test_corrupt_recovery_chain_is_stopped(self):
  self.assertEqual(self.worker(point='after_intent:INHIBIT').returncode,91)
  p=self.root/'recovery-000000.json';p.chmod(0o600);x=json.loads(p.read_bytes());x['binding']['transaction']='v11-'+'f'*32;p.write_bytes(encode(x));p.chmod(0o400)
  r=self.worker();self.assertEqual(r.stdout.strip(),b'PRESEAL_SECURED_STOP');self.assert_closed()
 def test_missing_middle_record_is_stopped(self):
  self.assertEqual(self.worker(point='after_commit:QUIESCE').returncode,91);(self.root/'recovery-000001.json').unlink()
  r=self.worker();self.assertEqual(r.stdout.strip(),b'PRESEAL_SECURED_STOP');self.assert_closed()

def crash_test(point,reboot):
 def test(self):
  first=self.worker(point=point);self.assertEqual(first.returncode,91,first.stderr);self.assert_closed()
  second=self.worker(boot=BOOT2 if reboot else None);self.assertEqual(second.returncode,0,second.stderr);self.assertEqual(second.stdout.strip(),b'ROLLED_BACK');self.assert_closed()
  names=sorted(self.root.glob('recovery-*.json'));self.assertEqual(len(names),2*len(STEPS));before={p.name:p.read_bytes() for p in names}
  third=self.worker(boot=BOOT2 if reboot else None);self.assertEqual(third.stdout.strip(),b'ROLLED_BACK');self.assertEqual(before,{p.name:p.read_bytes() for p in names})
  self.assertEqual(json.loads((self.root/'fixture-completed.json').read_bytes()),list(STEPS))
 return test
for step in STEPS:
 for edge in ('before_intent','after_intent','before','after_action','after_commit'):
  for reboot in (False,True):setattr(ProcessReplay,'test_crash_'+step+'_'+edge+('_reboot' if reboot else '_restart'),crash_test(edge+':'+step,reboot))
 def fail(self,step=step):
  r=self.worker(bad=step);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.strip(),b'PRESEAL_SECURED_STOP');self.assert_closed();self.assertTrue((self.root/'fixture-stop.json').exists())
 setattr(ProcessReplay,'test_failure_'+step,fail)
def publication_test(point,reboot):
 def test(self):
  r=self.worker(point=point);self.assertEqual(r.returncode,91,r.stderr);self.assert_closed()
  r=self.worker(boot=BOOT2 if reboot else None);self.assertEqual(r.returncode,0,r.stderr)
  self.assertIn(r.stdout.strip(),(b'ROLLED_BACK',b'PRESEAL_SECURED_STOP'));self.assert_closed()
  # A hardlink publication interrupted before unlink has nlink=2. This is
  # deliberately refused, not silently repaired or treated as successful.
  if point.startswith('after_link:'):self.assertEqual(r.stdout.strip(),b'PRESEAL_SECURED_STOP')
 return test
for name in ('PRESEAL_INHIBIT','recovery-000000.json','recovery-000001.json'):
 for edge in ('before_file_fsync','after_file_fsync','before_publish','after_link','before_directory_fsync','after_directory_fsync'):
  for reboot in (False,True):setattr(ProcessReplay,'test_publish_'+name.replace('.','_')+'_'+edge+('_reboot' if reboot else '_restart'),publication_test(edge+':'+name,reboot))
if __name__=='__main__':unittest.main()
