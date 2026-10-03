import os,sys,time,unittest,tempfile,subprocess,json
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).parent
sys.path[:0]=[str(HERE),str(HERE.parent/'v11_guard_recovery'),str(HERE.parent/'v11_dispatcher')]
from anchor import Refused,digest,encode
import control_handoff as h,outer_supervisor as supervisor,build_validation,build_anchor

def receipt():
 return {'schema':1,'owner':'Adult Publishing S12.1-R9','status':'CONTROL_HANDOFF_COMPLETE','control_commit':h.CONTROL,'control_tree':h.TREE,'index_sha256':'a'*64,'metadata_sha256':'b'*64,'no_locks':True,'no_writers':True,'recovery_terminal':True,'no_rc5_activation':True,'no_content_drift':True}
class HandoffTests(unittest.TestCase):
 def test_pending_no_production_read(self):
  with patch.object(Path,'lstat',side_effect=AssertionError('NO_READ')):
   with self.assertRaisesRegex(Refused,'WAITING_FOR_CONTROL_HANDOFF'):h.verify(None,None)
 def test_exact_pinned_official_handoff(self):
  r=receipt();self.assertEqual(h.admitted(r,digest(encode(r))),r)
 def test_unpinned_handoff(self):
  with self.assertRaisesRegex(Refused,'HANDOFF_PIN'):h.admitted(receipt(),'0'*64)
 def test_foreign_owner(self):
  r=receipt();r['owner']='V11'
  with self.assertRaises(Refused):h.admitted(r,digest(encode(r)))
 def test_descendant_is_not_automatic_supersession(self):
  r=receipt();r['control_commit']='0'*40
  with self.assertRaises(Refused):h.admitted(r,digest(encode(r)))
 def test_recovery_not_terminal(self):
  r=receipt();r['recovery_terminal']=False
  with self.assertRaisesRegex(Refused,'NOT_TERMINAL'):h.admitted(r,digest(encode(r)))
 def test_missing_index_metadata(self):
  r=receipt();r.pop('index_sha256')
  with self.assertRaises(Refused):h.admitted(r,digest(encode(r)))

def incomplete_case(field):
 def test(self):
  r=receipt();r[field]=False
  with self.assertRaises(Refused):h.admitted(r,digest(encode(r)))
 return test
for field in ('no_locks','no_writers','no_rc5_activation','no_content_drift'):setattr(HandoffTests,'test_reject_'+field,incomplete_case(field))

class SupervisorTests(unittest.TestCase):
 def test_success_restores_before_return(self):
  with tempfile.TemporaryDirectory(prefix='tu1nz-v11-supervisor-',dir='/tmp') as folder:
   p=Path(folder)/'owned';p.write_text('owned')
   def restore(reason):p.unlink();return reason=='CONTROLLER_COMPLETE'
   self.assertEqual(supervisor.supervise(lambda:42,restore,5),42);self.assertFalse(p.exists())
 def test_failure_still_restores(self):
  with tempfile.TemporaryDirectory(prefix='tu1nz-v11-supervisor-',dir='/tmp') as folder:
   p=Path(folder)/'owned';p.write_text('owned')
   def restore(reason):p.unlink();return True
   def run():raise Refused('INJECTED_FAILURE')
   with self.assertRaisesRegex(Refused,'INJECTED_FAILURE'):supervisor.supervise(run,restore,5)
   self.assertFalse(p.exists())
 def test_failed_cleanup_is_not_success(self):
  with self.assertRaisesRegex(Refused,'INDEPENDENT_CLEANUP_FAILED'):supervisor.supervise(lambda:0,lambda reason:False,5)
 def test_invalid_deadline_before_fork(self):
  for seconds in (0,1201,'1200',None):
   with self.assertRaises(Refused):supervisor.supervise(lambda:None,lambda reason:True,seconds)
 def test_direct_worker_pidfd_registered_and_stopped_before_restore(self):
  owned={}
  def run():
   p=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(20)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
   owned['process']=p;supervisor.register(p);return p.pid
  self.assertGreater(supervisor.supervise(run,lambda reason:True,5),0)
  self.assertEqual(owned['process'].wait(timeout=5),-9)
 def test_registration_without_guardian_denied(self):
  with self.assertRaisesRegex(Refused,'SUPERVISOR_ABSENT'):supervisor.register(None)
 def child_case(self,timeout):
  with tempfile.TemporaryDirectory(prefix='tu1nz-v11-supervisor-',dir='/tmp') as folder:
   f=Path(folder)/'proof'
   code='''import sys,os,time,signal
sys.path[:0]=%r
import outer_supervisor
def restore(reason):
 with open(%r,'x') as out:out.write(reason)
 return True
def run():
 %s
outer_supervisor.supervise(run,restore,%d)
'''%([str(HERE),str(HERE.parent/'v11_guard_recovery'),str(HERE.parent/'v11_dispatcher')],str(f),'time.sleep(10)' if timeout else 'os.kill(os.getpid(),signal.SIGKILL)',1 if timeout else 5)
   p=subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
   self.assertEqual(p.returncode,-9,p.stderr)
   deadline=time.monotonic()+5
   while not f.exists() and time.monotonic()<deadline:time.sleep(.01)
   self.assertTrue(f.exists());self.assertEqual(f.read_text(),'MONOTONIC_TIMEOUT' if timeout else 'PARENT_EXIT')
 def test_parent_sigkill_cleanup_survives(self):self.child_case(False)
 def test_monotonic_timeout_independent_cleanup(self):self.child_case(True)

class BuilderTests(unittest.TestCase):
 def test_single_pending_launcher_compiles_and_is_closed_before_effects(self):
  r=build_validation.render(HERE,'/usr/bin/python3.12','a'*64,'v11-'+'e'*32)
  self.assertFalse(r['root_validation_ready']);self.assertTrue(r['offline_stage_b_ready']);self.assertEqual(r['blocked_by'],['CONTROL_HANDOFF_PENDING'])
  self.assertEqual(digest(r['bytes']),r['sha256']);compile(r['bytes'],'root-validation.py','exec')
  self.assertLess(r['bytes'].index(b"raise SystemExit('WAITING_FOR_CONTROL_HANDOFF')"),r['bytes'].index(b'ModuleType'))
 def test_supplied_handoff_still_needs_real_root_validation(self):
  r=build_validation.render(HERE,'/usr/bin/python3.12','a'*64,'v11-'+'e'*32,receipt())
  self.assertFalse(r['root_validation_ready']);self.assertEqual(r['blocked_by'],['ROOT_VALIDATION_NOT_RUN'])
 def test_capsule_directional_handlers_are_pinned(self):
  c=build_anchor.build(HERE,'validation')
  for name in ('directional','phase0_cleanup','typed_adapter','isolated_runtime'):
   self.assertIn(('ModuleType('+repr(name)+')').encode(),c['worker'])
  self.assertIn(b"ModuleType('routing')",c['anchor']);self.assertNotIn(b'urlopen(',c['worker'])
 def test_launch_has_no_automatic_production_admission(self):
  c=build_anchor.build(HERE,'production');self.assertFalse(c['production_activation_ready'])
  self.assertIn(b'raise SystemExit(78) #',c['worker'])

if __name__=='__main__':unittest.main()
