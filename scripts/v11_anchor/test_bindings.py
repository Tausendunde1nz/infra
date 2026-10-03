import os,sys,unittest,copy,subprocess,tempfile,shutil
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
HERE=Path(__file__).parent
sys.path[:0]=[str(HERE),str(HERE.parent/'v11_guard_recovery'),str(HERE.parent/'v11_dispatcher')]
from anchor import Refused,TERMINAL,digest,encode,Store
import directional as d,phase0_cleanup as cleanup,seal_boundary as sb
import test_seal_boundary as old,test_install as ins,typed_adapter as ta

class BoundWorkflow(unittest.TestCase):
 def setUp(self):
  old.IntegratedFiles.setUp(self)
  self.host.verify_artifacts=lambda c:self.assertEqual(c['activation_manifest_sha256'],__import__('bootstrap').plan_pin(self.s,self.c,self.before))
  self.host.verify_inactive=lambda:self.assertTrue(self.audit.all_inactive)
  self.host.cleanup_owned_temporaries=lambda:self.assertTrue(self.s.closed())
  self.driver=d.Driver(self.boundary)
 def tearDown(self):old.IntegratedFiles.tearDown(self)
 def job(self,role,action):return self.driver.job(role,action)
 def test_full_bound_bootstrap_installer(self):
  self.assertEqual(self.driver.execute(self.job(d.PRE,'ACTIVATE')),'COMPLETE')
  self.assertEqual(self.driver.execute(self.job(d.POST,'VERIFY')),'COMPLETE')
  self.assertEqual(cleanup.Cleanup(self.boundary).run(),'COMPLETE')
  self.assertNotIn('rollback',self.hguard.actions)
 def test_preseal_worker_rejects_sealed_phase(self):
  self.driver.execute(self.job(d.PRE,'ACTIVATE'))
  with self.assertRaisesRegex(Refused,'WRONG_DIRECTIONAL'):self.driver.execute(self.job(d.PRE,'RECOVER'))
 def test_forward_worker_rejects_unsealed(self):
  with self.assertRaisesRegex(Refused,'WRONG_DIRECTIONAL'):self.driver.execute(self.job(d.POST,'RECOVER'))
  self.assertIsNone(self.j.load()[0])
 def test_postseal_worker_cannot_activate(self):
  self.driver.execute(self.job(d.PRE,'ACTIVATE'))
  with self.assertRaisesRegex(Refused,'WRONG_DIRECTIONAL'):self.driver.execute(self.job(d.POST,'ACTIVATE'))
 def test_preseal_cleanup_exact_restore(self):
  with self.boundary.locked():self.boundary.prepare_locked()
  self.assertEqual(cleanup.Cleanup(self.boundary).run(),TERMINAL)
  self.assertTrue(self.f.same_restored_snapshot(self.before));self.assertEqual(self.s.read('anchor.py',0o500),b'anchor')
 def test_postseal_cleanup_no_old_rollback(self):
  self.driver.execute(self.job(d.PRE,'ACTIVATE'));self.hguard.actions=[]
  self.assertEqual(cleanup.Cleanup(self.boundary).run(),'COMPLETE');self.assertNotIn('rollback',self.hguard.actions)
 def test_unknown_cleanup_no_temporary_deletion(self):
  self.audit.bad=True;called=[];self.host.cleanup_owned_temporaries=lambda:called.append(True)
  self.assertEqual(cleanup.Cleanup(self.boundary).run(),sb.UNKNOWN);self.assertEqual(called,[])
 def test_legacy_stop_is_not_bypassed(self):
  self.s.stop('FIXED_FAILURE');self.assertEqual(cleanup.Cleanup(self.boundary).run(),sb.UNKNOWN)
  self.assertNotIn('rollback',self.hguard.actions)
 def test_sealed_failure_is_sticky_and_closed(self):
  self.hguard.fail='install_authority'
  self.assertEqual(self.driver.execute(self.job(d.PRE,'ACTIVATE')),sb.SEALED_STOP)
  self.hguard.fail=None;self.assertEqual(cleanup.Cleanup(self.boundary).run(),sb.SEALED_STOP)
  self.assertNotIn('rollback',self.hguard.actions)
 def test_cleanup_reboot_complete_no_reapply(self):
  self.driver.execute(self.job(d.PRE,'ACTIVATE'));before=list(self.hguard.actions);self.audit.current_boot=old.REBOOT
  self.assertEqual(cleanup.Cleanup(self.boundary).run(),'COMPLETE');self.assertEqual(before,self.hguard.actions)
 def test_parallel_cleanup_refused(self):
  with self.s.locked():
   with self.assertRaises(BlockingIOError):cleanup.Cleanup(self.boundary).run()
  self.assertIsNone(self.j.load()[0])
 def test_artifact_drift_denies_before_worker(self):
  self.c[next(iter(self.c))]['sha256']='0'*64
  with self.assertRaises(Refused):self.driver.selected_job('ACTIVATE')
  self.assertIsNone(self.j.load()[0])
 def test_lying_exit_result_independent_postcondition(self):
  with self.boundary.locked():
   with self.assertRaises(Refused):self.driver.result_verified('COMPLETE')
 def test_incomplete_attestation_stop_only(self):
  with self.boundary.locked():self.boundary.prepare_locked()
  (self.a/'boundary-preseal-commit.json').unlink()
  self.assertEqual(cleanup.Cleanup(self.boundary).run(),sb.UNKNOWN)
 def test_parent_protected_against_phase1_cleanup(self):
  from anchor import phase1_scope
  for p in (str(self.s.path),'/run/tu1nz-v11-anchor-validation/anchor.py','/var/lib/tu1nz-v11-anchor/base.json'):
   if p==str(self.s.path):continue
   with self.assertRaises(Refused):phase1_scope([p])

def replay_test(field,value):
 def test(self):
  job=self.job(d.PRE,'RECOVER');job[field]=value
  with self.assertRaisesRegex(Refused,'WORKER_CONTEXT_REPLAY'):self.driver.execute(job)
  self.assertNotIn('rollback',self.hguard.actions)
 return test
for field,value in [('transaction','v11-'+'b'*32),('generation',1),('context_sha256','0'*64),('artifacts_sha256','0'*64),('base_sha256','0'*64)]:setattr(BoundWorkflow,'test_replay_'+field,replay_test(field,value))

class Stored:
 targets=('fixed',);directories={}
 def __init__(self):self.state={'fixed':{'sha256':'a'*64,'mode':0o644}}
 def snapshot(self,t,d):assert t==self.targets and d==self.directories;return copy.deepcopy(self.state)
class AdapterTests(unittest.TestCase):
 def setUp(self):
  self.fake=ins.Fake();self.records=[];self.closed=[];self.files=Stored()
  for r in self.fake.rows.values():r['LoadState']='loaded'
  self.m=ins.manager.Manager('validation',self.records.append,lambda:self.closed.append(True),self.fake);self.adapter=ta.Adapter(self.m,self.files)
 def test_all_ids_constant_transport(self):
  for a in ta.ACTIONS:self.adapter.perform(a)
  self.assertTrue(all(x[:3]==('/usr/bin/systemctl','--no-pager','--no-ask-password') for x in self.fake.calls))
  self.assertTrue(all('--' in x[3:] for x in self.fake.calls if x[3]!='daemon-reload'))
 def test_no_free_unit_option_or_shell(self):
  for a in ('ssh.service','--help','WATCH_START;rm','start','/tmp/worker',{},None):
   with self.assertRaises(Refused):self.adapter.perform(a)
  self.assertEqual(self.fake.calls,[])
 def test_zero_exit_does_not_prove_loaded(self):
  original=self.fake.__call__
  def runner(args,**kw):
   result=original(args,**kw)
   if args[3]=='start':self.fake.rows['watch']['ActiveState']='inactive'
   return result
  self.m.runner=runner
  with self.assertRaisesRegex(Refused,'ACTION_POSTCONDITION'):self.adapter.perform('WATCH_START')
  self.assertTrue(self.closed)
 def test_zero_exit_stored_drift(self):
  original=self.fake.__call__
  def runner(args,**kw):
   r=original(args,**kw)
   if args[3]=='start':self.files.state['fixed']['mode']=0o600
   return r
  self.m.runner=runner
  with self.assertRaisesRegex(Refused,'ADAPTER_STORED_DRIFT'):self.adapter.perform('WATCH_START')
 def test_loaded_exec_drift(self):
  original=self.fake.__call__
  def runner(args,**kw):
   r=original(args,**kw)
   if args[3]=='start':self.fake.rows['watch']['ExecStart']='unapproved'
   return r
  self.m.runner=runner
  with self.assertRaisesRegex(Refused,'ADAPTER_LOADED_CONFIGURATION'):self.adapter.perform('WATCH_START')
 def test_active_consumer_blocks(self):
  self.fake.rows['consumer']['ActiveState']='active'
  with self.assertRaisesRegex(Refused,'ADAPTER_CONSUMER'):self.adapter.perform('RELOAD')
 def test_transport_timeout(self):
  self.m.runner=lambda *a,**kw:(_ for _ in ()).throw(subprocess.TimeoutExpired('fixed',30))
  with self.assertRaisesRegex(Refused,'SYSTEMD_TRANSPORT'):self.adapter.perform('RELOAD')
  self.assertTrue(self.closed)
 def test_bound_installer_facade(self):
  bound=ta.BoundManager(self.m,self.files);bound.action('start','watch')
  with self.assertRaises(Refused):bound.action('stop','consumer')
 def test_journal_intent_and_done_hashes(self):
  self.adapter.perform('WATCH_START');rows=[r for r in self.records if r.get('operation')=='FIXED_ADAPTER']
  self.assertEqual([r['state'] for r in rows],['INTENT','DONE']);self.assertEqual(rows[0]['stored_sha256'],rows[1]['stored_sha256'])

if __name__=='__main__':unittest.main()
