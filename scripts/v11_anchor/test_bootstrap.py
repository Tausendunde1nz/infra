import os,sys,tempfile,shutil,unittest
from pathlib import Path
HERE=Path(__file__).parent
sys.path[:0]=[str(HERE),str(HERE.parent/'v11_guard_recovery'),str(HERE.parent/'v11_dispatcher')]
from anchor import *
import bootstrap,attestation,state as gs,coordinator
import test_phase as ph
from test_attestation import context,terminal_guard,Verifier,BOOT_ID
class BootstrapTests(unittest.TestCase):
 def setUp(self):
  ph.Phase.setUp(self);self.gp=Path(tempfile.mkdtemp(prefix='tu1nz-fence-test-',dir='/tmp'));self.gp.chmod(0o700)
  self.g=terminal_guard(self.gp,'v11-'+'a'*32);self.ctx=context(self.s);self.ctx['activation_manifest_sha256']=bootstrap.plan_pin(self.s,self.c,self.before)
  self.gate=attestation.Gate(self.s);self.gate.bind(self.ctx);self.b=bootstrap.Bootstrap(self.s,self.i,self.h)
 def tearDown(self):self.g.close();shutil.rmtree(self.gp);ph.Phase.tearDown(self)
 def test_attested_bootstrap_and_recovery(self):
  self.gate.publish(self.g,Verifier());self.assertEqual(self.b.stage(self.ctx,BOOT_ID,0,self.c,self.before),'PHASE1_PUBLISHED_FENCED')
  self.b.verify_resume(self.ctx,BOOT_ID,0,self.c,self.before)
  self.assertEqual(self.i.recover(parse(self.s.read('phase1.json',0o600))),TERMINAL);self.assertEqual(self.s.read('anchor.py',0o500),b'anchor')
 def test_missing_attestation_secured_stop_before_publication(self):
  with self.assertRaises(OSError):self.b.stage(self.ctx,BOOT_ID,0,self.c,self.before)
  self.assertTrue(self.s.closed());self.assertTrue(self.s.exists('stop.json'));self.assertIsNone(self.j.load()[0]);self.assertTrue(self.f.same_restored_snapshot(self.before))
 def test_changed_artifacts_denied_before_publication(self):
  self.gate.publish(self.g,Verifier());key=next(iter(self.c));self.c[key]['bytes']+=b'x'
  with self.assertRaises(Refused):self.b.stage(self.ctx,BOOT_ID,0,self.c,self.before)
  self.assertTrue(self.f.same_restored_snapshot(self.before));self.assertIsNone(self.j.load()[0])
 def test_old_boot_denied_before_publication(self):
  self.gate.publish(self.g,Verifier())
  with self.assertRaises(Refused):self.b.stage(self.ctx,'11234567-89ab-cdef-0123-456789abcdef',0,self.c,self.before)
  self.assertIsNone(self.j.load()[0]);self.assertTrue(self.s.closed())
 def test_replayed_bootstrap_denied(self):
  self.gate.publish(self.g,Verifier());self.b.stage(self.ctx,BOOT_ID,0,self.c,self.before)
  with self.assertRaisesRegex(Refused,'DUPLICATE'):self.b.stage(self.ctx,BOOT_ID,0,self.c,self.before)
 def test_guard_terminal_is_sealed_prerequisite_not_reversible_proof(self):
  # The completion attestation must NEVER be treated as authorization to
  # roll back the Guard security barrier. This is a deployment-plan blocker.
  state=self.g.current();self.assertEqual(state['phase'],'COMPLETED');self.assertTrue(state['sealed'])
  with self.assertRaises(gs.Refused):self.g.rollback({'originals_identical':True,'no_foreign_writer':True,'timer_original_verified':True})
 def test_postseal_interrupted_guard_is_secured_stop(self):
  self.g.close();shutil.rmtree(self.gp);self.gp.mkdir(mode=0o700);self.g=gs.Store(self.gp,fixture=True)
  self.g.initialize({'transaction':self.ctx['transaction'],'boot':BOOT_ID,'contract_sha256':'b'*64,'deadline_ns':999999999999999999,'coordinator_pid':os.getpid(),'coordinator_start_ticks':1})
  self.g.advance('FENCE_INSTALLED_UNARMED',{});self.g.advance('LEGACY_INHIBITED_PRESEAL',{});self.g.advance('SECURITY_BARRIER_SEALED',{'inhibit_verified':True,'blocked_start_verified':True,'recovery_verified':True,'watchdog_verified':True})
  from types import SimpleNamespace
  h=SimpleNamespace(stop_timer=lambda:None)
  self.assertEqual(coordinator.Coordinator(self.g,h).recover(),'SECURED_STOP')
  with self.assertRaises(gs.Refused):self.g.current()
# Original component cases run separately without inheritance or duplicate counts.
# These new cases exercise the actual Gate -> Bootstrap -> Installer.
if __name__=='__main__':unittest.main()
