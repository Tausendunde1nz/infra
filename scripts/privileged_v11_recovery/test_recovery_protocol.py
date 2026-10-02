import copy,unittest
import recovery_protocol as r
BOOT='11111111-1111-1111-1111-111111111111'
class RecoveryProtocolTests(unittest.TestCase):
 def setUp(self):self.disk=None
 def save(self,s):self.disk=copy.deepcopy(s)
 def intent(self):return r.start_intent('tu1nz-privileged-v11-'+'a'*32,BOOT,'a'*64,'b'*64,{'unit':r.UNIT,'active':False,'pid':0,'pending_job':False,'no_conflicting_lock':True},self.save)
 def claim(self):return r.claim_before_main(self.intent(),BOOT,'c'*32,100,{'root_owned_unit_and_prologue':True,'unit_and_source_hash_match':True,'transaction_lock_held':True,'single_use_claim_absent':True},self.save)
 def current(self):return {'unit':r.UNIT,'boot':BOOT,'invocation':'c'*32,'pid':123,'process_start_ticks':345,'start_monotonic_ns':101,'active':True}
 def bound(self):return r.reconcile_main(self.claim(),self.current(),self.save)
 def test_receipt_reconciliation_after_lost_post_start_write(self):
  c=self.claim()
  def fail(s):raise OSError('fsync')
  with self.assertRaises(OSError):r.reconcile_main(c,self.current(),fail)
  self.assertEqual(self.disk['status'],'START_CLAIMED')
  bound=r.reconcile_main(self.disk,self.current(),self.save);self.assertTrue(r.owns_current(bound,self.current()))
 def test_intent_alone_cannot_claim_an_existing_instance(self):
  with self.assertRaises(r.Refused):r.reconcile_main(self.intent(),self.current(),self.save)
 def test_claim_write_failure_prevents_main_admission(self):
  i=self.intent()
  def fail(s):raise OSError()
  with self.assertRaises(OSError):r.claim_before_main(i,BOOT,'c'*32,100,{'root_owned_unit_and_prologue':True,'unit_and_source_hash_match':True,'transaction_lock_held':True,'single_use_claim_absent':True},fail)
  self.assertEqual(self.disk['status'],'START_INTENT')
 def test_double_claim_refused(self):
  c=self.claim()
  with self.assertRaises(r.Refused):r.claim_before_main(c,BOOT,'c'*32,100,{},self.save)
 def test_foreign_invocation_refused(self):
  c=self.claim();v=self.current();v['invocation']='d'*32
  with self.assertRaises(r.Refused):r.reconcile_main(c,v,self.save)
 def test_boot_change_refused(self):
  c=self.claim();v=self.current();v['boot']='22222222-2222-2222-2222-222222222222'
  with self.assertRaises(r.Refused):r.reconcile_main(c,v,self.save)
 def test_pid_reuse_refused(self):
  c=self.bound();v=self.current();v['process_start_ticks']+=1
  self.assertFalse(r.owns_current(c,v))
  with self.assertRaises(r.Refused):r.reconcile_main(c,v,self.save)
 def test_start_before_claim_refused(self):
  c=self.claim();v=self.current();v['start_monotonic_ns']=99
  with self.assertRaises(r.Refused):r.reconcile_main(c,v,self.save)
 def test_660_seconds_required(self):
  h=r.StableHealth(self.bound())
  for sec in range(0,660,30):h.sample(sec*10**9,self.current(),True)
  h.sample(659_900_000_000,self.current(),True)
  with self.assertRaises(r.Refused):h.complete()
  h.sample(661_000_000_000,self.current(),True);self.assertTrue(h.complete())
 def test_observation_gap_refused(self):
  h=r.StableHealth(self.bound());h.sample(0,self.current(),True)
  with self.assertRaises(r.Refused):h.sample(31_000_000_000,self.current(),True)
 def test_clock_reversal_refused(self):
  h=r.StableHealth(self.bound());h.sample(10,self.current(),True)
  with self.assertRaises(r.Refused):h.sample(9,self.current(),True)
 def test_health_failure_sticky(self):
  h=r.StableHealth(self.bound())
  with self.assertRaises(r.Refused):h.sample(0,self.current(),False)
  with self.assertRaises(r.Refused):h.sample(1,self.current(),True)
 def test_provider_intent_precedes_irreversible_action(self):
  proofs={k:True for k in ('backup_verified','consumers_confirmed_stopped','independent_watchdog_verified','protected_input_ready','provider_route_confirmed')}
  s=r.provider_handoff({'phase':'CONSUMERS_QUIESCED','forward_only':False},proofs,self.save)
  self.assertTrue(self.disk['forward_only']);self.assertEqual(r.recovery_decision(s),'SECURED_STOP_NO_OLD_CREDENTIAL')
 def test_handoff_persistence_failure_does_not_authorize_action(self):
  def fail(s):raise OSError()
  with self.assertRaises(OSError):r.provider_handoff({'phase':'CONSUMERS_QUIESCED','forward_only':False},{k:True for k in ('backup_verified','consumers_confirmed_stopped','independent_watchdog_verified','protected_input_ready','provider_route_confirmed')},fail)
 def test_failure_boundaries_never_reactivate_old_credential(self):
  for phase in ('PROVIDER_HANDOFF_INTENT','PROVIDER_REPLACED','NEW_CREDENTIAL_INSTALLED','AGENTMODE_START','RECEIPT_PERSIST','WATCHDOG_RESTART','BOOT_CHANGED'):
   with self.subTest(phase=phase):
    s={'phase':phase,'forward_only':True};self.assertEqual(r.recovery_decision(s),'SECURED_STOP_NO_OLD_CREDENTIAL');self.assertEqual(r.recovery_decision(s,True),'FORWARD_REPAIR_NEW_CREDENTIAL')
 def test_pre_handoff_failures_are_reversible(self):
  for phase in ('ROOT_STARTED','BACKUP_VERIFIED','ADAPTERS_INSTALLED','CONSUMERS_QUIESCED'):
   self.assertEqual(r.recovery_decision({'phase':phase,'forward_only':False}),'ROLLBACK_VERIFIED_OWNED_CHANGES')
 def test_inconsistent_boundary_refused(self):
  with self.assertRaises(r.Refused):r.recovery_decision({'phase':'PROVIDER_REPLACED','forward_only':False})
 def test_unknown_unsealed_phase_refuses_rollback(self):
  with self.assertRaises(r.Refused):r.recovery_decision({'phase':'UNKNOWN','forward_only':False})
 def test_numeric_proofs_are_not_booleans(self):
  proofs={k:1 for k in ('backup_verified','consumers_confirmed_stopped','independent_watchdog_verified','protected_input_ready','provider_route_confirmed')}
  with self.assertRaises(r.Refused):r.provider_handoff({'phase':'CONSUMERS_QUIESCED','forward_only':False},proofs,self.save)
 def test_private_fields_cannot_enter_handoff_state(self):
  with self.assertRaises(r.Refused):r.provider_handoff({'phase':'CONSUMERS_QUIESCED','forward_only':False,'token':'synthetic-private'}, {},self.save)
if __name__=='__main__':unittest.main()
