import unittest
from rotation_contract import Rotation,Refused,REQUIRED,restart_admission
EVENTS=['prepare','provider_replaced','install_new_secret','verify_new_identity_and_permissions','reload_fixed_consumers','verify_function_and_stability','verify_old_rejected_and_rescan']
class RotationTests(unittest.TestCase):
 def good(self):return {k:True for k in REQUIRED}
 def test_sequence(self):
  r=Rotation()
  for e in EVENTS:r.advance(e,self.good())
  self.assertEqual(r.state,'COMPLETE');self.assertTrue(r.irreversible)
 def test_every_missing_proof(self):
  for k in REQUIRED:
   p=self.good();p.pop(k)
   with self.subTest(k=k),self.assertRaises(Refused):Rotation().advance('prepare',p)
 def test_every_false_proof(self):
  for k in REQUIRED:
   p=self.good();p[k]=False
   with self.subTest(k=k),self.assertRaises(Refused):Rotation().advance('prepare',p)
 def test_failures_all_boundaries(self):
  for n in range(len(EVENTS)):
   r=Rotation()
   for e in EVENTS[:n]:r.advance(e,self.good())
   state=r.fail();self.assertEqual(state,'SECURED_STOP_NEW_CREDENTIAL_REQUIRED' if n>=2 else 'ABORTED_NO_ROTATION')
   with self.assertRaises(Refused):r.rollback_credential(exposed=True)
 def test_out_of_order(self):
  for e in EVENTS[1:]:
   with self.assertRaises(Refused):Rotation().advance(e)
 def test_no_reuse_after_failure(self):
  r=Rotation();r.fail()
  with self.assertRaises(Refused):r.advance('prepare',self.good())
 def test_unknown_proof_rejected(self):
  p=self.good();p['assume_unreadable_is_clean']=True
  with self.assertRaises(Refused):Rotation().advance('prepare',p)
 def test_restart_unknown_rejected(self):
  with self.assertRaises(Refused):restart_admission({})
 def test_readiness_is_not_live_authorization(self):
  keys={'no_instance','no_lock_conflict','no_lease_conflict','no_partial_transaction','unit_and_config_bound','source_bound','permissions_bound','dependencies_available','detached_head_pinned','docs_mutation_disabled','notification_state_preserved','no_approval_consumer','start_health_stop_tests_passed','rollback_tests_passed'}
  p={k:True for k in keys};self.assertFalse(restart_admission(p)['restart_authorized'])
  for k in keys:
   p[k]=False
   with self.assertRaises(Refused):restart_admission(p)
   p[k]=True
if __name__=='__main__':unittest.main()
