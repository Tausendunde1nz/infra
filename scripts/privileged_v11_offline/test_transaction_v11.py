import copy,json,os,tempfile,unittest
from pathlib import Path
from transaction_v11 import Coordinator,Store,Refused,PHASES,REQUIRED_PROOFS,watchdog_due,window

class Crash(BaseException):pass
class Host:
 def __init__(self,root,fail=None,crash=None):self.root=root;self.fail=fail;self.crash=crash;self.watchdog=False;self.revoked=False;self.frozen=b'unchanged';self.calls=[]
 def preflight(self,p):return True
 def backup(self):return {'verified':'fixture'}
 def verify_backup(self,b):return b=={'verified':'fixture'}
 def arm_watchdog(self,s):self.watchdog=True;return True
 def checkpoint(self,p):return {'exists':(self.root/p).exists()}
 def precondition(self,p,c,s):return True
 def verify_checkpoint(self,p,c):return c==self.checkpoint(p)
 def apply(self,p,s):
  self.calls.append(p)
  if self.fail==(p,'before'):raise Refused('injected')
  if self.crash==(p,'before'):raise Crash()
  (self.root/p).write_text('candidate')
  if self.fail==(p,'after'):raise Refused('injected')
  if self.crash==(p,'after'):raise Crash()
 def verify(self,p,s):return (self.root/p).read_text()=='candidate'
 def secure_fail_closed(self,s):self.revoked=True;return True
 def restore(self,p,c,sealed):
  if not sealed:
   try:(self.root/p).unlink()
   except FileNotFoundError:pass
 def verify_restore(self,p,c,sealed):return self.revoked if sealed else not (self.root/p).exists()
 def verify_frozen(self,s):return self.frozen==b'unchanged'
 def final_verify(self,s):return len(self.calls)==len(PHASES)
 def disarm_watchdog(self,s):self.watchdog=False;return True

class TransactionTests(unittest.TestCase):
 def fixture(self,fail=None,crash=None):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);p=Path(t.name);os.chmod(p,0o700)
  st=Store(p,fixture=True);self.addCleanup(st.close);st.write({'status':'ROOT_STARTED','transaction_id':'v11-fixture-123456789','boot_id':'boot'},initial=True)
  h=Host(p,fail,crash);c=Coordinator(st,h,clock=lambda:1_000_000_000);proofs={k:{'passed':True,'sha256':'a'*64} for k in REQUIRED_PROOFS};c.start('v11-fixture-123456789','boot',4000,3600,proofs);return st,h,c
 def test_success(self):
  s,h,c=self.fixture()
  for p in PHASES:c.step(p)
  self.assertEqual(c.finish()['status'],'COMPLETED');self.assertFalse(h.watchdog)
 def test_every_mutation_boundary(self):
  for p in PHASES:
   for when in ['before','after']:
    with self.subTest(p=p,when=when):
     s,h,c=self.fixture(fail=(p,when))
     for phase in PHASES:
      if phase==p:
       with self.assertRaises(Refused):c.step(phase)
       break
      c.step(phase)
     sealed=PHASES.index(p)>=PHASES.index('seal_authority');self.assertEqual(s.read()['status'],'SECURED_STOP' if sealed else 'ROLLED_BACK');self.assertEqual(h.revoked,sealed);self.assertEqual(h.frozen,b'unchanged')
 def test_crash_recovery_every_boundary(self):
  for p in PHASES:
   for when in ['before','after']:
    s,h,c=self.fixture(crash=(p,when))
    for phase in PHASES:
     if phase==p:
      with self.assertRaises(Crash):c.step(phase)
      break
     c.step(phase)
    self.assertEqual(s.read()['status'],'PHASE_INTENT');c.recover();self.assertIn(s.read()['status'],['ROLLED_BACK','SECURED_STOP'])
 def test_early_finish(self):
  s,h,c=self.fixture()
  with self.assertRaises(Refused):c.finish()
 def test_wrong_order(self):
  s,h,c=self.fixture()
  with self.assertRaises(Refused):c.step(PHASES[1])
 def test_window(self):
  for a,b in [(1800,1800),(1,3600),(9999,100),(True,3600)]:
   with self.assertRaises(Refused):window(a,b)
 def test_double_start(self):
  s,h,c=self.fixture()
  with self.assertRaises(Refused):s.write({},initial=True)
 def test_state_tamper(self):
  s,h,c=self.fixture();(s.path/'state.json').write_text('{"state":{},"sha256":"bad"}')
  with self.assertRaises(Refused):s.read()
 def test_symlink_state(self):
  s,h,c=self.fixture();(s.path/'state.json').unlink();(s.path/'state.json').symlink_to('other')
  with self.assertRaises(OSError):s.read()
 def test_concurrent_store(self):
  s,h,c=self.fixture()
  with self.assertRaises(BlockingIOError):Store(s.path,fixture=True)
 def test_expiry(self):
  s,h,c=self.fixture();c.clock=lambda:10**20
  with self.assertRaises(Refused):c.step(PHASES[0])
 def test_restore_failure(self):
  s,h,c=self.fixture(fail=(PHASES[0],'after'));h.verify_restore=lambda *a,**k:False
  with self.assertRaises(Refused):c.step(PHASES[0])
  self.assertEqual(s.read()['status'],'ROLLBACK_FAILED')
 def test_crash_before_watchdog_cancel_recovers_commit(self):
  s,h,c=self.fixture()
  for phase in PHASES:c.step(phase)
  h.disarm_watchdog=lambda state: (_ for _ in ()).throw(Crash())
  with self.assertRaises(Crash):c.finish()
  self.assertEqual(s.read()['status'],'COMMIT_RECORDED');self.assertTrue(h.watchdog)
  h.disarm_watchdog=lambda state:True
  self.assertEqual(c.recover(),'COMPLETED');self.assertEqual(len(h.calls),len(PHASES))
 def test_crash_after_watchdog_cancel_recovers_commit(self):
  s,h,c=self.fixture()
  for phase in PHASES:c.step(phase)
  def cancel(state):h.watchdog=False;raise Crash()
  h.disarm_watchdog=cancel
  with self.assertRaises(Crash):c.finish()
  self.assertEqual(s.read()['status'],'COMMIT_RECORDED');self.assertFalse(h.watchdog)
  h.disarm_watchdog=lambda state:True
  self.assertEqual(c.recover(),'COMPLETED');self.assertFalse(h.revoked)
 def test_failed_cancel_not_completed(self):
  s,h,c=self.fixture()
  for phase in PHASES:c.step(phase)
  h.disarm_watchdog=lambda state:False
  with self.assertRaisesRegex(Refused,'WATCHDOG_DISARM'):c.finish()
  self.assertEqual(s.read()['status'],'COMMIT_RECORDED')
 def test_false_final_check_keeps_watchdog(self):
  s,h,c=self.fixture()
  for phase in PHASES:c.step(phase)
  h.final_verify=lambda state:False
  with self.assertRaisesRegex(Refused,'FINAL_VERIFY'):c.finish()
  self.assertEqual(s.read()['status'],'PHASE_VERIFIED');self.assertTrue(h.watchdog)
 def test_watchdog(self):
  self.assertTrue(watchdog_due({'status':'PHASE_INTENT','boot_id':'a','deadline_ns':99},'b',1));self.assertFalse(watchdog_due({'status':'COMPLETED'},'b',100))
if __name__=='__main__':unittest.main()
