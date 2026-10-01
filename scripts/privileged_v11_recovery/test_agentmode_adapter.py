import unittest
import agentmode_adapter as a
class Fixture:
 def __init__(self):self.r={'Id':a.UNIT,'ActiveState':'inactive','SubState':'dead','InvocationID':'a'*32,'MainPID':'0','User':'chatops','Group':'chatops','NeedDaemonReload':'no'};self.calls=[]
 def __call__(self,cmd):
  self.calls.append(cmd)
  if cmd==a.START:self.r.update(ActiveState='active',SubState='running',InvocationID='b'*32,MainPID='123')
  elif cmd==a.STOP:self.r.update(ActiveState='inactive',SubState='dead',MainPID='0')
  return '\n'.join(k+'='+v for k,v in self.r.items())
class AdapterTests(unittest.TestCase):
 def setUp(self):self.f=Fixture();self.a=a.Adapter(self.f);self.before=dict(self.f.r);self.proofs={k:True for k in ('transaction_lock_held','checkpoint_verified','new_unit_and_source_verified','restart_preflight_passed')}
 def test_start_and_stop_owned(self):
  saved=[];r=self.a.start(self.before,self.proofs,saved.append);self.assertEqual(saved,[r]);self.assertTrue(self.a.stop_owned(r));self.assertTrue(self.a.stop_owned(r))
 def test_changed_invocation_not_stopped(self):
  r=self.a.start(self.before,self.proofs,lambda r:None);self.f.r['InvocationID']='c'*32
  with self.assertRaisesRegex(a.Refused,'FOREIGN_INVOCATION'):self.a.stop_owned(r)
  self.assertNotIn(a.STOP,self.f.calls)
 def test_changed_pid_not_stopped(self):
  r=self.a.start(self.before,self.proofs,lambda r:None);self.f.r['MainPID']='456'
  with self.assertRaises(a.Refused):self.a.stop_owned(r)
  self.assertNotIn(a.STOP,self.f.calls)
 def test_every_failed_precondition(self):
  for k in self.proofs:
   p=dict(self.proofs);p[k]=False
   with self.assertRaises(a.Refused):self.a.start(self.before,p,lambda r:None)
  self.assertNotIn(a.START,self.f.calls)
 def test_unexpected_running_before_start(self):
  self.f.r['ActiveState']='active'
  with self.assertRaises(a.Refused):self.a.start(self.before,self.proofs,lambda r:None)
  self.assertNotIn(a.START,self.f.calls)
 def test_wrong_identity(self):
  self.f.r['User']='root'
  with self.assertRaises(a.Refused):a.state(self.f)
 def test_receipt_failure_no_blind_stop(self):
  def fail(r):raise OSError('fixture receipt fsync')
  with self.assertRaises(OSError):self.a.start(self.before,self.proofs,fail)
  self.assertNotIn(a.STOP,self.f.calls)
class DropinTests(unittest.TestCase):
 def test_fixed_exec_and_exact_pin(self):
  s=a.recovery_dropin('a'*40);self.assertIn('ExecStart=/bin/bash /usr/local/libexec/tu1nz-privileged-v11/agentmode_observer.sh --loop',s);self.assertEqual(s.count('Environment='),1)
 def test_pin_injection_rejected(self):
  for value in ['a'*39,'a'*40+'\nUser=root','../../file','main','A'*40]:
   with self.assertRaises(a.Refused):a.recovery_dropin(value)
if __name__=='__main__':unittest.main()
