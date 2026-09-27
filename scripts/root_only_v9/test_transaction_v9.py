"""Every phase: crash before/after mutation, durable recovery, sealed rollback."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from policy_v9 import PHASES,SEAL_PHASE,Refused
from transaction_v9 import Store,Transaction,watchdog_due

class FakeHost:
 def __init__(self,fail=None,at='after'):self.values={p:False for p in PHASES};self.fail=fail;self.at=at;self.disabled=False;self.restarted=[]
 def snapshot(self,p):return {'value':self.values[p]}
 def preflight(self,p,b):
  if p==self.fail and self.at=='preflight':raise Refused('preflight failure')
  return True
 def apply(self,p,s):
  if p==self.fail and self.at=='before':raise Refused('before apply')
  self.values[p]=True
  if p==self.fail and self.at=='after':raise Refused('after apply')
 def verify(self,p,b,a,s):return p!=self.fail or self.at!='verify'
 def restore(self,p,b,policy):
  if policy['socket']=='KEEP_ROOT_ONLY' and p in ('socket_cutover','socket_persistence','remove_membership','remove_unsafe_sudo','quarantines','install_components'):self.values[p]=True
  else:self.values[p]=b['value']
 def verify_restore(self,p,b,policy):
  expected=True if policy['socket']=='KEEP_ROOT_ONLY' and p in ('socket_cutover','socket_persistence','remove_membership','remove_unsafe_sudo','quarantines','install_components') else b['value']
  return self.values[p]==expected
 def final_verify(self,s):return all(self.values.values())
 def disable_watchdog(self):self.disabled=True

class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();os.chmod(self.tmp.name,0o700)
  self.store=Store(self.tmp.name,fixture=True);self.clock=[100];self.host=FakeHost();self.tx=Transaction(self.store,self.host,lambda:self.clock[0]);self.tx.begin('boot')
 def tearDown(self):self.store.close();self.tmp.cleanup()
 def test_all_phases(self):
  for p in PHASES:self.tx.step(p)
  self.tx.finish();self.assertTrue(self.host.disabled);self.assertEqual(self.host.restarted,[])
 def test_fail_every_phase(self):
  for phase in PHASES:
   for at in ('before','after','verify'):
    with self.subTest(phase=phase,at=at),tempfile.TemporaryDirectory() as td:
     os.chmod(td,0o700);store=Store(td,fixture=True);host=FakeHost(phase,at);tx=Transaction(store,host,lambda:1);tx.begin('boot')
     try:
      with self.assertRaises(Refused):
       for p in PHASES:tx.step(p)
      state=store.read();sealed=PHASES.index(phase)>=PHASES.index(SEAL_PHASE)
      self.assertEqual(state['status'],'SECURED_STOP' if sealed else 'ROLLED_BACK');self.assertFalse(host.disabled)
      if sealed:self.assertTrue(host.values['socket_cutover'])
      else:self.assertFalse(any(host.values.values()))
     finally:store.close()
 def test_interrupted_checkpoint_recovered(self):
  self.tx.step('backup');s=self.store.read();s['status']='INTENT';s['steps'].append({'phase':'watchdog','status':'INTENT','before':{'value':False}});self.store.write(s);self.host.values['watchdog']=True
  Transaction(self.store,self.host).rollback();self.assertFalse(any(self.host.values.values()))
 def test_corrupt_checkpoint(self):
  p=Path(self.tmp.name)/'state.json';p.write_text('{"data":{},"sha256":"bad"}');os.chmod(p,0o600)
  with self.assertRaises(Refused):self.store.read()
 def test_deadline(self):
  self.clock[0]=self.store.read()['deadline_ns']
  with self.assertRaises(Refused):self.tx.step('backup')
 def test_no_short_watchdog(self):
  with self.assertRaises(Refused):self.tx.begin('boot',10)
 def test_phase_order(self):
  with self.assertRaises(Refused):self.tx.step('socket_cutover')
 def test_incomplete_cannot_finish(self):
  with self.assertRaises(Refused):self.tx.finish()
 def test_symlink_checkpoint_refused(self):
  p=Path(self.tmp.name)/'state.json';p.unlink();p.symlink_to('/etc/passwd')
  with self.assertRaises(OSError):self.store.read()
 def test_lock_exclusion(self):
  with self.assertRaises(BlockingIOError):Store(self.tmp.name,fixture=True)
 def test_watchdog_due_after_ssh_exit(self):
  state=self.store.read();self.assertTrue(watchdog_due(state,'boot',state['deadline_ns']+1))
 def test_watchdog_boot_change(self):self.assertTrue(watchdog_due(self.store.read(),'new-boot',0))
 def test_watchdog_not_premature(self):self.assertFalse(watchdog_due(self.store.read(),'boot',100))
 def test_watchdog_terminal_states(self):
  for status in ('COMPLETE','ROLLED_BACK','SECURED_STOP'):
   self.assertFalse(watchdog_due({'status':status},'boot',10**30))
 def test_no_backup_file_leak(self):
  for p in Path(self.tmp.name).iterdir():self.assertEqual(p.stat().st_mode&0o777,0o600)

if __name__=='__main__':unittest.main()
