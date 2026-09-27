"""Actual independent watchdog entry, with non-executing system boundary doubles."""
import hashlib
import json
import unittest
from unittest.mock import patch
import entry_v9 as entry
from transaction_v9 import encoded

class EntryTests(unittest.TestCase):
 def run_watchdog(self,state,boot='same',now=10,terminal_after_stop=False):
  events=[];box={'state':state.copy()}
  class S:
   def __init__(self,*args):events.append('lock')
   def read(self):return box['state'].copy()
   def write(self,value):box['state']=value.copy();events.append('persist')
   def close(self):events.append('unlock')
  class H:
   def __init__(self,*args):pass
   def disable_watchdog(self):events.append('disable')
  class T:
   def __init__(self,*args):pass
   def rollback(self):events.append('rollback');box['state']['status']='ROLLED_BACK'
  def checked(cmd,**kw):
   events.append(tuple(cmd))
   if terminal_after_stop:box['state']['status']='SECURED_STOP'
  envelope={'data':state,'sha256':hashlib.sha256(encoded(state)).hexdigest()}
  with patch('loader_v9.protected_read',return_value=json.dumps(envelope).encode()),patch('pathlib.Path.read_text',return_value=boot),patch('time.monotonic_ns',return_value=now),patch('transaction_v9.Store',S),patch('transaction_v9.Transaction',T),patch('host_v9.Host',H),patch('command_v9.checked',side_effect=checked):
   result=entry.execute('watchdog',{})
  return result,events,box['state']
 def test_no_early_rollback(self):
  r,e,s=self.run_watchdog({'status':'INTENT','boot_id':'same','deadline_ns':11});self.assertEqual(e,[])
 def test_deadline_stops_only_worker_then_rolls_back(self):
  r,e,s=self.run_watchdog({'status':'INTENT','boot_id':'same','deadline_ns':10})
  self.assertEqual(e[0],('/usr/bin/systemctl','stop','tu1nz-root-only-v9.service'));self.assertLess(e.index('rollback'),e.index('disable'));self.assertTrue(s['watchdog_disabled'])
 def test_boot_change_rolls_back(self):
  r,e,s=self.run_watchdog({'status':'INTENT','boot_id':'old','deadline_ns':100});self.assertIn('rollback',e)
 def test_worker_already_recovered(self):
  r,e,s=self.run_watchdog({'status':'INTENT','boot_id':'same','deadline_ns':10},terminal_after_stop=True);self.assertNotIn('rollback',e);self.assertEqual(s['status'],'SECURED_STOP')
 def test_terminal_cleanup(self):
  for status in ('COMPLETE','ROLLED_BACK','SECURED_STOP'):
   r,e,s=self.run_watchdog({'status':status,'watchdog_disabled':False});self.assertIn('disable',e);self.assertTrue(s['watchdog_disabled'])
 def test_already_disabled_no_commands(self):
  r,e,s=self.run_watchdog({'status':'COMPLETE','watchdog_disabled':True});self.assertEqual(e,[])
 def test_digest_failure_no_stop(self):
  with patch('loader_v9.protected_read',return_value=b'{"data":{},"sha256":"wrong"}'),patch('command_v9.checked') as c:
   with self.assertRaises(Exception):entry.execute('watchdog',{})
   c.assert_not_called()

if __name__=='__main__':unittest.main()
