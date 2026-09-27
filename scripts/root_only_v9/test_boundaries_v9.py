"""Offline contract regressions; no SSH, sudo, Docker or real root activity."""
import copy
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import audit_v9 as audit
import runtime_v9 as runtime
import capsule_v9 as capsule
import client_v9 as client
import tu1nz_codex_broker_v9 as broker
from contracts_v9 import schedule_window
from policy_v9 import Refused
from public_v9 import projection
from loader_v9 import Loader,NAMES
from prepare_v9 import validate_payload

class Boundaries(unittest.TestCase):
 def test_mount_order_only(self):
  a=[{'Destination':'/a','Source':'/src-a','RW':True},{'Destination':'/b','Source':'/src-b','RW':False}]
  self.assertEqual(runtime.mount_digest(a),runtime.mount_digest(list(reversed(a))))
  b=copy.deepcopy(a);b[0]['RW']=False;self.assertNotEqual(runtime.mount_digest(a),runtime.mount_digest(b))
 def test_mount_duplicate_destination(self):
  with self.assertRaises(Refused):runtime.mount_digest([{'Destination':'/a'},{'Destination':'/a'}])
 def test_calendar_clear(self):self.assertTrue(schedule_window(datetime(2026,9,27,20,10,tzinfo=timezone.utc),2700,[10**15]*4,0))
 def test_calendar_near_cron(self):
  with self.assertRaises(Refused):schedule_window(datetime(2026,9,27,21,40,tzinfo=timezone.utc),2700,[10**15]*4,0)
 def test_calendar_recent_cron(self):
  with self.assertRaises(Refused):schedule_window(datetime(2026,9,27,22,1,tzinfo=timezone.utc),2700,[10**15]*4,0)
 def test_timer_near(self):
  with self.assertRaises(Refused):schedule_window(datetime(2026,9,27,20,10,tzinfo=timezone.utc),2700,[1,10**15,10**15,10**15],0)
 def test_timer_coverage(self):
  with self.assertRaises(Refused):schedule_window(datetime(2026,9,27,20,10,tzinfo=timezone.utc),2700,[],0)
 def test_all_broker_operations_fixed(self):
  for op in broker.OPS:self.assertEqual(broker.parse([op]),op)
  for args in ([],['docker'],['containers','x'],['mychatbuddy-start','x'],['mychatbuddy-stop','--all'],['python','x']):
   with self.assertRaises(ValueError):broker.parse(args)
 def test_final_sudo_no_confirmation(self):
  self.assertIn('migration-confirm',broker.sudoers());self.assertNotIn('migration-confirm',broker.sudoers(False))
  for raw in (broker.sudoers(),broker.sudoers(False)):
   self.assertNotIn('NOPASSWD: ALL',raw);self.assertNotIn('*',raw);self.assertNotIn('SETENV:',raw.replace('NOSETENV:',''))
 def test_capsule_determinism_compile(self):
  a,h=capsule.build(Path(__file__).parent,{'containers':{},'units':{}},{})
  b,j=capsule.build(Path(__file__).parent,{'containers':{},'units':{}},{})
  self.assertEqual(a,b);self.assertEqual(h,j);self.assertEqual(h,hashlib.sha256(a).hexdigest());compile(a,'fixture','exec')
 def test_bad_payload(self):
  with self.assertRaises(Refused):validate_payload({'version':9,'modules':{},'runtime':{},'baseline_files':{}})
 def test_loader_coverage(self):
  with self.assertRaises(RuntimeError):Loader({})
  l=Loader({n:b'' for n in NAMES});self.assertIsNone(l.find_spec('user_supplied'))
 def test_public_no_private(self):
  s={'status':'COMPLETE','watchdog_disabled':False,'steps':[{'phase':'finalize','before':{'secret':'test sentinel'}}],'capsule_sha256':'a'*64,'deadline_ns':1,'boot_id':'fixture'}
  p=projection(s);self.assertEqual(p['status'],'FINALIZATION_PENDING');self.assertNotIn('sentinel',json.dumps(p))
  s['watchdog_disabled']=True;self.assertEqual(projection(s)['status'],'COMPLETE')
 def test_clients_identity_and_ports(self):
  def fake(cmd,*args,**kwargs):
   if cmd[0]=='/usr/bin/curl':return b'200'
   if cmd[-1]=='/usr/bin/id -un':return b'chatops\n'
   return b'{"status":"OK"}'
  with patch.object(client,'capture',side_effect=fake) as m:client.client_checks()
  commands=[x.args[0] for x in m.call_args_list];self.assertEqual(commands[0][commands[0].index('-p')+1],'22');self.assertEqual(commands[1][commands[1].index('-p')+1],'2222')
 def test_client_wrong_user_refused(self):
  with patch.object(client,'capture',return_value=b'root\n'):
   with self.assertRaises(RuntimeError):client.client_checks()
 def test_client_non200_refused(self):
  with patch.object(client,'capture',side_effect=[b'chatops\n',b'chatops\n',b'302']):
   with self.assertRaises(RuntimeError):client.client_checks()
 def test_peer_topology_bounded_retry(self):
  with patch.object(runtime,'audit',side_effect=[audit.TopologyChanged('fixture'),{}]),patch.object(runtime,'assess_clients',return_value={'wait_pids':[]}),patch.object(runtime.time,'sleep'):
   self.assertEqual(runtime.clear_clients({})['classification']['wait_pids'],[])
 def test_non_topology_error_never_ignored(self):
  with patch.object(runtime,'audit',side_effect=Refused('unknown client')):
   with self.assertRaises(Refused):runtime.clear_clients({})
 def test_path_fd_chatops_rejected(self):
  with self.assertRaises(Refused):runtime.assess_clients({'path_handles':[{'identity':{'uid':(1001,)*4}}],'peers':{}},{})
 def test_socket_pre_intent_foreign_metadata(self):
  b={'dev':1,'ino':2,'uid':0,'gid':987,'mode':0o660}
  with self.assertRaises(Refused):audit.rollback_postimage(b,{**b,'mode':0o600},False)
 def test_socket_partial_write_recovery(self):
  b={'dev':1,'ino':2,'uid':0,'gid':987,'mode':0o660}
  self.assertEqual(audit.rollback_postimage(b,{**b,'mode':0o600},True)['gid'],987)
 def test_socket_replacement_refused(self):
  b={'dev':1,'ino':2,'uid':0,'gid':987,'mode':0o660}
  with self.assertRaises(Refused):audit.rollback_postimage(b,{**b,'ino':3},True)

if __name__=='__main__':unittest.main()
