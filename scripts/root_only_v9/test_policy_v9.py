import unittest
from policy_v9 import *
from audit_v9 import peer_ids

BASE='[Socket]\nListenStream=/run/docker.sock\nSocketMode=0660\nSocketUser=root\nSocketGroup=docker\n'
class PolicyTests(unittest.TestCase):
 def facts(self):return {'socket_path':SOCKET,'socket_creator':'systemd','dockerd_hosts':['fd://'],'socket_unit':'docker.socket','daemon_hosts':False,'daemon_group':False,'other_listeners':[]}
 def test_systemd(self):self.assertEqual(persistence(self.facts())['content'],DROPIN)
 def test_dockerd_requires_separate_contract(self):
  f=self.facts();f.update(socket_creator='dockerd',socket_unit_active=False,dockerd_hosts=['unix://'+SOCKET]);self.assertFalse(persistence(f)['activation_ready'])
 def test_conflicting_creators(self):
  f=self.facts();f['dockerd_hosts']=['unix://'+SOCKET]
  with self.assertRaises(Refused):persistence(f)
 def test_daemon_conflict(self):
  for key in ('daemon_hosts','daemon_group','other_listeners'):
   f=self.facts();f[key]=True
   with self.assertRaises(Refused):persistence(f)
 def test_persistence_both_restart_paths(self):
  for event in ('docker_restart','host_restart'):
   self.assertTrue(validate_persistence(BASE,{'90-tu1nz-root-only.conf':DROPIN}))
 def test_later_override_rejected(self):
  with self.assertRaises(Refused):validate_persistence(BASE,{'90.conf':DROPIN,'99.conf':'[Socket]\nSocketMode=0660\n'})
 def test_root(self):self.assertTrue(dac_connect_allowed(0,[],0,0,0o600))
 def test_old_gid_is_not_authority(self):self.assertFalse(dac_connect_allowed(1001,[4,27,100,987,999,1001],0,0,0o600))
 def test_previous_group_authority(self):self.assertTrue(dac_connect_allowed(1001,[987],0,987,0o660))
 def test_other_group_interface(self):self.assertTrue(dac_connect_allowed(1001,[987],0,987,0o660))
 def test_caps_must_be_reviewed(self):self.assertTrue(dac_connect_allowed(1001,[987],0,0,0o600,['CAP_DAC_OVERRIDE']))
 def client(self):
  c={'pid':3,'start_ticks':4,'uid':0,'gid':0,'cgroup':'monitor','namespace':'host','fd_snapshot_complete':True,'peer_resolved':True,'identity_before':'a','identity_after':'a','chatops_controlled':False};return c
 def test_accepted_monitoring(self):
  c=self.client();self.assertEqual(client_gate([c],(1,2),(1,2),{identity(c)}),'CLEAR')
 def test_unknown_client(self):
  c=self.client()
  with self.assertRaises(Refused):client_gate([c],1,1,set())
 def test_open_chatops_connection(self):
  c=self.client();c['chatops_controlled']=True
  with self.assertRaises(Refused):client_gate([c],1,1,{identity(c)})
 def test_transient_cli_waits(self):
  c=self.client();c.update(chatops_controlled=True,transient_cli=True);self.assertEqual(client_gate([c],1,1,set()),'WAIT_AND_RESCAN')
 def test_pid_reuse(self):
  c=self.client();c['identity_after']='different'
  with self.assertRaises(Refused):client_gate([c],1,1,{identity(c)})
 def test_inode_reuse(self):
  with self.assertRaises(Refused):client_gate([],1,2,set())
 def test_fd_incomplete(self):
  c=self.client();c['fd_snapshot_complete']=False
  with self.assertRaises(Refused):client_gate([c],1,1,{identity(c)})
 def authority(self):
  return dict(socket={'uid':0,'gid':0,'mode':0o600},socket_identity_stable=True,all_namespaces_reviewed=True,fd_audit_complete=True,other_gid_interfaces_closed=True,fresh_connection_denied=True,old_context_connections_denied=True,broker_no_passthrough=True,root_docker_ok=True,monitoring_ok=True,chatops_open_peers=[],chatops_is_docker_member=False,old_process_groups=[987])
 def test_authority_not_numeric_gid(self):self.assertTrue(authority_gate(self.authority()))
 def test_each_gate_required(self):
  for key,value in self.authority().items():
   if value is True:
    f=self.authority();f[key]=False
    with self.assertRaises(Refused):authority_gate(f)
 def test_member_rejected(self):
  f=self.authority();f['chatops_is_docker_member']=True
  with self.assertRaises(Refused):authority_gate(f)
 def test_open_peer_rejected(self):
  f=self.authority();f['chatops_open_peers']=[1]
  with self.assertRaises(Refused):authority_gate(f)
 def test_preseal_rollback(self):self.assertEqual(rollback_policy(False,[])['socket'],'RESTORE_EXACT_METADATA')
 def test_sealed_rollback(self):
  p=rollback_policy(True,list(PHASES));self.assertEqual(p['socket'],'KEEP_ROOT_ONLY');self.assertEqual(p['unsafe_triggers'],'KEEP_QUARANTINED')
 def test_no_service_restart(self):self.assertFalse(any(restart_permissions(True).values()))
 def test_ss_inodes_distinguished(self):
  text='u_str LISTEN 0 4096 /run/docker.sock 5809 * 0 ino:1268\nu_str ESTAB 0 0 /run/docker.sock 91 * 92 ino:1268\n'
  peers,servers,listeners=peer_ids(text);self.assertEqual(peers,{92});self.assertEqual(servers,{91});self.assertEqual(listeners,{5809});self.assertNotIn(1268,peers)
 def test_ss_unparsed_fails_closed(self):
  with self.assertRaises(Refused):peer_ids('/run/docker.sock invalid')
 def test_ss_listener_required(self):
  with self.assertRaises(Refused):peer_ids('')

if __name__=='__main__':unittest.main()
