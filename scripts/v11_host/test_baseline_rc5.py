import copy,unittest
import baseline as b
import rc5_gate as r
class Baseline(unittest.TestCase):
 def setUp(self):
  i={'uid':1001,'gid':1001,'mode':0o600,'nlink':1,'regular':True,'sha256':'a'*64,'inode':4}
  self.o={'active_writer':False,'tracked_match':True,'index_before':i,'index_after':dict(i),'head':b.HEAD,'tree':b.TREE}
  self.t={'from':b.PREVIOUS,'to':b.HEAD,'tree':b.TREE,'merge_base':b.PREVIOUS,'ahead':b.AHEAD,'behind':0,'changed_paths':sorted(b.PATHS),'authorized':True}
 def test_authorized(self):self.assertEqual(b.admit(self.o,self.t)['status'],'AUTHORIZED_FORWARD_SUPERSESSION')
 def test_old(self):
  self.o['head']=b.PREVIOUS
  with self.assertRaises(b.Refused):b.admit(self.o,self.t)
 def test_unknown(self):
  self.o['head']='a'*40
  with self.assertRaises(b.Refused):b.admit(self.o,self.t)
 def test_wrong_tree(self):
  self.o['tree']='a'*40
  with self.assertRaises(b.Refused):b.admit(self.o,self.t)
 def test_root_index(self):
  self.o['index_before']['uid']=0
  with self.assertRaises(b.Refused):b.admit(self.o,self.t)
 def test_index_mutation(self):
  self.o['index_after']['inode']=5
  with self.assertRaises(b.Refused):b.admit(self.o,self.t)
 def test_authorized_new_index(self):
  for i in ('index_before','index_after'):self.o[i]['inode']=88;self.o[i]['sha256']='b'*64
  self.assertEqual(b.admit(self.o,self.t)['head'],b.HEAD)
 def test_writer(self):
  self.o['active_writer']=True
  with self.assertRaises(b.Refused):b.admit(self.o,self.t)
 def test_local_mutation(self):
  self.o['tracked_match']=False
  with self.assertRaises(b.Refused):b.admit(self.o,self.t)
 def test_side_line(self):
  self.t['merge_base']='f'*40
  with self.assertRaises(b.Refused):b.admit(self.o,self.t)
 def test_extra_path(self):
  self.t['changed_paths'].append('other')
  with self.assertRaises(b.Refused):b.admit(self.o,self.t)
class RC5(unittest.TestCase):
 def test_zero_activity(self):r.activity(dict.fromkeys(('owner_bindings','provider_reservations','provider_leases','delivered_updates'),0))
 def test_activity_or_bool(self):
  for v in (1,True,-1):
   with self.assertRaises(r.Refused):r.activity(dict.fromkeys(('owner_bindings','provider_reservations','provider_leases','delivered_updates'),v))
 def test_fresh(self):self.assertEqual(len(r.heartbeat(None,'2026-10-02 12:00:01.000000','2026-10-02T12:00:00+00:00','2026-10-02T12:00:02+00:00')),64)
 def test_stale_future_malformed(self):
  for v in ('2026-10-02 11:00:00.000000','2026-10-02 13:00:00.000000','bad',None):
   with self.assertRaises(r.Refused):r.heartbeat(None,v,'2026-10-02T12:00:00+00:00','2026-10-02T12:00:02+00:00')
 def test_unchanged(self):
  with self.assertRaises(r.Refused):r.heartbeat('2026-10-02 12:00:01.000000','2026-10-02 12:00:01.000000','2026-10-02T12:00:00+00:00','2026-10-02T12:00:02+00:00')
 def test_long_poll(self):self.assertFalse(r.sockets(['192.0.2.1'],[('192.0.2.1',443)])['proves_no_egress'])
 def test_zero_socket(self):self.assertEqual(r.sockets(['192.0.2.1'],[])['established'],0)
 def test_unknown_multiple_socket(self):
  for rows in ([('192.0.2.2',443)],[('192.0.2.1',80)],[('192.0.2.1',443)]*2,[('::1',443)]):
   with self.assertRaises(r.Refused):r.sockets(['192.0.2.1'],rows)
 def test_probe_failure(self):
  with self.assertRaises(r.Refused):r.sockets(['192.0.2.1'],[],socket_rc=1)
 def test_old_gate(self):
  with self.assertRaises(r.Refused):r.outer_policy('ZERO_ESTABLISHED')
 def test_no_identity_output(self):self.assertNotIn('192.0.2.1',str(r.sockets(['192.0.2.1'],[('192.0.2.1',443)])))
if __name__=='__main__':unittest.main()
