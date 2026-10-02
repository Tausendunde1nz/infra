import tempfile,unittest
from pathlib import Path
from state import Store,Refused,encode,digest
from preseal import Journal,Recovery,STEPS
from test_fence import BINDING,FakeHost
from host import Host
class PresealTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='tu1nz-fence-test-',dir='/tmp');self.path=Path(self.tmp.name);self.path.chmod(0o700);self.store=Store(self.path,fixture=True);self.store.initialize(dict(BINDING));self.j=Journal(self.store)
 def tearDown(self):self.store.close();self.tmp.cleanup()
 def test_marker_is_durable_and_bound(self):
  self.j.inhibit();self.assertEqual(self.store.read('PRESEAL_INHIBIT')['binding'],BINDING);self.assertEqual((self.path/'PRESEAL_INHIBIT').stat().st_mode&0o777,0o400)
 def test_marker_blocks_legacy_even_before_arm(self):
  h=FakeHost(self.store);h.install_fence_recovery();h.reload_fence();self.assertTrue(h.can_start('legacy'));self.j.inhibit();self.assertFalse(h.can_start('legacy'))
 def test_marker_survives_reopen(self):
  self.j.inhibit();self.store.close();self.store=Store(self.path,fixture=True);self.assertTrue(self.store.exists('PRESEAL_INHIBIT'))
 def test_no_skip_to_fence_removal(self):
  with self.assertRaises(Refused):self.j.append('REMOVE_FENCE','INTENT')
 def test_intent_resumes_same_step(self):
  self.j.inhibit();self.j.append('INHIBIT','INTENT');_,rows,_=self.j.read();self.assertEqual(rows[-1]['status'],'INTENT')
  with self.assertRaises(Refused):self.j.append('VALIDATE_ORIGINALS','INTENT')
 def test_hash_chain_detects_mutation(self):
  self.j.append('INHIBIT','INTENT');self.j.append('INHIBIT','VERIFIED','a'*64);p=self.path/'recovery-000000.json';x=self.store.read(p.name);x['proof']='tampered';p.chmod(0o600);p.write_bytes(encode(x));p.chmod(0o400)
  with self.assertRaises(Refused):self.j.read()
 def test_foreign_binding(self):
  self.j.append('INHIBIT','INTENT');p=self.path/'recovery-000000.json';x=self.store.read(p.name);x['binding']={**BINDING,'transaction':'v11-'+'c'*32};p.chmod(0o600);p.write_bytes(encode(x));p.chmod(0o400)
  with self.assertRaises(Refused):self.j.read()
 def test_exclusive_recovery_lock(self):
  with self.j.locked():
   with self.assertRaises(BlockingIOError):
    with Journal(self.store).locked():pass
 def test_production_lifetime_gate_before_mutation(self):
  h=Host.__new__(Host)
  with self.assertRaisesRegex(Refused,'INDEPENDENT_ROLLBACK_DISPATCHER_NOT_BOUND'):h.preseal_step('INHIBIT',BINDING,BINDING['boot'])
 def test_closed_admission_does_not_write_or_stop_service(self):
  h=Host.__new__(Host);before=sorted(self.path.iterdir())
  with self.assertRaisesRegex(Refused,'PRESEAL_PRODUCTION_ADMISSION_CLOSED'):Recovery(self.store,h).run(BINDING['boot'])
  self.assertEqual(before,sorted(self.path.iterdir()));self.assertFalse(self.store.exists('PRESEAL_INHIBIT'))
 def test_known_steps_only(self):
  with self.assertRaises(Refused):self.j.append('ARBITRARY','INTENT')
if __name__=='__main__':unittest.main()
