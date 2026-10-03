import unittest,tempfile,os,shutil,sys,subprocess
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from anchor import *
def corrupt(p,data):
 mode=p.stat().st_mode&0o777;p.chmod(0o600);p.write_bytes(data);p.chmod(mode)
W1=b'worker version one\n';W2=b'worker version two\n'
class Host:
 def __init__(self,s):self.s=s;self.calls=[];self.fail=None;self.running=False;self.restored=False
 def call(self,n):
  self.calls.append(n)
  if self.fail==n:raise Refused('INJECTED_FAILURE')
 def confirm_closed(self):self.call('closed');assert self.s.closed()
 def verify_base(self):self.call('base');self.s.base();self.s.choose()
 def run_worker(self,slot,phase):self.call('worker');self.running=False;self.restored=True;return TERMINAL
 def quiesce_watchdog(self):self.call('watchdog_off')
 def no_worker(self):self.call('no_worker');assert not self.running
 def verify_rollback(self,phase):self.call('rollback');assert self.restored
class Tests(unittest.TestCase):
 def setUp(self):
  self.root=Path(tempfile.mkdtemp(prefix='tu1nz-anchor-test-',dir='/tmp'));self.root.chmod(0o700);self.root.rmdir();self.s=Store(self.root,fixture=True,create=True)
  self.s.write('anchor.py',b'anchor v1',0o500)
  self.base={'schema':1,'anchor_sha256':digest(b'anchor v1'),'interpreter':'/usr/bin/python3.12','interpreter_sha256':'a'*64,'workers':[digest(W1),digest(W2)],'phase1_paths':['/usr/local/libexec/tu1nz-v11-dispatcher/installer.py']}
  self.s.write('base.json',encode(self.base));self.s.publish_slot('A',W1);self.h=Host(self.s)
 def tearDown(self):self.s.close();shutil.rmtree(self.root)
 def phase(self):self.s.write('phase1.json',encode({'transaction':'v11-'+'a'*32,'manifest_sha256':'b'*64,'paths':self.base['phase1_paths']}),0o600)
 def test_phase0_ready(self):self.assertEqual(Anchor(self.s,self.h).run(),'RECOVERY_BASE_READY');self.assertTrue(self.s.closed())
 def test_roundtrip_idempotent(self):
  self.phase();self.assertEqual(Anchor(self.s,self.h).run(),TERMINAL);self.assertEqual(Anchor(self.s,self.h).run(),TERMINAL);self.assertEqual(self.h.calls.count('worker'),1)
 def test_active_never_overwritten(self):
  with self.assertRaisesRegex(Refused,'ACTIVE_SLOT'):self.s.publish_slot('A',W2)
  self.assertEqual(self.s.read('slot-A.py',0o500),W1)
 def test_switch_retains_prior(self):
  self.s.publish_slot('B',W2);self.assertEqual(self.s.choose()['slot'],'B');self.assertEqual(self.s.read('slot-A.py',0o500),W1)
  with self.assertRaisesRegex(Refused,'PREVIOUS_SLOT'):self.s.publish_slot('A',W1)
 def test_corrupt_active_falls_back(self):
  self.s.publish_slot('B',W2);corrupt(self.root/'slot-B.py',b'corrupt');self.assertEqual(self.s.choose()['slot'],'A')
 def test_corrupt_inactive_keeps_active(self):
  self.s.publish_slot('B',W2);corrupt(self.root/'slot-A.py',b'corrupt');self.assertEqual(self.s.choose()['slot'],'B')
 def test_both_corrupt_secured_stop(self):
  self.s.publish_slot('B',W2)
  for n in ('A','B'):corrupt(self.root/('slot-'+n+'.py'),b'corrupt')
  self.assertEqual(Anchor(self.s,self.h).run(),'SECURED_STOP')
 def test_corrupt_anchor_secured_stop(self):
  corrupt(self.root/'anchor.py',b'corrupt');self.assertEqual(Anchor(self.s,self.h).run(),'SECURED_STOP')
 def test_crash_before_selection_keeps_active(self):
  def fail(point):
   if point=='before_select':raise Refused('CRASH')
  self.s.inject=fail
  with self.assertRaises(Refused):self.s.publish_slot('B',W2)
  self.assertEqual(self.s.choose()['slot'],'A');self.s.inject=lambda p:None;self.s.publish_slot('B',W2);self.assertEqual(self.s.choose()['slot'],'B')
 def test_slot_symlink_rejected(self):
  p=self.root/'slot-A.py';p.unlink();p.symlink_to('/etc/passwd')
  with self.assertRaises(Refused):self.s.choose()
 def test_slot_hardlink_rejected(self):
  os.link(self.root/'slot-A.py',self.root/'other')
  with self.assertRaises(Refused):self.s.choose()
 def test_slot_mode_rejected(self):
  (self.root/'slot-A.py').chmod(0o700)
  with self.assertRaises(Refused):self.s.choose()
 def test_path_swap_rejected(self):
  other=self.root.with_name(self.root.name+'-old');self.root.rename(other);self.root.mkdir(mode=0o700)
  try:
   with self.assertRaises(Refused):self.s.base()
  finally:self.root.rmdir();other.rename(self.root)
 def test_unpinned_worker(self):
  with self.assertRaisesRegex(Refused,'UNPINNED'):self.s.publish_slot('B',b'unpinned')
 def test_duplicate_manifest_fields(self):
  (self.root/'selection.json').write_bytes(b'{"active":1,"active":2}')
  with self.assertRaises(Refused):self.s.choose()
 def test_selection_injection(self):
  (self.root/'selection.json').write_bytes(encode({'active':{'slot':'../../etc/passwd','sha256':'a'*64},'previous':None,'generation':0}))
  with self.assertRaises(Refused):self.s.choose()
 def test_nonpinned_manifest_hash(self):
  corrupt(self.root/'slot-A.json',encode({'schema':1,'slot':'A','worker_sha256':'a'*64,'base_sha256':digest(self.s.read('base.json'))}))
  with self.assertRaises(Refused):self.s.choose()
 def test_phase0_not_in_rollback(self):
  for p in (ROOT,ROOT+'/anchor.py','/var/lib','/'):
   b=dict(self.base,phase1_paths=[p]);corrupt(self.root/'base.json',encode(b))
   with self.assertRaises(Refused):self.s.base()
 def test_late_failure_closes(self):
  self.phase();self.h.fail='rollback';self.assertEqual(Anchor(self.s,self.h).run(),'SECURED_STOP');self.assertTrue(self.s.closed());self.assertFalse(self.s.exists('terminal.json'))
 def test_existing_stop_never_releases(self):
  self.s.stop('TEST');self.assertEqual(Anchor(self.s,self.h).run(),'SECURED_STOP');self.assertNotIn('worker',self.h.calls)
 def test_terminal_requires_reverification(self):
  self.phase();self.assertEqual(Anchor(self.s,self.h).run(),TERMINAL);self.h.restored=False;self.assertEqual(Anchor(self.s,self.h).run(),'SECURED_STOP')
 def test_parallel_process_lock(self):
  code='import sys;sys.path.insert(0,'+repr(str(Path(__file__).parent))+');from anchor import Store;s=Store('+repr(str(self.root))+',fixture=True);c=s.locked();c.__enter__()'
  with self.s.locked():
   p=subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  self.assertNotEqual(p.returncode,0)
 def test_reboot_resume(self):
  self.phase();self.s.close();self.s=Store(self.root,fixture=True);self.h=Host(self.s);self.assertEqual(Anchor(self.s,self.h).run(),TERMINAL)
 def test_unknown_phase_path(self):
  self.phase();x=parse(self.s.read('phase1.json',0o600));x['paths']=['/etc/shadow'];self.s.write('phase1.json',encode(x),0o600,True);self.assertEqual(Anchor(self.s,self.h).run(),'SECURED_STOP');self.assertNotIn('worker',self.h.calls)
 def test_unknown_names(self):
  for n in ('../x','A.py','/etc/passwd','slot-C.py'):
   with self.assertRaises(Refused):self.s.write(n,b'x')
 def test_decommission_is_not_an_anchor_operation(self):self.assertFalse(hasattr(self.s,'decommission'));self.assertFalse(hasattr(Anchor,'decommission'))
if __name__=='__main__':unittest.main()
