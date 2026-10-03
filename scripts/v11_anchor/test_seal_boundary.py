import os,sys,unittest,tempfile,shutil,time,copy,subprocess,contextlib
from pathlib import Path
HERE=Path(__file__).parent
sys.path[:0]=[str(HERE),str(HERE.parent/'v11_guard_recovery'),str(HERE.parent/'v11_dispatcher')]
from anchor import *
import phase0,seal_boundary as sb,split_guard as sg,state as gs
import test_phase as component
BOOT='01234567-89ab-cdef-0123-456789abcdef'
REBOOT='11234567-89ab-cdef-0123-456789abcdef'
PROOFS=('preflight','backups','rollback','anchor','fence','legacy_block','unsealed')
FINAL=('consumers','permissions','authority','watchdog','services','transitions')
def ctx(s):
 a={'guard':'c'*64,'authority':'d'*64}
 return {'schema':2,'transaction':'v11-'+'a'*32,'origin_boot':BOOT,'recovery_generation':0,'control_commit':sb.CONTROL,'control_tree':sb.TREE,'infra_basis':'cd4a10320fe935fd615570a3e90d3fa6127c0fa5','guard_version':'v11-guard-2','guard_sha256':'c'*64,'guard_contract_sha256':'b'*64,'artifacts':a,'artifact_manifest_sha256':digest(encode(a)),'activation_manifest_sha256':'e'*64,'base_sha256':digest(s.read('base.json')),'worker_pins':s.base()['workers']}
class Audit:
 def __init__(self,s,g):self.s=s;self.g=g;self.current_boot=BOOT;self.bad=False;self.final_bad=False;self.actions=[];self.block=True;self.all_inactive=True
 def close(self):self.s.close_fence();self.block=True
 def confirm_closed(self):assert self.s.closed() and self.block
 def quiesce(self):self.actions.append('quiesce');self.all_inactive=True
 def boot(self):return self.current_boot
 def legacy_block_pin(self):self.confirm_closed();return digest(b'fixed-closed-fence')
 def verify_barrier(self,c,sealed):
  if self.bad:raise Refused('CONFLICTING_OBJECTIVE_MARKERS')
  self.confirm_closed()
  if not sealed:
   # Fixture analogue of pinned original permission/authority checks.
   if (self.g.path/'unexpected-authority').exists():raise Refused('ORIGINAL_AUTHORITY_CHANGED')
 def preseal_proofs(self,state):
  assert state['phase']=='LEGACY_INHIBITED_PRESEAL' and not state['sealed'];self.confirm_closed()
  return {k:digest(k.encode()) for k in PROOFS}
 def postseal_proofs(self,state):
  if self.final_bad:raise Refused('FINAL_CHECK_FAILED')
  assert state['sealed'] and state['phase']=='COMPLETED';self.confirm_closed()
  return {k:digest(k.encode()) for k in FINAL}
 def verify_rollback(self):
  assert not self.g.exists('SEALED') and self.g.current()['phase']=='ROLLED_BACK_PRESEAL';self.confirm_closed()
class Host:
 def __init__(self,g):self.g=g;self.actions=[];self.fail=None
 def action(self,name):
  self.actions.append(name)
  if self.fail==name:raise Refused('HOST_FAILURE')
 def __getattr__(self,n):
  if n in ('preflight','backup','install_fence_recovery','reload_fence','verify_fence_loaded','enable_recovery','start_recovery','enable_watchdog','start_watchdog','verify_watchdog','quiesce_prearm','stop_timer','install_guard','install_authority','install_consumer','install_checksum','reload_consumer','verify_new_loaded','probe_new','start_timer','final_verify'):
   return lambda:self.action(n)
  raise AttributeError(n)
 def blocked_start(self):self.action('blocked_start');return True
 def verify_result(self):return {'consumer_sha256':'c'*64,'authority_sha256':'d'*64,'loaded_unit_sha256':'e'*64,'result_sha256':'f'*64}
 def rollback_preseal(self):
  self.action('rollback');assert not self.g.exists('SEALED')
  return {'originals_identical':True,'no_foreign_writer':True,'timer_original_verified':True}
 def finish_rollback(self):return 'ROLLED_BACK_PRESEAL'
def setup_files():
 a=Path(tempfile.mkdtemp(prefix='tu1nz-anchor-test-',dir='/tmp'));a.rmdir()
 phase0.prepare(a,b'anchor',[b'worker'],'/usr/bin/python3.12','a'*64,['/run/phase1-test'],fixture=True)
 gp=Path(tempfile.mkdtemp(prefix='tu1nz-fence-test-',dir='/tmp'));gp.chmod(0o700)
 g=gs.Store(gp,fixture=True);g.initialize({'transaction':'v11-'+'a'*32,'boot':BOOT,'contract_sha256':'b'*64,'deadline_ns':time.monotonic_ns()+1800_000_000_000,'coordinator_pid':os.getpid(),'coordinator_start_ticks':1})
 return a,gp,g
class BoundaryTests(unittest.TestCase):
 def setUp(self):
  self.a,self.gp,self.g=setup_files();self.s=Store(self.a,fixture=True);self.audit=Audit(self.s,self.g);self.host=Host(self.g);self.bridge=sg.GuardBridge(self.g,self.host,self.audit);self.b=sb.Boundary(self.s,self.bridge);self.c=ctx(self.s);self.b.bind(self.c)
 def tearDown(self):self.g.close();self.s.close();shutil.rmtree(self.a);shutil.rmtree(self.gp)
 def prepared(self):
  with self.b.locked():return self.b.prepare_locked()
 def intent(self):
  with self.b.locked():
   ready=self.b.prepare_locked();self.b.chain.publish('SEAL_INTENT',ready,{'ready':ready,'guard_contract':self.c['guard_contract_sha256']})
 def sealed(self):
  self.intent()
  with self.b.locked():self.bridge.seal()
 def test_success_all_three_attestations(self):
  self.assertEqual(self.b.run(),'COMPLETE')
  self.b.chain.ready();self.b.chain.sealed();self.b.chain.complete()
  self.assertNotIn('rollback',self.host.actions)
 def test_preseal_ready_is_reversible(self):self.prepared();self.assertEqual(self.b.recover(),TERMINAL);self.assertFalse(self.g.exists('SEALED'))
 def test_no_intent_rolls_back(self):self.assertEqual(self.b.recover(),TERMINAL)
 def test_unsealed_despite_intent_rolls_back(self):self.intent();self.assertEqual(self.b.recover(),TERMINAL)
 def test_sealed_without_outer_attestation_repairs_forward(self):self.sealed();self.assertEqual(self.b.recover(),'COMPLETE');self.assertNotIn('rollback',self.host.actions)
 def test_sealed_without_intent_never_rolls_back(self):
  self.prepared();self.bridge.seal();self.assertEqual(self.b.recover(),sb.UNKNOWN);self.assertNotIn('rollback',self.host.actions)
 def test_journal_alone_never_proves_seal(self):
  self.intent();self.audit.bad=True;self.assertEqual(self.b.recover(),sb.UNKNOWN);self.assertNotIn('rollback',self.host.actions)
 def test_original_authority_changed_no_marker_cannot_rollback(self):
  (self.gp/'unexpected-authority').write_bytes(b'fixture');self.assertEqual(self.b.recover(),sb.UNKNOWN);self.assertNotIn('rollback',self.host.actions)
 def test_postseal_failure_stops_sealed(self):
  self.sealed();self.host.fail='install_guard';self.assertEqual(self.b.recover(),sb.SEALED_STOP);self.assertNotIn('rollback',self.host.actions);self.assertTrue(self.audit.all_inactive)
 def test_final_verification_failure_never_complete(self):
  self.sealed();self.audit.final_bad=True;self.assertEqual(self.b.recover(),sb.SEALED_STOP);self.assertFalse(self.s.exists('boundary-complete.json'))
 def test_timeout_before_seal_rolls_back(self):self.prepared();self.assertEqual(self.b.timeout(),TERMINAL)
 def test_timeout_after_seal_goes_forward(self):self.sealed();self.assertEqual(self.b.timeout(),'COMPLETE');self.assertNotIn('rollback',self.host.actions)
 def test_reboot_after_seal_uses_fresh_objective_probe(self):
  self.sealed();self.audit.current_boot=REBOOT;self.assertEqual(self.b.recover(),'COMPLETE');self.assertEqual(self.b.chain.context()['origin_boot'],BOOT)
 def test_terminal_reboot_verifies_does_not_reapply(self):
  self.assertEqual(self.b.run(),'COMPLETE');old=list(self.host.actions);self.audit.current_boot=REBOOT;self.assertEqual(self.b.recover(),'COMPLETE');self.assertEqual(old,self.host.actions)
 def test_replayed_run_only_verifies_complete(self):
  self.assertEqual(self.b.run(),'COMPLETE');old=list(self.host.actions);self.assertEqual(self.b.run(),'COMPLETE');self.assertEqual(old,self.host.actions)
 def test_rebind_transaction_denied(self):
  with self.assertRaises(Refused):self.b.bind(dict(self.c,transaction='v11-'+'b'*32))
 def test_wrong_recovery_generation_denied(self):
  with self.assertRaises(Refused):self.b.bind(dict(self.c,recovery_generation=1))
 def test_unknown_stop_remains_stopped_after_probe_changes(self):
  self.intent();self.audit.bad=True;self.assertEqual(self.b.recover(),sb.UNKNOWN);self.audit.bad=False;self.assertEqual(self.b.recover(),sb.UNKNOWN);self.assertNotIn('rollback',self.host.actions)
 def test_sealed_marker_mode_corruption_stops(self):
  self.sealed();(self.gp/'SEALED').chmod(0o600);self.assertEqual(self.b.recover(),sb.UNKNOWN);self.assertNotIn('rollback',self.host.actions)
 def test_sealed_marker_hardlink_stops(self):
  self.sealed();os.link(self.gp/'SEALED',self.gp/'duplicate');self.assertEqual(self.b.recover(),sb.UNKNOWN)
 def test_parent_swap_stops_before_mutation(self):
  self.intent();old=self.a.with_name(self.a.name+'-old');self.a.rename(old);self.a.mkdir(mode=0o700)
  try:
   with self.assertRaises(Refused):self.b.recover()
   self.assertNotIn('rollback',self.host.actions)
  finally:self.a.rmdir();old.rename(self.a)
 def test_old_rollback_after_sealed_is_denied(self):
  self.sealed()
  with self.b.locked():self.assertFalse(self.b.rollback_allowed())
  with self.assertRaises(Refused):self.bridge.rollback_preseal()
 def test_guard_marker_transaction_tamper_stops(self):
  self.sealed();p=self.gp/'SEALED';row=gs.strict(p.read_bytes());row['binding']['transaction']='v11-'+'f'*32;p.chmod(0o600);p.write_bytes(gs.encode(row));p.chmod(0o400)
  self.assertEqual(self.b.recover(),sb.UNKNOWN);self.assertNotIn('rollback',self.host.actions)
 def test_concurrent_process_cannot_enter_boundary(self):
  code='import sys;sys.path.insert(0,'+repr(str(HERE))+');from test_seal_boundary import crash_child;crash_child('+repr(str(self.a))+','+repr(str(self.gp))+',None)'
  with self.b.locked():
   p=subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
  self.assertNotEqual(p.returncode,0);self.assertFalse(self.s.exists('boundary-intent.json'))
 def test_preseal_rollback_repeat_is_idempotent(self):
  self.prepared();self.assertEqual(self.b.recover(),TERMINAL);self.assertEqual(self.b.recover(),TERMINAL)
 def test_old_rollback_without_lock_denies(self):
  with self.assertRaisesRegex(Refused,'BOUNDARY_LOCK'):self.b.rollback_allowed()
 def test_guard_parent_swap_stops(self):
  self.sealed();old=self.gp.with_name(self.gp.name+'-old');self.gp.rename(old);self.gp.mkdir(mode=0o700)
  try:self.assertEqual(self.b.recover(),sb.UNKNOWN);self.assertNotIn('rollback',self.host.actions)
  finally:self.gp.rmdir();old.rename(self.gp)
 def test_production_factory_is_closed(self):
  self.s.fixture=False
  try:
   with self.assertRaisesRegex(Refused,'PRODUCTION_DIRECTIONAL'):sb.Boundary(self.s,self.bridge)
  finally:self.s.fixture=True

def tamper_case(state,kind):
 def test(self):
  if state=='PRESEAL_READY':self.prepared()
  else:self.b.run()
  p=self.a/sb.NAMES[state];raw=p.read_bytes()
  if kind=='symlink':p.unlink();p.symlink_to('/etc/passwd')
  elif kind=='hardlink':os.link(p,self.a/'copy')
  elif kind=='content':p.chmod(0o600);p.write_bytes(b'{}');p.chmod(0o400)
  elif kind=='commit':q=p.with_name(p.stem+'-commit.json');q.unlink()
  old=len(self.host.actions)
  outcome=self.b.recover();self.assertIn(outcome,(sb.UNKNOWN,sb.SEALED_STOP));self.assertNotIn('rollback',self.host.actions[old:])
 return test
for state in sb.ATTESTATIONS:
 for kind in ('symlink','hardlink','content','commit'):setattr(BoundaryTests,'test_'+state+'_'+kind,tamper_case(state,kind))

def crash_child(a,gp,point):
 s=Store(a,fixture=True,inject=lambda p:os._exit(91) if p==point else None);g=gs.Store(gp,fixture=True);au=Audit(s,g);h=Host(g);b=sb.Boundary(s,sg.GuardBridge(g,h,au));b.run()
def crash_case(point,expected):
 def test(self):
  code='import sys;sys.path.insert(0,'+repr(str(HERE))+');from test_seal_boundary import crash_child;crash_child('+repr(str(self.a))+','+repr(str(self.gp))+','+repr(point)+')'
  p=subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30);self.assertEqual(p.returncode,91,p.stderr)
  self.audit.current_boot=REBOOT;self.assertEqual(self.b.recover(),expected);self.assertEqual(self.s.read('anchor.py',0o500),b'anchor');self.assertEqual(self.s.choose()['slot'],'A')
 return test
for point,outcome in [
 ('before_publish:boundary-preseal.json',TERMINAL),('after_publish:boundary-preseal.json',sb.UNKNOWN),
 ('before_publish:boundary-intent.json',TERMINAL),('after_publish:boundary-intent.json',sb.UNKNOWN),
 ('boundary_durable:SEAL_INTENT',sb.UNKNOWN),('before_barrier',TERMINAL),('after_barrier','COMPLETE'),
 ('before_publish:boundary-sealed.json','COMPLETE'),('after_publish:boundary-sealed.json',sb.SEALED_STOP),
 ('before_publish:boundary-complete.json','COMPLETE'),('after_publish:boundary-complete.json',sb.SEALED_STOP)]:
 setattr(BoundaryTests,'test_crash_'+point.replace(':','_'),crash_case(point,outcome))

class IntegratedFiles(unittest.TestCase):
 def setUp(self):
  component.Phase.setUp(self)
  self.gp=Path(tempfile.mkdtemp(prefix='tu1nz-fence-test-',dir='/tmp'));self.gp.chmod(0o700);self.g=gs.Store(self.gp,fixture=True)
  self.g.initialize({'transaction':'v11-'+'a'*32,'boot':BOOT,'contract_sha256':'b'*64,'deadline_ns':time.monotonic_ns()+1800_000_000_000,'coordinator_pid':os.getpid(),'coordinator_start_ticks':1})
  self.audit=Audit(self.s,self.g);self.hguard=Host(self.g);self.guard=sg.GuardBridge(self.g,self.hguard,self.audit)
  def trial(c,before):
   # Practical separate shadow roundtrip of the actual publication engine.
   t=component.Phase('test_roundtrip_removes_main_but_preserves_anchor_slots');t.setUp()
   try:t.test_roundtrip_removes_main_but_preserves_anchor_slots();return digest(encode({'candidates':{p:r['sha256'] for p,r in c.items()},'before':before,'roundtrip':True}))
   finally:t.tearDown()
  self.host=sg.SplitInstallerHost(self.i,self.guard,self.c,self.before,trial);self.boundary=sb.Boundary(self.s,self.host);self.host.boundary=self.boundary;self.i.boundary=self.boundary;self.context=ctx(self.s);from bootstrap import plan_pin;self.context['activation_manifest_sha256']=plan_pin(self.s,self.c,self.before);self.boundary.bind(self.context)
 def tearDown(self):self.g.close();shutil.rmtree(self.gp);component.Phase.tearDown(self)
 def test_integrated_preseal_rollback_exact_files_and_phase0_retained(self):
  with self.boundary.locked():self.boundary.prepare_locked()
  self.assertEqual(self.boundary.recover(),TERMINAL);self.assertTrue(self.f.same_restored_snapshot(self.before));self.assertEqual(self.s.read('anchor.py',0o500),b'anchor')
 def test_integrated_postseal_complete_never_restores_originals(self):
  self.assertEqual(self.boundary.run(),'COMPLETE');self.assertFalse(self.f.same_restored_snapshot(self.before))
  self.i.load()
  with self.boundary.locked():
   with self.assertRaisesRegex(Refused,'ROLLBACK_FORBIDDEN'):self.i._rollback()
 def test_old_rollback_missing_direction_adapter_denies(self):
  with self.boundary.locked():self.boundary.prepare_locked()
  self.i.boundary=None
  with self.assertRaisesRegex(Refused,'ROLLBACK_NOT_BOUND'):self.i._rollback()
 def test_candidate_plan_pin_denies_before_any_publication(self):
  p=next(iter(self.c));self.c[p]['bytes']+=b'change';self.c[p]['sha256']=digest(self.c[p]['bytes'])
  self.assertEqual(self.boundary.run(),sb.UNKNOWN);self.assertTrue(self.f.same_restored_snapshot(self.before))
 def test_postseal_failure_retains_published_files_and_anchor(self):
  self.hguard.fail='install_authority';self.assertEqual(self.boundary.run(),sb.SEALED_STOP);self.assertFalse(self.f.same_restored_snapshot(self.before));self.assertEqual(self.s.choose()['slot'],'A')

def guard_crash_child(a,gp,point):
 s=Store(a,fixture=True);g=gs.Store(gp,fixture=True,inject=lambda p:os._exit(91) if p==point else None)
 au=Audit(s,g);b=sb.Boundary(s,sg.GuardBridge(g,Host(g),au));b.run()
def guard_crash_case(point,outcome):
 def test(self):
  code='import sys;sys.path.insert(0,'+repr(str(HERE))+');from test_seal_boundary import guard_crash_child;guard_crash_child('+repr(str(self.a))+','+repr(str(self.gp))+','+repr(point)+')'
  p=subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30);self.assertEqual(p.returncode,91,p.stderr)
  self.audit.current_boot=REBOOT;self.assertEqual(self.b.recover(),outcome);self.assertTrue(self.s.closed())
  if outcome!=TERMINAL:self.assertNotIn('rollback',self.host.actions)
 return test
for point,outcome in [('before_publish:SEALED',TERMINAL),('after_link:SEALED',sb.UNKNOWN),('before_directory_fsync:SEALED',sb.SEALED_STOP),('after_directory_fsync:SEALED',sb.SEALED_STOP)]:
 setattr(BoundaryTests,'test_guard_barrier_crash_'+point.replace(':','_'),guard_crash_case(point,outcome))

if __name__=='__main__':unittest.main()
