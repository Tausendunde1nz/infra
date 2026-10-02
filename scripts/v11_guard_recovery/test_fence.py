import copy,os,tempfile,unittest
from pathlib import Path
import state as s
import runtime as r
from coordinator import Coordinator,EVENTS
BINDING={'transaction':'v11-'+'a'*32,'boot':'12345678-1234-1234-1234-123456789abc','deadline_ns':10**12,'coordinator_pid':100,'coordinator_start_ticks':200,'contract_sha256':'a'*64}
class FakeHost:
 def __init__(self,store):
  self.store=store;self.pin='a'*64;self.installed=False;self.loaded_fence=False;self.new=False;self.loaded_new=False;self.timer=True;self.bad=False;self.calls=[]
  self.c={'files':{r.NEW:{'sha256':'b'*64},r.AUTH:{'sha256':'c'*64}},'unit_templates':{r.CONSUMER:'new-unit'},'new_authority_sha256':'c'*64}
 def preflight(self):return True
 def backup(self):return True
 def install_fence_recovery(self):self.installed=True
 def reload_fence(self):self.loaded_fence=self.installed
 def verify_fence_loaded(self):
  if not self.loaded_fence:raise s.Refused('RELOAD_INCOMPLETE')
 def enable_recovery(self):pass
 def start_recovery(self):pass
 def enable_watchdog(self):pass
 def start_watchdog(self):pass
 def verify_watchdog(self):self.verify_fence_loaded()
 def quiesce_prearm(self):return True
 def blocked_start(self):return not self.can_start('legacy')
 def stop_timer(self):self.timer=False
 def install_guard(self):self.new=True
 def install_authority(self):pass
 def install_consumer(self):pass
 def install_checksum(self):pass
 def reload_consumer(self):self.loaded_new=self.new
 def verify_new_loaded(self):
  if not self.loaded_new or self.bad:raise s.Refused('NEW_NOT_LOADED')
 def probe_new(self):self.verify_new_loaded()
 def verify_result(self):return {'consumer_sha256':'b'*64,'authority_sha256':'c'*64,'loaded_unit_sha256':s.digest(b'new-unit'),'result_sha256':'d'*64}
 def start_timer(self):
  if not self.can_start('new'):raise s.Refused('NEW_NOT_ADMITTED')
  self.timer=True
 def final_verify(self):self.verify_new_loaded();return True
 def rollback_preseal(self):
  if self.bad:raise s.Refused('FOREIGN_WRITER')
  return {'originals_identical':True,'no_foreign_writer':True,'timer_original_verified':True}
 def finish_rollback(self):self.installed=False;self.loaded_fence=False;self.timer=True;return 'ROLLED_BACK_PRESEAL'
 def verify(self,c,pin,new):
  if self.bad or not self.installed or (new and not self.new):raise s.Refused('PAYLOAD')
  return True
 def run(self,argv):
  self.calls.append(argv)
  if argv==r.SHOW_GUARD:
   return '\n'.join(('ExecStart={ argv[]='+('/usr/bin/python3 -I -B '+r.NEW if self.loaded_new else r.LEGACY)+' ; }','ExecCondition={ argv[]=/usr/bin/python3 -I -B '+r.PROGRAM+' condition '+self.pin+' ; }','DropInPaths='+r.FENCE+(' '+r.CONSUMER if self.loaded_new else ''),'Requires='+r.RECOVERY,'After='+r.RECOVERY,'ActiveState=inactive'))+'\n'
  if argv==r.SHOW_TIMER:return 'Requires='+r.RECOVERY+'\nAfter='+r.RECOVERY+'\nDropInPaths='+r.TIMER_DEP+'\nActiveState='+('active' if self.timer else 'inactive')+'\nUnitFileState=enabled\n'
  if argv==r.STOP_TIMER:self.timer=False;return ''
  if argv==r.START_TIMER:self.timer=True;return ''
  if argv in (r.NEW_PROBE,r.STATUS_PROBE):self.verify_new_loaded();return ''
  raise s.Refused('COMMAND')
 def can_start(self,consumer):
  if not self.loaded_fence:return consumer=='legacy'
  if consumer!=('new' if self.loaded_new else 'legacy'):return False
  return r.condition(self.store,self.c,self.pin,self.run,self.verify)

class Base(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='tu1nz-fence-test-',dir='/tmp');self.path=Path(self.tmp.name);self.path.chmod(0o700);self.store=s.Store(self.path,fixture=True);self.store.initialize(dict(BINDING));self.host=FakeHost(self.store)
 def tearDown(self):self.store.close();self.tmp.cleanup()
 def arm(self):
  self.host.install_fence_recovery();self.host.reload_fence();self.store.advance('FENCE_INSTALLED_UNARMED',{});self.store.advance('LEGACY_INHIBITED_PRESEAL',{})
 def seal(self):
  self.arm();self.store.advance('SECURITY_BARRIER_SEALED',{'inhibit_verified':True,'blocked_start_verified':True,'recovery_verified':True,'watchdog_verified':True})
class StateTests(Base):
 def test_success(self):self.assertEqual(Coordinator(self.store,self.host,clock=lambda:0).run(),'COMPLETED');self.assertTrue(self.host.can_start('new'));self.assertFalse(self.host.can_start('legacy'))
 def test_repeat_complete(self):
  c=Coordinator(self.store,self.host,clock=lambda:0);c.run();count=len(list(self.path.iterdir()));c.run();self.assertEqual(count,len(list(self.path.iterdir())))
 def test_immutable_records(self):
  self.arm()
  for f in self.path.glob('state-*.json'):self.assertEqual(f.stat().st_mode&0o777,0o400);self.assertEqual(f.stat().st_nlink,1)
 def test_missing(self):
  self.arm();(self.path/'state-000002.json').unlink()
  self.assertFalse(self.host.can_start('legacy'))
 def test_corrupt(self):
  self.arm();f=self.path/'state-000002.json';f.chmod(0o600);f.write_bytes(b'bad');f.chmod(0o400);self.assertFalse(self.host.can_start('legacy'))
 def test_symlink(self):
  self.arm();f=self.path/'state-000002.json';f.unlink();f.symlink_to('/etc/passwd');self.assertFalse(self.host.can_start('legacy'))
 def test_hardlink(self):
  self.arm();os.link(self.path/'state-000002.json',self.path/'other');self.assertFalse(self.host.can_start('legacy'))
 def test_wrong_mode(self):
  self.arm();(self.path/'state-000002.json').chmod(0o640);self.assertFalse(self.host.can_start('legacy'))
 def test_duplicate_json(self):
  with self.assertRaises(s.Refused):s.strict(b'{"x":1,"x":2}')
 def test_unknown_phase(self):
  self.arm()
  with self.assertRaises(s.Refused):self.store.advance('UNKNOWN',{})
 def test_sealed_rollback(self):
  self.seal()
  with self.assertRaises(s.Refused):self.store.rollback({'originals_identical':True,'no_foreign_writer':True,'timer_original_verified':True})
 def test_preseal_verified_rollback(self):
  self.arm();self.assertEqual(Coordinator(self.store,self.host,clock=lambda:0).recover(),'ROLLED_BACK_PRESEAL')
 def test_foreign_rollback(self):
  self.arm();self.host.bad=True
  with self.assertRaises(s.Refused):Coordinator(self.store,self.host,clock=lambda:0).recover()
  self.assertFalse(self.host.can_start('legacy'))
 def test_latch_crash(self):
  self.arm()
  def crash(_):raise s.Crash()
  with self.assertRaises(s.Crash):self.store.advance('SECURITY_BARRIER_SEALED',{'inhibit_verified':True,'blocked_start_verified':True,'recovery_verified':True,'watchdog_verified':True},crash)
  self.assertTrue(self.store.current()['sealed']);self.assertFalse(self.host.can_start('legacy'))
 def test_stop_idempotent(self):
  self.arm();self.store.stop('TEST');count=len(list(self.path.iterdir()));self.store.stop('TEST');self.assertEqual(count,len(list(self.path.iterdir())));self.assertFalse(self.host.can_start('legacy'))
 def test_parent_replacement(self):
  self.arm();original=self.path.with_name(self.path.name+'-old');self.path.rename(original);self.path.mkdir(mode=0o700)
  try:
   with self.assertRaises(s.Refused):self.store.current()
  finally:self.path.rmdir();original.rename(self.path)
 def test_watchdog_alive_waits_sealed(self):
  self.seal();self.assertEqual(s.decision(self.store.current(),BINDING['boot'],1,True),'WAIT')
 def test_deadline(self):
  self.seal();self.assertEqual(s.decision(self.store.current(),BINDING['boot'],10**12,True),'FORWARD_OR_SECURED_STOP')
 def test_reboot(self):
  self.seal();self.assertEqual(s.decision(self.store.current(),'other-boot',1,True),'FORWARD_OR_SECURED_STOP')
 def test_no_terminal_replay(self):
  Coordinator(self.store,self.host,clock=lambda:0).run();self.host.calls=[]
  self.assertEqual(r.recover_once(self.store,self.host.c,self.host.pin,'other',10**15,self.host.run,self.host.verify,lambda _:False,mode='watchdog'),'COMPLETED')
  self.assertNotIn(r.NEW_PROBE,self.host.calls);self.assertNotIn(r.START_TIMER,self.host.calls)
 def test_wrong_loaded_unit(self):
  self.arm();self.host.loaded_new=True;self.assertFalse(self.host.can_start('legacy'))
 def test_corrupt_recovery_keeps_fence_closed(self):
  self.arm();(self.path/'state-000002.json').chmod(0o600)
  self.assertEqual(r.recover_once(self.store,self.host.c,self.host.pin,'other',0,self.host.run,self.host.verify,lambda _:False),'SECURED_STOP')
  self.assertFalse(self.host.can_start('legacy'))

FAULTS=('coordinator_crash','watchdog_crash','both_crash','signal','timeout','reboot','corrupt','missing','foreign_writer','unit_swap','hash','owner','mode','symlink','hardlink','incomplete_reload','timer','manual','repeat','expired')
class CrashMatrix(Base):
 def case(self,point,fault):
  def inject(p):
   if p==point:raise s.Crash()
  try:Coordinator(self.store,self.host,inject,clock=lambda:0).run()
  except s.Crash:pass
  phase=self.store.current()['phase'];sealed=self.store.current()['sealed'];armed=phase in s.PHASES[2:]
  if fault in ('foreign_writer','unit_swap','hash','owner','mode'):self.host.bad=True
  if fault=='incomplete_reload':self.host.loaded_new=False if self.host.new else self.host.loaded_new
  if fault in ('corrupt','missing','symlink','hardlink'):
   f=sorted(self.path.glob('state-*.json'))[-1]
   if fault=='corrupt':f.chmod(0o600);f.write_bytes(b'bad');f.chmod(0o400)
   if fault=='missing':f.unlink()
   if fault=='symlink':f.unlink();f.symlink_to('/etc/passwd')
   if fault=='hardlink':os.link(f,self.path/'extra-link')
  if armed:self.assertFalse(self.host.can_start('legacy'),(point,fault))
  if fault in ('watchdog_crash','timer','manual') and phase!='COMPLETED':
   # Fence remains effective even with no executing recovery process.
   if armed:self.assertFalse(self.host.can_start('legacy'))
  result=r.recover_once(self.store,self.host.c,self.host.pin,'new-boot' if fault=='reboot' else BINDING['boot'],10**15 if fault in ('timeout','expired') else 1,self.host.run,self.host.verify,lambda _:False,mode='watchdog')
  if sealed:self.assertIn(result,('SECURED_STOP','COMPLETED','WAIT_TIMER'))
  if armed:self.assertFalse(self.host.can_start('legacy'))
  for _ in range(2):r.recover_once(self.store,self.host.c,self.host.pin,'new-boot',10**15,self.host.run,self.host.verify,lambda _:False,mode='watchdog')
  if armed:self.assertFalse(self.host.can_start('legacy'))
for event in EVENTS:
 for edge in ('before','after'):
  for fault in FAULTS:
   point=edge+':'+event
   def test(self,p=point,f=fault):self.case(p,f)
   setattr(CrashMatrix,'test_'+edge+'_'+event+'_'+fault,test)
if __name__=='__main__':unittest.main()
