"""Ordered Guard subtransaction; no host action on import."""
from state import *
EVENTS=('preflight','backup','install_fence_recovery','reload_fence','verify_fence_loaded','enable_recovery','start_recovery','enable_watchdog','start_watchdog','verify_watchdog','unarmed','quiesce_prearm','arm','blocked_start','seal','stop_timer','install_guard','install_authority','install_consumer','install_checksum','stage','reload_consumer','verify_new_loaded','probe_new','verify_result','verify_state','start_timer','final_verify','complete')
class Coordinator:
 def __init__(self,store,host,inject=lambda event:None,clock=time.monotonic_ns):self.store=store;self.host=host;self.inject=inject;self.clock=clock
 def event(self,name,fn):
  state=self.store.current()
  if self.clock()+300_000_000_000>=state['binding']['deadline_ns']:raise Refused('RECOVERY_MARGIN')
  self.inject('before:'+name);result=fn();self.inject('after:'+name);return result
 def run(self):
  s=self.store.current()
  if s['phase']=='COMPLETED':return self.host.final_verify()
  if s['phase']!='LEGACY_ALLOWED_PRETRANSACTION':raise Refused('FRESH_TRANSACTION_REQUIRED')
  self.event('preflight',self.host.preflight);self.event('backup',self.host.backup)
  for name in EVENTS[2:10]:self.event(name,getattr(self.host,name))
  self.event('unarmed',lambda:self.store.advance('FENCE_INSTALLED_UNARMED',{'loaded_and_verified':True}))
  self.event('quiesce_prearm',self.host.quiesce_prearm)
  self.event('arm',lambda:self.store.advance('LEGACY_INHIBITED_PRESEAL',{'fence_loaded':True}))
  proof=self.event('blocked_start',self.host.blocked_start)
  if proof is not True:raise Refused('LEGACY_START_NOT_PROVEN_BLOCKED')
  self.event('seal',lambda:self.store.advance('SECURITY_BARRIER_SEALED',{'inhibit_verified':True,'blocked_start_verified':True,'recovery_verified':True,'watchdog_verified':True},self.inject))
  for name in ('stop_timer','install_guard','install_authority','install_consumer','install_checksum'):self.event(name,getattr(self.host,name))
  self.event('stage',lambda:self.store.advance('NEW_CONSUMER_STAGED',{'candidate_bytes_installed':True}))
  self.event('reload_consumer',self.host.reload_consumer);self.event('verify_new_loaded',self.host.verify_new_loaded)
  self.event('probe_new',self.host.probe_new);proof=self.event('verify_result',self.host.verify_result)
  self.event('verify_state',lambda:self.store.advance('NEW_CONSUMER_VERIFIED',proof))
  self.event('start_timer',self.host.start_timer);self.event('final_verify',self.host.final_verify)
  self.event('complete',lambda:self.store.advance('COMPLETED',{'final_checks_passed':True}))
  return 'COMPLETED'
 def recover(self):
  try:s=self.store.current()
  except Exception:self.store.stop('CORRUPT_OR_UNKNOWN');return 'SECURED_STOP'
  if s['phase']=='COMPLETED':self.host.final_verify();return 'COMPLETED'
  if s['sealed']:
   self.store.stop('SEALED_TRANSACTION_INTERRUPTED');self.host.stop_timer();return 'SECURED_STOP'
  proof=self.host.rollback_preseal()
  self.store.rollback(proof)
  return self.host.finish_rollback()
