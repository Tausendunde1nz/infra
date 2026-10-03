"""Split adapter for the existing Guard; marker proof is not journal inference.
A fixed caller must provide the original-byte and closed-fence audit. Real
production construction stays closed until the independent lifetime binding.
"""
import contextlib,os
from pathlib import Path
from anchor import Refused,digest,encode,TERMINAL
import coordinator as old
class GuardBridge:
 def __init__(self,store,host,audit):
  self.g=store;self.h=host;self.audit=audit
  if os.geteuid()==0:
   from isolated_runtime import GuardStore,GuardHost,Audit
   if type(store)!=GuardStore or type(host)!=GuardHost or type(audit)!=Audit:raise Refused('PRODUCTION_GUARD_SPLIT_NOT_BOUND')
  elif store.uid==0 or store.path.parent!=Path('/tmp') or not store.path.name.startswith('tu1nz-fence-test-'):raise Refused('PRODUCTION_GUARD_SPLIT_NOT_BOUND')
 def locked(self):return self.g.locked()
 def close(self):self.audit.close()
 def confirm_closed(self):self.audit.confirm_closed()
 def quiesce(self):self.audit.quiesce()
 def observe(self,c):
  st=self.g.path.lstat();fd=os.fstat(self.g.fd);self.g.check(self.g.fd,True,0o700)
  if (st.st_dev,st.st_ino)!=(fd.st_dev,fd.st_ino):raise Refused('OBJECTIVE_GUARD_PATH_SWAP')
  self.confirm_closed();b=self.g.current()['binding'] if not self.g.exists('SEALED') else self.g.read('SEALED')['binding']
  if b['transaction']!=c['transaction'] or b['contract_sha256']!=c['guard_contract_sha256'] or b['boot']!=c['origin_boot']:raise Refused('OBJECTIVE_GUARD_BINDING')
  if self.g.exists('SEALED'):
   marker=self.g.read('SEALED')
   if marker!={'binding':b,'sealed':True}:raise Refused('OBJECTIVE_GUARD_MARKER')
   self.audit.verify_barrier(c,True)
   status='SEALED';barrier=digest(encode(marker))
  else:
   # Marker absence alone cannot authorize rollback. Verify the pinned original
   # trust boundary, starts and inactive consumers independently of the journal.
   self.audit.verify_barrier(c,False)
   status='UNSEALED';barrier=digest(encode({'binding':b,'verified_original_boundary':True}))
  return {'state':status,'boot':self.audit.boot(),'barrier':barrier,'authority':c['guard_contract_sha256'],'legacy_forbidden':self.audit.legacy_block_pin()}
 def verify_observation(self,c,p):
  if self.observe(c)!=p:raise Refused('OBJECTIVE_OBSERVATION_CHANGED')
 def prepare_preseal(self):
  co=old.Coordinator(self.g,self.h);s=self.g.current()
  if s['phase']=='LEGACY_INHIBITED_PRESEAL':return
  if s['phase']!='LEGACY_ALLOWED_PRETRANSACTION':raise Refused('GUARD_PRESEAL_STAGE')
  co.event('preflight',self.h.preflight);co.event('backup',self.h.backup)
  for name in old.EVENTS[2:10]:co.event(name,getattr(self.h,name))
  self.g.advance('FENCE_INSTALLED_UNARMED',{'loaded_and_verified':True})
  co.event('quiesce_prearm',self.h.quiesce_prearm)
  self.g.advance('LEGACY_INHIBITED_PRESEAL',{'fence_loaded':True})
  if self.h.blocked_start() is not True:raise Refused('LEGACY_NOT_BLOCKED')
 def verify_preseal(self):
  return self.audit.preseal_proofs(self.g.current())
 def seal(self):
  # Only called after outer SEAL_INTENT and fsync commit validation.
  self.g.advance('SECURITY_BARRIER_SEALED',{'inhibit_verified':True,'blocked_start_verified':True,'recovery_verified':True,'watchdog_verified':True})
 def rollback_preseal(self):
  if self.g.exists('SEALED'):raise Refused('GUARD_OBJECTIVE_SEALED')
  if self.g.current()['phase']=='ROLLED_BACK_PRESEAL':
   self.audit.verify_rollback();return TERMINAL
  result=old.Coordinator(self.g,self.h).recover()
  if result!='ROLLED_BACK_PRESEAL':raise Refused('GUARD_PRESEAL_ROLLBACK')
  return TERMINAL
 def verify_rollback(self):self.audit.verify_rollback()
 def forward_repair(self):
  s=self.g.current()
  if not s['sealed']:raise Refused('FORWARD_NOT_SEALED')
  # Each host installation validates original or owned postimage receipts.
  # An incomplete Guard hash-chain or missing original receipts safely refuses.
  if s['phase']=='SECURITY_BARRIER_SEALED':
   for name in ('stop_timer','install_guard','install_authority','install_consumer','install_checksum'):getattr(self.h,name)()
   self.g.advance('NEW_CONSUMER_STAGED',{'candidate_bytes_installed':True});s=self.g.current()
  if s['phase']=='NEW_CONSUMER_STAGED':
   self.h.reload_consumer();self.h.verify_new_loaded();self.h.probe_new()
   self.g.advance('NEW_CONSUMER_VERIFIED',self.h.verify_result());s=self.g.current()
  if s['phase']=='NEW_CONSUMER_VERIFIED':
   self.h.start_timer();self.h.final_verify();self.g.advance('COMPLETED',{'final_checks_passed':True})
  elif s['phase']!='COMPLETED':raise Refused('FORWARD_GUARD_PHASE')
  self.h.final_verify()
 def verify_final(self):return self.audit.postseal_proofs(self.g.current())

class SplitInstallerHost:
 """Compose exact file publication with the Guard bridge. No commands in data.
 The fixed outer engine already holds the anchor/Guard locks."""
 def __init__(self,installer,guard,candidates,originals,rollback_trial):
  self.i=installer;self.g=guard;self.c=candidates;self.before=originals;self.trial=rollback_trial
  self.boundary=None
 def locked(self):return self.g.locked()
 def close(self):self.g.close()
 def confirm_closed(self):self.g.confirm_closed()
 def quiesce(self):self.g.quiesce()
 def observe(self,c):return self.g.observe(c)
 def verify_observation(self,c,p):return self.g.verify_observation(c,p)
 def prepare_preseal(self):
  from bootstrap import plan_pin
  if self.boundary.chain.context()['activation_manifest_sha256']!=plan_pin(self.i.s,self.c,self.before):raise Refused('SPLIT_CANDIDATE_PLAN_PIN')
  self.i.boundary=self.boundary
  if self.i.j.load()[0] is None:
   c=self.boundary.chain.context()
   if self.i.start_locked(c['transaction'],self.c,self.before)!='PHASE1_PUBLISHED_FENCED':raise Refused('PHASE1A_STAGE')
  self.i.load();self.i.h.verify_published(self.c);self.g.prepare_preseal()
 def verify_preseal(self):
  proof=self.g.verify_preseal();trial=self.trial(self.c,self.before)
  if not isinstance(trial,str) or len(trial)!=64:raise Refused('PRACTICAL_ROLLBACK_TRIAL')
  return {**proof,'rollback':trial}
 def seal(self):
  self.g.seal()
  # Secondary journal flag is defense in depth, never the seal classifier.
  self.i.load();self.i.state['sealed']=True;self.i.persist()
 def rollback_preseal(self):
  self.g.rollback_preseal()
  with self.i.j.locked():
   self.i.load();return self.i._rollback()
 def verify_rollback(self):self.i.f.same_restored_snapshot(self.before) or (_ for _ in ()).throw(Refused('PHASE1A_ROLLBACK'));self.g.verify_rollback()
 def forward_repair(self):
  self.i.load();self.i.state['sealed']=True;self.i.persist()
  self.i.h.verify_published(self.c);self.g.forward_repair()
 def verify_final(self):self.i.h.verify_published(self.c);return self.g.verify_final()
