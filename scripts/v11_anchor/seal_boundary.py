"""Directional V11 boundary v2: no import-time actions or production admission.
Durable intent is not proof of seal. Every direction needs fresh objective
Guard-marker verification under the same lock as the mutation. Unknown stops.
"""
import os,re,contextlib
from anchor import Refused,encode,parse,digest,pin,tx,TERMINAL
CONTROL='2281b2b397c017bc370ba108eab3dc00c989eaa5'
TREE='3d52fe0898238e1132d8947a7e171d8086982170'
UNKNOWN='SECURED_STOP_SEAL_UNKNOWN'
SEALED_STOP='SECURED_STOP_SEALED'
ATTESTATIONS=('PRESEAL_READY','SEALED','POSTSEAL_COMPLETE')
NAMES={'PRESEAL_READY':'boundary-preseal.json','SEAL_INTENT':'boundary-intent.json','SEALED':'boundary-sealed.json','POSTSEAL_COMPLETE':'boundary-complete.json'}
FIELDS={'schema','transaction','origin_boot','recovery_generation','control_commit','control_tree','infra_basis','guard_version','guard_sha256','guard_contract_sha256','artifacts','artifact_manifest_sha256','activation_manifest_sha256','base_sha256','worker_pins'}
def valid_context(c,s):
 if type(c)!=dict or set(c)!=FIELDS or c['schema']!=2 or not tx(c['transaction']):raise Refused('BOUNDARY_CONTEXT')
 if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',c['origin_boot']):raise Refused('BOUNDARY_BOOT')
 if type(c['recovery_generation'])!=int or not 0<=c['recovery_generation']<1000000:raise Refused('BOUNDARY_GENERATION')
 if c['control_commit']!=CONTROL or c['control_tree']!=TREE or not re.fullmatch('[0-9a-f]{40}',c['infra_basis']):raise Refused('BOUNDARY_BASELINE')
 if not re.fullmatch('[A-Za-z0-9_.-]{1,64}',c['guard_version']):raise Refused('BOUNDARY_VERSION')
 for k in ('guard_sha256','guard_contract_sha256','artifact_manifest_sha256','activation_manifest_sha256','base_sha256'):
  if not pin(c[k]):raise Refused('BOUNDARY_PIN')
 a=c['artifacts']
 if type(a)!=dict or not a or len(a)>256 or any(not re.fullmatch('[A-Za-z0-9_.-]{1,128}',k) or not pin(v) for k,v in a.items()) or a.get('guard')!=c['guard_sha256'] or digest(encode(a))!=c['artifact_manifest_sha256']:raise Refused('BOUNDARY_ARTIFACTS')
 if c['base_sha256']!=digest(s.read('base.json')) or c['worker_pins']!=s.base()['workers']:raise Refused('BOUNDARY_ANCHOR')
 return True

class Chain:
 def __init__(self,s):self.s=s
 def bind(self,c):
  valid_context(c,self.s)
  if self.s.exists('boundary-context.json'):
   if self.context()!=c:raise Refused('BOUNDARY_REBIND')
  else:self.s.write('boundary-context.json',encode(c))
 def context(self):
  c=parse(self.s.read('boundary-context.json'));valid_context(c,self.s);return c
 def row(self,state,previous,proof):
  c=self.context()
  if state not in NAMES or not pin(previous) or type(proof)!=dict or not proof or any(not pin(v) for v in proof.values()):raise Refused('BOUNDARY_PROOF')
  return {'schema':2,'state':state,'context_sha256':digest(encode(c)),'transaction':c['transaction'],'recovery_generation':c['recovery_generation'],'previous_sha256':previous,'proof':proof,'fence':'CLOSED','starts':'CLOSED'}
 def publish(self,state,previous,proof):
  row=self.row(state,previous,proof);n=NAMES[state];raw=encode(row)
  if self.s.exists(n):
   if self.s.read(n)!=raw:raise Refused('BOUNDARY_EXISTING_DRIFT')
  else:self.s.write(n,raw)
  # Durable receipts are never inferred from a successful rename or journal.
  fd=self.s.open(n,0o400)
  try:os.fsync(fd)
  finally:os.close(fd)
  os.fsync(self.s.fd)
  self.s.inject('boundary_durable:'+state)
  commit={'schema':2,'state':state,'sha256':digest(raw),'context_sha256':row['context_sha256'],'file_fsync':True,'directory_fsync':True}
  cn=n.replace('.json','-commit.json')
  if self.s.exists(cn):
   if parse(self.s.read(cn))!=commit:raise Refused('BOUNDARY_COMMIT_DRIFT')
  else:self.s.write(cn,encode(commit))
  return digest(raw)
 def read(self,state,previous,keys):
  n=NAMES[state];r=parse(self.s.read(n));wanted=self.row(state,previous,r.get('proof'))
  if r!=wanted or set(r['proof'])!=set(keys):raise Refused('BOUNDARY_CHAIN_OR_PROOF')
  c=parse(self.s.read(n.replace('.json','-commit.json')))
  if c!={'schema':2,'state':state,'sha256':digest(encode(r)),'context_sha256':r['context_sha256'],'file_fsync':True,'directory_fsync':True}:raise Refused('BOUNDARY_NOT_DURABLE')
  return digest(encode(r))
 def ready(self):return self.read('PRESEAL_READY','0'*64,('preflight','backups','rollback','anchor','fence','legacy_block','unsealed'))
 def intent(self):return self.read('SEAL_INTENT',self.ready(),('ready','guard_contract'))
 def sealed(self):return self.read('SEALED',self.intent(),('barrier','authority','legacy_forbidden'))
 def complete(self):return self.read('POSTSEAL_COMPLETE',self.sealed(),('consumers','permissions','authority','watchdog','services','transitions'))

class Boundary:
 """Host is fixed code, never selected from persisted data. Production factories
 remain closed until independent lifetime/marker adapters are verified."""
 def __init__(self,s,host):
  self.s=s;self.h=host;self.chain=Chain(s);self.depth=0
  if not s.fixture:
   from isolated_runtime import Runtime
   if type(host)!=Runtime or not host.root_binding(s):raise Refused('PRODUCTION_DIRECTIONAL_HOST_NOT_BOUND')
 @contextlib.contextmanager
 def locked(self):
  # Same ordering everywhere: outer anchor, then actual Guard writer lock.
  with self.s.locked(),self.h.locked():
   if self.depth:raise Refused('BOUNDARY_REENTRY')
   self.depth=1
   try:yield
   finally:self.depth=0
 def bind(self,c):
  with self.locked():self.s.base();self.s.choose();self.chain.bind(c)
 def close(self):
  self.s.close_fence();self.h.close();self.h.confirm_closed()
 def probe(self):
  self.close();c=self.chain.context();proof=self.h.observe(c)
  if type(proof)!=dict or set(proof)!={'state','boot','barrier','authority','legacy_forbidden'}:raise Refused('OBJECTIVE_PROOF_FIELDS')
  if proof['state'] not in ('UNSEALED','SEALED','UNKNOWN') or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',proof['boot']) or any(not pin(proof[k]) for k in ('barrier','authority','legacy_forbidden')):raise Refused('OBJECTIVE_PROOF_FORMAT')
  # Observe must freshly verify installed root markers AND authority/fence.
  # A state journal alone, boot mismatch or timeout does not choose direction.
  self.h.verify_observation(c,proof)
  return proof
 def stop(self,state):
  self.close();self.h.quiesce()
  r={'schema':2,'state':state,'context_sha256':digest(encode(self.chain.context())),'fence':'CLOSED','starts':'CLOSED'}
  if self.s.exists('boundary-stop.json'):
   old=parse(self.s.read('boundary-stop.json'))
   if old!=r:raise Refused('STOP_CLASSIFICATION_DRIFT')
  else:self.s.write('boundary-stop.json',encode(r))
  return state
 def prior_stop(self):
  if self.s.exists('stop.json') and not self.s.exists('boundary-stop.json'):
   self.s.read('stop.json');return self.stop(UNKNOWN)
  if not self.s.exists('boundary-stop.json'):return None
  r=parse(self.s.read('boundary-stop.json'))
  if r!={'schema':2,'state':r.get('state'),'context_sha256':digest(encode(self.chain.context())),'fence':'CLOSED','starts':'CLOSED'} or r['state'] not in (UNKNOWN,SEALED_STOP):raise Refused('STOP_BINDING')
  self.close();self.h.quiesce();return r['state']
 def rollback_allowed(self):
  # Called while both the outer and Guard writer locks are already held.
  if self.depth!=1:raise Refused('ROLLBACK_REQUIRES_BOUNDARY_LOCK')
  p=self.probe()
  if p['state']!='UNSEALED' or self.s.exists(NAMES['SEALED']) or self.s.exists(NAMES['POSTSEAL_COMPLETE']):return False
  if self.s.exists(NAMES['PRESEAL_READY']):self.chain.ready()
  if self.s.exists(NAMES['SEAL_INTENT']):
   self.chain.intent() # corrupt/uncommitted intent cannot grant rollback
  return not self.s.exists('boundary-stop.json')
 def rollback(self):
  if not self.rollback_allowed():return self.stop(UNKNOWN)
  result=self.h.rollback_preseal()
  if result!=TERMINAL:raise Refused('PRESEAL_ROLLBACK_RESULT')
  self.h.verify_rollback();self.s.base();self.s.choose();self.close()
  return TERMINAL
 def prepare_locked(self):
  if self.s.exists(NAMES['SEAL_INTENT']):raise Refused('PREPARE_AFTER_INTENT')
  if self.probe()['state']!='UNSEALED':raise Refused('PREPARE_NOT_UNSEALED')
  self.h.prepare_preseal()
  proof=self.h.verify_preseal()
  if set(proof)!={'preflight','backups','rollback','anchor','fence','legacy_block','unsealed'}:raise Refused('PRESEAL_CHECKS')
  if self.probe()['state']!='UNSEALED':raise Refused('PRESEAL_BARRIER_CHANGED')
  return self.chain.publish('PRESEAL_READY','0'*64,proof)
 def forward(self,p):
  if p['state']!='SEALED':return self.stop(UNKNOWN)
  try:
   self.chain.intent()
   if self.s.exists(NAMES['SEALED']):self.chain.sealed()
   else:self.chain.publish('SEALED',self.chain.intent(),{k:p[k] for k in ('barrier','authority','legacy_forbidden')})
   if self.s.exists(NAMES['POSTSEAL_COMPLETE']):
    self.chain.complete();self.h.verify_final();self.close();return 'COMPLETE'
   self.s.record({'operation':'POSTSEAL_APPLYING','context_sha256':digest(encode(self.chain.context()))})
   self.h.forward_repair()
   if self.probe()['state']!='SEALED':return self.stop(SEALED_STOP)
   proof=self.h.verify_final()
   if set(proof)!={'consumers','permissions','authority','watchdog','services','transitions'}:raise Refused('POSTSEAL_CHECKS')
   self.chain.publish('POSTSEAL_COMPLETE',self.chain.sealed(),proof)
   self.chain.complete();self.close();return 'COMPLETE'
  except Exception:return self.stop(SEALED_STOP)
 def run(self):
  with self.locked():return self.run_locked()
 def run_locked(self):
  if self.depth!=1:raise Refused('BOUNDARY_LOCK_REQUIRED')
  old=self.prior_stop()
  if old:return old
  try:
   p=self.probe()
   if self.s.exists(NAMES['SEAL_INTENT']):return self.recover_locked()
   if p['state']!='UNSEALED':return self.stop(UNKNOWN)
   ready=self.prepare_locked()
   self.chain.publish('SEAL_INTENT',ready,{'ready':ready,'guard_contract':self.chain.context()['guard_contract_sha256']})
   self.chain.intent() # file+directory fsync before the first barrier action
   self.s.inject('before_barrier');self.h.seal();self.s.inject('after_barrier')
   return self.forward(self.probe())
  except Exception:return self.recover_locked()
 def recover_locked(self):
  old=self.prior_stop()
  if old:return old
  try:
   p=self.probe()
   if p['state']=='UNKNOWN':return self.stop(UNKNOWN)
   has_intent=self.s.exists(NAMES['SEAL_INTENT'])
   if not has_intent:
    if p['state']!='UNSEALED' or self.s.exists(NAMES['SEALED']) or self.s.exists(NAMES['POSTSEAL_COMPLETE']):return self.stop(UNKNOWN)
    return self.rollback()
   self.chain.intent()
   if p['state']=='UNSEALED':
    if self.s.exists(NAMES['SEALED']) or self.s.exists(NAMES['POSTSEAL_COMPLETE']):return self.stop(UNKNOWN)
    return self.rollback()
   return self.forward(p)
  except Exception:return self.stop(UNKNOWN)
 def recover(self):
  with self.locked():return self.recover_locked()
 def timeout(self):return self.recover() # Never infer seal from elapsed time.
