"""Guard completion attestation v1. Root-owned durable data, never commands.
The producer requires the actual Guard state chain and independently rechecks
artifacts and the closed outer fence. An attestation is unusable until its
separate fsync commit exists. Admission is single-use; resume is exact-bound.
"""
import re,time,os
from anchor import Refused,encode,digest,parse,pin,tx
CONTROL='2281b2b397c017bc370ba108eab3dc00c989eaa5'
TREE='3d52fe0898238e1132d8947a7e171d8086982170'
BOOT=re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
FIELDS={'schema','format','transaction','guard_boot','recovery_boot','recovery_generation','generation','guard_version','guard_sha256','guard_contract_sha256','control_commit','control_tree','infra_basis','activation_manifest_sha256','artifacts','artifact_manifest_sha256','base_sha256','worker_pins'}
def context_valid(c,store):
 if type(c)!=dict or set(c)!=FIELDS or c['schema']!=1 or c['format']!='GUARD_COMPLETION_V1':raise Refused('ATTEST_CONTEXT_SCHEMA')
 if not tx(c['transaction']) or not BOOT.fullmatch(c['guard_boot']) or not BOOT.fullmatch(c['recovery_boot']):raise Refused('ATTEST_TRANSACTION_BOOT')
 for k in ('generation','recovery_generation'):
  if type(c[k])!=int or not 0<=c[k]<1000000:raise Refused('ATTEST_GENERATION')
 if c['control_commit']!=CONTROL or c['control_tree']!=TREE or not re.fullmatch('[0-9a-f]{40}',c['infra_basis']):raise Refused('ATTEST_BASELINE')
 if not re.fullmatch('[A-Za-z0-9_.-]{1,64}',c['guard_version']):raise Refused('ATTEST_GUARD_VERSION')
 for k in ('guard_sha256','guard_contract_sha256','activation_manifest_sha256','artifact_manifest_sha256','base_sha256'):
  if not pin(c[k]):raise Refused('ATTEST_PIN')
 if type(c['artifacts'])!=dict or not c['artifacts'] or len(c['artifacts'])>256 or any(not re.fullmatch('[A-Za-z0-9_.-]{1,128}',k) or not pin(v) for k,v in c['artifacts'].items()):raise Refused('ATTEST_ARTIFACTS')
 if c['artifacts'].get('guard')!=c['guard_sha256'] or c['artifact_manifest_sha256']!=digest(encode(c['artifacts'])):raise Refused('ATTEST_MANIFEST')
 b=store.base()
 if c['base_sha256']!=digest(store.read('base.json')) or c['worker_pins']!=b['workers']:raise Refused('ATTEST_RECOVERY_BASE')
 return True
class Gate:
 def __init__(self,store):self.s=store
 def bind(self,context):
  context_valid(context,self.s)
  with self.s.locked():
   if self.s.exists('guard-binding.json'):
    if parse(self.s.read('guard-binding.json'))!=context:raise Refused('ATTEST_BINDING_DRIFT')
   else:self.s.write('guard-binding.json',encode(context))
  return digest(encode(context))
 def context(self):
  c=parse(self.s.read('guard-binding.json'));context_valid(c,self.s);return c
 def names(self,c):return 'attestation-%06d.json'%c['generation'],'attestation-commit-%06d.json'%c['generation']
 def publish(self,guard,verifier):
  # Fixed lock order: anchor then Guard; no Guard coordinator executes while
  # the root producer validates the terminal state and publishes its receipt.
  with self.s.locked(),guard.locked():
   c=self.context();self.s.close_fence();verifier.confirm_closed()
   state=guard.current()
   if state['phase']!='COMPLETED' or state['sealed'] is not True or state['proof']!={'final_checks_passed':True}:raise Refused('GUARD_NOT_COMPLETE')
   b=state['binding']
   if b['transaction']!=c['transaction'] or b['boot']!=c['guard_boot'] or b['contract_sha256']!=c['guard_contract_sha256']:raise Refused('GUARD_BINDING')
   previous=guard.read('state-%06d.json'%(state['seq']-1))
   if previous['phase']!='NEW_CONSUMER_VERIFIED' or previous['proof'].get('consumer_sha256')!=c['guard_sha256']:raise Refused('GUARD_ARTIFACT_STATE')
   verifier.verify_completed(c,state)
   self.s.inject('after_guard_complete')
   row={'schema':1,'format':'GUARD_COMPLETION_V1','context_sha256':digest(encode(c)),'guard_record_sha256':state['record_sha256'],'terminal':'COMPLETED','completion_phase':'GUARD_COMPLETED','allowed_next':'PHASE1_BOOTSTRAP','fence':'CLOSED','starts':'CLOSED','generation':c['generation'],'recovery_generation':c['recovery_generation'],'creation':'AFTER_VERIFIED_GUARD_TERMINAL','synchronization':'REQUIRES_SEPARATE_FSYNC_COMMIT'}
   name,commit=self.names(c)
   if self.s.exists(name):
    if parse(self.s.read(name))!=row:raise Refused('ATTEST_EXISTING_DRIFT')
   else:self.s.write(name,encode(row))
   self.s.inject('before_attest_commit')
   proof={'schema':1,'attestation_sha256':digest(encode(row)),'context_sha256':digest(encode(c)),'file_fsync_completed':True,'parent_fsync_completed':True}
   # write() has already completed file and directory fsync for the attestation.
   # Recovery of a publication-before-fsync crash revalidates Guard first.
   f=self.s.open(name,0o400)
   try:os.fsync(f)
   finally:os.close(f)
   os.fsync(self.s.fd)
   if self.s.exists(commit):
    if parse(self.s.read(commit))!=proof:raise Refused('ATTEST_COMMIT_DRIFT')
   else:self.s.write(commit,encode(proof))
   return digest(encode(row))
 def validate(self,expected,boot,recovery_generation):
  c=self.context()
  if c!=expected or c['recovery_boot']!=boot or c['recovery_generation']!=recovery_generation:raise Refused('ATTEST_STALE_OR_CONTEXT')
  name,commit=self.names(c);r=parse(self.s.read(name));p=parse(self.s.read(commit))
  fields={'schema','format','context_sha256','guard_record_sha256','terminal','completion_phase','allowed_next','fence','starts','generation','recovery_generation','creation','synchronization'}
  if set(r)!=fields or r['schema']!=1 or r['format']!='GUARD_COMPLETION_V1' or r['context_sha256']!=digest(encode(c)) or not pin(r['guard_record_sha256']) or r['terminal']!='COMPLETED' or r['completion_phase']!='GUARD_COMPLETED' or r['allowed_next']!='PHASE1_BOOTSTRAP' or r['fence']!='CLOSED' or r['starts']!='CLOSED' or r['generation']!=c['generation'] or r['recovery_generation']!=c['recovery_generation'] or r['creation']!='AFTER_VERIFIED_GUARD_TERMINAL' or r['synchronization']!='REQUIRES_SEPARATE_FSYNC_COMMIT':raise Refused('ATTEST_SEMANTICS')
  if p!={'schema':1,'attestation_sha256':digest(encode(r)),'context_sha256':digest(encode(c)),'file_fsync_completed':True,'parent_fsync_completed':True}:raise Refused('ATTEST_NOT_SYNCED')
  if not self.s.closed() or self.s.exists('stop.json'):raise Refused('ATTEST_FENCE_OR_STOP')
  return digest(encode(r))
 def admit(self,expected,boot,recovery_generation,phase_manifest_sha256,resume=False):
  with self.s.locked():return self.admit_locked(expected,boot,recovery_generation,phase_manifest_sha256,resume)
 def admit_locked(self,expected,boot,recovery_generation,phase_manifest_sha256,resume=False):
  # Only the fixed Bootstrap caller already holding the anchor lock uses this.
  if not pin(phase_manifest_sha256):raise Refused('ADMISSION_PHASE_PIN')
  want=self.validate(expected,boot,recovery_generation)
  self.s.inject('before_bootstrap_release')
  name='attestation-use-%06d.json'%expected['generation']
  row={'schema':1,'transaction':expected['transaction'],'attestation_sha256':want,'phase_manifest_sha256':phase_manifest_sha256,'generation':expected['generation'],'recovery_generation':recovery_generation}
  if self.s.exists(name):
   if not resume or parse(self.s.read(name))!=row:raise Refused('ATTEST_REPLAY')
  elif resume:raise Refused('ATTEST_NO_PRIOR_ADMISSION')
  else:self.s.write(name,encode(row))
  return row
class AttestedCoordinator:
 """The existing Guard coordinator remains the only owner of its state chain.
This bridge never fabricates COMPLETED or silently advances a sealed state.
"""
 def __init__(self,coordinator,gate,verifier):self.coordinator=coordinator;self.gate=gate;self.verifier=verifier
 def run(self):
  result=self.coordinator.run()
  current=self.coordinator.store.current()
  if current['phase']!='COMPLETED':raise Refused('GUARD_COORDINATOR_NONTERMINAL')
  return self.gate.publish(self.coordinator.store,self.verifier)
