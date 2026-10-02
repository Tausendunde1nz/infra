"""Durable recovery protocol primitives; no host commands or activation CLI.
A root-owned, single-use ExecStartPre claim is required before main startup.
Time proximity alone NEVER attributes a service instance to a transaction.
Host wiring and independent watchdog deployment are still admission requirements.
"""
import copy,re
UNIT='tu1nz_agentmode.service'
class Refused(RuntimeError):pass

def ident(value,pattern):
 if type(value) is not str or not re.fullmatch(pattern,value):raise Refused('IDENTITY')
 return value

def start_intent(transaction,boot,unit_sha,source_sha,inactive,save):
 ident(transaction,r'tu1nz-privileged-v11-[a-f0-9]{32}');ident(boot,r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
 for x in (unit_sha,source_sha):ident(x,r'[a-f0-9]{64}')
 if type(inactive.get('active')) is not bool or type(inactive.get('pid')) is not int or type(inactive.get('pending_job')) is not bool or type(inactive.get('no_conflicting_lock')) is not bool:raise Refused('PRECONDITION_TYPES')
 if inactive!={'unit':UNIT,'active':False,'pid':0,'pending_job':False,'no_conflicting_lock':True}:raise Refused('INACTIVE_PRECONDITION')
 state={'transaction':transaction,'boot':boot,'unit':UNIT,'unit_sha':unit_sha,'source_sha':source_sha,'status':'START_INTENT'}
 save(copy.deepcopy(state));return state

def claim_before_main(intent,boot,invocation,monotonic_ns,verified,save):
 if intent.get('status')!='START_INTENT' or intent.get('boot')!=boot:raise Refused('START_CLAIM_STATE')
 ident(invocation,r'[a-f0-9]{32}')
 if type(monotonic_ns) is not int or monotonic_ns<0:raise Refused('TIME')
 if any(type(v) is not bool for v in verified.values()):raise Refused('PROOF_TYPES')
 if verified!={'root_owned_unit_and_prologue':True,'unit_and_source_hash_match':True,'transaction_lock_held':True,'single_use_claim_absent':True}:raise Refused('CLAIM_PROOF')
 state=copy.deepcopy(intent);state.update(status='START_CLAIMED',invocation=invocation,claim_ns=monotonic_ns)
 # The host prologue must fail before starting the main process if this write fails.
 save(copy.deepcopy(state));return state

def reconcile_main(claim,current,save):
 expected={'unit','boot','invocation','pid','process_start_ticks','start_monotonic_ns','active'}
 if set(current)!=expected or claim.get('status') not in ('START_CLAIMED','MAIN_BOUND'):raise Refused('RECONCILIATION_INPUT')
 if current['unit']!=UNIT or current['boot']!=claim['boot'] or current['invocation']!=claim['invocation']:raise Refused('FOREIGN_INSTANCE')
 if current['active'] is not True or any(type(current[k]) is not int or current[k]<=0 for k in ('pid','process_start_ticks','start_monotonic_ns')) or current['start_monotonic_ns']<claim['claim_ns']:raise Refused('MAIN_IDENTITY')
 if claim['status']=='MAIN_BOUND':
  for k in ('pid','process_start_ticks','start_monotonic_ns'):
   if claim[k]!=current[k]:raise Refused('FOREIGN_PROCESS')
 state=copy.deepcopy(claim);state.update(status='MAIN_BOUND',**{k:current[k] for k in ('pid','process_start_ticks','start_monotonic_ns')})
 save(copy.deepcopy(state));return state

def owns_current(bound,current):
 return bound.get('status')=='MAIN_BOUND' and current.get('active') is True and all(bound.get(k)==current.get(k) for k in ('unit','boot','invocation','pid','process_start_ticks','start_monotonic_ns'))

class StableHealth:
 def __init__(self,bound):self.bound=copy.deepcopy(bound);self.first=None;self.last=None;self.samples=0;self.failed=False
 def sample(self,now_ns,current,health_ok):
  if self.failed:raise Refused('STABILITY_ALREADY_FAILED')
  if type(now_ns) is not int or now_ns<0 or not owns_current(self.bound,current) or health_ok is not True or (self.last is not None and (now_ns<=self.last or now_ns-self.last>30_000_000_000)):
   self.failed=True;raise Refused('STABILITY_FAILURE')
  if self.first is None:self.first=now_ns
  self.last=now_ns;self.samples+=1
 def complete(self):
  if self.failed or self.first is None or self.last-self.first<660_000_000_000 or self.samples<23:raise Refused('STABILITY_TOO_SHORT')
  return True

def provider_handoff(state,proofs,save):
 if set(state)!={'phase','forward_only'}:raise Refused('HANDOFF_STATE_FIELDS')
 if state.get('phase')!='CONSUMERS_QUIESCED' or state.get('forward_only') is not False:raise Refused('ROTATION_PHASE')
 if any(type(v) is not bool for v in proofs.values()):raise Refused('PROOF_TYPES')
 if proofs!={'backup_verified':True,'consumers_confirmed_stopped':True,'independent_watchdog_verified':True,'protected_input_ready':True,'provider_route_confirmed':True}:raise Refused('PROVIDER_PREFLIGHT')
 next_state=copy.deepcopy(state);next_state.update(phase='PROVIDER_HANDOFF_INTENT',forward_only=True)
 # Persist BEFORE allowing a human/provider action; crash after revoke cannot reopen rollback.
 save(copy.deepcopy(next_state));return next_state

def recovery_decision(state,new_credential_verified=False):
 if type(state.get('forward_only')) is not bool:raise Refused('RECOVERY_STATE')
 if state['forward_only']:
  return 'FORWARD_REPAIR_NEW_CREDENTIAL' if new_credential_verified is True else 'SECURED_STOP_NO_OLD_CREDENTIAL'
 if state.get('phase') in ('PROVIDER_HANDOFF_INTENT','PROVIDER_REPLACED','NEW_CREDENTIAL_INSTALLED'):raise Refused('INCONSISTENT_IRREVERSIBLE_MARKER')
 if state.get('phase') not in ('PRECHECK_ONLY','ROOT_STARTED','BACKUP_VERIFIED','ADAPTERS_INSTALLED','CONSUMERS_QUIESCED'):raise Refused('UNKNOWN_REVERSIBLE_PHASE')
 return 'ROLLBACK_VERIFIED_OWNED_CHANGES'
