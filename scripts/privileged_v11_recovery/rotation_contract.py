"""Offline admission/state contract, not a live rotation implementation.
No provider request, secret read, service call, or activation entrypoint.
"""
from dataclasses import dataclass, field

REQUIRED={'consumer_inventory_complete','protected_locations_verified','baseline_matches',
 'backup_verified','watchdog_offline_passed','recovery_offline_passed',
 'new_secret_input_protected','provider_replacement_semantics_confirmed',
 'all_consumers_quiesced','agentmode_restart_contract_passed',
 'production_adapters_passed','fresh_client_checks_prepared'}
class Refused(ValueError):pass

@dataclass
class Rotation:
 state:str='PRECHECK_ONLY'
 irreversible:bool=False
 events:list=field(default_factory=list)
 def advance(self,event,proofs=None):
  transitions={'PRECHECK_ONLY':('prepare','PREPARED'),
   'PREPARED':('provider_replaced','PROVIDER_REPLACED'),
   'PROVIDER_REPLACED':('install_new_secret','SECRET_INSTALLED'),
   'SECRET_INSTALLED':('verify_new_identity_and_permissions','SECRET_VERIFIED'),
   'SECRET_VERIFIED':('reload_fixed_consumers','CONSUMERS_RELOADED'),
   'CONSUMERS_RELOADED':('verify_function_and_stability','FUNCTION_VERIFIED'),
   'FUNCTION_VERIFIED':('verify_old_rejected_and_rescan','COMPLETE')}
  if self.state not in transitions or transitions[self.state][0]!=event:raise Refused('PHASE_ORDER')
  if event=='prepare':
   if not isinstance(proofs,dict) or set(proofs)!=REQUIRED or any(v is not True for v in proofs.values()):raise Refused('PREFLIGHT_INCOMPLETE')
  if event=='provider_replaced':self.irreversible=True
  self.events.append(event);self.state=transitions[self.state][1]
 def fail(self):
  if self.state=='COMPLETE':raise Refused('COMPLETED_TRANSACTION')
  self.state='SECURED_STOP_NEW_CREDENTIAL_REQUIRED' if self.irreversible else 'ABORTED_NO_ROTATION'
  return self.state
 def rollback_credential(self,exposed):
  if exposed:raise Refused('EXPOSED_CREDENTIAL_REACTIVATION_FORBIDDEN')
  raise Refused('RECOVERY_REQUIRES_VERIFIED_NEW_CREDENTIAL')

def restart_admission(facts):
 required={'no_instance','no_lock_conflict','no_lease_conflict','no_partial_transaction',
 'unit_and_config_bound','source_bound','permissions_bound','dependencies_available',
 'detached_head_pinned','docs_mutation_disabled','notification_state_preserved',
 'no_approval_consumer','start_health_stop_tests_passed','rollback_tests_passed'}
 if set(facts)!=required or any(v is not True for v in facts.values()):raise Refused('RESTART_NOT_READY')
 return {'restart_authorized':False,'offline_contract_passed':True}
