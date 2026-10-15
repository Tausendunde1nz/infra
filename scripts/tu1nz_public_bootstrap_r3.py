"""Durable ordering component for the separately authorized R3 Host operator.

NO CLI/SSH/Host dispatcher, signature, R2 call or JSON-to-admission interface.
The operator's authenticated, reviewed adapter must obtain actual observations
and maintain the fences in PUBLIC_WEB_BOOTSTRAP_R3_HOST_PLAN.txt. This module
orders those operations and permanently refuses replay/ambiguous outcomes. Its
isolated fixtures are NOT effective production authority or Host acceptance.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

UNITS=('tu1nz-adult-public-s7.service','tu1nz-adult-public-s8-landing.service',
       'tu1nz-adult-public-s10-wms.service')
STOP=tuple(reversed(UNITS))
TX='public-rights-20261014-1'
MACHINE='a2166d9d5e0815dc5e452be3d01a1356f4d39e2164446274a43cde5afa7d8aae'
OWNER_PLAN='e9ac7f6056c42c5bcc67b9823d4cd65740a5037bae816a10431b0c8635dd6b36'
BOOT='/etc/tu1nz/public-web-bootstrap-r3/20261014-1'
BARRIER='zzzz-tu1nz-bootstrap-r3.conf'
BARRIER_BYTES=('[Unit]\n# R3 start barrier, not a permit/slot. Never create this condition path.\n'
               'ConditionPathExists='+BOOT+'/NEVER-CREATE-START-PERMIT\n').encode()

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
class Denied(RuntimeError):pass
class FlowFailure(Denied):
    def __init__(self,primary,*,abort=(),cleanup=()):
        require(all(type(c) is str and re.fullmatch(r'PUBLIC_BOOTSTRAP_[A-Z0-9_]{1,96}',c)
                    for c in (primary,*abort,*cleanup)),'ERROR_PROVENANCE_SCHEMA_RED')
        self.primary=primary;self.abort=tuple(abort);self.cleanup=tuple(cleanup)
        super().__init__(primary)
def failure_code(error):
    if isinstance(error,(KeyboardInterrupt,SystemExit)):return 'PUBLIC_BOOTSTRAP_INTERRUPTED'
    if isinstance(error,OSError):return 'PUBLIC_BOOTSTRAP_IO_UNCONFIRMED'
    # Deliberately never publish arbitrary adapter exception text.
    return 'PUBLIC_BOOTSTRAP_REQUIREMENT_OR_OPERATION_UNCONFIRMED'
def require(ok,code):
    if not ok:raise Denied('PUBLIC_BOOTSTRAP_'+code)

@dataclass(frozen=True)
class Observation:
    """In-process adapter witness; not a user-supplied JSON permission claim.

    Actual issuer/authenticity/fences are the supervised operator's boundary.
    No production adapter or permission is manufactured by this component.
    """
    transaction: str
    binding: str
    phase: str
    facts: frozenset
    observed_monotonic: float

BASE=frozenset(('authenticated_operator_kernel_manager','exact_host_source_scope',
    'source_bound_prestate_read_witness','prestate_NOT_claimed_backup',
    'other_admin_writer_actors_individually_closed','no_unknown_or_extra_delegation',
    'known_delegation_exactly_three_stop_targets','exact_stop_impact_no_foreign_units',
    'no_queued_or_uncontrolled_activation','current_control_paths_and_own_namespace',
    'bootstrap_barriers_and_quarantine_same_filesystem',
    'separate_exact_R3_bootstrap_host_confirmation'))
QUIET=frozenset(('three_cgroups_empty','no_escaped_or_broker_descendants',
    'no_jobs_or_external_reactivation','other_admin_writer_actors_individually_closed',
    'control_source_prestate_and_barriers_unchanged','persistent_barriers_effective',
    'client_server_intents_hash_linked','no_unknown_authority'))
REQUIRED={
 'pre_stop':BASE,
 'barriers':frozenset(('three_own_create_only_barriers_bound','conditions_false_effective',
                     'parent_profiles_and_boot_objects_bound','no_foreign_reload_delta')),
 'quiet':QUIET,
 'staging_ready':QUIET|{'opt_ancestors_exact_acl_profile','private_space_and_quota',
                        'no_foreign_or_partial_transaction'},
 'staging':QUIET|{'sealed_opt_children_exact_acl_profile','private_space_and_quota',
                  'no_foreign_or_partial_transaction'},
 'backup':QUIET|{'full_units_dropins_inputs_tool_pins_protected_backup','independent_readback',
                 'not_the_pre_stop_read_witness'},
 'restore':QUIET|{'isolated_metadata_content_restore_and_return_rehearsal','no_live_or_DB_restore'},
 'probes':QUIET|{'three_exact_synthetic_probes_passed','installed_kernel_systemd_proof',
                 'owned_probe_cleanup_receipted','no_real_inputs_provider_or_network'},
 'install':QUIET|{'four_exact_unchanged_runtime_artifacts','backup_restore_and_probes_bound',
                  'effective_config_verified_barriers_still_false'},
 'release':frozenset(('all_three_own_barriers_quarantined_exactly','no_foreign_change',
                     'effective_installed_isolation_verified','persistent_journal_protected')),
 'rights':frozenset(('three_actual_functional_invocations','uid_gid_1001_groups_empty',
                    'five_capsets_zero_NNP1_minimal_maps','no_effective_alternate_admin_access',
                    'actual_credentials_data_DB_and_HTTP','old_separate_RED_states_not_lifted')),
 'owner_ready':frozenset(('original_exact_owner_plan_matches','rights_acceptance_current',
                         'all82_file_leases_namespace_FD_mapping_fences','owner120s512FD_bound',
                         'actual_owner_backup_independent_read_restore',
                         'separate_owner_journal_and_intent_unspent')),
 'owner_done':frozenset(('all84_exact_uid_changes_four_root_files_untouched',
                        'all_bytes_mode_gid_ACL_attrs_flags_inodes_preserved',
                        'actual_post_ctimes_and_per_object_ACKs','nginx_read_HTTP_passed',
                        'receipt_and_cleanup_all_fences_no_break','primary_abort_cleanup_separate')),
 'r2_ready':frozenset(('fresh_original_frozen_R2_gates','fresh_actual_same_slot_unspent',
                      'original_R2_release_capsule_target_unchanged','no_new_signature_or_dispatch')),
 'return_request':frozenset(('separate_once_old_operation_return_confirmed','all_prior_effects_classified_no_unknown_jobs',
                     'authenticated_operator_kernel_manager','exact_stop_impact_no_foreign_units',
                     'other_actor_TCB_and_original_function_prerequisites_current','own_barriers_and_journal_bound',
                     'no_foreign_control_config_source_change')),
 'return_before_install':frozenset(('all_three_stopped_and_bound','no_forward_artifact_or_owner_change',
                     'current_all_original_config_source_inputs_match_authenticated_baseline',
                     'other_actor_TCB_and_original_function_prerequisites_current',
                     'own_barriers_and_journal_bound','separate_once_old_operation_return_confirmed')),
 'return_after_install':frozenset(('all_three_stopped_and_bound','no_owner_attempt_or_change',
                     'protected_backup_restore_bound','only_own_four_artifacts_bound_for_quarantine',
                     'other_actor_TCB_and_original_function_prerequisites_current',
                     'own_barriers_and_journal_bound','separate_once_old_operation_return_confirmed')),
 'return_config':frozenset(('exact_original_config_source_inputs_verified_no_foreign_change',
                     'no_forward_artifacts_left','all_three_stopped_and_bound',
                     'own_barriers_and_journal_bound')),
 'return_release':frozenset(('all_three_own_return_barriers_quarantined_exactly',
                     'reload_verified_original_effective_config_no_false_barrier',
                     'no_foreign_change','persistent_journal_protected')),
 'old_function':frozenset(('original_function_and_config_verified','restored_old_authority_security_RED')),
}
for _unit in UNITS:
    REQUIRED['started:'+_unit]=frozenset(('fresh_expected_invocation_cgroup_function',
        'actual_unit_rights_and_required_data_DB_HTTP_or_credentials'))
    REQUIRED['old_started:'+_unit]=frozenset(('fresh_original_unit_invocation_and_function',))

class Journal:
    """Create-only LOCAL operator custody; existing transaction always denies.

    Host bootstrap objects are NOT called protected backups. Before/after every
    operation this client witness is durably sealed. The actual operator also
    needs protected ancestor/name/ACL custody, server mirror and exclusive
    control from the bound plan; parent mode alone is not that entire proof.
    """
    def __init__(self,parent,binding):
        self.parent=Path(parent);self.binding=binding;self.seq=0
        require(re.fullmatch('[a-f0-9]{64}',binding) is not None,'BINDING_RED')
        self.pfd=None;self.fd=None
        try:
            self.pfd=os.open(self.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            s=os.fstat(self.pfd)
            require(s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700,'PRIVATE_CUSTODY_RED')
            require((s.st_dev,s.st_ino)==(os.lstat(self.parent).st_dev,os.lstat(self.parent).st_ino),'CUSTODY_REPLACED')
            try:os.mkdir(TX,0o700,dir_fd=self.pfd)
            except FileExistsError:raise Denied('PUBLIC_BOOTSTRAP_EXISTING_TRANSACTION_NO_REPLAY') from None
            self.fd=os.open(TX,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.pfd)
            self.identity=(os.fstat(self.fd).st_dev,os.fstat(self.fd).st_ino)
            self.write('binding',{'tx':TX,'binding':binding,'owner_plan':OWNER_PLAN,'R2_slot_consumed':False})
        except BaseException:
            self.close()
            raise
    def check(self):
        s=os.stat(TX,dir_fd=self.pfd,follow_symlinks=False)
        require((s.st_dev,s.st_ino)==self.identity,'CUSTODY_REPLACED')
        p=os.lstat(self.parent);a=os.fstat(self.pfd)
        require((p.st_dev,p.st_ino)==(a.st_dev,a.st_ino),'CUSTODY_REPLACED')
    def claim(self):
        self.check()
        try:fd=os.open('flow-claimed',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        except FileExistsError:raise Denied('PUBLIC_BOOTSTRAP_EXISTING_FLOW_NO_REPLAY') from None
        with os.fdopen(fd,'wb') as f:f.write(self.binding.encode());f.flush();os.fsync(f.fileno())
        os.fsync(self.fd);self.check()
    def write(self,kind,value):
        self.check();self.seq+=1
        require(self.seq<=64 and re.fullmatch('[a-z_]+',kind) is not None,'JOURNAL_BOUND')
        raw=canonical({'sequence':self.seq,'kind':kind,'binding':self.binding,'value':value})
        require(len(raw)<=65536,'JOURNAL_RECORD_BOUND')
        fd=os.open(str(self.seq).zfill(3)+'-'+kind+'.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        os.fsync(self.fd);os.fsync(self.pfd);self.check()
    def close(self):
        for name in ('fd','pfd'):
            fd=getattr(self,name,None)
            if fd is not None:os.close(fd);setattr(self,name,None)

class Flow:
    """Stateful supervised sequence, no automatic rollback/retry on any failure."""
    def __init__(self,adapter,journal):
        self.a=adapter;self.j=journal;self.stage='NEW';self.stopped=[]
        self.j.claim()
        self.mutation_started=False;self.install_started=False;self.owner_started=False
        self.return_used=False;self.hold=False;self.last_fault=None
        self.current_action=None;self.current_gate=None
        self.deadline=time.monotonic()+600
    def witness(self,phase):
        self.current_gate=phase
        o=self.a.observe(phase)
        require(type(o) is Observation and o.transaction==TX and o.binding==self.j.binding
                and o.phase==phase,'OBSERVATION_BINDING_RED')
        age=time.monotonic()-o.observed_monotonic
        require(0<=age<=2 and REQUIRED[phase]<=o.facts,'CURRENT_'+phase.upper()+'_GATE_RED')
        return o
    def effect(self,name,unit=None):
        # Lost ACK/interrupt/failure never turns into a repeated request. Leave
        # intent and barriers, let same bounded transaction be classified READONLY.
        self.current_action=name
        require(time.monotonic()<self.deadline,'TRANSACTION_DEADLINE')
        self.j.write('intent',{'action':name,'unit':unit})
        self.mutation_started=True
        limit=min(self.deadline,time.monotonic()+(20 if name in ('stop','return_stop','start','start_old') else 120))
        value=self.a.perform(name,unit,deadline=limit)
        require(time.monotonic()<=limit,'ACTION_DEADLINE_HOLD')
        require(value is not None and value.get('outcome')=='CONFIRMED','ACTION_UNKNOWN_HOLD')
        require(value.get('action')==name and value.get('unit')==unit,'ACTION_BINDING_RED')
        require(set(value)<=frozenset(('action','unit','outcome','cgroup_empty','no_job','proof_sha256')),
                'ACTION_RECEIPT_FIELDS_RED')
        self.j.write('ack',value)
        return value
    def forward(self):
        require(self.stage=='NEW' and not self.hold,'NO_FORWARD_REPLAY')
        try:
            self.witness('pre_stop')
            self.effect('create_persistent_barriers');self.witness('barriers')
            self.stage='STOPPING'
            for unit in STOP:
                r=self.effect('stop',unit)
                require(r.get('cgroup_empty') is True and r.get('no_job') is True,'INCOMPLETE_STOP_HOLD')
                self.stopped.append(unit)
            self.witness('quiet');self.stage='QUIET'
            self.witness('staging_ready')
            for action,phase in (('create_sealed_staging','staging'),('protected_rights_backup','backup'),
                                 ('isolated_restore_rehearsal','restore'),('bounded_synthetic_probes','probes')):
                self.witness('quiet');self.effect(action);self.witness(phase);self.stage=phase.upper()
            self.witness('quiet');self.install_started=True
            self.effect('install_four_artifacts');self.witness('install');self.stage='INSTALLED'
            self.effect('quarantine_own_barriers');self.witness('release')
            for unit in UNITS:
                self.effect('start',unit);self.witness('started:'+unit)
            self.witness('rights');self.stage='RIGHTS_ACCEPTED'
            self.witness('owner_ready');self.owner_started=True
            self.effect('supervised_owner_transaction');self.witness('owner_done')
            self.stage='RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED'
            self.j.write('complete',{'stage':self.stage,'r2_dispatch':False,'slot_consumed':False})
            return self.stage
        except BaseException as e:
            self.hold=True;self.last_fault=type(e).__name__
            primary=e.primary if type(e) is FlowFailure else failure_code(e)
            abort=list(e.abort) if type(e) is FlowFailure else []
            cleanup=list(e.cleanup) if type(e) is FlowFailure else []
            try:
                self.j.write('hold',{'stage':self.stage,'error_type':self.last_fault,
                    'action':self.current_action,'gate':self.current_gate,
                    'primary':primary,'abort':abort,'cleanup':cleanup})
            except BaseException:cleanup.append('PUBLIC_BOOTSTRAP_HOLD_RECORD_PERSISTENCE_RED')
            raise FlowFailure(primary,abort=abort,cleanup=cleanup) from None
    def return_old(self):
        require(self.hold and not self.return_used and not self.owner_started,'RETURN_NOT_ADMITTED')
        # Requires a separate current confirmation and actual fresh proofs; NOT
        # called by forward(). Even failure before stop never assumes old state.
        self.witness('return_request')
        phase='return_after_install' if self.install_started else 'return_before_install'
        self.return_used=True;self.j.write('return_intent',{'phase':phase,'security_result':'RED'})
        try:
            self.effect('establish_return_barriers');self.witness('barriers')
            for unit in STOP:
                r=self.effect('return_stop',unit)
                require(r.get('cgroup_empty') is True and r.get('no_job') is True,'RETURN_INCOMPLETE_STOP_HOLD')
            self.witness(phase)
            self.effect('return_old_configuration',phase);self.witness('return_config')
            self.effect('quarantine_own_return_barriers');self.witness('return_release')
            for unit in UNITS:
                self.effect('start_old',unit);self.witness('old_started:'+unit)
            self.witness('old_function');self.stage='OLD_OPERATION_RESTORED_SECURITY_RED'
            self.j.write('returned',{'stage':self.stage,'r2_eligible':False,'forward_retry':False})
            return self.stage
        except BaseException as e:
            primary=e.primary if type(e) is FlowFailure else failure_code(e)
            abort=list(e.abort) if type(e) is FlowFailure else []
            cleanup=list(e.cleanup) if type(e) is FlowFailure else []
            try:self.j.write('hold',{'stage':'RETURN_UNKNOWN','primary':primary,'abort':abort,'cleanup':cleanup})
            except BaseException:cleanup.append('PUBLIC_BOOTSTRAP_HOLD_RECORD_PERSISTENCE_RED')
            raise FlowFailure(primary,abort=abort,cleanup=cleanup) from None
    def r2_eligibility(self):
        require(self.stage=='RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED' and not self.hold,'R2_NOT_ELIGIBLE')
        self.witness('r2_ready')
        return 'FRESH_FROZEN_R2_GATE_ELIGIBILITY_ONLY_NO_SIGNATURE_OR_DISPATCH'

if __name__=='__main__':
    print(json.dumps({'component':'PUBLIC_BOOTSTRAP_R3_ORDERING_ONLY','host_execution':False,
                      'host_admission':False,'slot_consumed':False,'separate_host_decision_required':True}))
