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
CUSTODY_PARENT=Path('/Users/daniel/Developer/tu1nz/service-isolation-lighting-night-20261013/host-operator-intents')
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
 'old_function':frozenset(('original_function_and_config_verified','restored_old_authority_security_RED')),
}
for _unit in UNITS:
    REQUIRED['return_state:'+_unit]=frozenset(('fresh_exact_unit_invocation_cgroup_classified',
        'all_prior_effects_classified_no_pending_job','own_persistent_barrier_effective'))
    REQUIRED['release:'+_unit]=frozenset(('only_this_own_barrier_quarantined_exactly',
        'downstream_barriers_still_effective','prior_unit_function_durably_accepted',
        'effective_installed_isolation_verified','no_foreign_change','persistent_journal_protected'))
    REQUIRED['return_release:'+_unit]=frozenset(('only_this_own_return_barrier_quarantined_exactly',
        'downstream_barriers_still_effective','prior_old_unit_function_durably_accepted',
        'reload_verified_original_effective_config_no_false_barrier_for_this_unit',
        'no_foreign_change','persistent_journal_protected'))
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
        require(self.parent==CUSTODY_PARENT and self.parent.resolve(strict=True)==CUSTODY_PARENT,
                'FIXED_CUSTODY_PARENT_RED')
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
        require(self.seq<=128 and re.fullmatch('[a-z_]+',kind) is not None,'JOURNAL_BOUND')
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
    required = REQUIRED
    twenty_second_actions = frozenset(('stop', 'return_stop', 'start', 'start_old'))
    def __init__(self,adapter,journal):
        self.a=adapter;self.j=journal;self.stage='NEW';self.stopped=[]
        self.j.claim()
        self.mutation_started=False;self.install_started=False;self.owner_started=False
        self.return_used=False;self.hold=False;self.last_fault=None
        self.current_action=None;self.current_gate=None
        self.deadline=time.monotonic()+600
    def witness(self,phase):
        self.current_gate=phase
        require(time.monotonic()<self.deadline,'OBSERVATION_DEADLINE_HOLD')
        o=self.a.observe(phase,deadline=self.deadline)
        require(time.monotonic()<=self.deadline,'OBSERVATION_DEADLINE_HOLD')
        require(type(o) is Observation and o.transaction==TX and o.binding==self.j.binding
                and o.phase==phase,'OBSERVATION_BINDING_RED')
        age=time.monotonic()-o.observed_monotonic
        require(0<=age<=2 and self.required[phase]<=o.facts,'CURRENT_'+phase.upper()+'_GATE_RED')
        self.j.write('observation',{'phase':phase,'facts_sha256':digest(canonical(sorted(o.facts))),
                                   'observed_monotonic':o.observed_monotonic})
        require(time.monotonic()<=self.deadline,'OBSERVATION_PERSISTENCE_DEADLINE_HOLD')
        return o
    def effect(self,name,unit=None):
        # Lost ACK/interrupt/failure never turns into a repeated request. Leave
        # intent and barriers, let same bounded transaction be classified READONLY.
        self.current_action=name
        require(time.monotonic()<self.deadline,'TRANSACTION_DEADLINE')
        self.j.write('intent',{'action':name,'unit':unit})
        self.mutation_started=True
        require(time.monotonic()<self.deadline,'INTENT_PERSISTENCE_DEADLINE_HOLD')
        limit=min(self.deadline,time.monotonic()+(20 if name in self.twenty_second_actions else 120))
        value=self.a.perform(name,unit,deadline=limit)
        require(time.monotonic()<=limit,'ACTION_DEADLINE_HOLD')
        require(value is not None and value.get('outcome')=='CONFIRMED','ACTION_UNKNOWN_HOLD')
        require(value.get('action')==name and value.get('unit')==unit,'ACTION_BINDING_RED')
        require(set(value)<=frozenset(('action','unit','outcome','cgroup_empty','no_job','proof_sha256')),
                'ACTION_RECEIPT_FIELDS_RED')
        self.j.write('ack',value)
        return value
    def prepare_before_barriers(self):
        pass  # historical ordering; R4 overrides this explicit boundary
    def prepare_after_quiet(self):
        self.witness('staging_ready')
        self.witness('quiet');self.effect('create_sealed_staging');self.witness('staging')
        self.stage='STAGING'
    def forward(self):
        require(self.stage=='NEW' and not self.hold,'NO_FORWARD_REPLAY')
        try:
            self.witness('pre_stop')
            self.prepare_before_barriers()
            self.effect('create_persistent_barriers');self.witness('barriers')
            self.stage='STOPPING'
            for unit in STOP:
                r=self.effect('stop',unit)
                require(r.get('cgroup_empty') is True and r.get('no_job') is True,'INCOMPLETE_STOP_HOLD')
                self.stopped.append(unit)
            self.witness('quiet');self.stage='QUIET'
            self.prepare_after_quiet()
            for action,phase in (('protected_rights_backup','backup'),
                                 ('isolated_restore_rehearsal','restore'),('bounded_synthetic_probes','probes')):
                self.witness('quiet');self.effect(action);self.witness(phase);self.stage=phase.upper()
            self.witness('quiet');self.install_started=True
            self.effect('install_four_artifacts');self.witness('install');self.stage='INSTALLED'
            for unit in UNITS:
                self.effect('quarantine_own_barrier',unit);self.witness('release:'+unit)
                self.effect('start',unit);self.witness('started:'+unit)
            self.witness('rights');self.stage='RIGHTS_ACCEPTED'
            self.witness('owner_ready');self.owner_started=True
            self.effect('supervised_owner_transaction');self.witness('owner_done')
            self.stage='RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED'
            self.j.write('complete',{'stage':self.stage,'r2_dispatch':False,'slot_consumed':False})
            require(time.monotonic()<=self.deadline,'COMPLETION_PERSISTENCE_DEADLINE_HOLD')
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
        phase='return_after_install' if self.install_started else 'return_before_install'
        self.return_used=True
        try:
            self.j.write('return_intent',{'phase':phase,'security_result':'RED'})
            self.witness('return_request')
            self.effect('establish_return_barriers');self.witness('barriers')
            for unit in STOP:
                o=self.witness('return_state:'+unit)
                stopped='currently_stopped_cgroup_empty' in o.facts
                active='currently_active_requires_single_return_stop' in o.facts
                require(stopped!=active,'RETURN_STATE_AMBIGUOUS_HOLD')
                if active:
                    r=self.effect('return_stop',unit)
                    require(r.get('cgroup_empty') is True and r.get('no_job') is True,'RETURN_INCOMPLETE_STOP_HOLD')
            self.witness(phase)
            self.effect('return_old_configuration',phase);self.witness('return_config')
            for unit in UNITS:
                self.effect('quarantine_own_return_barrier',unit);self.witness('return_release:'+unit)
                self.effect('start_old',unit);self.witness('old_started:'+unit)
            self.witness('old_function');self.stage='OLD_OPERATION_RESTORED_SECURITY_RED'
            self.j.write('returned',{'stage':self.stage,'r2_eligible':False,'forward_retry':False})
            require(time.monotonic()<=self.deadline,'RETURN_PERSISTENCE_DEADLINE_HOLD')
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

class MaintenanceFlow(Flow):
    """The sole R4 original order; all effects still use the durable Flow API.

    No recovery or old-runtime return dispatch is implicit in an exception.
    The outer session's earlier 600s deadline includes transport/admission.
    """
    required = {**REQUIRED,
        **{'started:'+u: REQUIRED['started:'+u] | {'current_no_start_limit_before_request'} for u in UNITS},
        'owner_ready': REQUIRED['owner_ready'] | {'first_owner_marker_two_custodies_same_window'},
        'prepared': frozenset((
        'ready_two_custodies', 'full_runtime_identity_digest', 'ten_complete_candidates',
        'prepared_external_dependencies', 'old_runtime_not_activated',
        'private_roots_and_exclusive_lock', 'native_after_ready_budget_remaining'))}

    def __init__(self, adapter, journal):
        super().__init__(adapter, journal)
        self.deadline = min(self.deadline, adapter.deadline)

    def prepare_before_barriers(self):
        self.stage = 'PREPARING'
        self.effect('prepare_runtime_bundle'); self.witness('prepared')
        self.stage = 'PREPARED'

    def prepare_after_quiet(self):
        # These exact roots were created before READY. The actual adapter
        # freshly checks quiet/space/profiles; no absence or backup is claimed.
        self.witness('staging'); self.stage = 'STAGING'

    def return_old(self):
        raise Denied('PUBLIC_BOOTSTRAP_MAINTENANCE_OLD_RUNTIME_RETURN_FORBIDDEN')


RECOVERY_BASE = frozenset((
    'same_original_host_boot_source_scope', 'original_failed_hold_preserved',
    'both_original_chains_and_ready_current', 'one_recovery_entry_both_custodies',
    'old_operator_helpers_jobs_gone', 'exclusive_same_transaction_lock',
    'fresh_current_authority_writer_and_data_admission', 'owner_admission_and_claims_unspent',
    'full_runtime_identity_digest_current', 'one_recovery_600s_including_cleanup'))
RECOVERY_UNIT = frozenset(('current_unit_job_and_cgroup', 'current_effective_config',
    'exact_own_barrier_place', 'prior_invocation_and_restart_counter_preserved',
    'no_foreign_dependency_effect', 'current_relevant_authority'))


class RecoveryFlow(Flow):
    """One finite F1–F4 continuation under its own already-consumed entry.

    Fresh in-process observations from RecoveryAdapter select the state.
    A journal JSON flag is never an admission. Original intents/ACKs/HOLD
    remain untouched. Neither forward(), return_old() nor a second recover()
    can restart this flow after an exception or an unconfirmed effect.
    """
    required = {**REQUIRED,
        **{'started:'+u: REQUIRED['started:'+u] | {'current_no_start_limit_before_request'} for u in UNITS},
        'owner_ready': REQUIRED['owner_ready'] | {'first_owner_marker_two_custodies_same_window'},
        'recovery_admitted': RECOVERY_BASE,
        **{'recovery_state:'+u: RECOVERY_UNIT for u in UNITS},
        **{'recovery_active:'+u: frozenset(('existing_new_invocation_freshly_accepted',
            'actual_rights_data_DB_HTTP', 'no_start_or_restart_performed')) for u in UNITS}}
    twenty_second_actions = Flow.twenty_second_actions | {'recovery_stop', 'recovery_start'}

    def __init__(self, adapter, journal):
        super().__init__(adapter, journal)
        self.deadline = min(self.deadline, adapter.deadline)
        self.recovery_used = False; self.in_f4 = False

    def forward(self):
        raise Denied('PUBLIC_BOOTSTRAP_RECOVERY_NOT_ORIGINAL_FORWARD')

    def return_old(self):
        raise Denied('PUBLIC_BOOTSTRAP_RECOVERY_OLD_RUNTIME_RETURN_FORBIDDEN')

    def recover(self):
        require(not self.recovery_used and self.stage == 'NEW' and not self.hold, 'NO_RECOVERY_REPLAY')
        self.recovery_used = True  # before admission; failure spends this entry
        try:
            observed = self.witness('recovery_admitted')
            states = observed.facts & {'F1', 'F2', 'F3', 'F4'}
            require(len(states) == 1, 'RECOVERY_STATE_NOT_UNIQUE')
            state = next(iter(states)); self.stage = state
            if state != 'F1':
                # A completed rename can precede a lost reload ACK. Only the
                # exact own disk/loaded delta may be reconciled; the adapter
                # skips daemon-reload when effective configuration is current.
                self.effect('recovery_reconcile_config')
            if state == 'F1':
                self.effect('recovery_complete_barriers'); self.witness('barriers')
                for unit in STOP:
                    current = self.witness('recovery_state:'+unit)
                    choices = current.facts & {'known_old_active', 'empty_inactive', 'empty_terminal_failed'}
                    require(len(choices) == 1, 'RECOVERY_OLD_STOP_STATE_UNKNOWN')
                    if 'known_old_active' in choices:
                        value = self.effect('recovery_stop', unit)
                        require(value.get('cgroup_empty') is True and value.get('no_job') is True,
                                'RECOVERY_INCOMPLETE_STOP')
                    self.stopped.append(unit)
                self.witness('quiet'); self.stage = state = 'F2'
            if state == 'F2':
                self.witness('quiet')
                self.effect('recovery_private_backup'); self.witness('backup')
                self.effect('recovery_private_restore'); self.witness('restore')
                self.effect('recovery_unused_or_verified_probes'); self.witness('probes')
                self.stage = state = 'F3'
            if state == 'F3':
                # For direct F3 admission the adapter must freshly validate
                # complete prior backup/restore/probe receipts and cleanup.
                self.witness('quiet'); self.witness('backup'); self.witness('restore'); self.witness('probes')
                self.install_started = True
                self.effect('recovery_publish_assets'); self.witness('install')
                self.stage = state = 'F4'
            require(state == 'F4', 'RECOVERY_NO_STATE_TRANSITION')
            self.in_f4 = True
            for unit in UNITS:
                current = self.witness('recovery_state:'+unit)
                choices = current.facts & {'known_new_active', 'empty_inactive', 'empty_terminal_failed'}
                require(len(choices) == 1, 'RECOVERY_NEW_START_STATE_UNKNOWN')
                if 'known_new_active' in choices:
                    self.witness('recovery_active:'+unit)
                else:
                    self.effect('recovery_release_barrier', unit); self.witness('release:'+unit)
                    self.effect('recovery_start', unit); self.witness('started:'+unit)
            self.witness('rights'); self.stage = 'RECOVERY_RIGHTS_ACCEPTED'
            # K6 starts the one owner window before its durable entry marker.
            # Adapter checks FULL remaining120s and all unused claims first.
            self.witness('owner_ready'); self.owner_started = True
            self.effect('supervised_owner_transaction'); self.witness('owner_done')
            self.stage = 'RECOVERY_RIGHTS_OWNER_RECEIPTED_PENDING_OPERATOR_CLEANUP'
            self.j.write('complete', {'stage': self.stage, 'original': 'FAILED_HOLD',
                'final_host_acceptance': False, 'r2_dispatch': False, 'slot_consumed': False})
            require(time.monotonic() <= self.deadline, 'RECOVERY_COMPLETION_PERSISTENCE_DEADLINE')
            return self.stage
        except BaseException as error:
            self.hold = True; self.last_fault = type(error).__name__
            primary = error.primary if type(error) is FlowFailure else failure_code(error)
            abort = list(error.abort) if type(error) is FlowFailure else []
            cleanup = list(error.cleanup) if type(error) is FlowFailure else []
            try:
                self.j.write('hold', {'stage': self.stage, 'original': 'FAILED_HOLD',
                    'action': self.current_action, 'gate': self.current_gate,
                    'primary': primary, 'abort': abort, 'cleanup': cleanup})
            except BaseException:
                cleanup.append('PUBLIC_BOOTSTRAP_RECOVERY_HOLD_RECORD_UNCONFIRMED')
            # Only the separately admitted, finite terminal F4 action may run
            # here. It rechecks channel/fences/known identities/time/NO OWNER
            # itself; it cannot retry a failed forward action or start again.
            if self.in_f4 and not self.owner_started and getattr(self.a, 'owner_admission_started', True) is False:
                try:self.a.hold_known_new_units(deadline=self.deadline)
                except BaseException as terminal:
                    abort.append(terminal.primary if type(terminal) is FlowFailure else
                                 'PUBLIC_BOOTSTRAP_RECOVERY_TERMINAL_STOP_UNCONFIRMED')
            raise FlowFailure(primary, abort=abort, cleanup=cleanup) from None


if __name__=='__main__':
    print(json.dumps({'component':'PUBLIC_BOOTSTRAP_R3_ORDERING_ONLY','host_execution':False,
                      'host_admission':False,'slot_consumed':False,'separate_host_decision_required':True}))
