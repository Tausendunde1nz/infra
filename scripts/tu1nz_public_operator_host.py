"""Finite production implementation of the unchanged R3 ordering boundary.

No CLI at import, no facts deserialized into admission, no automatic return.
The authenticated coordinator supplies code, exact expected baselines and a
live durable channel. All effects are bounded by that same surviving process.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat
import signal
import ctypes
import math
import time

import tu1nz_public_operator_io as io
from tu1nz_public_operator_fs import Paths, Backup
from tu1nz_public_operator_observe import Authority, command, process, starttime, initial_profile, UNITS
from tu1nz_public_operator_probes import Probes

STAGING = '/opt/tu1nz_repos/public-web-isolation-r1/20261014-1'
LIGHTING = '/opt/tu1nz_repos/lighting-halloween-r1/20261014-1'
HELPER = '/usr/local/bin/tu1nz_public_web_isolate_r1.py'
DROPIN = 'zz-public-isolation-r1.conf'
ASSET_NAMES = ('dropin_s7', 'dropin_s8_landing', 'dropin_wms')


class Adapter:
    authority_type = Authority
    def __init__(self, source, baseline, plan_raw, channel, binding, *, deadline):
        self.source, self.r = source, source.load('r3')
        self.channel, self.binding, self.deadline = channel, binding, deadline
        io.require(io.sha(plan_raw) == self.r.OWNER_PLAN, 'ORIGINAL_OWNER_PLAN_REQUIRED')
        self.plan_raw = plan_raw
        self.p = Paths.__new__(Paths)
        self.p.__init__(source.load('entry'), deadline=deadline)
        self.a = self.authority_type.__new__(self.authority_type)
        self.a.__init__(baseline, self.p, channel, machine=self.r.MACHINE, deadline=deadline)
        self.initialize_operation_state()
        # Every original unit/drop-in/input/tool must be an exact expected source
        # object, not an object discovered and silently blessed during this run.
        required = {p for v in baseline['unit_files'].values() for p in [v['fragment'], *v['dropins']]}
        io.require(required <= set(baseline['files']) and not set(self.artifacts) & set(baseline['files']),
                   'ORIGINAL_CONFIG_SET_OR_FORWARD_ABSENCE')
        self.pre_stop()
        self.preparing = False; self.old_accepted.clear()

    def initialize_operation_state(self):
        """Empty local bookkeeping only, no authority, claim or observation."""
        self.barriers = {}; self.return_barriers = {}; self.installed = {}
        self.barrier_places = {}; self.barrier_history = []
        self.accepted = {}; self.old_accepted = {}; self.started = {}; self.start_requested = set()
        self.old_started = {}; self.old_start_requested = set(); self.stop_requested = set()
        self.backup = None; self.backup_hash = None; self.restore_hash = None
        self.probe_hash = None; self.probes = None; self.owner = None; self.owner_result = None
        self.pending = None; self.failed = False; self.returning = False; self.original_restored = False
        self.preparing = True; self.owner_admission_started = False
        self.created = set(); self.absence_prefixes = set(); self.read_witness = None
        self.artifacts = {HELPER: ('runtime', 0o555)}
        self.artifacts.update({self.dropdir(u)+'/'+DROPIN: (n, 0o644) for u, n in zip(UNITS, ASSET_NAMES)})

    @staticmethod
    def dropdir(unit):
        return '/etc/systemd/system/'+unit+'.d'

    def now(self):
        io.require(time.monotonic() < min(self.deadline, self.channel.ceiling), 'TRANSACTION_DEADLINE')

    def absent(self, path):
        # Exact absence with all existing ancestors held; no mkdir during read.
        p = PurePosixPath(path)
        while not os.path.lexists(str(p.parent)):
            p = p.parent
        self.p.absent(str(p))
        self.absence_prefixes.add(str(p))

    def directory(self, path, mode=0o700):
        fd = self.p.create_directory(path, mode); self.created.add(path)
        return fd

    def parent(self, path, mode=0o700):
        if os.path.lexists(path):
            io.require(path not in self.absence_prefixes or path in self.created,
                       'FOREIGN_NEW_PARENT_NO_ADOPTION')
            return self.p.get(path)
        self.parent(str(PurePosixPath(path).parent), mode)
        return self.directory(path, mode)

    def pre_stop(self):
        self.a.check(stop_only=True)
        rollback_device = os.fstat(self.p.get('/opt/tu1nz_repos')).st_dev
        for parent in ('/usr/local/bin', '/etc/systemd/system'):
            io.require(os.fstat(self.p.get(parent)).st_dev == rollback_device,
                       'FOUR_ARTIFACT_QUARANTINE_DEVICE')
        for path in (self.r.BOOT, STAGING, LIGHTING, *self.artifacts):
            self.absent(path)
        for unit in UNITS:
            self.absent(self.dropdir(unit)+'/'+self.r.BARRIER)
            parent = PurePosixPath(self.dropdir(unit)).parent
            self.p.get(str(parent))
            io.require(os.fstat(self.p.get(str(parent))).st_dev ==
                       os.fstat(self.p.get('/etc/tu1nz')).st_dev, 'BARRIER_QUARANTINE_DEVICE')
        site_digest = self.site_read_witness()
        self.channel.http(self.a.b['http']['lighting'])
        self.function_all(old=True)
        self.read_witness = {'boot': self.a.b['boot_id'], 'files': self.a.initial,
                             'targets': self.a.targets, 'units': self.a.initial_units,
                             'site_read_witness_sha256': site_digest,
                             'runtime_files_sha256': self.a.runtime.digest,
                             'application_reference': io.application_coordinates(
                                 self.a.b['source_release']['runtime_reference']),
                             'application_host_git_metadata': 'NOT_CHECKED_BY_THIS_OPERATOR',
                             'kind': 'READ_WITNESS_NOT_BACKUP'}
        self.a.check(stop_only=True)

    def site_read_witness(self):
        guard = self.source.load('guard'); plan = io.parse(self.plan_raw)
        expected = plan['capture']['objects']; directories = {}; observed = {}
        parent = self.p.get('/var/www')
        try:
            directories['.'] = os.open('lighting.tu1nz.com', os.O_RDONLY | os.O_DIRECTORY |
                                       os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            for rel in sorted(expected, key=lambda r: (len(PurePosixPath(r).parts), r)):
                if rel != '.':
                    path = PurePosixPath(rel)
                    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                                 os.O_CLOEXEC | os.O_NOATIME, dir_fd=directories[str(path.parent)])
                    if expected[rel]['metadata']['type'] == stat.S_IFDIR: directories[rel] = fd
                else: fd = directories['.']
                try: observed[rel] = guard.observe_fd(fd)
                finally:
                    if rel not in directories: os.close(fd)
            io.require(observed == expected, 'CURRENT_SITE_NOT_ORIGINAL_OWNER_PLAN')
            for rel, fd in directories.items():
                names = {PurePosixPath(n).name for n in expected if n != '.' and str(PurePosixPath(n).parent) == rel}
                io.require(set(os.listdir(fd)) == names and guard.observe_fd(fd) == expected[rel],
                           'SITE_READ_WITNESS_CHANGED')
            # This read witness deliberately claims NO lease, writer exclusion,
            # backup or future stability. All owner fences are acquired later.
            return io.sha(io.canonical(observed))
        finally:
            for fd in directories.values(): os.close(fd)

    def condition(self, unit, *, present):
        value = self.a.unit(unit)
        path = self.dropdir(unit)+'/'+self.r.BARRIER
        if present:
            raw, row = self.p.read(path)
            expected = self.return_barriers.get(unit, self.barriers.get(unit))
            io.require(expected is not None and self.same_file(row, expected) and raw == self.r.BARRIER_BYTES,
                       'OWN_BARRIER_LOST')
            io.require(path in value['DropInPaths'].split(), 'BARRIER_NOT_LOADED')
        else:
            self.p.absent(path)
            io.require(path not in value['DropInPaths'].split(), 'BARRIER_STILL_LOADED')
        object_path = '/org/freedesktop/systemd1/unit/'+''.join(
            c if c.isascii() and c.isalnum() else '_'+format(ord(c), '02x') for c in unit)
        r = command(['/usr/bin/busctl', '--system', '--auto-start=no', '--allow-interactive-authorization=no',
                     '--json=short', 'get-property', 'org.freedesktop.systemd1', object_path,
                     'org.freedesktop.systemd1.Unit', 'Conditions'], self.deadline)
        io.require(r.returncode == 0, 'EFFECTIVE_CONDITIONS_UNKNOWN')
        result = io.parse(r.stdout)
        io.require(set(result) == {'type', 'data'} and result['type'] == 'a(sbbsi)',
                   'EFFECTIVE_CONDITIONS_SCHEMA')
        conditions = result['data']
        marker = self.r.BOOT+'/NEVER-CREATE-START-PERMIT'
        io.require((len(conditions) == 1 and conditions[0][:4] ==
                    ['ConditionPathExists', False, False, marker] and len(conditions[0]) == 5 and
                    type(conditions[0][4]) is int and conditions[0][4] in (0, -1))
                   if present else conditions == [], 'EFFECTIVE_CONDITION_BINDING')
        self.absent(self.r.BOOT+'/NEVER-CREATE-START-PERMIT')

    @staticmethod
    def same_file(left, right):
        return all(left[k] == right[k] for k in left if k != 'atime_ns')

    def reload(self):
        self.p.check(); self.a.check_files()
        io.require(self.a.unit_search() == self.a.b['unit_search_sha256'], 'FOREIGN_PRE_RELOAD_DELTA')
        r = command(['/usr/bin/systemctl', 'daemon-reload'], self.deadline)
        io.require(r.returncode == 0, 'RELOAD_OUTCOME_UNKNOWN_NO_RETRY')
        self.a.units_check(stop_only=len(self.a.stopped) != 3 and not self.a.rights)
        io.require(self.a.unit_search() == self.a.b['unit_search_sha256'], 'FOREIGN_POST_RELOAD_DELTA')

    def quiet(self):
        self.a.check()
        io.require(self.a.stopped == set(UNITS) and all(self.a.empty(u) for u in UNITS), 'THREE_UNITS_NOT_QUIET')
        for unit in UNITS:
            self.condition(unit, present=True)
        self.channel.check()

    def barrier(self, unit, *, returning):
        path = self.dropdir(unit)+'/'+self.r.BARRIER
        if returning and unit in self.barriers and os.path.lexists(path):
            self.condition(unit, present=True)
            self.return_barriers[unit] = self.barriers[unit]
            return
        self.parent(self.dropdir(unit), 0o755)
        self.a.new_parent_paths |= self.created & {self.dropdir(u) for u in UNITS}
        row = self.p.create_file(path, self.r.BARRIER_BYTES, 0o644)
        self.a.own_config_paths.add(path); self.a.own_dropins[unit].add(path)
        (self.return_barriers if returning else self.barriers)[unit] = row
        self.barrier_places[unit] = (path, row)

    def check_barrier_bindings(self):
        io.require(set(self.barrier_places) == set(UNITS), 'BARRIER_CREATION_INCOMPLETE')
        for path, expected in [*self.barrier_history, *self.barrier_places.values()]:
            raw, row = self.p.read(path)
            io.require(self.same_file(row, expected) and raw == self.r.BARRIER_BYTES, 'BARRIER_CUSTODY_CHANGED')

    def classify_for_return(self):
        """One READ-ONLY classification, not a forward ACK/retry or rollback.

        Only private backup/restore/probe or fully individually bound partial
        installation outcomes can be classified here. Ambiguous stop/start,
        barrier creation, missing intent ACK, unknown probe job or lost wire
        remains HOLD. The original failed forward intent is never removed.
        """
        io.require(self.channel.return_confirmed and not self.owner_admission_started, 'RETURN_NOT_EXPLICIT')
        if self.pending is None: return
        action, unit = self.pending
        io.require(unit is None and action in ('protected_rights_backup', 'isolated_restore_rehearsal',
                   'bounded_synthetic_probes', 'install_four_artifacts'), 'UNCLASSIFIED_EFFECT_NO_RETURN')
        self.quiet(); self.check_barrier_bindings()
        if action == 'bounded_synthetic_probes':
            io.require(self.probes is not None and self.probes.cleanup_complete and not self.probes.unconfirmed,
                       'UNCLASSIFIED_PROBE_EFFECT_NO_RETURN')
        for path, (name, _mode) in self.artifacts.items():
            if path in self.installed:
                raw, row = self.p.read(path)
                io.require(self.same_file(row, self.installed[path]) and raw == self.source.bytes[name],
                           'PARTIAL_INSTALL_NOT_BOUND')
            else: self.p.absent(path)
        if self.installed:
            io.require(self.backup_hash is not None and self.restore_hash == self.backup_hash,
                       'RETURN_BACKUP_NOT_PROVED')
        self.channel.record('read_only_effect_classification', {'action': action,
            'original_forward_intent_stays_unacknowledged': True, 'forward_retry': False,
            'all_three_currently_stopped': True, 'bound_installed_paths': sorted(self.installed)})
        self.pending = None

    def space(self):
        fd = self.p.get('/opt/tu1nz_repos'); s = os.fstatvfs(fd)
        # Budget includes dependency copies, exact source/input backup and owner
        # copies. A privileged quota/LSM unknown is not called free space proof.
        required = 768*1024*1024 + sum(os.stat(p, follow_symlinks=False).st_size for p in self.a.b['files'])
        io.require(s.f_bavail*s.f_frsize >= required and s.f_favail >= 8192, 'PRIVATE_SPACE_RED')
        r = command(['/usr/bin/findmnt', '-n', '-o', 'VFS-OPTIONS,FS-OPTIONS', '-T', '/opt/tu1nz_repos'], self.deadline)
        io.require(r.returncode == 0 and not any(x in r.stdout.decode().replace(',', ' ').split()
                   for x in ('ro', 'usrquota', 'grpquota', 'prjquota', 'quota', 'pquota')), 'QUOTA_OR_MOUNT_UNKNOWN')

    def isolation(self, unit):
        r = command(['/usr/bin/systemctl', 'show', unit, '--property=ExecStart,NoNewPrivileges,PrivateUsers,RestrictNamespaces,InaccessiblePaths,SupplementaryGroups', '--no-pager'], self.deadline)
        io.require(r.returncode == 0, 'EFFECTIVE_ISOLATION_UNKNOWN')
        v = dict(x.split('=', 1) for x in r.stdout.decode().splitlines() if '=' in x)
        profile = ('s7', 's8-landing', 'wms')[UNITS.index(unit)]
        io.require(HELPER+' --profile '+profile in v.get('ExecStart', '') and
                   v.get('NoNewPrivileges') == 'yes' and not v.get('SupplementaryGroups') and
                   v.get('PrivateUsers') == 'no' and v.get('RestrictNamespaces') == 'user',
                   'EFFECTIVE_ISOLATION_RED')
        for path in ('/run/docker.sock', '/run/containerd', '/run/user/1001'):
            io.require(path in v.get('InaccessiblePaths', ''), 'EFFECTIVE_BROKER_PATH_NOT_HIDDEN')
        for path, (name, _mode) in self.artifacts.items():
            raw, row = self.p.read(path)
            io.require(raw == self.source.bytes[name] and self.same_file(row, self.installed[path]),
                       'INSTALLED_ARTIFACT_CHANGED')

    def function(self, unit, *, old):
        proof = self.a.function(unit, old=old)
        row = process(int(self.a.unit(unit)['MainPID']))
        if not old:
            self.a.rights_check(unit, row)
        value = {'unit': unit, 'pid': row['pid'], 'start': row['starttime'], 'old': old,
                 'invocation': self.a.unit(unit)['InvocationID'], 'function': proof,
                 'kernel': {k: row[k] for k in ('uid', 'gid', 'groups', 'caps', 'nnp', 'uid_map', 'gid_map',
                                               'setgroups', 'namespaces', 'lsm_sha256', 'exe_sha256')}}
        if not self.preparing:
            self.channel.record('old_function_accepted' if old else 'function_accepted', value)
            (self.old_accepted if old else self.accepted)[unit] = value
        return value

    def function_all(self, *, old):
        for unit in UNITS:
            self.function(unit, old=old)

    def state(self, unit):
        value = self.a.unit(unit)
        io.require(not value['Job'] and not int(value['ControlPID']), 'PRIOR_EFFECT_UNCLASSIFIED')
        if value['ActiveState'] == 'inactive' and self.a.empty(unit):
            return 'currently_stopped_cgroup_empty'
        row = process(int(value['MainPID']))
        expected = self.started.get(unit, self.old_started.get(unit))
        if expected is None:
            expected = self.a.targets.get(unit)
        io.require(value['ActiveState'] == 'active' and (row['pid'], row['starttime']) == expected,
                   'PRIOR_INVOCATION_UNKNOWN')
        return 'currently_active_requires_single_return_stop'

    def service_action(self, action, unit, *, deadline):
        io.require(action in ('start', 'stop') and unit in UNITS, 'SERVICE_ACTION_SCOPE')
        return command(['/usr/bin/systemctl', action, unit], deadline)

    def before_start_request(self, unit, before, *, old, deadline):
        pass  # Historical entry behavior remains unchanged.

    def start_baseline_check(self, unit, before, *, old):
        io.require(before['ActiveState'] == 'inactive' and before['MainPID'] == '0' and not before['Job'],
                   'START_BASELINE_NOT_FULLY_INACTIVE')

    def record_start_attempt(self, unit, before, *, old):
        self.channel.record('first_start_attempt', {'unit': unit, 'old_operation': old,
            'prior_invocation': before['InvocationID'], 'prior_restart_counter': before['NRestarts']})

    def observe_start_identity(self, unit, identity, *, old):
        pass  # An observation is not runtime/rights/functional acceptance.

    def fault(self, error):
        if type(error) is self.r.FlowFailure: return error
        if isinstance(error, io.Hold): primary = error.primary
        elif isinstance(error, self.source.load('entry').Denied):
            primary = 'PUBLIC_BOOTSTRAP_'+str(error)
        elif type(error).__module__ == self.source.load('owner').__name__ and hasattr(error, 'primary'):
            primary = 'PUBLIC_BOOTSTRAP_'+error.primary
        else: primary = self.r.failure_code(error)
        cleanup = ['PUBLIC_BOOTSTRAP_OWNED_RESOURCE_CLEANUP_UNCONFIRMED' for _ in
                   getattr(error, '_owner_cleanup', ())]
        cleanup.extend(getattr(error, '_probe_cleanup', ()))
        cleanup.extend(getattr(error, '_runtime_cleanup', ()))
        cleanup.extend(io.http_cleanup(error))
        return self.r.FlowFailure(primary, cleanup=cleanup)

    def observe(self, phase, *, deadline):
        try:
            deadline = min(deadline, self.channel.ceiling)
            with self.a.limit(deadline): return self._observe(phase, deadline=deadline)
        except BaseException as error: raise self.fault(error) from None

    def _observe(self, phase, *, deadline):
        self.now(); io.require(deadline <= self.deadline, 'OBSERVATION_SCOPE')
        facts = set()
        if phase == 'pre_stop':
            self.a.check(stop_only=True); self.channel.check()
            io.require(self.read_witness is not None and self.channel.approval_bound, 'PRESTATE_OR_AUTHORITY_UNBOUND')
            facts.update(('authenticated_operator_kernel_manager', 'exact_host_source_scope',
                'source_bound_prestate_read_witness', 'prestate_NOT_claimed_backup',
                'other_admin_writer_actors_individually_closed', 'no_unknown_or_extra_delegation',
                'known_delegation_exactly_three_stop_targets', 'exact_stop_impact_no_foreign_units',
                'no_queued_or_uncontrolled_activation', 'current_control_paths_and_own_namespace',
                'bootstrap_barriers_and_quarantine_same_filesystem', 'separate_exact_R3_bootstrap_host_confirmation'))
        elif phase == 'barriers':
            self.a.check(stop_only=not self.a.stopped)
            for unit in UNITS: self.condition(unit, present=True)
            facts.update(('three_own_create_only_barriers_bound', 'conditions_false_effective',
                          'parent_profiles_and_boot_objects_bound', 'no_foreign_reload_delta'))
        elif phase in ('quiet', 'staging_ready', 'staging', 'backup', 'restore', 'probes', 'install'):
            self.quiet()
            facts.update(('three_cgroups_empty', 'no_escaped_or_broker_descendants',
                'no_jobs_or_external_reactivation', 'other_admin_writer_actors_individually_closed',
                'control_source_prestate_and_barriers_unchanged', 'persistent_barriers_effective',
                'client_server_intents_hash_linked', 'no_unknown_authority'))
            if phase in ('staging_ready', 'staging'):
                self.space()
                for path in (STAGING, LIGHTING):
                    if phase == 'staging_ready': self.absent(path)
                    else: self.p.get(path)
                facts.update(('private_space_and_quota', 'no_foreign_or_partial_transaction',
                              'opt_ancestors_exact_acl_profile' if phase == 'staging_ready' else
                              'sealed_opt_children_exact_acl_profile'))
            if phase == 'backup':
                io.require(self.backup_hash is not None, 'BACKUP_INCOMPLETE')
                facts.update(('full_units_dropins_inputs_tool_pins_protected_backup', 'independent_readback',
                              'not_the_pre_stop_read_witness'))
            if phase == 'restore':
                io.require(self.restore_hash == self.backup_hash and self.restore_hash is not None, 'RESTORE_INCOMPLETE')
                facts.update(('isolated_metadata_content_restore_and_return_rehearsal', 'no_live_or_DB_restore'))
            if phase == 'probes':
                io.require(self.probe_hash is not None, 'PROBES_INCOMPLETE')
                facts.update(('three_exact_synthetic_probes_passed', 'installed_kernel_systemd_proof',
                              'owned_probe_cleanup_receipted', 'no_real_inputs_provider_or_network'))
            if phase == 'install':
                for unit in UNITS: self.isolation(unit)
                facts.update(('four_exact_unchanged_runtime_artifacts', 'backup_restore_and_probes_bound',
                              'effective_config_verified_barriers_still_false'))
        elif phase.startswith(('release:', 'return_release:')):
            old = phase.startswith('return_'); unit = phase.split(':', 1)[1]; index = UNITS.index(unit)
            accepted = self.old_accepted if old else self.accepted
            io.require(all(u in accepted for u in UNITS[:index]), 'PREDECESSOR_NOT_DURABLY_ACCEPTED')
            self.a.check(stop_only=old); self.channel.check(); self.condition(unit, present=False)
            self.check_barrier_bindings()
            for downstream in UNITS[index+1:]: self.condition(downstream, present=True)
            if not old: self.isolation(unit)
            else: io.require(self.original_restored, 'ORIGINAL_CONFIG_NOT_RESTORED')
            facts.update(('only_this_own_return_barrier_quarantined_exactly' if old else 'only_this_own_barrier_quarantined_exactly',
                'downstream_barriers_still_effective', 'prior_old_unit_function_durably_accepted' if old else
                'prior_unit_function_durably_accepted', 'reload_verified_original_effective_config_no_false_barrier_for_this_unit'
                if old else 'effective_installed_isolation_verified', 'no_foreign_change', 'persistent_journal_protected'))
        elif phase.startswith(('started:', 'old_started:')):
            old = phase.startswith('old_'); unit = phase.split(':', 1)[1]
            self.function(unit, old=old); self.a.check(stop_only=old)
            facts.update(('fresh_original_unit_invocation_and_function',) if old else
                         ('fresh_expected_invocation_cgroup_function', 'actual_unit_rights_and_required_data_DB_HTTP_or_credentials'))
        elif phase == 'rights':
            self.a.check(); self.function_all(old=False)
            io.require(set(self.accepted) == set(UNITS), 'RIGHTS_NOT_ACCEPTED')
            facts.update(('three_actual_functional_invocations', 'uid_gid_1001_groups_empty',
                'five_capsets_zero_NNP1_minimal_maps', 'no_effective_alternate_admin_access',
                'actual_credentials_data_DB_and_HTTP', 'old_separate_RED_states_not_lifted'))
        elif phase == 'owner_ready':
            self.a.check(); self.function_all(old=False)
            io.require(not self.owner_admission_started, 'NO_OWNER_ADMISSION_REPLAY')
            self.owner_admission_started = True
            owner_deadline = min(deadline, time.monotonic()+120)
            # From this point the entire same-process owner continuation,
            # explicit return, wire waits and cleanup share its 120s ceiling.
            self.channel.cap(owner_deadline)
            self.owner = self.source.load('owner').Supervisor(self.source.load('guard'), self.plan_raw,
                self.r.OWNER_PLAN, self.a.bounded(owner_deadline), self.channel.bounded(owner_deadline),
                deadline=owner_deadline)
            self.owner.check_all()
            facts.update(('original_exact_owner_plan_matches', 'rights_acceptance_current',
                'all82_file_leases_namespace_FD_mapping_fences', 'owner120s512FD_bound',
                'actual_owner_backup_independent_read_restore', 'separate_owner_journal_and_intent_unspent'))
        elif phase == 'owner_done':
            io.require(self.owner_result and self.owner_result['status'] == 'OWNER_COMPLETED' and
                       self.owner_result['owner_acks'] == 84 and self.owner_result.get('cleanup_sha256'),
                       'OWNER_CLEAN_COMPLETION_MISSING')
            self.a.check()
            facts.update(('all84_exact_uid_changes_four_root_files_untouched',
                'all_bytes_mode_gid_ACL_attrs_flags_inodes_preserved', 'actual_post_ctimes_and_per_object_ACKs',
                'nginx_read_HTTP_passed', 'receipt_and_cleanup_all_fences_no_break', 'primary_abort_cleanup_separate'))
        elif phase == 'return_request':
            self.classify_for_return()
            io.require(self.channel.return_confirmed and self.pending is None and not self.owner_admission_started,
                       'EXPLICIT_RETURN_OR_EFFECT_UNKNOWN')
            self.a.check(stop_only=True); self.channel.check()
            self.check_barrier_bindings()
            for unit in UNITS: self.state(unit)
            facts.update(('separate_once_old_operation_return_confirmed', 'all_prior_effects_classified_no_unknown_jobs',
                'authenticated_operator_kernel_manager', 'exact_stop_impact_no_foreign_units',
                'other_actor_TCB_and_original_function_prerequisites_current', 'own_barriers_and_journal_bound',
                'no_foreign_control_config_source_change'))
        elif phase.startswith('return_state:'):
            unit = phase.split(':', 1)[1]; self.condition(unit, present=True)
            classified = self.state(unit)
            facts.update(('fresh_exact_unit_invocation_cgroup_classified', 'all_prior_effects_classified_no_pending_job',
                          'own_persistent_barrier_effective', classified))
        elif phase in ('return_before_install', 'return_after_install', 'return_config'):
            self.quiet(); io.require(self.channel.return_confirmed and not self.owner_admission_started, 'RETURN_NOT_ADMITTED')
            if phase == 'return_after_install':
                io.require(self.backup_hash is not None and self.restore_hash == self.backup_hash, 'RETURN_BACKUP_NOT_PROVED')
                for p, row in self.installed.items():
                    raw, actual = self.p.read(p)
                    io.require(self.same_file(actual, row) and raw == self.source.bytes[self.artifacts[p][0]], 'RETURN_ARTIFACT_UNBOUND')
                facts.update(('no_owner_attempt_or_change', 'protected_backup_restore_bound', 'only_own_four_artifacts_bound_for_quarantine'))
            elif phase == 'return_before_install':
                io.require(not self.installed, 'FORWARD_ARTIFACT_EXISTS')
                facts.update(('no_forward_artifact_or_owner_change',
                              'current_all_original_config_source_inputs_match_authenticated_baseline'))
            else:
                io.require(self.original_restored, 'ORIGINAL_CONFIG_UNPROVED')
                for path in self.artifacts: self.p.absent(path)
                facts.update(('exact_original_config_source_inputs_verified_no_foreign_change', 'no_forward_artifacts_left'))
            facts.update(('all_three_stopped_and_bound', 'other_actor_TCB_and_original_function_prerequisites_current',
                          'own_barriers_and_journal_bound', 'separate_once_old_operation_return_confirmed'))
        elif phase == 'old_function':
            self.a.check(stop_only=True); self.function_all(old=True)
            facts.update(('original_function_and_config_verified', 'restored_old_authority_security_RED'))
        else:
            raise io.Hold('PUBLIC_OPERATOR_UNKNOWN_OR_UNIMPLEMENTED_PHASE')
        self.now()
        return self.r.Observation(self.r.TX, self.binding, phase, frozenset(facts), time.monotonic())

    def perform(self, action, unit, *, deadline):
        try:
            deadline = min(deadline, self.channel.ceiling)
            with self.a.limit(deadline): return self._perform(action, unit, deadline=deadline)
        except BaseException as error: raise self.fault(error) from None

    def _perform(self, action, unit, *, deadline):
        io.require(self.pending is None and time.monotonic() < deadline <= self.deadline, 'ACTION_OR_BUDGET_UNKNOWN')
        self.pending = (action, unit)
        self.channel.record('host_action_intent', {'action': action, 'unit': unit})
        result = {'action': action, 'unit': unit, 'outcome': 'CONFIRMED'}
        if action == 'create_persistent_barriers':
            self.parent(str(PurePosixPath(self.r.BOOT).parent)); self.directory(self.r.BOOT)
            for name in ('read-witness', 'intents', 'acknowledgments', 'quarantine', 'reports'):
                self.directory(self.r.BOOT+'/'+name)
            self.channel.attach(self.p.get(self.r.BOOT+'/intents'))
            self.p.create_file(self.r.BOOT+'/read-witness/witness.json', io.canonical(self.read_witness))
            for u in UNITS: self.barrier(u, returning=False)
            self.reload()
        elif action in ('stop', 'return_stop'):
            io.require(unit in UNITS and (action, unit) not in self.stop_requested, 'NO_STOP_REPLAY')
            classified = self.state(unit)
            io.require(classified == 'currently_active_requires_single_return_stop', 'STOP_STATE_NOT_ACTIVE')
            self.stop_requested.add((action, unit))
            r = self.service_action('stop', unit, deadline=deadline)
            io.require(r.returncode == 0 and self.a.empty(unit), 'STOP_OUTCOME_UNKNOWN')
            self.a.stopped.add(unit); self.a.rights.discard(unit)
            result.update(cgroup_empty=True, no_job=not self.a.unit(unit)['Job'])
        elif action == 'create_sealed_staging':
            self.quiet(); self.space()
            for p in (STAGING, LIGHTING):
                self.parent(str(PurePosixPath(p).parent)); self.directory(p)
            for name in ('quarantine', 'reports', 'result'):
                self.directory(STAGING+'/'+name)
        elif action == 'protected_rights_backup':
            self.quiet()
            self.backup = Backup(self.p, {p: v['sha256'] for p, v in self.a.b['files'].items()},
                                 STAGING, self.quiet)
            self.backup_hash = self.backup.create(); result['proof_sha256'] = self.backup_hash
        elif action == 'isolated_restore_rehearsal':
            self.quiet(); self.restore_hash = self.backup.restore_test(); result['proof_sha256'] = self.restore_hash
        elif action == 'bounded_synthetic_probes':
            self.quiet()
            self.probes = Probes(self.p, self.source, self.a, self.channel, deadline=deadline)
            self.probe_hash = self.probes.run()
            result['proof_sha256'] = self.probe_hash
        elif action == 'install_four_artifacts':
            self.quiet()
            io.require(self.backup_hash is not None and self.restore_hash == self.backup_hash and self.probe_hash,
                       'INSTALL_PREREQUISITES')
            for p, (name, mode) in self.artifacts.items():
                self.quiet(); self.installed[p] = self.p.create_file(p, self.source.bytes[name], mode)
                if p != HELPER:
                    self.a.own_config_paths.add(p)
                    self.a.own_dropins[next(u for u in UNITS if p.startswith(self.dropdir(u)+'/'))].add(p)
            self.reload()
        elif action in ('quarantine_own_barrier', 'quarantine_own_return_barrier'):
            io.require(unit in UNITS, 'UNIT_SCOPE')
            old = action == 'quarantine_own_return_barrier'
            accepted = self.old_accepted if old else self.accepted
            io.require(all(u in accepted for u in UNITS[:UNITS.index(unit)]), 'PREDECESSOR_NOT_ACCEPTED')
            self.a.check(stop_only=old); self.condition(unit, present=True)
            path = self.dropdir(unit)+'/'+self.r.BARRIER
            target = self.r.BOOT+'/quarantine/'+('return-' if old else 'forward-')+unit
            row = self.p.quarantine(path, target, (self.return_barriers if old else self.barriers)[unit])
            self.barrier_places[unit] = (target, row)
            self.channel.record('barrier_quarantined', {'unit': unit, 'path': target, 'actual': row})
            self.a.own_dropins[unit].remove(path); self.reload()
        elif action in ('start', 'start_old'):
            old = action == 'start_old'; attempted = self.old_start_requested if old else self.start_requested
            io.require(unit in UNITS and unit not in attempted and self.a.empty(unit), 'NO_START_REPLAY_OR_NONEMPTY')
            self.condition(unit, present=False); attempted.add(unit)
            before = self.a.unit(unit)
            self.start_baseline_check(unit, before, old=old)
            self.record_start_attempt(unit, before, old=old)
            self.before_start_request(unit, before, old=old, deadline=deadline)
            r = self.service_action('start', unit, deadline=deadline)
            io.require(r.returncode == 0, 'START_OUTCOME_UNKNOWN_NO_RETRY')
            value = self.a.unit(unit)
            # A manual start resets the manager's automatic-restart counter;
            # every queued automatic restart increments and retains it. Thus
            # a replacement BEFORE this first sample cannot become "first".
            # Counter semantics: systemd v255 src/core/service.c service_start /
            # service_enter_restart. No reset/restart-rule mutation is used.
            io.require(value['NRestarts'] == '0', 'FIRST_START_AUTORESTART_DETECTED')
            io.require(value['ActiveState'] == 'active' and not value['Job'], 'START_OUTCOME_UNKNOWN_NO_RETRY')
            first = (value['InvocationID'], int(value['MainPID']), starttime(int(value['MainPID'])))
            self.observe_start_identity(unit, first, old=old)
            while True:
                value = self.a.unit(unit)
                io.require((value['InvocationID'], int(value['MainPID']), starttime(int(value['MainPID']))) == first and
                           value['NRestarts'] == '0' and
                           value['ActiveState'] == 'active' and not value['Job'], 'FIRST_START_INVOCATION_CHANGED')
                row = initial_profile(first[1], first[2], deadline)
                # No replacement/counter change during profile acquisition may
                # become acceptance of the original requested start.
                after = self.a.unit(unit)
                io.require((after['InvocationID'], int(after['MainPID']), row['starttime']) == first and
                           after['NRestarts'] == '0' and after['ActiveState'] == 'active' and not after['Job'],
                           'FIRST_START_INVOCATION_CHANGED')
                if old:
                    if all(row[k] == v for k, v in self.a.original_profiles[unit].items()):
                        self.a.delegation_check(row, known_stop=True)
                        break
                elif (row['uid'] == row['gid'] == [1001]*4 and not row['groups'] and not any(row['caps'].values()) and
                      self.a.initial_application_ready(unit,row)):
                    # Readiness is not a profile or admission. An exec can
                    # expose the target exe before its environment is filled.
                    # Do not pass that earlier row to rights acceptance.
                    row = initial_profile(first[1], first[2], deadline)
                    after = self.a.unit(unit)
                    io.require((after['InvocationID'], int(after['MainPID']), row['starttime']) == first and
                               after['NRestarts'] == '0' and after['ActiveState'] == 'active' and not after['Job'],
                               'FIRST_START_INVOCATION_CHANGED')
                    self.a.interpreter_binding(row, old=False)
                    io.require(self.a.initial_application_ready(unit,row), 'FIRST_START_READINESS_LOST')
                    self.a.rights_check(unit, row)
                    final = self.a.unit(unit)
                    io.require((final['InvocationID'], int(final['MainPID']), starttime(row['pid'])) == first and
                               row['pid'] == first[1] and final['NRestarts'] == '0' and
                               final['ActiveState'] == 'active' and not final['Job'],
                               'FIRST_START_INVOCATION_CHANGED')
                    break
                io.require(time.monotonic()+.01 < deadline, 'FIRST_START_KERNEL_PROFILE_DEADLINE')
                time.sleep(.01)
            (self.old_started if old else self.started)[unit] = (row['pid'], row['starttime'])
            self.a.stopped.remove(unit)
            self.a.runtime_invocations[unit] = first
            if not old:
                self.a.rights.add(unit)
            else:
                self.a.targets[unit] = (row['pid'], row['starttime'])
        elif action == 'supervised_owner_transaction':
            io.require(self.owner is not None, 'OWNER_NOT_READY')
            self.owner.apply(); self.owner_result = self.owner.finish()
            result['proof_sha256'] = io.sha(io.canonical(self.owner_result))
        elif action == 'establish_return_barriers':
            io.require(self.channel.return_confirmed and not self.owner_admission_started, 'RETURN_NOT_EXPLICIT_OR_OWNER_BEGUN')
            self.check_barrier_bindings()
            self.barrier_history.extend((p, row) for p, row in self.barrier_places.values()
                                        if p.startswith(self.r.BOOT+'/quarantine/'))
            self.returning = True
            for u in UNITS: self.barrier(u, returning=True)
            self.reload()
        elif action == 'return_old_configuration':
            self.quiet()
            for p, row in self.installed.items():
                self.p.quarantine(p, STAGING+'/quarantine/runtime-'+PurePosixPath(p).parent.name+'-'+PurePosixPath(p).name, row)
                if p != HELPER:
                    u = next(u for u in UNITS if p.startswith(self.dropdir(u)+'/'))
                    self.a.own_dropins[u].remove(p)
            self.installed.clear(); self.reload(); self.a.check_files(); self.original_restored = True
        else:
            raise io.Hold('PUBLIC_OPERATOR_UNIMPLEMENTED_ACTION')
        io.require(time.monotonic() < deadline, 'ACTION_LATE_HOLD')
        self.channel.record('host_action_ack', result)
        self.pending = None
        return result

    def close(self):
        errors = []
        if getattr(self, 'owner', None) is not None:
            errors.extend('PUBLIC_BOOTSTRAP_OWNER_CLEANUP_UNCONFIRMED' for _ in self.owner.close())
        if getattr(self, 'p', None) is not None:
            if getattr(self, 'a', None) is not None: errors.extend(self.a.close())
            errors.extend(self.p.close())
        return errors


class RemoteJournal:
    def __init__(self, channel, binding):
        self.channel, self.binding = channel, binding
        self.claimed = False

    def claim(self):
        io.require(not self.claimed, 'NO_FLOW_REPLAY')
        self.claimed = True
        self.channel.record('flow_claim', {'transaction': 'public-rights-20261014-1'})

    def write(self, kind, value):
        io.require(self.claimed, 'FLOW_NOT_CLAIMED')
        self.channel.record('flow_'+kind, value)


class RecoveryRemoteJournal:
    """Own bounded Flow subchain. Never invokes the original Flow claim."""
    def __init__(self, channel):
        io.require(isinstance(channel, io.RecoveryLinkedRecords), 'RECOVERY_JOURNAL_CHANNEL')
        self.channel, self.binding = channel, channel.binding
        self.claimed = False; self.count = 0

    def claim(self):
        io.require(not self.claimed, 'RECOVERY_FLOW_NO_REPLAY')
        self.claimed = True
        self.write('claim', {'transaction': 'public-rights-20261014-1',
                             'original_claim_reset': False, 'recovery_of_recovery': False})

    def write(self, kind, value):
        io.require(self.claimed and self.count < 128 and kind in
                   ('claim', 'observation', 'intent', 'ack', 'hold', 'complete'),
                   'RECOVERY_FLOW_RECORD_BOUND')
        self.count += 1
        self.channel.record('recovery_flow_'+kind, value)


def source_fault_location(error):
    """Source-only location, never exception text, locals or Host path values."""
    seen = set(); location = None
    while error is not None and id(error) not in seen:
        seen.add(id(error)); trace = error.__traceback__
        while trace is not None:
            filename = trace.tb_frame.f_code.co_filename
            if filename.startswith('<authenticated-memory:') and filename != '<authenticated-memory:io>':
                location = {'component': filename, 'line': trace.tb_lineno, 'type': type(error).__name__}
            trace = trace.tb_next
        if location is not None and type(error).__name__ != 'FlowFailure': return location
        error = error.__context__
    return location


class RecoveryHostEntry:
    """Create-only half of the sole additive Recovery entry, never a retry.

    The session must validate its complete packet/gates BEFORE construction;
    the Mac has already spent its fixed entry BEFORE opening this transport.
    This object only binds that entry, not fresh Authority or an effect grant.
    Partial creation/unknown ACK is retained and consumes the entry. Paths
    owns all opened descriptors; no original record, claim or lock is changed.
    """
    ROOT = '/etc/tu1nz/public-web-bootstrap-r3/20261014-1/recovery-once'

    def __init__(self, paths, entry, *, original_binding, boot_id, source_sha256,
                 mac_snapshot_sha256, ready_sha256, deadline):
        self.p = paths; self.deadline = deadline; self.confirm_attempted = False; self.confirmed = False
        self.entry = io.recovery_entry(original_binding, boot_id, source_sha256,
                                       mac_snapshot_sha256, ready_sha256)
        io.require(entry == self.entry and type(deadline) in (int, float) and deadline == paths.deadline and
                   0 < deadline-time.monotonic() <= 600,
                   'RECOVERY_HOST_ENTRY_BINDING_OR_DEADLINE')
        self.raw = io.canonical(self.entry); self.metadata = None
        paths.absent(self.ROOT)
        # Creating the root spends the entry even if a following mkdir,
        # fsync, write or readback fails. No existing directory is adopted.
        paths.create_directory(self.ROOT)
        for name in ('intents', 'acknowledgments', 'reports'):
            paths.create_directory(self.ROOT+'/'+name)
        self.metadata = paths.create_file(self.ROOT+'/reports/entry.json', self.raw)
        self.check()

    def check(self):
        io.require(self.metadata is not None and time.monotonic() < self.deadline,
                   'RECOVERY_HOST_ENTRY_INCOMPLETE_OR_EXPIRED')
        self.p.check(full=True)
        # Paths retains and rechecks the created directory inode/security
        # bindings. Its ordinary journal writes may change directory times.
        for name in ('', '/intents', '/acknowledgments', '/reports'):
            self.p.get(self.ROOT+name)
        raw, actual = self.p.read(self.ROOT+'/reports/entry.json')
        io.require(raw == self.raw and Adapter.same_file(actual, self.metadata),
                   'RECOVERY_HOST_ENTRY_CHANGED')
        self.p.check(full=True)

    def confirm(self, wire):
        io.require(not self.confirm_attempted and wire.deadline == self.deadline,
                   'RECOVERY_HOST_ENTRY_ACK_NO_RETRY_OR_TIMER_CHANGE')
        self.confirm_attempted = True  # consume BEFORE send, including a lost output
        self.check()
        context = {'original_binding':self.entry['original_binding'], 'entry_sha256':io.sha(self.raw)}
        wire.send({'type':'recovery_entry_created', **context})
        io.require(wire.receive() == {'type':'recovery_entry_confirmed', **context},
                   'RECOVERY_HOST_ENTRY_MAC_ACK_UNKNOWN')
        self.check(); self.confirmed = True


class MaintenanceSessionResult:
    """Own partial session resources and a pending result, never an admission.

    The future complete Rev4 dispatcher must first pass every material/current
    coverage gate. This class neither creates a channel/adapter nor dispatches
    an action. A returned Flow status alone cannot confer K5 completion. The
    caller must retain partially initialized resources here before __init__.
    Original and Recovery journals stay separate; no original ACK is repaired.
    """
    ORIGINAL_COMPLETE = 'RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED'
    RECOVERY_PENDING = 'RECOVERY_RIGHTS_OWNER_RECEIPTED_PENDING_OPERATOR_CLEANUP'
    RECOVERY_COMPLETE = 'RECOVERY_RIGHTS_OWNER_RECEIPTED_ORIGINAL_HOLD_R2_NOT_DISPATCHED'

    def __init__(self, wire, r3, *, route):
        io.require(route in ('original', 'recovery-once'), 'MAINTENANCE_RESULT_ROUTE')
        self.wire, self.r, self.route = wire, r3, route
        self.adapter = self.channel = self.evidence = self.paths = None
        self.chain_started = False; self.closed = False
        self.status = 'HOLD'; self.primary = None; self.abort = []; self.cleanup = []
        self.location = None; self.owner_completion = None

    def failure(self, error):
        """Keep the first failure; cleanup/notification cannot erase it."""
        location = source_fault_location(error)
        if self.location is None:self.location = location
        fault = None
        if self.adapter is not None:
            try:fault = self.adapter.fault(error)
            except BaseException:
                self.abort.append('PUBLIC_BOOTSTRAP_FAILURE_CLASSIFICATION_UNKNOWN')
        value = fault if fault is not None else error
        primary = getattr(value, 'primary', self.r.failure_code(error))
        if self.primary is None:self.primary = primary
        else:self.abort.append(primary)
        self.abort.extend(getattr(value, 'abort', ()))
        self.cleanup.extend(getattr(value, 'cleanup', ()))
        self.status = 'HOLD'

    def completed(self, flow):
        """Use the actual in-process Flow and own 84-ACK Owner result only.

        The Flow has already witnessed actual rights/function/owner_done.
        This is only a candidate until close(), durable cleanup and channel
        close succeed. No historical successful record or boolean is input.
        """
        expected = self.ORIGINAL_COMPLETE if self.route == 'original' else self.RECOVERY_PENDING
        flow_type = self.r.MaintenanceFlow if self.route == 'original' else self.r.RecoveryFlow
        channel_type = io.MaintenanceLinkedRecords if self.route == 'original' else io.RecoveryLinkedRecords
        io.require(type(flow) is flow_type and flow.a is self.adapter and
                   type(self.channel) is channel_type and flow.j.channel is self.channel and self.chain_started and
                   self.channel.host_fd is not None and flow.j.claimed and flow.j.binding == self.channel.binding and
                   flow.stage == expected and flow.hold is False and flow.owner_started is True and
                   self.primary is None and not self.abort and not self.cleanup,
                   'MAINTENANCE_COMPLETION_NOT_CURRENT_FLOW')
        owner = self.adapter.owner_result
        io.require(type(owner) is dict and owner.get('status') == 'OWNER_COMPLETED' and
                   type(owner.get('owner_acks')) is int and owner['owner_acks'] == 84 and
                   type(owner.get('cleanup_sha256')) is str and len(owner['cleanup_sha256']) == 64 and
                   all(c in '0123456789abcdef' for c in owner['cleanup_sha256']) and
                   self.channel.owner_entry_started and self.adapter.owner_admission_started and
                   time.monotonic() < min(self.wire.deadline, self.channel.ceiling, flow.deadline),
                   'MAINTENANCE_CURRENT_OWNER_COMPLETION_MISSING')
        self.owner_completion = io.sha(io.canonical(owner))
        self.status = expected

    def owner_return_or_hold(self):
        """Only the already live Owner's original window may allow return.

        This is not Recovery or an automatic fallback. Missing/late/unknown
        confirmation is HOLD. RETURN_OLD is never offered or accepted. A
        returned Owner state can never become a successful K5 completion.
        """
        io.require(self.primary is not None and self.status == 'HOLD' and self.chain_started,
                   'MAINTENANCE_RETURN_WITHOUT_CURRENT_FAILURE')
        adapter = self.adapter
        owner = getattr(adapter, 'owner', None)
        available = owner is not None and owner.attempted
        end = min(self.wire.deadline, self.channel.ceiling, time.monotonic()+20,
                  owner.deadline if available else self.wire.deadline)
        seconds = max(0, min(20, end-time.monotonic()))
        self.wire.send({'type':'held', 'primary':self.primary, 'abort':self.abort, 'cleanup':self.cleanup,
            'return_available':False, 'owner_return_available':available and seconds > 0,
            'decision_seconds':seconds})
        # No separate20s or120s window. The transport itself enforces this cap.
        with self.channel.limit(end):
            decision = self.wire.receive()
            io.require(decision in ({'type':'decision','value':'HOLD'},
                                    {'type':'decision','value':'OWNER_RETURN'}),
                       'MAINTENANCE_RETURN_DECISION_NOT_ALLOWED')
            if decision['value'] == 'OWNER_RETURN':
                io.require(available and time.monotonic() < end, 'OWNER_RETURN_NOT_AVAILABLE')
                owner.return_once(); adapter.owner_result = owner.finish()
        self.status = 'HOLD'  # original primary/abort/cleanup remain intact

    def close(self):
        """Close only owned resources, then persist the current cleanup result.

        All operations spend the existing wire deadline. Loss of the cleanup
        ACK or final frame cannot confer success. Even a candidate successful
        Flow is downgraded on any close/clock error. The client must separately
        prove its own transport/custody cleanup before whole-run acceptance.
        """
        io.require(not self.closed, 'MAINTENANCE_RESULT_CLOSE_ONCE')
        self.closed = True
        # Adapters normally own their Paths/evidence. Finally also drain the
        # retained partial objects idempotently, including an early init error.
        if self.adapter is not None:
            try:self.cleanup.extend(self.adapter.close())
            except BaseException:self.cleanup.append('PUBLIC_BOOTSTRAP_OPERATOR_CLOSE_UNCONFIRMED')
        evidence = self.evidence if self.evidence is not None else getattr(self.adapter, 'evidence', None)
        paths = self.paths if self.paths is not None else getattr(self.adapter, 'p', None)
        if evidence is not None:
            try:self.cleanup.extend(evidence.close())
            except BaseException:self.cleanup.append('PUBLIC_BOOTSTRAP_RECOVERY_EVIDENCE_CLOSE_UNKNOWN')
        if paths is not None and (getattr(paths, 'rows', None) or getattr(paths, 'events', None) is not None):
            try:self.cleanup.extend(paths.close())
            except BaseException:self.cleanup.append('PUBLIC_BOOTSTRAP_RECOVERY_PATHS_CLOSE_UNKNOWN')
        if time.monotonic() >= self.wire.deadline:
            self.cleanup.append('PUBLIC_BOOTSTRAP_MAINTENANCE_HOST_DEADLINE_EXPIRED')
        if self.cleanup or self.primary is not None or self.abort:self.status = 'HOLD'
        elif self.status == self.RECOVERY_PENDING:self.status = self.RECOVERY_COMPLETE
        original = None
        if self.route == 'recovery-once' and type(self.channel) is io.RecoveryLinkedRecords:
            try:
                original = dict(self.channel.seed)
                io.require(io.recovery_binding(original) == self.channel.binding, 'RECOVERY_RESULT_SEED_CHANGED')
            except BaseException:
                self.cleanup.append('PUBLIC_BOOTSTRAP_RECOVERY_RESULT_ORIGINAL_BINDING_CHANGED'); self.status = 'HOLD'
                original = None
        record = {'status':self.status, 'primary':self.primary, 'abort':list(self.abort),
                  'cleanup':list(self.cleanup), 'owner_completion_sha256':self.owner_completion,
                  'original_status':'FAILED_HOLD' if self.route == 'recovery-once' else 'THIS_RUN',
                  'original_evidence':original,
                  'client_cleanup_still_required':True, 'r2_dispatch':False}
        if self.chain_started:
            try:self.channel.record('operator_cleanup', record)
            except BaseException:
                self.cleanup.append('PUBLIC_BOOTSTRAP_CLEANUP_RECORD_UNCONFIRMED'); self.status = 'HOLD'
        if self.channel is not None and self.channel.host_fd is not None:
            try:os.close(self.channel.host_fd)
            except OSError:
                self.cleanup.append('PUBLIC_BOOTSTRAP_MIRROR_CLOSE_UNCONFIRMED'); self.status = 'HOLD'
            self.channel.host_fd = None
        if time.monotonic() >= self.wire.deadline:
            self.status = 'HOLD'
            if 'PUBLIC_BOOTSTRAP_MAINTENANCE_HOST_DEADLINE_EXPIRED' not in self.cleanup:
                self.cleanup.append('PUBLIC_BOOTSTRAP_MAINTENANCE_HOST_DEADLINE_EXPIRED')
        result = {'type':'final', **record, 'status':self.status, 'cleanup':list(self.cleanup),
                  'source_fault':self.location, 'slot_consumed':False}
        self.wire.send(result)
        return result


def dispatch_maintenance(source, packet, wire):
    io.require(type(packet) is dict and packet.get('scope', {}).get('schema') == io.MAINTENANCE_SCOPE,
               'MAINTENANCE_EXPLICIT_SCOPE_REQUIRED')
    io.require(packet.get('route') in ('original','recovery-once'), 'MAINTENANCE_EXPLICIT_ROUTE_REQUIRED')
    return (maintenance_session if packet['route'] == 'original' else recovery_session)(source, packet, wire)


def maintenance_session_setup(source, packet, wire, *, route):
    """Finite envelope, evidence, coverage and shared-clock admission.

    The explicit Rev4 dispatcher selects these entries. Legacy session() does
    not. Actual live Authority, Writer and prepared-state checks follow; this
    pure input validation never replaces them or supplies a missing proof.
    """
    io.require(packet.get('route') == route and os.geteuid() == 0, 'MAINTENANCE_SESSION_ROUTE_OR_UID')
    remaining = io.maintenance_remote_deadline(packet, wire)
    bound = io.maintenance_packet_binding(packet, source, remaining_seconds=remaining)
    bound['coverage'] = source.load('admission').validate(packet, source, bound, remaining_seconds=remaining)
    parent = os.getppid(); libc = ctypes.CDLL(None, use_errno=True)
    io.require(libc.prctl(1, signal.SIGTERM, 0, 0, 0) == 0 and os.getppid() == parent,
               'COORDINATOR_PARENT_BINDING')
    def interrupted(_number, _frame):raise KeyboardInterrupt()
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):signal.signal(number, interrupted)
    return bound


def maintenance_session(source, packet, wire):
    """Original Rev4 Host sequence; no fallback to legacy Flow or Recovery.

    All entry/coverage/native gates are supplied by the admitted dispatcher.
    Actual adapter observations remain mandatory; packet facts cannot replace
    them. The original Flow alone owns its fixed original claim and ordering.
    """
    r = source.load('r3'); state = MaintenanceSessionResult(wire, r, route='original')
    try:
        bound = maintenance_session_setup(source, packet, wire, route='original')
        source.load('artifact'); replacement = source.load('replacement')
        channel = state.channel = io.MaintenanceLinkedRecords(wire, packet['binding'],
            original_binding=packet['binding'], boot_id=packet['baseline']['boot_id'])
        channel.approval_bound = True
        adapter = state.adapter = replacement.MaintenanceAdapter.__new__(replacement.MaintenanceAdapter)
        adapter.__init__(source, packet['baseline'], bound['plan'], channel, packet['binding'],
            deadline=wire.deadline, maintenance_inputs=bound['inputs'],
            after_ready_seconds=bound['timing']['after_ready_seconds'], coverage=bound['coverage'])
        # Read-only adapter admission may consume time. Recheck the SAME
        # current packet/lifetime before creating local original custody.
        io.maintenance_packet_binding(packet, source,
            remaining_seconds=max(1, math.ceil(wire.deadline-time.monotonic())))
        io.require(time.monotonic() < wire.deadline, 'MAINTENANCE_ADMISSION_EXPIRED')
        wire.send({'type':'prepared', 'binding':packet['binding']})
        io.require(wire.receive() == {'type':'client_custody_created', 'binding':packet['binding']},
                   'FIXED_CLIENT_CUSTODY_NOT_CREATED')
        state.chain_started = True
        channel.record('prestate_read_witness', adapter.read_witness)
        flow = r.MaintenanceFlow(adapter, RemoteJournal(channel, packet['binding']))
        try:
            flow.forward(); state.completed(flow)
        except BaseException as error:
            state.failure(error); state.owner_return_or_hold()
        channel.record('operator_pending_cleanup', {'status':state.status, 'primary':state.primary,
            'abort':list(state.abort), 'cleanup':list(state.cleanup), 'client_cleanup_still_required':True})
    except BaseException as error:state.failure(error)
    finally:result = state.close()
    return result


def recovery_session(source, packet, wire):
    """Sole F1–F4 Host sequence, with actual entry and fresh admission.

    Does not call original Adapter.__init__, original pre_stop, Flow.forward,
    runtime transfer or original Journal.claim. No original evidence is written.
    Only the explicit Rev4 dispatcher can select this separate route.
    """
    r = source.load('r3'); state = MaintenanceSessionResult(wire, r, route='recovery-once')
    try:
        bound = maintenance_session_setup(source, packet, wire, route='recovery-once')
        source.load('artifact'); replacement = source.load('replacement')
        paths = state.paths = Paths.__new__(Paths)
        paths.__init__(source.load('entry'), deadline=wire.deadline)
        machine, _ = paths.read('/etc/machine-id')
        io.require(io.sha(machine) == r.MACHINE and
                   Path('/proc/sys/kernel/random/boot_id').read_text().strip() == packet['baseline']['boot_id'],
                   'RECOVERY_ENTRY_ACTUAL_HOST_OR_BOOT_CHANGED')
        entry = packet['recovery']['entry']; manifest = packet['recovery']['manifest']
        host_entry = RecoveryHostEntry(paths, entry, original_binding=packet['binding'],
            boot_id=packet['baseline']['boot_id'], source_sha256=bound['inputs']['source_sha256'],
            mac_snapshot_sha256=manifest['snapshot_sha256'], ready_sha256=entry['ready_sha256'],
            deadline=wire.deadline)
        host_entry.confirm(wire)  # both entry markers spent BEFORE evidence/Authority/Flow
        evidence = state.evidence = replacement.RecoveryOriginalEvidence.__new__(replacement.RecoveryOriginalEvidence)
        evidence.__init__(paths, source, manifest, original_binding=packet['binding'],
            maintenance_inputs=bound['inputs'], boot_id=packet['baseline']['boot_id'], deadline=wire.deadline)
        admission = state.channel = io.RecoveryAdmissionChannel(wire, original_binding=packet['binding'],
            entry_sha256=io.sha(io.canonical(entry)), mac_snapshot_sha256=manifest['snapshot_sha256'])
        adapter = state.adapter = replacement.RecoveryAdapter.__new__(replacement.RecoveryAdapter)
        adapter.__init__(source, packet['baseline'], bound['plan'], admission, evidence=evidence,
            deadline=wire.deadline, terminal_prepare_seconds=bound['timing']['terminal_prepare_seconds'],
            terminal_cleanup_seconds=bound['timing']['terminal_cleanup_seconds'], coverage=bound['coverage'])
        io.maintenance_packet_binding(packet, source,
            remaining_seconds=max(1, math.ceil(wire.deadline-time.monotonic())))
        io.require(time.monotonic() < wire.deadline, 'RECOVERY_ADMISSION_EXPIRED')
        host_entry.check(); evidence.check_original()
        fresh = adapter.recovery_state_proof
        seed = {'schema':'TU1NZ_MAIN_SERVER_REV4_RECOVERY_ONCE', 'transaction':r.TX, 'machine':r.MACHINE,
            'boot_id':packet['baseline']['boot_id'], 'owner_plan_sha256':r.OWNER_PLAN,
            'original_binding':packet['binding'], 'ready_sha256':io.sha(evidence.ready_raw),
            'source_sha256':bound['inputs']['source_sha256'], 'artifact_sha256':evidence.ready['artifact_sha256'],
            'original_status':'FAILED_HOLD', 'original_failure_sha256':io.sha(io.canonical(evidence.failure)),
            'fresh_state_sha256':io.sha(io.canonical(fresh)),
            **{k:evidence.pair[k] for k in ('mac_tail_sha256','host_tail_sha256','unconfirmed_mac_tail')}}
        channel = io.RecoveryLinkedRecords(wire, seed)
        wire.send({'type':'recovery_prepared','seed':seed,'fresh_state':fresh,'original_failure':evidence.failure})
        io.require(wire.receive() == {'type':'recovery_custody_bound','binding':channel.binding},
                   'RECOVERY_FRESH_CLIENT_CUSTODY_NOT_BOUND')
        state.channel = channel  # own even a failed partial attach
        channel.attach(paths.get(RecoveryHostEntry.ROOT+'/intents'))
        state.chain_started = True; channel.approval_bound = True
        channel.record('recovery_context', seed)
        adapter.bind_execution(channel)
        flow = r.RecoveryFlow(adapter, RecoveryRemoteJournal(channel))
        try:
            flow.recover(); state.completed(flow)
        except BaseException as error:
            state.failure(error); state.owner_return_or_hold()
        channel.record('operator_pending_cleanup', {'status':state.status, 'primary':state.primary,
            'abort':list(state.abort), 'cleanup':list(state.cleanup), 'original_status':'FAILED_HOLD',
            'client_cleanup_still_required':True})
    except BaseException as error:state.failure(error)
    finally:result = state.close()
    return result


def session(source, packet, wire):
    """Actual production session, also the isolated integration entry.

    The transport has already authenticated the exact code and independent
    expected-scope binding. No replay, reattachment, resume or alternate TX.
    """
    import base64
    r = source.load('r3')
    parent = os.getppid()
    libc = ctypes.CDLL(None, use_errno=True)
    io.require(libc.prctl(1, signal.SIGTERM, 0, 0, 0) == 0 and os.getppid() == parent,
               'COORDINATOR_PARENT_BINDING')
    def interrupted(_number, _frame): raise KeyboardInterrupt()
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, interrupted)
    replacing=packet['scope'].get('schema') in io.R5_SCOPES
    prospective=packet['scope'].get('schema') in io.PROSPECTIVE_SCOPES
    io.require(set(packet) == {'source', 'hashes', 'baseline', 'baseline_raw', 'scope_raw',
                               'owner_plan', 'scope', 'scope_sha256', 'binding'} |
                               ({'baseline_encoding'} if replacing else set()) |
                               ({'prospective_material'} if prospective else set()),
               'SESSION_PACKET_SCHEMA')
    scope = packet['scope']; plan = base64.b64decode(packet['owner_plan'], validate=True)
    replacement=io.replacement_scope(scope,packet['baseline'])
    io.require(
               scope['r3_approval_sha256'] == '7032ae9a4baf5c358e81050cd3fd675386c2f33100ab9932f504c053eaa10a7d',
               'SESSION_SCOPE_AUTHORITY_SCHEMA')
    io.require(io.parse(plan)['host'] == r.MACHINE, 'OWNER_PLAN_HOST_NOT_SESSION_HOST')
    scope_raw = base64.b64decode(packet['scope_raw'], validate=True)
    baseline_raw = io.baseline_bytes(packet)
    io.require(io.parse(scope_raw) == scope and io.parse(baseline_raw) == packet['baseline'] and
               io.sha(scope_raw) == packet['scope_sha256'] and io.sha(io.canonical(scope)) == packet['binding'] and
               scope['machine_sha256'] == r.MACHINE and scope['transaction'] == r.TX and
               scope['owner_plan_sha256'] == io.sha(plan) == r.OWNER_PLAN and
               scope['baseline_sha256'] == io.sha(baseline_raw) and
               scope['administrative_roles_sha256'] == io.sha(io.canonical(packet['baseline']['actors'])) and
               scope['baseline_origins_sha256'] == io.sha(io.canonical(packet['baseline']['source_origin_receipts'])),
               'SESSION_INDEPENDENT_BINDING')
    prospective_binding=io.prospective_packet_material(packet)  # BEFORE adapter or claim
    channel = io.LinkedRecords(wire, packet['binding'])
    channel.approval_bound = True  # only after exact scope/code/host checks above
    adapter = None; flow = None; final_status = 'HOLD'; primary = None; abort = []; cleanup = []; claimed = False
    location = None
    try:
        # Retain ownership of a partially initialized adapter too. Read-only
        # admission can fail after opening fences, before __init__ returns.
        if replacement:source.load('artifact')
        adapter_type=source.load('replacement').ReplacementAdapter if replacement else Adapter
        adapter = adapter_type.__new__(adapter_type)
        adapter.__init__(source, packet['baseline'], plan, channel, packet['binding'], deadline=wire.deadline)
        if prospective:
            adapter.a.admit_prospective_names(prospective_binding)
            io.prospective_packet_material(packet)  # admission may expire during read-only preparation
        wire.send({'type': 'prepared', 'binding': packet['binding']})
        io.require(wire.receive() == {'type': 'client_custody_created', 'binding': packet['binding']},
                   'FIXED_CLIENT_CUSTODY_NOT_CREATED')
        if prospective:io.prospective_packet_material(packet)
        claimed = True
        channel.record('prestate_read_witness', adapter.read_witness)
        flow = r.Flow(adapter, RemoteJournal(channel, packet['binding']))
        flow.deadline = min(flow.deadline, wire.deadline)
        try:
            final_status = flow.forward()
        except BaseException as error:
            location = source_fault_location(error)
            primary = getattr(error, 'primary', r.failure_code(error))
            abort.extend(getattr(error, 'abort', ())); cleanup.extend(getattr(error, 'cleanup', ()))
            # No mutation from a decision file. Only the still-live explicit
            # client response can request the already confirmed once-return.
            wire.send({'type': 'held', 'primary': primary, 'abort': abort, 'cleanup': cleanup,
                       'return_available': not adapter.owner_admission_started and not getattr(adapter, 'forbid_legacy_return', False),
                       'owner_return_available': adapter.owner is not None and adapter.owner.attempted,
                       'decision_seconds': max(0, min(20, channel.ceiling-time.monotonic()))})
            decision = wire.receive()
            io.require(set(decision) == {'type', 'value'} and decision['type'] == 'decision', 'RETURN_DECISION_SCHEMA')
            if decision['value'] == 'RETURN_OLD':
                io.require(not getattr(adapter, 'forbid_legacy_return', False), 'LEGACY_RETURN_NOT_AUTHENTICATED')
                channel.return_confirmed = True
                final_status = flow.return_old()
            elif decision['value'] == 'OWNER_RETURN':
                io.require(adapter.owner is not None and adapter.owner.attempted, 'OWNER_RETURN_NOT_AVAILABLE')
                adapter.owner.return_once(); adapter.owner_result = adapter.owner.finish()
                final_status = adapter.owner_result['status']
            else:
                io.require(decision['value'] == 'HOLD', 'UNKNOWN_RETURN_DECISION')
        channel.record('operator_pending_cleanup', {'status': final_status, 'primary': primary,
                                                  'abort': abort, 'cleanup': cleanup})
    except BaseException as error:
        location = source_fault_location(error)
        failure = adapter.fault(error) if adapter is not None else None
        if primary is None:
            primary = failure.primary if failure is not None else getattr(error, 'primary', r.failure_code(error))
        else:
            abort.append(failure.primary if failure is not None else 'PUBLIC_BOOTSTRAP_FOLLOWUP_UNCONFIRMED')
            if failure is not None: abort.extend(failure.abort); cleanup.extend(failure.cleanup)
        final_status = 'HOLD'
    finally:
        if adapter is not None:
            try: cleanup.extend(adapter.close())
            except BaseException: cleanup.append('PUBLIC_BOOTSTRAP_OPERATOR_CLOSE_UNCONFIRMED')
        if cleanup: final_status = 'HOLD'
        # Cleanup is a separate hash-linked record, never inferred from a
        # pending receipt. Lost transport/durability leaves occupied HOLD.
        if claimed:
            try:
                channel.record('operator_cleanup', {'status': final_status, 'primary': primary,
                                                   'abort': abort, 'cleanup': cleanup})
            except BaseException:
                cleanup.append('PUBLIC_BOOTSTRAP_CLEANUP_RECORD_UNCONFIRMED'); final_status = 'HOLD'
        if channel.host_fd is not None:
            try: os.close(channel.host_fd)
            except OSError: cleanup.append('PUBLIC_BOOTSTRAP_MIRROR_CLOSE_UNCONFIRMED'); final_status = 'HOLD'
            channel.host_fd = None
        wire.send({'type': 'final', 'status': final_status, 'primary': primary,
                   'abort': abort, 'cleanup': cleanup, 'source_fault': location,
                   'r2_dispatch': False, 'slot_consumed': False})
