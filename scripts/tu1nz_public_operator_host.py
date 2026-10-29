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
        self.p = Paths(source.load('entry'), deadline=deadline)
        self.a = self.authority_type.__new__(self.authority_type)
        self.a.__init__(baseline, self.p, channel, machine=self.r.MACHINE, deadline=deadline)
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
        # Every original unit/drop-in/input/tool must be an exact expected source
        # object, not an object discovered and silently blessed during this run.
        required = {p for v in baseline['unit_files'].values() for p in [v['fragment'], *v['dropins']]}
        io.require(required <= set(baseline['files']) and not set(self.artifacts) & set(baseline['files']),
                   'ORIGINAL_CONFIG_SET_OR_FORWARD_ABSENCE')
        self.pre_stop()
        self.preparing = False; self.old_accepted.clear()

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
            r = command(['/usr/bin/systemctl', 'stop', unit], deadline)
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
            io.require(before['ActiveState'] == 'inactive' and before['MainPID'] == '0' and not before['Job'],
                       'START_BASELINE_NOT_FULLY_INACTIVE')
            self.channel.record('first_start_attempt', {'unit': unit, 'old_operation': old,
                'prior_invocation': before['InvocationID'], 'prior_restart_counter': before['NRestarts']})
            r = command(['/usr/bin/systemctl', 'start', unit], deadline)
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
