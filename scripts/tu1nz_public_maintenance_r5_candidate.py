"""Local independent R5 completion candidate; NOT an admitted Host entry.

No CLI, source-package registration or dispatcher selection. Integration needs
its own scope/material, client acceptance and native timing contract. Existing
entries keep their Owner contract and cannot accept these new status values.
The existing adapters/flows supply all protection, action and restart gates.
"""
import time

import tu1nz_public_operator_io as io
import tu1nz_public_bootstrap_r3 as r3
import tu1nz_public_operator_host as host
import tu1nz_public_runtime_transition as transition
from tu1nz_public_operator_fs import Backup


ORIGINAL_COMPLETE = 'R5_ISOLATION_RECEIPTED_R2_NOT_DISPATCHED'
RECOVERY_PENDING = 'RECOVERY_R5_ISOLATION_RECEIPTED_PENDING_OPERATOR_CLEANUP'
RECOVERY_COMPLETE = 'RECOVERY_R5_ISOLATION_RECEIPTED_ORIGINAL_HOLD_R2_NOT_DISPATCHED'
FINISH_FACTS = frozenset(('current_three_isolated_functional_invocations',
    'protected_backup_and_restored_copy_freshly_read', 'probe_cleanup_current',
    'lighting_read_witness_current_no_owner_entry', 'existing_entry_deadline'))


class _IndependentFinish:
    def witness(self, phase):
        r3.require(phase not in ('owner_ready', 'owner_done'), 'R5_OWNER_PHASE_FORBIDDEN')
        return super().witness(phase)

    def effect(self, name, unit=None):
        r3.require(name != 'supervised_owner_transaction', 'R5_OWNER_ACTION_FORBIDDEN')
        return super().effect(name, unit)

    def complete_after_rights(self):
        r3.require(not self.owner_started and self.stage in
                   ('RIGHTS_ACCEPTED', 'RECOVERY_RIGHTS_ACCEPTED'), 'R5_FINISH_ORDER')
        self.witness('r5_finish')
        self.stage = self.completion_stage

    def r2_eligibility(self):
        raise r3.Denied('PUBLIC_BOOTSTRAP_R5_COMPLETION_IS_NOT_PUBLICATION_AUTHORITY')


class R5MaintenanceFlow(_IndependentFinish, r3.MaintenanceFlow):
    required = {**r3.MaintenanceFlow.required, 'r5_finish': FINISH_FACTS}
    completion_stage = ORIGINAL_COMPLETE


class R5RecoveryFlow(_IndependentFinish, r3.RecoveryFlow):
    required = {**r3.RecoveryFlow.required, 'r5_finish': FINISH_FACTS}
    completion_stage = RECOVERY_PENDING


class _R5AdapterFinish:
    """Fresh terminal witness using the existing protected readers only."""
    def observe(self, phase, *, deadline):
        io.require(phase not in ('owner_ready', 'owner_done'), 'R5_OWNER_PHASE_FORBIDDEN')
        return super().observe(phase, deadline=deadline)

    def perform(self, action, unit, *, deadline):
        io.require(action != 'supervised_owner_transaction', 'R5_OWNER_ACTION_FORBIDDEN')
        return super().perform(action, unit, deadline=deadline)

    def _observe(self, phase, *, deadline):
        if phase != 'r5_finish':return super()._observe(phase, deadline=deadline)
        self.r5_completion = None
        self.now()
        io.require(self.owner is None and self.owner_result is None and
                   self.owner_admission_started is False and self.channel.owner_entry_started is False and
                   self.pending is None and not self.failed and
                   self.replacement_ready and self.a.replacement_active and
                   isinstance(self.a.runtime, transition.ReplacementFence), 'R5_FINISH_STATE')
        self.channel.check(); self.check_prepared_state()
        # Includes fresh Authority, kernel rights, DB/data/HTTP and all three
        # actual invocations; old accepted dictionaries alone cannot pass.
        super()._observe('rights', deadline=deadline)
        io.require(self.backup is not None and self.backup_hash is not None and
                   self.restore_hash == self.backup_hash and self.probe_hash is not None,
                   'R5_BACKUP_RESTORE_OR_PROBES_MISSING')
        current = Backup(self.p, self.backup.files, self.backup.root, self.a.check)
        readback = current.load_verified_existing(expected_sha256=self.backup_hash)
        if isinstance(self, transition.RecoveryAdapter):
            self.check_probe_current()
        else:
            io.require(self.probes is not None and self.probes.cleanup_complete and not self.probes.unconfirmed and
                       io.sha(io.canonical(self.probes.reports)) == self.probe_hash,
                       'R5_PROBE_CLEANUP_UNCONFIRMED')
            self.probes.check_retained()
        lighting = self.site_read_witness()
        io.require(lighting == self.read_witness['site_read_witness_sha256'], 'R5_LIGHTING_READ_WITNESS_CHANGED')
        self.channel.http(self.a.b['http']['lighting'])
        self.a.check(); self.channel.check(); self.now()
        io.require(time.monotonic() < min(deadline, self.deadline, self.channel.ceiling), 'R5_FINISH_DEADLINE')
        receipt = {'schema': 'TU1NZ_R5_INDEPENDENT_COMPLETION_CANDIDATE_V1',
            'binding': self.binding, 'backup_readback': readback,
            'functions_sha256': io.sha(io.canonical(self.accepted)),
            'probes_sha256': self.probe_hash, 'lighting_read_witness_sha256': lighting,
            'owner_entered': False, 'publication_authorized': False}
        self.channel.record('r5_completion', receipt)
        self.now()
        self.r5_completion = receipt
        return self.r.Observation(self.r.TX, self.binding, phase, FINISH_FACTS, time.monotonic())


class R5MaintenanceAdapter(_R5AdapterFinish, transition.MaintenanceAdapter):
    pass


class R5RecoveryAdapter(_R5AdapterFinish, transition.RecoveryAdapter):
    pass


class R5SessionResult(host.MaintenanceSessionResult):
    """New completion candidate, drained by the unchanged resource lifecycle.

Host cleanup/final never proves client receipt or process end. Both remain
mandatory for the future integrated client/native acceptance contract.
"""
    ORIGINAL_COMPLETE = ORIGINAL_COMPLETE
    RECOVERY_PENDING = RECOVERY_PENDING
    RECOVERY_COMPLETE = RECOVERY_COMPLETE

    def __init__(self, wire, module, *, route):
        super().__init__(wire, module, route=route)
        self.r5_completion = None

    def completed(self, flow):
        flow_type = R5MaintenanceFlow if self.route == 'original' else R5RecoveryFlow
        adapter_type = R5MaintenanceAdapter if self.route == 'original' else R5RecoveryAdapter
        channel_type = io.MaintenanceLinkedRecords if self.route == 'original' else io.RecoveryLinkedRecords
        expected = self.ORIGINAL_COMPLETE if self.route == 'original' else self.RECOVERY_PENDING
        io.require(not self.closed and type(flow) is flow_type and type(self.adapter) is adapter_type and flow.a is self.adapter and
                   type(self.channel) is channel_type and flow.j.channel is self.channel and self.chain_started and
                   self.channel.host_fd is not None and flow.j.claimed and flow.j.binding == self.channel.binding and
                   flow.stage == expected and flow.hold is False and flow.owner_started is False and
                   self.primary is None and not self.abort and not self.cleanup and
                   self.adapter.owner is None and self.adapter.owner_result is None and
                   self.adapter.owner_admission_started is False and self.channel.owner_entry_started is False,
                   'R5_COMPLETION_NOT_CURRENT_FLOW')
        receipt = getattr(self.adapter, 'r5_completion', None)
        io.require(type(receipt) is dict and receipt.get('schema') == 'TU1NZ_R5_INDEPENDENT_COMPLETION_CANDIDATE_V1' and
                   receipt.get('binding') == self.channel.binding and receipt.get('owner_entered') is False and
                   receipt.get('publication_authorized') is False and
                   flow.current_gate == 'r5_finish' and
                   time.monotonic() < min(self.wire.deadline, self.channel.ceiling, flow.deadline),
                   'R5_COMPLETION_RECEIPT_OR_DEADLINE')
        self.r5_completion = io.sha(io.canonical(receipt))
        self.status = expected

    def completion_fields(self):
        return {'owner_completion_sha256': None, 'r5_completion_sha256': self.r5_completion,
                'publication_authorized': False}

    def close(self):
        try:return super().close()
        except BaseException:
            # A durable cleanup candidate is not a received final. Do not send
            # again, reset a channel/claim or erase an earlier primary fault.
            self.status = 'HOLD'
            if self.primary is None:self.primary = 'PUBLIC_BOOTSTRAP_R5_CLOSE_UNCONFIRMED'
            if 'PUBLIC_BOOTSTRAP_R5_CLOSE_UNCONFIRMED' not in self.cleanup:
                self.cleanup.append('PUBLIC_BOOTSTRAP_R5_CLOSE_UNCONFIRMED')
            raise
