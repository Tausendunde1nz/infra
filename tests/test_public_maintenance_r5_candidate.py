"""Local candidate boundaries, not native isolation/timing or Host admission."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator as client
import tu1nz_public_operator_io as io
with patch.object(os, 'O_NOATIME', getattr(os, 'O_NOATIME', 0), create=True):
    import tu1nz_public_maintenance_r5_candidate as candidate
import tu1nz_public_bootstrap_r3 as r3
import tu1nz_public_operator_host as host
import tu1nz_public_runtime_transition as transition


class FlowTests(unittest.TestCase):
    def fixture(self, *, recovery=False, failed_action=None, failed_gate=None, state='F1', active=()):
        adapter = Mock(); adapter.deadline = time.monotonic()+500; adapter.owner_admission_started = False
        journal = Mock(); journal.binding = 'a'*64
        cls = candidate.R5RecoveryFlow if recovery else candidate.R5MaintenanceFlow
        effects = []; gates = []; limits = []; quiet = state != 'F1'
        def observe(phase, *, deadline):
            nonlocal quiet
            gates.append(phase)
            facts = set(cls.required[phase])
            if phase == 'recovery_admitted':facts.add(state)
            if phase == 'quiet':quiet = True
            if phase.startswith('recovery_state:'):
                unit = phase.split(':', 1)[1]
                facts.add('known_new_active' if quiet and unit in active else
                          'empty_inactive' if quiet else 'known_old_active')
            if phase == failed_gate:facts.clear()
            return r3.Observation(r3.TX, journal.binding, phase, frozenset(facts), time.monotonic())
        def perform(action, unit, *, deadline):
            effects.append((action, unit)); limits.append((action, deadline-time.monotonic()))
            if action == failed_action:return None
            return dict(action=action, unit=unit, outcome='CONFIRMED', cgroup_empty=True, no_job=True)
        adapter.observe.side_effect = observe; adapter.perform.side_effect = perform
        return cls(adapter, journal), adapter, journal, effects, gates, limits

    def run_flow(self, flow):
        return flow.recover() if isinstance(flow, candidate.R5RecoveryFlow) else flow.forward()

    def test_original_keeps_protection_restore_probes_and_exact_restart_order(self):
        flow, _, journal, effects, gates, limits = self.fixture()
        self.assertEqual(flow.forward(), candidate.ORIGINAL_COMPLETE)
        names = [a for a, _ in effects]
        required = ['prepare_runtime_bundle', 'create_persistent_barriers', 'stop',
                    'protected_rights_backup', 'isolated_restore_rehearsal',
                    'bounded_synthetic_probes', 'install_four_artifacts', 'start']
        self.assertEqual([names.index(x) for x in required], sorted(names.index(x) for x in required))
        self.assertEqual([u for a, u in effects if a == 'stop'], list(r3.STOP))
        self.assertEqual([u for a, u in effects if a == 'start'], list(r3.UNITS))
        self.assertEqual(gates[-2:], ['rights', 'r5_finish'])
        self.assertFalse(flow.owner_started); self.assertFalse(any('owner' in x for x in names+gates))
        for action, remaining in limits:self.assertLessEqual(remaining, 20 if action in ('stop','start') else 120)
        journal.write.assert_any_call('complete',dict(stage=candidate.ORIGINAL_COMPLETE,r2_dispatch=False,slot_consumed=False))
        with self.assertRaises(r3.Denied):flow.forward()
        with self.assertRaises(r3.Denied):flow.return_old()
        with self.assertRaises(r3.Denied):flow.r2_eligibility()

    def test_all_recovery_states_keep_single_entry_and_no_repeat_of_active_unit(self):
        for state in ('F1','F2','F3','F4'):
            with self.subTest(state=state):
                flow, _, journal, effects, gates, _ = self.fixture(recovery=True,state=state,
                    active=(r3.UNITS[0],) if state == 'F4' else ())
                self.assertEqual(flow.recover(), candidate.RECOVERY_PENDING)
                self.assertFalse(flow.owner_started); self.assertTrue(flow.recovery_used)
                self.assertFalse(any('owner' in a for a, _ in effects))
                self.assertEqual(gates[-2:], ['rights','r5_finish'])
                starts = [u for a,u in effects if a == 'recovery_start']
                self.assertEqual(starts, list(r3.UNITS[1:] if state == 'F4' else r3.UNITS))
                complete = [c.args[1] for c in journal.write.call_args_list if c.args[0] == 'complete']
                self.assertEqual(complete[0]['original'], 'FAILED_HOLD')
                with self.assertRaises(r3.Denied):flow.recover()
                with self.assertRaises(r3.Denied):flow.forward()
                with self.assertRaises(r3.Denied):flow.return_old()

    def test_protection_and_function_failures_remain_hold_without_owner_or_success(self):
        for recovery, actions in ((False, ('protected_rights_backup','isolated_restore_rehearsal','start')),
                                 (True, ('recovery_private_backup','recovery_private_restore','recovery_start'))):
            for action, gate in [(x,None) for x in actions]+[(None,'rights'),(None,'r5_finish')]:
                with self.subTest(recovery=recovery, action=action, gate=gate):
                    flow, adapter, journal, effects, _, _ = self.fixture(recovery=recovery,
                        failed_action=action,failed_gate=gate)
                    with self.assertRaises(r3.FlowFailure):self.run_flow(flow)
                    self.assertTrue(flow.hold); self.assertFalse(flow.owner_started)
                    self.assertFalse(any('owner' in a for a, _ in effects))
                    self.assertFalse(any(c.args[0]=='complete' for c in journal.write.call_args_list))
                    with self.assertRaises(r3.Denied):self.run_flow(flow)
                    if recovery and (action=='recovery_start' or gate):adapter.hold_known_new_units.assert_called_once()

    def test_expiry_or_lost_complete_ack_cannot_confer_success(self):
        for recovery in (False,True):
            for fault in ('expiry','ack'):
                flow, _, journal, _, _, _ = self.fixture(recovery=recovery)
                def write(kind,value):
                    if kind == 'complete':
                        if fault=='ack':raise OSError('synthetic lost persistence')
                        flow.deadline=time.monotonic()-1
                journal.write.side_effect=write
                with self.subTest(recovery=recovery,fault=fault), self.assertRaises(r3.FlowFailure):self.run_flow(flow)
                self.assertTrue(flow.hold)

    def test_owner_operations_rejected_before_adapter_or_journal(self):
        flow, adapter, journal, _, _, _ = self.fixture()
        for phase in ('owner_ready','owner_done'):
            with self.assertRaises(r3.Denied):flow.witness(phase)
        with self.assertRaises(r3.Denied):flow.effect('supervised_owner_transaction')
        adapter.observe.assert_not_called(); adapter.perform.assert_not_called(); journal.write.assert_not_called()


class AdapterFinishTests(unittest.TestCase):
    def fixture(self, recovery=False):
        cls=candidate.R5RecoveryAdapter if recovery else candidate.R5MaintenanceAdapter
        a=cls.__new__(cls); a.r=r3; a.binding='a'*64; a.deadline=time.monotonic()+60
        a.owner=a.owner_result=a.pending=None; a.owner_admission_started=False; a.failed=False
        a.channel=Mock(); a.channel.owner_entry_started=False; a.channel.ceiling=a.deadline
        a.replacement_ready=True; a.a=Mock(); a.a.replacement_active=True
        a.a.runtime=transition.ReplacementFence.__new__(transition.ReplacementFence)
        a.a.b={'http':{'lighting':{'synthetic':'expectation'}}}
        a.now=Mock();a.check_prepared_state=Mock();a.p=Mock()
        a.backup=SimpleNamespace(files={'/synthetic':'b'*64},root=host.STAGING)
        a.backup_hash=a.restore_hash='c'*64
        a.probes=Mock();a.probes.cleanup_complete=True;a.probes.unconfirmed=[];a.probes.reports=[]
        a.probe_hash=io.sha(io.canonical([]));a.accepted={u:{'unit':u} for u in r3.UNITS}
        a.read_witness={'site_read_witness_sha256':'d'*64};a.site_read_witness=Mock(return_value='d'*64)
        a.check_probe_current=Mock()
        return a

    def exercise(self, a, *, read_error=False, rights_error=False):
        # Only native-dependent readers are replaced. The new terminal gate
        # itself executes; existing native reader parity remains a separate gate.
        parent=transition.RecoveryAdapter if isinstance(a,transition.RecoveryAdapter) else transition.MaintenanceAdapter
        with patch.object(parent,'_observe',side_effect=io.Hold('PUBLIC_OPERATOR_TEST_RIGHTS') if rights_error else None) as rights, \
             patch.object(candidate,'Backup') as backup:
            backup.return_value.load_verified_existing.side_effect=OSError('synthetic read error') if read_error else None
            backup.return_value.load_verified_existing.return_value={'manifest_sha256':'c'*64}
            value=a._observe('r5_finish',deadline=a.deadline)
            rights.assert_called_once_with('rights',deadline=a.deadline)
            backup.return_value.load_verified_existing.assert_called_once_with(expected_sha256='c'*64)
            return value

    def test_fresh_function_and_independent_backup_readback_required_for_both_routes(self):
        for recovery in (False,True):
            a=self.fixture(recovery);result=self.exercise(a)
            self.assertEqual(result.facts,candidate.FINISH_FACTS)
            self.assertFalse(a.r5_completion['owner_entered'])
            a.channel.record.assert_called_once_with('r5_completion',a.r5_completion)
            a.site_read_witness.assert_called_once();a.channel.http.assert_called_once()
            if recovery:a.check_probe_current.assert_called_once()
            else:a.probes.check_retained.assert_called_once()

    def test_missing_or_changed_protection_never_creates_completion(self):
        for fault in ('backup','restore','probe','owner','marker','pending','runtime','lighting','expiry','read','rights'):
            with self.subTest(fault=fault):
                a=self.fixture()
                if fault=='backup':a.backup=None
                if fault=='restore':a.restore_hash='e'*64
                if fault=='probe':a.probes.unconfirmed=['test']
                if fault=='owner':a.owner=object()
                if fault=='marker':a.channel.owner_entry_started=True
                if fault=='pending':a.pending=('unknown',None)
                if fault=='runtime':a.a.replacement_active=False
                if fault=='lighting':a.site_read_witness.return_value='e'*64
                if fault=='expiry':a.deadline=time.monotonic()-1
                with self.assertRaises((io.Hold,OSError)):self.exercise(a,read_error=fault=='read',rights_error=fault=='rights')
                self.assertIsNone(a.r5_completion);a.channel.record.assert_not_called()

    def test_adapter_also_rejects_direct_owner_invocation(self):
        a=self.fixture()
        with self.assertRaises(io.Hold):a.observe('owner_ready',deadline=a.deadline)
        with self.assertRaises(io.Hold):a.perform('supervised_owner_transaction',None,deadline=a.deadline)

    def test_lost_finish_receipt_ack_does_not_set_completion(self):
        a=self.fixture();a.channel.record.side_effect=io.Hold('PUBLIC_OPERATOR_CLIENT_CUSTODY_ACK_LOST')
        with self.assertRaises(io.Hold):self.exercise(a)
        self.assertIsNone(a.r5_completion)


class LocalPeer:
    def __init__(self):self.deadline=time.monotonic()+60;self.sent=[];self.fail_ack=False;self.fail_final=False
    def send(self,row):
        if row['type']=='final' and self.fail_final:raise BrokenPipeError('synthetic closed pipe')
        self.sent.append(copy.deepcopy(row))
    def receive(self):
        if self.fail_ack:return {'type':'UNKNOWN'}
        row=self.sent[-1]
        return dict(type='persisted',sequence=row['record']['sequence'],sha256=row['sha256'])


class SessionCleanupTests(unittest.TestCase):
    def fixture(self,recovery=False, *, record=True):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        wire=LocalPeer();route='recovery-once' if recovery else 'original'
        state=candidate.R5SessionResult(wire,r3,route=route)
        if recovery:
            seed={k:'a'*64 for k in ('original_binding','ready_sha256','source_sha256','artifact_sha256',
                'mac_tail_sha256','host_tail_sha256','original_failure_sha256','fresh_state_sha256')}
            seed.update(schema='TU1NZ_MAIN_SERVER_REV4_RECOVERY_ONCE',transaction=r3.TX,machine=r3.MACHINE,
                boot_id='00000000-0000-0000-0000-000000000001',owner_plan_sha256=r3.OWNER_PLAN,
                original_status='FAILED_HOLD',unconfirmed_mac_tail=None)
            channel=io.RecoveryLinkedRecords(wire,seed);channel.sequence=2;channel.previous='b'*64
        else:channel=io.MaintenanceLinkedRecords(wire,'a'*64,original_binding='a'*64,
                    boot_id='00000000-0000-0000-0000-000000000001')
        channel.host_fd=os.open(temp.name,os.O_RDONLY|os.O_DIRECTORY)
        state.channel=channel;state.chain_started=True
        cls=candidate.R5RecoveryAdapter if recovery else candidate.R5MaintenanceAdapter
        a=state.adapter=cls.__new__(cls);a.r=r3;a.owner=a.owner_result=None;a.owner_admission_started=False
        a.close=Mock(return_value=[])
        a.r5_completion=dict(schema='TU1NZ_R5_INDEPENDENT_COMPLETION_CANDIDATE_V1',binding=channel.binding,
                             owner_entered=False,publication_authorized=False)
        fc=candidate.R5RecoveryFlow if recovery else candidate.R5MaintenanceFlow
        flow=fc.__new__(fc);flow.a=a;flow.j=SimpleNamespace(channel=channel,claimed=True,binding=channel.binding)
        flow.stage=candidate.RECOVERY_PENDING if recovery else candidate.ORIGINAL_COMPLETE
        flow.hold=False;flow.owner_started=False;flow.current_gate='r5_finish';flow.deadline=wire.deadline
        # Real linked record and durable local mirror; no fake native/Host Flow.
        if record:channel.record('r5_completion',a.r5_completion)
        self.addCleanup(lambda:state.close() if not state.closed else None)
        return state,flow,wire,Path(temp.name)

    def test_executed_flows_and_durable_journals_feed_the_same_completion_and_close(self):
        for recovery in (False,True):
            state,_,wire,root=self.fixture(recovery,record=False);a=state.adapter;a.deadline=wire.deadline
            cls=candidate.R5RecoveryFlow if recovery else candidate.R5MaintenanceFlow
            journal=host.RecoveryRemoteJournal(state.channel) if recovery else host.RemoteJournal(state.channel,state.channel.binding)
            def observe(phase,*,deadline):
                facts=set(cls.required[phase])
                if phase=='recovery_admitted':facts.add('F4')
                if phase.startswith('recovery_state:'):facts.add('known_new_active')
                if phase=='r5_finish':state.channel.record('r5_completion',a.r5_completion)
                return r3.Observation(r3.TX,state.channel.binding,phase,frozenset(facts),time.monotonic())
            a.observe=Mock(side_effect=observe)
            a.perform=Mock(side_effect=lambda action,unit,**kw:dict(action=action,unit=unit,
                outcome='CONFIRMED',cgroup_empty=True,no_job=True))
            flow=cls(a,journal)
            flow.recover() if recovery else flow.forward()
            state.completed(flow);final=state.close()
            rows=[json.loads(p.read_bytes()) for p in sorted(root.glob('*.json'))]
            kinds=[v['kind'] for v in rows]
            self.assertLess(kinds.index('r5_completion'),kinds.index('operator_cleanup'))
            self.assertEqual(kinds[-2:],[('recovery_flow_complete' if recovery else 'flow_complete'),'operator_cleanup'])
            self.assertEqual(sum(k=='owner_object_intent' for k in kinds),0)
            self.assertEqual(sum(k=='owner_object_ack' for k in kinds),0)
            self.assertEqual(final['cleanup'],[]);self.assertFalse(flow.owner_started)

    def test_both_routes_persist_cleanup_close_descriptor_then_send_distinct_final(self):
        for recovery in (False,True):
            state,flow,wire,root=self.fixture(recovery);fd=state.channel.host_fd
            state.completed(flow);result=state.close()
            self.assertEqual(result['status'],candidate.RECOVERY_COMPLETE if recovery else candidate.ORIGINAL_COMPLETE)
            row=json.loads(next(root.glob('*-operator_cleanup.json')).read_bytes())
            self.assertEqual(row['value']['r5_completion_sha256'],result['r5_completion_sha256'])
            self.assertIsNone(result['owner_completion_sha256']);self.assertTrue(result['client_cleanup_still_required'])
            self.assertFalse(result['publication_authorized']);self.assertEqual(wire.sent[-1],result)
            self.assertEqual(result['original_status'],'FAILED_HOLD' if recovery else 'THIS_RUN')
            with self.assertRaises(OSError):os.fstat(fd)
            with self.assertRaises(io.Hold):state.close()
            self.assertFalse(any('owner' in x.name for x in root.iterdir()))

    def test_cleanup_error_lost_ack_and_deadline_remain_hold(self):
        for fault in ('cleanup','ack','deadline'):
            state,flow,wire,root=self.fixture();fd=state.channel.host_fd;state.completed(flow)
            if fault=='cleanup':state.adapter.close.return_value=['PUBLIC_BOOTSTRAP_TEST_CLEANUP']
            if fault=='ack':wire.fail_ack=True
            if fault=='deadline':wire.deadline=time.monotonic()-1
            result=state.close();self.assertEqual(result['status'],'HOLD');self.assertTrue(result['cleanup'])
            with self.assertRaises(OSError):os.fstat(fd)
            self.assertTrue(list(root.glob('*-r5_completion.json')))

    def test_missing_final_does_not_become_a_received_success(self):
        state,flow,wire,_=self.fixture();state.completed(flow);fd=state.channel.host_fd;wire.fail_final=True
        with self.assertRaises(BrokenPipeError):state.close()
        self.assertEqual(state.status,'HOLD');self.assertIn('PUBLIC_BOOTSTRAP_R5_CLOSE_UNCONFIRMED',state.cleanup)
        self.assertFalse(any(x['type']=='final' for x in wire.sent))
        with self.assertRaises(OSError):os.fstat(fd)

    def test_primary_and_cleanup_survive_failed_flow(self):
        state,_,_,_=self.fixture(True)
        state.failure(r3.FlowFailure('PUBLIC_BOOTSTRAP_TEST_FAILURE',cleanup=['PUBLIC_BOOTSTRAP_TEST_CLEANUP']))
        result=state.close();self.assertEqual(result['status'],'HOLD')
        self.assertEqual(result['primary'],'PUBLIC_BOOTSTRAP_TEST_FAILURE')
        self.assertIn('PUBLIC_BOOTSTRAP_TEST_CLEANUP',result['cleanup'])
        self.assertEqual(result['original_status'],'FAILED_HOLD')

    def test_owner_receipt_missing_r5_receipt_or_detached_flow_never_accepted(self):
        for fault in ('owner','marker','receipt','flow','held'):
            state,flow,_,_=self.fixture()
            if fault=='owner':state.adapter.owner_result=dict(status='OWNER_COMPLETED',owner_acks=84)
            if fault=='marker':state.channel.owner_entry_started=True
            if fault=='receipt':state.adapter.r5_completion=None
            if fault=='flow':flow.a=object()
            if fault=='held':flow.hold=True
            with self.assertRaises(io.Hold):state.completed(flow)
            self.assertEqual(state.close()['status'],'HOLD')

    def test_candidate_is_not_selected_by_existing_source_package_or_dispatcher(self):
        self.assertNotIn('scripts/tu1nz_public_maintenance_r5_candidate.py',client.INFRA_FILES.values())
        self.assertNotEqual(candidate.ORIGINAL_COMPLETE,host.MaintenanceSessionResult.ORIGINAL_COMPLETE)


if __name__=='__main__':unittest.main()
