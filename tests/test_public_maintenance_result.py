"""Session result/custody component tests; no Host, Flow or native acceptance.

The fixtures do not run adapters or manufacture a native600s result. They test
actual local record writes/descriptor close and reject misleading completion.
"""
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
if hasattr(os, 'O_NOATIME'):
    import tu1nz_public_operator_host as host
else:
    with patch.object(os, 'O_NOATIME', 0, create=True):
        import tu1nz_public_operator_host as host
import tu1nz_public_bootstrap_r3 as r3


class LocalPeer:
    def __init__(self):
        self.deadline = time.monotonic()+60; self.sent = []; self.answer = None; self.read_deadline = None

    def send(self, value):
        self.sent.append(copy.deepcopy(value))

    def receive(self):
        self.read_deadline = self.deadline
        if self.answer is not None:return self.answer
        row = self.sent[-1]
        if row['type'] == 'durable_record':
            return {'type':'persisted', 'sequence':row['record']['sequence'], 'sha256':row['sha256']}
        raise AssertionError('unexpected component message')


class MaintenanceSessionResultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.wire = LocalPeer(); self.states = []

    def tearDown(self):
        for state in self.states:
            if not state.closed:
                try:state.close()
                except BaseException:pass
        self.temp.cleanup()

    def fixture(self, route='original'):
        state = host.MaintenanceSessionResult(self.wire, r3, route=route); self.states.append(state)
        if route == 'original':
            channel = io.MaintenanceLinkedRecords(self.wire,'a'*64,original_binding='a'*64,
                boot_id='00000000-0000-0000-0000-000000000001')
            flow_type = r3.MaintenanceFlow
        else:
            seed = {k:'a'*64 for k in ('original_binding','ready_sha256','source_sha256','artifact_sha256',
                'mac_tail_sha256','host_tail_sha256','original_failure_sha256','fresh_state_sha256')}
            seed.update(schema='TU1NZ_MAIN_SERVER_REV4_RECOVERY_ONCE',transaction=r3.TX,machine=r3.MACHINE,
                boot_id='00000000-0000-0000-0000-000000000001',owner_plan_sha256=r3.OWNER_PLAN,
                original_status='FAILED_HOLD',unconfirmed_mac_tail=None)
            channel = io.RecoveryLinkedRecords(self.wire,seed); flow_type = r3.RecoveryFlow
            # Simulate an already bound chain prefix only. No attach() to its
            # real fixed Host path, recovery admission or claim is performed.
            channel.sequence = 2; channel.previous = 'b'*64
        directory = self.root/str(len(self.states)); directory.mkdir(mode=0o700)
        channel.host_fd = os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        channel.owner_entry_started = True
        state.channel = channel; state.chain_started = True
        state.adapter = SimpleNamespace(owner_result={'status':'OWNER_COMPLETED','owner_acks':84,
            'cleanup_sha256':'c'*64},owner_admission_started=True,close=Mock(return_value=[]),r=r3)
        state.adapter.fault=lambda error:host.Adapter.fault(state.adapter,error)
        flow = flow_type.__new__(flow_type)  # inert component input, not an executed Flow
        flow.a=state.adapter;flow.j=SimpleNamespace(channel=channel,claimed=True,binding=channel.binding)
        flow.stage = state.ORIGINAL_COMPLETE if route == 'original' else state.RECOVERY_PENDING
        flow.hold=False;flow.owner_started=True;flow.deadline=self.wire.deadline
        return state,flow,directory

    def test_real_local_cleanup_record_and_owned_descriptor_end_precede_final(self):
        state,flow,root=self.fixture();fd=state.channel.host_fd
        state.completed(flow);result=state.close()
        self.assertEqual(result['status'],state.ORIGINAL_COMPLETE)
        row=json.loads((root/'001-operator_cleanup.json').read_bytes())
        self.assertEqual(row['value']['owner_completion_sha256'],io.sha(io.canonical(flow.a.owner_result)))
        self.assertTrue(row['value']['client_cleanup_still_required'])
        self.assertIsNone(result['original_evidence'])
        with self.assertRaises(OSError):os.fstat(fd)
        self.assertEqual(self.wire.sent[-1],result)
        with self.assertRaisesRegex(io.Hold,'CLOSE_ONCE'):state.close()

    def test_recovery_completion_keeps_original_hold_and_both_actual_tail_hashes(self):
        state,flow,root=self.fixture('recovery-once');original=copy.deepcopy(state.channel.seed)
        state.completed(flow)
        self.assertEqual(state.status,state.RECOVERY_PENDING)
        result=state.close();row=json.loads((root/'003-operator_cleanup.json').read_bytes())
        self.assertEqual(result['status'],state.RECOVERY_COMPLETE)
        self.assertEqual(result['original_status'],'FAILED_HOLD')
        self.assertEqual(result['original_evidence'],original)
        self.assertEqual(row['value']['original_evidence'],original)
        self.assertEqual(state.channel.seed,original)

    def test_bare_stage_wrong_flow_or_missing_actual_owner_cannot_complete(self):
        for change in ('mapping','hold','83acks','unknown_owner_cleanup','no_marker','unclaimed','detached'):
            state,flow,_=self.fixture()
            if change=='mapping':flow=vars(flow)
            elif change=='hold':flow.hold=True
            elif change=='83acks':state.adapter.owner_result['owner_acks']=83
            elif change=='unknown_owner_cleanup':state.adapter.owner_result['cleanup_sha256']=''
            elif change=='no_marker':state.channel.owner_entry_started=False
            elif change=='unclaimed':flow.j.claimed=False
            elif change=='detached':flow.a=SimpleNamespace()
            with self.subTest(change=change),self.assertRaises(io.Hold):state.completed(flow)
            self.assertEqual(state.close()['status'],'HOLD')

    def test_first_failure_and_cleanup_errors_are_never_erased_by_followup_failure(self):
        state,_,_=self.fixture('recovery-once')
        state.failure(r3.FlowFailure('PUBLIC_BOOTSTRAP_FIRST',abort=['PUBLIC_BOOTSTRAP_ABORT'],
                                   cleanup=['PUBLIC_BOOTSTRAP_CLEANUP']))
        state.failure(io.Hold('PUBLIC_OPERATOR_SECOND'))
        result=state.close()
        self.assertEqual(result['status'],'HOLD');self.assertEqual(result['primary'],'PUBLIC_BOOTSTRAP_FIRST')
        self.assertIn('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_SECOND',result['abort'])
        self.assertIn('PUBLIC_BOOTSTRAP_CLEANUP',result['cleanup'])
        self.assertEqual(result['original_status'],'FAILED_HOLD')

    def test_pending_success_cannot_survive_adapter_cleanup_error_or_lost_cleanup_ack(self):
        for failure in ('close','ack'):
            state,flow,_=self.fixture();state.completed(flow)
            if failure=='close':state.adapter.close.return_value=['PUBLIC_BOOTSTRAP_TEST_CLOSE_UNKNOWN']
            else:self.wire.answer={'type':'UNKNOWN_ACK'}
            with self.subTest(failure=failure):
                result=state.close();self.assertEqual(result['status'],'HOLD')
                self.assertTrue(result['cleanup']);self.assertIsNone(state.channel.host_fd)
            self.wire.answer=None

    def test_partial_adapter_failure_still_drains_owned_evidence_paths_and_mirror(self):
        state,_,_=self.fixture('recovery-once');fd=state.channel.host_fd
        state.adapter.close.side_effect=RuntimeError('synthetic no payload')
        state.adapter.evidence=SimpleNamespace(close=Mock(return_value=[]))
        state.adapter.p=SimpleNamespace(rows={1:'owned'},events=None,close=Mock(return_value=[]))
        result=state.close()
        state.adapter.evidence.close.assert_called_once();state.adapter.p.close.assert_called_once()
        self.assertEqual(result['status'],'HOLD')
        with self.assertRaises(OSError):os.fstat(fd)

    def test_expired_or_seed_changed_result_remains_hold_and_closes_mirror(self):
        for failure in ('expiry','seed'):
            state,flow,_=self.fixture('recovery-once');state.completed(flow);fd=state.channel.host_fd
            if failure=='expiry':self.wire.deadline=time.monotonic()-1
            else:state.channel.seed['original_status']='SUCCESS'
            with self.subTest(failure=failure):
                result=state.close();self.assertEqual(result['status'],'HOLD')
                with self.assertRaises(OSError):os.fstat(fd)
            self.wire.deadline=time.monotonic()+60

    def test_owner_return_uses_existing_owner_window_and_never_makes_hold_success(self):
        state,_,_=self.fixture();state.failure(io.Hold('PUBLIC_OPERATOR_ORIGINAL'))
        end=time.monotonic()+5
        owner=SimpleNamespace(attempted=True,deadline=end,return_once=Mock(),
                              finish=Mock(return_value={'status':'OWNER_RETURNED'}))
        state.adapter.owner=owner;self.wire.answer={'type':'decision','value':'OWNER_RETURN'}
        state.owner_return_or_hold()
        owner.return_once.assert_called_once();self.assertEqual(self.wire.read_deadline,end)
        self.assertFalse(self.wire.sent[-1]['return_available'])
        self.assertEqual(state.status,'HOLD');self.assertEqual(state.primary,'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_ORIGINAL')
        self.wire.answer=None;self.assertEqual(state.close()['status'],'HOLD')

    def test_old_return_unknown_confirmation_or_missing_owner_cannot_trigger_return(self):
        for decision in ('RETURN_OLD','UNKNOWN','OWNER_RETURN'):
            state,_,_=self.fixture();state.failure(io.Hold('PUBLIC_OPERATOR_ORIGINAL'))
            self.wire.answer={'type':'decision','value':decision}
            with self.subTest(decision=decision),self.assertRaises(io.Hold):state.owner_return_or_hold()
            self.assertFalse(self.wire.sent[-1]['return_available'])
            self.assertFalse(self.wire.sent[-1]['owner_return_available'])
            self.wire.answer=None;self.assertEqual(state.close()['status'],'HOLD')


if __name__ == '__main__':unittest.main()
