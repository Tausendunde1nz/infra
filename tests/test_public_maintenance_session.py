"""Orchestration-only tests with inert adapters/channels; NOT native admission.

No fixed path is opened, no privileged operation or claim is performed. The
completion evaluator is separately tested; these fixtures always finish HOLD.
"""
import os
from pathlib import Path
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from contextlib import ExitStack, contextmanager

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator as client
import tu1nz_public_operator_io as io
if hasattr(os,'O_NOATIME'):
    import tu1nz_public_operator_host as host
else:
    with patch.object(os,'O_NOATIME',0,create=True):import tu1nz_public_operator_host as host
import tu1nz_public_bootstrap_r3 as r3


class SessionOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.events=[];self.fail=None;self.end=time.monotonic()+100
        self.boot='00000000-0000-0000-0000-000000000001'
        self.bound={'coverage':{'inert':True},'plan':b'SYNTHETIC_PLAN_NOT_USED','inputs':{'source_sha256':'b'*64},
            'timing':{'after_ready_seconds':300,'terminal_prepare_seconds':20,'terminal_cleanup_seconds':20}}

    @contextmanager
    def fixture(self, route):
        events=self.events;outer=self;io_sha=io.sha
        def hit(name):
            events.append(name)
            if outer.fail==name:raise io.Hold('PUBLIC_OPERATOR_SYNTHETIC_PHASE_FAILURE')
        class Wire:
            deadline=outer.end
            def send(self,value):
                self.last=value;hit('send:'+value['type'])
            def receive(self):
                kind=self.last['type'];hit('receive:'+kind)
                if kind=='prepared':return {'type':'client_custody_created','binding':'a'*64}
                if kind=='recovery_prepared':return {'type':'recovery_custody_bound','binding':io.recovery_binding(self.last['seed'])}
                if kind=='held':return {'type':'decision','value':'HOLD'}
                raise AssertionError(kind)
        wire=Wire()
        class Channel:
            def __init__(self,wire,binding,**kwargs):
                self.wire=wire;self.ceiling=wire.deadline;self.binding=binding;self.host_fd=None
                self.approval_bound=False;self.owner_entry_started=False;hit('original_channel')
            def record(self,kind,value):hit('record:'+kind)
            @contextmanager
            def limit(self,end):
                assert end<=self.ceiling
                yield
        class Admission(Channel):
            def __init__(self,wire,**kwargs):
                self.wire=wire;self.ceiling=wire.deadline;self.binding=kwargs['original_binding'];self.host_fd=None
                hit('admission_channel')
        class RecoveryChannel(Channel):
            def __init__(self,wire,seed):
                self.wire=wire;self.ceiling=wire.deadline;self.seed=seed
                self.binding=io.recovery_binding(seed);self.host_fd=None;self.approval_bound=False
                hit('recovery_channel')
            def attach(self,fd):assert fd=='INERT_TEST_DIRECTORY';hit('attach_recovery_chain')
        class InertPaths:
            def __init__(self,entry,*,deadline):
                self.rows={'INERT':'owned'};self.events=None;self.deadline=deadline;hit('paths_init')
            def read(self,path):
                assert path=='/etc/machine-id';hit('machine_read');return b'SYNTHETIC_MACHINE',{}
            def get(self,path):
                assert path==host.RecoveryHostEntry.ROOT+'/intents';return 'INERT_TEST_DIRECTORY'
            def close(self):hit('paths_close');self.rows.clear();return []
        class HostEntry:
            ROOT=host.RecoveryHostEntry.ROOT
            def __init__(self,*args,**kwargs):hit('entry_create')
            def confirm(self,wire):hit('entry_confirm')
            def check(self):hit('entry_check')
        class Evidence:
            def __init__(self,*args,**kwargs):
                self.ready_raw=b'SYNTHETIC_READY';self.ready={'artifact_sha256':'c'*64}
                self.failure={'synthetic_original_failure':True}
                self.pair={'mac_tail_sha256':'d'*64,'host_tail_sha256':'e'*64,'unconfirmed_mac_tail':None}
                hit('evidence_init')
            def check_original(self):hit('evidence_check')
            def close(self):hit('evidence_close');return []
        class Adapter:
            def __init__(self,*args,**kwargs):
                assert kwargs['deadline']==outer.end
                self.read_witness={'synthetic_readonly':True};self.owner=None
                self.recovery_state_proof={'synthetic_current_state':True};hit('adapter_init')
            def bind_execution(self,channel):assert channel.approval_bound;hit('bind_execution')
            def fault(self,error):return r3.FlowFailure(getattr(error,'primary',r3.failure_code(error)))
            def close(self):hit('adapter_close');return []
        class OriginalFlow:
            def __init__(self,adapter,journal):
                hit('original_flow_init');journal.claim()
            def forward(self):hit('forward')
        class RecoveryFlow:
            def __init__(self,adapter,journal):hit('recovery_flow_init');journal.claim()
            def recover(self):hit('recover')
            def forward(self):raise AssertionError('NO ORIGINAL FORWARD')
        r=SimpleNamespace(MACHINE=r3.MACHINE,TX=r3.TX,OWNER_PLAN=r3.OWNER_PLAN,
            failure_code=r3.failure_code,MaintenanceFlow=OriginalFlow,RecoveryFlow=RecoveryFlow)
        replacement=SimpleNamespace(MaintenanceAdapter=Adapter,RecoveryAdapter=Adapter,RecoveryOriginalEvidence=Evidence)
        source=SimpleNamespace(load=lambda n:{'r3':r,'artifact':None,'replacement':replacement,'entry':None}[n])
        packet={'route':route,'binding':'a'*64,'baseline':{'boot_id':self.boot},
                'recovery':{'entry':{'ready_sha256':'f'*64},'manifest':{'snapshot_sha256':'1'*64}}}
        with ExitStack() as stack:
            stack.enter_context(patch.object(host,'maintenance_session_setup',side_effect=lambda *a,**k:(hit('setup'),outer.bound)[1]))
            stack.enter_context(patch.object(io,'maintenance_packet_binding',side_effect=lambda *a,**k:hit('packet_recheck')))
            stack.enter_context(patch.object(host,'Paths',InertPaths))
            stack.enter_context(patch.object(host,'RecoveryHostEntry',HostEntry))
            stack.enter_context(patch.object(io,'MaintenanceLinkedRecords',Channel))
            stack.enter_context(patch.object(io,'RecoveryAdmissionChannel',Admission))
            stack.enter_context(patch.object(io,'RecoveryLinkedRecords',RecoveryChannel))
            stack.enter_context(patch.object(host.Path,'read_text',return_value=outer.boot))
            stack.enter_context(patch.object(io,'sha',side_effect=lambda raw:r3.MACHINE if raw==b'SYNTHETIC_MACHINE' else io_sha(raw)))
            stack.enter_context(patch.object(host.MaintenanceSessionResult,'completed',side_effect=lambda f:hit('candidate_only_not_acceptance')))
            yield source,packet,wire

    def test_original_order_rechecks_before_custody_and_only_calls_original_flow(self):
        with self.fixture('original') as values:result=host.maintenance_session(*values)
        self.assertEqual(result['status'],'HOLD')  # fixture cannot grant acceptance
        ordered=['setup','original_channel','adapter_init','packet_recheck','send:prepared','receive:prepared',
                 'record:prestate_read_witness','original_flow_init','record:flow_claim','forward',
                 'candidate_only_not_acceptance','record:operator_pending_cleanup','adapter_close',
                 'record:operator_cleanup','send:final']
        self.assertEqual(self.events,ordered)

    def test_original_partial_admission_and_flow_faults_close_without_recovery_or_replay(self):
        for failure in ('setup','adapter_init','packet_recheck','receive:prepared','forward'):
            self.events=[];self.fail=failure
            with self.subTest(failure=failure),self.fixture('original') as values:
                result=host.maintenance_session(*values)
            self.assertEqual(result['status'],'HOLD');self.assertIsNotNone(result['primary'])
            self.assertLessEqual(self.events.count('forward'),1)
            self.assertNotIn('recover',self.events);self.assertNotIn('entry_create',self.events)
            if 'adapter_init' in self.events:self.assertIn('adapter_close',self.events)

    def test_recovery_entry_precedes_fresh_evidence_and_own_binding_precedes_flow(self):
        with self.fixture('recovery-once') as values:result=host.recovery_session(*values)
        self.assertEqual(result['status'],'HOLD');self.assertEqual(result['original_status'],'FAILED_HOLD')
        ordered=['entry_create','entry_confirm','evidence_init','admission_channel','adapter_init',
                 'packet_recheck','entry_check','evidence_check','recovery_channel','send:recovery_prepared',
                 'receive:recovery_prepared','attach_recovery_chain','record:recovery_context','bind_execution',
                 'recovery_flow_init','record:recovery_flow_claim','recover','candidate_only_not_acceptance',
                 'record:operator_pending_cleanup','adapter_close','evidence_close','paths_close','record:operator_cleanup']
        positions=[self.events.index(v) for v in ordered];self.assertEqual(positions,sorted(positions))
        for forbidden in ('forward','original_flow_init','record:flow_claim','send:prepared','record:prestate_read_witness'):
            self.assertNotIn(forbidden,self.events)
        self.assertEqual(result['original_evidence']['host_tail_sha256'],'e'*64)
        self.assertEqual(result['original_evidence']['mac_tail_sha256'],'d'*64)

    def test_recovery_partial_failures_consume_at_most_one_entry_and_close_owned_paths(self):
        for failure in ('entry_create','entry_confirm','evidence_init','adapter_init',
                        'receive:recovery_prepared','attach_recovery_chain','recover'):
            self.events=[];self.fail=failure
            with self.subTest(failure=failure),self.fixture('recovery-once') as values:
                result=host.recovery_session(*values)
            self.assertEqual(result['status'],'HOLD');self.assertIsNotNone(result['primary'])
            self.assertEqual(self.events.count('entry_create'),1)
            self.assertEqual(self.events.count('paths_close'),1)
            self.assertLessEqual(self.events.count('recover'),1);self.assertNotIn('forward',self.events)
            if 'evidence_init' in self.events:self.assertIn('evidence_close',self.events)

    def test_real_setup_denies_invalid_packet_before_parent_signals_or_any_effect_owner(self):
        started=time.monotonic();wire=SimpleNamespace(bootstrap_started=started,deadline=started+600)
        packet={'route':'original','remaining_milliseconds':590000}
        with patch.object(host.os,'geteuid',return_value=0), \
             patch.object(io,'maintenance_packet_binding',side_effect=io.Hold('PUBLIC_OPERATOR_BAD_BOUND_INPUT')), \
             patch.object(host.ctypes,'CDLL') as libc,patch.object(host.signal,'signal') as signals:
            with self.assertRaises(io.Hold):host.maintenance_session_setup(None,packet,wire,route='original')
            libc.assert_not_called();signals.assert_not_called()
        self.assertEqual(wire.deadline,started+590)

    def test_partial_paths_object_is_retained_by_original_adapter_before_constructor_error(self):
        opened=[]
        class BrokenPaths:
            def __init__(self,*args,**kwargs):opened.append(self);raise RuntimeError('synthetic init error')
        adapter=host.Adapter.__new__(host.Adapter)
        source=SimpleNamespace(load=lambda n:r3 if n=='r3' else None)
        with patch.object(host,'Paths',BrokenPaths),patch.object(io,'sha',return_value=r3.OWNER_PLAN):
            with self.assertRaises(RuntimeError):adapter.__init__(source,{},b'SYNTHETIC',None,'a'*64,deadline=self.end)
        self.assertIs(adapter.p,opened[0])


if __name__=='__main__':unittest.main()
