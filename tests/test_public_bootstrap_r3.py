import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import sys

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('bootstrap_r3',ROOT/'scripts/tu1nz_public_bootstrap_r3.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
BINDING='a'*64
def temporary():return tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())

class Adapter:
    def __init__(self):self.calls=[];self.deny=None;self.fail=None;self.unknown=None;self.incomplete=False
    def observe(self,phase,*,deadline):
        facts=m.REQUIRED[phase]
        if phase==self.deny:facts=frozenset()
        return m.Observation(m.TX,BINDING,phase,frozenset(facts),time.monotonic())
    def perform(self,action,unit,*,deadline):
        self.calls.append((action,unit))
        if action==self.fail:raise OSError('PRIVATE_FAILURE_DETAILS')
        if action==self.unknown:return None
        return {'action':action,'unit':unit,'outcome':'CONFIRMED',
                'cgroup_empty':not self.incomplete,'no_job':True}

class BootstrapSequence(unittest.TestCase):
    def setUp(self):
        self.tmp=temporary();self.addCleanup(self.tmp.cleanup)
        self.custody=patch.object(m,'CUSTODY_PARENT',Path(self.tmp.name));self.custody.start();self.addCleanup(self.custody.stop)
        self.j=m.Journal(self.tmp.name,BINDING);self.addCleanup(self.j.close)
        self.a=Adapter();self.f=m.Flow(self.a,self.j)
    def test_full_sequence_no_R2_dispatch(self):
        self.assertEqual(self.f.forward(),'RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED')
        calls=self.a.calls
        self.assertEqual([u for a,u in calls if a=='stop'],list(m.STOP))
        self.assertEqual([u for a,u in calls if a=='start'],list(m.UNITS))
        names=[a for a,u in calls]
        self.assertLess(names.index('create_persistent_barriers'),names.index('stop'))
        self.assertLess(max(i for i,n in enumerate(names) if n=='stop'),names.index('create_sealed_staging'))
        self.assertLess(names.index('protected_rights_backup'),names.index('isolated_restore_rehearsal'))
        self.assertLess(names.index('bounded_synthetic_probes'),names.index('install_four_artifacts'))
        self.assertLess(names.index('start'),names.index('supervised_owner_transaction'))
        self.assertEqual(self.f.r2_eligibility(),'FRESH_FROZEN_R2_GATE_ELIGIBILITY_ONLY_NO_SIGNATURE_OR_DISPATCH')
        self.assertNotIn('R2',str(calls))
    def test_pre_stop_unknown_other_writer_no_effect(self):
        self.a.deny='pre_stop'
        with self.assertRaises(m.Denied):self.f.forward()
        self.assertEqual(self.a.calls,[])
    def test_barrier_failure_no_stop_or_staging(self):
        self.a.deny='barriers'
        with self.assertRaises(m.Denied):self.f.forward()
        self.assertEqual(self.a.calls,[('create_persistent_barriers',None)])
    def test_incomplete_stop_never_reaches_next_stop_or_backup(self):
        self.a.incomplete=True
        with self.assertRaises(m.Denied):self.f.forward()
        self.assertEqual([x for x in self.a.calls if x[0]=='stop'],[('stop',m.STOP[0])])
        self.assertNotIn('protected_rights_backup',str(self.a.calls))
    def test_remaining_writer_after_stop_no_staging(self):
        self.a.deny='quiet'
        with self.assertRaises(m.Denied):self.f.forward()
        self.assertEqual(self.a.calls[-1],('stop',m.STOP[-1]))
    def test_wrong_opt_profile_denies_before_create(self):
        self.a.deny='staging_ready'
        with self.assertRaises(m.Denied):self.f.forward()
        self.assertNotIn('create_sealed_staging',str(self.a.calls))
    def test_post_stop_backup_restore_probe_failures_no_automatic_return(self):
        for action in ('protected_rights_backup','isolated_restore_rehearsal','bounded_synthetic_probes'):
            with self.subTest(action=action),temporary() as parent,patch.object(m,'CUSTODY_PARENT',Path(parent)):
                j=m.Journal(parent,BINDING);a=Adapter();a.fail=action;f=m.Flow(a,j)
                try:
                    with self.assertRaises(m.FlowFailure):f.forward()
                    self.assertNotIn('start_old',str(a.calls));self.assertNotIn('install_four_artifacts',str(a.calls))
                    self.assertTrue(f.hold)
                finally:j.close()
    def test_explicit_preinstall_return_is_once_and_security_RED(self):
        self.a.fail='protected_rights_backup'
        with self.assertRaises(m.FlowFailure):self.f.forward()
        self.a.fail=None
        self.assertEqual(self.f.return_old(),'OLD_OPERATION_RESTORED_SECURITY_RED')
        self.assertEqual([u for a,u in self.a.calls if a=='start_old'],list(m.UNITS))
        names=[a for a,u in self.a.calls]
        self.assertLess(names.index('return_old_configuration'),names.index('quarantine_own_return_barrier'))
        self.assertLess(names.index('quarantine_own_return_barrier'),names.index('start_old'))
        with self.assertRaises(m.Denied):self.f.return_old()
        with self.assertRaises(m.Denied):self.f.r2_eligibility()
        with self.assertRaises(m.Denied):self.f.forward()
    def test_unsafe_return_after_stop_stays_held(self):
        self.a.fail='protected_rights_backup'
        with self.assertRaises(m.FlowFailure):self.f.forward()
        self.a.deny='return_request'
        with self.assertRaises(m.Denied):self.f.return_old()
        self.assertNotIn('start_old',str(self.a.calls))
    def test_foreign_baseline_after_return_stop_never_starts(self):
        self.a.fail='protected_rights_backup'
        with self.assertRaises(m.FlowFailure):self.f.forward()
        self.a.fail=None;self.a.deny='return_before_install'
        with self.assertRaises(m.Denied):self.f.return_old()
        self.assertNotIn('start_old',str(self.a.calls))
    def test_partial_install_requires_actual_protected_return(self):
        self.a.fail='install_four_artifacts'
        with self.assertRaises(m.FlowFailure):self.f.forward()
        self.a.fail=None;self.a.deny='return_after_install'
        with self.assertRaises(m.Denied):self.f.return_old()
        self.assertNotIn('start_old',str(self.a.calls))
    def test_return_configuration_postproof_and_barrier_release_are_distinct_gates(self):
        for phase in ('return_config','return_release:'+m.UNITS[0]):
            with self.subTest(phase=phase),temporary() as parent,patch.object(m,'CUSTODY_PARENT',Path(parent)):
                j=m.Journal(parent,BINDING);a=Adapter();a.fail='install_four_artifacts';f=m.Flow(a,j)
                try:
                    with self.assertRaises(m.FlowFailure):f.forward()
                    a.fail=None;a.deny=phase
                    with self.assertRaises(m.FlowFailure):f.return_old()
                    self.assertNotIn('start_old',str(a.calls))
                    if phase=='return_config':self.assertNotIn('quarantine_own_return_barrier',str(a.calls))
                    with self.assertRaises(m.Denied):f.return_old()
                finally:j.close()
    def test_unknown_return_barrier_release_never_requests_start(self):
        self.a.fail='protected_rights_backup'
        with self.assertRaises(m.FlowFailure):self.f.forward()
        self.a.fail=None;self.a.unknown='quarantine_own_return_barrier'
        with self.assertRaises(m.FlowFailure):self.f.return_old()
        self.assertNotIn('start_old',str(self.a.calls))
    def test_failed_or_unknown_start_not_retried(self):
        self.a.unknown='start'
        with self.assertRaises(m.Denied):self.f.forward()
        self.assertEqual([u for a,u in self.a.calls if a=='start'],[m.UNITS[0]])
        with self.assertRaises(m.Denied):self.f.forward()
        self.assertNotIn('supervised_owner_transaction',str(self.a.calls))
    def test_owner_interruption_blocks_configuration_return(self):
        self.a.fail='supervised_owner_transaction'
        with self.assertRaises(m.FlowFailure):self.f.forward()
        with self.assertRaises(m.Denied):self.f.return_old()
        self.assertNotIn('return_old_configuration',str(self.a.calls))
    def test_failed_owner_postproof_cannot_admit_R2(self):
        self.a.deny='owner_done'
        with self.assertRaises(m.Denied):self.f.forward()
        with self.assertRaises(m.Denied):self.f.r2_eligibility()
    def test_remote_slot_unknown_not_inferred_from_source(self):
        self.f.forward();self.a.deny='r2_ready'
        with self.assertRaises(m.Denied):self.f.r2_eligibility()
    def test_same_process_new_flow_same_journal_denies(self):
        with self.assertRaises(m.Denied):m.Flow(Adapter(),self.j)
    def test_reopen_or_new_binding_does_not_make_new_attempt(self):
        with self.assertRaises(m.Denied):m.Journal(self.tmp.name,'b'*64)
    def test_alternate_empty_custody_parent_cannot_create_fresh_claim(self):
        with temporary() as alternate,self.assertRaisesRegex(m.Denied,'FIXED_CUSTODY_PARENT_RED'):
            m.Journal(alternate,BINDING)
    def test_denied_return_admission_consumes_attempt_before_any_effect(self):
        self.a.fail='protected_rights_backup'
        with self.assertRaises(m.FlowFailure):self.f.forward()
        self.a.fail=None;self.a.deny='return_request'
        with self.assertRaises(m.FlowFailure):self.f.return_old()
        before=list(self.a.calls);self.a.deny=None
        with self.assertRaises(m.Denied):self.f.return_old()
        self.assertEqual(before,self.a.calls)
        records=[json.loads(p.read_bytes()) for p in (Path(self.tmp.name)/m.TX).glob('*.json')]
        self.assertTrue(any(r['kind']=='return_intent' for r in records))
    def test_late_owner_observation_never_reports_completion(self):
        clock=[100.0];original=self.a.observe
        def observe(phase,*,deadline):
            if phase=='owner_done':clock[0]=deadline+1
            return original(phase,deadline=deadline)
        with patch.object(m.time,'monotonic',side_effect=lambda:clock[0]):
            self.f.deadline=700
            with patch.object(self.a,'observe',side_effect=observe),self.assertRaises(m.FlowFailure):self.f.forward()
        self.assertTrue(self.f.hold)
        self.assertNotEqual(self.f.stage,'RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED')
    def test_function_observation_is_durable_before_downstream_barrier_release(self):
        self.f.forward()
        records=[json.loads(p.read_bytes()) for p in sorted((Path(self.tmp.name)/m.TX).glob('*.json'))]
        for prior,downstream in zip(m.UNITS,m.UNITS[1:]):
            observed=next(r['sequence'] for r in records if r['kind']=='observation' and r['value']['phase']=='started:'+prior)
            released=next(r['sequence'] for r in records if r['kind']=='intent' and r['value']=={'action':'quarantine_own_barrier','unit':downstream})
            self.assertLess(observed,released)
        self.assertLess(len(records),128)
    def test_failed_function_observation_persistence_keeps_downstream_barrier(self):
        original=self.j.write
        def write(kind,value):
            if kind=='observation' and value['phase']=='started:'+m.UNITS[0]:raise OSError('SYNTHETIC_STORAGE_RED')
            return original(kind,value)
        with patch.object(self.j,'write',side_effect=write),self.assertRaises(m.FlowFailure):self.f.forward()
        self.assertEqual([u for a,u in self.a.calls if a=='quarantine_own_barrier'],[m.UNITS[0]])
    def test_slow_observation_persistence_does_not_admit_effect(self):
        clock=[100.0];original=self.j.write
        def write(kind,value):
            result=original(kind,value)
            if kind=='observation':clock[0]=701
            return result
        with patch.object(m.time,'monotonic',side_effect=lambda:clock[0]):
            self.f.deadline=700
            with patch.object(self.j,'write',side_effect=write),self.assertRaises(m.FlowFailure):self.f.forward()
        self.assertEqual(self.a.calls,[])
    def test_slow_completion_never_returns_GREEN(self):
        clock=[100.0];original=self.j.write
        def write(kind,value):
            result=original(kind,value)
            if kind=='complete':clock[0]=701
            return result
        with patch.object(m.time,'monotonic',side_effect=lambda:clock[0]):
            self.f.deadline=700
            with patch.object(self.j,'write',side_effect=write),self.assertRaises(m.FlowFailure):self.f.forward()
        self.assertTrue(self.f.hold)
    def test_lost_ack_durable_intent_remains_and_no_replay(self):
        original=self.j.write
        def fail(kind,value):
            if kind=='ack':raise OSError('ACK_DISK_FULL')
            original(kind,value)
        with patch.object(self.j,'write',side_effect=fail):
            with self.assertRaises(m.FlowFailure):self.f.forward()
        self.assertEqual(self.a.calls,[('create_persistent_barriers',None)])
        events=[json.loads(p.read_bytes()) for p in (Path(self.tmp.name)/m.TX).glob('*.json')]
        self.assertIn('intent',[x['kind'] for x in events]);self.assertNotIn('ack',[x['kind'] for x in events])
        with self.assertRaises(m.Denied):self.f.forward()
    def test_interruption_keeps_journal_and_never_retries_or_returns(self):
        with patch.object(self.a,'perform',side_effect=KeyboardInterrupt):
            with self.assertRaises(m.FlowFailure):self.f.forward()
        self.assertTrue((Path(self.tmp.name)/m.TX/'flow-claimed').exists())
        with self.assertRaises(m.Denied):m.Journal(self.tmp.name,BINDING)
    def test_stale_wrong_host_scope_or_raw_JSON_observation_denied(self):
        for o in (m.Observation('other',BINDING,'pre_stop',m.BASE,time.monotonic()),
                  m.Observation(m.TX,'b'*64,'pre_stop',m.BASE,time.monotonic()),
                  m.Observation(m.TX,BINDING,'pre_stop',m.BASE,time.monotonic()-3),
                  {'phase':'pre_stop','approved':True}):
            with self.subTest(o=type(o).__name__):
                with patch.object(self.a,'observe',return_value=o),self.assertRaises(m.Denied):self.f.witness('pre_stop')
    def test_arbitrary_unit_or_command_not_a_public_parameter(self):
        self.assertEqual(len(m.UNITS),3)
        self.assertIn('NEVER-CREATE-START-PERMIT',m.BARRIER_BYTES.decode())
        self.assertNotIn('ExecStart',m.BARRIER_BYTES.decode())
    def test_primary_not_overwritten_by_failed_hold_record(self):
        self.a.fail='create_persistent_barriers'
        original=self.j.write
        def write(kind,value):
            if kind=='hold':raise OSError('PRIVATE_SECONDARY_FAILURE')
            return original(kind,value)
        with patch.object(self.j,'write',side_effect=write),self.assertRaises(m.FlowFailure) as result:
            self.f.forward()
        self.assertEqual(result.exception.primary,'PUBLIC_BOOTSTRAP_IO_UNCONFIRMED')
        self.assertEqual(result.exception.abort,())
        self.assertEqual(result.exception.cleanup,('PUBLIC_BOOTSTRAP_HOLD_RECORD_PERSISTENCE_RED',))
        self.assertNotIn('PRIVATE',str(result.exception))
    def test_first_start_function_failure_prevents_next_start(self):
        self.a.deny='started:'+m.UNITS[0]
        with self.assertRaises(m.FlowFailure):self.f.forward()
        self.assertEqual([u for a,u in self.a.calls if a=='start'],[m.UNITS[0]])
    def test_oversized_record_denies_before_action(self):
        with self.assertRaises(m.Denied):self.j.write('intent',{'data':'X'*65536})
        self.assertEqual(self.a.calls,[])
    def test_adapter_private_fields_not_persisted(self):
        original=self.a.perform
        def perform(action,unit,*,deadline):
            return {**original(action,unit,deadline=deadline),'secret':'PRIVATE_CANARY'}
        with patch.object(self.a,'perform',side_effect=perform),self.assertRaises(m.FlowFailure):self.f.forward()
        raw=b''.join(p.read_bytes() for p in (Path(self.tmp.name)/m.TX).glob('*.json'))
        self.assertNotIn(b'PRIVATE_CANARY',raw)
    def test_late_adapter_response_does_not_admit_next_action(self):
        clock=[100.0]
        original=self.a.perform
        def late(action,unit,*,deadline):
            value=original(action,unit,deadline=deadline);clock[0]=deadline+1;return value
        with patch.object(m.time,'monotonic',side_effect=lambda:clock[0]):
            self.f.deadline=700
            with patch.object(self.a,'perform',side_effect=late),self.assertRaises(m.FlowFailure):self.f.forward()
        self.assertEqual(self.a.calls,[('create_persistent_barriers',None)])
    def test_component_primary_abort_cleanup_not_overwritten(self):
        failure=m.FlowFailure('PUBLIC_BOOTSTRAP_COMPONENT_PRIMARY',
            abort=('PUBLIC_BOOTSTRAP_COMPONENT_ABORT',),cleanup=('PUBLIC_BOOTSTRAP_COMPONENT_CLEANUP',))
        with patch.object(self.a,'perform',side_effect=failure),self.assertRaises(m.FlowFailure) as result:self.f.forward()
        self.assertEqual(result.exception.primary,failure.primary)
        self.assertEqual(result.exception.abort,failure.abort)
        self.assertEqual(result.exception.cleanup,failure.cleanup)
    def test_original_four_runtime_bytes_unchanged(self):
        expected={'scripts/tu1nz_public_web_isolate_r1.py':'2884c2531e73480513d533844cab9ac1a906e13fd4fdb104ab1d49759f3e9b01',
          'tu1nz-adult-public-s7.service':'df605ffec37e59d1c3c535a93879e7e155447967c6cd97a2f83ca866f841c16b',
          'tu1nz-adult-public-s8-landing.service':'1e84f8904b4ce292e8b002ad373b27ea5d6592ddaaca4c07c68e990452133213',
          'tu1nz-adult-public-s10-wms.service':'ce23c6382e50b740fb22f5a085d15fb0f96cd7fc15afcc1deaf23e04aff8bcf3'}
        for name,h in expected.items():
            path=ROOT/name if name.startswith('scripts/') else ROOT/'systemd'/(name+'.d')/'zz-public-isolation-r1.conf'
            self.assertEqual(m.digest(path.read_bytes()),h)

if __name__=='__main__':unittest.main(verbosity=2)
