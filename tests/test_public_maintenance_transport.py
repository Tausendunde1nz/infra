"""Pure Rev4 deadline boundaries; no Host/native timing acceptance."""
from pathlib import Path
import copy
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator as client
import tu1nz_public_operator_io as io


def synthetic_timing(source_hashes, artifact):
    """Synthetic validator input ONLY; not a measured600s/native receipt."""
    dimensions = {'runtime_objects':len(artifact['objects']), 'archive_bytes':artifact['archive_bytes'],
        'expanded_file_bytes':artifact['expanded_file_bytes'], 'lighting_objects':88,
        'lighting_files':82, 'protected_objects':4}
    runs = {}
    for index,name in enumerate(('original','recovery_F1','recovery_F2','recovery_F3',
                                  'recovery_F4','recovery_terminal_F4')):
        original = name == 'original'; terminal = name == 'recovery_terminal_F4'
        runs[name] = {'entrypoints':['tu1nz_public_operator.execute_maintenance',
            'tu1nz_public_operator_host.'+('maintenance_session' if original else 'recovery_session')],
            'status':'HOLD_KNOWN_NEW_UNITS_STOPPED' if terminal else 'COMPLETE', 'cleanup_complete':True,
            'trace_sha256':io.sha(('SYNTHETIC_TRACE_NOT_NATIVE_'+name).encode()), 'dimensions':dict(dimensions),
            'elapsed_milliseconds':100000 if terminal else (300000 if original else 320000),
            'after_ready_milliseconds':210000 if original else 0,
            'preparation_milliseconds':60000 if original else 0,
            'owner_milliseconds':0 if terminal else 30000, 'largest_service_action_milliseconds':2000,
            'terminal_prepare_milliseconds':10000 if terminal else 0,
            'terminal_stop_milliseconds':6000 if terminal else 0,
            'terminal_cleanup_milliseconds':5000 if terminal else 0,
            'linked_records':20 if terminal else 350, 'flow_records':10 if terminal else 70,
            'largest_record_bytes':60000, 'owner_intents':0 if terminal else 84, 'owner_acks':0 if terminal else 84}
    return {'schema':'TU1NZ_REV4_FULL_NATIVE_TIMING_V1', 'source_sha256':io.sha(io.canonical(source_hashes)),
        'artifact_sha256':io.sha(io.canonical(artifact)), 'measurement_source_sha256':'b'*64,
        'transport_cleanup_reserve_milliseconds':10000, 'runs':runs}


class MaintenanceTimingProofTests(unittest.TestCase):
    def setUp(self):
        self.source = {k:'a'*64 for k in set(io.MODULES)|set(io.ASSETS)}
        self.artifact = {'objects':{'synthetic':{}}, 'archive_bytes':45560268, 'expanded_file_bytes':200000000}
        self.proof = synthetic_timing(self.source, self.artifact)

    def check(self, proof=None):
        return io.maintenance_timing_binding(self.proof if proof is None else proof,
                                             source_hashes=self.source, artifact=self.artifact)

    def test_derives_reserves_and_replaces_fast_owner_with_full_120_seconds(self):
        value = self.check()
        self.assertEqual(value['after_ready_seconds'], 310)
        self.assertEqual(value['terminal_prepare_seconds'], 20)
        self.assertEqual(value['terminal_cleanup_seconds'], 15)
        self.assertEqual(value['whole_budget_milliseconds'], {'original':400000,
            'recovery_F1':420000, 'recovery_F2':420000, 'recovery_F3':420000,
            'recovery_F4':420000, 'recovery_terminal_F4':174000})

    def test_independent_review_terminal_prefix_counterexample_denies(self):
        # Former arithmetic accepted591s, although the actual reserve needs646s.
        self.proof['transport_cleanup_reserve_milliseconds']=1000
        self.proof['runs']['recovery_terminal_F4']['elapsed_milliseconds']=590000
        with self.assertRaisesRegex(io.Hold,'TERMINAL_WHOLE_600_BUDGET_EXCEEDED'):self.check()

    def test_terminal_exact_600_boundary_and_one_millisecond_below(self):
        self.proof['transport_cleanup_reserve_milliseconds']=1000
        row=self.proof['runs']['recovery_terminal_F4']
        # prepare11+stops60+cleanup6 =77s; elapsed544 minus measured21 =523s prefix.
        row['elapsed_milliseconds']=544000
        with self.assertRaisesRegex(io.Hold,'TERMINAL_WHOLE_600_BUDGET_EXCEEDED'):self.check()
        row['elapsed_milliseconds']=543999
        self.assertEqual(self.check()['whole_budget_milliseconds']['recovery_terminal_F4'],599999)

    def test_component_or_green_flag_never_counts_as_full_native_measurement(self):
        for proof in ({'passed':True}, {'component_seconds':0.276},
                      {**self.proof,'schema':'START_LIMIT_NATIVE'}):
            with self.subTest(proof=proof), self.assertRaises(io.Hold):self.check(proof)

    def test_source_artifact_and_each_required_path_remain_bound(self):
        for fault in ('source_sha256','artifact_sha256','missing_F1','missing_terminal','extra_path','duplicate_trace'):
            proof = copy.deepcopy(self.proof)
            if fault in ('source_sha256','artifact_sha256'):proof[fault]='f'*64
            elif fault == 'missing_F1':del proof['runs']['recovery_F1']
            elif fault == 'missing_terminal':del proof['runs']['recovery_terminal_F4']
            elif fault == 'extra_path':proof['runs']['retry']={}
            else:proof['runs']['recovery_F1']['trace_sha256']=proof['runs']['original']['trace_sha256']
            with self.subTest(fault=fault), self.assertRaises(io.Hold):self.check(proof)

    def test_real_entry_and_cleanup_not_skips_or_legacy_adapter(self):
        for key,value in (('entrypoints',['legacy.session']),('status','SKIPPED'),('cleanup_complete',False),
                          ('cleanup_complete',1),('trace_sha256','')):
            proof = copy.deepcopy(self.proof);proof['runs']['recovery_F2'][key]=value
            with self.subTest(key=key,value=value), self.assertRaises(io.Hold):self.check(proof)

    def test_smaller_runtime_or_wrong_owner_dimensions_deny(self):
        for key,value in (('runtime_objects',0),('archive_bytes',45560267),('expanded_file_bytes',199999999),
                          ('lighting_objects',87),('lighting_files',83),('protected_objects',3)):
            proof = copy.deepcopy(self.proof);proof['runs']['original']['dimensions'][key]=value
            with self.subTest(key=key), self.assertRaises(io.Hold):self.check(proof)

    def test_journal_owner_and_action_limits_remain_unchanged(self):
        for key,value in (('linked_records',513),('flow_records',129),('largest_record_bytes',65537),
                          ('owner_intents',85),('owner_acks',83),('owner_milliseconds',120001),
                          ('preparation_milliseconds',120001),('largest_service_action_milliseconds',20001),
                          ('linked_records',200)):
            proof = copy.deepcopy(self.proof);proof['runs']['original'][key]=value
            with self.subTest(key=key), self.assertRaises(io.Hold):self.check(proof)

    def test_all_required_paths_must_fit_600_including_unused_owner_and_reserve(self):
        for name in self.proof['runs']:
            proof = copy.deepcopy(self.proof)
            proof['runs'][name]['elapsed_milliseconds']=590000 if name=='recovery_terminal_F4' else 500000
            with self.subTest(name=name), self.assertRaisesRegex(io.Hold,'WHOLE_600_BUDGET_EXCEEDED'):
                self.check(proof)

    def test_no_bool_nonfinite_negative_or_missing_reserve(self):
        for value in (True,0,-1,float('nan'),float('inf'),120000):
            proof = copy.deepcopy(self.proof);proof['transport_cleanup_reserve_milliseconds']=value
            with self.subTest(value=value), self.assertRaises(io.Hold):self.check(proof)
        for value in (True,-1,float('nan'),float('inf')):
            proof = copy.deepcopy(self.proof);proof['runs']['original']['elapsed_milliseconds']=value
            with self.subTest(value=value), self.assertRaises(io.Hold):self.check(proof)

    def test_phase_intervals_and_terminal_owner_exclusion(self):
        for name,key,value in (('original','after_ready_milliseconds',290000),
                              ('original','owner_milliseconds',0),
                              ('recovery_F1','preparation_milliseconds',1),
                              ('recovery_F1','terminal_stop_milliseconds',1),
                              ('recovery_terminal_F4','owner_intents',1),
                              ('recovery_terminal_F4','terminal_stop_milliseconds',60001),
                              ('recovery_terminal_F4','terminal_cleanup_milliseconds',0)):
            proof = copy.deepcopy(self.proof);proof['runs'][name][key]=value
            with self.subTest(name=name,key=key), self.assertRaises(io.Hold):self.check(proof)


class MaintenanceDeadlineTests(unittest.TestCase):
    def test_transport_delays_do_not_extend_original_physical_deadline(self):
        # Physical client start=0/deadline=600. Host clock offset=5000;
        # ready emitted at120, client receives it at135, packet arrives150.
        packet = {'route': 'original', 'remaining_milliseconds': 600000}
        with patch.object(io.time, 'monotonic', return_value=135):
            sent = io.maintenance_transport_packet(packet, deadline=600)
        wire = SimpleNamespace(bootstrap_started=5120, deadline=5720)
        with patch.object(io.time, 'monotonic', return_value=5150):
            self.assertEqual(io.maintenance_remote_deadline(sent, wire), 435)
        self.assertEqual(wire.deadline, 5585)
        self.assertLessEqual(wire.deadline-5000, 600)
        self.assertEqual(packet['remaining_milliseconds'], 600000)

    def test_packet_transit_exhausts_budget_before_admission(self):
        wire = SimpleNamespace(bootstrap_started=100, deadline=700)
        with patch.object(io.time, 'monotonic', return_value=151):
            with self.assertRaisesRegex(io.Hold, 'PACKET_ARRIVED_AFTER_DEADLINE'):
                io.maintenance_remote_deadline({'remaining_milliseconds': 50000}, wire)
        self.assertEqual(wire.deadline, 150)
        self.assertTrue(wire._maintenance_deadline_bound)

    def test_existing_shorter_host_deadline_is_not_reset(self):
        wire = SimpleNamespace(bootstrap_started=100, deadline=120)
        with patch.object(io.time, 'monotonic', return_value=110):
            self.assertEqual(io.maintenance_remote_deadline({'remaining_milliseconds': 500000}, wire), 10)
        self.assertEqual(wire.deadline, 120)

    def test_second_binding_is_rejected_even_with_a_shorter_value(self):
        wire = SimpleNamespace(bootstrap_started=100, deadline=700)
        with patch.object(io.time, 'monotonic', return_value=110):
            io.maintenance_remote_deadline({'remaining_milliseconds': 500000}, wire)
            with self.assertRaisesRegex(io.Hold, 'DEADLINE_ALREADY_BOUND'):
                io.maintenance_remote_deadline({'remaining_milliseconds': 100000}, wire)
        self.assertEqual(wire.deadline, 600)

    def test_missing_future_nonfinite_or_extended_bootstrap_anchor_denies(self):
        for values in ({'deadline': 700}, {'bootstrap_started': 111, 'deadline': 711},
                       {'bootstrap_started': float('nan'), 'deadline': 700},
                       {'bootstrap_started': 100, 'deadline': float('inf')},
                       {'bootstrap_started': 100, 'deadline': 701}):
            with self.subTest(values=values), patch.object(io.time, 'monotonic', return_value=110):
                with self.assertRaises(io.Hold):
                    io.maintenance_remote_deadline({'remaining_milliseconds': 100000}, SimpleNamespace(**values))

    def test_bad_remaining_duration_denies(self):
        for value in (True, 1.5, '1000', 0, -1, 600001, None):
            with self.subTest(value=value), patch.object(io.time, 'monotonic', return_value=110):
                with self.assertRaises(io.Hold):
                    io.maintenance_remote_deadline({'remaining_milliseconds': value},
                        SimpleNamespace(bootstrap_started=100, deadline=700))

    def test_client_rounds_down_and_never_supplies_a_new_timer(self):
        with patch.object(io.time, 'monotonic', return_value=100.0001):
            self.assertEqual(io.maintenance_transport_packet({'route': 'recovery-once'},
                deadline=101)['remaining_milliseconds'], 999)
            for deadline in (100, 100.0002, 701, float('inf'), float('nan'), True):
                with self.subTest(deadline=deadline), self.assertRaises(io.Hold):
                    io.maintenance_transport_packet({'route': 'original'}, deadline=deadline)

    def test_unrecognized_route_cannot_get_maintenance_transport_budget(self):
        with patch.object(io.time, 'monotonic', return_value=100):
            for route in (None, 'resume', 'retry', 'original-again'):
                with self.subTest(route=route), self.assertRaises(io.Hold):
                    io.maintenance_transport_packet({'route': route}, deadline=200)

    def test_actual_generated_bootstrap_sets_anchor_before_ready(self):
        # Execute the real generated bootstrap with an inert in-memory IO
        # fixture. No filesystem import, SSH, sudo, marker or Host operation.
        inert = b'''class Wire:
    def __init__(self, *args, deadline): self.deadline=deadline
    def send(self, value):
        assert self.bootstrap_started == 37 and self.deadline == 637
        assert value['type'] == 'ready'
    def receive(self): return {'source': {}, 'hashes': {}}
class Source:
    def __init__(self, *args): pass
    def load(self, name): return self
    def session(self, source, packet, wire):
        assert wire.bootstrap_started == 37 and wire.deadline == 637
'''
        namespace = {}
        with patch.dict(sys.modules), patch.object(io.time, 'monotonic', return_value=37):
            exec(compile(client.bootstrap(inert), '<inert-bootstrap-deadline-test>', 'exec'), namespace)
        self.assertEqual(namespace['w'].bootstrap_started, 37)


if __name__ == '__main__':
    unittest.main()
