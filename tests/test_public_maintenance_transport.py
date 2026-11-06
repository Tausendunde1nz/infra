"""Pure Rev4 deadline boundaries; no Host/native timing acceptance."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator as client
import tu1nz_public_operator_io as io


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
