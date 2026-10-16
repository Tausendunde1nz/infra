"""Local pure boundary tests; no Host/SSH/admission observations are mocked GREEN.

Full action/observation/supervisor proofs are the separate native suite. These
tests cover parsing, exact custody, reference material and negative CLI edges.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0, str(SCRIPTS))
import tu1nz_public_operator as client
import tu1nz_public_operator_io as io
import tu1nz_public_operator_observe as observe


class Reply:
    """Protocol unit peer only. Never passed to a Host adapter/Authority."""
    def __init__(self, reply): self.reply = reply; self.sent = []; self.deadline = time.monotonic()+10
    def send(self, value): self.sent.append(value)
    def receive(self): return self.reply


class OperatorBoundary(unittest.TestCase):
    def test_strict_json_duplicates_and_nonfinite(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(io.Hold): io.parse(raw)
        self.assertEqual(io.parse(io.canonical({'x': [1, None]})), {'x': [1, None]})

    def test_actual_framing_roundtrip_eof_and_budget(self):
        a, b = os.pipe(); c, d = os.pipe()
        try:
            wire = io.Wire(a, d, deadline=time.monotonic()+2)
            raw = io.canonical({'type': 'synthetic'})
            os.write(b, len(raw).to_bytes(4, 'big')+raw)
            self.assertEqual(wire.receive(), {'type': 'synthetic'})
            wire.send({'ack': 1}); count = int.from_bytes(os.read(c, 4), 'big')
            self.assertEqual(io.parse(os.read(c, count)), {'ack': 1})
            os.close(b); b = None
            with self.assertRaisesRegex(io.Hold, 'WIRE_LOST_NO_RETRY'): wire.receive()
        finally:
            for fd in (a, b, c, d):
                if fd is not None: os.close(fd)

    def test_framing_rejects_oversized_before_payload(self):
        a, b = os.pipe()
        try:
            os.write(b, (io.MAX_FRAME+1).to_bytes(4, 'big'))
            with self.assertRaisesRegex(io.Hold, 'FRAME_SIZE'):
                io.Wire(a, b, deadline=time.monotonic()+1).receive()
        finally: os.close(a); os.close(b)

    def test_create_only_record_real_readback_no_overwrite(self):
        with tempfile.TemporaryDirectory() as value:
            fd = os.open(value, os.O_RDONLY | os.O_DIRECTORY)
            try:
                io.exclusive(fd, 'record', b'SYNTHETIC')
                self.assertEqual((Path(value)/'record').read_bytes(), b'SYNTHETIC')
                with self.assertRaises(FileExistsError): io.exclusive(fd, 'record', b'REPLACEMENT')
                with self.assertRaises(io.Hold): io.exclusive(fd, '../escape', b'')
            finally: os.close(fd)

    def test_private_input_rejects_link_mode_and_changes(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value); p = root/'material'; p.write_bytes(b'SYNTHETIC'); p.chmod(0o600)
            self.assertEqual(io.private_read(p), b'SYNTHETIC')
            p.chmod(0o644)
            with self.assertRaises(io.Hold): io.private_read(p)
            p.chmod(0o600); (root/'link').symlink_to(p)
            with self.assertRaises(OSError): io.private_read(root/'link')
            os.link(p, root/'hard')
            with self.assertRaises(io.Hold): io.private_read(p)

    def test_linked_denial_preserves_chain_but_never_confirms_effect(self):
        binding = 'a'*64
        payload = {'sequence': 1, 'binding': binding, 'previous': binding,
                   'kind': 'owner_object_intent', 'value': {'relative': '.'}}
        digest = io.sha(io.canonical(payload))
        wire = Reply({'type': 'persisted', 'sequence': 1, 'sha256': digest, 'control': 'HOLD_BEFORE_OWNER_EFFECT'})
        channel = io.LinkedRecords(wire, binding)
        with self.assertRaisesRegex(io.Hold, 'REQUESTED_OWNER_BOUNDARY_HOLD'):
            channel.record('owner_object_intent', {'relative': '.'})
        self.assertEqual(channel.previous, digest); self.assertEqual(channel.sequence, 1)
        self.assertFalse(channel.return_confirmed)

    def test_lost_ack_is_not_repaired_into_permission(self):
        channel = io.LinkedRecords(Reply({'type': 'persisted', 'sequence': 1, 'sha256': '0'*64}), 'a'*64)
        with self.assertRaisesRegex(io.Hold, 'ACK_LOST'): channel.record('host_action_intent', {'action': 'synthetic'})
        self.assertEqual(channel.previous, 'a'*64)
        self.assertEqual(channel.sequence, 1)  # consumed; no rewind/retry

    def test_denial_control_not_valid_for_operation_ack(self):
        binding = 'a'*64; payload = {'sequence': 1, 'binding': binding, 'previous': binding,
                                  'kind': 'owner_object_ack', 'value': {}}
        reply = {'type': 'persisted', 'sequence': 1, 'sha256': io.sha(io.canonical(payload)),
                 'control': 'HOLD_BEFORE_OWNER_EFFECT'}
        with self.assertRaisesRegex(io.Hold, 'ACK_LOST'):
            io.LinkedRecords(Reply(reply), binding).record('owner_object_ack', {})

    def test_remaining_deadline_never_widens_after_owner_cap(self):
        wire = Reply(None); channel = io.LinkedRecords(wire, 'a'*64)
        original = wire.deadline; cap = time.monotonic()+1
        with channel.limit(original): channel.cap(cap)
        self.assertEqual(channel.ceiling, cap); self.assertEqual(wire.deadline, cap)
        with channel.limit(original): self.assertEqual(wire.deadline, cap)

    def test_actor_numeric_boolean_is_not_a_permission_profile(self):
        p = {'role': 'administrative_service', 'exe': '/usr/bin/synthetic', 'exe_sha256': 'a'*64,
             'uid': [0]*4, 'gid': [0]*4, 'groups': [], 'caps': {k: 0 for k in observe.CAPS},
             'nnp': 1, 'argv_sha256': 'b'*64, 'cgroup': '0::/system.slice/synthetic.service',
             'initial_env_sha256': 'c'*64, 'lsm_sha256': 'd'*64, 'namespaces': {},
             'max_instances': 1, 'origin_sha256': 'e'*64}
        self.assertTrue(observe.exact_actor(p, p))
        for key, value in (('max_instances', True), ('nnp', True), ('uid', [False]*4)):
            with self.subTest(key=key), self.assertRaises(io.Hold): observe.exact_actor(p, {**p, key: value})

    def test_reference_origins_require_actual_material_and_bound_contents(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value); old = root/'prior'; old.write_bytes(b'SYNTHETIC PRIOR SOURCE RECEIPT'); old.chmod(0o600)
            prior = io.sha(old.read_bytes()); objects = {'.': {'kind': 'directory'}}
            receipt = {'schema': 'TU1NZ_PUBLIC_RUNTIME_ORIGIN_V1', 'application_commit': '1'*40,
                       'application_tree': '2'*40, 'runtime_objects_sha256': io.sha(io.canonical(objects)),
                       'prior_evidence_sha256': [prior]}
            current = root/'origin'; current.write_bytes(io.canonical(receipt)); current.chmod(0o600)
            digest = io.sha(current.read_bytes())
            b = {'source_origin_receipts': [prior, digest], 'source_release': {'runtime_reference': {
                'commit': '1'*40, 'tree': '2'*40, 'objects': objects, 'origin_sha256': digest}}}
            client.reference_origins([old, current], b)
            with self.assertRaises(io.Hold): client.reference_origins([current], b)
            with self.assertRaises(io.Hold): client.reference_origins([old, old, current], b)
            b['source_release']['runtime_reference']['objects'] = {}
            with self.assertRaisesRegex(io.Hold, 'ORIGIN_CONTENT'): client.reference_origins([old, current], b)

    def test_wrong_application_reference_denies_before_any_git_or_host(self):
        b = {'source_origin_receipts': ['a'*64], 'source_release': {'runtime_reference': {
            'commit': 'f'*40, 'tree': 'e'*40, 'origin_sha256': 'a'*64, 'objects': {}}}}
        with self.assertRaisesRegex(io.Hold, 'APPLICATION_REFERENCE_BINDING'):
            client.application_reference(Path('/DOES-NOT-EXIST'), b)

    def test_cli_help_is_non_mutating_and_exposes_no_target_override(self):
        r = subprocess.run([sys.executable, '-I', '-B', str(SCRIPTS/'tu1nz_public_operator.py'), '--help'],
                           capture_output=True, timeout=10)
        self.assertEqual(r.returncode, 0); self.assertIn(b'--execute', r.stdout)
        for forbidden in (b'--host ', b'--transaction ', b'--skip-', b'--retry', b'--approve '):
            self.assertNotIn(forbidden, r.stdout)


if __name__ == '__main__': unittest.main()
