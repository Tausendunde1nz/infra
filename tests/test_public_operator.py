"""Local pure boundary tests; no Host/SSH/admission observations are mocked GREEN.

Full action/observation/supervisor proofs are the separate native suite. These
tests cover parsing, exact custody, reference material and negative CLI edges.
"""
import importlib.util
import base64
import contextlib
import io as text_io
import json
import os
from pathlib import Path
import subprocess
import socket
import select
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

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


def native_trace_capable():
    if sys.platform != 'linux' or os.geteuid() != 0: return False
    try:
        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        return bool(int(status['CapEff'].strip(), 16) & (1 << 19))  # CAP_SYS_PTRACE
    except (OSError, ValueError, KeyError): return False


class OperatorBoundary(unittest.TestCase):
    @unittest.skipUnless(native_trace_capable(), 'requires isolated native Linux root with CAP_SYS_PTRACE')
    def test_actual_fsuid_socket_owner_cannot_be_admitted_as_other_effective_uid(self):
        # Actual synthetic Unix socket and actual kernel fsuid in an owned
        # subprocess only. No administrative broker/provider operation.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); root.chmod(0o755); path = root/'synthetic.sock'
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(path)); listener.listen(1)
                os.chown(path, 1001, 1001); path.chmod(0o200)
                program = '''import ctypes,json,os,socket,sys
from pathlib import Path
libc=ctypes.CDLL(None,use_errno=True)
assert libc.setfsuid(1001)==0
s=dict(line.split(":",1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
uids=list(map(int,s["Uid"].split()))
assert os.geteuid()==0 and uids[1]==0 and uids[3]==1001
peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);peer.connect(sys.argv[1]);peer.close()
print("ACTUAL_FSUID_SOCKET_CONNECTED",flush=True)
assert sys.stdin.buffer.readline()==b"DONE\\n"
'''
                # The real production observer retains its privileged read
                # identity. Only the observed actor has a different fsuid.
                # Changing the observer's fsuid too would test different
                # procfs/LSM read authority, not the production DAC decision.
                child = subprocess.Popen([sys.executable, '-I', '-B', '-c', program, str(path)],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    self.assertTrue(select.select([child.stdout], [], [], 10)[0])
                    self.assertEqual(child.stdout.readline(128), b'ACTUAL_FSUID_SOCKET_CONNECTED\n')
                    row = observe.process(child.pid)
                    self.assertEqual(row['uid'][1], 0); self.assertEqual(row['uid'][3], 1001)
                    def unexpected(*a, **k): raise AssertionError('DAC_REJECTION_MUST_PRECEDE_INHERITED_INSPECTION')
                    authority = SimpleNamespace(b={'broker_tcp': [], 'broker_sockets': [str(path)]},
                                                inherited_sockets=unexpected)
                    with self.assertRaisesRegex(io.Hold, 'BROKER_EFFECTIVE_DAC_ACCESS'):
                        observe.Authority.broker_access(authority, row)
                finally:
                    _out, errors = child.communicate(b'DONE\n', timeout=10)
                    self.assertEqual(child.returncode, 0, errors.decode())
            finally: listener.close()

    def test_unknown_or_non_uint32_restart_counter_denies_unit_read(self):
        for counter in ('', '-1', 'True', '00', '4294967296'):
            values = {p: '' for p in observe.PROPERTIES.split(',')}
            values.update(Id=observe.UNITS[0], LoadState='loaded', NRestarts=counter)
            reply = SimpleNamespace(returncode=0, stdout='\n'.join(k+'='+v for k, v in values.items()).encode())
            with self.subTest(counter=counter), patch.object(observe, 'command', return_value=reply):
                with self.assertRaisesRegex(io.Hold, 'UNIT_RESTART_COUNTER_UNKNOWN'):
                    observe.Authority.unit(SimpleNamespace(deadline=time.monotonic()+1), observe.UNITS[0])

    def test_entry_sanitizes_private_input_error_without_traceback(self):
        output = text_io.StringIO()
        with patch.object(client, 'main', side_effect=OSError('PRIVATE_CANARY_PATH')), contextlib.redirect_stdout(output):
            self.assertEqual(client.entry(), 1)
        value = json.loads(output.getvalue())
        self.assertEqual(value['status'], 'HOLD'); self.assertNotIn('CANARY', output.getvalue())
        self.assertNotIn('Traceback', output.getvalue())

    def test_transport_eof_records_rereads_and_reports_hold_without_ssh(self):
        # Transport-boundary ONLY: replace the SSH executable with an owned
        # local framed peer which closes before a result. No Host observation,
        # admission flag, action, journal claim or provider effect is supplied.
        raw = (SCRIPTS/'tu1nz_public_operator_io.py').read_bytes(); digest = io.sha(raw)
        peer = ('import sys,json;sys.stdin.buffer.readline();v=json.dumps('+repr(
            {'type': 'ready', 'io_sha256': digest})+').encode();'
            'sys.stdout.buffer.write(len(v).to_bytes(4,"big")+v);sys.stdout.buffer.flush();'
            'n=int.from_bytes(sys.stdin.buffer.read(4),"big");sys.stdin.buffer.read(n)')
        original = subprocess.Popen; children = []
        def popen(argv, **kw):
            if argv[0] == '/usr/bin/ssh':
                child = original([sys.executable, '-I', '-B', '-c', peer], **kw)
                children.append(child); return child
            return original(argv, **kw)
        with tempfile.TemporaryDirectory(prefix='PRIVATE_CANARY-') as d:
            paths = [Path(d)/name for name in ('first', 'second')]
            for p in paths: p.mkdir(mode=0o700)
            fds = [os.open(p, os.O_RDONLY | os.O_DIRECTORY) for p in paths]
            output = text_io.StringIO()
            with patch.object(client, 'preparation_records', return_value=(paths, fds)), \
                 patch.object(client.getpass, 'getpass', return_value='SYNTHETIC_ONLY'), \
                 patch.object(client.subprocess, 'Popen', popen), contextlib.redirect_stdout(output):
                result = client.execute({'binding': 'a'*64}, {'io': base64.b64encode(raw).decode()}, {'io': digest},
                                        {'http': {'lighting': {'location': 'root'}}}, SimpleNamespace(UNITS=()))
            self.assertEqual(result, 1); self.assertEqual(json.loads(output.getvalue())['status'], 'HOLD')
            self.assertEqual((paths[0]/'result.json').read_bytes(), (paths[1]/'result.json').read_bytes())
            record = json.loads((paths[0]/'result.json').read_bytes())
            self.assertEqual(record['status'], 'HOLD'); self.assertTrue(record['client_primary'])
            self.assertEqual(record['client_abort'], []); self.assertEqual(record['client_cleanup'], [])
            self.assertEqual(len(children), 1); self.assertIsNotNone(children[0].poll())
            for fd in fds:
                with self.assertRaises(OSError): os.fstat(fd)
            self.assertNotIn('CANARY', output.getvalue()); self.assertNotIn('Traceback', output.getvalue())

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
