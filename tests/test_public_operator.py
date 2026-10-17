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
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0, str(SCRIPTS))
import tu1nz_public_operator as client
import tu1nz_public_operator_io as io
import tu1nz_public_operator_observe as observe
import tu1nz_public_operator_runtime_guard as runtime_guard


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


def native_network_guest():
    return (sys.platform == 'linux' and os.environ.get('container') == 'docker' and
            Path('/proc/1/comm').read_text().strip() == 'systemd')


class NativeFSUIDFailure(AssertionError):
    def __init__(self, code, number=0):
        self.primary = code; self.native_errno = number
        super().__init__(code)


class OperatorBoundary(unittest.TestCase):
    def test_fresh_proc_read_helpers_never_cache_values_or_hide_read_errors(self):
        with tempfile.TemporaryDirectory(prefix='r4-owned-read-helper-') as folder:
            path = Path(folder)/'synthetic-field'
            for helper in (observe.proc_text, observe.proc_bytes, runtime_guard.proc_text):
                binary = helper is observe.proc_bytes
                path.write_bytes(b'FIRST\n')
                self.assertEqual(helper(str(path)), b'FIRST\n' if binary else 'FIRST\n')
                path.write_bytes(b'CHANGED\n')
                self.assertEqual(helper(path), b'CHANGED\n' if binary else 'CHANGED\n')
                path.unlink()
                with self.assertRaises(FileNotFoundError): helper(path)
                with self.assertRaises(IsADirectoryError): helper(folder)

    @unittest.skipUnless(native_network_guest(), 'requires the inspected network-none native guest')
    def test_actual_http_reader_absolute_deadline_and_reap(self):
        for mode in ('normal', 'slow_header', 'slow_body', 'redirect', 'oversize'):
            with self.subTest(mode=mode):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(.1)
                stop = threading.Event(); progress = []; failures = []; children = []
                body = b'S'*64
                def serve():
                    try:
                        while not stop.is_set():
                            try: peer, _ = listener.accept(); break
                            except socket.timeout: pass
                        else: return
                        with peer:
                            peer.settimeout(2); peer.recv(8192)
                            if mode == 'redirect':
                                peer.sendall(b'HTTP/1.1 302 Found\r\nLocation: https://tu1nz.com/health\r\nContent-Length: 0\r\n\r\n')
                            else:
                                payload = b'S'*(1024*1024+1) if mode == 'oversize' else body
                                header = b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(payload)).encode()+b'\r\nConnection: close\r\n\r\n'
                                if mode == 'slow_header':
                                    for byte in header:
                                        if stop.is_set(): return
                                        peer.sendall(bytes([byte])); progress.append(1); stop.wait(.02)
                                else: peer.sendall(header)
                                if mode == 'slow_body':
                                    for byte in payload:
                                        if stop.is_set(): return
                                        peer.sendall(bytes([byte])); progress.append(1); stop.wait(.02)
                                else: peer.sendall(payload)
                    except (BrokenPipeError, ConnectionResetError): pass  # own reader was stopped
                    except BaseException as error: failures.append(type(error).__name__)
                worker = threading.Thread(target=serve); worker.start()
                original = subprocess.Popen
                def actual_child(*args, **kwargs):
                    child = original(*args, **kwargs); children.append(child)
                    self.assertEqual(args[0][1:5], ['-I', '-B', '-S', '-c'])
                    self.assertEqual(args[0][5], io.HTTP_READER)
                    self.assertEqual(set(kwargs['env']), {'PATH', 'LC_ALL'})
                    return child
                endpoint = {'stage': 'internal', 'location': 'host', 'url':
                    'http://127.0.0.1:'+str(listener.getsockname()[1])+'/health', 'method': 'GET',
                    'host_header': None, 'status': 200, 'body_sha256': io.sha(body)}
                began = time.monotonic()
                try:
                    with patch.object(io.subprocess, 'Popen', actual_child):
                        if mode in ('slow_header', 'slow_body'):
                            with self.assertRaisesRegex(io.Hold, 'HTTP_ABSOLUTE_DEADLINE') as caught:
                                io.measured_http(endpoint, deadline=began+.35, location='host')
                            self.assertLess(time.monotonic()-began, .8)
                            self.assertGreater(len(progress), 1)
                            self.assertEqual(io.http_cleanup(caught.exception), [])
                        elif mode in ('redirect', 'oversize'):
                            with self.assertRaisesRegex(io.Hold, 'HTTP_REDIRECT_NOT_ADMITTED' if mode == 'redirect' else 'HTTP_OUTPUT_LIMIT'):
                                io.measured_http(endpoint, deadline=began+3, location='host')
                        else:
                            value = io.measured_http(endpoint, deadline=began+3, location='host')
                            self.assertEqual(value, {'status': 200, 'body_sha256': io.sha(body), 'bytes': len(body)})
                    self.assertEqual(len(children), 1); self.assertIsNotNone(children[0].poll())
                    self.assertTrue(all(s.closed for s in (children[0].stdin, children[0].stdout, children[0].stderr)))
                finally:
                    stop.set(); worker.join(2); listener.close()
                    self.assertFalse(worker.is_alive()); self.assertFalse(failures, failures)

    def test_http_cleanup_keeps_primary_and_nested_cleanup_separate(self):
        inner = io.Hold('PUBLIC_OPERATOR_HTTP_ABSOLUTE_DEADLINE')
        inner._http_cleanup = tuple(io.HTTP_CLEANUP)
        try:
            try: raise inner
            except io.Hold: raise RuntimeError('synthetic owner wrapper') from None
        except RuntimeError as outer:
            self.assertEqual(set(io.http_cleanup(outer)), io.HTTP_CLEANUP)
            self.assertEqual(inner.primary, 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_HTTP_ABSOLUTE_DEADLINE')

    @unittest.skipUnless(native_trace_capable(), 'requires isolated native Linux root with CAP_SYS_PTRACE')
    def test_actual_single_leader_start_sample_is_bound_not_another_start(self):
        # The faster pathname implementation must still perform BOTH complete
        # live samples. Instrumentation delegates every real read unchanged.
        text_reads = []; byte_reads = []
        text, binary = observe.proc_text, observe.proc_bytes
        def actual_text(path):
            text_reads.append(str(path)); return text(path)
        def actual_bytes(path):
            byte_reads.append(str(path)); return binary(path)
        with patch.object(observe, 'proc_text', actual_text), patch.object(observe, 'proc_bytes', actual_bytes):
            row = observe.process(os.getpid())
        self.assertEqual(row['pid'], os.getpid())
        for name in ('status', 'cgroup', 'uid_map', 'gid_map', 'setgroups'):
            self.assertEqual(sum(p.endswith('/'+name) for p in text_reads), 2)
        self.assertEqual(sum(p.endswith('/stat') for p in text_reads), 4)
        self.assertEqual(sum(p.endswith('/attr/current') for p in byte_reads), 2)
        self.assertEqual(sum(p.endswith('/cmdline') for p in byte_reads), 1)
        self.assertEqual(sum(p.endswith('/environ') for p in byte_reads), 1)
        program = '''import ctypes,signal,sys
libc=ctypes.CDLL(None)
def change(_number,_frame):
 assert libc.setfsuid(1001)==0;print("ACTUAL_START_PROFILE_CHANGED",flush=True)
signal.signal(signal.SIGUSR1,change)
print("ACTUAL_START_PROFILE_READY",flush=True)
assert sys.stdin.buffer.readline()==b"DONE\\n"
'''
        for initial in (False, True):
            with self.subTest(initial=initial):
                child = subprocess.Popen([sys.executable, '-I', '-B', '-c', program],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                    self.assertEqual(child.stdout.readline(128), b'ACTUAL_START_PROFILE_READY\n')
                    tick = observe.starttime(child.pid); original = observe.thread_security; changed = False
                    def change_after_actual_leader_status(path):
                        nonlocal changed
                        if not changed:
                            changed = True; child.send_signal(signal.SIGUSR1)
                            self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                            self.assertEqual(child.stdout.readline(128), b'ACTUAL_START_PROFILE_CHANGED\n')
                        return original(path)
                    with patch.object(observe, 'thread_security', change_after_actual_leader_status):
                        if initial:
                            row = observe.initial_profile(child.pid, tick, time.monotonic()+5)
                            self.assertEqual((row['pid'], row['starttime'], row['uid'][3]), (child.pid, tick, 1001))
                        else:
                            with self.assertRaisesRegex(io.Hold, 'ACTOR_LEADER_SECURITY_CHANGED_DURING_SAMPLE'):
                                observe.process(child.pid)
                    self.assertTrue(changed); self.assertEqual(observe.starttime(child.pid), tick)
                    with self.assertRaisesRegex(io.Hold, 'INITIAL_PROFILE_INVOCATION_CHANGED'):
                        observe.initial_profile(child.pid, 'NOT-THE-BOUND-TICK', time.monotonic()+1)
                    with self.assertRaisesRegex(io.Hold, 'INITIAL_PROFILE_DEADLINE'):
                        observe.initial_profile(child.pid, tick, time.monotonic()-1)
                finally:
                    _out, errors = child.communicate(b'DONE\n', timeout=5)
                    self.assertEqual(child.returncode, 0, errors)

    @unittest.skipUnless(native_trace_capable(), 'requires isolated native Linux root with CAP_SYS_PTRACE')
    def test_actual_unshared_nonleader_source_descriptor_is_rejected(self):
        program = '''import ctypes,os,sys,threading
fd=os.open(sys.argv[1],os.O_RDWR);ready=threading.Event();done=threading.Event()
def worker():
 assert ctypes.CDLL(None).unshare(0x400)==0
 ready.set();done.wait(10)
t=threading.Thread(target=worker);t.start();assert ready.wait(5)
os.close(fd);print("ACTUAL_UNSHARED_SOURCE_FD",flush=True)
assert sys.stdin.buffer.readline()==b"DONE\\n"
done.set();t.join(5);assert not t.is_alive()
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'synthetic-source'; path.write_bytes(b'SYNTHETIC SOURCE')
            s = path.stat(); target = (s.st_dev, s.st_ino)
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', program, str(path)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertTrue(select.select([child.stdout], [], [], 10)[0])
                self.assertEqual(child.stdout.readline(128), b'ACTUAL_UNSHARED_SOURCE_FD\n')
                tasks = Path('/proc')/str(child.pid)/'task'
                def holds(root):
                    return any((p.stat().st_dev, p.stat().st_ino) == target for p in (root/'fd').iterdir())
                self.assertFalse(holds(tasks/str(child.pid)))
                others = [p for p in tasks.iterdir() if p.name != str(child.pid)]
                self.assertEqual(len(others), 1); self.assertTrue(holds(others[0]))
                with self.assertRaisesRegex(io.Hold, 'EXISTING_SOURCE_WRITABLE_FD'):
                    observe.writer_check({target}, time.monotonic()+10)
                with self.assertRaisesRegex(io.Hold, 'ACTOR_THREAD_FILE_TABLE_NOT_SHARED'):
                    observe.process(child.pid)
                with self.assertRaisesRegex(io.Hold, 'ACTOR_THREAD_FILE_TABLE_NOT_SHARED'):
                    observe.initial_profile(child.pid, observe.starttime(child.pid), time.monotonic()+5)
            finally:
                _out, errors = child.communicate(b'DONE\n', timeout=10)
                self.assertEqual(child.returncode, 0, errors)

    @unittest.skipUnless(native_trace_capable(), 'requires isolated native Linux root with CAP_SYS_PTRACE')
    def test_actual_nonleader_security_must_match_leader(self):
        # Real per-task changes, not glibc's process-wide credential broadcast.
        # The observer never changes its own rights and touches no Host service.
        program = '''import ctypes,json,os,signal,sys,threading
from pathlib import Path
libc=ctypes.CDLL(None,use_errno=True)
mode=sys.argv[1];ready=threading.Event();done=threading.Event()
def worker():
 if mode=="nnp":assert libc.prctl(38,1,0,0,0)==0
 ready.set();done.wait(10)
t=threading.Thread(target=worker);t.start();assert ready.wait(5)
def retire(_number,_frame):
 done.set();t.join(5);assert not t.is_alive();print("ACTUAL_THREAD_EXITED",flush=True)
signal.signal(signal.SIGUSR1,retire)
if mode=="fsuid":assert libc.setfsuid(1001)==0
if mode=="fsgid":assert libc.setfsgid(1001)==0
if mode=="caps":
 class H(ctypes.Structure):_fields_=[("version",ctypes.c_uint32),("pid",ctypes.c_int)]
 class D(ctypes.Structure):_fields_=[("effective",ctypes.c_uint32),("permitted",ctypes.c_uint32),("inheritable",ctypes.c_uint32)]
 assert libc.capset(ctypes.byref(H(0x20080522,0)),(D*2)())==0
print("ACTUAL_THREADS_READY",flush=True)
assert sys.stdin.buffer.readline()==b"DONE\\n"
done.set();t.join(5);assert not t.is_alive()
'''
        for mode in ('same', 'fsuid', 'fsgid', 'caps', 'nnp'):
            with self.subTest(mode=mode):
                child = subprocess.Popen([sys.executable, '-I', '-B', '-c', program, mode],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    self.assertTrue(select.select([child.stdout], [], [], 10)[0])
                    self.assertEqual(child.stdout.readline(128), b'ACTUAL_THREADS_READY\n')
                    tasks = Path('/proc')/str(child.pid)/'task'
                    self.assertEqual(len(os.listdir(tasks)), 2)
                    if mode == 'same':
                        row = observe.process(child.pid)
                        self.assertRegex(row['threads_sha256'], '[a-f0-9]{64}')
                        with patch.object(observe, 'thread_security', side_effect=PermissionError):
                            with self.assertRaisesRegex(io.Hold, 'ACTOR_THREAD_VIEW_UNKNOWN'):
                                observe.threads_check(child.pid, row)
                        original = observe.thread_security; retired = False
                        def retire_after_real_read(path):
                            nonlocal retired
                            measured = original(path)
                            if not retired:
                                retired = True; child.send_signal(signal.SIGUSR1)
                                self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                                self.assertEqual(child.stdout.readline(128), b'ACTUAL_THREAD_EXITED\n')
                                # Python's join acknowledgement can precede
                                # final kernel task removal. Wait for the real
                                # synthetic exit, not a substituted census.
                                until = time.monotonic()+5
                                while len(os.listdir(tasks)) != 1:
                                    self.assertLess(time.monotonic(), until)
                                    time.sleep(.001)
                                self.assertEqual(len(os.listdir(tasks)), 1)
                            return measured
                        with patch.object(observe, 'thread_security', retire_after_real_read):
                            with self.assertRaisesRegex(io.Hold, 'ACTOR_THREAD_(VIEW_UNKNOWN|SET_CHANGED|FILE_TABLE_VIEW_UNKNOWN)'):
                                observe.threads_check(child.pid, row)
                    else:
                        first = observe.thread_security(tasks/str(child.pid))[1]
                        other = observe.thread_security(next(p for p in tasks.iterdir() if p.name != str(child.pid)))[1]
                        self.assertNotEqual(first, other)
                        with self.assertRaisesRegex(io.Hold, 'ACTOR_THREAD_SECURITY_MISMATCH'):
                            observe.process(child.pid)
                        with self.assertRaisesRegex(io.Hold, 'ACTOR_THREAD_SECURITY_MISMATCH'):
                            observe.initial_profile(child.pid, observe.starttime(child.pid), time.monotonic()+5)
                finally:
                    output, errors = child.communicate(b'DONE\n', timeout=10)
                    self.assertEqual(child.returncode, 0, errors)

    @unittest.skipUnless(native_trace_capable(), 'requires isolated native Linux root with CAP_SYS_PTRACE')
    def test_actual_child_dac_failure_is_not_replaced_by_fixture_cleanup(self):
        original = Path.chmod
        def deny_fixture_socket(path, mode, *args, **kwargs):
            # Fixture INPUT fault only: real mode0 on the actual synthetic
            # socket. No production observation/permission result is replaced.
            return original(path, 0 if path.name == 'synthetic.sock' else mode, *args, **kwargs)
        with patch.object(Path, 'chmod', deny_fixture_socket), self.assertRaises(NativeFSUIDFailure) as caught:
            self.test_actual_fsuid_socket_owner_cannot_be_admitted_as_other_effective_uid()
        self.assertEqual(caught.exception.primary, 'NATIVE_FSUID_CHILD_CONNECT_RED')
        self.assertEqual(caught.exception.native_errno, 13)

    @unittest.skipUnless(native_trace_capable(), 'requires isolated native Linux root with CAP_SYS_PTRACE')
    def test_actual_fsuid_socket_owner_cannot_be_admitted_as_other_effective_uid(self):
        self._actual_socket_dac_probe(filesystem_group=False)

    @unittest.skipUnless(native_trace_capable(), 'requires isolated native Linux root with CAP_SYS_PTRACE')
    def test_actual_fsgid_not_real_saved_group_controls_other_write(self):
        self._actual_socket_dac_probe(filesystem_group=True)

    def _actual_socket_dac_probe(self, *, filesystem_group):
        # Actual synthetic Unix socket and actual kernel fsuid in an owned
        # subprocess only. No administrative broker/provider operation.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); root.chmod(0o755); path = root/'synthetic.sock'
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(path)); listener.listen(1)
                os.chown(path, 1001, 1001); path.chmod(0o002 if filesystem_group else 0o200)
                program = '''import ctypes,json,os,socket,sys
from pathlib import Path
libc=ctypes.CDLL(None,use_errno=True)
phase="NATIVE_FSUID_CHILD_SETFSUID_RED"
try:
 group=sys.argv[2]=="GROUP"
 if group:
  os.setgroups([]);os.setresgid(1001,1002,1001)
 assert libc.setfsuid(1003 if group else 1001)==0
 phase="NATIVE_FSUID_CHILD_UID_VIEW_RED"
 s=dict(line.split(":",1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
 uids=list(map(int,s["Uid"].split()))
 assert os.geteuid()==0 and uids[1]==0 and uids[3]==(1003 if group else 1001)
 if group:assert list(map(int,s["Gid"].split()))==[1001,1002,1001,1002] and not s["Groups"].split()
 phase="NATIVE_FSUID_CHILD_CONNECT_RED"
 peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);peer.connect(sys.argv[1]);peer.close()
 print("ACTUAL_FSUID_SOCKET_CONNECTED",flush=True)
 phase="NATIVE_FSUID_CHILD_HANDSHAKE_RED"
 assert sys.stdin.buffer.readline()==b"DONE\\n"
except BaseException as error:
 number=error.errno if isinstance(error,OSError) and type(error.errno) is int and 0<error.errno<4096 else 0
 sys.stderr.write(json.dumps({"code":phase,"errno":number})+"\\n")
 raise SystemExit(1)
'''
                # The real production observer retains its privileged read
                # identity. Only the observed actor has a different fsuid.
                # Changing the observer's fsuid too would test different
                # procfs/LSM read authority, not the production DAC decision.
                child = subprocess.Popen([sys.executable, '-I', '-B', '-c', program, str(path),
                                          'GROUP' if filesystem_group else 'OWNER'],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                failure = None; ready = False
                try:
                    self.assertTrue(select.select([child.stdout], [], [], 10)[0])
                    ready = child.stdout.readline(128) == b'ACTUAL_FSUID_SOCKET_CONNECTED\n'
                    self.assertTrue(ready)
                    row = observe.process(child.pid)
                    self.assertEqual(row['uid'][1], 0); self.assertEqual(row['uid'][3], 1003 if filesystem_group else 1001)
                    if filesystem_group:
                        self.assertEqual(row['gid'], [1001, 1002, 1001, 1002]); self.assertEqual(row['groups'], [])
                    def unexpected(*a, **k): raise AssertionError('DAC_REJECTION_MUST_PRECEDE_INHERITED_INSPECTION')
                    authority = SimpleNamespace(b={'broker_tcp': [], 'broker_sockets': [str(path)]},
                                                inherited_sockets=unexpected)
                    with self.assertRaisesRegex(io.Hold, 'BROKER_EFFECTIVE_DAC_ACCESS'):
                        observe.Authority.broker_access(authority, row)
                except BaseException as error:
                    failure = error
                finally:
                    _out, errors = child.communicate(b'DONE\n', timeout=10)
                    if child.returncode != 0:
                        try:
                            detail = json.loads(errors)
                            self.assertEqual(set(detail), {'code', 'errno'})
                            self.assertIn(detail['code'], ('NATIVE_FSUID_CHILD_SETFSUID_RED', 'NATIVE_FSUID_CHILD_UID_VIEW_RED',
                                'NATIVE_FSUID_CHILD_CONNECT_RED', 'NATIVE_FSUID_CHILD_HANDSHAKE_RED'))
                            self.assertIs(type(detail['errno']), int); self.assertTrue(0 <= detail['errno'] < 4096)
                        except BaseException:
                            detail = {'code': 'NATIVE_FSUID_CHILD_PROTOCOL_RED', 'errno': 0}
                        child_failure = NativeFSUIDFailure(detail['code'], detail['errno'])
                        if failure is None or not ready:
                            if failure is not None: child_failure.__context__ = failure
                            failure = child_failure
                        else:
                            failure.native_cleanup = detail
                    if failure is not None: raise failure
            finally: listener.close()

    def test_unknown_or_non_uint32_restart_counter_denies_unit_read(self):
        for counter in ('', '-1', 'True', '00', '4294967296'):
            values = {p: '' for p in observe.PROPERTIES.split(',')}
            values.update(Id=observe.UNITS[0], LoadState='loaded', NRestarts=counter)
            reply = SimpleNamespace(returncode=0, stdout='\n'.join(k+'='+v for k, v in values.items()
                if k not in observe.EXEC_PROPERTIES).encode())
            bus=SimpleNamespace(returncode=0,stdout=io.canonical({'type':'a{sv}','data':[
                {k:{'type':'a(sasbttttuii)','data':[]} for k in observe.EXEC_PROPERTIES}]}))
            with self.subTest(counter=counter), patch.object(observe, 'command',
                    side_effect=lambda argv,*a,**kw:bus if argv[0]=='/usr/bin/busctl' else reply):
                with self.assertRaisesRegex(io.Hold, 'UNIT_RESTART_COUNTER_UNKNOWN'):
                    observe.Authority.unit(SimpleNamespace(deadline=time.monotonic()+1), observe.UNITS[0])

    def test_only_typed_present_empty_exec_arrays_mean_no_hook(self):
        # Parser-only samples. Real manager/D-Bus reads are mandatory native.
        raw={'type':'a{sv}','data':[{k:{'type':'a(sasbttttuii)','data':[]} for k in observe.EXEC_PROPERTIES}]}
        self.assertEqual(observe.typed_exec_properties(io.canonical(raw),observe.EXEC_PROPERTIES),
                         {k:'' for k in observe.EXEC_PROPERTIES})
        key='ExecStop';row=['/bin/false',['SYNTHETIC_SECRET'],False,0,0,0,0,0,0,0]
        raw['data'][0][key]['data']=[row]
        nonempty=observe.typed_exec_properties(io.canonical(raw),observe.EXEC_PROPERTIES)
        self.assertTrue(nonempty[key]);self.assertNotIn('SYNTHETIC_SECRET',nonempty[key])
        for bad in ({'type':'a{sv}','data':[{}]}, {'type':'a{sv}','data':[]},
            {'type':'a{sv}','data':[{key:{'type':'s','data':''}}]},
            {'type':'a{sv}','data':[{key:{'type':'a(sasbttttuii)','data':[[]]}}]}):
            with self.subTest(bad=bad),self.assertRaises(io.Hold):
                observe.typed_exec_properties(io.canonical(bad),{key})

    def test_unit_batch_requires_every_exact_individual_block(self):
        # Parser-only protocol cases, not manager/authority GREEN substitutes.
        units = observe.UNITS[:2]
        a = 'Id='+units[0]+'\nLoadState=loaded'
        b = 'Id='+units[1]+'\nLoadState=loaded'
        bad = (a, a+'\n\n'+a, a+'\n\n'+b+'\nId='+units[1],
               a+'\n\n'+b.replace(units[1], 'foreign.service'),
               a+'\n\n'+b+'\nUnknown=yes', a+'\n\n'+b.replace('LoadState=loaded', 'LoadState'))
        for raw in bad:
            with self.subTest(raw=raw), patch.object(observe, 'command',
                    return_value=SimpleNamespace(returncode=0, stdout=raw.encode())):
                with self.assertRaises(io.Hold): observe.unit_properties(units, 'LoadState', time.monotonic()+1)
        with patch.object(observe, 'command', return_value=SimpleNamespace(returncode=0,
                stdout=(b+'\n\n'+a+'\n').encode())) as queried:
            result = observe.unit_properties(units, 'LoadState', time.monotonic()+1)
            self.assertEqual(set(result), set(units)); self.assertEqual(queried.call_count, 1)

    def test_unit_batch_is_fresh_each_call_and_failure_is_not_cached(self):
        unit = observe.UNITS[0]; deadline = time.monotonic()+1
        first = SimpleNamespace(returncode=0, stdout=('Id='+unit+'\nLoadState=loaded').encode())
        changed = SimpleNamespace(returncode=0, stdout=('Id='+unit+'\nLoadState=not-found').encode())
        failed = SimpleNamespace(returncode=1, stdout=first.stdout)
        with patch.object(observe, 'command', side_effect=(first, changed, failed)) as queried:
            self.assertEqual(observe.unit_properties((unit,), 'LoadState', deadline)[unit]['LoadState'], 'loaded')
            self.assertEqual(observe.unit_properties((unit,), 'LoadState', deadline)[unit]['LoadState'], 'not-found')
            with self.assertRaisesRegex(io.Hold, 'UNIT_READ_UNKNOWN'):
                observe.unit_properties((unit,), 'LoadState', deadline)
            self.assertEqual(queried.call_count, 3)

    def test_owner_epoch_never_survives_success_failure_change_or_reentry(self):
        # Protocol/lifetime test ONLY, not a Host authorization observation.
        authority = observe.Authority.__new__(observe.Authority)
        authority._authorization_owner = None
        with patch.object(authority, 'policy_owner', side_effect=(':1.1', ':1.1', ':1.2', ':1.3')) as read:
            with authority.authorization_epoch(): self.assertEqual(authority._authorization_owner, ':1.1')
            self.assertIsNone(authority._authorization_owner)
            with self.assertRaisesRegex(io.Hold, 'AUTHORIZATION_OWNER_CHANGED'):
                with authority.authorization_epoch(): self.assertEqual(authority._authorization_owner, ':1.2')
            self.assertIsNone(authority._authorization_owner); self.assertEqual(read.call_count, 4)
        with patch.object(authority, 'policy_owner', return_value=':1.4') as read:
            with self.assertRaisesRegex(RuntimeError, 'SYNTHETIC_PRIMARY'):
                with authority.authorization_epoch(): raise RuntimeError('SYNTHETIC_PRIMARY')
            self.assertIsNone(authority._authorization_owner); self.assertEqual(read.call_count, 1)
            with self.assertRaisesRegex(io.Hold, 'AUTHORIZATION_EPOCH_REENTRY'):
                with authority.authorization_epoch():
                    with authority.authorization_epoch(): pass
            self.assertIsNone(authority._authorization_owner)

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
                self.assertEqual(argv, client.ssh_argv(argv[-1]))
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

    def test_actual_ssh_config_only_keeps_fixed_endpoint_and_trust_sources(self):
        # OpenSSH -G only parses configuration: no socket, key enrollment,
        # authentication, local command, sudo password or private payload.
        argv = client.ssh_argv('SYNTHETIC_NOT_EXECUTED')
        self.assertEqual(argv[:4], ['/usr/bin/ssh', '-F', '/dev/null', '-T'])
        result = subprocess.run([argv[0], '-G', *argv[1:]], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        values = {}
        for line in result.stdout.decode().splitlines():
            key, value = line.split(' ', 1); values.setdefault(key, []).append(value)
        expected = {'hostname': '100.121.130.51', 'user': 'chatops', 'port': '22',
            'userknownhostsfile': '/Users/daniel/.ssh/known_hosts', 'globalknownhostsfile': '/dev/null',
            'hostkeyalias': '100.121.130.51', 'identityfile': '/Users/daniel/.ssh/id_ed25519',
            'identityagent': 'none', 'identitiesonly': 'yes', 'canonicalizehostname': 'false',
            'permitlocalcommand': 'no', 'stricthostkeychecking': 'true', 'forwardagent': 'no',
            'controlmaster': 'false', 'preferredauthentications': 'publickey',
            'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no'}
        for key, value in expected.items(): self.assertEqual(values.get(key), [value], key)
        for key in ('proxycommand', 'proxyjump', 'knownhostscommand', 'remotecommand'):
            self.assertIn(values.get(key), (None, ['none']), key)

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
