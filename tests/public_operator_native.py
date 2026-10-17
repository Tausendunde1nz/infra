"""Real production session/Client/adapter in a fresh network-none PID1 guest.

Only synthetic application, SQL, TLS, policy and website data. The sole test
substitutions are EXPECTED target machine/owner-plan/custody/legacy-context bindings and,
for R5, the explicitly synthetic expected Application catalog/input bindings, because
real Host data and its immutable plan are forbidden here. No observation,
authorization query, fence, action, backup, supervisor or receipt is replaced.
The two restart-race cases also delay the caller AFTER the actual start command,
without substituting a manager response or safety decision. No production entry
exposes these test bindings/scheduler injections as CLI options.
Error-only instrumentation delegates the production source-location diagnostic,
returns it unchanged and captures only finite failure enums from its original
failing actor frame. It never replaces an observation/action or grants admission.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
import signal
from pathlib import Path
import stat
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, '/source/scripts')
sys.path.insert(0, '/source')
import tu1nz_public_operator as client
import tu1nz_public_operator_io as io

ROOT = Path('/fixture-r4')
APP = Path('/opt/tu1nz_repos/adult-publishing-core')
STATE = Path('/var/lib/tu1nz-adult-public-s9')
WEB = Path('/var/www/lighting.tu1nz.com')
UNITS = ('tu1nz-adult-public-s7.service', 'tu1nz-adult-public-s8-landing.service', 'tu1nz-adult-public-s10-wms.service')
CONFIGS = ('adult-commercial-s7-public.json', 'adult-commercial-s8-landing.json', 'adult-commercial-s10-wms.json')
PROFILES = ('s7', 's8-landing', 'wms')
SERVER = r'''import argparse,ctypes,json,mmap,os,sys,threading,time
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--contract');args,_=p.parse_known_args()
c=json.loads(Path(args.contract).read_bytes());body=('SYNTHETIC-'+c['profile']).encode()
handle_kind=Path('/var/lib/tu1nz-adult-public-s9/native-source-handle-kind')
if c['profile']=='s7' and handle_kind.exists():
 held_fd=os.open('/opt/tu1nz_repos/adult-publishing-core/source-handle.bin',os.O_RDWR)
 if handle_kind.read_text()=='shared':
  libc=ctypes.CDLL(None,use_errno=True);libc.mmap.restype=ctypes.c_void_p
  libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
  held_map=libc.mmap(None,os.fstat(held_fd).st_size,mmap.PROT_READ|mmap.PROT_WRITE,mmap.MAP_SHARED,held_fd,0)
  assert held_map not in (None,ctypes.c_void_p(-1).value)
  os.close(held_fd)
  ctypes.memmove(held_map,b'READY',5)
 else:
  os.pwrite(held_fd,b'READY',0);os.fsync(held_fd)
  if handle_kind.read_text()=='thread_fd':
   split_done=threading.Event()
   def split_source_table():
    while not Path('/var/lib/tu1nz-adult-public-s9/native-split-request').exists():time.sleep(.01)
    assert ctypes.CDLL(None).unshare(0x400)==0
    split_done.set();threading.Event().wait(120)
   threading.Thread(target=split_source_table).start()
if c['profile']=='s7' and Path('/var/lib/tu1nz-adult-public-s9/native-crash-request').exists():os._exit(72)
if c['profile']!='s7':
 root=Path('/var/lib/tu1nz-adult-public-s9')
 for name in ('landing-aggregates.json','wms-traffic-quality.json'):
  q=root/name
  if not q.exists():q.write_text('{"synthetic_count":7}');q.chmod(0o600)
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def do_HEAD(self):self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
 def log_message(self,*a):pass
server=HTTPServer((c['bind_host'],c['bind_port']),Handler)
if c['profile']=='s7' and handle_kind.exists() and handle_kind.read_text()=='thread_fd':
 server.timeout=.01
 while not split_done.is_set():server.handle_request()
 os.close(held_fd)
 Path('/var/lib/tu1nz-adult-public-s9/native-split-ready').write_bytes(b'READY')
server.serve_forever()
'''
SCENARIOS = ('success', 'writer', 'namespace_swap', 'lost_ack', 'interrupt', 'runtime_tamper',
             'restore_fail_return', 'probe_fail_return', 'denied_return', 'owner_return', 'lost_start_ack',
             'first_restart', 'old_restart', 'stop_source_fd', 'stop_source_mapping', 'unknown_actor', 'thread_authority',
             'thread_source_fd', 'r5_success', 'r5_legacy_unknown', 'r5_hooks', 'r5_chunk_loss',
             'r5_partial_interrupt', 'r5_artifact_tamper', 'r5_legacy_tamper', 'r5_old_return_denied', 'r5_first_restart', 'r5_owner_return')
PRODUCTION_FAULT = None
PRODUCTION_OUTCOME = None
ACTOR_DIAGNOSTIC = None
READ_COST = None
PRIMARY_WRITER_FAULT = None
NATIVE_ERRNO = None

# Delegating test-only timing of actual Source calls. No safety observation,
# action, result or deadline is replaced. Inclusive durations overlap; timing
# overhead exists and must not be called the uninstrumented CI root cause.
READ_COST_WRAPPER = r'''
import time as _cost_time
_read_cost={}
def _cost(name,actual):
 def invoke(*args,**kwargs):
  began=_cost_time.monotonic_ns()
  try:return actual(*args,**kwargs)
  finally:
   row=_read_cost.setdefault(name,{"calls":0,"inclusive_ns":0})
   row["calls"]+=1;row["inclusive_ns"]+=_cost_time.monotonic_ns()-began
 return invoke
_observer=s.load("observe")
for _name in ("check","check_files","units_check","actors_check"):
 setattr(_observer.Authority,_name,_cost("authority_"+_name,getattr(_observer.Authority,_name)))
for _name in ("process","writer_check"):
 _actual=getattr(_observer,_name);_wrapped=_cost(_name,_actual)
 setattr(_observer,_name,_wrapped)
 if _name=="process":
  for _role in ("host","probes"):
   if getattr(s.load(_role),_name,None) is _actual:setattr(s.load(_role),_name,_wrapped)
_paths=s.load("fs").Paths;_paths.check=_cost("paths_check",_paths.check)
_linked=s.load("io").LinkedRecords;_linked.record=_cost("linked_record",_linked.record)
_io=s.load("io");_io.measured_http=_cost("measured_http",_io.measured_http)
_owner=s.load("owner").Supervisor
for _name in ("check_all","apply","finish"):
 setattr(_owner,_name,_cost("owner_"+_name,getattr(_owner,_name)))
def _save_read_cost():
 import json,os
 raw=json.dumps(_read_cost,sort_keys=True).encode()
 fd=os.open("/fixture-r4/read-cost.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:os.write(fd,raw);os.fsync(fd)
 finally:os.close(fd)
'''

# Error-only instrumentation: returns the ACTUAL production diagnostic result
# unchanged. No observation/action/verdict replacement. No argv/PID/path/UID.
ACTOR_DIAGNOSTIC_WRAPPER = r'''
_actual_source_fault=s.load("host").source_fault_location
def _diagnostic_source_fault(error):
 location=_actual_source_fault(error)
 try:
  import json
  from pathlib import Path
  seen=set();current=error;captured=False
  while current is not None and id(current) not in seen and not captured:
   seen.add(id(current));trace=current.__traceback__
   while trace is not None and not captured:
    frame=trace.tb_frame
    if (getattr(current,"primary",None) in
        ("PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_ACTOR_THREAD_SECURITY_MISMATCH",
         "PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_ACTOR_LEADER_SECURITY_CHANGED_DURING_SAMPLE") and
        frame.f_code.co_filename=="<authenticated-memory:observe>" and frame.f_code.co_name=="threads_check"):
     state=frame.f_locals
     measured=state.get("security",{});expected=state.get("expected",{});leader=state.get("leader",{})
     executable=Path(leader.get("exe","UNKNOWN")).name
     if executable not in ("postgres","polkitd","systemd","systemd-journald","dbus-daemon","nginx","python3.12"):executable="OTHER"
     record={"executable_class":executable,"task_count":len(state.get("names",[])),
             "task_is_leader":state.get("name")==str(state.get("pid")),
             "different_fields":[k for k in ("uid","gid","groups","caps","nnp","cgroup","namespaces","uid_map","gid_map","setgroups","lsm_sha256") if measured.get(k)!=expected.get(k)]}
     raw=json.dumps(record,sort_keys=True).encode()
     fd=os.open("/fixture-r4/thread-diagnostic.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
     try:os.write(fd,raw);os.fsync(fd)
     finally:os.close(fd)
     captured=True
    if (getattr(current,"primary",None)=="PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_UNCLASSIFIED_OR_EXTRA_ACTOR" and
        frame.f_code.co_filename=="<authenticated-memory:observe>" and frame.f_code.co_name=="actors_check"):
     row=frame.f_locals.get("row");authority=frame.f_locals.get("self")
     if row is not None and authority is not None and not frame.f_locals.get("matched"):
      candidates=[r for r in authority.b["actors"] if r["exe_sha256"]==row["exe_sha256"]]
      keys=("uid","gid","groups","caps","nnp","argv_sha256","cgroup","initial_env_sha256","lsm_sha256","namespaces")
      different=[k for k in keys if candidates and all(row[k]!=r[k] for r in candidates)]
      executable=Path(row["exe"]).name
      if executable not in ("postgres","polkitd","systemd","systemd-journald","dbus-daemon","nginx","python3.12","busctl","systemctl","sudo","sleep"):executable="OTHER"
      stable=False;kind="UNKNOWN"
      try:
       raw=Path("/proc",str(row["pid"]),"cmdline").read_bytes()
       stable=s.load("io").sha(raw)==row["argv_sha256"] and s.load("observe").starttime(row["pid"])==row["starttime"]
       if stable:
        kind=("POSTGRES_AUTOVACUUM_WORKER" if executable=="postgres" and candidates and b"autovacuum worker" in raw else
              "POSTGRES_AUTOVACUUM_LAUNCHER" if executable=="postgres" and candidates and b"autovacuum launcher" in raw else "OTHER")
      except (FileNotFoundError,ProcessLookupError):pass
      record={"executable_class":executable,"matching_executable_profiles":len(candidates),"different_fields":different,
              "stable_followup":stable,"title_kind":kind}
      fd=os.open("/fixture-r4/actor-diagnostic.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
      with os.fdopen(fd,"w") as f:json.dump(record,f);f.flush();os.fsync(f.fileno())
      captured=True
    trace=trace.tb_next
   current=current.__cause__ or current.__context__
 except BaseException:pass
 return location
s.load("host").source_fault_location=_diagnostic_source_fault
'''

# Error-only provenance of the first underlying writer-view exception. The
# later once-return can itself fail; neither location may overwrite the other.
WRITER_DIAGNOSTIC_WRAPPER = r'''
_previous_source_fault=s.load("host").source_fault_location
def _writer_source_fault(error):
 location=_previous_source_fault(error)
 if getattr(error,"primary",None)!="PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_WRITER_VIEW_UNKNOWN":return location
 try:
  import json,os
  from pathlib import Path
  seen=set();current=error;fault=None;number=0;subject=None;tick=None
  while current is not None and id(current) not in seen:
   seen.add(id(current));trace=current.__traceback__
   while trace is not None:
    frame=trace.tb_frame
    if frame.f_code.co_filename=="<authenticated-memory:runtime_guard>":
     if frame.f_code.co_name=="writer_check":
      subject=frame.f_locals.get("root");tick=frame.f_locals.get("tick")
     if isinstance(current,(OSError,ValueError,KeyError,IndexError)):
      fault={"component":frame.f_code.co_filename,"line":trace.tb_lineno,"type":type(current).__name__}
      number=getattr(current,"errno",None) or 0
    trace=trace.tb_next
   current=current.__cause__ or current.__context__
  if fault is not None:
   record={"fault":fault,"errno":number}
   try:
    assert type(subject) is str and subject.startswith("/proc/")
    row=s.load("observe").process(int(subject.split("/")[2]))
    candidates=[r for r in p["baseline"]["actors"] if r["exe_sha256"]==row["exe_sha256"]]
    executable=Path(row["exe"]).name
    if executable not in ("postgres","polkitd","systemd","systemd-journald","dbus-daemon","nginx","python3.12","busctl","systemctl","sudo","sleep"):executable="OTHER"
    keys=("uid","gid","groups","caps","nnp","argv_sha256","cgroup","initial_env_sha256","lsm_sha256","namespaces")
    record["actor"]={"executable_class":executable,"matching_executable_profiles":len(candidates),
      "different_fields":[k for k in keys if candidates and all(row[k]!=r[k] for r in candidates)],
      "stable_followup":str(row["starttime"])==str(tick),"title_kind":"UNKNOWN"}
   except BaseException:pass  # missing process remains UNKNOWN; no invented actor
   fd=os.open("/fixture-r4/writer-diagnostic.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,"w") as stream:json.dump(record,stream);stream.flush();os.fsync(stream.fileno())
 except BaseException:pass
 return location
s.load("host").source_fault_location=_writer_source_fault
'''


class FaultWire:
    """Test faults are real Guest files/signals/transport, never observations.

    The actual production Client and remote admission/backup/action/supervisor
    code still execute. No REQUIRED facts, policy response or GREEN is replaced.
    """
    def __init__(self, wire, scenario, child):
        self.wire, self.scenario, self.child = wire, scenario, child
        self.record = None; self.intents = self.acks = 0; self.injected = []
        self.extra_actor = None

    @property
    def deadline(self): return self.wire.deadline

    def receive(self):
        message = self.wire.receive()
        if message.get('type') != 'durable_record': return message
        self.record = message['record']; kind, value = self.record['kind'], self.record['value']
        wanted = 'start_old' if self.scenario == 'old_restart' else 'start'
        if (self.scenario in ('first_restart', 'old_restart', 'r5_first_restart') and kind == 'host_action_intent' and
                value['action'] == wanted and value.get('unit') == UNITS[0]):
            marker = STATE/'native-crash-request'
            write(marker, b'SYNTHETIC_INITIAL_INVOCATION_CRASH_ONLY', 0o600); os.chown(marker, 1001, 1001)
            self.injected.append('REAL_INITIAL_FAILURE_ARMED')
        if kind == 'owner_object_intent':
            self.intents += 1
            if self.intents == 8 and self.scenario == 'namespace_swap':
                path = WEB/'dir0/file5'; saved = WEB/'dir0/fixture-renamed'
                os.rename(path, saved); os.rename(saved, path); self.injected.append('REAL_RENAME_AND_RETURN')
            if self.intents == 8 and self.scenario == 'interrupt':
                fd = os.pidfd_open(self.child.pid)
                try: signal.pidfd_send_signal(fd, signal.SIGINT)
                finally: os.close(fd)
                self.injected.append('OWNED_COORDINATOR_PIDFD_INTERRUPT')
        if kind == 'owner_object_ack': self.acks += 1
        if kind == 'host_action_intent' and not self.injected:
            if value['action'] == 'isolated_restore_rehearsal' and self.scenario == 'restore_fail_return':
                p = Path('/opt/tu1nz_repos/public-web-isolation-r1/20261014-1/before/000')
                p.write_bytes(b'SYNTHETIC_PRIVATE_BACKUP_CORRUPTION'); self.injected.append('REAL_BACKUP_CORRUPTION')
            if value['action'] == 'create_sealed_staging' and self.scenario == 'denied_return':
                p = APP/'.venv/bin/tu1nz-public-s7'
                p.write_bytes(p.read_bytes()+b'\n# SYNTHETIC_RUNTIME_DRIFT\n')
                self.injected.append('REAL_RUNTIME_DRIFT_AFTER_STOP')
        if kind == 'probe_start_intent' and not self.injected and self.scenario in ('probe_fail_return', 'old_restart'):
            p = Path('/opt/tu1nz_repos/public-web-isolation-r1/20261014-1/probe/inputs/s7_form_secret')
            p.write_bytes(b'SYNTHETIC-ONLY-DIFFERENT-00000000000000000000000000000000')
            self.injected.append('REAL_SYNTHETIC_CREDENTIAL_DRIFT')
        if kind=='replacement_install_progress' and not self.injected and self.scenario=='r5_partial_interrupt':
            fd=os.pidfd_open(self.child.pid)
            try:signal.pidfd_send_signal(fd,signal.SIGINT)
            finally:os.close(fd)
            self.injected.append('REAL_R5_PARTIAL_INSTALL_INTERRUPT')
        if kind=='replacement_artifact_verified' and not self.injected and self.scenario=='r5_artifact_tamper':
            import tu1nz_public_runtime_artifact as artifact
            p=Path(artifact.ROOT)/'python/bin/python3.12';p.write_bytes(b'SYNTHETIC_TAMPER')
            self.injected.append('REAL_R5_ARTIFACT_WRITE_AFTER_FENCE')
        if kind=='replacement_artifact_verified' and not self.injected and self.scenario=='r5_legacy_tamper':
            p=APP/'.venv/bin/tu1nz-public-s7';p.write_bytes(b'SYNTHETIC_LEGACY_TAMPER')
            self.injected.append('REAL_R5_LEGACY_WRITE_AFTER_REPLACEMENT')
        if kind=='probe_start_intent' and not self.injected and self.scenario=='r5_old_return_denied':
            p=Path('/opt/tu1nz_repos/public-web-isolation-r1/20261014-1/probe/inputs/s7_form_secret')
            p.write_bytes(b'SYNTHETIC-ONLY-DIFFERENT-00000000000000000000000000000000')
            self.injected.append('REAL_SYNTHETIC_CREDENTIAL_DRIFT')
        return message

    def send(self, message):
        if message.get('type')=='runtime_chunk' and not self.injected and self.scenario=='r5_chunk_loss':
            message={**message,'index':message['index']+1}
            self.injected.append('REAL_R5_WRONG_CHUNK_SEQUENCE')
        if message.get('type') == 'persisted' and self.record is not None:
            kind, value = self.record['kind'], self.record['value']
            if self.scenario == 'unknown_actor' and kind == 'owner_object_ack' and self.acks == 1:
                self.extra_actor = subprocess.Popen(['/usr/bin/sleep', '120'])
                self.injected.append('REAL_UNCLASSIFIED_NEW_PROCESS')
            if self.scenario == 'lost_ack' and kind == 'owner_object_ack' and self.acks == 8:
                message = {**message, 'sha256': '0'*64}; self.injected.append('REAL_INVALID_TRANSPORT_ACK')
            if self.scenario == 'lost_start_ack' and kind == 'host_action_ack' and value['action'] == 'start':
                message = {**message, 'sha256': '0'*64}; self.injected.append('REAL_INVALID_START_ACK')
            if self.scenario in ('owner_return','r5_owner_return') and kind == 'owner_object_intent' and self.intents == 8:
                message = {**message, 'control': 'HOLD_BEFORE_OWNER_EFFECT'}
                self.injected.append('EXPLICIT_DURABLE_OWNER_DENIAL_BEFORE_EFFECT')
        if message.get('type') == 'decision':
            if self.scenario in ('restore_fail_return', 'probe_fail_return', 'denied_return', 'lost_start_ack', 'old_restart', 'r5_old_return_denied'):
                message = {'type': 'decision', 'value': 'RETURN_OLD'}
                if self.scenario=='r5_old_return_denied':self.injected.append('REAL_R5_FORBIDDEN_OLD_RETURN_REQUEST')
            elif self.scenario in ('owner_return', 'r5_owner_return', 'namespace_swap', 'lost_ack'):
                message = {'type': 'decision', 'value': 'OWNER_RETURN'}
        self.wire.send(message)


def run(*args, data=None):
    r = subprocess.run(args, input=data, capture_output=True, timeout=30)
    if r.returncode:
        raise RuntimeError('SYNTHETIC_SETUP_'+Path(args[0]).name+'_EXIT_'+str(r.returncode))
    return r.stdout


def write(path, raw, mode=0o644):
    path = Path(path); path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())


def assert_guest():
    assert os.geteuid() == 0 and Path('/.dockerenv').is_file() and os.environ.get('container') == 'docker'
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert not ROOT.exists() and not Path('/opt/tu1nz_repos').exists()
    assert all(p.name == 'lo' or not int((p/'flags').read_text(), 16) & 1
               for p in Path('/sys/class/net').iterdir() if p.is_dir())
    assert not Path('/proc/net/route').read_text().splitlines()[1:]
    for path in ('/source', '/control-source'):
        assert run('/usr/bin/findmnt', '-n', '-o', 'VFS-OPTIONS', '-T', path).decode().split(',')[0] == 'ro'


def source():
    paths = {n: Path('/source')/p for n, p in client.INFRA_FILES.items()}
    paths.update({n: Path('/control-source')/p for n, p in client.CONTROL_FILES.items()})
    raw = {n: p.read_bytes() for n, p in paths.items()}
    hashes = {n: io.sha(x) for n, x in raw.items()}
    encoded = {n: base64.b64encode(x).decode() for n, x in raw.items()}
    s = io.Source(encoded, hashes)
    for name in ('io', 'entry', 'guard', 'owner', 'r3', 'fs', 'runtime_guard', 'observe', 'probes', 'host'): s.load(name)
    return s, encoded, hashes


def prepare_guest_kernel_view():
    """Fixture-only read view, before either component or full driver tests.

    The production adapter never mounts a Host filesystem to fill a missing
    observation. This is the already-used synthetic Guest prerequisite only.
    """
    assert os.geteuid() == 0 and Path('/.dockerenv').is_file() and os.environ.get('container') == 'docker'
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert run('/usr/bin/findmnt', '-n', '-o', 'PROPAGATION', '--mountpoint', '/').strip() == b'private'
    # Read-only kernel inventory mount in this synthetic guest only. Never a
    # production-adapter effect: absent Host evidence must remain UNKNOWN.
    if not Path('/sys/kernel/security/lsm').exists():
        run('/usr/bin/mount', '-t', 'securityfs', '-o', 'ro', 'securityfs', '/sys/kernel/security')
    assert Path('/sys/kernel/security/lsm').read_text().strip()


def setup(s, *, source_handle=None):
    ROOT.mkdir(mode=0o700)
    prepare_guest_kernel_view()
    # Distribution nginx may already be running in this NEW disposable guest.
    # Stop that fixture service before constructing its synthetic edge. This
    # is not a production-adapter action and never reaches an existing Host.
    run('/usr/bin/systemctl', 'stop', 'nginx.service')
    import pwd
    try: pwd.getpwnam('chatops')
    except KeyError:
        run('/usr/sbin/groupadd', '--gid', '1001', 'chatops')
        run('/usr/sbin/useradd', '--uid', '1001', '--gid', '1001', '--no-create-home', 'chatops')
    # Reproduce the existing expected parent ACL, without touching a Host.
    parent = Path('/opt/tu1nz_repos'); parent.mkdir(); os.chown(parent, 0, 1001)
    unset = 0xffffffff
    access = [(1,5,unset),(2,1,995),(2,1,996),(2,7,1001),(4,7,unset),(8,7,1001),(16,5,unset),(32,0,unset)]
    default = [(1,7,unset),(2,7,1001),(4,7,unset),(8,5,1001),(16,7,unset),(32,0,unset)]
    for name, rows in (('access', access), ('default', default)):
        os.setxattr(parent, 'system.posix_acl_'+name, struct.pack('<I', 2)+b''.join(struct.pack('<HHI', *r) for r in rows))
    parent.chmod(0o2550)
    # Private synthetic App tree, with its own inherited ACL removed explicitly
    # by the fixture creator. The production adapter never normalizes this tree.
    APP.mkdir(mode=0o755)
    for attr in os.listxattr(APP): os.removexattr(APP, attr)
    os.chown(APP, 0, 0); APP.chmod(0o755)
    for profile in ('s7', 's8-landing'):
        write(APP/('.venv/bin/tu1nz-public-'+profile), b'#!/usr/bin/python3\n'+SERVER.encode(), 0o555)
    write(APP/'src/tu1nz_exposure_s10/__init__.py', b'')
    write(APP/'src/tu1nz_exposure_s10/runtime.py', SERVER.encode())
    os.symlink('/usr/bin/python3', APP/'.venv/bin/python')
    STATE.mkdir(mode=0o700, parents=True); os.chown(STATE, 1001, 1001)
    for name in ('landing-aggregates.json', 'wms-traffic-quality.json'):
        write(STATE/name, b'{"synthetic_count":7}', 0o600); os.chown(STATE/name, 1001, 1001)
    for i, (name, profile) in enumerate(zip(CONFIGS, PROFILES)):
        write('/etc/tu1nz/'+name, io.canonical({'profile': profile, 'canonical_origin':
            'https://wantmeseen.com' if i == 2 else 'https://tu1nz.com', 'bind_host': '127.0.0.1', 'bind_port': 18071+i}))
    for name in ('adult-commercial-s10-wms-copy.json', 'adult-commercial-s10-wms-bot-identity.json',
                 'adult-commercial-s10-2d-community.json'):
        write('/etc/tu1nz/'+name, b'{"synthetic":1}')
    write('/etc/tu1nz/adult-commercial-s7-form.secret', b'SYNTHETIC-ONLY-NOT-A-PRODUCTION-SECRET', 0o600)
    write('/etc/tu1nz/adult-commercial-s7-database.dsn', b'postgresql:///r4_probe', 0o600)
    for unit in UNITS:
        raw = (Path('/source/systemd')/unit).read_bytes()
        write('/etc/systemd/system/'+unit, raw)
    write('/etc/systemd/system/'+UNITS[1]+'.d/s9-growth.conf',
          (Path('/source/systemd')/(UNITS[1]+'.d/s9-growth.conf')).read_bytes())
    # Existing static NO policy in this synthetic environment, not a proposed
    # Host installation and not a fake authorization result. Real D-Bus policy
    # evaluations and the live unique owner are subsequently checked.
    write('/etc/polkit-1/rules.d/00-fixture-public-no-admin.rules', s.load('observe').STATIC_SYSTEMD_DENY)
    run('/usr/bin/systemctl', 'start', 'polkit.service')
    run('/usr/bin/pg_ctlcluster', '16', 'main', 'status')
    # Real value in the fresh fixture cluster, not an accepted actor/health
    # flag. Automatic maintenance is not part of a deterministic success case.
    # Production unknown-actor rejection and the explicit extra-process fault
    # remain untouched. The PID1 fixture initializer sets this before boot.
    assert run('/usr/sbin/runuser','-u','postgres','--','/usr/bin/psql','-X','-At',
               '-c','SHOW autovacuum;').strip()==b'off'
    sql = ("CREATE ROLE chatops LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; "
           "CREATE DATABASE r4_probe OWNER chatops;")
    run('/usr/sbin/runuser', '-u', 'postgres', '--', '/usr/bin/psql', '-X', '-v', 'ON_ERROR_STOP=1', data=sql.encode())
    run('/usr/sbin/runuser', '-u', 'postgres', '--', '/usr/bin/psql', '-X', '-d', 'r4_probe',
        '-v', 'ON_ERROR_STOP=1', data=("CREATE TABLE commercial_s7_waitlist (id int); "
        "CREATE TABLE commercial_s7_analytics_events (id int); "
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO chatops;").encode())
    # Own ext4 website supports real FID metadata notifications and all leases.
    run('/usr/bin/truncate', '-s', '512M', str(ROOT/'web.img'))
    run('/usr/sbin/mkfs.ext4', '-q', '-F', str(ROOT/'web.img'))
    # Docker exposes only loop0..7 by default although the kernel allocates
    # further devices. Retain every earlier fixture; create only the missing
    # device node in THIS guest's private /dev, never detach another image.
    loop_control = os.open('/dev/loop-control', os.O_RDWR | os.O_CLOEXEC)
    try: loop_number = fcntl.ioctl(loop_control, 0x4C82, 0)  # LOOP_CTL_GET_FREE
    finally: os.close(loop_control)
    assert 0 <= loop_number < 64
    loop_path = Path('/dev/loop'+str(loop_number))
    if not loop_path.exists(): os.mknod(loop_path, stat.S_IFBLK | 0o600, os.makedev(7, loop_number))
    assert stat.S_ISBLK(loop_path.stat().st_mode) and loop_path.stat().st_rdev == os.makedev(7, loop_number)
    Path('/var/www').mkdir(exist_ok=True)
    run('/usr/bin/mount', '-o', 'loop', str(ROOT/'web.img'), '/var/www')
    WEB.mkdir(mode=0o755)
    for i in range(5): (WEB/('dir'+str(i))).mkdir(mode=0o755)
    for i in range(82):
        p = WEB/'index.html' if i == 0 else WEB/('dir'+str(i%5))/('file'+str(i))
        write(p, ('SYNTHETIC-FILE-'+str(i)).encode())
        os.chown(p, 0 if 1 <= i <= 4 else 33, 33)
    for p in [WEB, *WEB.glob('dir*')]: os.chown(p, 33, 33)
    if source_handle is not None:
        # Synthetic INPUT fault before admission: a real service opens a file
        # while writable, then root restores read-only metadata. Existing FD /
        # shared map authority survives chmod and must still deny the stop.
        assert source_handle in ('fd', 'shared', 'thread_fd')
        write(APP/'source-handle.bin', b'SYNTHETIC-SOURCE-HANDLE\n'*128, 0o666)
        (APP/'source-handle.bin').chmod(0o666)  # real fixture access, not subject to creator umask
        write(STATE/'native-source-handle-kind', source_handle.encode())
        write('/etc/systemd/system/'+UNITS[0]+'.d/fixture-source-handle.conf',
              b'[Service]\nReadWritePaths=/opt/tu1nz_repos/adult-publishing-core/source-handle.bin\n'+
              (b'ReadWritePaths=/var/lib/tu1nz-adult-public-s9/native-split-ready\n'
               if source_handle == 'thread_fd' else b''))
        if source_handle == 'thread_fd':
            # Only this synthetic acknowledgement file, not a writable State
            # directory or a changed production permission/drop-in contract.
            write(STATE/'native-split-ready', b'', 0o600)
            os.chown(STATE/'native-split-ready', 1001, 1001)
    # Synthetic public edge: real nginx UID33 reads, real TLS validation and
    # real proxy requests. DNS/TLS trust are fixture data confined to this guest.
    run('/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=TU1NZ-SYNTHETIC-ONLY', '-addext', 'subjectAltName=DNS:tu1nz.com,DNS:wantmeseen.com,DNS:lighting.tu1nz.com',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', str(ROOT/'tls.key'), '-out', str(ROOT/'tls.crt'))
    run('/usr/bin/cp', str(ROOT/'tls.crt'), '/usr/local/share/ca-certificates/tu1nz-synthetic.crt')
    run('/usr/sbin/update-ca-certificates')
    with Path('/etc/hosts').open('a') as f:
        f.write('\n127.0.0.1 tu1nz.com wantmeseen.com lighting.tu1nz.com '+socket.gethostname()+'\n')
    nginx = ('user www-data; worker_processes 1; pid /run/nginx.pid; events { worker_connections 128; }\n'
             'http { access_log off; error_log '+str(ROOT/'nginx-error.log')+' error;\n')
    for domain, locations in (
        ('tu1nz.com', 'location /adult/ { proxy_pass http://127.0.0.1:18071; } location / { proxy_pass http://127.0.0.1:18072; }'),
        ('wantmeseen.com', 'location / { proxy_pass http://127.0.0.1:18073; }'),
        ('lighting.tu1nz.com', 'root '+str(WEB)+'; index index.html;')):
        nginx += ('server { listen 80; listen 443 ssl; server_name '+domain+'; ssl_certificate '+str(ROOT/'tls.crt')+
                  '; ssl_certificate_key '+str(ROOT/'tls.key')+'; '+locations+' }\n')
    nginx += '}\n'
    # Replace only this new guest's distribution fixture config, never a Host.
    Path('/etc/nginx/nginx.conf').write_text(nginx)
    run('/usr/bin/systemctl', 'daemon-reload')
    for unit in UNITS: run('/usr/bin/systemctl', 'start', unit)
    run('/usr/bin/systemctl', 'start', 'nginx.service')
    if source_handle is not None:
        deadline = time.monotonic()+10
        while not (APP/'source-handle.bin').read_bytes().startswith(b'READY'):
            assert time.monotonic() < deadline
            time.sleep(.01)
        (APP/'source-handle.bin').chmod(0o555)


def baseline(s, *, replacement_dependencies=None):
    observer = s.load('observe'); entry = s.load('entry'); fs = s.load('fs')
    paths = fs.Paths(entry, deadline=time.monotonic()+120)
    pseudo = observer.Authority.__new__(observer.Authority)
    pseudo.paths = paths; pseudo.deadline = paths.deadline
    pseudo.own_config_paths = set(); pseudo.new_parent_paths = set()
    machine = io.sha(Path('/etc/machine-id').read_bytes())
    origin = io.sha(Path(__file__).read_bytes())
    b = {'schema': 'TU1NZ_PUBLIC_HOST_BASELINE_V1', 'machine_sha256': machine,
         'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'files': {}, 'unit_files': {},
         'actors': [], 'policy_roots': {}, 'broker_sockets': [], 'broker_tcp': [], 'source_release': {},
         'http': {}, 'database': {}, 'nginx_groups': [33], 'source_origin_receipts': [origin],
         'unit_search_sha256': pseudo.unit_search()}
    files = {str(p) for p in Path('/etc/tu1nz').iterdir()} | {
        '/etc/passwd', '/etc/group', '/etc/nsswitch.conf', '/etc/sudoers', '/etc/hosts'}
    for unit in UNITS:
        v = observer.Authority.unit(pseudo, unit)
        b['unit_files'][unit] = {'fragment': v['FragmentPath'], 'dropins': v['DropInPaths'].split(),
                                'properties': {k: v[k] for k in ('Requires', 'BindsTo', 'PartOf', 'KillMode',
                                                               'Restart', 'User', 'Group', 'NoNewPrivileges')}}
        files.update([v['FragmentPath'], *v['DropInPaths'].split()])
    roots = ('/etc/polkit-1/rules.d', '/usr/share/polkit-1/rules.d', '/etc/sudoers.d',
             '/etc/dbus-1/system.d', '/usr/share/dbus-1/system.d')
    for root in roots:
        b['policy_roots'][root] = sorted(os.listdir(root)); files.update(root+'/'+n for n in b['policy_roots'][root])
    for p in sorted(files):
        raw, m = paths.read(p)
        b['files'][p] = {k: m[k] for k in ('uid', 'gid', 'mode', 'attrs', 'flags')}
        b['files'][p].update(sha256=io.sha(raw), origin_sha256=origin)
    targets = {int(observer.Authority.unit(pseudo, u)['MainPID']) for u in UNITS}
    profiles = {}
    for name in os.listdir('/proc'):
        if not name.isdecimal() or int(name) in targets: continue
        try: row = observer.process(int(name))
        except (FileNotFoundError, ProcessLookupError): continue
        if row.get('kernel_thread'): continue
        role = 'kernel_manager' if int(name) == 1 else ('nginx_reader' if row['uid'] == [33]*4 else
                'authenticated_maintenance' if int(name) == os.getpid() else 'administrative_service')
        profile = {k: row[k] for k in ('exe', 'exe_sha256', 'uid', 'gid', 'groups', 'caps', 'nnp',
                                      'argv_sha256', 'cgroup', 'initial_env_sha256', 'lsm_sha256', 'namespaces')}
        profile.update(role=role, max_instances=0, origin_sha256=origin)
        key = io.sha(io.canonical(profile)); profiles.setdefault(key, profile)['max_instances'] += 1
    b['actors'] = list(profiles.values())
    # Pin installed dependency bytes, not a hardcoded "kernel supported" flag.
    dependencies = {}; objects = set(); python = Path('/usr/bin/python3').resolve()
    for path in [python, *(p for p in Path('/usr/lib/python3.12').rglob('*') if
                            p.is_file() and not p.is_symlink() and p.suffix in ('.py', '.so'))]:
        dependencies[str(path)] = {'source': str(path.resolve()), 'sha256': io.sha(path.read_bytes())}
        if path == python or path.suffix == '.so':
            for line in run('/usr/bin/ldd', str(path)).decode().splitlines():
                objects.update(w for w in line.split() if w.startswith('/'))
    for name in objects:
        path = Path(name); dependencies[name] = {'source': str(path.resolve()), 'sha256': io.sha(path.read_bytes())}
    dependencies['/usr/bin/python3'] = {'source': str(python), 'sha256': io.sha(python.read_bytes())}
    for name,row in (replacement_dependencies or {}).items():
        path=Path(name)
        # Fresh actual synthetic package bytes, not an accepted GREEN flag.
        assert row=={'source':str(path.resolve(strict=True)),'sha256':io.sha(path.read_bytes())}
        assert str(path.resolve()).startswith(('/usr/lib/','/usr/bin/'))
        if name in dependencies:assert dependencies[name]==row
        dependencies[name]=row
    objects = {'.': {'kind': 'directory'}}
    for p in sorted(APP.rglob('*')):
        rel = str(p.relative_to(APP))
        objects[rel] = ({'kind': 'link', 'target': os.readlink(p)} if p.is_symlink() else
                        {'kind': 'directory'} if p.is_dir() else {'kind': 'file', 'sha256': io.sha(p.read_bytes())})
    b['source_release'] = {'probe_dependencies': dependencies, 'python_binary': str(python),
        'runtime_reference': {'schema': 'TU1NZ_PUBLIC_RUNTIME_REFERENCE_V1', 'commit': origin[:40],
            'tree': io.sha(io.canonical(objects))[:40], 'origin_sha256': origin, 'objects': objects}}
    b['database'] = {'role': 'chatops', 'database': 'r4_probe', 'credential_sha256': {
        's7_form_secret': io.sha(Path('/etc/tu1nz/adult-commercial-s7-form.secret').read_bytes()),
        's7_database_dsn': io.sha(Path('/etc/tu1nz/adult-commercial-s7-database.dsn').read_bytes())}}
    for i, unit in enumerate(UNITS):
        path = '/adult/health' if i == 0 else '/health'; domain = 'wantmeseen.com' if i == 2 else 'tu1nz.com'
        body = ('SYNTHETIC-'+PROFILES[i]).encode()
        def endpoint(stage, location, url, host):
            return {'stage': stage, 'location': location, 'url': url, 'method': 'GET', 'host_header': host,
                    'status': 200, 'body_sha256': io.sha(body)}
        b['http'][unit] = [endpoint('internal', 'host', 'http://127.0.0.1:'+str(18071+i)+path, None),
            endpoint('proxy', 'host', 'http://127.0.0.1'+path, domain),
            endpoint('public', 'client', 'https://'+domain+path, None)]
    b['http']['lighting'] = {'stage': 'public', 'location': 'client', 'url': 'https://lighting.tu1nz.com/',
        'method': 'GET', 'host_header': None, 'status': 200, 'body_sha256': io.sha((WEB/'index.html').read_bytes())}
    errors = paths.close(); assert not errors
    return b


def plan(s, machine):
    guard = s.load('guard'); guard.d.MACHINE = machine
    rows = {}
    for p in [WEB, *sorted(WEB.rglob('*'))]:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try: rows[str(p.relative_to(WEB))] = guard.observe_fd(fd)
        finally: os.close(fd)
    capture = {'schema': 'TU1NZ_LIGHTING_COMPLETE_PROTECTED_READ_V1', 'host': machine, 'root': str(WEB),
               'objects': rows, 'second_pass': rows, 'observed_at_utc': '2026-10-16T00:00:00Z',
               'reader_sha256': io.sha(Path(__file__).read_bytes())}
    return io.canonical(guard.ownership_plan(capture))


def source_read_census_fence(s):
    """Actual parent rename/return during the real compiled read census.

    Fixture input mutation only; the stable reader and all safety checks run
    unchanged. No synthetic GREEN or Host observation is substituted.
    """
    folder = APP/'read-census'; folder.mkdir()
    for name in ('a.json', 'b.json'): write(folder/name, b'SYNTHETIC-READ-CENSUS\n')
    d = s.load('entry'); observer = s.load('observe')
    paths = s.load('fs').Paths(d, deadline=time.monotonic()+20)
    reader = observer.Authority.__new__(observer.Authority)
    reader.paths = paths; reader.deadline = paths.deadline; reader.initial = {}
    origin = io.sha(Path(__file__).read_bytes()); files = {}
    for name in ('a.json', 'b.json'):
        raw, row = paths.read(str(folder/name))
        files[str(folder/name)] = {k: row[k] for k in ('uid', 'gid', 'mode', 'attrs', 'flags')}
        files[str(folder/name)].update(sha256=io.sha(raw), origin_sha256=origin)
    reader.b = {'files': files, 'source_origin_receipts': [origin]}
    reader.check_files()  # real positive census, including current NSS checks
    original = d.stable_file; swapped = False; rejected = False
    def rename_after_actual_read(parent, name, *args, **kwargs):
        nonlocal swapped
        result = original(parent, name, *args, **kwargs)
        if name == 'a.json' and not swapped:
            swapped = True
            moved = folder.with_name('read-census-moved')
            folder.rename(moved); moved.rename(folder)
        return result
    d.stable_file = rename_after_actual_read
    try:
        try: reader.check_files()
        except s.load('io').Hold as error:
            assert error.primary in ('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_PATH_RENAME_EVENT',
                                     'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_PATH_WATCH_LOST')
            rejected = True
        assert swapped and rejected
    finally:
        d.stable_file = original
        assert paths.close()  # the failed namespace fence stays latched


def actual_policy_owner_epoch(s):
    # The same actual D-Bus reads as production. Restart ONLY the synthetic
    # Guest's own policy daemon, BEFORE taking the fixture baseline. This is
    # not a Host operation or a substituted authorization/owner response.
    observer = s.load('observe'); authority = observer.Authority.__new__(observer.Authority)
    authority.deadline = time.monotonic()+20; authority._authorization_owner = None
    with authority.authorization_epoch(): pass
    rejected = False
    try:
        with authority.authorization_epoch(): run('/usr/bin/systemctl', 'restart', 'polkit.service')
    except s.load('io').Hold as error:
        assert error.primary == 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_AUTHORIZATION_OWNER_CHANGED'
        rejected = True
    assert rejected and authority._authorization_owner is None


def actual_loader_alias_fence(s):
    """Own synthetic library names only; no systemd ancestor/reload experiment."""
    replacement=s.load('replacement');entry=s.load('entry');fs=s.load('fs')
    for case in ('ancestor','leaf','file'):
        root=ROOT/('loader-name-'+case);root.mkdir(mode=0o700)
        real=root/'real';real.mkdir(mode=0o755);write(real/'library.bin',b'SYNTHETIC_LIBRARY_BYTES',0o444)
        (root/'top').symlink_to('real');(root/'loader').symlink_to('top')
        (real/'leaf.so').symlink_to('library.bin')
        paths=fs.Paths(entry,deadline=time.monotonic()+20)
        reader=replacement.ReplacementAuthority.__new__(replacement.ReplacementAuthority)
        reader.paths=paths;reader.deadline=paths.deadline;reader.loader_bindings={};reader.loader_aliases={}
        try:
            assert reader.bind_loader_path(str(root/'loader/leaf.so'))==str(real/'library.bin')
            reader.check_loader_paths()
            changed=root/'top' if case=='ancestor' else real/('leaf.so' if case=='leaf' else 'library.bin')
            saved=changed.with_name('saved-object');changed.rename(saved);saved.rename(changed)
            rejected=False
            try:reader.check_loader_paths()
            except s.load('io').Hold:rejected=True
            assert rejected
        finally:assert paths.close()  # failed namespace binding remains latched


def production_outcome(result,code,r,fault_wire,stderr):
    """Retain the actual result BEFORE a later test-only proof can fail.

    Missing fault-injection evidence must fail the test, not erase a prior
    admission rejection or be misreported as the production cause.
    """
    acknowledgments=list((r.CUSTODY_PARENT/r.TX/'operator-records').glob('*-owner_object_ack.json'))
    actual_root=sum(p.stat().st_uid==0 for p in [WEB,*WEB.rglob('*')])
    value={k:result.get(k) for k in ('status','primary','abort','cleanup')}
    value.update(abort=result.get('abort',[]),cleanup=result.get('cleanup',[]),
        client_error_type=result.get('error_type'),server_exit=code,owner_confirmations=len(acknowledgments),
        actual_root_objects=actual_root,last_record_kind=fault_wire.record.get('kind') if fault_wire.record else None,
        last_record_sequence=fault_wire.record.get('sequence',0) if fault_wire.record else 0)
    from tu1nz_public_operator_ci import terminal_wire_code
    value['server_terminal_code']=terminal_wire_code(stderr)
    return value,acknowledgments,actual_root


def main():
    global PRODUCTION_FAULT, PRODUCTION_OUTCOME, ACTOR_DIAGNOSTIC, READ_COST, PRIMARY_WRITER_FAULT, NATIVE_ERRNO
    parser = argparse.ArgumentParser(); parser.add_argument('--scenario', choices=SCENARIOS, default='success')
    args = parser.parse_args(); assert_guest(); s, encoded, hashes = source()
    setup(s, source_handle={'stop_source_fd': 'fd', 'stop_source_mapping': 'shared',
                           'thread_source_fd': 'thread_fd'}.get(args.scenario))
    replacing=args.scenario.startswith('r5_');runtime_payload=runtime_receipt=runtime_inputs=None
    if args.scenario=='r5_hooks':
        write('/etc/systemd/system/'+UNITS[0]+'.d/12-r5-native-hook.conf',b'[Service]\nExecStop=/usr/bin/false\n')
        run('/usr/bin/systemctl','daemon-reload')
    if args.scenario=='r5_legacy_unknown':
        p=APP/'.venv/bin/tu1nz-public-s7';p.write_bytes(p.read_bytes()+b'\n# SYNTHETIC_UNKNOWN_OLD_INSTALL_BYTES\n')
    legacy_bytes={str(p.relative_to(APP)):io.sha(p.read_bytes()) for p in APP.rglob('*') if p.is_file() and not p.is_symlink()}
    source_read_census_fence(s)
    actual_loader_alias_fence(s)
    actual_policy_owner_epoch(s)
    if args.scenario == 'thread_authority':
        # Exact profile first, then a real per-task fsuid change. A worker
        # retains root filesystem authority while the leader no longer does.
        # Only this synthetic Guest service is created; no Host actor is used.
        program = '''import ctypes,os,threading,time
from pathlib import Path
ready=threading.Event()
def worker():ready.set();time.sleep(120)
threading.Thread(target=worker).start();assert ready.wait(5)
root=Path('/fixture-r4');(root/'threads-ready').write_bytes(b'READY')
while not (root/'threads-change').exists():time.sleep(.01)
fd=os.open(root/'threads-changed',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
assert ctypes.CDLL(None).setfsuid(1001)==0
os.write(fd,b'CHANGED');os.close(fd);time.sleep(120)
'''
        write(ROOT/'thread-actor.py', program.encode(), 0o555)
        write('/etc/systemd/system/r4-thread-actor.service',
              b'[Service]\nType=simple\nExecStart=/usr/bin/python3 -I -B /fixture-r4/thread-actor.py\n')
        run('/usr/bin/systemctl', 'daemon-reload')
        run('/usr/bin/systemctl', 'start', 'r4-thread-actor.service')
        until = time.monotonic()+10
        while not (ROOT/'threads-ready').exists():
            assert time.monotonic() < until
            time.sleep(.01)
    replacement_dependencies=None
    if replacing:
        from tests.public_runtime_fixture import runtime,external_dependencies
        runtime_payload,runtime_receipt,runtime_inputs=runtime(s)
        replacement_dependencies=external_dependencies(s,runtime_payload,runtime_receipt)
    b = baseline(s,replacement_dependencies=replacement_dependencies)
    if replacing:
        origin=io.sha(io.canonical(runtime_receipt));b['source_origin_receipts'].append(origin)
        b['source_release']['runtime_reference']={'schema':'TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1',
            'artifact':runtime_receipt,'origin_sha256':origin}
    raw_plan = plan(s, b['machine_sha256']); baseline_raw = io.canonical(b)
    write(ROOT/'baseline.json', baseline_raw, 0o600)
    # Actual PID1 batch and three independent single reads must agree before
    # fault injection. Not a synthetic success response for an observer.
    measured_units = s.load('observe').unit_rows(UNITS, time.monotonic()+20)
    assert measured_units == {u: s.load('observe').Authority.unit(
        type('Read', (), {'deadline': time.monotonic()+20})(), u) for u in UNITS}
    legacy = {}
    for u in UNITS:
        row = s.load('observe').process(int(s.load('observe').Authority.unit(
            type('Read', (), {'deadline': time.monotonic()+30})(), u)['MainPID']))
        legacy[u] = {k: row[k] for k in ('uid', 'gid', 'groups', 'nnp')}
        legacy[u]['caps'] = {k: format(row['caps'][k], '016x') for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')}
    legacy_hash = io.sha(io.canonical(legacy))
    scope = {'schema': 'TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_V1', 'release_sha256': 'a'*64,
        'baseline_sha256': io.sha(baseline_raw), 'administrative_roles_sha256': io.sha(io.canonical(b['actors'])),
        'baseline_origins_sha256': io.sha(io.canonical(b['source_origin_receipts'])), 'r3_approval_sha256': client.APPROVAL,
        'machine_sha256': b['machine_sha256'], 'transaction': 'public-rights-20261014-1',
        'owner_plan_sha256': io.sha(raw_plan)}
    if replacing:scope.update(schema='TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_R5_V1',
        runtime_artifact_sha256=io.sha(io.canonical(runtime_receipt)),legacy_return=False)
    raw_scope = io.canonical(scope)
    packet = {'source': encoded, 'hashes': hashes, 'baseline': b, 'baseline_raw': base64.b64encode(baseline_raw).decode(),
              'owner_plan': base64.b64encode(raw_plan).decode(), 'scope': scope,
              'scope_raw': base64.b64encode(raw_scope).decode(), 'scope_sha256': io.sha(raw_scope), 'binding': io.sha(raw_scope)}
    if replacing:
        import zlib
        packet['baseline_encoding']='zlib_R5';packet['baseline_raw']=base64.b64encode(zlib.compress(baseline_raw,9)).decode()
    held_writer = None
    if args.scenario == 'thread_authority':
        write(ROOT/'threads-change', b'CHANGE')
        until = time.monotonic()+10
        while not (ROOT/'threads-changed').exists():
            assert time.monotonic() < until
            time.sleep(.01)
        pid = int(run('/usr/bin/systemctl', 'show', 'r4-thread-actor.service', '--property=MainPID', '--value'))
        tasks = Path('/proc')/str(pid)/'task'
        leader = s.load('observe').thread_security(tasks/str(pid))[1]
        other = [s.load('observe').thread_security(p)[1] for p in tasks.iterdir() if p.name != str(pid)]
        assert leader['uid'][3] == 1001 and len(other) == 1 and other[0]['uid'][3] == 0
    if args.scenario == 'writer': held_writer = os.open(WEB/'dir0/file5', os.O_WRONLY | os.O_CLOEXEC)
    if args.scenario == 'runtime_tamper':
        p = APP/'.venv/bin/tu1nz-public-s7'; p.write_bytes(p.read_bytes()+b'\n# SYNTHETIC_REFERENCE_MISMATCH\n')
    r = s.load('r3'); r.MACHINE = b['machine_sha256']; r.OWNER_PLAN = io.sha(raw_plan)
    r.CUSTODY_PARENT = ROOT/'client-custody'; r.CUSTODY_PARENT.mkdir(mode=0o700)
    program = client.bootstrap(base64.b64decode(encoded['io']))
    target_substitution = ('s.load("r3").MACHINE='+repr(r.MACHINE)+'\n'+
                          's.load("entry").MACHINE='+repr(r.MACHINE)+'\n'+
                          's.load("r3").OWNER_PLAN='+repr(r.OWNER_PLAN)+'\n'+
                          's.load("observe").LEGACY_CONTEXTS_SHA='+repr(legacy_hash)+'\n')
    if replacing:
        from tests.public_runtime_fixture import substitutions
        target_substitution+=substitutions(s,runtime_inputs)
    else:
        target_substitution += ('s.load("runtime_guard").APP_PIN='+repr((
            b['source_release']['runtime_reference']['commit'], b['source_release']['runtime_reference']['tree']))+'\n')
    target_substitution += ACTOR_DIAGNOSTIC_WRAPPER
    target_substitution += WRITER_DIAGNOSTIC_WRAPPER
    if args.scenario in ('first_restart', 'old_restart', 'r5_first_restart'):
        # Deterministic scheduler fault ONLY: execute the ACTUAL start, then
        # delay its caller until the real crash/on-failure replacement exists.
        # No observation/action result is replaced or returned as GREEN.
        target_substitution += '''
_real_command=s.load("host").command
_delayed=False
def _delay_after_actual_start(argv, deadline):
 global _delayed
 result=_real_command(argv,deadline)
 if argv==["/usr/bin/systemctl","start","tu1nz-adult-public-s7.service"] and not _delayed:
  _delayed=True
  import json,time
  from pathlib import Path
  marker=Path("/var/lib/tu1nz-adult-public-s9/native-crash-request")
  assert marker.is_file()
  while True:
   row=_real_command(["/usr/bin/systemctl","show","tu1nz-adult-public-s7.service","--property=ExecMainStatus,InvocationID"],deadline)
   value=dict(line.split("=",1) for line in row.stdout.decode().splitlines() if "=" in line)
   if value.get("ExecMainStatus")=="72":break
   assert time.monotonic()<deadline
   time.sleep(.01)
  initial=value["InvocationID"];marker.unlink()
  while True:
   row=_real_command(["/usr/bin/systemctl","show","tu1nz-adult-public-s7.service","--property=NRestarts,InvocationID,ActiveState,MainPID"],deadline)
   value=dict(line.split("=",1) for line in row.stdout.decode().splitlines() if "=" in line)
   if int(value["NRestarts"])>=1 and value["ActiveState"]=="active" and int(value["MainPID"])>0:break
   assert time.monotonic()<deadline
   time.sleep(.01)
  assert initial and initial!=value["InvocationID"]
  with Path("/fixture-r4/actual-restart-proof.json").open("x") as f:json.dump({"initial":initial,"replacement":value},f)
 return result
s.load("host").command=_delay_after_actual_start
'''
    target_substitution += READ_COST_WRAPPER
    program = program.replace('s.load("host").session(s,p,w)',
        target_substitution+'try:\n s.load("host").session(s,p,w)\nfinally:\n _save_read_cost()\n')
    if args.scenario == 'thread_source_fd':
        write(STATE/'native-split-request', b'SPLIT')
        until = time.monotonic()+10
        while (STATE/'native-split-ready').read_bytes() != b'READY':
            assert time.monotonic() < until
            time.sleep(.01)
        pid = int(run('/usr/bin/systemctl', 'show', UNITS[0], '--property=MainPID', '--value'))
        target = (APP/'source-handle.bin').stat(); identity = (target.st_dev, target.st_ino)
        tasks = Path('/proc')/str(pid)/'task'
        def holds(root):
            return any((p.stat().st_dev, p.stat().st_ino) == identity for p in (root/'fd').iterdir())
        assert not holds(tasks/str(pid))
        others = [p for p in tasks.iterdir() if p.name != str(pid)]
        assert len(others) == 1 and holds(others[0])
        rejected = False
        try: s.load('runtime_guard').writer_check({identity}, time.monotonic()+10)
        except s.load('io').Hold as error:
            assert error.primary == 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_EXISTING_SOURCE_WRITABLE_FD'
            rejected = True
        assert rejected
    child = subprocess.Popen(['/usr/bin/python3', '-I', '-B', '-S', '-c', program],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wire = io.Wire(child.stdout.fileno(), child.stdin.fileno(), deadline=time.monotonic()+600)
    assert wire.receive() == {'type': 'ready', 'io_sha256': hashes['io']}
    wire.send(packet)
    endpoints = [e for u in (*UNITS, 'lighting') for e in (b['http'][u] if u != 'lighting' else [b['http'][u]])
                 if e['location'] == 'client']
    fault_wire = FaultWire(wire, args.scenario, child)
    if args.scenario == 'writer': fault_wire.injected.append('REAL_PREEXISTING_WRITABLE_FD')
    if args.scenario=='r5_legacy_unknown':fault_wire.injected.append('REAL_R5_LEGACY_BYTES_NOT_ADOPTED')
    if args.scenario=='r5_hooks':fault_wire.injected.append('REAL_R5_EXECSTOP_HOOK')
    if args.scenario == 'runtime_tamper': fault_wire.injected.append('REAL_RUNTIME_DRIFT_BEFORE_ADMISSION')
    if args.scenario == 'thread_source_fd':
        fault_wire.injected.extend(['REAL_NONLEADER_SOURCE_FD_WITH_UNSHARED_TABLE', 'REAL_WRITER_TASK_CENSUS_REJECTED'])
    if args.scenario in ('stop_source_fd', 'stop_source_mapping'):
        fault_wire.injected.append('REAL_STOP_TARGET_SOURCE_FD' if args.scenario == 'stop_source_fd'
                                   else 'REAL_STOP_TARGET_SOURCE_SHARED_MAP')
    supervisor = client.Client(fault_wire, r, packet['binding'], http_expectations=endpoints,runtime_payload=runtime_payload)
    result = {'status': 'UNKNOWN_TEST_PROTOCOL_HOLD'}
    try:
        result = supervisor.serve()
    except BaseException as error:
        result.update(error_type=type(error).__name__, primary=getattr(error, 'primary', 'UNKNOWN'))
    finally:
        child.stdin.close(); supervisor.close()
    stderr = child.stderr.read(); code = child.wait(timeout=10)
    if fault_wire.extra_actor is not None:
        fault_wire.extra_actor.terminate(); fault_wire.extra_actor.wait(timeout=5)
    if held_writer is not None: os.close(held_writer)
    write(ROOT/'server-stderr', stderr, 0o600)
    write(ROOT/'result.json', io.canonical(result), 0o600)
    PRODUCTION_FAULT = result.get('source_fault')
    diagnostic_path = ROOT/'actor-diagnostic.json'
    if diagnostic_path.exists(): ACTOR_DIAGNOSTIC = io.parse(diagnostic_path.read_bytes())
    writer_path=ROOT/'writer-diagnostic.json'
    if writer_path.exists():
        writer=io.parse(writer_path.read_bytes());PRIMARY_WRITER_FAULT=writer['fault'];NATIVE_ERRNO=writer['errno']
        if ACTOR_DIAGNOSTIC is None:ACTOR_DIAGNOSTIC=writer.get('actor')
    cost_path = ROOT/'read-cost.json'
    if cost_path.exists(): READ_COST = io.parse(cost_path.read_bytes())
    PRODUCTION_OUTCOME,acknowledgments,actual_root=production_outcome(result,code,r,fault_wire,stderr)
    if args.scenario in ('first_restart', 'old_restart', 'r5_first_restart'):
        proof = json.loads((ROOT/'actual-restart-proof.json').read_bytes())
        assert proof['initial'] != proof['replacement']['InvocationID'] and int(proof['replacement']['NRestarts']) >= 1
        expected = 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_FIRST_START_AUTORESTART_DETECTED'
        assert result.get('primary') == expected or expected in result.get('abort', []), result
        fault_wire.injected.append('REAL_REPLACEMENT_BEFORE_FIRST_OBSERVATION')
    from tu1nz_public_operator_ci import FAULTS
    if args.scenario == 'thread_authority': fault_wire.injected.append('REAL_NONLEADER_RETAINS_FILESYSTEM_UID')
    assert fault_wire.injected == FAULTS[args.scenario], 'INTENDED_REAL_FAULT_NOT_INJECTED'
    report = {'scenario': args.scenario, 'status': result['status'], 'server_exit': code,
                      'proof': io.sha(io.canonical(result)), 'source_files': hashes,
                      'owner_confirmations': len(acknowledgments), 'actual_root_objects': actual_root,
                      'actual_faults': fault_wire.injected,
                      'fixture_only_no_host_acceptance': True}
    if args.scenario in ('success','r5_success','r5_legacy_unknown'):
        assert code == 0 and result['status'] == 'RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED', result
        assert actual_root == 88 and len(acknowledgments) == 84
    elif args.scenario in ('restore_fail_return', 'probe_fail_return'):
        assert code == 0 and result['status'] == 'OLD_OPERATION_RESTORED_SECURITY_RED', result
        assert actual_root == 4 and not acknowledgments
    elif args.scenario in ('owner_return','r5_owner_return'):
        assert code == 0 and result['status'] == 'OWNER_RETURNED_SECURITY_RED', result
        assert actual_root == 4 and len(acknowledgments) == 7
    else:
        assert result['status'] in ('HOLD', 'UNKNOWN_TEST_PROTOCOL_HOLD'), result
        if args.scenario in ('writer', 'runtime_tamper', 'denied_return', 'lost_start_ack', 'first_restart', 'old_restart',
                             'r5_hooks','r5_chunk_loss','r5_partial_interrupt','r5_artifact_tamper','r5_legacy_tamper',
                             'r5_old_return_denied','r5_first_restart',
                             'stop_source_fd', 'stop_source_mapping', 'thread_authority', 'thread_source_fd'): assert actual_root == 4
        else: assert 4 < actual_root < 88
        if args.scenario == 'unknown_actor':
            assert result.get('primary') == 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_UNCLASSIFIED_OR_EXTRA_ACTOR'
            assert ACTOR_DIAGNOSTIC and ACTOR_DIAGNOSTIC['executable_class'] == 'sleep'
            assert ACTOR_DIAGNOSTIC['matching_executable_profiles'] == 0 and ACTOR_DIAGNOSTIC['stable_followup'] is True
        if args.scenario in ('runtime_tamper', 'stop_source_fd', 'stop_source_mapping', 'thread_authority', 'thread_source_fd'):
            assert not (r.CUSTODY_PARENT/r.TX).exists()
        if args.scenario == 'thread_source_fd':
            assert result.get('primary') == 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_ACTOR_THREAD_FILE_TABLE_NOT_SHARED', result
            assert all(run('/usr/bin/systemctl', 'show', u, '--property=ActiveState', '--value').strip() == b'active'
                       for u in UNITS)
        if args.scenario == 'thread_authority':
            assert result.get('primary') == 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_ACTOR_THREAD_SECURITY_MISMATCH', result
            assert all(run('/usr/bin/systemctl', 'show', u, '--property=ActiveState', '--value').strip() == b'active'
                       for u in UNITS)
        if args.scenario in ('stop_source_fd', 'stop_source_mapping'):
            expected = 'EXISTING_SOURCE_WRITABLE_FD' if args.scenario == 'stop_source_fd' else 'EXISTING_SOURCE_SHARED_WRITABLE_MAPPING'
            assert result.get('primary') == 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_'+expected, result
            assert all(run('/usr/bin/systemctl', 'show', u, '--property=ActiveState', '--value').strip() == b'active'
                       for u in UNITS)
        if args.scenario == 'denied_return':
            assert all(run('/usr/bin/systemctl', 'show', u, '--property=ActiveState', '--value').strip() == b'inactive'
                       for u in UNITS)
    if replacing:
        if args.scenario=='r5_legacy_tamper':
            legacy_bytes['.venv/bin/tu1nz-public-s7']=io.sha(b'SYNTHETIC_LEGACY_TAMPER')
        assert legacy_bytes=={str(p.relative_to(APP)):io.sha(p.read_bytes()) for p in APP.rglob('*') if p.is_file() and not p.is_symlink()}
        if args.scenario=='r5_hooks':
            assert not (r.CUSTODY_PARENT/r.TX).exists()
            assert all(run('/usr/bin/systemctl','show',u,'--property=ActiveState','--value').strip()==b'active' for u in UNITS)
        if args.scenario in ('r5_chunk_loss','r5_partial_interrupt','r5_artifact_tamper','r5_legacy_tamper','r5_old_return_denied'):
            assert all(run('/usr/bin/systemctl','show',u,'--property=ActiveState','--value').strip()==b'inactive' for u in UNITS)
        if args.scenario=='r5_partial_interrupt':
            import tu1nz_public_runtime_artifact as artifact
            prefix=Path(artifact.ROOT);assert prefix.is_dir() and 0<len(list(prefix.rglob('*')))<len(runtime_receipt['objects'])
            assert stat.S_IMODE(prefix.stat().st_mode)==0o700
        if args.scenario=='r5_old_return_denied':
            records=list((r.CUSTODY_PARENT/r.TX/'operator-records').glob('*.json'))
            assert not any(io.parse(p.read_bytes()).get('value',{}).get('action')=='start_old' for p in records)
    if (r.CUSTODY_PARENT/r.TX).exists():
        try: repeated = r.Journal(r.CUSTODY_PARENT, packet['binding'])
        except r.Denied: pass
        else:
            repeated.close(); raise AssertionError('FIXED_TRANSACTION_REPLAY_NOT_DENIED')
    print(json.dumps(report))


if __name__ == '__main__':
    try: main()
    except BaseException as error:
        # Only source locations, not assertion values/tracebacks/observations.
        trace = error.__traceback__; line = 1
        while trace is not None:
            if trace.tb_frame.f_code.co_filename == __file__: line = trace.tb_lineno
            trace = trace.tb_next
        location = {'test_line': line, 'test_type': type(error).__name__, 'production_fault': PRODUCTION_FAULT}
        if PRIMARY_WRITER_FAULT is not None:location['primary_fault']=PRIMARY_WRITER_FAULT
        if NATIVE_ERRNO is not None:location['errno']=NATIVE_ERRNO
        if PRODUCTION_OUTCOME is not None: location['outcome'] = PRODUCTION_OUTCOME
        if ACTOR_DIAGNOSTIC is not None: location['actor'] = ACTOR_DIAGNOSTIC
        if READ_COST: location['read_cost'] = READ_COST  # strict reader forbids an empty cost object
        print(json.dumps({'native_failure': location}))
        raise SystemExit(1)
