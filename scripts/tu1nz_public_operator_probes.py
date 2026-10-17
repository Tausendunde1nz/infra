"""Exactly three bounded synthetic RootDirectory probes, never real inputs.

StartTransientUnit is used only for the three compiled probe names. No persistent
unit, reload, provider, production repository/data/credential or Host socket bind.
All disk objects stay under the approved private probe root and are retained.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import socket
import stat
import struct
import threading
import time

import tu1nz_public_operator_io as io
from tu1nz_public_operator_observe import command, process, starttime, initial_profile, UNITS

ROOT = '/opt/tu1nz_repos/public-web-isolation-r1/20261014-1/probe'
APP = '/opt/tu1nz_repos/adult-publishing-core'
STATE = '/var/lib/tu1nz-adult-public-s9'
PROFILES = ('s7', 's8-landing', 'wms')
NAMES = tuple('tu1nz-public-isolation-r2-probe-'+p+'.service' for p in PROFILES)
BODY = r'''import hashlib,json,os,socket,stat,struct,threading,time
from pathlib import Path
profile='s7' if 'public-s7' in __file__ else 's8-landing' if 'public-s8' in __file__ else 'wms'
listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
listener.bind('/run/reports/peer-'+profile);listener.listen(1)
def serve():
 c,_=listener.accept()
 with c:
  c.recv(16);pid,uid,gid=struct.unpack('3i',c.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
  c.sendall((str(uid)+':'+str(gid)).encode())
 listener.close()
peer_thread=threading.Thread(target=serve,daemon=True);peer_thread.start()
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
 s.settimeout(2);s.connect('/run/reports/peer-'+profile);s.sendall(b'PING');peer=s.recv(128).decode()
peer_end=time.monotonic()+2;peer_thread.join(2)
while peer_thread.is_alive() or len(list(Path('/proc/self/task').iterdir()))!=1:
 if time.monotonic()>=peer_end:raise RuntimeError('SYNTHETIC_PEER_THREAD_EXIT_UNKNOWN')
 time.sleep(.001)
try:
 fd=os.open('/run/p-admin-file',os.O_RDONLY);os.close(fd)
except PermissionError:admin='DENIED'
else:raise RuntimeError('SYNTHETIC_ADMIN_NOT_DENIED')
if profile!='s7':
 p=Path('/var/lib/tu1nz-adult-public-s9/landing-aggregates.json');raw=p.read_bytes()
 n=p.with_suffix('.'+profile);n.write_bytes(raw);n.chmod(0o600);os.replace(n,p)
report={'profile':profile,'peer':peer,'admin':admin}
p=Path('/run/reports')/(profile+'.json')
with p.open('x') as f:json.dump(report,f);f.flush();os.fsync(f.fileno())
end=time.monotonic()+15
while not Path('/run/reports/continue-'+profile).exists():
 if time.monotonic()>end:raise RuntimeError('SYNTHETIC_OBSERVATION_DEADLINE')
 time.sleep(.01)
'''


def bus_properties(properties):
    flat = []
    for name, (signature, values) in properties.items():
        flat += [name, signature, *map(str, values)]
    return [str(len(properties)), *flat]


class Probes:
    def __init__(self, paths, source, authority, channel, *, deadline):
        self.p, self.source, self.a, self.channel = paths, source, authority, channel
        self.deadline = min(deadline, time.monotonic()+120)
        self.used = False; self.owned = {}; self.reports = []; self.sockets = []
        self.cleanup_complete = False; self.cleanup_codes = []; self.unconfirmed = set()
        self.retained = {}
        if hasattr(authority, 'probe_check'):
            io.require(authority.probe_check is None, 'PROBE_CHECKER_ALREADY_OWNED')
            authority.probe_check = self.check_retained
        self.private = ROOT+'/root'; self.handles = {}; self.bytes = 0

    def directory(self, relative, *, uid=0, mode=0o755):
        path = PurePosixPath(relative)
        io.require(path.is_absolute() and '..' not in path.parts, 'PROBE_PATH')
        if relative in self.handles:
            return self.handles[relative]
        parent = self.directory(str(path.parent))
        self.p.d.new_directory(parent, path.name, mode)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        if uid:
            os.fchown(fd, uid, uid)
        self.handles[relative] = fd
        return fd

    def file(self, relative, raw, *, mode=0o555, uid=0):
        self.bytes += len(raw)
        io.require(self.bytes <= 512*1024*1024 and time.monotonic() < self.deadline, 'PROBE_ROOT_BOUND')
        p = PurePosixPath(relative); parent = self.directory(str(p.parent))
        self.p.d.new_file(parent, p.name, raw, mode)
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            if uid:
                os.fchown(fd, uid, uid)
            io.require(os.pread(fd, len(raw)+1, 0) == raw, 'PROBE_COPY_READBACK')
        finally:
            os.close(fd)

    def prepare(self):
        self.p.create_directory(ROOT)
        for name in ('source', 'inputs', 'reports', 'quarantine'):
            self.p.create_directory(ROOT+'/'+name)
        self.handles['/'] = self.p.create_directory(self.private, 0o755)
        dependencies = self.a.b['source_release']['probe_dependencies']
        io.require(0 < len(dependencies) <= 4096, 'PROBE_DEPENDENCY_SET')
        for destination, expected in sorted(dependencies.items()):
            io.require(destination.startswith(('/usr/bin/python3', '/usr/lib/', '/lib/', '/lib64/')) and
                       set(expected) == {'source', 'sha256'}, 'PROBE_DEPENDENCY_SCOPE')
            io.require(expected['source'].startswith(('/usr/bin/', '/usr/lib/')), 'PROBE_DEPENDENCY_ORIGIN')
            raw, _ = self.p.read(expected['source'])
            io.require(io.sha(raw) == expected['sha256'], 'INSTALLED_DEPENDENCY_CHANGED')
            self.file(destination, raw)
        self.file('/etc/passwd', b'root:x:0:0:root:/:/bin/false\nchatops:x:1001:1001:synthetic:/:/bin/false\n', mode=0o444)
        self.file('/etc/group', b'root:x:0:\nchatops:x:1001:\n', mode=0o444)
        self.file('/etc/nsswitch.conf', b'passwd: files\ngroup: files\n', mode=0o444)
        self.directory('/run/reports', uid=1001, mode=0o700)
        # MountAPIVFS creates a fresh /run inside RootDirectory. Bind sources
        # must therefore be outside that overmounted subtree, but still below
        # this invocation's approved private probe root. Never bind Host /run.
        inputs = self.p.get(ROOT+'/inputs')
        self.p.d.new_directory(inputs, 'runtime-reports', 0o700)
        reports = os.open('runtime-reports', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=inputs)
        os.fchown(reports, 1001, 1001)
        os.close(self.handles['/run/reports'])
        self.handles['/run/reports'] = reports
        self.directory(STATE, uid=1001, mode=0o700)
        self.file(STATE+'/landing-aggregates.json', b'{"synthetic_count":7}', mode=0o600, uid=1001)
        self.file(STATE+'/wms-traffic-quality.json', b'{"synthetic_count":7}', mode=0o600, uid=1001)
        for path in (APP+'/.venv/bin/tu1nz-public-s7', APP+'/.venv/bin/tu1nz-public-s8-landing',
                     APP+'/src/tu1nz_exposure_s10/runtime.py'):
            self.file(path, b'#!/usr/bin/python3\n'+BODY.encode())
        python, _ = self.p.read(self.a.b['source_release']['python_binary'])
        self.file(APP+'/.venv/bin/python', python)
        self.file('/usr/local/bin/tu1nz_public_web_isolate_r1.py', self.source.bytes['runtime'])
        for name in ('adult-commercial-s7-public.json', 'adult-commercial-s8-landing.json',
                     'adult-commercial-s10-wms.json', 'adult-commercial-s10-wms-copy.json',
                     'adult-commercial-s10-wms-bot-identity.json', 'adult-commercial-s10-2d-community.json'):
            self.file('/etc/tu1nz/'+name, b'{"synthetic":1}', mode=0o444)
        for unit, profile in zip(UNITS, PROFILES):
            canonical = '/run/credentials/'+unit
            self.directory(canonical)
            wrapper = ('import os,sys\n'
                       'assert (os.stat("/").st_dev,os.stat("/").st_ino)=='+repr(
                           (os.fstat(self.handles['/']).st_dev, os.fstat(self.handles['/']).st_ino))+'\n'+
                       ('os.environ["CREDENTIALS_DIRECTORY"]='+repr(canonical)+'\n' if profile == 's7' else '')+
                       'os.execv("/usr/bin/python3",["/usr/bin/python3","-I","-B","-S",'
                       '"/usr/local/bin/tu1nz_public_web_isolate_r1.py","--profile",'+repr(profile)+'])\n')
            self.file('/source/wrapper-'+profile+'.py', wrapper.encode())
        for name in ('s7_form_secret', 's7_database_dsn'):
            self.p.create_file(ROOT+'/inputs/'+name, b'SYNTHETIC-ONLY-00000000000000000000000000000000')
        self.p.create_file(ROOT+'/source/helper.py', self.source.bytes['runtime'], 0o555)
        self._peer()

    def _peer(self):
        # The program measures SO_PEERCRED on a real synthetic local peer,
        # never a Host/manager socket. An ordinary GID987 file independently
        # witnesses effective group removal. Only these OWN synthetic paths
        # are exposed through the unit's private /run view.
        run = self.p.get(ROOT+'/inputs')
        self.p.d.new_file(run, 'p-admin-file', b'SYNTHETIC_ADMIN_ONLY', 0o660)
        fd = os.open('p-admin-file', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=run)
        try:
            os.fchown(fd, 0, 987)
        finally:
            os.close(fd)

    def show(self, unit):
        r = command(['/usr/bin/systemctl', 'show', unit, '--property=LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,ControlGroup,Result,Job,ExecMainStatus', '--no-pager'], self.deadline)
        io.require(r.returncode in (0, 1), 'PROBE_MANAGER_READ')
        return dict(x.split('=', 1) for x in r.stdout.decode().splitlines() if '=' in x)

    def start(self, unit, profile, index):
        io.require(self.show(unit).get('LoadState') == 'not-found', 'PROBE_OCCUPIED_NO_RETRY')
        props = {
            'Description': ('s', ['TU1NZ isolated synthetic probe '+profile]),
            'Type': ('s', ['oneshot']), 'User': ('s', ['chatops']), 'Group': ('s', ['chatops']),
            'Restart': ('s', ['no']), 'RemainAfterExit': ('b', ['false']),
            'RootDirectory': ('s', [self.private]), 'WorkingDirectory': ('s', [APP]),
            'PrivateNetwork': ('b', ['true']), 'MountAPIVFS': ('b', ['true']),
            'NoNewPrivileges': ('b', ['true']), 'PrivateTmp': ('b', ['true']),
            'PrivateDevices': ('b', ['true']), 'ProtectSystem': ('s', ['strict']), 'ProtectHome': ('s', ['yes']),
            'ProtectKernelTunables': ('b', ['true']), 'ProtectKernelModules': ('b', ['true']),
            'ProtectControlGroups': ('b', ['true']), 'RestrictSUIDSGID': ('b', ['true']),
            'RestrictRealtime': ('b', ['true']), 'LockPersonality': ('b', ['true']),
            'MemoryDenyWriteExecute': ('b', ['true']), 'SystemCallArchitectures': ('as', [1, 'native']),
            'RestrictNamespaces': ('t', [0x10000000]), 'PrivateUsers': ('b', ['false']),
            'SupplementaryGroups': ('as', [0]),
            'InaccessiblePaths': ('as', [3, '-/run/docker.sock', '-/run/containerd', '-/run/user/1001']),
            # '+' scopes access mounts to RootDirectory; bare paths would
            # address the guest's outside tree, not the synthetic state tree.
            'ReadWritePaths': ('as', [2, '+/run/reports', '+'+STATE]),
            'BindPaths': ('a(ssbt)', [1, ROOT+'/inputs/runtime-reports', '/run/reports', 'false', 16384]),
            'BindReadOnlyPaths': ('a(ssbt)', [1, ROOT+'/inputs/p-admin-file', '/run/p-admin-file', 'false', 0]),
            'TimeoutStartUSec': ('t', [20_000_000]), 'RuntimeMaxUSec': ('t', [20_000_000]),
            'TimeoutStopUSec': ('t', [5_000_000]), 'CPUQuotaPerSecUSec': ('t', [200_000]),
            'MemoryMax': ('t', [256*1024*1024]), 'TasksMax': ('t', [16]),
            'LimitNOFILE': ('t', [128]), 'LimitNOFILESoft': ('t', [128]),
            'LimitFSIZE': ('t', [16*1024*1024]), 'LimitFSIZESoft': ('t', [16*1024*1024]),
            'UMask': ('u', [0o077]),
            'ExecStartEx': ('a(sasas)', [1, '/usr/bin/python3', 6, '/usr/bin/python3', '-I', '-B', '-S',
                                        '/source/wrapper-'+profile+'.py', profile, 2, 'no-setuid', 'no-env-expand'])}
        if profile == 's7':
            props['LoadCredential'] = ('a(ss)', [2, 's7_form_secret', ROOT+'/inputs/s7_form_secret',
                                                 's7_database_dsn', ROOT+'/inputs/s7_database_dsn'])
            props['BindReadOnlyPaths'] = ('a(ssbt)', [2, ROOT+'/inputs/p-admin-file',
                '/run/p-admin-file', 'false', 0, '/run/credentials/'+unit,
                '/run/credentials/'+UNITS[index], 'false', 0])
        self.channel.record('probe_start_intent', {'unit': unit, 'profile': profile,
                                                 'properties_sha256': io.sha(io.canonical(props))})
        self.unconfirmed.add(unit)
        args = ['/usr/bin/busctl', '--system', '--allow-interactive-authorization=no', '--', 'call',
                'org.freedesktop.systemd1', '/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager',
                'StartTransientUnit', 'ssa(sv)a(sa(sv))', unit, 'fail', *bus_properties(props), '0']
        r = command(args, self.deadline)
        self.p.create_file(ROOT+'/reports/start-'+profile+'-stderr', r.stderr)
        self.channel.record('probe_start_result', {'unit': unit, 'exit': r.returncode,
            'stderr_sha256': io.sha(r.stderr), 'stdout_sha256': io.sha(r.stdout)})
        io.require(r.returncode == 0, 'PROBE_START_UNKNOWN_NO_RETRY')
        self.owned[unit] = {'requested': 1, 'pid': None, 'start': None, 'invocation': None}
        end = min(self.deadline, time.monotonic()+20)
        while time.monotonic() < end:
            value = self.show(unit); pid = int(value.get('MainPID', '0'))
            if pid:
                tick = starttime(pid)
                if self.owned[unit]['invocation'] is not None:
                    io.require((pid, tick, value['InvocationID']) ==
                               (self.owned[unit]['pid'], self.owned[unit]['start'], self.owned[unit]['invocation']),
                               'PROBE_FIRST_INVOCATION_CHANGED')
                self.owned[unit].update(pid=pid, start=tick, invocation=value['InvocationID'],
                                        cgroup=value['ControlGroup'])
                self.unconfirmed.discard(unit)
                report = Path('/proc')/str(pid)/'root/run/reports'/(profile+'.json')
                # Not an admission flag: wait for the controlled producer's
                # bounded completion point, then measure ALL real rights.
                # Its own IPC worker has actually exited before this file.
                if report.exists():
                    row = initial_profile(pid, tick, end)
                    after = self.show(unit)
                    io.require((int(after.get('MainPID', '0')), row['starttime'], after['InvocationID']) ==
                               (pid, tick, value['InvocationID']), 'PROBE_FIRST_INVOCATION_CHANGED')
                    io.require(row['uid'] == row['gid'] == [1001]*4, 'PROBE_KERNEL_RIGHTS_RED')
                    io.require(not row['groups'] and not any(row['caps'].values()) and row['nnp'] == 1 and
                               row['uid_map'] == row['gid_map'] == ['0', '0', '1', '1001', '1001', '1'] and
                               row['setgroups'] == 'deny', 'PROBE_KERNEL_RIGHTS_RED')
                    if report.exists():
                        measurement = io.parse(report.read_bytes())
                        io.require(measurement == {'profile': profile, 'peer': '1001:1001', 'admin': 'DENIED'},
                                   'PROBE_UNIX_PEER_OR_ADMIN_RED')
                        root = Path('/proc')/str(pid)/'root'
                        bound = os.stat(root)
                        own = os.fstat(self.handles['/'])
                        io.require((bound.st_dev, bound.st_ino) == (own.st_dev, own.st_ino), 'PROBE_ROOT_ALIAS_RED')
                        io.require((Path('/proc')/str(pid)/'task'/str(pid)/'children').read_text().strip() == '',
                                   'PROBE_CREATOR_NOT_REAPED')
                        io.require(row['namespaces']['net'] != os.readlink('/proc/self/ns/net') and
                                   all(x.split()[0] == 'lo' for x in
                                       (Path('/proc')/str(pid)/'net/route').read_text().splitlines()[1:]),
                                   'PROBE_NETWORK_NAMESPACE_RED')
                        if profile == 's7':
                            credential = root/'run/credentials'/UNITS[index]
                            for name in ('s7_form_secret', 's7_database_dsn'):
                                s = os.stat(credential/name)
                                io.require(s.st_uid == s.st_gid == 1001 and stat.S_IMODE(s.st_mode) == 0o600 and
                                           os.statvfs(credential/name).f_flag & os.ST_RDONLY and
                                           (credential/name).read_bytes() ==
                                           b'SYNTHETIC-ONLY-00000000000000000000000000000000',
                                           'PROBE_CREDENTIAL_VIEW_RED')
                        else:
                            state = root/STATE.lstrip('/')/'landing-aggregates.json'
                            io.require(state.read_bytes() == b'{"synthetic_count":7}' and
                                       state.stat().st_uid == 1001 and stat.S_IMODE(state.stat().st_mode) == 0o600,
                                       'PROBE_SYNTHETIC_STATE_RED')
                        io.require(starttime(pid) == row['starttime'], 'PROBE_PROCESS_CHANGED')
                        self.p.d.new_file(self.handles['/run/reports'], 'continue-'+profile, b'CONTINUE', 0o444)
                        break
            io.require(value.get('ActiveState') not in ('failed', 'inactive'), 'PROBE_EXIT_BEFORE_OBSERVATION')
            time.sleep(.01)
        else:
            raise io.Hold('PUBLIC_OPERATOR_PROBE_OBSERVATION_DEADLINE')
        while time.monotonic() < end:
            value = self.show(unit)
            if value.get('LoadState') == 'not-found' or value.get('ActiveState') == 'inactive':
                io.require(value.get('Result', 'success') == 'success' and self.empty(unit, value),
                           'PROBE_EXIT_OR_CLEANUP_RED')
                self.reports.append({'unit': unit, 'kernel_process': row,
                                     'measurements_sha256': io.sha(io.canonical(measurement))})
                self.channel.record('probe_completed', self.reports[-1])
                return
            io.require(value.get('InvocationID') == self.owned[unit]['invocation'], 'PROBE_INVOCATION_CHANGED')
            time.sleep(.01)
        raise io.Hold('PUBLIC_OPERATOR_PROBE_CLEANUP_DEADLINE')

    def empty(self, unit, value):
        group = value.get('ControlGroup') or self.owned.get(unit, {}).get('cgroup', '')
        io.require('..' not in PurePosixPath(group).parts, 'PROBE_CGROUP_UNKNOWN')
        root = Path('/sys/fs/cgroup')/group.lstrip('/')
        return (not value.get('Job') and int(value.get('MainPID', '0')) == 0 and
                int(value.get('ControlPID', '0')) == 0 and (not group or not root.exists() or
                all(not p.read_text().strip() for p in [root/'cgroup.procs', *root.rglob('cgroup.procs')])))

    def inactive_profile(self, unit, deadline):
        properties = ('LoadState,ActiveState,Job,MainPID,ControlPID,ControlGroup,FragmentPath,Transient,'
                      'RootDirectory,Restart,Triggers,TriggeredBy,OnFailure,OnSuccess,User,Group,Type,InvocationID')
        r = command(['/usr/bin/systemctl', 'show', unit, '--property='+properties, '--no-pager'], deadline)
        v = dict(x.split('=', 1) for x in r.stdout.decode().splitlines() if '=' in x)
        io.require(r.returncode in (0, 1) and self.empty(unit, v), 'RETAINED_PROBE_NOT_QUIET')
        if v.get('LoadState') == 'not-found': return None
        path = '/run/systemd/transient/'+unit
        io.require(v.get('LoadState') == 'loaded' and v.get('Transient') == 'yes' and
                   v.get('FragmentPath') == path and v.get('RootDirectory') == self.private and
                   v.get('Restart') == 'no' and v.get('User') == v.get('Group') == 'chatops' and
                   v.get('InvocationID') == self.owned[unit]['invocation'] and
                   v.get('Type') == 'oneshot' and not any(v.get(k) for k in
                   ('Triggers', 'TriggeredBy', 'OnFailure', 'OnSuccess')), 'RETAINED_PROBE_CONFIG_UNKNOWN')
        object_path = '/org/freedesktop/systemd1/unit/'+''.join(
            c if c.isascii() and c.isalnum() else '_'+format(ord(c), '02x') for c in unit)
        r = command(['/usr/bin/busctl', '--system', '--auto-start=no', '--json=short', 'get-property',
                     'org.freedesktop.systemd1', object_path, 'org.freedesktop.systemd1.Service', 'ExecStartEx'], deadline)
        result = io.parse(r.stdout); profile = PROFILES[NAMES.index(unit)]
        io.require(r.returncode == 0 and result.get('type') == 'a(sasasttttuii)' and
                   len(result.get('data', [])) == 1, 'RETAINED_PROBE_EXEC_UNKNOWN')
        row = result['data'][0]
        statistics_owned = (len(row) == 10 and (row[7] == self.owned[unit]['pid'] or
            # PID1 discards per-Exec statistics on daemon-reload, NOT the Unit
            # invocation. Only an ALREADY bound same-inode/hash own definition
            # may use that all-zero state, with empty cgroup/job and same ID.
            unit in self.retained and all(type(v) is int and v == 0 for v in row[3:])))
        io.require(statistics_owned and row[0] == '/usr/bin/python3' and row[1] ==
                   ['/usr/bin/python3', '-I', '-B', '-S', '/source/wrapper-'+profile+'.py', profile] and
                   set(row[2]) == {'no-setuid', 'no-env-expand'},
                   'RETAINED_PROBE_EXEC_NOT_OWN_INVOCATION')
        return path

    def bind_retained(self, unit):
        # A failed own transient unit can remain loaded after verified stop.
        # Retain it and its evidence; no reset-failed, unload or second start.
        path = self.inactive_profile(unit, self.deadline)
        if path is None: return
        raw, row = self.p.read(path)
        self.retained[unit] = {'path': path, 'row': row, 'sha256': io.sha(raw), 'absent_after_gc': False}
        self.a.own_config_paths.add(path)

    def check_retained(self):
        deadline = min(self.channel.ceiling, self.a.deadline)
        for unit, expected in self.retained.items():
            path = self.inactive_profile(unit, deadline)
            if path is None:
                self.p.absent(expected['path']); expected['absent_after_gc'] = True
                self.a.own_config_paths.discard(expected['path'])
                continue
            io.require(not expected['absent_after_gc'] and path == expected['path'], 'RETAINED_PROBE_NAME_REUSED')
            raw, row = self.p.read(path)
            io.require(io.sha(raw) == expected['sha256'] and all(row[k] == expected['row'][k] for k in row
                       if k != 'atime_ns'), 'RETAINED_PROBE_OBJECT_CHANGED')

    def run(self):
        io.require(not self.used, 'NO_PROBE_REPLAY'); self.used = True
        primary = None; result = None
        try:
            self.prepare()
            for index, (unit, profile) in enumerate(zip(NAMES, PROFILES)):
                self.start(unit, profile, index)
            io.require(len(self.reports) == 3 and time.monotonic() < self.deadline, 'PROBE_INCOMPLETE')
            result = io.sha(io.canonical(self.reports))
        except BaseException as error:
            primary = error
        finally:
            cleanup = []
            if self.unconfirmed: cleanup.append('PUBLIC_BOOTSTRAP_PROBE_START_UNCONFIRMED')
            for unit, owned in self.owned.items():
                try:
                    value = self.show(unit)
                    if value.get('ActiveState') in ('active', 'activating'):
                        io.require(owned['invocation'] and value['InvocationID'] == owned['invocation'] and
                                   int(value['MainPID']) == owned['pid'] and
                                   starttime(owned['pid']) == owned['start'], 'PROBE_CLEANUP_IDENTITY_UNKNOWN')
                        r = command(['/usr/bin/systemctl', 'stop', unit], min(self.deadline, time.monotonic()+5))
                        io.require(r.returncode == 0, 'PROBE_CLEANUP_UNKNOWN')
                        value = self.show(unit)
                    io.require(self.empty(unit, value), 'PROBE_CLEANUP_NONEMPTY_OR_JOB')
                    if hasattr(self.a, 'own_config_paths') and owned['invocation'] is not None:
                        self.bind_retained(unit)
                except BaseException as error:
                    cleanup.append(getattr(error, 'primary', 'PUBLIC_BOOTSTRAP_PROBE_CLEANUP_UNCONFIRMED'))
            for listener in self.sockets:
                listener.close()
            for path, fd in self.handles.items():
                if path != '/':
                    os.close(fd)
            self.handles.clear()
            try:
                self.channel.record('probe_cleanup', {'owned_units': list(self.owned), 'cleanup': cleanup,
                                                      'retained_transient_units': sorted(self.retained),
                                                      'persistent_objects_retained': ROOT})
            except BaseException:
                cleanup.append('PUBLIC_BOOTSTRAP_PROBE_CLEANUP_RECORD_UNCONFIRMED')
            self.cleanup_codes = cleanup; self.cleanup_complete = not cleanup
        if primary is not None:
            primary._probe_cleanup = tuple(cleanup)
            raise primary
        io.require(self.cleanup_complete, 'PROBE_CLEANUP_FAILED')
        return result
