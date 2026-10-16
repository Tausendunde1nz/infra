"""Actual finite Host observations for the R3 operator. No permission flags.

The authenticated private baseline contains expected bytes, identities and
explicitly reviewed administrative role bindings, not GREEN/test receipts.
Every present actor is measured. Unknown policy, inaccessible evidence or
unclassified authority denies. No writable broker/provider or auth trial.
"""
from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import socket
import stat
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager

import tu1nz_public_operator_io as io
from tu1nz_public_operator_runtime_guard import RuntimeFence, writer_check

UNITS = ('tu1nz-adult-public-s7.service', 'tu1nz-adult-public-s8-landing.service',
         'tu1nz-adult-public-s10-wms.service')
CAPS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
PROPERTIES = ('Id,Names,LoadState,ActiveState,SubState,Result,MainPID,ControlPID,Job,'
              'InvocationID,NRestarts,ControlGroup,NeedDaemonReload,FragmentPath,DropInPaths,'
              'Requires,BindsTo,PartOf,RequiredBy,BoundBy,ConsistsOf,PropagatesStopTo,'
              'StopPropagatedFrom,Triggers,TriggeredBy,OnFailure,KillMode,Restart,'
              'TimeoutStopUSec,User,Group,SupplementaryGroups,NoNewPrivileges,'
              'OnSuccess,FailureAction,SuccessAction,StartLimitAction,RefuseManualStop,'
              'RefuseManualStart,JobTimeoutAction,StopWhenUnneeded,BusName,Type,Wants')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'PYTHONNOUSERSITE': '1'}
ADMIN_ACTIONS = ('org.freedesktop.systemd1.manage-units',
                 'org.freedesktop.systemd1.manage-unit-files',
                 'org.freedesktop.systemd1.reload-daemon',
                 'org.freedesktop.systemd1.set-environment')
STATIC_SYSTEMD_DENY = (b'polkit.addRule(function(action, subject) {\n'
    b'  if ((subject.user == "chatops" || subject.user == "www-data") &&\n'
    b'      action.id.indexOf("org.freedesktop.systemd1.") == 0) return polkit.Result.NO;\n'
    b'});\n')
# Numeric UID/GID/groups/NNP projection of the already sealed R3 read witness
# d83569a1... (15 October). Digest only, no private capture is published. This
# limits the three temporary exceptions; it does NOT turn that read into full
# authority, namespace, Source, backup or current process admission.
LEGACY_CONTEXTS_SHA = 'e7551fc09ed17b9e8250260b3cf02280d46a9a8a96e2d8d11ad0043b06cc56b5'
EXE_HASHES = {}  # actual kernel identities, never an input GREEN/cache receipt


def command(argv, deadline, *, data=None, preexec=None, extra_env=None):
    io.require(argv[0] in ('/usr/bin/systemctl', '/usr/bin/pkcheck', '/usr/bin/sudo',
                          '/usr/bin/psql', '/usr/bin/python3', '/usr/bin/systemd-run',
                          '/usr/bin/ldd', '/usr/bin/findmnt', '/usr/bin/busctl'), 'COMMAND_SCOPE')
    remaining = min(20, deadline-time.monotonic())
    io.require(remaining > 0, 'COMMAND_DEADLINE')
    io.require(extra_env is None or set(extra_env) <= {'PGDATABASE', 'PGOPTIONS', 'PGCONNECT_TIMEOUT',
                                                    'PGAPPNAME', 'PGPASSFILE', 'PGUSER', 'PGHOST', 'PGPORT',
                                                    'PGPASSWORD'}, 'COMMAND_ENV_SCOPE')
    result = subprocess.run(argv, input=data, capture_output=True, timeout=remaining,
                            env={**ENV, **(extra_env or {})}, preexec_fn=preexec, cwd='/')
    io.require(time.monotonic() < deadline and len(result.stdout) <= 2*1024*1024 and
               len(result.stderr) <= 2*1024*1024, 'COMMAND_TIME_OR_OUTPUT_BOUND')
    return result


def unit_properties(units, properties, deadline):
    """One fresh bounded manager read, never a cache across checks/actions.

    Keep every requested object/property, reject duplicates/missing/foreign
    blocks. Repeated identical dependency reads within a single census need
    not each spawn another systemctl process. Manager reads remain sequential,
    not claimed to be an atomic snapshot or evidence of future stability.
    """
    allowed = {*UNITS, 'system.slice', 'sysinit.target', 'network-online.target', 'tmp.mount'}
    io.require(units and len(units) == len(set(units)) and set(units) <= allowed,
               'UNIT_BATCH_SCOPE')
    keys = set(properties.split(',')) | {'Id'}
    io.require(keys <= set(PROPERTIES.split(',')), 'UNIT_PROPERTY_SCOPE')
    r = command(['/usr/bin/systemctl', 'show', *units, '--no-pager',
                 '--property='+','.join(sorted(keys))], deadline)
    io.require(r.returncode == 0, 'UNIT_READ_UNKNOWN')
    result = {}
    for block in r.stdout.decode().strip().split('\n\n'):
        value = {}
        for line in block.splitlines():
            io.require('=' in line, 'UNIT_PROFILE_UNKNOWN')
            name, item = line.split('=', 1)
            io.require(name in keys and name not in value, 'UNIT_PROFILE_UNKNOWN')
            value[name] = item
        identity = value.get('Id')
        io.require(set(value) == keys and identity in units and identity not in result,
                   'UNIT_PROFILE_UNKNOWN')
        result[identity] = value
    io.require(set(result) == set(units), 'UNIT_PROFILE_UNKNOWN')
    return result


def unit_rows(units, deadline):
    result = unit_properties(units, PROPERTIES, deadline)
    for value in result.values():
        io.require(value['LoadState'] == 'loaded', 'UNIT_PROFILE_UNKNOWN')
        io.require(re.fullmatch('0|[1-9][0-9]{0,9}', value['NRestarts']) and
                   int(value['NRestarts']) <= 0xffffffff, 'UNIT_RESTART_COUNTER_UNKNOWN')
    return result


def starttime(pid):
    value = Path('/proc', str(pid), 'stat').read_text()
    return value[value.rfind(')')+2:].split()[19]


def task_label(pid):
    try: return (Path('/proc')/str(pid)/'attr/current').read_bytes().strip()
    except OSError as error:
        io.require(error.errno == errno.EINVAL, 'TASK_LABEL_VIEW_UNKNOWN')
        # EINVAL alone proves nothing. Require the actual active LSM list and
        # distinguish kernels without a per-task LABEL provider from an unread
        # AppArmor/SELinux/etc context. This does not claim no kernel policy.
        active = Path('/sys/kernel/security/lsm').read_text().strip().split(',')
        io.require(active and len(active) == len(set(active)) and set(active) <=
                   {'capability', 'landlock', 'lockdown', 'yama', 'bpf', 'integrity'},
                   'TASK_LABEL_PROVIDER_UNKNOWN')
        return b'NO_PER_TASK_LABEL_PROVIDER:'+','.join(active).encode()


def process(pid):
    root = Path('/proc')/str(pid); before = starttime(pid)
    s = dict(x.split(':', 1) for x in (root/'status').read_text().splitlines() if ':' in x)
    if s.get('Kthread', '').strip() == '1':
        io.require(starttime(pid) == before, 'KERNEL_TASK_CHANGED')
        return {'pid': pid, 'starttime': before, 'kernel_thread': 1}
    exe = os.readlink(root/'exe')
    fd = os.open(root/'exe', os.O_RDONLY | os.O_CLOEXEC | os.O_NOATIME)
    try:
        a = os.fstat(fd)
        key = (a.st_dev, a.st_ino, a.st_uid, a.st_gid, a.st_mode, a.st_nlink,
               a.st_size, a.st_mtime_ns, a.st_ctime_ns)
        io.require(a.st_size <= 32*1024*1024, 'ACTOR_EXEC_CHANGED')
        if key not in EXE_HASHES:
            raw = os.pread(fd, a.st_size+1, 0)
            io.require(len(raw) == a.st_size, 'ACTOR_EXEC_CHANGED')
            if len(EXE_HASHES) >= 128: EXE_HASHES.clear()
            EXE_HASHES[key] = io.sha(raw)
        digest = EXE_HASHES[key]
        io.require(a == os.fstat(fd), 'ACTOR_EXEC_CHANGED')
    finally:
        os.close(fd)
    out = {'pid': pid, 'starttime': before, 'kernel_thread': 0, 'exe': exe, 'exe_sha256': digest,
           'uid': list(map(int, s['Uid'].split())), 'gid': list(map(int, s['Gid'].split())),
           'groups': list(map(int, s['Groups'].split())), 'caps': {k: int(s[k].strip(), 16) for k in CAPS},
           'nnp': int(s['NoNewPrivs'].strip()), 'ppid': int(s['PPid'].strip()),
           'argv_sha256': io.sha((root/'cmdline').read_bytes()),
           'cgroup': (root/'cgroup').read_text().strip(),
           'namespaces': {n: os.readlink(root/'ns'/n) for n in ('pid', 'mnt', 'user', 'net')},
           'uid_map': (root/'uid_map').read_text().split(),
           'gid_map': (root/'gid_map').read_text().split(),
           'setgroups': (root/'setgroups').read_text().strip()}
    initial_env = (root/'environ').read_bytes()
    io.require(len(initial_env) <= 1024*1024, 'ACTOR_ENVIRONMENT_BOUND')
    out['initial_env_sha256'] = io.sha(initial_env)
    out['lsm_sha256'] = io.sha(task_label(pid))
    io.require(starttime(pid) == before, 'ACTOR_IDENTITY_CHANGED')
    return out


def exact_actor(row, expected):
    allowed = {'role', 'exe', 'exe_sha256', 'uid', 'gid', 'groups', 'caps', 'nnp',
               'argv_sha256', 'cgroup', 'initial_env_sha256', 'lsm_sha256', 'namespaces',
               'max_instances', 'origin_sha256'}
    io.require(set(expected) == allowed and expected['role'] in
               ('kernel_manager', 'administrative_service', 'authenticated_maintenance', 'nginx_reader'),
               'ADMIN_ROLE_SCHEMA')
    io.require(type(expected['max_instances']) is int and 1 <= expected['max_instances'] <= 8192 and
               type(expected['nnp']) is int and expected['nnp'] in (0, 1) and
               set(expected['caps']) == set(CAPS) and all(type(n) is int and 0 <= n < 2**64
               for n in expected['caps'].values()) and
               all(type(expected[k]) is list and len(expected[k]) == 4 and all(type(n) is int and 0 <= n < 2**32
                   for n in expected[k]) for k in ('uid', 'gid')) and type(expected['groups']) is list and
               all(type(n) is int and 0 <= n < 2**32 for n in expected['groups']), 'ADMIN_NUMERIC_PROFILE_SCHEMA')
    return all(row[k] == expected[k] for k in allowed-{'role', 'max_instances', 'origin_sha256'})


class Authority:
    def __init__(self, baseline, paths, channel, *, machine, deadline):
        required = {'schema', 'machine_sha256', 'boot_id', 'files', 'unit_files', 'actors',
                    'policy_roots', 'broker_sockets', 'broker_tcp', 'source_release',
                    'http', 'database', 'nginx_groups', 'source_origin_receipts', 'unit_search_sha256'}
        io.require(set(baseline) == required and baseline['schema'] == 'TU1NZ_PUBLIC_HOST_BASELINE_V1',
                   'BASELINE_SCHEMA')
        io.require(baseline['machine_sha256'] == machine and baseline['source_origin_receipts'], 'BASELINE_HOST_ORIGIN')
        origins = baseline['source_origin_receipts']
        io.require(type(origins) is list and 0 < len(origins) <= 256 and len(set(origins)) == len(origins) and
                   all(type(h) is str and re.fullmatch('[a-f0-9]{64}', h) for h in origins), 'BASELINE_ORIGIN_SCHEMA')
        # No "passed", "closed", "trusted:true" etc can enter this schema.
        self.b, self.paths, self.channel, self.deadline = baseline, paths, channel, deadline
        self.runtime = None
        self.probe_check = None
        self.initial = {}; self.profiles = {}; self.targets = {}; self.accepted = set()
        self.operator_pid = os.getpid(); self.operator_start = starttime(os.getpid())
        self.own_children = {}; self.stopped = set(); self.rights = set()
        self.runtime_invocations = {}; self.original_profiles = {}
        self.legacy_contexts = {}
        self.own_dropins = {u: set() for u in UNITS}
        self.own_config_paths = set(); self.new_parent_paths = set()
        self.negative_authorizations = {}; self.static_systemd_deny = False
        io.require(set(baseline['policy_roots']) == {'/etc/polkit-1/rules.d', '/usr/share/polkit-1/rules.d',
                   '/etc/sudoers.d', '/etc/dbus-1/system.d', '/usr/share/dbus-1/system.d'},
                   'INCOMPLETE_POLICY_ROOTS')
        io.require(all(a['origin_sha256'] in baseline['source_origin_receipts'] for a in baseline['actors']),
                   'ADMIN_ROLE_ORIGIN_UNBOUND')
        io.require({'/etc/passwd', '/etc/group', '/etc/nsswitch.conf', '/etc/sudoers', '/etc/hosts'} <=
                   set(baseline['files']), 'IDENTITY_OR_POLICY_INPUT_UNBOUND')
        libc = ctypes.CDLL(None, use_errno=True)
        io.require(libc.prctl(4, 0, 0, 0, 0) == 0, 'OPERATOR_DUMP_PROTECTION')
        raw, _ = paths.read('/etc/machine-id')
        # Same exact byte hash as the unchanged Control entry/owner plan. Do
        # not silently normalize newline/whitespace into a different Host pin.
        io.require(io.sha(raw) == machine, 'WRONG_HOST')
        io.require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == baseline['boot_id'], 'WRONG_BOOT')
        io.require(os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt') and
                   os.readlink('/proc/self/ns/user') == os.readlink('/proc/1/ns/user'), 'HOST_NAMESPACE_REQUIRED')
        io.require(set(baseline['source_release']) == {'probe_dependencies', 'python_binary', 'runtime_reference'},
                   'RUNTIME_SOURCE_RELEASE_INCOMPLETE')
        self.runtime = RuntimeFence(baseline['source_release']['runtime_reference'], paths,
            baseline['source_origin_receipts'], python_binary=baseline['source_release']['python_binary'], deadline=deadline)
        self.check_files()
        io.require(self.unit_search() == baseline['unit_search_sha256'], 'UNIT_SEARCH_BASELINE_CHANGED')
        self.initial_units = unit_rows(UNITS, self.deadline)
        self.check(stop_only=True)

    def function(self, unit, *, old):
        io.require(unit in UNITS, 'FUNCTION_UNIT_SCOPE')
        before = self.unit(unit); row = process(int(before['MainPID']))
        io.require(before['ActiveState'] == 'active' and not before['Job'], 'FUNCTION_INVOCATION_UNKNOWN')
        binary = self.b['source_release']['python_binary']
        io.require(row['exe'] == binary and row['exe_sha256'] ==
                   self.b['source_release']['probe_dependencies'][binary]['sha256'],
                   'RUNTIME_INTERPRETER_NOT_AUTHENTIC_REFERENCE')
        label = task_label(row['pid'])
        io.require(row['namespaces']['net'] == os.readlink('/proc/self/ns/net') and
                   label == task_label(os.getpid()) and (label == b'unconfined' or
                   label.startswith(b'NO_PER_TASK_LABEL_PROVIDER:')),
                   'FUNCTION_NAMESPACE_OR_LSM_PREREQUISITE_UNKNOWN')
        endpoints = self.b['http'][unit]
        io.require(type(endpoints) is list and 3 <= len(endpoints) <= 12 and
                   {'internal', 'proxy', 'public'} <= {e['stage'] for e in endpoints}, 'HTTP_CHAIN_INCOMPLETE')
        config = ('adult-commercial-s7-public.json', 'adult-commercial-s8-landing.json',
                  'adult-commercial-s10-wms.json')[UNITS.index(unit)]
        raw, _ = self.paths.read('/etc/tu1nz/'+config)
        contract = io.parse(raw); origin = urllib.parse.urlsplit(contract['canonical_origin'])
        io.require(origin.scheme == 'https' and origin.hostname in io.PUBLIC_HOSTS, 'CANONICAL_HTTP_ORIGIN_UNKNOWN')
        proof = {'listener': self.listener_binding(row, contract), 'http': [], 'data': {}}
        for endpoint in endpoints:
            url = urllib.parse.urlsplit(endpoint['url'])
            if endpoint['stage'] == 'internal':
                io.require(endpoint['location'] == 'host' and endpoint['host_header'] is None and
                           url.hostname == contract['bind_host'] and url.port == contract['bind_port'],
                           'INTERNAL_ENDPOINT_NOT_BOUND_TO_UNIT')
            elif endpoint['stage'] == 'proxy':
                io.require(endpoint['location'] == 'host' and endpoint['host_header'] == origin.hostname and
                           url.hostname in ('127.0.0.1', '::1') and url.port in (None, 80),
                           'PROXY_ENDPOINT_NOT_BOUND_TO_VHOST')
            else:
                io.require(endpoint['stage'] == 'public' and endpoint['location'] == 'client' and
                           url.scheme == 'https' and url.hostname == origin.hostname,
                           'PUBLIC_ENDPOINT_NOT_EXTERNAL_CANONICAL_TLS')
            measured = self.channel.http(endpoint)
            proof['http'].append({'stage': endpoint['stage'], **measured})
        if unit == UNITS[0]:
            base = Path('/proc')/str(row['pid'])/'root/run/credentials'/unit
            io.require(set(os.listdir(base)) == {'s7_form_secret', 's7_database_dsn'}, 'CREDENTIAL_SET_CHANGED')
            for name in ('s7_form_secret', 's7_database_dsn'):
                fd = os.open(base/name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME)
                try:
                    s = os.fstat(fd); raw = os.pread(fd, s.st_size+1, 0)
                    io.require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 1 <= len(raw) <= 4096 and
                               len(raw) == s.st_size and os.fstat(fd) == s and not s.st_mode & 0o022,
                               'CREDENTIAL_READ_UNKNOWN')
                    if not old:
                        io.require(s.st_uid == s.st_gid == 1001 and stat.S_IMODE(s.st_mode) == 0o600 and
                                   os.statvfs(base/name).f_flag & os.ST_RDONLY, 'CREDENTIAL_RUNTIME_VIEW_RED')
                    expected = self.b['database']['credential_sha256'][name]
                    io.require(io.sha(raw) == expected, 'CREDENTIAL_ORIGIN_CHANGED')
                    proof['data'][name] = {'sha256': io.sha(raw), 'uid': s.st_uid, 'gid': s.st_gid,
                                          'mode': stat.S_IMODE(s.st_mode)}
                    if name == 's7_database_dsn': dsn = raw.strip().decode()
                finally:
                    os.close(fd)
            # A fixed SELECT-only transaction under the actual required peer
            # identity. DSN never occurs in argv, records or private errors.
            parsed = urllib.parse.urlsplit(dsn)
            query_params = urllib.parse.parse_qsl(parsed.query, strict_parsing=True)
            options = dict(query_params)
            io.require(parsed.scheme in ('postgresql', 'postgres') and not parsed.fragment and
                       len(options) == len(query_params) and set(options) <= {'host', 'port', 'user', 'password', 'dbname'},
                       'DB_AUTHENTICATION_PROFILE_UNKNOWN')
            host = options.get('host', urllib.parse.unquote(parsed.hostname or '') or '/var/run/postgresql')
            database = options.get('dbname', urllib.parse.unquote(parsed.path.lstrip('/')))
            user = options.get('user', urllib.parse.unquote(parsed.username or '') or 'chatops')
            password = options.get('password', urllib.parse.unquote(parsed.password or ''))
            port = options.get('port', str(parsed.port or 5432))
            io.require(host in ('/var/run/postgresql', '/run/postgresql', 'localhost', '127.0.0.1', '::1') and
                       port.isdecimal() and 1 <= int(port) <= 65535 and database == self.b['database']['database'] and
                       user == self.b['database']['role'] and all('\x00' not in v and '\n' not in v
                       for v in (database, user, password)), 'DB_LOCAL_TARGET_OR_IDENTITY_UNKNOWN')
            def peer():
                libc = ctypes.CDLL(None, use_errno=True)
                last = int(Path('/proc/sys/kernel/cap_last_cap').read_text())
                if not 0 <= last <= 63: os._exit(126)
                for cap in range(last+1):
                    if libc.prctl(24, cap, 0, 0, 0) != 0: os._exit(126)
                if libc.prctl(38, 1, 0, 0, 0) != 0: os._exit(126)
                os.setgroups([]); os.setgid(1001); os.setuid(1001)
            if host.startswith('/'):
                socket_name = host+'/.s.PGSQL.'+port
                runtime_socket = Path('/proc')/str(row['pid'])/'root'/socket_name.lstrip('/')
                host_stat, runtime_stat = os.stat(socket_name), os.stat(runtime_socket)
                io.require(stat.S_ISSOCK(host_stat.st_mode) and
                           (host_stat.st_dev, host_stat.st_ino) == (runtime_stat.st_dev, runtime_stat.st_ino),
                           'DB_RUNTIME_SOCKET_NOT_SAME_OBJECT')
            query = ("BEGIN READ ONLY; SET LOCAL statement_timeout='2s'; "
                     "SELECT current_user,current_database(),current_setting('transaction_read_only'),"
                     "has_table_privilege(current_user,'commercial_s7_waitlist','SELECT'),"
                     "has_table_privilege(current_user,'commercial_s7_analytics_events','SELECT'); "
                     "SELECT rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls "
                     "FROM pg_roles WHERE rolname=current_user; "
                     "SELECT EXISTS(SELECT 1 FROM commercial_s7_waitlist LIMIT 1),"
                     "EXISTS(SELECT 1 FROM commercial_s7_analytics_events LIMIT 1); ROLLBACK;")
            result = command(['/usr/bin/psql', '-X', '-w', '-q', '-A', '-t', '-F', '|',
                              '--set=ON_ERROR_STOP=1'], self.deadline, data=query.encode(), preexec=peer,
                             extra_env={'PGDATABASE': database, 'PGUSER': user, 'PGHOST': host, 'PGPORT': port,
                                        'PGPASSWORD': password, 'PGCONNECT_TIMEOUT': '2',
                                        'PGAPPNAME': 'tu1nz-readonly-public-admission',
                                        'PGOPTIONS': '-c default_transaction_read_only=on',
                                        'PGPASSFILE': '/proc/self/fd/-1'})
            io.require(result.returncode == 0 and not result.stderr, 'DB_PEER_READ_UNKNOWN')
            lines = result.stdout.decode().splitlines()
            wanted = '|'.join((self.b['database']['role'], self.b['database']['database'], 'on', 't', 't'))
            io.require(len(lines) == 3 and lines[0] == wanted and lines[1] == 'f|f|f|f|f' and
                       lines[2] in ('t|t', 't|f', 'f|t', 'f|f'),
                       'DB_IDENTITY_OR_READ_RED')
            proof['data']['database'] = {'peer_uid_gid': 1001, 'identity_readonly_select': lines[0].split('|'),
                                        'actual_role_flags': lines[1].split('|'),
                                        'query_result_sha256': io.sha(result.stdout), 'provider_data_emitted': False}
        else:
            root = Path('/proc')/str(row['pid'])/'root/var/lib/tu1nz-adult-public-s9'
            for name in ('landing-aggregates.json',) if unit == UNITS[1] else (
                    'landing-aggregates.json', 'wms-traffic-quality.json'):
                fd = os.open(root/name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME)
                try:
                    s = os.fstat(fd); raw = os.pread(fd, min(s.st_size, 1024*1024)+1, 0)
                    io.require(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 1001 and
                               stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and
                               len(raw) == s.st_size <= 1024*1024 and s == os.fstat(fd) and
                               type(io.parse(raw)) is dict and
                               (s.st_dev, s.st_ino) == (os.stat(root/name, follow_symlinks=False).st_dev,
                                                       os.stat(root/name, follow_symlinks=False).st_ino),
                               'CURRENT_STATE_READ_OR_PROFILE_RED')
                    proof['data'][name] = {'sha256': io.sha(raw), 'size': s.st_size,
                                          'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode)}
                finally:
                    os.close(fd)
        after = self.unit(unit)
        io.require(before['InvocationID'] == after['InvocationID'] and before['MainPID'] == after['MainPID'] and
                   starttime(row['pid']) == row['starttime'], 'FUNCTION_INVOCATION_CHANGED')
        return proof

    def listener_binding(self, row, contract):
        host, port = contract['bind_host'], contract['bind_port']
        io.require(host in ('127.0.0.1', '::1') and type(port) is int and 1024 <= port <= 65535,
                   'FUNCTION_LISTENER_SCOPE')
        root = Path('/proc')/str(row['pid']); inodes = set()
        for path in (root/'fd').iterdir():
            try: link = os.readlink(path)
            except FileNotFoundError: continue
            match = re.fullmatch(r'socket:\[(\d+)\]', link)
            if match: inodes.add(match[1])
        bound = []
        for name in ('tcp', 'tcp6'):
            for line in (root/'net'/name).read_text().splitlines()[1:]:
                parts = line.split(); address, number = parts[1].split(':')
                if parts[3] != '0A' or parts[9] not in inodes or int(number, 16) != port: continue
                raw = bytes.fromhex(address)
                raw = raw[::-1] if name == 'tcp' else b''.join(raw[n:n+4][::-1] for n in range(0, 16, 4))
                bound.append(socket.inet_ntop(socket.AF_INET if name == 'tcp' else socket.AF_INET6, raw))
        io.require(bound == [host] and starttime(row['pid']) == row['starttime'],
                   'HTTP_LISTENER_NOT_OWNED_BY_EXPECTED_INVOCATION')
        return {'pid': row['pid'], 'starttime': row['starttime'], 'address': bound[0], 'port': port}

    @contextmanager
    def limit(self, deadline):
        prior, old_paths = self.deadline, self.paths.deadline
        self.deadline = min(prior, deadline); self.paths.deadline = min(old_paths, deadline)
        try:
            io.require(time.monotonic() < self.deadline, 'AUTHORITY_DEADLINE')
            with self.channel.limit(deadline): yield
            io.require(time.monotonic() < self.deadline, 'AUTHORITY_DEADLINE')
        finally:
            self.deadline, self.paths.deadline = prior, old_paths

    def bounded(self, deadline):
        parent = self
        class Bound:
            def check(self):
                with parent.limit(deadline): return parent.check()
            def accept_site(self, rows):
                with parent.limit(deadline): return parent.accept_site(rows)
        return Bound()

    def check_files(self):
        io.require(time.monotonic() < self.deadline and len(self.b['files']) <= 256, 'BASELINE_FILE_BOUND')
        for path, expected in self.b['files'].items():
            pp = PurePosixPath(path)
            io.require(pp.is_absolute() and '..' not in pp.parts and
                       path.startswith(('/etc/', '/usr/', '/opt/tu1nz_repos/adult-publishing-core/')),
                       'BASELINE_READ_SCOPE')
            raw, row = self.paths.read(path)
            io.require(set(expected) == {'sha256', 'uid', 'gid', 'mode', 'attrs', 'flags', 'origin_sha256'} and
                       re.fullmatch('[a-f0-9]{64}', expected['origin_sha256']) and
                       expected['origin_sha256'] in self.b['source_origin_receipts'], 'FILE_ORIGIN_UNBOUND')
            io.require(io.sha(raw) == expected['sha256'] and all(row[k] == expected[k] for k in
                       ('uid', 'gid', 'mode', 'attrs', 'flags')), 'SOURCE_OR_INPUT_DRIFT')
            identity = (row['device'], row['inode'], row['mtime_ns'], row['ctime_ns'])
            if path in self.initial:
                io.require(self.initial[path] == identity, 'BOUND_SOURCE_REPLACED')
            else:
                self.initial[path] = identity
        # Numeric kernel subjects must have exactly the supported NSS identity;
        # an alias/duplicate UID must not change polkit/sudo's interpretation.
        passwd, _ = self.paths.read('/etc/passwd')
        records = [x.split(':') for x in passwd.decode().splitlines()]
        for uid, name in ((1001, 'chatops'), (33, 'www-data')):
            matches = [r for r in records if len(r) == 7 and r[2] == str(uid)]
            io.require(len(matches) == 1 and matches[0][0] == name and
                       len([r for r in records if len(r) == 7 and r[0] == name]) == 1,
                       'NUMERIC_NSS_SUBJECT_BINDING_UNKNOWN')

    def unit(self, unit):
        io.require(unit in UNITS, 'UNIT_SCOPE')
        return unit_rows((unit,), self.deadline)[unit]

    def units_check(self, *, stop_only):
        rows = unit_rows(UNITS, self.deadline)
        # Gather only the same four permitted dependencies, freshly measured
        # in this check. No dependency is inferred healthy from the baseline.
        dependency_names = set()
        for value in rows.values():
            dependency_names.update(set(value['Requires'].split()) & {'system.slice', 'sysinit.target'})
            dependency_names.update(set(value['Wants'].split()) & {'network-online.target', 'tmp.mount'})
        dependencies = (unit_properties(sorted(dependency_names),
            'LoadState,StopWhenUnneeded,ActiveState,Job', self.deadline) if dependency_names else {})
        for unit in UNITS:
            value = rows[unit]
            expected = self.b['unit_files'][unit]
            io.require(value['FragmentPath'] == expected['fragment'] and
                       not value['Job'] and value['NeedDaemonReload'] == 'no' and
                       value['KillMode'] == 'control-group', 'UNIT_CONTROL_DRIFT_OR_JOB')
            io.require(set(value['DropInPaths'].split()) == set(expected['dropins']) | self.own_dropins[unit],
                       'FOREIGN_OR_MISSING_EFFECTIVE_DROPIN')
            for relation in ('RequiredBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo', 'StopPropagatedFrom'):
                io.require(set(value[relation].split()) <= set(UNITS), 'FOREIGN_STOP_IMPACT')
            explicit_requires = set() if unit == UNITS[0] else {UNITS[0]}
            actual_requires = set(value['Requires'].split())
            io.require(not value['PartOf'] and not value['BindsTo'] and
                       explicit_requires <= actual_requires <= explicit_requires | {'system.slice', 'sysinit.target'} and
                       set(value['Names'].split()) == {unit} and value['Restart'] == 'on-failure' and
                       value['User'] == value['Group'] == 'chatops' and value['NoNewPrivileges'] == 'yes',
                       'FIXED_UNIT_CONTROL_CONTRACT_CHANGED')
            for implicit in actual_requires & {'system.slice', 'sysinit.target'}:
                props = dependencies[implicit]
                io.require(props['LoadState'] == 'loaded' and props['StopWhenUnneeded'] == 'no',
                           'IMPLICIT_DEPENDENCY_STOP_IMPACT_UNKNOWN')
            io.require(not any(value[k] for k in ('Triggers', 'TriggeredBy', 'OnFailure')),
                       'UNCONTROLLED_ACTIVATION')
            io.require(not value['OnSuccess'] and not value['BusName'] and value['Type'] == 'simple' and
                       all(value[k] == 'none' for k in ('FailureAction', 'SuccessAction', 'StartLimitAction',
                                                       'JobTimeoutAction')) and
                       all(value[k] == 'no' for k in ('RefuseManualStop', 'RefuseManualStart', 'StopWhenUnneeded')),
                       'UNEXPECTED_UNIT_SIDE_EFFECT_OR_MANUAL_REFUSAL')
            wants = set(value['Wants'].split())
            io.require(wants <= {'network-online.target', 'tmp.mount'}, 'FOREIGN_START_IMPACT')
            for dependency in wants:
                props = {k: v for k, v in dependencies[dependency].items() if k != 'Id'}
                io.require(props == {'LoadState': 'loaded', 'StopWhenUnneeded': 'no',
                                                          'ActiveState': 'active', 'Job': ''},
                           'START_DEPENDENCY_NOT_ALREADY_ACTIVE_OR_UNCONTROLLED')
            # Allowed base dependency order is pinned independently, not merely
            # derived from the current manager response.
            for key, expected_value in expected['properties'].items():
                unordered = key in ('Requires', 'Wants', 'BindsTo', 'PartOf', 'RequiredBy', 'BoundBy',
                                    'ConsistsOf', 'PropagatesStopTo', 'StopPropagatedFrom', 'Names')
                io.require(key in value and (set(value[key].split()) == set(expected_value.split())
                           if unordered else value[key] == expected_value), 'UNIT_DEPENDENCY_OR_POLICY_CHANGED')
            current = process(int(value['MainPID'])) if int(value['MainPID']) else None
            if current is not None:
                io.require(value['ControlGroup'] == '/system.slice/'+unit and
                           current['cgroup'] == '0::'+value['ControlGroup'], 'UNIT_PROCESS_CGROUP_BINDING')
            if unit in self.runtime_invocations and unit not in self.stopped:
                io.require(value['NRestarts'] == '0' and current is not None and value['ActiveState'] == 'active' and
                           (value['InvocationID'], current['pid'], current['starttime']) == self.runtime_invocations[unit],
                           'ACCEPTED_FIRST_INVOCATION_OR_RESTART_COUNTER_CHANGED')
            if unit in self.stopped:
                io.require(value['ActiveState'] == 'inactive' and current is None and self.empty(unit),
                           'UNIT_NOT_QUIET')
            elif unit in self.rights:
                io.require(value['ActiveState'] == 'active' and current is not None, 'START_NOT_ACTIVE')
                io.require((value['InvocationID'], current['pid'], current['starttime']) == self.runtime_invocations[unit],
                           'ACCEPTED_RUNTIME_INVOCATION_CHANGED')
                self.rights_check(unit, current)
            elif stop_only:
                io.require(value['ActiveState'] == 'active' and current is not None and
                           current['uid'] == current['gid'] == [1001]*4 and current['nnp'] == 1 and
                           not any(current['caps'][k] for k in ('CapPrm', 'CapEff', 'CapAmb')) and
                           current['namespaces']['user'] == os.readlink('/proc/self/ns/user'),
                           'STOP_TARGET_STATE_CHANGED')
                if unit in self.targets:
                    io.require((current['pid'], current['starttime']) == self.targets[unit], 'STOP_TARGET_CHANGED')
                self.targets[unit] = (current['pid'], current['starttime'])
                self.original_profiles.setdefault(unit, {k: current[k] for k in
                    ('uid', 'gid', 'groups', 'caps', 'nnp', 'uid_map', 'gid_map', 'setgroups')})
                self.legacy_contexts[unit] = {k: current[k] for k in ('uid', 'gid', 'groups', 'nnp')}
                self.legacy_contexts[unit]['caps'] = {k: format(current['caps'][k], '016x')
                                                    for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')}
        if stop_only:
            io.require(set(self.legacy_contexts) == set(UNITS) and
                       io.sha(io.canonical(self.legacy_contexts)) == LEGACY_CONTEXTS_SHA,
                       'NOT_THE_THREE_BOUND_LEGACY_CONTEXTS')

    def empty(self, unit):
        value = self.unit(unit); group = value['ControlGroup']
        if not group:
            return int(value['MainPID']) == 0 and not value['Job']
        root = Path('/sys/fs/cgroup')/group.lstrip('/')
        io.require('..' not in PurePosixPath(group).parts, 'CGROUP_PATH')
        if not root.exists():
            return int(value['MainPID']) == 0 and not value['Job']
        return all(not p.read_text().strip() for p in [root/'cgroup.procs', *root.rglob('cgroup.procs')])

    def actors_check(self, *, stop_only):
        counts = [0]*len(self.b['actors'])
        target_ids = set(self.targets.values()) if stop_only else set()
        # Measure each accepted unit once for THIS census. The former nested
        # query repeated all three manager reads for every unrelated PID. No
        # observation is reused across censuses or a Host action.
        right_pids = {}; right_seen = set()
        right_rows = unit_rows(sorted(self.rights), self.deadline) if self.rights else {}
        for unit in self.rights:
            value = right_rows[unit]; expected = self.runtime_invocations[unit]
            io.require(value['ActiveState'] == 'active' and not value['Job'] and
                       value['NRestarts'] == '0' and
                       (value['InvocationID'], int(value['MainPID'])) == expected[:2],
                       'ACCEPTED_RUNTIME_INVOCATION_CHANGED')
            right_pids[expected[1]] = (unit, expected[2])
        io.require(len(right_pids) == len(self.rights), 'UNIT_MAIN_PROCESS_COLLISION')
        brokers = []
        for name in os.listdir('/proc'):
            if not name.isdecimal():
                continue
            pid = int(name)
            try:
                row = process(pid)
            except (FileNotFoundError, ProcessLookupError):
                continue
            # Each exception has a precise, measured identity. No UID0/1001 or
            # generic descendant exception is present.
            if row.get('kernel_thread') == 1:
                continue
            if pid == self.operator_pid:
                io.require(row['starttime'] == self.operator_start, 'OPERATOR_IDENTITY_CHANGED')
                continue
            if PurePosixPath(row['exe']).name in ('dockerd', 'containerd', 'podman', 'rootlesskit', 'buildkitd'):
                brokers.append(row)
            if (pid, row['starttime']) in target_ids:
                self.delegation_check(row, known_stop=True)
                continue
            if pid in right_pids:
                started, tick = right_pids[pid]
                io.require(row['starttime'] == tick, 'ACCEPTED_RUNTIME_INVOCATION_CHANGED')
                self.rights_check(started, row); right_seen.add(pid); continue
            matched = [i for i, profile in enumerate(self.b['actors']) if exact_actor(row, profile)]
            io.require(len(matched) == 1, 'UNCLASSIFIED_OR_EXTRA_ACTOR')
            index = matched[0]; counts[index] += 1
            io.require(counts[index] <= self.b['actors'][index]['max_instances'], 'ACTOR_COUNT_CHANGED')
            role = self.b['actors'][index]['role']
            if role == 'kernel_manager':
                io.require(pid == 1 and row['uid'] == [0]*4, 'MANAGER_ROLE_NOT_KERNEL_PID1')
            elif role == 'authenticated_maintenance':
                ancestor = self.operator_pid; parents = set()
                for _ in range(32):
                    if ancestor <= 1: break
                    raw = (Path('/proc')/str(ancestor)/'status').read_text()
                    values = dict(x.split(':', 1) for x in raw.splitlines() if ':' in x)
                    ancestor = int(values['PPid'].strip()); parents.add(ancestor)
                io.require(pid in parents, 'MAINTENANCE_NOT_OWN_AUTHENTICATED_ANCESTRY')
            elif role == 'administrative_service':
                io.require('/system.slice/' in row['cgroup'], 'ADMIN_NOT_BOUND_SERVICE_CONTEXT')
            if self.b['actors'][index]['role'] == 'nginx_reader':
                # A bounding ceiling is not an effective/inheritable grant.
                # It remains exactly pinned in the actor profile; real broker,
                # authorization and inherited-access checks are still required.
                io.require(PurePosixPath(row['exe']).name == 'nginx' and
                           self.b['nginx_groups'] == row['groups'] == [33] and
                           row['uid'] == row['gid'] == [33]*4 and not any(v for k, v in row['caps'].items()
                           if k != 'CapBnd'),
                           'NGINX_AUTHORITY_CHANGED')
                self.delegation_check(row)
        io.require(all(counts) and right_seen == set(right_pids), 'EXPECTED_ADMIN_ROLE_MISSING')
        unix, tcp = self.broker_endpoints(brokers)
        io.require(unix == sorted(self.b['broker_sockets']) and tcp == self.b['broker_tcp'],
                   'BROKER_LISTENER_SET_CHANGED_OR_UNKNOWN')
        io.require(not tcp, 'TCP_BROKER_AUTHENTICATION_UNPROVEN')

    def broker_endpoints(self, actors):
        unix, tcp = set(), []
        for row in actors:
            root = Path('/proc')/str(row['pid']); inodes = set()
            for fd in (root/'fd').iterdir():
                try:
                    link = os.readlink(fd)
                except FileNotFoundError:
                    continue
                match = re.fullmatch(r'socket:\[(\d+)\]', link)
                if match:
                    inodes.add(match[1])
            for line in (root/'net/unix').read_text().splitlines()[1:]:
                parts = line.split(None, 7)
                if len(parts) == 8 and parts[6] in inodes and int(parts[3], 16) & 0x10000:
                    io.require(parts[7].startswith('/'), 'ABSTRACT_BROKER_AUTHORITY_UNKNOWN')
                    unix.add(parts[7])
            for name in ('tcp', 'tcp6'):
                for line in (root/'net'/name).read_text().splitlines()[1:]:
                    parts = line.split()
                    if parts[3] == '0A' and parts[9] in inodes:
                        tcp.append({'family': name, 'address_port': parts[1],
                                    'broker_exe_sha256': row['exe_sha256']})
            io.require(starttime(row['pid']) == row['starttime'], 'BROKER_PROCESS_CHANGED')
        return sorted(unix), sorted(tcp, key=io.canonical)

    def unit_search(self):
        result = command(['/usr/bin/systemctl', 'show', '--property=UnitPath', '--value'], self.deadline)
        roots = result.stdout.decode().split()
        allowed = {'/etc/systemd/system.control', '/run/systemd/system.control', '/run/systemd/transient',
                   '/run/systemd/generator.early', '/etc/systemd/system', '/etc/systemd/system.attached',
                   '/run/systemd/system', '/run/systemd/system.attached', '/run/systemd/generator',
                   '/usr/local/lib/systemd/system', '/usr/lib/systemd/system', '/run/systemd/generator.late'}
        io.require(result.returncode == 0 and len(roots) == len(set(roots)) and set(roots) == allowed,
                   'MANAGER_SEARCH_PATH_UNSUPPORTED_OR_INCOMPLETE')
        values = {'manager_search_order': roots}
        for root in roots:
            if not os.path.lexists(root):
                # StartTransientUnit may create its manager-owned empty
                # container. Empty absence vs empty safe directory conveys no
                # unit/activation authority. Every nonempty entry is compared.
                if root != '/run/systemd/transient': values[root] = {'absent': 1}
                continue
            generated = root in ('/run/systemd/generator', '/run/systemd/generator.early',
                                 '/run/systemd/generator.late')
            if generated:
                # PID1 intentionally replaces these OUTPUT directories during
                # the authorized reload. They are not original configuration,
                # Source, backup or owner objects. Compare the entire exact
                # output namespace/content/profile, not discarded inode names.
                # No such rebinding is permitted for any original input.
                parent = self.paths.get('/run/systemd')
                fd = os.open(PurePosixPath(root).name, os.O_RDONLY | os.O_DIRECTORY |
                             os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            else: fd = os.dup(self.paths.get(root))
            try:
                root_row = self.paths.d.metadata(fd)
                if generated:
                    values[root] = {k: root_row[k] for k in ('uid', 'gid', 'mode', 'type', 'attrs', 'flags')}
                    values[root]['flags'] &= ~self.paths.d.PHYSICAL_FLAGS
                self.search_directory(fd, root, values, generated=generated, depth=0)
            finally: os.close(fd)
        return io.sha(io.canonical(values))

    def search_directory(self, fd, current, values, *, generated, depth):
        io.require(depth < 32 and time.monotonic() < self.deadline, 'MANAGER_SEARCH_BOUND')
        before = os.fstat(fd)
        for name in sorted(os.listdir(fd)):
            path = str(PurePosixPath(current)/name)
            if path in self.own_config_paths or path in self.new_parent_paths:
                # Recurse through new own parents too; only the individually
                # registered artifact names can disappear from comparison.
                if path not in self.new_parent_paths: continue
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC | os.O_NOATIME, dir_fd=fd)
                try:
                    self.paths.d.metadata(child)
                    self.search_directory(child, path, values, generated=generated, depth=depth+1)
                finally: os.close(child)
                continue
            s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            io.require(s.st_uid == 0 and (stat.S_ISLNK(s.st_mode) or not s.st_mode & 0o022),
                       'UNSAFE_MANAGER_SEARCH_OBJECT')
            row = {'device': s.st_dev, 'inode': s.st_ino, 'type': stat.S_IFMT(s.st_mode),
                   'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode)}
            if generated: row.pop('device'); row.pop('inode')
            if stat.S_ISLNK(s.st_mode): row['link'] = os.readlink(name, dir_fd=fd)
            elif stat.S_ISREG(s.st_mode):
                raw, metadata = self.paths.d.stable_file(fd, name)
                row.update(sha256=io.sha(raw), attrs=metadata['attrs'],
                           flags=metadata['flags'] & ~self.paths.d.PHYSICAL_FLAGS)
            elif stat.S_ISDIR(s.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC | os.O_NOATIME, dir_fd=fd)
                try:
                    metadata = self.paths.d.metadata(child)
                    io.require((metadata['device'], metadata['inode']) == (s.st_dev, s.st_ino),
                               'MANAGER_SEARCH_OBJECT_CHANGED')
                    row.update(attrs=metadata['attrs'], flags=metadata['flags'] & ~self.paths.d.PHYSICAL_FLAGS)
                    self.search_directory(child, path, values, generated=generated, depth=depth+1)
                finally: os.close(child)
            else: raise io.Hold('PUBLIC_OPERATOR_UNKNOWN_MANAGER_SEARCH_OBJECT')
            again = os.stat(name, dir_fd=fd, follow_symlinks=False)
            io.require((s.st_dev, s.st_ino, s.st_mtime_ns, s.st_ctime_ns) ==
                       (again.st_dev, again.st_ino, again.st_mtime_ns, again.st_ctime_ns),
                       'MANAGER_SEARCH_OBJECT_CHANGED')
            values[path] = row
            io.require(len(values) <= 8192, 'MANAGER_SEARCH_BOUND')
        after = os.fstat(fd)
        io.require((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
                   (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
                   'MANAGER_SEARCH_DIRECTORY_CHANGED')

    def delegation_check(self, row, *, known_stop=False):
        # Noninteractive protected POLICY QUERIES only: no sudo authentication,
        # systemd/broker operation or provider call is attempted.
        pid, tick, uid = row['pid'], row['starttime'], row['uid'][1]
        if row['nnp'] != 1:
            raw, _ = self.paths.read('/etc/passwd')
            names = [x.split(':')[0] for x in raw.decode().splitlines() if len(x.split(':')) == 7 and
                     x.split(':')[2] == str(uid)]
            io.require(len(names) == 1 and names[0] in ('www-data', 'chatops'), 'SUDO_SUBJECT_NAME_UNKNOWN')
            name = names[0]
            r = command(['/usr/bin/sudo', '-n', '-l', '-U', name], self.deadline)
            # -l's exit status is NOT an authorization decision. In particular
            # unknown-user/parser/I/O errors must never be admitted as denial.
            # sudo may print its NSS-canonical FQDN rather than gethostname().
            # The no--host query evaluates THIS process's Host; the independent
            # machine-id pin above, not this display string, authenticates it.
            denied = rb'User '+re.escape(name.encode())+rb' is not allowed to run sudo on [A-Za-z0-9._-]{1,255}\.\n'
            io.require(r.returncode in (0, 1) and not r.stderr and re.fullmatch(denied, r.stdout),
                       'SUDO_AUTHORITY_OR_UNKNOWN')
        # Never let a nominally read-only authorization query activate a daemon.
        # Address the already-running unique owner, with D-Bus auto-start OFF.
        r = command(['/usr/bin/busctl', '--system', '--auto-start=no', '--allow-interactive-authorization=no',
                     '--', 'call', 'org.freedesktop.DBus', '/org/freedesktop/DBus',
                     'org.freedesktop.DBus', 'GetNameOwner', 's', 'org.freedesktop.PolicyKit1'], self.deadline)
        words = shlex.split(r.stdout.decode())
        io.require(r.returncode == 0 and len(words) == 2 and words[0] == 's' and
                   re.fullmatch(r':\d+\.\d+', words[1]), 'EXISTING_POLICY_DAEMON_UNKNOWN_NO_ACTIVATION')
        owner = words[1]
        cache_key = (pid, tick, uid, owner, io.sha(io.canonical(row)))
        # Only an actually measured negative under the recognized unconditional
        # NO rule is stable across session/cache activity. Generic negative or
        # challenge decisions are NEVER cached. Every call still revalidates
        # actual actor/policy identities and this already-running unique owner.
        cached = self.static_systemd_deny and cache_key in self.negative_authorizations
        if cached:
            io.require(starttime(pid) == tick, 'AUTHORIZATION_SUBJECT_CHANGED')
            self.broker_access(row, known_stop=known_stop)
            return
        for action in ADMIN_ACTIONS:
            verbs = ('start', 'stop', 'restart', 'reload', 'kill', 'set-property') if action.endswith('manage-units') else ('',)
            for verb in verbs:
                for unit in UNITS if verb else ('',):
                    argv = ['/usr/bin/busctl', '--system', '--auto-start=no', '--allow-interactive-authorization=no',
                            '--', 'call', owner, '/org/freedesktop/PolicyKit1/Authority',
                            'org.freedesktop.PolicyKit1.Authority', 'CheckAuthorization', '(sa{sv})sa{ss}us',
                            'unix-process', '3', 'pid', 'u', str(pid), 'start-time', 't', str(tick),
                            'uid', 'i', str(uid), action, '2' if verb else '0']
                    if verb: argv += ['unit', unit, 'verb', verb]
                    argv += ['0', '']  # no interactive authorization or agent challenge
                    r = command(argv, self.deadline)
                    words = shlex.split(r.stdout.decode())
                    io.require(r.returncode == 0 and not r.stderr and len(words) >= 4 and
                               words[:3] == ['(bba{ss})', 'false', 'false'] and words[3].isdecimal(),
                               'POLKIT_AUTHORITY_CHALLENGE_OR_UNKNOWN')
                    count = int(words[3]); details = words[4:]
                    io.require(count <= 2 and len(details) == 2*count, 'POLKIT_DETAILS_UNKNOWN')
                    actual_details = dict(zip(details[::2], details[1::2]))
                    io.require(len(actual_details) == count and actual_details in
                               ({}, {'unit': unit, 'verb': verb} if verb else {}), 'POLKIT_DETAILS_NOT_REQUESTED')
        io.require(starttime(pid) == tick, 'AUTHORIZATION_SUBJECT_CHANGED')
        if self.static_systemd_deny:
            self.negative_authorizations[cache_key] = 1
        self.broker_access(row, known_stop=known_stop)

    def broker_access(self, row, *, known_stop=False):
        # Unknown TCP broker authentication is never inferred from an absent FD.
        io.require(not self.b['broker_tcp'], 'TCP_BROKER_AUTHENTICATION_UNPROVEN')
        # Linux pathname DAC uses fsuid, not effective UID. In particular an
        # otherwise different effective UID must not hide socket ownership.
        uid = row['uid'][3]
        for path in self.b['broker_sockets']:
            actual = Path('/proc')/str(row['pid'])/'root'/path.lstrip('/')
            try:
                s = os.stat(actual)
            except FileNotFoundError:
                continue
            io.require(stat.S_ISSOCK(s.st_mode), 'BROKER_ALIAS_UNKNOWN')
            io.require(not os.listxattr(actual), 'BROKER_ACL_OR_LSM_UNKNOWN')
            groups = set(row['groups']) | {row['gid'][3]}
            bits = (stat.S_IMODE(s.st_mode) >> (6 if uid == s.st_uid else 3 if s.st_gid in groups else 0)) & 7
            io.require(not bits & 2 or (known_stop and path in
                       ('/run/docker.sock', '/var/run/docker.sock', '/run/containerd/containerd.sock')),
                       'BROKER_EFFECTIVE_DAC_ACCESS')
        self.inherited_sockets(row, known_stop=known_stop)

    def inherited_sockets(self, row, *, known_stop):
        """Inspect real duplicate descriptors; no API request or auth trial.

        Current DAC cannot revoke an already connected administrative socket.
        Missing pidfd/getfd rights is UNKNOWN, never evidence of exclusion.
        Only the bound journal stdio and nginx's bound master IPC are allowed;
        the exact three stop-only contexts retain the explicit Docker exception.
        """
        root = Path('/proc')/str(row['pid']); names = list((root/'fd').iterdir())
        io.require(len(names) <= 4096, 'ACTOR_DESCRIPTOR_BOUND')
        libc = ctypes.CDLL(None, use_errno=True)
        pidfd = os.pidfd_open(row['pid'], 0)
        try:
            for path in names:
                try: link = os.readlink(path)
                except FileNotFoundError: continue
                if not link.startswith('socket:['): continue
                copied = libc.syscall(438, pidfd, int(path.name), 0)  # pidfd_getfd
                io.require(copied >= 0, 'INHERITED_SOCKET_VIEW_UNKNOWN')
                try:
                    # Do not construct a Python socket object around another
                    # process's shared open-file description. Use GET syscalls
                    # only; no timeout/blocking/setsockopt/API operation.
                    family = ctypes.c_int(); size = ctypes.c_uint(ctypes.sizeof(family))
                    io.require(libc.getsockopt(copied, socket.SOL_SOCKET, 39, ctypes.byref(family),
                               ctypes.byref(size)) == 0 and size.value == ctypes.sizeof(family), 'SOCKET_DOMAIN_UNKNOWN')
                    if family.value != socket.AF_UNIX: continue
                    credentials = ctypes.create_string_buffer(12); size.value = 12
                    io.require(libc.getsockopt(copied, socket.SOL_SOCKET, socket.SO_PEERCRED, credentials,
                               ctypes.byref(size)) == 0 and size.value == 12, 'UNIX_PEER_UNKNOWN')
                    peer_pid, peer_uid, _ = struct.unpack('=iII', credentials.raw)
                    io.require(peer_pid > 0, 'UNIDENTIFIED_UNIX_CONNECTION')
                    address = ctypes.create_string_buffer(110); size.value = 110
                    io.require(libc.getpeername(copied, address, ctypes.byref(size)) == 0 and 2 <= size.value <= 110,
                               'UNIX_PEER_ADDRESS_UNKNOWN')
                    peer_name = address.raw[2:size.value].split(b'\0', 1)[0]
                    peer_row = process(peer_pid)
                    matched = [p for p in self.b['actors'] if exact_actor(peer_row, p)]
                    io.require(len(matched) == 1, 'UNIX_PEER_NOT_BOUND_ADMINISTRATIVE_SERVICE')
                    executable = PurePosixPath(peer_row['exe']).name
                    journal = (int(path.name) in (0, 1, 2) and peer_name ==
                               b'/run/systemd/journal/stdout' and peer_uid == 0 and
                               ((matched[0]['role'] == 'kernel_manager' and peer_pid == 1 and executable == 'systemd')
                                or (matched[0]['role'] == 'administrative_service' and executable == 'systemd-journald')))
                    nginx = (PurePosixPath(row['exe']).name == executable == 'nginx' and
                             row['ppid'] == peer_pid and peer_uid == 0 and
                             matched[0]['role'] == 'administrative_service')
                    stop_docker = (known_stop and executable in ('dockerd', 'containerd') and peer_uid == 0 and
                                   matched[0]['role'] == 'administrative_service')
                    io.require(journal or nginx or stop_docker, 'INHERITED_ADMINISTRATIVE_OR_UNKNOWN_SOCKET')
                finally: os.close(copied)
            io.require(starttime(row['pid']) == row['starttime'], 'INHERITED_DESCRIPTOR_SUBJECT_CHANGED')
        finally: os.close(pidfd)

    def policies_check(self):
        # Source-bound custom/dynamic polkit JS is still not effective exclusion.
        # Admit only the vendor admin-identity declaration; decisions are queried
        # above for every relevant actual subject and fixed action/detail tuple.
        self.static_systemd_deny = False
        for root, expected_names in self.b['policy_roots'].items():
            io.require(root in ('/etc/polkit-1/rules.d', '/usr/share/polkit-1/rules.d',
                               '/etc/sudoers.d', '/etc/dbus-1/system.d', '/usr/share/dbus-1/system.d'),
                       'POLICY_SCOPE')
            fd = self.paths.get(root)
            io.require(sorted(os.listdir(fd)) == expected_names, 'POLICY_SET_CHANGED')
            for name in expected_names:
                path = root+'/'+name
                io.require(path in self.b['files'], 'POLICY_NOT_SOURCE_BOUND')
                if name.endswith('.rules'):
                    raw, _ = self.paths.read(path)
                    if raw == STATIC_SYSTEMD_DENY:
                        # Support an EXISTING exact no-grant rule; the operator
                        # never installs/edits polkit or treats this as a Host
                        # prerequisite already proved by Source tests.
                        self.static_systemd_deny = True
                        continue
                    if io.sha(raw) == 'f199e386a9297858331b00df07ed0b0ee5fcf4bea67f6c0bccc8a92b7e310bbd':
                        # Exact systemd vendor rule: YES only for subject.user
                        # systemd-network and hostname/timezone actions. It is
                        # inapplicable to the uniquely bound chatops/www-data
                        # subjects above; not a general JS/hash-origin waiver.
                        continue
                    text = re.sub(r'/\*.*?\*/|//[^\n]*', '', raw.decode(), flags=re.S)
                    io.require(re.fullmatch(r'\s*polkit\.addAdminRule\(function\(action,\s*subject\)\s*\{\s*return\s*\[\s*"unix-group:sudo"(?:\s*,\s*"unix-group:admin")?\s*\]\s*;\s*\}\);?\s*', text),
                               'DYNAMIC_POLKIT_POLICY_UNKNOWN')

    def rights_check(self, unit, row=None):
        row = row or process(int(self.unit(unit)['MainPID']))
        io.require(row['uid'] == row['gid'] == [1001]*4 and not row['groups'] and
                   not any(row['caps'].values()) and row['nnp'] == 1 and
                   row['uid_map'] == row['gid_map'] == ['0', '0', '1', '1001', '1001', '1'] and
                   row['setgroups'] == 'deny', 'ACTUAL_RUNTIME_RIGHTS_RED')
        self.delegation_check(row)
        return row

    def check(self, *, stop_only=False):
        io.require(time.monotonic() < self.deadline, 'AUTHORITY_DEADLINE')
        io.require(self.runtime is not None, 'RUNTIME_PROVENANCE_UNAVAILABLE')
        self.runtime.check()
        self.paths.check(); self.check_files(); self.policies_check()
        if self.probe_check is not None: self.probe_check()
        jobs = command(['/usr/bin/busctl', '--system', '--auto-start=no', '--allow-interactive-authorization=no',
                        '--json=short', 'call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1',
                        'org.freedesktop.systemd1.Manager', 'ListJobs'], self.deadline)
        io.require(jobs.returncode == 0 and io.parse(jobs.stdout) == {'type': 'a(usssoo)', 'data': [[]]},
                   'QUEUED_MANAGER_JOB_UNKNOWN')
        io.require(self.unit_search() == self.b['unit_search_sha256'], 'FOREIGN_MANAGER_RELOAD_DELTA')
        self.units_check(stop_only=stop_only); self.actors_check(stop_only=stop_only)
        # The three bound delegation exceptions authorize only their stop.
        # They never waive existing writable Source/config FDs or shared maps.
        writer_check(self.runtime.files | {v[:2] for v in self.initial.values()}, self.deadline)
        self.paths.check()
        io.require(time.monotonic() < self.deadline, 'AUTHORITY_DEADLINE')

    def close(self):
        runtime = getattr(self, 'runtime', None)
        if runtime is None: return []
        self.runtime = None
        return runtime.close()

    def accept_site(self, rows):
        groups = self.b['nginx_groups']
        io.require(type(groups) is list and all(type(n) is int for n in groups), 'NGINX_GROUP_BINDING')
        # This code is part of the reviewed operator, not supplied by a capsule.
        program = ('import hashlib,json,os,sys\n'
                   'v=json.load(sys.stdin)\n'
                   'for p,h in v.items():\n'
                   ' fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n'
                   ' try:\n'
                   '  s=os.fstat(fd)\n'
                   '  if h is None: assert os.path.isdir(p)\n'
                   '  else: assert hashlib.sha256(os.pread(fd,s.st_size+1,0)).hexdigest()==h\n'
                   ' finally: os.close(fd)\n')
        def reader():
            os.setgroups(groups); os.setgid(33); os.setuid(33)
        values = {str(Path('/var/www/lighting.tu1nz.com')/rel): row['sha256'] for rel, row in rows.items()}
        r = command(['/usr/bin/python3', '-I', '-B', '-S', '-c', program], self.deadline,
                    data=io.canonical(values), preexec=reader)
        io.require(r.returncode == 0, 'ACTUAL_NGINX_IDENTITY_READ_FAILED')
        # The trusted client performs the fixed read-only HTTP operation outside
        # the networkless owner supervisor and returns measured bytes/status,
        # never a GREEN claim. The operator verifies those measurements.
        self.channel.http(self.b['http']['lighting'])
