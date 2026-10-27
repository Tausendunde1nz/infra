"""Finite prospective coexistence, never isolation or Host discovery.

Import performs no I/O. Native reads occur only in the admitted operator.
Mount notifications and exec notifications are passive, not permission events:
no setns/chroot/ptrace, socket request, service control or permission response.
"""
from __future__ import annotations

import ctypes
from contextlib import contextmanager
import errno
import fcntl
import os
from pathlib import PurePosixPath
import re
import select
import shlex
import socket
import stat
import struct
import sys
import time

import tu1nz_public_operator_io as io

SCOPE = 'TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_R5P_CONTEXT_V1'
BASELINE = 'TU1NZ_PUBLIC_HOST_BASELINE_CONTEXT_V1'
BINDING = 'TU1NZ_PUBLIC_PROSPECTIVE_BINDING_CONTEXT_V1'
ACCEPTANCE = 'TU1NZ_PUBLIC_PROSPECTIVE_ACCEPTANCE_CONTEXT_V1'
RISK = 'SELECTED_COEXISTENCE_TCB_CAN_INFLUENCE_R5_NOT_ISOLATED'
NATIVE_FIXTURE_FAILED = 'PUBLIC_OPERATOR_CONTEXT_NATIVE_FIXTURE_FAILED'
ROLES = ('coexisting_container_tcb', 'coexisting_user_tcb')
CAPS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
NS = ('pid', 'mnt', 'user', 'net')
READ = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, 'O_NOATIME', 0)
O_PATH = 0x200000  # Linux, used only after native() has succeeded.
MAX_FILE = 32 * 1024 * 1024
UNITS = ('tu1nz-adult-public-s7.service','tu1nz-adult-public-s8-landing.service','tu1nz-adult-public-s10-wms.service')
ADMIN_ACTIONS = ('org.freedesktop.systemd1.manage-units','org.freedesktop.systemd1.manage-unit-files',
                 'org.freedesktop.systemd1.reload-daemon','org.freedesktop.systemd1.set-environment')
VERBS = ('start','stop','restart','reload','kill','set-property')
RESERVED = ['operator']+['stop:'+u for u in UNITS]+['runtime:'+u for u in UNITS]
CHANNEL_ACTIONS = {'application_input':['application-defined-input-potential-tcb'],
                   'tmux_command':['session-command-potential-tcb'],
                   'userbus_policy':['user-bus-delegation-potential-tcb'],
                   'agent_signing':['agent-delegation-potential-tcb'],
                   'system_broker':list(ADMIN_ACTIONS)}
PROFILE_FIELDS = {'role','exe','exe_sha256','uid','gid','groups','caps','nnp','argv_sha256',
                  'cgroup','initial_env_sha256','lsm_sha256','namespaces','max_instances','context_id'}
# Finite program slots, not prefix permissions. Real container IDs, PIDs,
# hashes, namespace IDs and private application inputs belong ONLY in annexes.
PROGRAMS = {
    'D1': {'/package/admin/s6-2.13.1.0/command/s6-svscan':1,
           '/package/admin/s6-2.13.1.0/command/s6-supervise':5,
           '/package/admin/s6-2.13.1.0/command/s6-ipcserverd':1,
           '/package/admin/s6-linux-init-1.1.2.1/command/s6-linux-init-shutdownd':1,
           '/usr/lib/jellyfin/bin/jellyfin':1,'/usr/bin/bash':1,'/usr/bin/sleep':1},
    'D2': {'/usr/share/grafana/bin/grafana':1},
    'D3': {'/usr/local/bin/python3.11':1}, 'D4': {'/usr/local/bin/python3.11':1},
    'D5': {'/usr/local/bin/node':1,'/sbin/tini':1}, 'D6': {'/usr/local/bin/python3.11':1},
    'U1': {'/usr/lib/systemd/systemd':1}, 'U2': {'/usr/lib/systemd/systemd-executor':1},
    'U3': {'/usr/bin/bash':1}, 'U4': {'/usr/bin/ssh-agent':1}, 'U5': {'/usr/bin/tmux':1},
    'U6': {'/usr/bin/bash':1}, 'U7': {'/usr/bin/dbus-daemon':1}}


def number(value, *, maximum=2**32-1, minimum=0):
    io.require(type(value) is int and minimum <= value <= maximum, 'CONTEXT_INTEGER_SCHEMA')


def digest(value):
    io.require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value), 'CONTEXT_DIGEST_SCHEMA')


def mapping(value):
    io.require(type(value) is list and 0 < len(value) <= 1024 and len(value) % 3 == 0 and
               all(type(n) is str and re.fullmatch('0|[1-9][0-9]{0,9}', n) for n in value),
               'CONTEXT_IDMAP_SCHEMA')
    rows = [tuple(map(int, value[n:n+3])) for n in range(0,len(value),3)]
    for inside, outside, count in rows:
        io.require(count > 0 and inside+count <= 2**32 and outside+count <= 2**32,
                   'CONTEXT_IDMAP_SCHEMA')
    for axis in (0,1):
        intervals = sorted((r[axis],r[axis]+r[2]) for r in rows)
        io.require(all(a[1] <= b[0] for a,b in zip(intervals,intervals[1:])), 'CONTEXT_IDMAP_OVERLAP')
    roots = [outside for inside,outside,count in rows if inside == 0]
    io.require(len(roots) == 1, 'CONTEXT_ROOT_IDMAP_REQUIRED')
    return roots[0]


def code_path(path):
    path_name(path)
    io.require(PurePosixPath(path).parts[1:2] not in (('proc',),('sys',),('dev',)),
               'CONTEXT_CODE_MAGIC_NAMESPACE')
    return path


def metadata_schema(row, uid, gid, *, link=False):
    keys = {'uid','gid','mode','attrs'} | (set() if link else {'flags'})
    io.require(type(row) is dict and set(row) == keys and row['uid'] == uid and row['gid'] == gid and
               type(row['uid']) is type(row['gid']) is int and type(row['mode']) is int and
               0 <= row['mode'] <= 0o777 and row['attrs'] == {}, 'CONTEXT_CODE_METADATA')
    if link:
        io.require(row['mode'] == 0o777, 'CONTEXT_LINK_METADATA')
    else:
        io.require(not row['mode'] & 0o022 and type(row['flags']) is int and
                   row['flags'] in (0,0x1000,0x80000,0x81000), 'CONTEXT_CODE_METADATA')


def selected_names(files, names, uid, gid):
    """Pure exact no-follow graph, including all alias targets and parents."""
    io.require(type(names) is dict and 0 < len(names) <= 1024, 'CONTEXT_NAME_BOUND')
    required = {'/'}; result = {}
    for path in files:
        code_path(path); pending = path.split('/')[1:]; current = PurePosixPath('/'); steps = 0
        while pending:
            steps += 1
            io.require(steps <= 512, 'CONTEXT_ALIAS_CYCLE')
            name = str(current/pending.pop(0)); code_path(name)
            row = names.get(name)
            if row is None:
                io.require(not pending and name in files, 'CONTEXT_NAME_MISSING')
                result[path] = name; break
            io.require(type(row) is dict and row.get('kind') in ('directory','link'), 'CONTEXT_NAME_SCHEMA')
            required.add(name)
            if row['kind'] == 'directory':
                io.require(set(row) == {'kind','uid','gid','mode','attrs','flags'}, 'CONTEXT_NAME_SCHEMA')
                metadata_schema({k:v for k,v in row.items() if k != 'kind'},uid,gid)
                current = PurePosixPath(name)
                io.require(pending, 'CONTEXT_CODE_IS_DIRECTORY')
            else:
                io.require(set(row) == {'kind','uid','gid','mode','attrs','target'}, 'CONTEXT_NAME_SCHEMA')
                metadata_schema({k:v for k,v in row.items() if k not in ('kind','target')},uid,gid,link=True)
                target = row['target']
                io.require(type(target) is str and 0 < len(target) <= 4096 and
                           '..' not in PurePosixPath(target).parts and
                           not any(ord(c)<32 or ord(c)==127 for c in target), 'CONTEXT_ALIAS_TARGET')
                if target.startswith('/'): current = PurePosixPath('/')
                pending = target.split('/') + pending
                pending = [p for p in pending if p not in ('','.')]
        io.require(path in result, 'CONTEXT_CODE_NAME_UNKNOWN')
    io.require(set(names) == required and names.get('/',{}).get('kind') == 'directory', 'CONTEXT_EXACT_NAMES')
    metadata_schema({k:v for k,v in names['/'].items() if k != 'kind'},uid,gid)
    return result


def profile_schema(profile, context_id):
    io.require(type(profile) is dict and set(profile) == PROFILE_FIELDS and
               profile['context_id'] == context_id and context_id in PROGRAMS and
               profile['role'] == ROLES[0 if context_id.startswith('D') else 1] and
               profile['exe'] in PROGRAMS[context_id], 'CONTEXT_PROFILE_SCHEMA')
    for key in ('exe_sha256','argv_sha256','initial_env_sha256','lsm_sha256'): digest(profile[key])
    for key in ('uid','gid'):
        io.require(type(profile[key]) is list and len(profile[key]) == 4, 'CONTEXT_IDENTITY_SCHEMA')
        for n in profile[key]: number(n)
    groups = profile['groups']
    io.require(type(groups) is list and len(groups) <= 65536 and all(type(n) is int for n in groups) and
               groups == sorted(groups), 'CONTEXT_GROUP_SCHEMA')
    for n in groups: number(n)
    io.require(type(profile['caps']) is dict and set(profile['caps']) == set(CAPS), 'CONTEXT_CAPSET_SCHEMA')
    for n in profile['caps'].values(): number(n,maximum=2**64-1)
    number(profile['nnp'],maximum=1)
    number(profile['max_instances'],minimum=1,maximum=PROGRAMS[context_id][profile['exe']])
    io.cgroup_records(profile['cgroup'])
    io.require(type(profile['namespaces']) is dict and set(profile['namespaces']) == set(NS) and
               all(type(v) is str and re.fullmatch(k+r':\[[0-9]+\]',v)
                   for k,v in profile['namespaces'].items()), 'CONTEXT_NAMESPACE_SCHEMA')


def validate_material(binding, baseline, material, byte_origin):
    """Additional pure checks; original HOST material validation still runs."""
    contexts = binding['contexts']
    io.require(type(contexts) is dict and set(contexts) == set(PROGRAMS), 'CONTEXT_EXACT_SET')
    profiles = {c:{} for c in contexts}; total_instances = names_count = file_count = 0
    identities = set(); user_root = None; shared_host_files = {}
    for item in binding['actors']:
        p = item['profile']
        if p['context_id'] == 'HOST': shared_host_files[p['exe']] = p['exe_sha256']
    for table in ('operator_dependencies','probe_dependencies'):
        for path,entry in baseline['source_release'][table].items():
            shared_host_files[entry.get('source',path)] = entry['sha256']
    for item in binding['actors']:
        profile = item['profile']; c = profile['context_id']
        if c == 'HOST': continue
        profile_schema(profile,c)
        h = io.sha(io.canonical(profile))
        io.require(h not in profiles[c], 'CONTEXT_PROFILE_DUPLICATE')
        profiles[c][h] = profile
    for key, row in contexts.items():
        fields = {'id','kind','full_cgroup','anchor_pid','anchor_starttime','root_identity','namespaces',
                  'uid_map','gid_map','setgroups','profiles','instance_policy','authority_edges',
                  'code_inputs','purpose_evidence_sha256','review_sha256'}
        io.require(type(row) is dict and set(row) == fields and row['id'] == key and
                   row['kind'] == ('container' if key.startswith('D') else 'user_session'), 'CONTEXT_SCHEMA')
        number(row['anchor_pid'],minimum=2); number(row['anchor_starttime'],minimum=1,maximum=2**64-1)
        root = row['root_identity']
        io.require(type(root) is dict and set(root) == {'device','inode','mount_id'}, 'CONTEXT_ROOT_SCHEMA')
        for n in root.values(): number(n,maximum=2**64-1)
        uid,gid = mapping(row['uid_map']),mapping(row['gid_map'])
        io.require(row['setgroups'] in ('allow','deny'), 'CONTEXT_SETGROUPS_SCHEMA')
        if key.startswith('D'):
            io.require(type(row['full_cgroup']) is str and
                       re.fullmatch(r'0::/system.slice/docker-[a-f0-9]{64}\.scope',row['full_cgroup']),
                       'CONTEXT_CONTAINER_CGROUP')
        else:
            io.require(type(row['full_cgroup']) is str and
                       re.fullmatch(r'0::/user.slice/user-1001.slice/[A-Za-z0-9_./@-]{1,256}',row['full_cgroup']),
                       'CONTEXT_USER_CGROUP')
            io.require(uid == gid == 0, 'CONTEXT_USER_HOST_IDMAP')
            current_root = (root,{n:row['namespaces'][n] for n in ('pid','mnt','user')},
                            row['code_inputs']['mountinfo_sha256'])
            if user_root is None: user_root = current_root
            io.require(user_root == current_root, 'CONTEXT_USER_ROOT_CONFLICT')
        io.require(type(row['profiles']) is list and row['profiles'] == sorted(set(row['profiles'])) and
                   set(row['profiles']) == set(profiles[key]) and profiles[key], 'CONTEXT_PROFILE_COVERAGE')
        for p in profiles[key].values():
            io.require(p['cgroup'] == row['full_cgroup'] and p['namespaces'] == row['namespaces'],
                       'CONTEXT_PROFILE_DOMAIN_DRIFT')
            if key.startswith('U'): io.require(p['uid'] == [1001]*4, 'CONTEXT_USER_SUBJECT')
        policy = row['instance_policy']
        io.require(type(policy) is dict and set(policy) == {'mode','members'} and
                   policy['mode'] == 'transaction-pinned' and type(policy['members']) is list and
                   1 <= len(policy['members']) <= sum(PROGRAMS[key].values()), 'CONTEXT_INSTANCE_POLICY')
        counts = {h:0 for h in profiles[key]}; member_ids = set()
        for member in policy['members']:
            io.require(type(member) is dict and set(member) == {'pid','starttime','profile_sha256'},
                       'CONTEXT_MEMBER_SCHEMA')
            number(member['pid'],minimum=2); number(member['starttime'],minimum=1,maximum=2**64-1)
            pair = member['pid'],member['starttime']
            io.require(member['pid'] not in identities and member['profile_sha256'] in counts,
                       'CONTEXT_MEMBER_COLLISION')
            identities.add(member['pid']); member_ids.add(pair); counts[member['profile_sha256']] += 1
        io.require((row['anchor_pid'],row['anchor_starttime']) in member_ids and
                   all(counts[h] == p['max_instances'] for h,p in profiles[key].items()), 'CONTEXT_MEMBER_COUNT')
        for exe,ceiling in PROGRAMS[key].items():
            io.require(sum(p['max_instances'] for p in profiles[key].values() if p['exe']==exe) <= ceiling,
                       'CONTEXT_PROGRAM_CEILING')
        total_instances += len(policy['members'])
        for h in (row['purpose_evidence_sha256'],row['review_sha256']):
            digest(h); raw = material(h)
            io.require(32 <= len(raw) <= 256*1024, 'CONTEXT_SEMANTIC_EVIDENCE_REQUIRED')
        inputs = row['code_inputs']
        io.require(type(inputs) is dict and set(inputs) == {'files','names','aliases','executable_mappings','dynamic_risk',
                                                          'mountinfo_sha256'} and
                   inputs['dynamic_risk'] == 'DYNAMIC_MEMORY_NOT_ATTESTED', 'CONTEXT_CODE_INPUT_SCHEMA')
        digest(inputs['mountinfo_sha256'])
        files = inputs['files']; names_count += len(inputs['names']); file_count += len(files)
        io.require(type(files) is dict and 0 < len(files) <= 512, 'CONTEXT_CODE_FILE_BOUND')
        aliases = inputs['aliases']
        io.require(type(aliases) is dict and not set(aliases) & set(files) and
                   all(type(v) is str and v in files for v in aliases.values()), 'CONTEXT_ALIAS_SCHEMA')
        resolved = selected_names({**files,**aliases},inputs['names'],uid,gid)
        io.require(all(resolved[p] == p for p in files), 'CONTEXT_CODE_CANONICAL_REQUIRED')
        io.require(all(resolved[p] == target for p,target in aliases.items()), 'CONTEXT_ALIAS_SOURCE')
        for path,entry in files.items():
            io.require(type(entry) is dict and set(entry) == {'sha256','origin_sha256','uid','gid','mode','attrs','flags'},
                       'CONTEXT_CODE_FILE_SCHEMA')
            metadata_schema({k:v for k,v in entry.items() if k not in ('sha256','origin_sha256')},uid,gid)
            io.require(entry['flags'] in (0,0x80000), 'CONTEXT_CODE_FILE_FLAGS')
            digest(entry['sha256']); byte_origin(entry['origin_sha256'],path,entry['sha256'],('PUBLISHER','GIT'))
            if key.startswith('U'):
                io.require(shared_host_files.setdefault(path,entry['sha256']) == entry['sha256'],
                           'CONTEXT_HOST_BYTE_COLLISION')
        for p in profiles[key].values():
            io.require(p['exe'] in files and files[p['exe']]['sha256'] == p['exe_sha256'], 'CONTEXT_EXE_ORIGIN')
        maps = inputs['executable_mappings']
        io.require(type(maps) is dict and set(maps) == {str(m['pid']) for m in policy['members']},
                   'CONTEXT_MAPPING_COVERAGE')
        for member in policy['members']:
            paths = maps[str(member['pid'])]
            io.require(type(paths) is list and paths == sorted(set(paths)) and paths and
                       set(paths) <= set(files) and profiles[key][member['profile_sha256']]['exe'] in paths,
                       'CONTEXT_MAPPING_INPUTS')
        validate_edges(row,baseline,material)
    io.require(total_instances <= 24 and file_count <= 512 and names_count+len(binding['names']) <= 1024,
               'CONTEXT_GLOBAL_BOUNDS')
    return total_instances


def protected_paths(baseline):
    return sorted(set(baseline['files']) | {
        '/opt/tu1nz_repos/public-web-runtime-r5/93555d8a141caf8ace33522f9340d30bfc47d2bb'} |
        {'/etc/systemd/system/'+unit+'.d/zzz-public-runtime-r5.conf' for unit in UNITS})


def admin_actions():
    return [dict(action=a,unit=u,verb=v) for a in ADMIN_ACTIONS
            for v in (VERBS if a.endswith('manage-units') else ('',)) for u in (UNITS if v else ('',))]


def edge_actions(kind):
    return admin_actions() if kind == 'administration' else [
        {'identity':'direct-identity-capability','descriptors':'exact-descriptor-channel',
         'same_uid':'same-uid-process-memory-and-fd-authority','mount_idmap':'namespace-root-idmap-authority'}[kind]]


def reserved_templates(baseline):
    artifact=baseline['source_release']['runtime_reference']['origin_sha256']
    return [dict(slot=s,machine_sha256=baseline['machine_sha256'],boot_id=baseline['boot_id'],
                 source='EXACT_OUTER_APPROVED_SCOPE_RELEASE',runtime_receipt_sha256=artifact,
                 witness='ORIGINAL_AUTHENTICATED_SELF' if s=='operator' else
                         'ORIGINAL_PINNED_STOP' if s.startswith('stop:') else 'ORIGINAL_OWN_VERIFIED_RUNTIME_START')
            for s in RESERVED]


def validate_edges(row, baseline, material):
    edges = row['authority_edges']; members = {m['pid'] for m in row['instance_policy']['members']}
    io.require(type(edges) is list and len(edges) == len(members)*5, 'CONTEXT_AUTHORITY_COVERAGE')
    actor_hashes = {io.sha(io.canonical({k:v for k,v in p.items() if k != 'origin_sha256'})) for p in baseline['actors']}
    sources = {m['pid']:m['profile_sha256'] for m in row['instance_policy']['members']}
    seen = set()
    for edge in edges:
        io.require(type(edge) is dict and set(edge) == {'kind','member','objects','measurement_sha256',
                                                       'evidence_sha256','effect','source_profile_sha256',
                                                       'target_profiles','reserved_targets','actions','channels'} and
                   edge['member'] in members and edge['kind'] in ('identity','administration','descriptors','same_uid','mount_idmap') and
                   (edge['kind'],edge['member']) not in seen and
                   edge['source_profile_sha256'] == sources[edge['member']] and
                   type(edge['target_profiles']) is list and edge['target_profiles'] == sorted(set(edge['target_profiles'])) and
                   set(edge['target_profiles']) <= actor_hashes and
                   edge['reserved_targets'] == (reserved_templates(baseline) if edge['kind'] in ('same_uid','mount_idmap') else []) and
                   edge['actions'] == edge_actions(edge['kind']) and
                   edge['objects'] == protected_paths(baseline) and
                   edge['effect'] == 'POTENTIAL_SUBJECT_AUTHORITY_ACCEPTED_TCB', 'CONTEXT_AUTHORITY_SCHEMA')
        seen.add((edge['kind'],edge['member'])); digest(edge['measurement_sha256'])
        channels=edge['channels']
        io.require(type(channels) is list and len(channels)<=4096 and
                   (edge['kind']=='descriptors' or channels==[]), 'CONTEXT_CHANNEL_SCHEMA')
        fds=set()
        for channel in channels:
            io.require(type(channel) is dict and set(channel)=={'fd','direction','provider_side','authority','actions','objects',
                       'source_profile_sha256','target_profile_sha256','socket_sha256'} and
                       type(channel['fd']) is int and 0<=channel['fd']<2**32 and channel['fd'] not in fds and
                       channel['direction'] in ('bound-listener','bound-peer') and
                       channel['provider_side'] in ('source','peer') and
                       (channel['direction']=='bound-peer' or channel['provider_side']=='source') and
                       channel['authority'] in CHANNEL_ACTIONS and
                       channel['actions']==CHANNEL_ACTIONS[channel['authority']] and
                       channel['objects']==protected_paths(baseline) and
                       channel['source_profile_sha256']==edge['source_profile_sha256'] and
                       (channel['target_profile_sha256'] in actor_hashes if channel['direction']=='bound-peer'
                        else channel['target_profile_sha256'] is None), 'CONTEXT_CHANNEL_SCHEMA')
            fds.add(channel['fd']);digest(channel['socket_sha256'])
        digest(edge['evidence_sha256']); raw = material(edge['evidence_sha256'])
        io.require(32 <= len(raw) <= 256*1024, 'CONTEXT_AUTHORITY_EVIDENCE')
        evidence = io.parse(raw)
        io.require(type(evidence) is dict and set(evidence) == {'schema','measurement','explanation'} and
                   evidence['schema'] == 'TU1NZ_CONTEXT_AUTHORITY_EVIDENCE_V1' and
                   type(evidence['measurement']) is dict and
                   io.sha(io.canonical(evidence['measurement'])) == edge['measurement_sha256'] and
                   type(evidence['explanation']) is str and 32 <= len(evidence['explanation']) <= 2048,
                   'CONTEXT_AUTHORITY_MEASUREMENT_EVIDENCE')


def native():
    io.require(sys.platform == 'linux' and hasattr(os, 'O_NOATIME') and
               os.uname().machine in ('x86_64', 'aarch64'), 'CONTEXT_NATIVE_KERNEL_REQUIRED')


def path_name(path):
    io.require(type(path) is str and 0 < len(path) <= 4096 and path.startswith('/') and
               not any(ord(c) < 32 or ord(c) == 127 for c in path) and
               '..' not in PurePosixPath(path).parts and str(PurePosixPath(path)) == path,
               'CONTEXT_PATH_SCHEMA')
    return path


def deadline_check(deadline):
    io.require(time.monotonic() < deadline, 'CONTEXT_DEADLINE')


def read_proc(path, bound=1024*1024, *, deadline):
    """Short reads are NOT EOF; use one sentinel byte and one outer deadline."""
    deadline_check(deadline)
    fd = os.open(path, READ)
    try:
        chunks = []; total = 0
        while True:
            deadline_check(deadline)
            raw = os.read(fd, min(65536,bound+1-total))
            deadline_check(deadline)
            if not raw: return b''.join(chunks)
            total += len(raw)
            io.require(total <= bound, 'CONTEXT_PROC_BOUND')
            chunks.append(raw)
    finally:
        os.close(fd)


def fd_identity(fd, *, deadline):
    value = os.fstat(fd)
    raw = read_proc('/proc/self/fdinfo/'+str(fd), 32768, deadline=deadline)
    matches = re.findall(rb'^mnt_id:\s*([0-9]+)$', raw, re.M)
    io.require(len(matches) == 1, 'CONTEXT_MOUNT_ID_UNKNOWN')
    return dict(device=value.st_dev, inode=value.st_ino, mount_id=int(matches[0]))


class ProcessLifetime:
    """One kernel lifetime per pinned member, never reopen/adopt after exit."""
    def __init__(self, pid, deadline):
        self.pid=pid;self.deadline=deadline;self.fd=None;self.failed=False
        try:
            deadline_check(deadline);self.fd=os.pidfd_open(pid,0)
            self.poll=select.poll();self.poll.register(self.fd,select.POLLIN|select.POLLERR|select.POLLHUP)
            self.check()
        except BaseException:
            self.close();raise

    def check(self):
        try:
            io.require(not self.failed and self.fd is not None,'CONTEXT_MEMBER_LIFETIME_LOST')
            deadline_check(self.deadline)
            io.require(not self.poll.poll(0),'CONTEXT_MEMBER_EXITED')
            raw=read_proc('/proc/self/fdinfo/'+str(self.fd),32768,deadline=self.deadline)
            found=re.findall(rb'^Pid:\s*(-?[0-9]+)$',raw,re.M)
            io.require(len(found)==1 and int(found[0])==self.pid and not self.poll.poll(0),
                       'CONTEXT_MEMBER_LIFETIME_LOST')
        except BaseException:
            self.failed=True;raise

    def close(self):
        if self.fd is not None:
            fd=self.fd;self.fd=None;os.close(fd)


def open_rooted(root, path, flags, *, aliases=False):
    """No fallback to openat/realpath and no execution in a foreign domain.

    Canonical components have already been explicitly walked. NO_SYMLINKS
    additionally prevents a racing intermediate alias. An O_PATH|O_NOFOLLOW
    leaf may be a symlink for the explicit, bounded name-graph parser.
    """
    native(); path_name(path)
    class How(ctypes.Structure):
        _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64),
                    ('resolve', ctypes.c_uint64)]
    io.require(flags & os.O_ACCMODE == os.O_RDONLY and
               not flags & ~(READ | O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW), 'CONTEXT_OPEN_FLAGS')
    how = How(flags, 0, 0x10 | 0x02 | (0 if aliases else 0x04))
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.syscall(437, root, os.fsencode(path), ctypes.byref(how), ctypes.sizeof(how))
    if fd < 0:
        error = io.Hold('PUBLIC_OPERATOR_CONTEXT_ROOTED_OPEN_UNKNOWN')
        error.native_errno = ctypes.get_errno()
        raise error
    return fd


class MountEpoch:
    """Latch foreign namespace mount AND unmount, including return-to-same.

    poll() itself acknowledges the kernel sequence. We NEVER acknowledge and
    continue after admission: any later event permanently fails this object.
    The first poll arms the epoch BEFORE any accepted root/topology sample.
    Reading the poll FD, recreating it, or resetting after a change is barred.
    """
    def __init__(self, pid, deadline):
        native(); self.deadline = deadline; self.failed = False; self.fd = None
        try:
            deadline_check(deadline)
            self.fd = os.open('/proc/'+str(pid)+'/mounts', READ)
            self.poll = select.poll()
            self.poll.register(self.fd, select.POLLPRI | select.POLLERR | select.POLLHUP | select.POLLNVAL)
            first = self.poll.poll(0)
            io.require(all(fd == self.fd and not mask & (select.POLLHUP | select.POLLNVAL)
                           for fd, mask in first), 'CONTEXT_MOUNT_EPOCH_UNAVAILABLE')
        except BaseException:
            self.close()
            raise

    def check(self):
        if self.failed or time.monotonic() >= self.deadline:
            self.failed = True
            raise io.Hold('PUBLIC_OPERATOR_CONTEXT_MOUNT_EPOCH_LOST')
        if self.poll.poll(0):
            self.failed = True
            raise io.Hold('PUBLIC_OPERATOR_CONTEXT_MOUNT_EVENT')

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None


class ExecEpoch:
    """Passive inode marks: a pinned actor reopening its original exe DENYs.

    This covers exec of the same inode and exec-away/return, not interpreted
    input, JIT, arbitrary memory integrity, or a complete process event trace.
    Subject/profile censuses separately reject an actor that stays on another
    image. No permission-event masks or responses, no unlimited queue/marks.
    """
    def __init__(self, pids, deadline):
        native(); self.pids = set(pids); self.deadline = deadline; self.failed = False
        self.fd = None; self.marked = set(); self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        self.libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
                                           ctypes.c_int, ctypes.c_char_p]
        self.fd = self.libc.fanotify_init(1 | 2 | 0x80, READ)  # CLOEXEC NONBLOCK REPORT_PIDFD
        io.require(self.fd >= 0, 'CONTEXT_EXEC_WATCH_UNAVAILABLE')

    def mark(self, fd):
        value = fd_identity(fd,deadline=self.deadline); key = (value['device'], value['inode'])
        if key not in self.marked:
            io.require(len(self.marked) < 512 and
                       self.libc.fanotify_mark(self.fd, 1, 0x1000, fd, None) == 0,
                       'CONTEXT_EXEC_MARK_UNKNOWN')  # ADD / OPEN_EXEC, inode via dirfd
            self.marked.add(key)

    def consume(self, raw):
        """Kernel ABI parser, also exercised with wholly synthetic bytes."""
        offset = 0; fault = schema_fault = False; owned = set()
        while offset < len(raw):
            if len(raw)-offset < 24:
                schema_fault = True; break
            length, version, _, metadata_len, mask, fd, pid = struct.unpack_from('=IBBHQii', raw, offset)
            if fd >= 0: owned.add(fd)
            if not 24 <= metadata_len <= length <= len(raw)-offset:
                schema_fault = True; break
            schema_fault |= version != 3
            try:
                pos = offset+metadata_len; pidfd = None
                while pos < offset+length:
                    if offset+length-pos < 4:
                        schema_fault = True; break
                    kind, _, size = struct.unpack_from('=BBH', raw, pos)
                    if size < 4 or pos+size > offset+length:
                        schema_fault = True; break
                    if kind == 4 and size == 8:
                        received = struct.unpack_from('=i', raw, pos+4)[0]
                        if received >= 0: owned.add(received)
                        schema_fault |= pidfd is not None
                        pidfd = received
                    else: schema_fault = True
                    pos += size
                # Overflow, unattributable subject/FD, or a selected actor's
                # exec latches HOLD. Still close ALL subsequent event handles.
                fault |= (mask != 0x1000 or pid <= 0 or fd < 0 or pidfd is None or
                          pidfd < 0 or pid in self.pids)
            except BaseException:
                schema_fault = True
            offset += length
        # Close every recognized delivered FD even when another queued event
        # fails. Unknown ABI latches permanently; no resume on later bytes.
        for handle in owned:
            try: os.close(handle)
            except OSError: schema_fault = True
        if schema_fault:
            self.failed = True
            raise io.Hold('PUBLIC_OPERATOR_CONTEXT_EXEC_EVENT_SCHEMA')
        if fault:
            self.failed = True
            raise io.Hold('PUBLIC_OPERATOR_CONTEXT_EXEC_EVENT_OR_VIEW_UNKNOWN')

    def check(self):
        io.require(not self.failed and time.monotonic() < self.deadline, 'CONTEXT_EXEC_EPOCH_LOST')
        for _ in range(64):
            deadline_check(self.deadline)
            try: raw = os.read(self.fd, 65536)
            except BlockingIOError: return
            io.require(raw, 'CONTEXT_EXEC_WATCH_LOST')
            self.consume(raw)
        self.failed = True
        raise io.Hold('PUBLIC_OPERATOR_CONTEXT_EXEC_EVENT_BOUND')

    def close(self):
        if self.fd is not None and self.fd >= 0:
            os.close(self.fd); self.fd = None


def socket_get(libc, fd, option, size):
    out = ctypes.create_string_buffer(size); length = ctypes.c_uint(size)
    io.require(libc.getsockopt(fd, socket.SOL_SOCKET, option, out, ctypes.byref(length)) == 0 and
               length.value == size, 'CONTEXT_SOCKET_OPTION_UNKNOWN')
    return out.raw


def socket_name(libc, fd, *, peer=False):
    out = ctypes.create_string_buffer(110); length = ctypes.c_uint(110)
    call = libc.getpeername if peer else libc.getsockname
    io.require(call(fd, out, ctypes.byref(length)) == 0 and 2 <= length.value <= 110,
               'CONTEXT_SOCKET_ADDRESS_UNKNOWN')
    # Exact sockaddr bytes preserve unnamed/abstract addresses without decoding
    # private titles or making a connect, recv, send, signing or broker request.
    return out.raw[:length.value].hex()


def unix_descriptor(libc, fd):
    domain = struct.unpack('=i', socket_get(libc, fd, 39, 4))[0]  # SO_DOMAIN
    io.require(domain == socket.AF_UNIX, 'CONTEXT_UNIX_DOMAIN_REQUIRED')
    accepting = struct.unpack('=i', socket_get(libc, fd, socket.SO_ACCEPTCONN, 4))[0]
    io.require(accepting in (0, 1), 'CONTEXT_SOCKET_STATE_UNKNOWN')
    row = dict(kind='listener' if accepting else 'connected',
               socket_type=struct.unpack('=i', socket_get(libc, fd, socket.SO_TYPE, 4))[0],
               cookie=struct.unpack('=Q', socket_get(libc, fd, 57, 8))[0],
               local=socket_name(libc, fd), peer=None, peer_pid=None, peer_uid=None, peer_gid=None)
    if not accepting:
        pid, uid, gid = struct.unpack('=iII', socket_get(libc, fd, 17, 12))  # Linux SO_PEERCRED
        io.require(pid > 0, 'CONTEXT_UNIX_PEER_UNKNOWN')
        row.update(peer=socket_name(libc, fd, peer=True), peer_pid=pid, peer_uid=uid, peer_gid=gid)
    return row

def file_metadata(fd):
    s = os.fstat(fd)
    io.require(stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode), 'CONTEXT_CODE_OBJECT_TYPE')
    io.require(not os.listxattr(fd), 'CONTEXT_CODE_ATTRIBUTE_UNKNOWN')
    flags = struct.unpack('=I',fcntl.ioctl(fd,0x80086601,struct.pack('=I',0)))[0]
    return dict(uid=s.st_uid,gid=s.st_gid,mode=stat.S_IMODE(s.st_mode),attrs={},flags=flags)


class RootBindings:
    """One held foreign root; no textual path is interpreted in HOST."""
    def __init__(self, row, deadline, exec_epoch, lifetime=None):
        native(); self.row = row; self.deadline = deadline; self.exec = exec_epoch
        self.root = self.events = None; self.mount = None
        self.lifetime=lifetime;self.owns_lifetime=lifetime is None
        self.namespace_fds = {}; self.dirs = {}; self.files = {}; self.links = {}
        self.watches = {}; self.failed = False; self.targets = set()
        try:
            pid = row['anchor_pid']
            if self.lifetime is None:self.lifetime=ProcessLifetime(pid,deadline)
            self.lifetime.check()
            self.mount = MountEpoch(pid,deadline)
            for name in NS:
                self.namespace_fds[name] = os.open('/proc/'+str(pid)+'/ns/'+name,os.O_RDONLY|os.O_CLOEXEC)
                io.require(os.readlink('/proc/self/fd/'+str(self.namespace_fds[name])) == row['namespaces'][name],
                           'CONTEXT_NAMESPACE_FD_DRIFT')
            self.root = os.open('/proc/'+str(pid)+'/root',READ|os.O_DIRECTORY)
            io.require(fd_identity(self.root,deadline=self.deadline) == row['root_identity'], 'CONTEXT_ROOT_IDENTITY_DRIFT')
            if row['kind'] == 'user_session':
                host = os.open('/',READ|os.O_DIRECTORY)
                try: io.require(fd_identity(host,deadline=self.deadline) == row['root_identity'], 'CONTEXT_USER_NOT_HOST_ROOT')
                finally: os.close(host)
                io.require(all(row['namespaces'][n] == os.readlink('/proc/1/ns/'+n)
                               for n in ('pid','mnt','user')), 'CONTEXT_USER_NOT_HOST_NAMESPACES')
            self.libc = ctypes.CDLL(None,use_errno=True)
            self.events = self.libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
            io.require(self.events >= 0, 'CONTEXT_NAME_WATCH_UNAVAILABLE')
            self.dirs['/'] = (self.root,fd_identity(self.root,deadline=self.deadline))
            self.watch(self.root, None)
            for path in row['code_inputs']['files']: self.pin(path)
            for path in row['code_inputs'].get('aliases',{}): self.pin(path)
            self.check()
        except BaseException:
            self.close(check=False)
            raise

    def watch(self, fd, leaf):
        wd = self.libc.inotify_add_watch(self.events,os.fsencode('/proc/self/fd/'+str(fd)),0x2fce)
        io.require(wd >= 0, 'CONTEXT_NAME_WATCH_UNAVAILABLE')
        self.watches.setdefault(wd,set()).add(leaf)

    def events_check(self):
        io.require(not self.failed and time.monotonic() < self.deadline, 'CONTEXT_NAME_FENCE_LOST')
        self.mount.check(); self.exec.check()
        try:
            for _ in range(64):
                try: raw = os.read(self.events,65536)
                except BlockingIOError: return
                io.require(raw, 'CONTEXT_NAME_WATCH_LOST')
                offset = 0
                while offset < len(raw):
                    io.require(len(raw)-offset >= 16, 'CONTEXT_NAME_EVENT_SCHEMA')
                    wd,mask,_,size = struct.unpack_from('=iIII',raw,offset)
                    io.require(offset+16+size <= len(raw), 'CONTEXT_NAME_EVENT_SCHEMA')
                    leaf = raw[offset+16:offset+16+size].split(b'\0',1)[0].decode('utf-8','strict')
                    io.require(not mask & (0x4000|0x2000|0x400|0x800|0x8000) and
                               not (leaf and leaf in self.watches.get(wd,set())) and
                               not (not leaf and mask & (0x02|0x04|0x08)), 'CONTEXT_CODE_NAME_EVENT')
                    offset += 16+size
            raise io.Hold('PUBLIC_OPERATOR_CONTEXT_NAME_EVENT_BOUND')
        except BaseException:
            self.failed = True
            raise

    def pin(self, path):
        code_path(path); pending = path.split('/')[1:]; current = PurePosixPath('/'); steps = 0
        while pending:
            self.events_check(); steps += 1
            io.require(steps <= 512 and len(self.dirs)+len(self.files)+len(self.links) <= 1024,
                       'CONTEXT_NAME_BOUND')
            leaf = pending.pop(0); name = str(current/leaf); code_path(name)
            parent = self.dirs[str(current)][0]
            self.watch(parent,leaf)  # BEFORE first lstat/readlink/open admission
            probe = open_rooted(self.root,name,O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                s = os.fstat(probe); identity = fd_identity(probe,deadline=self.deadline)
                expected = self.row['code_inputs']['names'].get(name)
                if stat.S_ISLNK(s.st_mode):
                    io.require(expected is not None and expected.get('kind') == 'link', 'CONTEXT_ALIAS_UNBOUND')
                    target = os.readlink('',dir_fd=probe)
                    io.require(target == expected['target'] and s.st_uid == expected['uid'] and
                               s.st_gid == expected['gid'] and stat.S_IMODE(s.st_mode) == expected['mode'] and
                               s.st_nlink == 1 and not os.listxattr('/proc/self/fd/'+str(parent)+'/'+leaf,
                                                                follow_symlinks=False), 'CONTEXT_ALIAS_DRIFT')
                    before = (identity,target,s.st_ctime_ns)
                    io.require(self.links.setdefault(name,before) == before, 'CONTEXT_ALIAS_IDENTITY_DRIFT')
                    if target.startswith('/'): current = PurePosixPath('/')
                    pending = [n for n in target.split('/') if n not in ('','.')] + pending
                    continue
                fd = open_rooted(self.root,name,READ|os.O_NOFOLLOW|
                                 (os.O_DIRECTORY if stat.S_ISDIR(s.st_mode) else 0))
                try:
                    io.require(fd_identity(fd,deadline=self.deadline) == identity, 'CONTEXT_CODE_OPEN_RACE')
                    actual = file_metadata(fd)
                    if stat.S_ISDIR(s.st_mode):
                        io.require(expected is not None and expected.get('kind') == 'directory' and
                                   actual == {k:v for k,v in expected.items() if k != 'kind'}, 'CONTEXT_DIRECTORY_DRIFT')
                        before = self.dirs.setdefault(name,(fd,identity))
                        if before[0] == fd: self.watch(fd,None); fd = None
                        io.require(before[1] == identity, 'CONTEXT_DIRECTORY_IDENTITY_DRIFT')
                        current = PurePosixPath(name)
                        io.require(pending, 'CONTEXT_CODE_IS_DIRECTORY')
                    else:
                        io.require(stat.S_ISREG(s.st_mode) and not pending and s.st_nlink == 1,
                                   'CONTEXT_CODE_TYPE_OR_LINKS')
                        entry = self.row['code_inputs']['files'].get(name)
                        io.require(entry is not None and actual == {k:v for k,v in entry.items()
                                   if k not in ('sha256','origin_sha256')}, 'CONTEXT_CODE_METADATA_DRIFT')
                        io.require(0 < s.st_size <= MAX_FILE, 'CONTEXT_CODE_BYTE_BOUND')
                        before = self.files.get(name)
                        signature = (identity,s.st_size,s.st_mtime_ns,s.st_ctime_ns,actual)
                        if before is None:
                            # Install BOTH passive fences before accepting any
                            # bytes. Stable full reads bracket watcher setup;
                            # no metadata-only shortcut at the acceptance edge.
                            self.exec.mark(fd); self.watch(fd,None)
                            self.events_check()
                            deadline_check(self.deadline)
                            raw = os.pread(fd,s.st_size+1,0)
                            io.require(len(raw) == s.st_size and io.sha(raw) == entry['sha256'] and
                                       os.fstat(fd) == s, 'CONTEXT_CODE_BYTES_DRIFT')
                            self.events_check(); deadline_check(self.deadline)
                            again = os.pread(fd,s.st_size+1,0)
                            io.require(again == raw and os.fstat(fd) == s, 'CONTEXT_CODE_BYTES_DRIFT')
                            self.events_check()
                            self.files[name] = (fd,signature); self.targets.add((s.st_dev,s.st_ino)); fd = None
                        else: io.require(before[1] == signature, 'CONTEXT_CODE_IDENTITY_DRIFT')
                        self.events_check()
                        return name
                finally:
                    if fd is not None: os.close(fd)
            finally: os.close(probe)
        raise io.Hold('PUBLIC_OPERATOR_CONTEXT_CODE_NAME_UNKNOWN')

    def check(self):
        self.lifetime.check();self.events_check(); row = self.row; pid = row['anchor_pid']
        io.require(io.sha(read_proc('/proc/'+str(pid)+'/mountinfo',deadline=self.deadline)) == row['code_inputs']['mountinfo_sha256'],
                   'CONTEXT_MOUNT_TOPOLOGY_DRIFT')
        fresh = os.open('/proc/'+str(pid)+'/root',READ|os.O_DIRECTORY)
        try: io.require(fd_identity(fresh,deadline=self.deadline) == row['root_identity'], 'CONTEXT_ROOT_IDENTITY_DRIFT')
        finally: os.close(fresh)
        io.require(all(os.readlink('/proc/'+str(pid)+'/ns/'+n) == row['namespaces'][n] for n in NS),
                   'CONTEXT_NAMESPACE_DRIFT')
        for name in ('uid_map','gid_map','setgroups'):
            raw = read_proc('/proc/'+str(pid)+'/'+name,32768,deadline=self.deadline).decode('ascii','strict')
            io.require((raw.strip() if name == 'setgroups' else raw.split()) == row[name], 'CONTEXT_IDMAP_DRIFT')
        expected_root = row['code_inputs']['names']['/']
        io.require(file_metadata(self.root) == {k:v for k,v in expected_root.items() if k != 'kind'},
                   'CONTEXT_ROOT_METADATA_DRIFT')
        for path in tuple(self.files): self.pin(path)
        for path in row['code_inputs'].get('aliases',{}): self.pin(path)
        self.events_check();self.lifetime.check()

    def close(self, *, check=True):
        errors = []
        if check:
            try: self.check()
            except BaseException: errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_CONTEXT_FENCE_CLOSE_UNKNOWN')
        handles = {v[0] for v in self.dirs.values()} | {v[0] for v in self.files.values()} | set(self.namespace_fds.values())
        handles.update(fd for fd in (self.root,self.events) if fd is not None and fd >= 0)
        if self.owns_lifetime and self.lifetime is not None:
            try:self.lifetime.close()
            except OSError:errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_CONTEXT_LIFETIME_CLOSE_UNKNOWN')
        if self.mount is not None:
            try: self.mount.close()
            except OSError: errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_CONTEXT_MOUNT_CLOSE_UNKNOWN')
            self.mount = None
        for fd in handles:
            try: os.close(fd)
            except OSError: errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_CONTEXT_HANDLE_CLOSE_UNKNOWN')
        self.dirs.clear(); self.files.clear(); self.namespace_fds.clear()
        self.root = self.events = None
        return errors


def identity_sample(row, domain):
    keys = ('pid','starttime','exe','exe_sha256','uid','gid','groups','caps','nnp','argv_sha256',
            'cgroup','initial_env_sha256','lsm_sha256','namespaces','uid_map','gid_map','setgroups')
    return {'subject':{k:row[k] for k in keys},'root_identity':domain['root_identity'],
            'mountinfo_sha256':domain['code_inputs']['mountinfo_sha256'],
            'interpretation':'BOUND_PRIVILEGES_POTENTIAL_TCB_INFLUENCE_NOT_ISOLATION'}


def broker_sample(root, paths, row, *, deadline):
    result = []
    for path in paths:
        deadline_check(deadline)
        path_name(path)
        try: fd = open_rooted(root,path,O_PATH|os.O_CLOEXEC,aliases=True)
        except io.Hold as error:
            if getattr(error,'native_errno',None) != errno.ENOENT: raise
            result.append(dict(path=path,present=False)); continue
        try:
            s = os.fstat(fd)
            io.require(stat.S_ISSOCK(s.st_mode) and not os.listxattr('/proc/self/fd/'+str(fd)),
                       'CONTEXT_BROKER_TYPE_OR_ATTRIBUTES_UNKNOWN')
            uid,gid = row['uid'][3],row['gid'][3]
            bits = (stat.S_IMODE(s.st_mode) >> (6 if uid == s.st_uid else
                    3 if s.st_gid in set(row['groups'])|{gid} else 0)) & 7
            result.append(dict(path=path,present=True,identity=fd_identity(fd,deadline=deadline),uid=s.st_uid,
                               gid=s.st_gid,mode=stat.S_IMODE(s.st_mode),fsuid=uid,fsgid=gid,mode_bits=bits))
        finally: os.close(fd)
    return result


def peer_binding(libc, fd, sock, census, match_profile, profiles, process, *, deadline):
    """A PID number is never joined to a reused present process.

    SO_PEERPIDFD binds the connection-time struct pid. A live pidfd brackets
    fresh complete process samples and its fdinfo PID must be identical.
    This still does NOT prove current socket ownership or no SCM_RIGHTS.
    """
    deadline_check(deadline)
    handle = struct.unpack('=i',socket_get(libc,fd,77,4))[0]  # SO_PEERPIDFD, no fallback
    io.require(handle >= 0, 'CONTEXT_PEER_LIFETIME_UNKNOWN')
    try:
        poll = select.poll(); poll.register(handle,select.POLLIN|select.POLLHUP|select.POLLERR)
        def live():
            deadline_check(deadline)
            io.require(not poll.poll(0), 'CONTEXT_PEER_EXITED')
            raw = read_proc('/proc/self/fdinfo/'+str(handle),32768,deadline=deadline)
            found = re.findall(rb'^Pid:\s*(-?[0-9]+)$',raw,re.M)
            io.require(len(found) == 1 and int(found[0]) == sock['peer_pid'], 'CONTEXT_PEER_LIFETIME_MISMATCH')
        live()
        peer = census.get(sock['peer_pid'])
        io.require(peer is not None and peer['uid'][1] == sock['peer_uid'] and
                   peer['gid'][1] == sock['peer_gid'] and process(sock['peer_pid']) == peer,
                   'CONTEXT_PEER_NOT_IN_FULL_CENSUS')
        matched = [p for p in profiles if match_profile(peer,p)]
        io.require(len(matched) == 1, 'CONTEXT_PEER_PROFILE_UNKNOWN')
        io.require(process(sock['peer_pid']) == peer, 'CONTEXT_PEER_CHANGED')
        live()
        return dict(peer_starttime=peer['starttime'],peer_profile_sha256=io.sha(io.canonical(
                    {k:v for k,v in matched[0].items() if k != 'origin_sha256'})))
    finally: os.close(handle)


def descriptors_sample(row, census, match_profile, profiles, process, *, deadline):
    """Only kernel getters on duplicate FDs. Never socket methods or payload I/O.

    SO_PEERCRED is connection-time identity, not proof of present ownership,
    delivery, agent keys or absence of SCM_RIGHTS. Those limitations are an
    explicit subject-TCB risk, not a negative-authorization shortcut.
    """
    pid = row['pid']; root = '/proc/'+str(pid); names = sorted(os.listdir(root+'/fd'),key=int)
    io.require(len(names) <= 4096, 'CONTEXT_DESCRIPTOR_BOUND')
    libc = ctypes.CDLL(None,use_errno=True); pidfd = os.pidfd_open(pid,0); values = []
    try:
        for name in names:
            deadline_check(deadline)
            number(int(name))
            fd = libc.syscall(438,pidfd,int(name),0)
            io.require(fd >= 0, 'CONTEXT_DESCRIPTOR_DUPLICATE_UNKNOWN')
            try:
                s = os.fstat(fd); flags = read_proc(root+'/fdinfo/'+name,32768,deadline=deadline)
                matches = re.findall(rb'^flags:\s*([0-7]+)$',flags,re.M)
                io.require(len(matches) == 1, 'CONTEXT_DESCRIPTOR_FLAGS_UNKNOWN')
                value = dict(fd=int(name),device=s.st_dev,inode=s.st_ino,type=stat.S_IFMT(s.st_mode),
                             rdev=s.st_rdev,flags=int(matches[0],8),socket=None)
                if stat.S_ISSOCK(s.st_mode):
                    family = struct.unpack('=i',socket_get(libc,fd,39,4))[0]
                    if family == socket.AF_UNIX:
                        sock = unix_descriptor(libc,fd)
                        if sock['kind'] == 'connected':
                            sock.update(peer_binding(libc,fd,sock,census,match_profile,profiles,process,deadline=deadline))
                        value['socket'] = sock
                    else:
                        # Network listeners can be bound as input-bearing TCB
                        # endpoints, not as trusted remote principals. Connected
                        # INET/NETLINK lacks a kernel-bound reviewed peer here:
                        # never turn its address into authority authentication.
                        io.require(family in (socket.AF_INET,socket.AF_INET6), 'CONTEXT_SOCKET_FAMILY_UNKNOWN')
                        accepting = struct.unpack('=i',socket_get(libc,fd,socket.SO_ACCEPTCONN,4))[0]
                        io.require(accepting == 1, 'CONTEXT_EXTERNAL_PEER_AUTHORITY_UNKNOWN')
                        value['socket'] = dict(kind='application-network-listener-untrusted-input',
                            family=family,cookie=struct.unpack('=Q',socket_get(libc,fd,57,8))[0],
                            socket_type=struct.unpack('=i',socket_get(libc,fd,socket.SO_TYPE,4))[0],
                            local=socket_name(libc,fd),peer=None)
                values.append(value)
            finally: os.close(fd)
        io.require(sorted(os.listdir(root+'/fd'),key=int) == names, 'CONTEXT_DESCRIPTOR_SET_CHANGED')
    finally: os.close(pidfd)
    return {'descriptors':values,'semantics':'EXACT_FD_VIEW_NOT_FUTURE_AUTHORITY_EXCLUSION'}


def positive_admin(authority, row, command, *, deadline):
    """Read-only positive/negative observations of EVERY fixed action tuple.

    No identity substitution, execution trial, interactive flag or cross-scan
    cache. Raw sudo text stays in memory; its policy interpretation remains
    independently reviewed material, never return-code-as-denial.
    """
    owner = authority._authorization_owner
    io.require(owner is not None, 'CONTEXT_ADMINISTRATION_OWNER_UNKNOWN')
    values = []
    for item in admin_actions():
        deadline_check(deadline); pid=row['pid'];tick=row['starttime'];uid=row['uid'][1]
        argv=['/usr/bin/busctl','--system','--auto-start=no','--allow-interactive-authorization=no',
              '--','call',owner,'/org/freedesktop/PolicyKit1/Authority',
              'org.freedesktop.PolicyKit1.Authority','CheckAuthorization','(sa{sv})sa{ss}us',
              'unix-process','3','pid','u',str(pid),'start-time','t',str(tick),'uid','i',str(uid),
              item['action'],'2' if item['verb'] else '0']
        if item['verb']:argv += ['unit',item['unit'],'verb',item['verb']]
        argv += ['0','']; r=command(argv,deadline)
        words=shlex.split(r.stdout.decode('utf-8','strict'))
        io.require(r.returncode == 0 and not r.stderr and len(words)>=4 and
                   words[0]=='(bba{ss})' and words[1] in ('true','false') and words[2]=='false' and
                   words[3].isdecimal(), 'CONTEXT_POLKIT_ACTION_UNKNOWN_OR_CHALLENGE')
        count=int(words[3]);details=words[4:]
        io.require(count<=2 and len(details)==2*count, 'CONTEXT_POLKIT_DETAILS_UNKNOWN')
        actual=dict(zip(details[::2],details[1::2]))
        io.require(len(actual)==count and actual in ({},{'unit':item['unit'],'verb':item['verb']} if item['verb'] else {}),
                   'CONTEXT_POLKIT_DETAILS_UNKNOWN')
        values.append(dict(**item,authorized=words[1]=='true',challenge=False,returned_details=actual))
    raw,_=authority.paths.read('/etc/passwd')
    names=[s.split(':')[0] for s in raw.decode().splitlines() if len(s.split(':'))==7 and s.split(':')[2]==str(uid)]
    io.require(len(names)==1 and re.fullmatch('[a-z_][a-z0-9_-]{0,31}',names[0]), 'CONTEXT_SUDO_SUBJECT_UNKNOWN')
    sudo=command(['/usr/bin/sudo','-n','-l','-U',names[0]],deadline)
    io.require(sudo.returncode in (0,1) and not sudo.stderr and sudo.stdout and len(sudo.stdout)<=256*1024,
               'CONTEXT_SUDO_POLICY_UNKNOWN')
    return dict(polkit=values,sudo=dict(subject_uid=uid,subject_name=names[0],returncode=sudo.returncode,
                listing_sha256=io.sha(sudo.stdout),actions=admin_actions(),
                interpretation='HOST_NSS_POLICY_LISTING_REQUIRES_EXACT_ACTION_SEMANTICS_REVIEW_NOT_CONTAINER_SUDO'))


class ContextBindings:
    def __init__(self, baseline, deadline, process):
        native(); self.baseline = baseline; self.deadline = deadline; self.process = process
        self.rows = baseline['contexts']; self.roots = {}; self.exec = None; self.members = {}; self.files = set()
        self.reserved_witnesses = {}
        self.lifetimes = {}
        self.profiles = {io.sha(io.canonical({k:v for k,v in p.items() if k != 'origin_sha256'})):p
                         for p in baseline['actors'] if p.get('context_id') != 'HOST'}
        io.require(set(self.rows) == set(PROGRAMS), 'CONTEXT_EXACT_SET')
        try:
            for key,domain in self.rows.items():
                for member in domain['instance_policy']['members']:
                    io.require(member['pid'] not in self.members, 'CONTEXT_MEMBER_COLLISION')
                    self.members[member['pid']] = (key,member)
            io.require(1 <= len(self.members) <= 24, 'CONTEXT_MEMBER_BOUND')
            for pid in self.members:self.lifetimes[pid]=ProcessLifetime(pid,deadline)
            self.exec = ExecEpoch(self.members,deadline)
            for key,domain in self.rows.items():
                # Full pinned subject first; no name/PID replacement/discovery.
                self.lifetimes[domain['anchor_pid']].check()
                actual = process(domain['anchor_pid'])
                self.lifetimes[domain['anchor_pid']].check()
                io.require(str(actual['starttime']) == str(domain['anchor_starttime']), 'CONTEXT_ANCHOR_CHANGED')
                self.roots[key] = RootBindings(domain,deadline,self.exec,self.lifetimes[domain['anchor_pid']])
                self.files.update(self.roots[key].targets)
            for pid,(_,member) in self.members.items():
                self.check_actor(process(pid),self.profiles[member['profile_sha256']])
            self.check()
        except BaseException:
            self.close(check=False)
            raise

    def matches(self, row, profile):
        selected = self.members.get(row['pid'])
        if selected is None or profile.get('context_id') != selected[0]: return False
        key,member = selected
        expected = self.profiles[member['profile_sha256']]
        return profile == expected and str(row['starttime']) == str(member['starttime']) and not row.get('kernel_thread') and all(
            row[k] == profile[k] for k in PROFILE_FIELDS-{'role','context_id','max_instances'})

    @contextmanager
    def limit(self, deadline):
        objects = [self,self.exec,*self.roots.values(),*(r.mount for r in self.roots.values()),*self.lifetimes.values()]
        previous = [(obj,obj.deadline) for obj in objects]
        for obj,old in previous: obj.deadline = min(old,deadline)
        try: yield
        finally:
            for obj,old in previous: obj.deadline = old

    def guard_exception(self, row, exceptions):
        if row['pid'] in self.members:
            _,member = self.members[row['pid']]
            io.require(not row.get('kernel_thread') and str(row['starttime']) == str(member['starttime']) and
                       (row['pid'],str(row['starttime'])) not in exceptions, 'CONTEXT_EXCEPTION_OR_IDENTITY_COLLISION')

    def mapped_files(self, row, root):
        raw = read_proc('/proc/'+str(row['pid'])+'/maps',8*1024*1024,deadline=self.deadline)
        observed = set()
        for line in raw.splitlines():
            deadline_check(self.deadline)
            parts = line.split(None,5)
            io.require(len(parts) >= 5 and re.fullmatch(rb'[0-9a-f]+-[0-9a-f]+',parts[0]) and
                       len(parts[1]) == 4, 'CONTEXT_MAPPING_VIEW_UNKNOWN')
            if b'x' not in parts[1] or parts[4] == b'0': continue
            io.require(len(parts) == 6 and not parts[5].endswith(b' (deleted)'), 'CONTEXT_MAPPING_SOURCE_UNKNOWN')
            fd = os.open('/proc/'+str(row['pid'])+'/map_files/'+parts[0].decode('ascii'),READ)
            try:
                identity = fd_identity(fd,deadline=self.deadline)
                candidates = [path for path,(held,_) in root.files.items()
                              if fd_identity(held,deadline=self.deadline) == identity]
                io.require(len(candidates) == 1, 'CONTEXT_UNBOUND_EXECUTABLE_MAPPING')
                observed.add(candidates[0])
            finally: os.close(fd)
        return sorted(observed)

    def check_actor(self, row, profile):
        self.lifetimes[row['pid']].check()
        io.require(self.matches(row,profile), 'CONTEXT_PINNED_ACTOR_CHANGED')
        key,member = self.members[row['pid']]; domain = self.rows[key]; root = self.roots[key]
        io.require(all(row[k] == domain[k] for k in ('namespaces','uid_map','gid_map','setgroups')),
                   'CONTEXT_ACTOR_NAMESPACE_OR_IDMAP_CHANGED')
        root.events_check()
        tasks = self.task_roots(row['pid'],domain['root_identity'])
        actor_root = exe = None
        try:
            deadline_check(self.deadline)
            actor_root = os.open('/proc/'+str(row['pid'])+'/root',READ|os.O_DIRECTORY)
            exe = os.open('/proc/'+str(row['pid'])+'/exe',READ)
            io.require(fd_identity(actor_root,deadline=self.deadline) == domain['root_identity'] and
                       fd_identity(exe,deadline=self.deadline) == fd_identity(root.files[profile['exe']][0],deadline=self.deadline),
                       'CONTEXT_ACTOR_ROOT_OR_EXE_DRIFT')
        finally:
            for fd in (exe,actor_root):
                if fd is not None: os.close(fd)
        before = self.mapped_files(row,root)
        io.require(before == domain['code_inputs']['executable_mappings'][str(row['pid'])] and
                   self.mapped_files(row,root) == before and self.process(row['pid']) == row,
                   'CONTEXT_MAPPING_OR_SUBJECT_CHANGED')
        io.require(self.task_roots(row['pid'],domain['root_identity']) == tasks, 'CONTEXT_TASK_ROOT_SET_CHANGED')
        root.events_check();self.lifetimes[row['pid']].check()

    def task_roots(self, pid, expected):
        path = '/proc/'+str(pid)+'/task'; names = sorted(os.listdir(path)); result = {}
        io.require(str(pid) in names and 1 <= len(names) <= 8192 and all(n.isdecimal() for n in names),
                   'CONTEXT_TASK_ROOT_SET_UNKNOWN')
        for name in names:
            deadline_check(self.deadline); task = path+'/'+name
            first = read_proc(task+'/stat',32768,deadline=self.deadline)
            tick = first[first.rfind(b')')+2:].split()[19]
            fd = os.open(task+'/root',READ|os.O_DIRECTORY)
            try: identity = fd_identity(fd,deadline=self.deadline)
            finally: os.close(fd)
            again = read_proc(task+'/stat',32768,deadline=self.deadline)
            io.require(again[again.rfind(b')')+2:].split()[19] == tick and identity == expected,
                       'CONTEXT_TASK_ROOT_DRIFT')
            result[name] = (tick,identity)
        io.require(sorted(os.listdir(path)) == names, 'CONTEXT_TASK_ROOT_SET_CHANGED')
        return result

    def authority_check(self, authority, census, command=None):
        io.require(command is not None, 'CONTEXT_POLICY_QUERY_UNAVAILABLE')
        io.require(set(self.members) <= set(census), 'CONTEXT_EXPECTED_MEMBER_MISSING')
        policy = {}
        paths = set(io.PROSPECTIVE_NSS)
        for directory,names in authority.b['policy_roots'].items():
            paths.update(directory+'/'+n for n in names)
        for path in sorted(paths):
            raw,_ = authority.paths.read(path); policy[path] = io.sha(raw)
        io.require(authority._authorization_owner is not None and not authority.b['broker_tcp'],
                   'CONTEXT_ADMINISTRATION_OWNER_OR_TCP_UNKNOWN')
        for pid,(key,member) in self.members.items():
            row = census[pid]; domain = self.rows[key]; root = self.roots[key]
            identity = identity_sample(row,domain)
            admin = dict(policy_sha256=policy,policy_owner=authority._authorization_owner,
                         broker_paths=broker_sample(root.root,authority.b['broker_sockets'],row,deadline=self.deadline),
                         action_effects=positive_admin(authority,row,command,deadline=self.deadline),
                         interpretation='BOUND_POLICY_POTENTIAL_AUTHORITY_NOT_A_NEGATIVE_DECISION')
            descriptors = descriptors_sample(row,census,authority.actor_matches,authority.b['actors'],self.process,deadline=self.deadline)
            # Descriptor and policy facts are not a trusted:true flag: each is
            # freshly measured and compared to exact reviewed private material.
            again = descriptors_sample(row,census,authority.actor_matches,authority.b['actors'],self.process,deadline=self.deadline)
            io.require(again == descriptors and self.process(pid) == row, 'CONTEXT_AUTHORITY_VIEW_CHANGED')
            def related(predicate):
                result=[]
                for target in census.values():
                    if not predicate(target):continue
                    reserved=(target['pid']==authority.operator_pid or
                              target['pid'] in {p for p,_ in authority.targets.values()} or
                              target['pid'] in {p for _,p,_ in authority.runtime_invocations.values()})
                    if reserved:
                        self.reserved_target(authority,target)
                        continue
                    matches=[p for p in authority.b['actors'] if authority.actor_matches(target,p)]
                    # The operator and the precisely checked original
                    # exceptions are not new context roles. Their transient
                    # identity remains governed by the original checks.
                    if not matches:
                        self.reserved_target(authority,target)
                        continue
                    io.require(len(matches)==1, 'CONTEXT_AUTHORITY_TARGET_AMBIGUOUS')
                    p=matches[0];result.append(io.sha(io.canonical({k:v for k,v in p.items() if k!='origin_sha256'})))
                return sorted(set(result))
            privileged = 0 in row['uid'] or any(row['caps'].values())
            # Conservative potential, NOT an assertion ptrace/signal/FD access
            # is granted. Include all UID-vector overlaps, not only EUID.
            same=related(lambda r:privileged or bool(set(r['uid']) & set(row['uid'])))
            mounts=related(lambda r:privileged or r['namespaces']['user']==row['namespaces']['user'] or
                                      r['namespaces']['mnt']==row['namespaces']['mnt'])
            facts = dict(identity=identity,administration=admin,descriptors=descriptors,
                         same_uid=dict(target_profiles=same,reserved_targets=reserved_templates(self.baseline),source=identity,
                                       effect='POTENTIAL_MEMORY_FD_SIGNAL_AUTHORITY_NOT_EXCLUDED'),
                         mount_idmap=dict(target_profiles=mounts,reserved_targets=reserved_templates(self.baseline),source=identity,
                                          effect='POTENTIAL_NAMESPACE_MOUNT_AUTHORITY_NOT_EXCLUDED'))
            for edge in domain['authority_edges']:
                if edge['member'] == pid:
                    kind=edge['kind'];targets=[]
                    if kind in ('same_uid','mount_idmap'):targets=facts[kind]['target_profiles']
                    if kind=='descriptors':
                        targets=sorted({d['socket']['peer_profile_sha256'] for d in descriptors['descriptors']
                                        if d['socket'] and d['socket'].get('peer_profile_sha256')})
                        self.channel_check(edge,descriptors,authority.b['actors'])
                    io.require(edge['target_profiles']==targets, 'CONTEXT_AUTHORITY_TARGET_DRIFT')
                    io.require(io.sha(io.canonical(facts[edge['kind']])) == edge['measurement_sha256'],
                               'CONTEXT_AUTHORITY_EDGE_DRIFT')
            root.events_check()

    def reserved_target(self, authority, row):
        """Only original already-checked identities, never UID/name adoption.

        Annexes explicitly accept potential influence on ALL seven finite
        transaction slots. Live slot membership is freshly checked, not a
        guessed future operator PID in a pre-launch annex or an absent edge.
        """
        if row['pid']==authority.operator_pid:
            io.require(row['starttime']==authority.operator_start,'CONTEXT_RESERVED_OPERATOR_DRIFT')
            slot='operator';value=(row['pid'],row['starttime'])
            self.hold_reserved(slot,value);return slot
        for unit,(pid,tick) in authority.targets.items():
            if row['pid']==pid:
                io.require(row['starttime']==tick,'CONTEXT_RESERVED_STOP_DRIFT')
                slot='stop:'+unit;self.hold_reserved(slot,(pid,tick));return slot
        for unit,(invocation,pid,tick) in authority.runtime_invocations.items():
            if row['pid']==pid:
                io.require(row['starttime']==tick,'CONTEXT_RESERVED_RUNTIME_DRIFT')
                slot='runtime:'+unit;self.hold_reserved(slot,(pid,tick,invocation));return slot
        raise io.Hold('PUBLIC_OPERATOR_CONTEXT_AUTHORITY_TARGET_UNKNOWN')

    def hold_reserved(self, slot, value):
        io.require(self.reserved_witnesses.setdefault(slot,value)==value, 'CONTEXT_RESERVED_REPLACEMENT')

    def channel_check(self, edge, descriptors, profiles):
        selected={c['fd']:c for c in edge['channels']}
        sockets={d['fd']:d['socket'] for d in descriptors['descriptors'] if d['socket'] is not None}
        io.require(set(selected)==set(sockets),'CONTEXT_CHANNEL_COVERAGE')
        by_hash={io.sha(io.canonical({k:v for k,v in p.items() if k!='origin_sha256'})):p for p in profiles}
        source=by_hash[edge['source_profile_sha256']]
        for fd,sock in sockets.items():
            c=selected[fd];peer=sock.get('peer_profile_sha256')
            io.require(c['socket_sha256']==io.sha(io.canonical(sock)) and
                       c['direction']==('bound-peer' if peer else 'bound-listener') and
                       c['target_profile_sha256']==peer,'CONTEXT_CHANNEL_DRIFT')
            io.require(c['provider_side'] in ('source','peer') and (peer or c['provider_side']=='source'),
                       'CONTEXT_CHANNEL_PROVIDER_UNKNOWN')
            provider=by_hash[peer] if c['provider_side']=='peer' else source
            required={'tmux_command':'tmux','userbus_policy':'dbus-daemon','agent_signing':'ssh-agent'}
            name=PurePosixPath(provider['exe']).name
            if c['authority'] in required:
                io.require(name==required[c['authority']], 'CONTEXT_CHANNEL_PROVIDER_UNKNOWN')
            # Either end may be the service provider. A tmux/agent/userbus
            # source must not disappear into generic input on its client FD.
            for endpoint in (source,*([by_hash[peer]] if peer else [])):
                executable=PurePosixPath(endpoint['exe']).name
                for kind,program in required.items():
                    if executable==program:
                        expected='system_broker' if executable=='dbus-daemon' and endpoint['role']=='administrative_service' else kind
                        io.require(c['authority']==expected and provider==endpoint,
                                   'CONTEXT_ADMINISTRATIVE_CHANNEL_RELABELLED')
                io.require(executable not in ('dockerd','containerd','podman','rootlesskit','buildkitd','sshd','sudo'),
                           'CONTEXT_UNBOUND_BROKER_ACTION_SET')
                if executable in ('systemd','polkitd'):
                    io.require(c['authority']=='system_broker' and provider==endpoint,
                               'CONTEXT_ADMINISTRATIVE_CHANNEL_RELABELLED')
            if c['authority']=='system_broker':
                io.require(provider['role'] in ('kernel_manager','administrative_service'), 'CONTEXT_CHANNEL_PROVIDER_UNKNOWN')

    def check(self):
        for lifetime in self.lifetimes.values():lifetime.check()
        self.exec.check()
        for key,root in self.roots.items():
            root.check()
            domain = self.rows[key]
            actual = self.process(domain['anchor_pid'])
            io.require(str(actual['starttime']) == str(domain['anchor_starttime']), 'CONTEXT_ANCHOR_CHANGED')
        self.exec.check()
        for lifetime in self.lifetimes.values():lifetime.check()

    def close(self, *, check=True):
        errors = []
        for root in self.roots.values(): errors.extend(root.close(check=check))
        self.roots.clear()
        if self.exec is not None:
            if check:
                try: self.exec.check()
                except BaseException: errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_CONTEXT_EXEC_CLOSE_UNKNOWN')
            try: self.exec.close()
            except OSError: errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_CONTEXT_EXEC_HANDLE_CLOSE_UNKNOWN')
            self.exec = None
        for lifetime in self.lifetimes.values():
            if check:
                try:lifetime.check()
                except BaseException:errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_CONTEXT_MEMBER_CLOSE_UNKNOWN')
            try:lifetime.close()
            except OSError:errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_CONTEXT_MEMBER_HANDLE_CLOSE_UNKNOWN')
        self.lifetimes.clear()
        return errors
