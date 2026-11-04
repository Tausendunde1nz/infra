"""Explicit production entry. Import/help never contacts a Host or claims a slot.

Execution requires exact independently approved private scope/Source receipt
hashes. Those select expected bytes and explicit TCB identities, NOT GREEN
observations. The remote reviewed code still measures every live prerequisite.
No password, private baseline, plan or credential goes into a process argument.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shlex
import stat
import subprocess
import sys
import time
import warnings
import zlib


def load_io():
    path = Path(__file__).resolve().with_name('tu1nz_public_operator_io.py')
    spec = importlib.util.spec_from_file_location('tu1nz_public_operator_io', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module; spec.loader.exec_module(module)
    return module


io = load_io()
INFRA_FILES = {n: 'scripts/tu1nz_public_operator_'+n+'.py' for n in ('io', 'fs', 'runtime_guard', 'observe', 'probes', 'host', 'context')}
INFRA_FILES['client'] = 'scripts/tu1nz_public_operator.py'
INFRA_FILES.update(artifact='scripts/tu1nz_public_runtime_artifact.py',
                   replacement='scripts/tu1nz_public_runtime_transition.py',
                   runtime_inputs='manifests/public-web-runtime-r5-inputs.json',
                   runtime_overlay='systemd/public-web-runtime-r5.conf')
INFRA_FILES.update(r3='scripts/tu1nz_public_bootstrap_r3.py', runtime='scripts/tu1nz_public_web_isolate_r1.py')
INFRA_FILES.update({n: 'systemd/'+u+'.d/zz-public-isolation-r1.conf' for n, u in zip(
    ('dropin_s7', 'dropin_s8_landing', 'dropin_wms'),
    ('tu1nz-adult-public-s7.service', 'tu1nz-adult-public-s8-landing.service', 'tu1nz-adult-public-s10-wms.service'))})
CONTROL_FILES = {'owner': 'managed/lighting/scripts/owner_supervisor.py',
                 'entry': 'managed/bin/tu1nz-lighting-halloween-deploy-r1',
                 'guard': 'managed/lighting/scripts/writer_guard_contract.py'}
APPROVAL = '7032ae9a4baf5c358e81050cd3fd675386c2f33100ab9932f504c053eaa10a7d'
HOST = 'chatops@100.121.130.51'
SSH_OPTIONS = (
    'HostName=100.121.130.51', 'User=chatops', 'Port=22', 'BatchMode=yes', 'ConnectTimeout=10',
    'StrictHostKeyChecking=yes', 'UpdateHostKeys=no',
    'UserKnownHostsFile=/Users/daniel/.ssh/known_hosts', 'GlobalKnownHostsFile=/dev/null',
    'KnownHostsCommand=none', 'HostKeyAlias=100.121.130.51', 'CanonicalizeHostname=no',
    'ProxyCommand=none', 'ProxyJump=none', 'PermitLocalCommand=no', 'RemoteCommand=none',
    'IdentityFile=/Users/daniel/.ssh/id_ed25519',
    'IdentityAgent=none', 'IdentitiesOnly=yes', 'CertificateFile=none',
    'PreferredAuthentications=publickey', 'PasswordAuthentication=no',
    'KbdInteractiveAuthentication=no', 'GSSAPIAuthentication=no', 'HostbasedAuthentication=no',
    'ControlMaster=no', 'ControlPath=none', 'ForwardAgent=no', 'ClearAllForwardings=yes')


def ssh_argv(remote):
    # -F also excludes system-wide ssh_config. No user Include/Match, proxy,
    # alternate endpoint, external known-host command or agent can receive the
    # sudo password/private packet. Existing key/trust store, no enrollment.
    return ['/usr/bin/ssh', '-F', '/dev/null', '-T',
            *[part for option in SSH_OPTIONS for part in ('-o', option)], HOST, remote]


def git(root, *args):
    return subprocess.check_output(['/usr/bin/git', '--no-optional-locks', '--no-replace-objects',
                                    '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-C', str(root), *args],
                                   stderr=subprocess.DEVNULL)


def source_package(infra, control, release):
    io.require(set(release) == {'schema', 'infra', 'control', 'files', 'gate_evidence_sha256'} and
               release['schema'] == 'TU1NZ_PUBLIC_OPERATOR_RELEASE_V1', 'RELEASE_SCHEMA')
    data = {}; expected_files = {}
    for role, root, paths in (('infra', infra, INFRA_FILES), ('control', control, CONTROL_FILES)):
        record = release[role]
        io.require(set(record) == {'merge', 'tree', 'reviewed_head', 'pr', 'ci', 'post_ci', 'review_evidence_sha256'},
                   'RELEASE_REPOSITORY_SCHEMA')
        io.require(all(type(record[k]) is str and re.fullmatch('[a-f0-9]{40}', record[k])
                       for k in ('merge', 'tree', 'reviewed_head')) and
                   re.fullmatch('[a-f0-9]{64}', record['review_evidence_sha256'] or '') and
                   all(type(record[k]) is int and record[k] > 0 for k in ('pr', 'ci', 'post_ci')),
                   'RELEASE_GATE_BINDING_FORMAT')
        io.require(git(root, 'rev-parse', 'HEAD').decode().strip() == record['merge'] and
                   git(root, 'rev-parse', 'HEAD^{tree}').decode().strip() == record['tree'] and
                   git(root, 'rev-parse', record['reviewed_head']+'^{tree}').decode().strip() == record['tree'] and
                   not git(root, 'status', '--porcelain', '--untracked-files=all'), 'RELEASE_CHECKOUT_DRIFT')
        origin = git(root, 'remote', 'get-url', 'origin').decode().strip()
        io.require(origin in ('https://github.com/Tausendunde1nz/'+role+'.git',
                             'git@github.com:Tausendunde1nz/'+role+'.git',
                             'https://github.com/Tausendunde1nz/'+role), 'RELEASE_ORIGIN')
        for name, path in paths.items():
            raw = git(root, 'show', record['merge']+':'+path)
            io.require((root/path).read_bytes() == raw and not (root/path).is_symlink(), 'SOURCE_WORKTREE_DRIFT')
            data[name] = raw; expected_files[name] = io.sha(raw)
    io.require(expected_files == release['files'], 'RELEASE_EXACT_MEMBER_HASHES')
    io.require(all(expected_files[k] == h for k, h in io.CONTROL_PINS.items()) and
               all(expected_files[k] == h for k, h in io.ASSETS.items()), 'OLD_COMPONENT_BYTES_CHANGED')
    return {n: base64.b64encode(raw).decode() for n, raw in data.items()}, expected_files


def application_reference(root, baseline):
    """Authenticate tracked expected bytes from canonical immutable Git, not
    the reference checkout's HEAD/worktree or a current Host inventory.

    The separate already-authenticated artifact origin for installed/untracked
    runtime dependencies remains explicit in the independently approved scope.
    This function never creates that origin from current server bytes.
    """
    reference = baseline['source_release']['runtime_reference']
    replacing=reference.get('schema')=='TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1'
    if replacing:
        value=reference['artifact']
        reference={'commit':value['application']['commit'],'tree':value['application']['tree'],
                   'origin_sha256':reference['origin_sha256'],
                   'objects':{k[4:]:{f:v for f,v in row.items() if f in ('kind','sha256','target')}
                              for k,row in value['objects'].items() if k.startswith('app/')}}
    commit = '93555d8a141caf8ace33522f9340d30bfc47d2bb'
    tree = '1e8a644115127818f394b6f9d24f31826e04ecba'
    io.require((reference['commit'], reference['tree']) == (commit, tree) and
               reference['origin_sha256'] in baseline['source_origin_receipts'], 'APPLICATION_REFERENCE_BINDING')
    origin = git(root, 'remote', 'get-url', 'origin').decode().strip()
    io.require(origin in ('https://github.com/Tausendunde1nz/adult-publishing-core.git',
                          'https://github.com/Tausendunde1nz/adult-publishing-core',
                          'git@github.com:Tausendunde1nz/adult-publishing-core.git') and
               git(root, 'rev-parse', commit+'^{tree}').decode().strip() == tree,
               'APPLICATION_CANONICAL_ORIGIN_OR_TREE')
    for raw in git(root, 'ls-tree', '-r', '-z', commit).split(b'\0'):
        if not raw: continue
        head, path = raw.split(b'\t', 1); mode, kind, blob = head.split(); name = path.decode()
        io.require(kind == b'blob' and mode in (b'100644', b'100755', b'120000'), 'APPLICATION_TREE_OBJECT')
        body = git(root, 'cat-file', 'blob', blob.decode())
        expected = ({'kind': 'link', 'target': body.decode()} if mode == b'120000' else
                    {'kind': 'file', 'sha256': io.sha(body)})
        io.require(reference['objects'].get(name) == expected, 'APPLICATION_TRACKED_BYTE_DRIFT')


def reference_origins(paths, baseline, scope=None):
    """Material readback of independently bound reference receipts.

    Hash identity does NOT itself prove the receipt's historical assertions.
    The independent approved scope must select verified existing evidence;
    neither this code nor a current server scan can create that trust.
    """
    actual = {}
    for path in paths:
        raw = io.private_read(path)
        io.require(raw and io.sha(raw) not in actual, 'ORIGIN_EMPTY_OR_DUPLICATED')
        actual[io.sha(raw)] = raw
    io.require(set(actual) == set(baseline['source_origin_receipts']), 'REFERENCE_ORIGIN_EVIDENCE_MISSING')
    prospective = io.prospective_binding(scope or {}, baseline, actual)
    runtime = baseline['source_release']['runtime_reference']
    origin = io.parse(actual[runtime['origin_sha256']])
    if runtime.get('schema')=='TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1':
        io.require(origin==runtime['artifact'],'REPLACEMENT_ARTIFACT_ORIGIN_BYTES')
        return prospective  # Never relabel an old installation receipt.
    io.require(set(origin) == {'schema', 'application_commit', 'application_tree', 'runtime_objects_sha256',
                              'prior_evidence_sha256'} and origin['schema'] == 'TU1NZ_PUBLIC_RUNTIME_ORIGIN_V1' and
               (origin['application_commit'], origin['application_tree']) == (runtime['commit'], runtime['tree']) and
               origin['runtime_objects_sha256'] == io.sha(io.canonical(runtime['objects'])) and
               type(origin['prior_evidence_sha256']) is list and origin['prior_evidence_sha256'] and
               set(origin['prior_evidence_sha256']) <= set(actual)-{runtime['origin_sha256']},
               'RUNTIME_ORIGIN_CONTENT_OR_PRIOR_EVIDENCE_UNBOUND')
    return prospective


def validate_scope(scope, baseline, baseline_raw, plan_raw, release_raw):
    io.replacement_scope(scope,baseline)
    io.require(scope['release_sha256'] == io.sha(release_raw) and
               scope['baseline_sha256'] == io.sha(baseline_raw) and
               scope['administrative_roles_sha256'] == io.sha(io.canonical(baseline['actors'])) and
               scope['baseline_origins_sha256'] == io.sha(io.canonical(baseline['source_origin_receipts'])) and
               scope['r3_approval_sha256'] == APPROVAL and
               scope['machine_sha256'] == baseline['machine_sha256'] and
               scope['transaction'] == 'public-rights-20261014-1' and
               scope['owner_plan_sha256'] == io.sha(plan_raw), 'APPROVED_SCOPE_BINDING')
    # Caller must supply an INDEPENDENTLY approved scope hash. This program
    # neither generates an approval nor accepts a passed/closed/trusted flag.


class Client:
    def __init__(self, wire, r3, binding, *, http_expectations, owner_hold_before=None, runtime_payload=None,
                 admission_packet=None):
        self.wire, self.r, self.binding = wire, r3, binding
        self.journal = None; self.fd = None; self.records = {}; self.last = binding; self.sequence = 0
        self.http_expectations = http_expectations
        self.owner_hold_before = owner_hold_before
        self.runtime_payload=runtime_payload;self.runtime_next=0
        self.runtime_payload_sha256=io.sha(runtime_payload) if runtime_payload is not None else None
        self.admission_packet=admission_packet

    def admission_current(self):
        if self.admission_packet is not None:io.prospective_packet_material(self.admission_packet)

    def initialize(self):
        parent = self.r.CUSTODY_PARENT
        # Only the compiled local parent, no caller-selected replacement slot.
        if not parent.exists():
            io.require(parent.parent.resolve(strict=True) == parent.parent and
                       parent.parent.stat().st_uid == os.geteuid(), 'CUSTODY_EXISTING_PARENT')
            parent.mkdir(mode=0o700)
        self.journal = self.r.Journal(parent, self.binding)
        os.mkdir('operator-records', 0o700, dir_fd=self.journal.fd)
        self.fd = os.open('operator-records', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=self.journal.fd)

    def check(self):
        io.require(self.journal is not None, 'CLIENT_NOT_CLAIMED')
        self.journal.check()
        for name, raw in self.records.items():
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
            try:
                io.require(os.read(fd, len(raw)+1) == raw, 'CLIENT_RECORD_CHANGED')
            finally:
                os.close(fd)
        self.journal.check()
        self.check_extra()

    def check_extra(self):
        pass

    def project_record(self, row):
        if row['kind'] == 'flow_claim':
            self.admission_current(); self.journal.claim()
        elif row['kind'].startswith('flow_'):
            self.journal.write(row['kind'][5:], row['value'])

    def extension_message(self, message):
        return False

    def serve(self):
        while True:
            message = self.wire.receive(); kind = message.get('type')
            if self.extension_message(message):continue
            if kind == 'prepared':
                io.require(set(message) == {'type', 'binding'} and message['binding'] == self.binding and
                           self.journal is None, 'PREPARED_BINDING_OR_REPLAY')
                self.admission_current()
                self.initialize()
                self.wire.send({'type': 'client_custody_created', 'binding': self.binding})
            elif kind == 'durable_record':
                self.check(); row = message['record']; raw = io.canonical(row)
                io.require(row['binding'] == self.binding and row['previous'] == self.last and
                           row['sequence'] == self.sequence+1 and io.sha(raw) == message['sha256'],
                           'HASH_LINK_OR_SEQUENCE_RED')
                name = str(row['sequence']).zfill(3)+'-'+row['kind']+'.json'
                io.exclusive(self.fd, name, raw); self.records[name] = raw
                self.project_record(row)
                self.last = message['sha256']; self.sequence = row['sequence']; self.check()
                ack = {'type': 'persisted', 'sequence': self.sequence, 'sha256': self.last}
                if row['kind'] == 'owner_object_intent' and row['value']['relative'] == self.owner_hold_before:
                    ack['control'] = 'HOLD_BEFORE_OWNER_EFFECT'
                self.wire.send(ack)
            elif kind == 'custody_check':
                self.check()
                io.require(message == {'type': kind, 'sequence': self.sequence, 'sha256': self.last}, 'CUSTODY_CHAIN_RED')
                self.wire.send({'type': 'custody_current', 'sequence': self.sequence, 'sha256': self.last})
            elif kind == 'http_read':
                endpoint = message['endpoint']
                io.require(endpoint in self.http_expectations, 'HTTP_NOT_IN_APPROVED_BASELINE')
                self.wire.send(io.measured_http(endpoint, deadline=self.wire.deadline, location='client'))
            elif kind == 'runtime_chunk_request':
                self.check()
                self.send_runtime_chunk(message)
            elif kind == 'held':
                # Explicit surviving-session decision only. EOF, no TTY, lost
                # confirmation, interruption or deadline defaults to HOLD.
                self.check()
                io.exclusive(self.fd, 'held.json', io.canonical(message))
                answer = 'HOLD'
                if sys.stdin.isatty():
                    choices = [value for key, value in (('return_available', 'RETURN_OLD'),
                                                       ('owner_return_available', 'OWNER_RETURN')) if message.get(key)]
                    if choices:
                        print('HOLD bleibt Standard; expliziter einmaliger Rückweg '+ '/'.join(choices)+': ',
                              end='', flush=True)
                        remaining = min(20, self.wire.deadline-time.monotonic(), message.get('decision_seconds', 0))
                        if remaining > 0 and select.select([sys.stdin], [], [], remaining)[0]:
                            typed = sys.stdin.readline().rstrip('\n')
                            if typed in choices: answer = typed
                self.wire.send({'type': 'decision', 'value': answer})
            elif kind == 'final':
                if self.journal is not None:
                    self.check(); io.exclusive(self.fd, 'final.json', io.canonical(message))
                return message
            else:
                raise io.Hold('PUBLIC_OPERATOR_PROTOCOL_MESSAGE_UNKNOWN')

    def send_runtime_chunk(self,message):
        # The session calls check() before this pure bounded transport step.
        # Supplying bytes is not an admission, effect, claim or ACK repair.
        io.require(self.runtime_payload is not None and
            set(message)=={'type','index','archive_sha256'} and type(message['index']) is int and
            message['index']==self.runtime_next and message['archive_sha256']==self.runtime_payload_sha256,
            'RUNTIME_CHUNK_NOT_BOUND_OR_REPLAY')
        offset=self.runtime_next*512*1024
        data=self.runtime_payload[offset:offset+512*1024]
        io.require(data,'RUNTIME_CHUNK_OUTSIDE_BOUND')
        self.runtime_next+=1  # Consume before send; lost output cannot be retried.
        self.wire.send({'type':'runtime_chunk','index':message['index'],
                        'data':base64.b64encode(data).decode()})

    def close(self):
        if self.fd is not None: os.close(self.fd); self.fd = None
        if self.journal is not None: self.journal.close(); self.journal = None


class MaintenanceClient(Client):
    """Fixed original-TX owner marker before its ACK, with continuous readback.

    Selected only by the new reviewed R4 session, never by a legacy scope.
    Recovery's client must override owner_marker_parent() to its independently
    held original TX root; this class never accepts a marker path from JSON.
    """
    def __init__(self, wire, r3, binding, *, boot_id, **kwargs):
        super().__init__(wire, r3, binding, **kwargs)
        self.original_binding = binding; self.boot_id = boot_id; self.route = 'original'
        self.ready_sha256 = None; self.owner_marker = None; self.owner_marker_identity = None

    def owner_marker_parent(self):
        self.journal.check()
        return self.journal.fd

    @staticmethod
    def marker_identity(row):
        return tuple(getattr(row, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode',
                                             'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

    def project_record(self, row):
        kind, value = row['kind'], row['value']
        if kind == 'maintenance_ready':
            io.require(self.route == 'original' and self.ready_sha256 is None and
                       type(value) is dict and type(value.get('ready')) is dict,
                       'CLIENT_READY_SEQUENCE')
            ready = value['ready']
            io.require(ready.get('schema') == 'TU1NZ_MAIN_SERVER_REV4_20261104' and
                       ready.get('transaction') == self.r.TX and ready.get('machine') == self.r.MACHINE and
                       ready.get('boot_id') == self.boot_id and ready.get('owner_plan_sha256') == self.r.OWNER_PLAN and
                       type(ready.get('inputs')) is dict and ready['inputs'].get('scope_sha256') == self.original_binding and
                       value.get('sha256') == io.sha(io.canonical(ready)), 'CLIENT_READY_BINDING')
            self.ready_sha256 = value['sha256']
        elif kind == 'owner_admission_intent':
            io.require(self.ready_sha256 is not None and self.owner_marker is None,
                       'CLIENT_OWNER_ENTRY_NOT_READY_OR_REPLAY')
            expected = io.owner_entry_marker(original_binding=self.original_binding, execution_binding=self.binding,
                ready_sha256=self.ready_sha256, boot_id=self.boot_id, route=self.route)
            prior = [io.parse(raw) for raw in self.records.values()]
            claim = 'flow_claim' if self.route == 'original' else 'recovery_flow_claim'
            io.require(value == expected and sum(v['kind'] == claim for v in prior) == 1 and
                       not any(v['kind'].startswith('owner_') and v['sequence'] != row['sequence'] for v in prior),
                       'CLIENT_OWNER_ENTRY_BINDING_OR_PRIOR_ADMISSION')
            parent = self.owner_marker_parent(); raw = io.canonical(expected)
            io.exclusive(parent, 'owner-admission-intent', raw)
            actual = os.stat('owner-admission-intent', dir_fd=parent, follow_symlinks=False)
            io.require(stat.S_ISREG(actual.st_mode) and actual.st_nlink == 1 and
                       actual.st_uid == os.geteuid() and stat.S_IMODE(actual.st_mode) == 0o600,
                       'CLIENT_OWNER_MARKER_PROFILE')
            self.owner_marker_identity = self.marker_identity(actual); self.owner_marker = raw
            self.check_extra()
        elif kind == 'owner_admission_markers_confirmed':
            io.require(self.owner_marker is not None and type(value) is dict and
                       value.get('sha256') == io.sha(self.owner_marker), 'CLIENT_OWNER_HOST_MARKER_UNCONFIRMED')
            self.check_extra()
        super().project_record(row)

    def check_extra(self):
        if self.owner_marker is None:return
        parent = self.owner_marker_parent()
        fd = os.open('owner-admission-intent', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = self.marker_identity(os.fstat(fd))
            raw = os.pread(fd, len(self.owner_marker)+1, 0)
            after = self.marker_identity(os.fstat(fd))
            named = self.marker_identity(os.stat('owner-admission-intent', dir_fd=parent, follow_symlinks=False))
            io.require(before == after == named == self.owner_marker_identity and raw == self.owner_marker,
                       'CLIENT_OWNER_MARKER_CHANGED')
        finally:os.close(fd)


class RecoveryCustody:
    """One additive fixed Mac entry; original files are always read-only.

    Construct after local material validation, BEFORE the new SSH attempt.
    Any partial creation/transport/admission failure leaves this directory
    occupied. close() closes only owned FDs; it never deletes or resets it.
    The original root FD is retained separately for K6's first owner marker.
    """
    def __init__(self, r3, original_binding, *, boot_id, source_sha256, deadline):
        self.r, self.original_binding, self.deadline = r3, original_binding, deadline
        self.parent_fd = self.original_fd = self.original_records_fd = self.fd = None
        self.binding = None; self.seq = 0; self.claimed = False; self.files = {}
        self.parent_path = r3.CUSTODY_PARENT
        io.require(self.parent_path == Path('/Users/daniel/Developer/tu1nz/service-isolation-lighting-night-20261013/host-operator-intents') and
                   self.parent_path.resolve(strict=True) == self.parent_path and
                   r3.TX == 'public-rights-20261014-1', 'RECOVERY_FIXED_MAC_CUSTODY')
        try:
            self.parent_fd = os.open(self.parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.parent_identity = self.directory_identity(self.parent_fd)
            self.original_fd = os.open(r3.TX, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                       dir_fd=self.parent_fd)
            self.original_identity = self.directory_identity(self.original_fd)
            self.original_files = self.read_original_root()
            self.original_records_fd = os.open('operator-records', os.O_RDONLY | os.O_DIRECTORY |
                                               os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.original_fd)
            self.original_records_identity = self.directory_identity(self.original_records_fd)
            self.snapshot = io.read_original_chain(self.original_records_fd, original_binding,
                owner=os.geteuid(), deadline=deadline, client_supplements=True)
            ready = [v['record']['value'] for v in self.snapshot['records']
                     if v['record']['kind'] == 'maintenance_ready']
            io.require(len(ready) == 1 and type(ready[0]) is dict, 'RECOVERY_MAC_READY_MISSING')
            self.ready_sha256 = ready[0]['sha256']
            io.original_chain_pair(self.snapshot, self.snapshot, binding=original_binding,
                                   ready_sha256=self.ready_sha256)
            actual_ready = self.ready = ready[0]['ready']
            io.require(actual_ready['boot_id'] == boot_id and
                       actual_ready['inputs']['scope_sha256'] == original_binding and
                       actual_ready['inputs']['source_sha256'] == source_sha256,
                       'RECOVERY_MAC_READY_SOURCE_OR_BOOT_CHANGED')
            self.manifest = io.original_chain_manifest(self.snapshot)
            self.entry = io.recovery_entry(original_binding, boot_id, source_sha256,
                                          self.manifest['snapshot_sha256'], self.ready_sha256)
            self.entry_raw = io.canonical(self.entry)
            self.check_original()
            # EEXIST and a partially written entry are both terminal. This
            # call is never wrapped in a retry or alternate-name fallback.
            os.mkdir('recovery-once', 0o700, dir_fd=self.original_fd)
            os.fsync(self.original_fd)
            self.fd = os.open('recovery-once', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=self.original_fd)
            self.identity = self.directory_identity(self.fd)
            io.exclusive(self.fd, 'entry.json', self.entry_raw)
            self.files['entry.json'] = self.read_file(self.fd, 'entry.json')
            self.check()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def directory_identity(fd):
        row = os.fstat(fd)
        io.require(stat.S_ISDIR(row.st_mode) and row.st_uid == os.geteuid() and
                   stat.S_IMODE(row.st_mode) == 0o700, 'RECOVERY_MAC_DIRECTORY_PROFILE')
        return (row.st_dev, row.st_ino, row.st_uid, row.st_gid, row.st_mode)

    @staticmethod
    def read_file(parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            first = os.fstat(fd)
            io.require(stat.S_ISREG(first.st_mode) and first.st_uid == os.geteuid() and first.st_nlink == 1 and
                       stat.S_IMODE(first.st_mode) == 0o600 and 0 < first.st_size <= 65536,
                       'RECOVERY_MAC_RECORD_PROFILE')
            raw = os.pread(fd, first.st_size+1, 0)
            identity = MaintenanceClient.marker_identity(first)
            io.require(len(raw) == first.st_size and identity == MaintenanceClient.marker_identity(os.fstat(fd)) ==
                       MaintenanceClient.marker_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                       'RECOVERY_MAC_RECORD_CHANGED')
            return {'identity': identity, 'sha256': io.sha(raw), 'raw': raw}
        finally:os.close(fd)

    def read_original_root(self):
        names = set(os.listdir(self.original_fd))
        if self.fd is not None:names.discard('recovery-once')
        # K6 creates this one additive marker later; its full bytes/identity
        # are then checked by MaintenanceClient before any ACK/effect.
        if getattr(self, 'owner_marker_allowed', False):names.discard('owner-admission-intent')
        io.require('operator-records' in names and 'flow-claimed' in names and len(names) <= 130 and
                   all(n in ('operator-records', 'flow-claimed') or
                       re.fullmatch('[0-9]{3}-[a-z_]+[.]json', n) for n in names),
                   'RECOVERY_ORIGINAL_ROOT_NAMES_OR_PRIOR_ENTRY')
        rows = {n:self.read_file(self.original_fd, n) for n in sorted(names) if n != 'operator-records'}
        io.require(rows['flow-claimed']['raw'] == self.original_binding.encode(), 'RECOVERY_ORIGINAL_MAC_CLAIM')
        return rows

    def check_original(self):
        io.require(time.monotonic() < self.deadline, 'RECOVERY_MAC_CUSTODY_DEADLINE')
        for parent, name, fd, expected in (
                (None, self.parent_path, self.parent_fd, self.parent_identity),
                (self.parent_fd, self.r.TX, self.original_fd, self.original_identity),
                (self.original_fd, 'operator-records', self.original_records_fd, self.original_records_identity)):
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            actual = (named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode)
            io.require(actual == expected == self.directory_identity(fd), 'RECOVERY_MAC_ORIGINAL_DIRECTORY_REPLACED')
        io.require(self.read_original_root() == self.original_files and
                   io.read_original_chain(self.original_records_fd, self.original_binding, owner=os.geteuid(),
                       deadline=self.deadline, client_supplements=True) == self.snapshot,
                   'RECOVERY_MAC_ORIGINAL_HISTORY_CHANGED')

    def check(self):
        self.check_original()
        named = os.stat('recovery-once', dir_fd=self.original_fd, follow_symlinks=False)
        io.require((named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode) ==
                   self.identity == self.directory_identity(self.fd), 'RECOVERY_MAC_ENTRY_DIRECTORY_REPLACED')
        expected = set(self.files) | ({'operator-records'} if self.binding is not None else set())
        io.require(set(os.listdir(self.fd)) == expected and all(self.read_file(self.fd,n) == v for n,v in self.files.items()),
                   'RECOVERY_MAC_ENTRY_OR_FLOW_CHANGED')

    def bind(self, seed):
        self.check(); io.require(self.binding is None, 'RECOVERY_MAC_BINDING_NO_REPLAY')
        binding = io.recovery_binding(seed)
        io.require(all(seed[k] == self.entry[k] for k in
                       ('original_binding', 'ready_sha256', 'source_sha256', 'boot_id')) and
                   seed['mac_tail_sha256'] == self.snapshot['tail'] and
                   seed['artifact_sha256'] == self.ready['artifact_sha256'], 'RECOVERY_MAC_FRESH_BINDING_DRIFT')
        expected_host_tail = self.snapshot['tail']
        if seed['unconfirmed_mac_tail'] is not None:
            io.require(len(self.snapshot['records']) >= 2, 'RECOVERY_MAC_NO_CONFIRMED_PREFIX')
            expected_host_tail = self.snapshot['records'][-2]['sha256']
        io.require(seed['host_tail_sha256'] == expected_host_tail, 'RECOVERY_MAC_HOST_TAIL_NOT_PREFIX')
        os.mkdir('operator-records', 0o700, dir_fd=self.fd); os.fsync(self.fd)
        self.binding = binding
        self.check()

    def claim(self):
        self.check(); io.require(self.binding is not None and not self.claimed, 'RECOVERY_MAC_FLOW_NO_REPLAY')
        self.claimed = True
        io.exclusive(self.fd, 'flow-claimed', self.binding.encode())
        self.files['flow-claimed'] = self.read_file(self.fd, 'flow-claimed'); self.check()

    def write(self, kind, value):
        self.check()
        io.require(self.claimed and self.seq < 128 and kind in ('claim', 'observation', 'intent', 'ack', 'hold', 'complete'),
                   'RECOVERY_MAC_FLOW_BOUND')
        self.seq += 1
        name = str(self.seq).zfill(3)+'-'+kind+'.json'
        raw = io.canonical({'sequence': self.seq, 'kind': kind, 'binding': self.binding, 'value': value})
        io.require(len(raw) <= 65536, 'RECOVERY_MAC_FLOW_RECORD_BOUND')
        io.exclusive(self.fd, name, raw); self.files[name] = self.read_file(self.fd, name); self.check()

    def close(self):
        errors = []
        for name in ('original_records_fd', 'original_fd', 'parent_fd', 'fd'):
            fd = getattr(self, name, None)
            if fd is not None:
                try:os.close(fd)
                except OSError:errors.append(name)
                setattr(self, name, None)
        io.require(not errors, 'RECOVERY_MAC_DESCRIPTOR_CLOSE_UNKNOWN')


class RecoveryClient(MaintenanceClient):
    def __init__(self, wire, r3, custody, *, http_expectations, owner_hold_before=None):
        io.require(isinstance(custody, RecoveryCustody) and custody.binding is None and custody.fd is not None,
                   'RECOVERY_CLIENT_EXISTING_ENTRY_REQUIRED')
        super().__init__(wire, r3, custody.original_binding, boot_id=custody.entry['boot_id'],
                         http_expectations=http_expectations, owner_hold_before=owner_hold_before)
        self.custody = custody; self.route = 'recovery-once'; self.ready_sha256 = custody.ready_sha256
        self.recovery_seed = None; self.admission_open = True

    def initialize(self):
        raise io.Hold('PUBLIC_OPERATOR_RECOVERY_ORIGINAL_INITIALIZER_FORBIDDEN')

    def owner_marker_parent(self):
        self.custody.check()
        self.custody.owner_marker_allowed = True
        return self.custody.original_fd

    def project_record(self, row):
        kind, value = row['kind'], row['value']
        io.require(kind not in ('flow_claim', 'flow_complete', 'maintenance_ready', 'prestate_read_witness') and
                   not kind.startswith('flow_'), 'RECOVERY_CLIENT_ORIGINAL_RECORD_FORBIDDEN')
        if row['sequence'] == 1:
            io.require(kind == 'recovery_context' and value == self.recovery_seed, 'RECOVERY_CLIENT_FIRST_CONTEXT')
        else:io.require(kind != 'recovery_context', 'RECOVERY_CLIENT_CONTEXT_NO_REPLAY')
        if row['sequence'] == 2:
            io.require(kind == 'recovery_state_observation' and
                       io.sha(io.canonical(value)) == self.recovery_seed['fresh_state_sha256'],
                       'RECOVERY_CLIENT_FRESH_STATE_REQUIRED')
            self.admission_open = False
        elif row['sequence'] > 2:
            io.require(not self.admission_open, 'RECOVERY_CLIENT_EFFECT_BEFORE_CURRENT_STATE')
        if kind == 'recovery_flow_claim':self.custody.claim()
        if kind.startswith('recovery_flow_'):self.custody.write(kind[len('recovery_flow_'):], value)
        super().project_record(row)

    def extension_message(self, message):
        kind = message.get('type')
        io.require(kind not in ('prepared', 'runtime_chunk_request'), 'RECOVERY_CLIENT_ORIGINAL_PROTOCOL_FORBIDDEN')
        if kind == 'recovery_admission_check':
            io.require(self.admission_open and message == {'type': kind,
                'original_binding': self.original_binding, 'entry_sha256': io.sha(self.custody.entry_raw),
                'mac_snapshot_sha256': self.custody.manifest['snapshot_sha256']}, 'RECOVERY_CLIENT_ADMISSION_BINDING')
            self.custody.check(); self.wire.send({**message, 'type': 'recovery_admission_current'})
            return True
        if kind == 'recovery_prepared':
            io.require(self.journal is None and set(message) == {'type', 'seed', 'fresh_state', 'original_failure'},
                       'RECOVERY_CLIENT_PREPARED_SCHEMA')
            seed = message['seed']
            io.require(seed['fresh_state_sha256'] == io.sha(io.canonical(message['fresh_state'])) and
                       seed['original_failure_sha256'] == io.sha(io.canonical(message['original_failure'])),
                       'RECOVERY_CLIENT_CURRENT_OBSERVATION_HASH')
            self.custody.bind(seed); self.recovery_seed = io.parse(io.canonical(seed))
            self.binding = self.last = self.custody.binding; self.journal = self.custody
            self.fd = os.open('operator-records', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=self.custody.fd)
            self.check()
            self.wire.send({'type': 'recovery_custody_bound', 'binding': self.binding})
            return True
        if kind == 'held':
            io.require(message.get('return_available') is False, 'RECOVERY_CLIENT_OLD_RETURN_FORBIDDEN')
        if kind == 'final' and self.journal is None:
            self.custody.check()
            raw = io.canonical(message); io.require(len(raw) <= 65536, 'RECOVERY_CLIENT_ADMISSION_RESULT_BOUND')
            io.exclusive(self.custody.fd, 'admission-final.json', raw)
            self.custody.files['admission-final.json'] = self.custody.read_file(self.custody.fd, 'admission-final.json')
            self.custody.check()
        return False

    def close(self):
        try:super().close()
        finally:self.custody.close()


def bootstrap(io_raw):
    # This exact source is in the authenticated SSH command; secret/private
    # input is sent only AFTER sudo exec and the ready frame, never argv.
    encoded = base64.b64encode(io_raw).decode()
    return ('import base64,hashlib,os,sys,time,types\n'
            'raw=base64.b64decode('+repr(encoded)+')\n'
            'assert hashlib.sha256(raw).hexdigest()=='+repr(io.sha(io_raw))+'\n'
            'm=types.ModuleType("tu1nz_public_operator_io");sys.modules[m.__name__]=m\n'
            'exec(compile(raw,"<authenticated-operator-io>","exec"),m.__dict__)\n'
            'w=m.Wire(0,1,deadline=time.monotonic()+600)\n'
            'w.send({"type":"ready","io_sha256":hashlib.sha256(raw).hexdigest()})\n'
            'p=w.receive()\n'
            's=m.Source(p["source"],p["hashes"])\n'
            'for n in ("io","entry","guard","owner","r3","fs","runtime_guard","observe","probes","host"):s.load(n)\n'
            's.load("host").session(s,p,w)\n')


def preparation_records(binding):
    roots = [Path('/Users/daniel/Developer/tu1nz/public-production-source-r4-20261016'),
             Path('/Users/daniel/.codex/backups/public-production-source-r4-20261016')]
    targets = []; descriptors = []
    for root in roots:
        st = root.stat()
        io.require(root.resolve(strict=True) == root and st.st_uid == os.geteuid() and
                   st.st_mode & 0o777 == 0o700, 'PRIVATE_PREPARATION_ROOT')
        target = root/('execute-read-'+binding)
        io.require(not os.path.lexists(target), 'PREPARATION_OCCUPIED_NO_ADOPTION')
        targets.append(target)
    try:
        for target in targets:
            target.mkdir(mode=0o700)
            descriptors.append(os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
        for fd in descriptors:
            io.exclusive(fd, 'intent.json', io.canonical({'binding': binding, 'host_effects': 'NOT_REQUESTED',
                                                        'is_transaction_permission': False}))
        code = ('from pathlib import Path;import sys;'
                'a,b=[Path(x).read_bytes() for x in sys.argv[1:]];assert a==b and a')
        checked = subprocess.run([sys.executable, '-I', '-B', '-c', code,
                                  *[str(p/'intent.json') for p in targets]], capture_output=True, timeout=10)
        io.require(checked.returncode == 0, 'PREPARATION_INDEPENDENT_READBACK')
        return targets, descriptors
    except BaseException as error:
        cleanup = []
        for fd in descriptors:
            try: io.exclusive(fd, 'preparation-failed.json', io.canonical({'host_dispatched': False, 'slot_consumed': False}))
            except BaseException: cleanup.append('PUBLIC_BOOTSTRAP_PREPARATION_FAILURE_RECORD_UNKNOWN')
            finally:
                try: os.close(fd)
                except OSError: cleanup.append('PUBLIC_BOOTSTRAP_PREPARATION_DESCRIPTOR_CLOSE_UNKNOWN')
        error.client_cleanup = cleanup
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--infra', type=Path, required=True); parser.add_argument('--control', type=Path, required=True)
    parser.add_argument('--release', type=Path, required=True); parser.add_argument('--release-sha256', required=True)
    parser.add_argument('--scope', type=Path, required=True); parser.add_argument('--approved-scope-sha256', required=True)
    parser.add_argument('--baseline', type=Path, required=True); parser.add_argument('--owner-plan', type=Path, required=True)
    parser.add_argument('--application-reference', type=Path,
                        default=Path('/Users/daniel/Developer/tu1nz/s8-atomic-source.r1'))
    parser.add_argument('--origin', type=Path, action='append', required=True,
                        help='private pre-existing reference evidence, one file for EACH bound origin hash')
    parser.add_argument('--execute', action='store_true', help='explicit Host execution; absent = LOCAL validation only')
    parser.add_argument('--runtime-archive',type=Path,help='R5 private artifact; old scopes cannot use this option')
    parser.add_argument('--runtime-input-cache',type=Path,help='R5 pinned upstream bytes for deterministic local verification')
    parser.add_argument('--hold-owner-before', help='DENY before this exact owner object; no extra permission or retry')
    args = parser.parse_args()
    io.require(Path.cwd().resolve() == args.infra.resolve(), 'ACTUAL_INFRA_CWD_REQUIRED')
    preflight = subprocess.run(['/opt/homebrew/bin/python3.12',
        '/Users/daniel/Developer/tu1nz/control-governance-v1.1/governance/preflight.py', '--cwd', str(Path.cwd())],
        capture_output=True, timeout=20)
    io.require(preflight.returncode == 0 and b'GOVERNANCE_V1_1_ACTIVE' in preflight.stdout,
               'CANONICAL_LOCAL_GOVERNANCE_RED')
    io.require(all(re.fullmatch('[a-f0-9]{64}', h) for h in
                   (args.release_sha256, args.approved_scope_sha256)), 'INDEPENDENT_HASH_FORMAT')
    release_raw = io.private_read(args.release); scope_raw = io.private_read(args.scope)
    baseline_raw = io.private_read(args.baseline); plan_raw = io.private_read(args.owner_plan)
    io.require(io.sha(release_raw) == args.release_sha256 and io.sha(scope_raw) == args.approved_scope_sha256,
               'INDEPENDENT_RELEASE_OR_SCOPE_HASH')
    scope, baseline = io.parse(scope_raw), io.parse(baseline_raw)
    validate_scope(scope, baseline, baseline_raw, plan_raw, release_raw)
    prospective = reference_origins(args.origin, baseline, scope)
    application_reference(args.application_reference, baseline)
    encoded, hashes = source_package(args.infra, args.control, io.parse(release_raw))
    source = io.Source(encoded, hashes); r3 = source.load('r3')
    replacing=io.replacement_scope(scope,baseline);runtime_payload=None
    if replacing:
        io.require(args.runtime_archive is not None and args.runtime_input_cache is not None,
                   'REPLACEMENT_MATERIAL_REQUIRED')
        builder=source.load('artifact')
        inputs=io.parse(source.bytes['runtime_inputs'])
        runtime=baseline['source_release']['runtime_reference']['artifact']
        builder.validate_receipt(runtime,inputs)
        runtime_payload=builder.private_read(args.runtime_archive)
        python_raw=builder.private_read(args.runtime_input_cache/inputs['python']['filename'])
        wheels={w['filename']:builder.private_read(args.runtime_input_cache/w['filename']) for w in inputs['wheels']}
        rebuilt,receipt=builder.assemble(builder.git_source(args.application_reference),python_raw,wheels,inputs)
        io.require(rebuilt==runtime_payload and builder.canonical(receipt)==builder.canonical(runtime),
                   'REPLACEMENT_OFFLINE_REBUILD_BINDING')
        builder.inspect_archive(runtime_payload,runtime)
    else:
        io.require(args.runtime_archive is None and args.runtime_input_cache is None,'REPLACEMENT_NOT_AUTHORIZED_BY_OLD_SCOPE')
    io.require(args.hold_owner_before is None or args.hold_owner_before in
               {a['relative'] for a in io.parse(plan_raw)['actions']}, 'OWNER_DENIAL_BOUNDARY_NOT_IN_PLAN')
    io.require(io.sha(plan_raw) == r3.OWNER_PLAN and scope['machine_sha256'] == r3.MACHINE, 'FIXED_HOST_OR_OWNER_PLAN')
    packet = {'source': encoded, 'hashes': hashes, 'baseline': baseline,
              'baseline_raw': base64.b64encode(baseline_raw).decode(),
              'scope_raw': base64.b64encode(scope_raw).decode(),
              'owner_plan': base64.b64encode(plan_raw).decode(), 'scope': scope,
              'scope_sha256': args.approved_scope_sha256, 'binding': io.sha(io.canonical(scope))}
    if replacing:
        packet['baseline_encoding']='zlib_R5'
        packet['baseline_raw']=base64.b64encode(zlib.compress(baseline_raw,9)).decode()
    if scope['schema'] in io.PROSPECTIVE_SCOPES:
        packet['prospective_material']={h:base64.b64encode(raw).decode() for h,raw in prospective.items()}
    io.prospective_packet_material(packet)
    io.require(io.baseline_bytes(packet)==baseline_raw,'BASELINE_PACKET_READBACK')
    io.require(len(io.canonical(packet))<=io.MAX_FRAME,'LOCAL_PACKET_BOUND_BEFORE_HOST')
    if not args.execute:
        print(json.dumps({'status': 'LOCAL_PACKAGE_VALIDATED_NO_HOST_ACCESS', 'binding': packet['binding'],
                          'host_dispatched': False, 'slot_consumed': False})); return
    io.require(sys.stdin.isatty(), 'HUMAN_TTY_REQUIRED_NO_CHAT_PASSWORD')
    return execute(packet, encoded, hashes, baseline, r3, owner_hold_before=args.hold_owner_before,
                   runtime_payload=runtime_payload)


def execute(packet, encoded, hashes, baseline, r3, *, owner_hold_before=None, runtime_payload=None):
    """Actual owned transport/custody lifecycle; no Host gate substitutions."""
    program = bootstrap(base64.b64decode(encoded['io']))
    remote = 'LC_ALL=C '+shlex.join(['/usr/bin/sudo', '-S', '-k', '-p', '', '--',
                                    '/usr/bin/python3', '-I', '-B', '-S', '-c', program])
    argv = ssh_argv(remote)
    # Password exists only in the invoking TTY and this owned SSH stdin. Do not
    # send a payload until the reviewed bootstrap has actually replaced sudo.
    # Preflight evidence is NOT a transaction permit. A real Host effect still
    # requires the independent fixed R3 Journal claim after actual admission.
    # Both copies are on this Mac, not physical redundancy.
    preparation = []; targets = []; password = None; child = None; client = None
    result = {'status': 'UNKNOWN_HOLD_NO_RETRY'}
    try:
        targets, preparation = preparation_records(packet['binding'])
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            password = getpass.getpass('chatops sudo — gebundener einmaliger R3/R4-Operator: ').encode()
        io.require(password and b'\n' not in password and b'\r' not in password, 'PASSWORD_INPUT_FORMAT')
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        child.stdin.write(password+b'\n'); child.stdin.flush(); password = None
        outer = time.monotonic()+600
        wire = io.Wire(child.stdout.fileno(), child.stdin.fileno(), deadline=min(outer, time.monotonic()+20))
        io.require(wire.receive() == {'type': 'ready', 'io_sha256': hashes['io']}, 'AUTHENTIC_BOOTSTRAP_NOT_READY')
        wire.deadline = outer
        wire.send(packet)
        http = [e for u in (*r3.UNITS, 'lighting') for e in
                (baseline['http'][u] if u != 'lighting' else [baseline['http'][u]]) if e['location'] == 'client']
        client = Client(wire, r3, packet['binding'], http_expectations=http, owner_hold_before=owner_hold_before,
                        runtime_payload=runtime_payload,
                        admission_packet=packet if packet['scope']['schema'] in io.PROSPECTIVE_SCOPES else None)
        result = client.serve(); child.stdin.close()
        io.require(child.wait(timeout=5) == 0, 'SSH_END_UNKNOWN')
    except BaseException as error:
        result = {**result, 'remote_status': result['status'], 'status': 'HOLD',
                  'client_primary': getattr(error, 'primary', 'PUBLIC_BOOTSTRAP_CLIENT_INTERRUPTED_OR_IO_UNKNOWN'),
                  'client_abort': [], 'client_cleanup': getattr(error, 'client_cleanup', [])}
    finally:
        password = None
        cleanup = list(result.get('client_cleanup', []))
        if client is not None:
            try: client.close()
            except BaseException: cleanup.append('PUBLIC_BOOTSTRAP_CLIENT_CUSTODY_CLOSE_UNKNOWN')
        if child is not None:
            for stream in (child.stdin, child.stdout):
                try:
                    if not stream.closed: stream.close()
                except BaseException: cleanup.append('PUBLIC_BOOTSTRAP_OWNED_CHANNEL_CLOSE_UNKNOWN')
            # No reconnect, numeric REMOTE signal, rollback or retry. Close
            # the channel first; if OUR still-unreaped local SSH child cannot
            # end, terminate only that child. Remote outcomes remain HOLD.
            try: child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                result = {**result, 'status': 'HOLD', 'ssh_cleanup': 'OWNED_CHANNEL_DID_NOT_END'}
                try:
                    child.terminate()
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill(); child.wait(timeout=5)
                except BaseException: cleanup.append('PUBLIC_BOOTSTRAP_OWNED_SSH_END_UNKNOWN')
            except BaseException:
                cleanup.append('PUBLIC_BOOTSTRAP_OWNED_SSH_WAIT_UNKNOWN')
        if cleanup:
            result = {**result, 'remote_status': result.get('remote_status', result['status']), 'status': 'HOLD'}
        result['client_cleanup'] = cleanup
        recording = []
        for fd in preparation:
            try: io.exclusive(fd, 'result.json', io.canonical(result))
            except BaseException: recording.append('PUBLIC_BOOTSTRAP_CLIENT_RESULT_RECORD_UNKNOWN')
            finally:
                try: os.close(fd)
                except OSError: recording.append('PUBLIC_BOOTSTRAP_CLIENT_PREPARATION_CLOSE_UNKNOWN')
        if recording: raise io.Hold('PUBLIC_OPERATOR_CLIENT_CLEANUP_OR_RECORD_UNCONFIRMED')
    code = 'from pathlib import Path;import sys;a,b=[Path(x).read_bytes() for x in sys.argv[1:]];assert a==b and a'
    check = subprocess.run([sys.executable, '-I', '-B', '-c', code, *[str(p/'result.json') for p in targets]],
                           capture_output=True, timeout=10)
    io.require(check.returncode == 0, 'RESULT_INDEPENDENT_READBACK')
    print(json.dumps({'status': result['status'], 'binding': packet['binding'],
                      'slot_consumed_by_operator': False, 'r2_dispatch': False}))
    return 0 if result['status'] == 'RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED' else 1


def entry():
    try:
        return main()
    except SystemExit:
        raise  # argparse help/usage has no Host dispatch and no private payload.
    except BaseException as error:
        primary = getattr(error, 'primary', '')
        if not isinstance(primary, str) or not re.fullmatch('PUBLIC_BOOTSTRAP_[A-Z0-9_]{1,160}', primary):
            primary = 'PUBLIC_OPERATOR_ENTRY_DENIED_OR_OUTCOME_UNCONFIRMED'
        print(json.dumps({'status': 'HOLD', 'primary': primary, 'r2_dispatch': False,
                          'slot_consumed_by_operator': False}))
        return 1


if __name__ == '__main__': raise SystemExit(entry())
