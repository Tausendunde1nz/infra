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
import subprocess
import sys
import time
import zlib


def load_io():
    path = Path(__file__).resolve().with_name('tu1nz_public_operator_io.py')
    spec = importlib.util.spec_from_file_location('tu1nz_public_operator_io', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module; spec.loader.exec_module(module)
    return module


io = load_io()
INFRA_FILES = {n: 'scripts/tu1nz_public_operator_'+n+'.py' for n in ('io', 'fs', 'runtime_guard', 'observe', 'probes', 'host')}
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
    def __init__(self, wire, r3, binding, *, http_expectations, owner_hold_before=None, runtime_payload=None):
        self.wire, self.r, self.binding = wire, r3, binding
        self.journal = None; self.fd = None; self.records = {}; self.last = binding; self.sequence = 0
        self.http_expectations = http_expectations
        self.owner_hold_before = owner_hold_before
        self.runtime_payload=runtime_payload;self.runtime_next=0
        self.runtime_payload_sha256=io.sha(runtime_payload) if runtime_payload is not None else None

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

    def serve(self):
        while True:
            message = self.wire.receive(); kind = message.get('type')
            if kind == 'prepared':
                io.require(set(message) == {'type', 'binding'} and message['binding'] == self.binding and
                           self.journal is None, 'PREPARED_BINDING_OR_REPLAY')
                self.initialize()
                self.wire.send({'type': 'client_custody_created', 'binding': self.binding})
            elif kind == 'durable_record':
                self.check(); row = message['record']; raw = io.canonical(row)
                io.require(row['binding'] == self.binding and row['previous'] == self.last and
                           row['sequence'] == self.sequence+1 and io.sha(raw) == message['sha256'],
                           'HASH_LINK_OR_SEQUENCE_RED')
                name = str(row['sequence']).zfill(3)+'-'+row['kind']+'.json'
                io.exclusive(self.fd, name, raw); self.records[name] = raw
                if row['kind'] == 'flow_claim': self.journal.claim()
                elif row['kind'].startswith('flow_'):
                    self.journal.write(row['kind'][5:], row['value'])
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
    if scope['schema']==io.PROSPECTIVE_SCOPE:
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
                        runtime_payload=runtime_payload)
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
