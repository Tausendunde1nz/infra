"""Finite R4 integration on an exact-reviewed, Environment-approved CI runner.

Only three pinned private Control blobs enter fresh network-none guests. No
credential, private source, exception text or guest output reaches public logs,
artifacts or caches. This helper is NOT Host admission or a deployment entry.
"""
import argparse
import ast
import base64
import builtins
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tu1nz_control_private_ci as boundary
import tu1nz_public_operator as operator

CONTROL_COMMIT = 'f2979863bbb7043261e9177842503a9b47cdb49f'
CASES = ('success', 'writer', 'namespace_swap', 'lost_ack', 'interrupt', 'runtime_tamper',
         'restore_fail_return', 'probe_fail_return', 'denied_return', 'owner_return', 'lost_start_ack',
         'first_restart', 'old_restart', 'stop_source_fd', 'stop_source_mapping', 'unknown_actor', 'thread_authority',
         'thread_source_fd', 'r5_success', 'r5_legacy_unknown', 'r5_hooks', 'r5_chunk_loss',
         'r5_partial_interrupt', 'r5_artifact_tamper', 'r5_legacy_tamper', 'r5_old_return_denied', 'r5_first_restart', 'r5_owner_return')
FAULTS = {'success': [], 'writer': ['REAL_PREEXISTING_WRITABLE_FD'],
          'stop_source_fd': ['REAL_STOP_TARGET_SOURCE_FD'],
          'stop_source_mapping': ['REAL_STOP_TARGET_SOURCE_SHARED_MAP'],
          'unknown_actor': ['REAL_UNCLASSIFIED_NEW_PROCESS'],
          'thread_authority': ['REAL_NONLEADER_RETAINS_FILESYSTEM_UID'],
          'thread_source_fd': ['REAL_NONLEADER_SOURCE_FD_WITH_UNSHARED_TABLE', 'REAL_WRITER_TASK_CENSUS_REJECTED'],
          'runtime_tamper': ['REAL_RUNTIME_DRIFT_BEFORE_ADMISSION'],
          'namespace_swap': ['REAL_RENAME_AND_RETURN'], 'lost_ack': ['REAL_INVALID_TRANSPORT_ACK'],
          'interrupt': ['OWNED_COORDINATOR_PIDFD_INTERRUPT'],
          'restore_fail_return': ['REAL_BACKUP_CORRUPTION'],
          'probe_fail_return': ['REAL_SYNTHETIC_CREDENTIAL_DRIFT'],
          'denied_return': ['REAL_RUNTIME_DRIFT_AFTER_STOP'],
          'owner_return': ['EXPLICIT_DURABLE_OWNER_DENIAL_BEFORE_EFFECT'],
          'lost_start_ack': ['REAL_INVALID_START_ACK'],
          'first_restart': ['REAL_INITIAL_FAILURE_ARMED', 'REAL_REPLACEMENT_BEFORE_FIRST_OBSERVATION'],
          'old_restart': ['REAL_SYNTHETIC_CREDENTIAL_DRIFT', 'REAL_INITIAL_FAILURE_ARMED',
                          'REAL_REPLACEMENT_BEFORE_FIRST_OBSERVATION'],
          'r5_success': [], 'r5_legacy_unknown': ['REAL_R5_LEGACY_BYTES_NOT_ADOPTED'],
          'r5_hooks': ['REAL_R5_EXECSTOP_HOOK'],
          'r5_chunk_loss': ['REAL_R5_WRONG_CHUNK_SEQUENCE'],
          'r5_partial_interrupt': ['REAL_R5_PARTIAL_INSTALL_INTERRUPT'],
          'r5_artifact_tamper': ['REAL_R5_ARTIFACT_WRITE_AFTER_FENCE'],
          'r5_legacy_tamper': ['REAL_R5_LEGACY_WRITE_AFTER_REPLACEMENT'],
          'r5_old_return_denied': ['REAL_SYNTHETIC_CREDENTIAL_DRIFT','REAL_R5_FORBIDDEN_OLD_RETURN_REQUEST'],
          'r5_first_restart': ['REAL_INITIAL_FAILURE_ARMED','REAL_REPLACEMENT_BEFORE_FIRST_OBSERVATION'],
          'r5_owner_return': ['EXPLICIT_DURABLE_OWNER_DENIAL_BEFORE_EFFECT']}
SCHEMA = 'TU1NZ_PUBLIC_OPERATOR_NATIVE_CI_V1'
SAFE_FAILURE_TYPES = frozenset(n for n, v in vars(builtins).items()
    if isinstance(v, type) and issubclass(v, BaseException)) | {'Hold', 'Denied', 'FlowFailure', 'OwnerFailure', 'NativeFSUIDFailure'}
SAFE_NATIVE_CODES = frozenset(('NATIVE_FSUID_CHILD_SETFSUID_RED', 'NATIVE_FSUID_CHILD_UID_VIEW_RED',
    'NATIVE_FSUID_CHILD_CONNECT_RED', 'NATIVE_FSUID_CHILD_HANDSHAKE_RED', 'NATIVE_FSUID_CHILD_PROTOCOL_RED'))


def diagnostic_codes():
    # Only literal public Source symbols can leave private CI memory. A child
    # exception or Host value merely matching a regex is NOT publishable.
    workspace = Path(__file__).resolve().parents[1]
    symbols = set()
    for relative in operator.INFRA_FILES.values():
        if not relative.endswith('.py'): continue
        for node in ast.walk(ast.parse((workspace/relative).read_bytes())):
            if isinstance(node, ast.Constant) and type(node.value) is str and re.fullmatch('[A-Z][A-Z0-9_]{1,160}', node.value):
                symbols.add(node.value)
    return symbols | SAFE_NATIVE_CODES | {prefix+x for prefix in ('PUBLIC_OPERATOR_', 'PUBLIC_BOOTSTRAP_',
        'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_', 'PUBLIC_RUNTIME_', 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_RUNTIME_')
        for x in symbols}


def terminal_wire_code(raw):
    # Only an exact, literal PUBLIC Source Hold symbol may leave private child
    # stderr. No traceback, path, argv, exception text or regex-shaped secret.
    symbols = diagnostic_codes(); candidates = set()
    for line in raw.splitlines():
        match = re.fullmatch(rb'tu1nz_public_operator_io\.Hold: (PUBLIC_OPERATOR_[A-Z0-9_]{1,96})', line)
        if match:
            value = match[1].decode()
            if value in symbols: candidates.add(value)
    return next(iter(candidates)) if len(candidates) == 1 else None


def safe_actor_diagnostic(value):
    # Fixed failure enums/field names only, never an admission observation.
    if type(value) is not dict or set(value) != {'executable_class', 'matching_executable_profiles',
            'different_fields', 'stable_followup', 'title_kind'}: return None
    if value['executable_class'] not in ('postgres', 'polkitd', 'systemd', 'systemd-journald',
            'dbus-daemon', 'nginx', 'python3.12', 'busctl', 'systemctl', 'sudo', 'sleep', 'OTHER'): return None
    if value['title_kind'] not in ('UNKNOWN', 'POSTGRES_AUTOVACUUM_WORKER',
                                  'POSTGRES_AUTOVACUUM_LAUNCHER', 'OTHER'): return None
    if type(value['matching_executable_profiles']) is not int or not 0 <= value['matching_executable_profiles'] <= 256: return None
    if type(value['stable_followup']) is not bool or type(value['different_fields']) is not list: return None
    fields = value['different_fields']
    if not all(type(k) is str and k in ('uid', 'gid', 'groups', 'caps', 'nnp', 'argv_sha256',
             'cgroup', 'initial_env_sha256', 'lsm_sha256', 'namespaces') for k in fields): return None
    if len(fields) != len(set(fields)): return None
    return value


def safe_read_cost(value):
    labels = {'authority_check', 'authority_check_files', 'authority_units_check', 'authority_actors_check',
              'process', 'writer_check', 'paths_check', 'linked_record', 'measured_http',
              'owner_check_all', 'owner_apply', 'owner_finish'}
    require(type(value) is dict and 0 < len(value) <= len(labels) and set(value) <= labels, 'READ_COST_SCHEMA')
    require(all(type(v) is dict and set(v) == {'calls', 'inclusive_ns'} and
                type(v['calls']) is int and 0 <= v['calls'] <= 10_000_000 and
                type(v['inclusive_ns']) is int and 0 <= v['inclusive_ns'] <= 720_000_000_000
                for v in value.values()), 'READ_COST_SCHEMA')
    return value


def native_fsuid_argv(name):
    program = '''import os,sys,unittest,json
assert sys.platform=="linux" and os.geteuid()==0
sys.path.insert(0,"/source")
from tests.public_operator_native import prepare_guest_kernel_view
prepare_guest_kernel_view()
from tests.test_public_operator import OperatorBoundary
class Result(unittest.TestResult):
 error=None
 def addError(self,test,error):
  if self.error is None:self.error=error
  super().addError(test,error)
 def addFailure(self,test,error):
  if self.error is None:self.error=error
  super().addFailure(test,error)
 def addSubTest(self,test,subtest,error):
  if error is not None and self.error is None:self.error=error
  super().addSubTest(test,subtest,error)
r=Result()
unittest.TestSuite([OperatorBoundary("test_actual_fsuid_socket_owner_cannot_be_admitted_as_other_effective_uid"),
 OperatorBoundary("test_actual_child_dac_failure_is_not_replaced_by_fixture_cleanup"),
 OperatorBoundary("test_actual_fsgid_not_real_saved_group_controls_other_write"),
 OperatorBoundary("test_actual_nonleader_security_must_match_leader"),
 OperatorBoundary("test_actual_unshared_nonleader_source_descriptor_is_rejected"),
 OperatorBoundary("test_actual_single_leader_start_sample_is_bound_not_another_start"),
 OperatorBoundary("test_actual_http_reader_absolute_deadline_and_reap")]).run(r)
if not (r.testsRun==7 and not r.skipped and not r.failures and not r.errors):
 line=1;kind="AssertionError";cause=None;number=0
 if r.error:
  kind=r.error[0].__name__;trace=r.error[2]
  while trace is not None:
   if trace.tb_frame.f_code.co_filename=="/source/tests/test_public_operator.py":line=trace.tb_lineno
   trace=trace.tb_next
  error=r.error[1];seen=set()
  while error is not None and id(error) not in seen:
   seen.add(id(error))
   if isinstance(getattr(error,"primary",None),str):
    cause=error.primary;number=getattr(error,"native_errno",0);break
   error=error.__context__
 print(json.dumps({"native_failure":{"test_line":line,"test_type":kind,"production_fault":None,"cause_code":cause,"errno":number}}))
 raise SystemExit(1)
print("ACTUAL_NATIVE_FSUID_DAC_GREEN")
'''
    return ['/usr/bin/docker', 'exec', name, '/usr/bin/python3', '-I', '-B', '-c', program]


class CIError(RuntimeError):
    pass


def require(ok, code):
    if not ok: raise CIError(code)


def command(argv, **kwargs):
    code, raw = boundary.bounded(argv, **kwargs)
    require(code == 0, 'COMMAND_RED')
    return raw


def save(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    require(path.read_bytes() == raw, 'PRIVATE_READBACK_RED')


def fetch_control(private, token):
    bare = private/'source.git'; bare.mkdir(mode=0o700)
    ask = private/'askpass.py'
    save(ask, b'#!/usr/bin/python3\nimport os,sys\nprint("x-access-token" if "Username" in sys.argv[1] else os.environ["CONTROL_POLICY_READ_TOKEN"])\n', 0o700)
    git = ['/usr/bin/git', '--no-optional-locks', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
           '-C', str(bare)]
    fetch_env = {**boundary.tool_env(), 'GIT_ASKPASS': str(ask), 'CONTROL_POLICY_READ_TOKEN': token}
    try:
        command(git+['init', '--bare', '-q'])
        command(git+['remote', 'add', 'origin', 'https://github.com/Tausendunde1nz/control.git'])
        command(git+['fetch', '--no-tags', 'origin', CONTROL_COMMIT], env=fetch_env, timeout=180)
        require(command(git+['rev-parse', 'FETCH_HEAD']).decode().strip() == CONTROL_COMMIT, 'CONTROL_REF_RED')
    finally:
        fetch_env.pop('CONTROL_POLICY_READ_TOKEN', None)
        ask.unlink(missing_ok=True)
    root = private/'control-source'; root.mkdir(mode=0o700)
    hashes = {}
    for name, relative in operator.CONTROL_FILES.items():
        raw = command(git+['show', CONTROL_COMMIT+':'+relative])
        require(0 < len(raw) <= 3*1024*1024, 'CONTROL_BLOB_BOUND')
        path = root/relative; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        save(path, raw); hashes[name] = hashlib.sha256(raw).hexdigest()
    require(all(hashes[n] == h for n, h in operator.io.CONTROL_PINS.items()), 'OLD_CONTROL_PIN_RED')
    shutil.rmtree(bare)
    return root, hashes


def native_argv(workspace, control, image, name, owner, *, runtime_inputs=None):
    argv=['/usr/bin/docker', 'create', '--name', name, '--label', 'tu1nz.private-ci.owner='+owner,
        '--network', 'none', '--privileged', '--cgroupns=private', '--env', 'container=docker',
        '--memory', '2048m', '--cpus', '2', '--pids-limit', '512',
        '--tmpfs', '/run', '--tmpfs', '/run/lock', '--tmpfs', '/tmp',
        '--mount', 'type=bind,src='+str(workspace)+',dst=/source,readonly',
        '--mount', 'type=bind,src='+str(control)+',dst=/control-source,readonly',
        '--workdir', '/source']
    if runtime_inputs is not None:
        argv+=['--mount','type=bind,src='+str(runtime_inputs)+',dst=/runtime-inputs,readonly']
    return [*argv,image]


def inspect_guest(name, owner, workspace, control, image_id, *, runtime_inputs=None):
    value = json.loads(command(['/usr/bin/docker', 'inspect', name], timeout=15))[0]
    require(value['Image'] == image_id and value['Config']['Labels'].get('tu1nz.private-ci.owner') == owner and
            value['HostConfig']['NetworkMode'] == 'none' and value['HostConfig']['CgroupnsMode'] == 'private',
            'GUEST_BOUNDARY_RED')
    mounts = [(m['Source'], m['Destination'], m['RW']) for m in value['Mounts'] if m['Type'] == 'bind']
    expected=[(str(workspace),'/source',False),(str(control),'/control-source',False)]
    if runtime_inputs is not None:expected.append((str(runtime_inputs),'/runtime-inputs',False))
    require(sorted(mounts)==sorted(expected),'GUEST_MOUNTS_RED')


def ready(name):
    deadline = time.monotonic()+20
    while time.monotonic() < deadline:
        code, raw = boundary.bounded(['/usr/bin/docker', 'exec', name, '/usr/bin/python3', '-I', '-B', '-c',
            'from pathlib import Path;print(Path("/proc/1/comm").read_text().strip())'],
            timeout=min(5, max(0.01, deadline-time.monotonic())))
        if code == 0 and raw.strip() == b'systemd' and time.monotonic() < deadline:
            # PID1's name alone says nothing about boot/tmpfiles/namespace
            # setup completion. Do not create the fixture socket during boot.
            code, state = boundary.bounded(['/usr/bin/docker', 'exec', name,
                '/usr/bin/systemctl', 'is-system-running'],
                timeout=min(5, max(0.01, deadline-time.monotonic())))
            if code == 0 and state.strip() == b'running' and time.monotonic() < deadline: return
        time.sleep(min(0.1, max(0, deadline-time.monotonic())))
    raise CIError('GUEST_BOOT_READY_RED')


def validate_report(raw, case, hashes):
    # A test's summary alone cannot admit a Host. Native driver assertions also
    # inspect actual on-disk UIDs, intents, actions, receipts and replay denial.
    require(len(raw) <= 65536, 'REPORT_BOUND')
    value = operator.io.parse(raw.strip())
    require(set(value) == {'scenario', 'status', 'server_exit', 'proof', 'source_files', 'owner_confirmations',
                           'actual_root_objects', 'actual_faults', 'fixture_only_no_host_acceptance'} and
            value['scenario'] == case and value['source_files'] == hashes and
            value['fixture_only_no_host_acceptance'] is True and
            re.fullmatch('[a-f0-9]{64}', value['proof'] or ''), 'REPORT_SOURCE_OR_SCHEMA_RED')
    require(value['actual_faults'] == FAULTS[case], 'INTENDED_FAULT_NOT_WITNESSED')
    if case in ('success','r5_success','r5_legacy_unknown'):
        require((value['status'], value['server_exit'], value['owner_confirmations'], value['actual_root_objects']) ==
                ('RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED', 0, 84, 88), 'FORWARD_RED')
    elif case in ('restore_fail_return', 'probe_fail_return', 'owner_return','r5_owner_return'):
        status = 'OWNER_RETURNED_SECURITY_RED' if case in ('owner_return','r5_owner_return') else 'OLD_OPERATION_RESTORED_SECURITY_RED'
        require((value['status'], value['server_exit'], value['owner_confirmations'], value['actual_root_objects']) ==
                (status, 0, 7 if case in ('owner_return','r5_owner_return') else 0, 4), 'RETURN_RED')
    else:
        require(value['status'] in ('HOLD', 'UNKNOWN_TEST_PROTOCOL_HOLD'), 'FAULT_NOT_HELD')
        if case in ('writer', 'runtime_tamper', 'denied_return', 'lost_start_ack', 'first_restart', 'old_restart',
                    'stop_source_fd', 'stop_source_mapping', 'thread_authority', 'thread_source_fd',
                    'r5_hooks','r5_chunk_loss','r5_partial_interrupt','r5_artifact_tamper','r5_legacy_tamper','r5_old_return_denied','r5_first_restart'):
            require(value['actual_root_objects'] == 4, 'UNAUTHORIZED_OWNER_EFFECT')
        else:
            require(4 < value['actual_root_objects'] < 88, 'PARTIAL_EFFECT_NOT_WITNESSED')
    return {'scenario': case, 'result_sha256': value['proof'], 'status': value['status'],
            'actual_faults': value['actual_faults']}


def failure_location(raw):
    """Finite Source locations only. Never forward child text or private data.

    Failure logs must distinguish a fixture error from a production rejection
    without persisting a traceback, observation, argv or private Source blob.
    This diagnostic cannot make a failed scenario pass.
    """
    try:
        # bounded() merges private stdout/stderr. Warnings must not erase the
        # one structured failure line or escape through the public diagnostic.
        candidates = []
        for line in raw.splitlines():
            if not line.strip().startswith(b'{"native_failure"'): continue
            try: item = operator.io.parse(line.strip())
            except (ValueError, UnicodeError): continue
            if type(item) is dict and set(item) == {'native_failure'}: candidates.append(item)
        require(len(candidates) == 1, 'FAILURE_SCHEMA')
        value = candidates[0]
        require(set(value) == {'native_failure'}, 'FAILURE_SCHEMA')
        location = value['native_failure']
        require({'test_line', 'test_type', 'production_fault'} <= set(location) <=
                {'test_line', 'test_type', 'production_fault', 'outcome', 'cause_code', 'errno', 'actor', 'read_cost'}, 'FAILURE_SCHEMA')
        if 'errno' in location:
            require(type(location['errno']) is int and 0 <= location['errno'] < 4096, 'FAILURE_ERRNO_SCHEMA')
        require(type(location['test_line']) is int and 0 < location['test_line'] < 10000 and
                location['test_type'] in SAFE_FAILURE_TYPES | {'TimeoutExpired'}, 'FAILURE_SCHEMA')
        fault = location['production_fault']
        if fault is not None:
            require(set(fault) == {'component', 'line', 'type'} and
                    fault['component'] in {'<authenticated-memory:'+n+'>' for n in
                        (*operator.INFRA_FILES, *operator.CONTROL_FILES)} and
                    type(fault['line']) is int and 0 < fault['line'] < 10000 and
                    fault['type'] in SAFE_FAILURE_TYPES | {'TimeoutExpired'}, 'FAILURE_SCHEMA')
        if 'cause_code' in location:
            value = location['cause_code']
            location = {**location, 'cause_code': value if type(value) is str and value in diagnostic_codes()
                        else (None if value is None else 'UNCLASSIFIED_CODE_REDACTED')}
        if 'outcome' in location:
            outcome = location['outcome']
            required_outcome = {'status', 'primary', 'abort', 'cleanup',
                'client_error_type', 'server_exit', 'owner_confirmations', 'actual_root_objects',
                'last_record_kind', 'last_record_sequence'}
            require(type(outcome) is dict and required_outcome <= set(outcome) <=
                    required_outcome | {'server_terminal_code'}, 'OUTCOME_SCHEMA')
            require(type(outcome['server_exit']) is int and -128 <= outcome['server_exit'] <= 255 and
                    type(outcome['owner_confirmations']) is int and 0 <= outcome['owner_confirmations'] <= 84 and
                    type(outcome['actual_root_objects']) is int and 0 <= outcome['actual_root_objects'] <= 88 and
                    type(outcome['last_record_sequence']) is int and 0 <= outcome['last_record_sequence'] <= 10000 and
                    all(type(outcome[k]) is list and len(outcome[k]) <= 32 for k in ('abort', 'cleanup')),
                    'OUTCOME_SCHEMA')
            symbols = diagnostic_codes()
            def code(value): return value if type(value) is str and value in symbols else ('UNCLASSIFIED_CODE_REDACTED' if value is not None else None)
            outcome = {**outcome, **{k: code(outcome[k]) for k in ('status', 'primary')},
                       **{k: [code(x) for x in outcome[k]] for k in ('abort', 'cleanup')}}
            if 'server_terminal_code' in outcome:
                outcome['server_terminal_code'] = code(outcome['server_terminal_code'])
            outcome['client_error_type'] = outcome['client_error_type'] if outcome['client_error_type'] is None or (
                type(outcome['client_error_type']) is str and outcome['client_error_type'] in SAFE_FAILURE_TYPES | {'TimeoutExpired'}) else 'REDACTED'
            outcome['last_record_kind'] = outcome['last_record_kind'] if outcome['last_record_kind'] in (
                None, 'flow_claim', 'host_action_intent', 'host_action_ack', 'function_accepted',
                'owner_claim_intent', 'owner_ready', 'owner_object_intent', 'owner_object_ack',
                'owner_completion', 'owner_cleanup', 'operator_pending_cleanup', 'operator_cleanup') else 'REDACTED'
            location = {**location, 'outcome': outcome}
        if 'actor' in location:
            location = {**location, 'actor': safe_actor_diagnostic(location['actor'])}
        if 'read_cost' in location:
            location = {**location, 'read_cost': safe_read_cost(location['read_cost'])}
        return location
    except BaseException:
        return None


def native_process_diagnostic(code, raw):
    """Finite process facts; not an inferred signal/OOM/production cause."""
    require(type(code) is int and -128 <= code <= 255 and type(raw) is bytes and
            len(raw) <= boundary.MAX_OUTPUT, 'NATIVE_PROCESS_DIAGNOSTIC_SCHEMA')
    parsed = failure_location(raw); lines = []
    for line in raw.splitlines():
        if not line.strip().startswith(b'{"native_failure"'): continue
        try: value = operator.io.parse(line.strip())
        except (ValueError, UnicodeError): continue
        if type(value) is dict and set(value) == {'native_failure'} and type(value['native_failure']) is dict:
            lines.append(value['native_failure'])
    basic = lines[0] if len(lines) == 1 else {}
    number = basic.get('test_line'); kind = basic.get('test_type')
    return {'exit': code, 'output_bytes': len(raw), 'output_sha256': hashlib.sha256(raw).hexdigest(),
        'structured_lines': len(lines),
        'source_line': number if type(number) is int and 0 < number < 10000 else None,
        'failure_type': kind if type(kind) is str and kind in SAFE_FAILURE_TYPES | {'TimeoutExpired', 'CalledProcessError'} else None,
        'parser_status': 'COMPLETE' if parsed is not None else
                         'STRUCTURED_DATA_REDACTED' if lines else 'NO_STRUCTURED_LINE'}


def cleanup_result(result, container, owner, root, parent):
    """Independent cleanup provenance never replaces an earlier failure."""
    errors = []
    try:
        if container is not None: boundary.cleanup_container(container, owner)
    except BaseException:
        errors.append('OWNED_CONTAINER_CLEANUP_RED')
    try:
        if root is not None: boundary.remove_private(root, parent)
    except BaseException:
        errors.append('PRIVATE_INPUT_CLEANUP_RED')
    if errors:
        return {**result, 'green': False,
                'code': 'PRIVATE_OPERATOR_CI_CLEANUP_RED' if result['green'] else result['code'],
                'cleanup_errors': errors}
    return result


def run(workspace, image):
    root = None; container = None; owner = uuid.uuid4().hex; phase = 'admission'
    parent = Path(os.environ.get('RUNNER_TEMP', '/nonexistent'))
    result = {'schema': SCHEMA, 'green': False, 'code': 'PRIVATE_OPERATOR_CI_RED'}
    diagnostic = None; native_process = None
    try:
        token = os.environ.pop('CONTROL_POLICY_READ_TOKEN', None)
        sha = boundary.runtime_binding(os.environ, workspace)
        require(type(token) is str and token.startswith('github_pat_'), 'READ_CREDENTIAL_MISSING')
        require(image == 'tu1nz-public-operator-private:'+os.environ['GITHUB_RUN_ID']+'-'+
                os.environ['GITHUB_RUN_ATTEMPT'], 'FRESH_IMAGE_BINDING_RED')
        image_id = command(['/usr/bin/docker', 'image', 'inspect', '--format', '{{.Id}}', image]).decode().strip()
        require(re.fullmatch('sha256:[a-f0-9]{64}', image_id), 'IMAGE_ID_RED')
        root = boundary.private_root(parent, workspace)
        phase = 'private-source'
        control, hashes = fetch_control(root, token); token = None
        hashes.update({n: hashlib.sha256((workspace/p).read_bytes()).hexdigest()
                       for n, p in operator.INFRA_FILES.items()})
        records = []
        # Public upstream artifacts only. No additional private repository or
        # credential scope; exact digests remain the reviewed Source lock.
        import tu1nz_public_runtime_build as build
        phase='runtime-public-inputs'
        inputs=json.loads((workspace/'manifests/public-web-runtime-r5-inputs.json').read_bytes())
        runtime_inputs=root/'runtime-inputs';runtime_inputs.mkdir(mode=0o700)
        for row in [inputs['python'],*inputs['wheels']]:
            save(runtime_inputs/row['filename'],build.fetch(row))
        for case in CASES:
            phase = case+'-create'
            container = 'tu1nz-public-operator-private-'+owner+'-'+case.replace('_', '-')
            runtime=runtime_inputs if case.startswith('r5_') else None
            command(native_argv(workspace, control, image, container, owner,runtime_inputs=runtime), timeout=30)
            phase = case+'-inspect'; inspect_guest(container, owner, workspace, control, image_id,runtime_inputs=runtime)
            phase = case+'-start'; command(['/usr/bin/docker', 'start', container], timeout=30)
            phase = case+'-ready'; ready(container)
            if case == 'success':
                phase = case+'-fsuid'
                code, raw = boundary.bounded(native_fsuid_argv(container), timeout=30)
                if code != 0: diagnostic = failure_location(raw)
                require(code == 0 and raw.strip() == b'ACTUAL_NATIVE_FSUID_DAC_GREEN',
                        'NATIVE_FSUID_DAC_RED')
            phase = case+'-production'
            code, raw = boundary.bounded(['/usr/bin/docker', 'exec', container, '/usr/bin/python3', '-I', '-B',
                '/source/tests/public_operator_native.py', '--scenario', case], timeout=720)
            if code != 0:
                diagnostic = failure_location(raw)
                native_process = native_process_diagnostic(code, raw)
            require(code == 0, 'NATIVE_CASE_RED')
            records.append(validate_report(raw, case, hashes))
            boundary.cleanup_container(container, owner); container = None
        result = {'schema': SCHEMA, 'green': True, 'code': 'PRIVATE_OPERATOR_CI_GREEN', 'source_sha': sha,
                  'control_commit': CONTROL_COMMIT, 'image_id': image_id, 'source_files': hashes, 'cases': records,
                  'native_fsuid_test': 'ACTUAL_NATIVE_FSUID_DAC_GREEN',
                  'native_fsuid_tests': 7,
                  'host_acceptance': False, 'slot_consumed': False}
    except BaseException as error:
        # Never print child output, command arguments, exception text/traceback
        # or private source. Only our finite safe stage and owned enum.
        result = {'schema': SCHEMA, 'green': False, 'stage': phase,
                  'code': str(error) if type(error) is CIError else 'PRIVATE_OPERATOR_CI_RED'}
        if diagnostic is not None: result['failure_location'] = diagnostic
        if native_process is not None: result['native_process'] = native_process
    finally:
        result = cleanup_result(result, container, owner, root, parent)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['green'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--image', required=True); args = parser.parse_args()
    with boundary.interrupted():
        raise SystemExit(run(Path(__file__).resolve().parents[1], args.image))
