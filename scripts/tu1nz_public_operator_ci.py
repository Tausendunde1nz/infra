"""Finite R4 integration on an exact-reviewed, Environment-approved CI runner.

Only three pinned private Control blobs enter fresh network-none guests. No
credential, private source, exception text or guest output reaches public logs,
artifacts or caches. This helper is NOT Host admission or a deployment entry.
"""
import argparse
import ast
import base64
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
         'first_restart', 'old_restart')
FAULTS = {'success': [], 'writer': ['REAL_PREEXISTING_WRITABLE_FD'],
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
                          'REAL_REPLACEMENT_BEFORE_FIRST_OBSERVATION']}
SCHEMA = 'TU1NZ_PUBLIC_OPERATOR_NATIVE_CI_V1'


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
    return symbols | {prefix+x for prefix in ('PUBLIC_OPERATOR_', 'PUBLIC_BOOTSTRAP_',
                                              'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_') for x in symbols}


def native_fsuid_argv(name):
    program = '''import os,sys,unittest,json
assert sys.platform=="linux" and os.geteuid()==0
sys.path.insert(0,"/source")
from tests.test_public_operator import OperatorBoundary
class Result(unittest.TestResult):
 error=None
 def addError(self,test,error):self.error=error;super().addError(test,error)
 def addFailure(self,test,error):self.error=error;super().addFailure(test,error)
r=Result()
OperatorBoundary("test_actual_fsuid_socket_owner_cannot_be_admitted_as_other_effective_uid").run(r)
if not (r.testsRun==1 and not r.skipped and not r.failures and not r.errors):
 line=1;kind="AssertionError";cause=None
 if r.error:
  kind=r.error[0].__name__;trace=r.error[2]
  while trace is not None:
   if trace.tb_frame.f_code.co_filename=="/source/tests/test_public_operator.py":line=trace.tb_lineno
   trace=trace.tb_next
  error=r.error[1];seen=set()
  while error is not None and id(error) not in seen:
   seen.add(id(error))
   if isinstance(getattr(error,"primary",None),str):cause=error.primary;break
   error=error.__context__
 print(json.dumps({"native_failure":{"test_line":line,"test_type":kind,"production_fault":None,"cause_code":cause}}))
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


def native_argv(workspace, control, image, name, owner):
    return ['/usr/bin/docker', 'create', '--name', name, '--label', 'tu1nz.private-ci.owner='+owner,
        '--network', 'none', '--privileged', '--cgroupns=private', '--env', 'container=docker',
        '--memory', '2048m', '--cpus', '2', '--pids-limit', '512',
        '--tmpfs', '/run', '--tmpfs', '/run/lock', '--tmpfs', '/tmp',
        '--mount', 'type=bind,src='+str(workspace)+',dst=/source,readonly',
        '--mount', 'type=bind,src='+str(control)+',dst=/control-source,readonly',
        '--workdir', '/source', image]


def inspect_guest(name, owner, workspace, control, image_id):
    value = json.loads(command(['/usr/bin/docker', 'inspect', name], timeout=15))[0]
    require(value['Image'] == image_id and value['Config']['Labels'].get('tu1nz.private-ci.owner') == owner and
            value['HostConfig']['NetworkMode'] == 'none' and value['HostConfig']['CgroupnsMode'] == 'private',
            'GUEST_BOUNDARY_RED')
    mounts = [(m['Source'], m['Destination'], m['RW']) for m in value['Mounts'] if m['Type'] == 'bind']
    require(sorted(mounts) == sorted([(str(workspace), '/source', False),
                                      (str(control), '/control-source', False)]), 'GUEST_MOUNTS_RED')


def ready(name):
    deadline = time.monotonic()+20
    while time.monotonic() < deadline:
        code, raw = boundary.bounded(['/usr/bin/docker', 'exec', name, '/usr/bin/python3', '-I', '-B', '-c',
            'from pathlib import Path;print(Path("/proc/1/comm").read_text().strip())'], timeout=5)
        if code == 0 and raw.strip() == b'systemd': return
        time.sleep(0.1)
    raise CIError('PID1_READY_RED')


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
    if case == 'success':
        require((value['status'], value['server_exit'], value['owner_confirmations'], value['actual_root_objects']) ==
                ('RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED', 0, 84, 88), 'FORWARD_RED')
    elif case in ('restore_fail_return', 'probe_fail_return', 'owner_return'):
        status = 'OWNER_RETURNED_SECURITY_RED' if case == 'owner_return' else 'OLD_OPERATION_RESTORED_SECURITY_RED'
        require((value['status'], value['server_exit'], value['owner_confirmations'], value['actual_root_objects']) ==
                (status, 0, 7 if case == 'owner_return' else 0, 4), 'RETURN_RED')
    else:
        require(value['status'] in ('HOLD', 'UNKNOWN_TEST_PROTOCOL_HOLD'), 'FAULT_NOT_HELD')
        if case in ('writer', 'runtime_tamper', 'denied_return', 'lost_start_ack', 'first_restart', 'old_restart'):
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
        value = operator.io.parse(raw.strip())
        require(set(value) == {'native_failure'}, 'FAILURE_SCHEMA')
        location = value['native_failure']
        require({'test_line', 'test_type', 'production_fault'} <= set(location) <=
                {'test_line', 'test_type', 'production_fault', 'outcome', 'cause_code'}, 'FAILURE_SCHEMA')
        require(type(location['test_line']) is int and 0 < location['test_line'] < 10000 and
                location['test_type'] in ('AssertionError', 'RuntimeError', 'OSError', 'Hold',
                                          'KeyError', 'ValueError', 'TimeoutExpired'), 'FAILURE_SCHEMA')
        fault = location['production_fault']
        if fault is not None:
            require(set(fault) == {'component', 'line', 'type'} and
                    fault['component'] in {'<authenticated-memory:'+n+'>' for n in
                        (*operator.INFRA_FILES, *operator.CONTROL_FILES)} and
                    type(fault['line']) is int and 0 < fault['line'] < 10000 and
                    fault['type'] in ('Hold', 'Denied', 'FlowFailure', 'OwnerFailure', 'AssertionError',
                                      'OSError', 'PermissionError', 'FileNotFoundError', 'RuntimeError',
                                      'KeyError', 'ValueError', 'TimeoutExpired'), 'FAILURE_SCHEMA')
        if 'cause_code' in location:
            value = location['cause_code']
            location = {**location, 'cause_code': value if type(value) is str and value in diagnostic_codes()
                        else (None if value is None else 'UNCLASSIFIED_CODE_REDACTED')}
        if 'outcome' in location:
            outcome = location['outcome']
            require(type(outcome) is dict and set(outcome) == {'status', 'primary', 'abort', 'cleanup',
                'client_error_type', 'server_exit', 'owner_confirmations', 'actual_root_objects',
                'last_record_kind', 'last_record_sequence'}, 'OUTCOME_SCHEMA')
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
            outcome['client_error_type'] = outcome['client_error_type'] if outcome['client_error_type'] in (
                None, 'Hold', 'OSError', 'AssertionError', 'TimeoutExpired', 'ValueError', 'KeyError') else 'REDACTED'
            outcome['last_record_kind'] = outcome['last_record_kind'] if outcome['last_record_kind'] in (
                None, 'flow_claim', 'host_action_intent', 'host_action_ack', 'function_accepted',
                'owner_claim_intent', 'owner_ready', 'owner_object_intent', 'owner_object_ack',
                'owner_completion', 'owner_cleanup', 'operator_pending_cleanup', 'operator_cleanup') else 'REDACTED'
            location = {**location, 'outcome': outcome}
        return location
    except BaseException:
        return None


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
    diagnostic = None
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
        for case in CASES:
            phase = case+'-create'
            container = 'tu1nz-public-operator-private-'+owner+'-'+case.replace('_', '-')
            command(native_argv(workspace, control, image, container, owner), timeout=30)
            phase = case+'-inspect'; inspect_guest(container, owner, workspace, control, image_id)
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
            if code != 0: diagnostic = failure_location(raw)
            require(code == 0, 'NATIVE_CASE_RED')
            records.append(validate_report(raw, case, hashes))
            boundary.cleanup_container(container, owner); container = None
        result = {'schema': SCHEMA, 'green': True, 'code': 'PRIVATE_OPERATOR_CI_GREEN', 'source_sha': sha,
                  'control_commit': CONTROL_COMMIT, 'image_id': image_id, 'source_files': hashes, 'cases': records,
                  'native_fsuid_test': 'ACTUAL_NATIVE_FSUID_DAC_GREEN',
                  'host_acceptance': False, 'slot_consumed': False}
    except BaseException as error:
        # Never print child output, command arguments, exception text/traceback
        # or private source. Only our finite safe stage and owned enum.
        result = {'schema': SCHEMA, 'green': False, 'stage': phase,
                  'code': str(error) if type(error) is CIError else 'PRIVATE_OPERATOR_CI_RED'}
        if diagnostic is not None: result['failure_location'] = diagnostic
    finally:
        result = cleanup_result(result, container, owner, root, parent)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['green'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--image', required=True); args = parser.parse_args()
    with boundary.interrupted():
        raise SystemExit(run(Path(__file__).resolve().parents[1], args.image))
