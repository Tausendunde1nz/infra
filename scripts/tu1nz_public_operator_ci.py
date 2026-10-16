"""Finite R4 integration on an exact-reviewed, Environment-approved CI runner.

Only three pinned private Control blobs enter fresh network-none guests. No
credential, private source, exception text or guest output reaches public logs,
artifacts or caches. This helper is NOT Host admission or a deployment entry.
"""
import argparse
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
        require(set(location) == {'test_line', 'test_type', 'production_fault'}, 'FAILURE_SCHEMA')
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
        return location
    except BaseException:
        return None


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
            phase = case
            container = 'tu1nz-public-operator-private-'+owner+'-'+case.replace('_', '-')
            command(native_argv(workspace, control, image, container, owner), timeout=30)
            inspect_guest(container, owner, workspace, control, image_id)
            command(['/usr/bin/docker', 'start', container], timeout=30); ready(container)
            code, raw = boundary.bounded(['/usr/bin/docker', 'exec', container, '/usr/bin/python3', '-I', '-B',
                '/source/tests/public_operator_native.py', '--scenario', case], timeout=720)
            if code != 0: diagnostic = failure_location(raw)
            require(code == 0, 'NATIVE_CASE_RED')
            records.append(validate_report(raw, case, hashes))
            boundary.cleanup_container(container, owner); container = None
        result = {'schema': SCHEMA, 'green': True, 'code': 'PRIVATE_OPERATOR_CI_GREEN', 'source_sha': sha,
                  'control_commit': CONTROL_COMMIT, 'image_id': image_id, 'source_files': hashes, 'cases': records,
                  'host_acceptance': False, 'slot_consumed': False}
    except BaseException as error:
        # Never print child output, command arguments, exception text/traceback
        # or private source. Only our finite safe stage and owned enum.
        result = {'schema': SCHEMA, 'green': False, 'stage': phase,
                  'code': str(error) if type(error) is CIError else 'PRIVATE_OPERATOR_CI_RED'}
        if diagnostic is not None: result['failure_location'] = diagnostic
    finally:
        try:
            if container is not None: boundary.cleanup_container(container, owner)
        except BaseException:
            result = {'schema': SCHEMA, 'green': False, 'code': 'OWNED_CONTAINER_CLEANUP_RED'}
        try:
            if root is not None: boundary.remove_private(root, parent)
        except BaseException:
            result = {'schema': SCHEMA, 'green': False, 'code': 'PRIVATE_INPUT_CLEANUP_RED'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['green'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--image', required=True); args = parser.parse_args()
    with boundary.interrupted():
        raise SystemExit(run(Path(__file__).resolve().parents[1], args.image))
