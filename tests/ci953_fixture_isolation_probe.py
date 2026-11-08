"""Single-purpose CI953 comparison; synthetic guests, no maintenance entry.

The original guard, image, init and guest helpers stay byte-identical to e0d13d6d.
Only the entry filename changes in the first Unit. The conditional second
Unit adds exactly Environment=container=docker. No private fetch is called.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/'scripts'))
import tu1nz_public_operator_ci as ci
import tu1nz_public_maintenance_diagnostics as diagnostics

BASE = 'e0d13d6d3532929286e5929d5005fe486eaf325b'
PARENT = '9a5c8b59417db820ed5d02b2406eeae80a2d0a11'
BRANCH = 'codex/ci953-fixture-isolation-probe-20261108'
ADDED = {'.github/workflows/ci953-fixture-isolation-probe.yml',
         'tests/ci953_fixture_isolation_probe.py', 'tests/test_ci953_fixture_isolation_probe.py'}
BOUND = ('tests/public-operator-native.Dockerfile', 'tests/public_operator_native_init.py',
         'tests/s8_native_init.py', 'tests/public_operator_native.py',
         'scripts/tu1nz_public_operator_ci.py', 'scripts/tu1nz_public_maintenance_ci.py',
         'scripts/tu1nz_control_private_ci.py', 'scripts/tu1nz_public_maintenance_diagnostics.py')
SCHEMA = 'TU1NZ_CI953_ISOLATION_PROBE_V1'
BOOLS = ('euid_is_zero', 'dockerenv_is_file', 'container_is_docker')
POINT = {'checkpoint': 'REV4_GUEST_ASSERT_GUEST_ISOLATION_ASSERT_01',
         'file': 'tests/public_operator_native.py', 'line': 461}
ERRORS = {'PROBE_BINDING_RED', 'PROBE_UNIT_SHAPE_RED', 'PROBE_REPORT_RED',
          'PROBE_UNEXPECTED_BASELINE', 'PROBE_CHANGED_GUEST_RED', 'PROBE_COMMAND_RED',
          'PROBE_WAIT_COMMAND_RED', 'PROBE_WAIT_PAYLOAD_RED', 'PROBE_REPORT_COPY_RED',
          'PROBE_REPORT_READ_RED', 'PROBE_REPORT_JSON_RED'}


class ProbeError(RuntimeError):
    pass


def require(ok, code):
    if not ok: raise ProbeError(code)


def unit_bytes(changed):
    """Use the exact original rendering expression, not a hand-copied Unit."""
    tree = ast.parse((ROOT/'scripts/tu1nz_public_maintenance_ci.py').read_bytes())
    expressions = [n.args[1] for n in ast.walk(tree) if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute) and n.func.attr == 'save'
        and len(n.args) == 2 and isinstance(n.args[0], ast.Name) and n.args[0].id == 'unit']
    require(len(expressions) == 1, 'PROBE_UNIT_SHAPE_RED')
    raw = eval(compile(ast.Expression(expressions[0]), '<bound-unit>', 'eval'),
               {'__builtins__': {}}, {'case': 'original', 'phase': 'calibration'})
    old = b'/source/tests/public_maintenance_native.py'
    require(type(raw) is bytes and raw.count(old) == 1 and raw.count(b'Type=simple\n') == 1
            and b'Environment=' not in raw, 'PROBE_UNIT_SHAPE_RED')
    raw = raw.replace(old, b'/source/tests/ci953_fixture_isolation_probe.py')
    if changed: raw = raw.replace(b'Type=simple\n', b'Type=simple\nEnvironment=container=docker\n')
    return raw


def source_hashes():
    return {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in BOUND}


def validate(value):
    require(type(value) is dict and set(value) == {'schema', 'conditions', 'guard_passed',
            'error_type', 'test_failure', 'source_files', 'host_acceptance'} and value['schema'] == SCHEMA
            and value['host_acceptance'] is False and value['source_files'] == source_hashes(), 'PROBE_REPORT_RED')
    flags = value['conditions']
    require(type(flags) is dict and set(flags) == set(BOOLS) and
            all(type(flags[k]) is bool for k in BOOLS) and type(value['guard_passed']) is bool, 'PROBE_REPORT_RED')
    if value['guard_passed']:
        require(all(flags.values()) and value['error_type'] is None and value['test_failure'] is None, 'PROBE_REPORT_RED')
    else:
        require(value['error_type'] in ('AssertionError', 'RuntimeError', 'OTHER') and
                diagnostics.validated(value['test_failure']) is not None, 'PROBE_REPORT_RED')
    return value


def only_missing_environment(value):
    validate(value)
    return (value['conditions'] == dict(zip(BOOLS, (True, True, False))) and
            value['guard_passed'] is False and value['error_type'] == 'AssertionError' and
            value['test_failure'] == POINT)


def receive_report(container, dest, variant, report):
    """Keep Docker command status, guest status and report acceptance separate.

    CI953 case_run requires docker wait to succeed, but does not require the
    returned guest status to be zero. A completed guest with status 1 therefore
    still has its report validated. No missing/invalid report can pass.
    """
    transport = {'variant': variant, 'wait_command_exit': None, 'guest_exit_status': None,
                 'report_copy_exit': None, 'report_valid': False}
    report['transports'].append(transport)
    report['phase'] = variant+'-wait-command'
    code, raw = ci.boundary.bounded(['/usr/bin/docker', 'wait', container], timeout=120)
    require(type(code) is int and -255 <= code <= 255, 'PROBE_WAIT_COMMAND_RED')
    transport['wait_command_exit'] = code
    require(code == 0, 'PROBE_WAIT_COMMAND_RED')
    report['phase'] = variant+'-guest-exit-payload'
    status = raw.strip()
    require(re.fullmatch(rb'(0|[1-9][0-9]{0,2})', status) is not None and int(status) <= 255,
            'PROBE_WAIT_PAYLOAD_RED')
    transport['guest_exit_status'] = int(status)
    report['phase'] = variant+'-report-copy'
    code, _ = ci.boundary.bounded(['/usr/bin/docker', 'cp', container+':/native-isolation-result.json', str(dest)], timeout=20)
    require(type(code) is int and -255 <= code <= 255, 'PROBE_REPORT_COPY_RED')
    transport['report_copy_exit'] = code
    require(code == 0, 'PROBE_REPORT_COPY_RED')
    report['phase'] = variant+'-report-read'
    try:
        require(dest.stat().st_size <= 16384, 'PROBE_REPORT_RED')
        raw = dest.read_bytes()
    except OSError:
        raise ProbeError('PROBE_REPORT_READ_RED') from None
    report['phase'] = variant+'-report-json'
    try: value = json.loads(raw)
    except (ValueError, UnicodeError): raise ProbeError('PROBE_REPORT_JSON_RED') from None
    report['phase'] = variant+'-report-validation'
    checked = validate(value)
    transport['report_valid'] = True
    return checked


def guest():
    from tests import public_operator_native as fixture
    value = {'schema': SCHEMA, 'conditions': dict(zip(BOOLS, (os.geteuid() == 0,
        Path('/.dockerenv').is_file(), os.environ.get('container') == 'docker'))),
        'guard_passed': False, 'error_type': None, 'test_failure': None,
        'source_files': source_hashes(), 'host_acceptance': False}
    try:
        fixture.assert_guest_isolation()  # unmodified real function, no substitutions
        value['guard_passed'] = True
    except BaseException as error:
        value['error_type'] = type(error).__name__ if type(error) in (AssertionError, RuntimeError) else 'OTHER'
        value['test_failure'] = diagnostics.capture(error)
    finally:
        ci.save(Path('/native-isolation-result.json'), json.dumps(value, sort_keys=True).encode())
        subprocess.run(['/usr/bin/systemctl', '--no-block', 'poweroff'], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=True)


def binding():
    require(sys.platform == 'linux' and Path('/etc/os-release').is_file() and
            'VERSION_ID="24.04"' in Path('/etc/os-release').read_text() and
            os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_EVENT_NAME') == 'push' and
            os.environ.get('GITHUB_REPOSITORY') == 'Tausendunde1nz/infra' and
            os.environ.get('GITHUB_REF') == 'refs/heads/'+BRANCH, 'PROBE_BINDING_RED')
    git = ['/usr/bin/git', '-C', str(ROOT)]
    sha = ci.command(git+['rev-parse', 'HEAD']).decode().strip()
    require(re.fullmatch('[a-f0-9]{40}', sha) and sha == os.environ.get('GITHUB_SHA') and
            ci.command(git+['rev-parse', 'HEAD^']).decode().strip() == PARENT and
            set(ci.command(git+['diff', '--name-only', BASE, sha]).decode().splitlines()) == ADDED and
            not ci.command(git+['status', '--porcelain', '--untracked-files=all']).strip(), 'PROBE_BINDING_RED')
    return sha


def driver(image):
    root = None; container = None; owner = uuid.uuid4().hex
    parent = Path(os.environ.get('RUNNER_TEMP', '/nonexistent'))
    report = {'schema': SCHEMA, 'green': False, 'host_acceptance': False, 'phase': 'binding',
              'guests': [], 'transports': [], 'cleanup_errors': [], 'temporary_inputs_removed': False}
    try:
        report['source_sha'] = binding(); report['source_files'] = source_hashes()
        require(image == 'tu1nz-ci953-probe:'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT'],
                'PROBE_BINDING_RED')
        root = ci.boundary.private_root(parent, ROOT)
        control = root/'synthetic-control'; inputs = root/'synthetic-inputs'
        for path in (control, inputs):
            path.mkdir(mode=0o700); ci.save(path/'synthetic.txt', b'SYNTHETIC ONLY\n')
        image_id = ci.command(['/usr/bin/docker', 'image', 'inspect', '--format', '{{.Id}}', image], timeout=15).decode().strip()
        require(re.fullmatch('sha256:[a-f0-9]{64}', image_id), 'PROBE_BINDING_RED')
        report['image_id'] = image_id
        for changed in (False, True):
            variant = 'unit-environment' if changed else 'original-unit'
            report['phase'] = variant+'-create'
            # Keep identity even after unclear create ACK: label-checked cleanup in finally.
            container = 'tu1nz-ci953-'+owner+'-'+variant
            ci.command(ci.native_argv(ROOT, control, image, container, owner, runtime_inputs=inputs), timeout=30)
            ci.inspect_guest(container, owner, ROOT, control, image_id, runtime_inputs=inputs)
            report['phase'] = variant+'-boot'
            ci.command(['/usr/bin/docker', 'start', container], timeout=30); ci.ready(container)
            unit = root/(variant+'.service'); ci.save(unit, unit_bytes(changed))
            report['phase'] = variant+'-unit'
            ci.command(['/usr/bin/docker', 'cp', str(unit), container+':/etc/systemd/system/tu1nz-rev4-native-fixture.service'], timeout=15)
            ci.command(['/usr/bin/docker', 'exec', container, '/usr/bin/systemctl', 'daemon-reload'], timeout=20)
            ci.command(['/usr/bin/docker', 'exec', container, '/usr/bin/systemctl', 'start', '--no-block', 'tu1nz-rev4-native-fixture.service'], timeout=20)
            # Diagnostic bound only; no production entry or entry deadline changes.
            dest = root/(variant+'.json')
            value = receive_report(container, dest, variant, report)
            report['phase'] = variant+'-cleanup'
            ci.boundary.cleanup_container(container, owner); container = None
            row = {'variant': variant, 'unit_sha256': hashlib.sha256(unit.read_bytes()).hexdigest(),
                   'result': value, 'guest_process_ended': True, 'guest_removed': True}
            report['guests'].append(row)
            print(json.dumps({'schema': SCHEMA, 'completed_guest': row, 'host_acceptance': False}, sort_keys=True), flush=True)
            report['phase'] = variant+'-comparison'
            if not changed: require(only_missing_environment(value), 'PROBE_UNEXPECTED_BASELINE')
            else: require(value['guard_passed'] is True, 'PROBE_CHANGED_GUEST_RED')
        report['green'] = True; report['phase'] = 'complete'
    except BaseException as error:
        report['green'] = False
        report['code'] = str(error) if type(error) is ProbeError and str(error) in ERRORS else 'PROBE_COMMAND_RED'
        report['error_type'] = type(error).__name__ if type(error).__name__ in ci.SAFE_FAILURE_TYPES else 'OTHER'
    finally:
        if container is not None:
            try: ci.boundary.cleanup_container(container, owner)
            except BaseException: report['cleanup_errors'].append('GUEST_CLEANUP_RED')
        if root is not None:
            try: ci.boundary.remove_private(root, parent); report['temporary_inputs_removed'] = True
            except BaseException: report['cleanup_errors'].append('INPUT_CLEANUP_RED')
        report['green'] = report['green'] and not report['cleanup_errors'] and report['temporary_inputs_removed']
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['green'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image'); parser.add_argument('--case', choices=('original',))
    parser.add_argument('--phase', choices=('calibration',))
    args = parser.parse_args()
    if args.case == 'original' and args.phase == 'calibration' and args.image is None:
        guest()
    elif args.image and args.case is None and args.phase is None:
        with ci.boundary.interrupted(): raise SystemExit(driver(args.image))
    else: parser.error('invalid probe mode')
