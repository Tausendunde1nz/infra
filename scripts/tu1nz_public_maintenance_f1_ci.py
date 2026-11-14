"""One F1 calibration counterprobe; never a full native or Host acceptance.

The guest, inputs, Unit, assertions and clocks are the unchanged a4646018 path.
Only a PR-241 first attempt with the bound Transient-absence fix is admitted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tu1nz_public_maintenance_ci as maintenance

ci = maintenance.ci
BASE = 'a46460183bfd4bdb893f3798174fb1808a9883d6'
CHANGES = frozenset(('.github/workflows/mainserver-f1-diagnostic.yml',
    'scripts/tu1nz_public_maintenance_f1_ci.py', 'tests/test_public_maintenance_f1_ci.py',
    'scripts/tu1nz_public_runtime_transition.py', 'tests/test_public_maintenance.py'))
SOURCE_PATH = 'scripts/tu1nz_public_runtime_transition.py'
SOURCE_SHA256 = '981e70dd5cddbe42ca58f1046db93ceb50c8f79fefbd6028e3e393428d97b567'
SCHEMA = 'TU1NZ_REV4_F1_COUNTERPROBE_V1'
CASE = 'recovery_F1'
PHASE = 'calibration'


def binding(workspace, env):
    ci.require(env.get('GITHUB_EVENT_NAME') == 'pull_request' and
        env.get('GITHUB_REF') == 'refs/pull/241/merge' and
        env.get('GITHUB_RUN_ATTEMPT') == '1', 'F1_DIAGNOSTIC_CONTEXT_RED')
    sha = ci.boundary.runtime_binding(env, workspace)
    event = json.loads(Path(env['GITHUB_EVENT_PATH']).read_bytes())
    ci.require(type(event.get('number')) is int and event['number'] == 241,
        'F1_DIAGNOSTIC_CONTEXT_RED')
    git = ['/usr/bin/git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
        '-c', 'core.hooksPath=/dev/null', '-C', str(workspace)]
    ci.command(git+['merge-base', '--is-ancestor', BASE, sha], timeout=10)
    delta = ci.command(git+['diff', '--no-ext-diff', '--no-renames', '--name-status',
        '-z', BASE, sha, '--'], timeout=10)
    expected = {b'M\0'+path.encode()+b'\0' for path in CHANGES}
    # Exact five-file delta plus the fixed corrected production bytes.
    # Fixture, native assertions, clocks and regular workflow stay unchanged.
    parts = delta.split(b'\0')
    ci.require(parts[-1:] == [b''] and len(parts) == 11 and
        {parts[n]+b'\0'+parts[n+1]+b'\0' for n in range(0, 10, 2)} == expected,
        'F1_DIAGNOSTIC_BASE_CHANGED')
    ci.require(hashlib.sha256((workspace/SOURCE_PATH).read_bytes()).hexdigest() == SOURCE_SHA256,
        'F1_DIAGNOSTIC_SOURCE_CHANGED')
    return sha


def failed_report(root):
    """Read only the already copied private report; publish the existing filter."""
    try:
        path = root/(PHASE+'-'+CASE+'-result.json')
        with path.open('rb') as stream: raw = stream.read(256*1024+1)
        ci.require(len(raw) <= 256*1024, 'REV4_NATIVE_PRIVATE_RESULT_BOUND')
        value = json.loads(raw)
        ci.require(type(value) is dict and value.get('schema') == 'TU1NZ_REV4_NATIVE_CASE_V1' and
            value.get('case') == CASE and value.get('phase') == PHASE and
            value.get('green') is False and value.get('host_acceptance') is False,
            'REV4_NATIVE_CASE_RED')
        return maintenance.safe_failure(value, CASE, PHASE)
    except (OSError, ValueError, ci.CIError):
        return None


def one_case(workspace, control, image, image_id, owner, root, inputs, hashes):
    result = {'schema': SCHEMA, 'case': CASE, 'phase': PHASE, 'green': False,
        'code': 'F1_DIAGNOSTIC_RED', 'native_batch_pass': False, 'host_acceptance': False,
        'report_status': 'MISSING_OR_INVALID', 'guest_cleanup': 'NOT_PROVED'}
    cleanup = ci.boundary.cleanup_container
    outcomes = []
    expected = 'tu1nz-rev4-'+owner+'-calibration-recovery-f1'

    def observed_cleanup(name, actual_owner):
        # Observe the existing finally cleanup, without an extra guest action,
        # retry, or a changed cleanup implementation. Never infer success from
        # a missing call. A previous cleanup failure remains visible.
        ci.require(name == expected and actual_owner == owner, 'F1_DIAGNOSTIC_CLEANUP_BINDING_RED')
        outcomes.append(False)
        cleanup(name, actual_owner)
        outcomes[-1] = True

    ci.boundary.cleanup_container = observed_cleanup
    try:
        value = maintenance.case_run(workspace, control, image, image_id, owner,
            root, inputs, hashes, CASE, PHASE)
        maintenance.validate_case(value, CASE, PHASE, hashes)
        row = value['run']
        result.update(green=True, code='F1_DIAGNOSTIC_GREEN', report_status='VALIDATED_PASS',
            elapsed_milliseconds=row['elapsed_milliseconds'],
            reserve_milliseconds=600000-row['elapsed_milliseconds'],
            owner_milliseconds=row['owner_milliseconds'], owner_intents=row['owner_intents'],
            owner_acks=row['owner_acks'], entry_cleanup_complete=row['cleanup_complete'],
            original_failed_hold_preserved=value['original_failed_hold_preserved'],
            second_recovery_denied_before_SSH=value['second_recovery_denied_before_SSH'])
    except BaseException:
        failure = failed_report(root)
        if failure is not None:
            result.update(report_status='FILTERED_FAILURE', failure=failure)
    finally:
        ci.boundary.cleanup_container = cleanup
        result['guest_cleanup'] = 'PASS' if outcomes and all(outcomes) else ('FAIL' if outcomes else 'NOT_PROVED')
        if result['guest_cleanup'] != 'PASS':
            result['green'] = False
            result['code'] = 'F1_DIAGNOSTIC_RED'
    return result


def run(workspace, image):
    parent = Path(os.environ.get('RUNNER_TEMP', '/nonexistent'))
    root = None
    owner = uuid.uuid4().hex
    stage = 'admission'
    result = {'schema': SCHEMA, 'case': CASE, 'phase': PHASE, 'green': False,
        'code': 'F1_DIAGNOSTIC_RED', 'native_batch_pass': False, 'host_acceptance': False}
    try:
        token = os.environ.pop('CONTROL_POLICY_READ_TOKEN', None)
        sha = binding(workspace, os.environ)
        ci.require(type(token) is str and token.startswith('github_pat_'), 'READ_CREDENTIAL_MISSING')
        ci.require(image == 'tu1nz-public-operator-private:'+os.environ['GITHUB_RUN_ID']+'-1',
            'FRESH_IMAGE_BINDING_RED')
        image_id = ci.command(['/usr/bin/docker', 'image', 'inspect', '--format', '{{.Id}}', image]).decode().strip()
        ci.require(re.fullmatch('sha256:[a-f0-9]{64}', image_id), 'IMAGE_ID_RED')
        root = ci.boundary.private_root(parent, workspace)
        stage = 'private-source'
        control, hashes = ci.fetch_control(root, token)
        token = None
        hashes.update({n: hashlib.sha256((workspace/p).read_bytes()).hexdigest()
            for n, p in ci.operator.INFRA_FILES.items()})
        stage = 'runtime-public-inputs'
        import tu1nz_public_runtime_build as build
        inputs = json.loads((workspace/'manifests/public-web-runtime-r5-inputs.json').read_bytes())
        runtime_inputs = root/'runtime-inputs'
        runtime_inputs.mkdir(mode=0o700)
        for row in [inputs['python'], *inputs['wheels']]:
            ci.save(runtime_inputs/row['filename'], build.fetch(row))
        stage = 'F1-calibration'
        result = one_case(workspace, control, image, image_id, owner, root, runtime_inputs, hashes)
        result['source_sha'] = sha
    except BaseException:
        # No exception text, child output, private paths or credential values.
        result.update(green=False, code='F1_DIAGNOSTIC_RED', stage=stage)
    finally:
        result = ci.cleanup_result(result, None, owner, root, parent)
        result['private_input_cleanup'] = ('NOT_CREATED' if root is None else
            ('FAIL' if 'PRIVATE_INPUT_CLEANUP_RED' in result.get('cleanup_errors', []) else 'PASS'))
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['green'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    with ci.boundary.interrupted():
        raise SystemExit(run(Path(__file__).resolve().parents[1], args.image))
