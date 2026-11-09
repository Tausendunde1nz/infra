"""One protected native diagnostic job, at most two serial synthetic guests.

All production/fixture sources and assertions remain at CI959. The second
guest adds fixed-label SELF-CPU timing in memory. Neither result admits a Host.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/'scripts'))
from tests import ci959_r5_profile as profile
import tu1nz_public_operator_ci as ci

BASE = 'd8e1ecd509224ffcc3ab62524831fb99c30f9cc8'
BRANCH = 'codex/ci959-r5-performance-20261109'
NATIVE_SHA = '424ec86dd553733a749dcbed9ac78e7ab9f930a488b809585ac52482f3e955d7'
ADDED = {'.github/workflows/ci959-r5-performance.yml', 'tests/ci959_r5_performance.py',
         'tests/ci959_r5_profile.py', 'tests/test_ci959_r5_performance.py'}
SCHEMA = 'TU1NZ_CI959_R5_PERFORMANCE_V1'
MODES = ('control', 'profile')
META = b'{"r5_performance_metadata":'
ERRORS = frozenset(('BINDING_RED', 'IMAGE_RED', 'CREDENTIAL_RED', 'METADATA_RED',
    'NATIVE_REPORT_RED', 'PROFILE_MISSING', 'NATIVE_UNEXPECTED_FAILURE',
    'CONTAINER_CLEANUP_RED', 'PRIVATE_CLEANUP_RED', 'PROBE_RED'))


class ProbeError(RuntimeError):
    pass


def require(ok, code):
    if not ok: raise ProbeError(code)


def git(*args):
    return ci.command(['/usr/bin/git', '--no-optional-locks', '--no-replace-objects',
        '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-C', str(ROOT), *args], timeout=15)


def binding(env):
    # Separate exact diagnostic PUSH admission, not a change to the production
    # runtime_binding/APPROVED_SOURCE_PRS. GitHub Environment protection must
    # admit this exact branch and reviewed SHA before any step/private input.
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_REPOSITORY') == ci.boundary.REPOSITORY
        and env.get('CONTROL_PRIVATE_ENVIRONMENT') == ci.boundary.ENVIRONMENT
        and env.get('GITHUB_EVENT_NAME') == 'push' and env.get('GITHUB_REF') == 'refs/heads/'+BRANCH
        and env.get('GITHUB_RUN_ATTEMPT') == '1', 'BINDING_RED')
    event = json.loads(Path(env['GITHUB_EVENT_PATH']).read_bytes())
    sha = env.get('GITHUB_SHA')
    require(type(sha) is str and re.fullmatch('[a-f0-9]{40}', sha) and
        sha == env.get('EXPECTED_SOURCE_SHA') == event.get('after') and
        event.get('ref') == 'refs/heads/'+BRANCH and
        event.get('repository', {}).get('full_name') == ci.boundary.REPOSITORY and
        event.get('head_commit', {}).get('message', '').startswith('CI959: one bounded R5 performance probe'), 'BINDING_RED')
    require(git('rev-parse', 'HEAD').decode().strip() == sha and
        git('rev-parse', 'HEAD^').decode().strip() == BASE and
        not git('status', '--porcelain=v1', '--untracked-files=all') and
        not git('ls-files', '--others', '--ignored', '--exclude-standard', '-z'), 'BINDING_RED')
    changed = git('diff', '--name-status', BASE, 'HEAD').decode().splitlines()
    require(set(changed) == {'A\t'+p for p in ADDED}, 'BINDING_RED')
    require(hashlib.sha256((ROOT/'tests/public_operator_native.py').read_bytes()).hexdigest() == NATIVE_SHA,
        'BINDING_RED')
    return sha


def prepared_native(raw, mode):
    require(mode in MODES and hashlib.sha256(raw).hexdigest() == NATIVE_SHA, 'BINDING_RED')
    filename = str(ROOT/'tests/public_operator_native.py')
    if mode == 'control': return compile(raw, filename, 'exec')
    tree = ast.parse(raw, filename)
    candidates = [n for n in tree.body if isinstance(n, ast.Assign) and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'READ_COST_WRAPPER']
    require(len(candidates) == 1 and isinstance(candidates[0].value, ast.Constant)
        and type(candidates[0].value.value) is str, 'BINDING_RED')
    candidates[0].value.value += profile.WRAPPER
    # No other AST node, assertion, function, delegate, result or deadline changes.
    return compile(tree, filename, 'exec')


def cpu_metadata():
    # Fixed non-secret numeric CPU classes only, no hostname, serial, model
    # string, env dump or arbitrary /proc text. No claim about CPU frequency.
    first = Path('/proc/cpuinfo').read_text().split('\n\n', 1)[0]
    fields = {key.strip(): value for key, value in
        (line.split(':', 1) for line in first.splitlines() if ':' in line)}
    vendor = fields.get('vendor_id', '').strip()
    return {'vendor': vendor if vendor in ('GenuineIntel', 'AuthenticAMD') else 'OTHER',
        'family': int(fields.get('cpu family', '-1').strip()),
        'model': int(fields.get('model', '-1').strip()),
        'stepping': int(fields.get('stepping', '-1').strip()),
        'affinity_cpus': len(os.sched_getaffinity(0)), 'python': list(sys.version_info[:3])}


def cgroup_cpu():
    # Container-scoped cumulative accounting, not exclusively coordinator CPU.
    wanted = {'usage_usec', 'user_usec', 'system_usec', 'nr_periods', 'nr_throttled', 'throttled_usec'}
    try:
        fields = dict(line.split() for line in Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())
        return {k: int(fields[k]) for k in wanted}
    except (OSError, KeyError, ValueError): return None


def microprobe(raw):
    tree = ast.parse(raw)
    wrapper = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == 'READ_COST_WRAPPER' for t in n.targets))
    ns = {}; exec(compile(wrapper.split('_observer=s.load("observe")', 1)[0]+profile.CORE,
        '<synthetic-cpu-wrapper-probe>', 'exec'), ns)
    ns['_owner_phase'] = 'apply'
    def noop(): return 1
    cost = ns['_cost']('synthetic', noop)
    both = ns['_pc_wrap']('process', cost)
    rows = []
    for _ in range(3):
        row = {}
        for name, actual in (('plain', noop), ('existing_cost', cost), ('with_cpu', both)):
            wall = time.monotonic_ns(); cpu = time.process_time_ns()
            for _ in range(10000): assert actual() == 1
            row[name] = {'cpu_ns': time.process_time_ns()-cpu, 'wall_ns': time.monotonic_ns()-wall}
        rows.append(row)
    assert ns['_read_cost']['synthetic']['calls'] == 60000 and not ns['_cost_stack'] and not ns['_pc_stack']
    return rows


def guest(mode):
    require(sys.platform == 'linux' and os.geteuid() == 0 and Path('/.dockerenv').is_file()
        and os.environ.get('container') == 'docker', 'BINDING_RED')
    raw = (ROOT/'tests/public_operator_native.py').read_bytes()
    program = prepared_native(raw, mode)
    metadata = {'mode': mode, 'cpu': cpu_metadata(), 'microprobe': microprobe(raw),
        'cgroup_before': cgroup_cpu(), 'cgroup_after': None, 'profile': None}
    # Same native argument vector/filename in BOTH guests. Parent's actual
    # argv differs from CI959: this is a diagnostic-context limitation.
    sys.argv = [str(ROOT/'tests/public_operator_native.py'), '--scenario', 'r5_success']
    code = 0
    try:
        exec(program, {'__name__': '__main__', '__file__': sys.argv[0], '__package__': None})
    except SystemExit as error:
        code = error.code if type(error.code) is int and 0 <= error.code <= 255 else 1
    finally:
        metadata['cgroup_after'] = cgroup_cpu()
        if mode == 'profile':
            p = Path('/fixture-r4/cpu-profile.json')
            if p.is_file() and not p.is_symlink():
                require(p.stat().st_size <= 65536, 'METADATA_RED')
                metadata['profile'] = profile.validate(json.loads(p.read_bytes()))
        print(json.dumps({'r5_performance_metadata': metadata}, sort_keys=True), flush=True)
    return code


def uint(value, upper):
    return type(value) is int and 0 <= value <= upper


def validate_metadata(value, mode):
    require(type(value) is dict and set(value) == {'mode', 'cpu', 'microprobe',
        'cgroup_before', 'cgroup_after', 'profile'} and value['mode'] == mode, 'METADATA_RED')
    cpu = value['cpu']
    require(type(cpu) is dict and set(cpu) == {'vendor', 'family', 'model', 'stepping', 'affinity_cpus', 'python'}
        and cpu['vendor'] in ('GenuineIntel', 'AuthenticAMD', 'OTHER') and
        all(type(cpu[k]) is int and -1 <= cpu[k] <= 65535 for k in ('family', 'model', 'stepping'))
        and uint(cpu['affinity_cpus'], 4096) and cpu['affinity_cpus'] > 0 and
        type(cpu['python']) is list and len(cpu['python']) == 3 and all(uint(n, 100) for n in cpu['python']), 'METADATA_RED')
    rows = value['microprobe']
    require(type(rows) is list and len(rows) == 3, 'METADATA_RED')
    for row in rows:
        require(type(row) is dict and set(row) == {'plain', 'existing_cost', 'with_cpu'}, 'METADATA_RED')
        for sample in row.values():
            require(type(sample) is dict and set(sample) == {'cpu_ns', 'wall_ns'}
                and all(uint(n, 60_000_000_000) for n in sample.values()), 'METADATA_RED')
    for key in ('cgroup_before', 'cgroup_after'):
        stat = value[key]
        require(stat is None or type(stat) is dict and set(stat) == {'usage_usec', 'user_usec', 'system_usec',
            'nr_periods', 'nr_throttled', 'throttled_usec'} and all(uint(v, 10**18) for v in stat.values()), 'METADATA_RED')
    if mode == 'control': require(value['profile'] is None, 'METADATA_RED')
    elif value['profile'] is not None: profile.validate(value['profile'])
    return value


def parse_guest(code, raw, mode, hashes):
    require(type(code) is int and code in (0, 1) and type(raw) is bytes and len(raw) <= 262144, 'NATIVE_REPORT_RED')
    meta_lines = [line for line in raw.splitlines() if line.startswith(META)]
    require(len(meta_lines) == 1, 'METADATA_RED')
    outer = json.loads(meta_lines[0]); require(set(outer) == {'r5_performance_metadata'}, 'METADATA_RED')
    meta = validate_metadata(outer['r5_performance_metadata'], mode)
    native = b'\n'.join(line for line in raw.splitlines() if line != meta_lines[0])
    if code == 0:
        report = ci.validate_report(native, 'r5_success', hashes)
        record = {'native_result': 'PASS', 'native_exit': 0, 'owner_timing': report['owner_timing'],
            'failure': None, 'owner_confirmations': 84}
    else:
        failure = ci.failure_location(native)
        require(failure is not None, 'NATIVE_REPORT_RED')
        record = {'native_result': 'FAIL', 'native_exit': code, 'owner_timing': failure.get('owner_timing'),
            'failure': failure, 'owner_confirmations': failure.get('outcome', {}).get('owner_confirmations')}
    return {**record, 'metadata': meta}


def may_continue(record):
    # A completed failing assertion stays FAIL. Only the already observed
    # Owner deadline, or a genuine native PASS, permits the second diagnostic.
    return record['native_result'] == 'PASS' or (
        record['failure'].get('outcome', {}).get('server_terminal_code') == 'PUBLIC_OPERATOR_WIRE_DEADLINE'
        and record['failure']['outcome'].get('server_exit') == 1
        and record['failure']['outcome'].get('abort') == [] and record['failure']['outcome'].get('cleanup') == []
        and record['owner_timing'] is not None and record['owner_timing']['started']
        and record['owner_timing']['stack_empty'])


def bound_image(image, env):
    run_id, attempt = env.get('GITHUB_RUN_ID', ''), env.get('GITHUB_RUN_ATTEMPT', '')
    require(re.fullmatch('[1-9][0-9]*', run_id) and attempt == '1' and
        image == 'tu1nz-ci959-performance:'+run_id+'-'+attempt, 'IMAGE_RED')
    return image


def cleanup_image(image, env):
    # A failed Docker query is never proof of absence. Restrict both queries
    # and the optional removal to this run's exact tag, never an image ID.
    bound_image(image, env)
    def present():
        raw = ci.command(['/usr/bin/docker', 'image', 'ls', '--no-trunc',
            '--filter', 'reference='+image, '--format', '{{.ID}}'], timeout=30)
        require(raw == b'' or re.fullmatch(rb'sha256:[a-f0-9]{64}\n?', raw), 'IMAGE_RED')
        return bool(raw)
    if present(): ci.command(['/usr/bin/docker', 'image', 'rm', image], timeout=30)
    require(not present(), 'IMAGE_RED')


def run(image):
    boundary = ci.boundary; owner = uuid.uuid4().hex
    root = container = None; parent = Path(os.environ.get('RUNNER_TEMP', '/nonexistent'))
    result = {'schema': SCHEMA, 'green': False, 'measurement_complete': False, 'records': [],
        'host_acceptance': False, 'regular_ci_acceptance': False, 'code': 'PROBE_RED',
        'container_absence_checks': 0, 'private_inputs_removed': False}
    phase = 'binding'
    try:
        token = os.environ.pop('CONTROL_POLICY_READ_TOKEN', None)
        sha = binding(os.environ); result['source_sha'] = sha
        require(type(token) is str and token.startswith('github_pat_'), 'CREDENTIAL_RED')
        bound_image(image, os.environ)
        image_id = ci.command(['/usr/bin/docker', 'image', 'inspect', '--format', '{{.Id}}', image]).decode().strip()
        require(re.fullmatch('sha256:[a-f0-9]{64}', image_id), 'IMAGE_RED')
        result['image_id'] = image_id
        root = boundary.private_root(parent, ROOT)
        phase = 'private-source'; control, hashes = ci.fetch_control(root, token); token = None
        hashes.update({n: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for n, p in ci.operator.INFRA_FILES.items()})
        phase = 'public-runtime'
        import tu1nz_public_runtime_build as build
        inputs = json.loads((ROOT/'manifests/public-web-runtime-r5-inputs.json').read_bytes())
        runtime = root/'runtime-inputs'; runtime.mkdir(mode=0o700)
        for row in [inputs['python'], *inputs['wheels']]: ci.save(runtime/row['filename'], build.fetch(row))
        for mode in MODES:
            phase = mode+'-create'; container = 'tu1nz-ci959-'+owner+'-'+mode
            ci.command(ci.native_argv(ROOT, control, image, container, owner, runtime_inputs=runtime), timeout=30)
            ci.inspect_guest(container, owner, ROOT, control, image_id, runtime_inputs=runtime)
            phase = mode+'-start'; ci.command(['/usr/bin/docker', 'start', container], timeout=30); ci.ready(container)
            phase = mode+'-native'; began = time.monotonic_ns()
            code, raw = boundary.bounded(['/usr/bin/docker', 'exec', container, '/usr/bin/python3', '-I', '-B',
                '/source/tests/ci959_r5_performance.py', '--guest', mode], timeout=720)
            ended = time.monotonic_ns()
            try: record = parse_guest(code, raw, mode, hashes)
            except BaseException:
                result['native_process'] = ci.native_process_diagnostic(code, raw)
                failure = ci.failure_location(raw)
                if failure is not None: result['failure_location'] = failure
                raise
            record.update(mode=mode, full_guest_test_process_ns=ended-began)
            result['records'].append(record)
            phase = mode+'-cleanup'; boundary.cleanup_container(container, owner); container = None
            result['container_absence_checks'] += 1; record['container_removed_processes_ended'] = True
            # Validated public progress after process end AND container removal.
            print(json.dumps({'schema': SCHEMA, 'progress': record, 'host_acceptance': False}, sort_keys=True), flush=True)
            if mode == 'control': require(may_continue(record), 'NATIVE_UNEXPECTED_FAILURE')
            else: require(record['metadata']['profile'] is not None, 'PROFILE_MISSING')
        result['measurement_complete'] = True
        result['green'] = all(r['native_result'] == 'PASS' for r in result['records'])
        result['code'] = 'DIAGNOSTIC_COMPLETE' if result['green'] else 'DIAGNOSTIC_COMPLETE_NATIVE_FAILURE_RETAINED'
    except BaseException as error:
        result.update(phase=phase, green=False,
            code=str(error) if type(error) is ProbeError and str(error) in ERRORS else 'PROBE_RED')
    finally:
        if container is not None:
            try:
                boundary.cleanup_container(container, owner); result['container_absence_checks'] += 1
            except BaseException: result['green'] = False; result['container_cleanup_error'] = 'CONTAINER_CLEANUP_RED'
        if root is not None:
            try: boundary.remove_private(root, parent); result['private_inputs_removed'] = True
            except BaseException: result['green'] = False; result['private_cleanup_error'] = 'PRIVATE_CLEANUP_RED'
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['green'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--guest', choices=MODES); group.add_argument('--image'); group.add_argument('--cleanup-image')
    args = parser.parse_args()
    if args.guest:
        try: raise SystemExit(guest(args.guest))
        except ProbeError: raise SystemExit(1) from None
    elif args.cleanup_image:
        try:
            with ci.boundary.interrupted(): cleanup_image(args.cleanup_image, os.environ)
        except BaseException:
            print('{"diagnostic_image_cleanup":"RED"}', flush=True)
            raise SystemExit(1) from None
        print('{"diagnostic_image_cleanup":"PASS"}', flush=True)
    else:
        with ci.boundary.interrupted(): raise SystemExit(run(args.image))
