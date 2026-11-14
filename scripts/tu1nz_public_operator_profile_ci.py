"""Test-only R5 measurement in the regular adapter sequence, never Host admission.

CPU wrappers and sampling are reused from fe4d684. Only r5_success uses this
entry. The original native AST changes solely at READ_COST_WRAPPER. Parent
argv differs; SELF CPU excludes child/systemd CPU, inclusive costs overlap.
The microprobe precedes native execution; cgroup counters cover that native
execution including fixture setup, not the complete container lifetime.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import tu1nz_public_operator_profile_cpu as profile

NATIVE_SHA = '424ec86dd553733a749dcbed9ac78e7ab9f930a488b809585ac52482f3e955d7'
MODES = ('profile',)
META = b'{"r5_performance_metadata":'


class ProbeError(RuntimeError):
    pass


def require(ok, code):
    if not ok: raise ProbeError(code)


def prepared_native(raw, mode):
    require(mode in MODES and hashlib.sha256(raw).hexdigest() == NATIVE_SHA, 'BINDING_RED')
    filename = str(ROOT/'tests/public_operator_native.py')
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
    # Same native sys.argv/filename as the regular test; parent actual argv
    # differs. All preceding scenarios run unmodified in their usual order.
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
    require(mode == 'profile', 'METADATA_RED')
    if value['profile'] is not None: profile.validate(value['profile'])
    return value


def extract(raw):
    """Return only strict, bounded metadata; keep native failure parsing separate.

    Missing/truncated/invalid reports never manufacture measurements or a PASS.
    This parser runs after the native process exits, outside Owner timing.
    """
    if type(raw) is not bytes or len(raw) > 262144:
        return raw, None
    lines = [line for line in raw.splitlines() if line.startswith(META)]
    if len(lines) != 1:
        return raw, None
    native = b'\n'.join(line for line in raw.splitlines() if line != lines[0])
    try:
        outer = json.loads(lines[0])
        require(type(outer) is dict and set(outer) == {'r5_performance_metadata'}, 'METADATA_RED')
        return native, validate_metadata(outer['r5_performance_metadata'], 'profile')
    except (ValueError, TypeError, KeyError, ProbeError):
        return native, None


if __name__ == '__main__':
    # Only the fixed synthetic R5 guest. No branch/credential admission,
    # dispatch, second guest or changes to the regular CI runtime_binding.
    try: raise SystemExit(guest('profile'))
    except Exception:
        # Never export exception text, arbitrary /proc content or a traceback.
        print('{"r5_profile_error":"GUEST_MEASUREMENT_RED"}', flush=True)
        raise SystemExit(1) from None
