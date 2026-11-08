"""CI954 manager-profile diagnosis in fresh synthetic Ubuntu guests.

Same image/Unit settings as4b66; entry filename alone selects this probe.
Compare actual search-object metadata using the unchanged Source predicate.
Only if the copied fixture Unit is the sole unsafe object, correct its UID/GID
in a second fresh guest. No private source, maintenance entry or Host access.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT/'scripts'))
import tu1nz_public_operator_ci as ci
import tu1nz_public_maintenance_diagnostics as diagnostics

BASE = '4b66e25571f194dca3ee7580be65b35409c3d246'
PARENT = BASE
BRANCH = 'codex/ci954-manager-profile-probe-20261108'
ADDED = {'.github/workflows/ci954-manager-profile-probe.yml',
         'tests/ci954_manager_profile_probe.py', 'tests/test_ci954_manager_profile_probe.py'}
BOUND = ('tests/public-operator-native.Dockerfile', 'tests/public_operator_native_init.py',
         'tests/s8_native_init.py', 'tests/public_operator_native.py',
         'scripts/tu1nz_public_operator_ci.py', 'scripts/tu1nz_public_maintenance_ci.py',
         'scripts/tu1nz_control_private_ci.py', 'scripts/tu1nz_public_maintenance_diagnostics.py',
         'scripts/tu1nz_public_operator_observe.py')
SCHEMA = 'TU1NZ_CI954_ISOLATION_PROBE_V1'
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


UNIT_PATH = '/etc/systemd/system/tu1nz-rev4-native-fixture.service'


def source_expressions():
    tree=ast.parse((ROOT/'scripts/tu1nz_public_operator_observe.py').read_bytes())
    authority=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Authority')
    search=next(n for n in authority.body if isinstance(n,ast.FunctionDef) and n.name=='search_directory')
    calls=[n for n in ast.walk(search) if isinstance(n,ast.Call) and len(n.args)==2 and
        isinstance(n.args[1],ast.Constant) and n.args[1].value=='UNSAFE_MANAGER_SEARCH_OBJECT']
    require(len(calls)==1,'PROBE_BINDING_RED')
    unit_search=next(n for n in authority.body if isinstance(n,ast.FunctionDef) and n.name=='unit_search')
    allowed=next(n.value for n in unit_search.body if isinstance(n,ast.Assign) and
        any(isinstance(t,ast.Name) and t.id=='allowed' for t in n.targets))
    return calls[0].args[0],ast.literal_eval(allowed)


def manager_profile():
    """Metadata only; evaluate the exact failed predicate, no substitute guard.

    This is not the complete unit_search content/fence proof. That remains in
    regular CI. Fixed synthetic guest paths only; no file contents are read.
    """
    expression,allowed=source_expressions()
    predicate=compile(ast.Expression(expression),'<bound-manager-predicate>','eval')
    roots=ci.command(['/usr/bin/systemctl','show','--property=UnitPath','--value'],timeout=15).decode().split()
    require(len(roots)==len(set(roots)) and set(roots)==allowed,'PROBE_BINDING_RED')
    result={'objects_examined':0,'offenders':[]};end=time.monotonic()+60
    def walk(fd,parent,depth):
        require(depth<32 and time.monotonic()<end,'PROBE_COMMAND_RED')
        for name in sorted(os.listdir(fd)):
            result['objects_examined']+=1
            require(result['objects_examined']<=8192 and time.monotonic()<end,'PROBE_COMMAND_RED')
            path=parent+'/'+name;s=os.stat(name,dir_fd=fd,follow_symlinks=False)
            if not eval(predicate,{'__builtins__':{},'stat':stat},{'s':s}):
                result['offenders'].append({'object':'FIXTURE_UNIT' if path==UNIT_PATH else 'OTHER_SEARCH_OBJECT',
                    'path_sha256':hashlib.sha256(path.encode()).hexdigest(),'uid':s.st_uid,'gid':s.st_gid,
                    'mode':stat.S_IMODE(s.st_mode),'nlink':s.st_nlink,'regular_file':stat.S_ISREG(s.st_mode)})
                require(len(result['offenders'])<=16,'PROBE_REPORT_RED')
            if stat.S_ISDIR(s.st_mode):
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:walk(child,path,depth+1)
                finally:os.close(child)
    for root in roots:
        try:fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        except FileNotFoundError:continue
        try:walk(fd,root,0)
        finally:os.close(fd)
    return result


def validate_profile(value):
    require(type(value) is dict and set(value)=={'objects_examined','offenders'} and
        type(value['objects_examined']) is int and 0<value['objects_examined']<=8192 and
        type(value['offenders']) is list and len(value['offenders'])<=16,'PROBE_REPORT_RED')
    for row in value['offenders']:
        require(type(row) is dict and set(row)=={'object','path_sha256','uid','gid','mode','nlink','regular_file'} and
            row['object'] in ('FIXTURE_UNIT','OTHER_SEARCH_OBJECT') and type(row['path_sha256']) is str and
            re.fullmatch('[a-f0-9]{64}',row['path_sha256']) and type(row['regular_file']) is bool and
            all(type(row[k]) is int and 0<=row[k]<2**32 for k in ('uid','gid')) and
            type(row['mode']) is int and 0<=row['mode']<=0o7777 and
            type(row['nlink']) is int and 0<row['nlink']<=65536,'PROBE_REPORT_RED')
        if row['object']=='FIXTURE_UNIT':
            require(row['path_sha256']==hashlib.sha256(UNIT_PATH.encode()).hexdigest(),'PROBE_REPORT_RED')
    return value


def fix_copied_unit_owner(container,unit):
    # Only our just-created private fixture Unit in the second isolated guest.
    # Prove bytes/profile before fchown, retain mode and verify the same FD/name.
    program='''import hashlib,os,stat,sys
p="/etc/systemd/system/tu1nz-rev4-native-fixture.service"
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
 assert (s.st_uid,s.st_gid)==(int(sys.argv[1]),int(sys.argv[2])) and s.st_size<=4096
 raw=os.pread(fd,4097,0);assert len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==sys.argv[3]
 os.fchown(fd,0,0)
 a=os.fstat(fd);n=os.stat(p,follow_symlinks=False)
 assert (a.st_dev,a.st_ino,a.st_uid,a.st_gid,a.st_mode,a.st_nlink,a.st_size)==(s.st_dev,s.st_ino,0,0,s.st_mode,1,s.st_size)
 assert (n.st_dev,n.st_ino)==(a.st_dev,a.st_ino) and os.pread(fd,4097,0)==raw
finally:os.close(fd)
'''
    ci.command(['/usr/bin/docker','exec',container,'/usr/bin/python3','-I','-B','-S','-c',program,
        str(os.geteuid()),str(os.getegid()),hashlib.sha256(unit.read_bytes()).hexdigest()],timeout=15)


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
            and raw.count(b'Environment=container=docker\n') == 1, 'PROBE_UNIT_SHAPE_RED')
    raw = raw.replace(old, b'/source/tests/ci954_manager_profile_probe.py')
    return raw


def source_hashes():
    return {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in BOUND}


def validate(value):
    require(type(value) is dict and set(value) == {'schema', 'conditions', 'guard_passed',
            'error_type', 'test_failure', 'source_files', 'host_acceptance', 'manager_profile'} and value['schema'] == SCHEMA
            and value['host_acceptance'] is False and value['source_files'] == source_hashes(), 'PROBE_REPORT_RED')
    flags = value['conditions']
    require(type(flags) is dict and set(flags) == set(BOOLS) and
            all(type(flags[k]) is bool for k in BOOLS) and type(value['guard_passed']) is bool, 'PROBE_REPORT_RED')
    if value['guard_passed']:
        require(all(flags.values()) and value['error_type'] is None and value['test_failure'] is None, 'PROBE_REPORT_RED')
    else:
        require(value['error_type'] in ('AssertionError', 'RuntimeError', 'OTHER') and
                diagnostics.validated(value['test_failure']) is not None, 'PROBE_REPORT_RED')
    validate_profile(value['manager_profile'])
    return value


def only_copied_unit_owner(value):
    validate(value)
    profile=value['manager_profile'];bad=profile['offenders']
    return (all(value['conditions'].values()) and value['guard_passed'] is True and
        len(bad)==1 and bad[0]['object']=='FIXTURE_UNIT' and bad[0]['uid']!=0 and
        bad[0]['uid']==os.geteuid() and bad[0]['gid']==os.getegid() and
        bad[0]['mode']==0o600 and bad[0]['regular_file'] is True and bad[0]['nlink']==1)


def receive_report(container, dest, variant, report):
    """Keep Docker command status, guest status and report acceptance separate.

    CI954 case_run requires docker wait to succeed, but does not require the
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
        'source_files': source_hashes(), 'host_acceptance': False, 'manager_profile': None}
    try:
        fixture.assert_guest_isolation()  # unmodified real function, no substitutions
        value['guard_passed'] = True
        value['manager_profile'] = manager_profile()
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
        require(image == 'tu1nz-ci954-probe:'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT'],
                'PROBE_BINDING_RED')
        root = ci.boundary.private_root(parent, ROOT)
        control = root/'synthetic-control'; inputs = root/'synthetic-inputs'
        for path in (control, inputs):
            path.mkdir(mode=0o700); ci.save(path/'synthetic.txt', b'SYNTHETIC ONLY\n')
        image_id = ci.command(['/usr/bin/docker', 'image', 'inspect', '--format', '{{.Id}}', image], timeout=15).decode().strip()
        require(re.fullmatch('sha256:[a-f0-9]{64}', image_id), 'PROBE_BINDING_RED')
        report['image_id'] = image_id
        for changed in (False, True):
            variant = 'unit-root-owner' if changed else 'original-unit'
            report['phase'] = variant+'-create'
            # Keep identity even after unclear create ACK: label-checked cleanup in finally.
            container = 'tu1nz-ci954-'+owner+'-'+variant
            ci.command(ci.native_argv(ROOT, control, image, container, owner, runtime_inputs=inputs), timeout=30)
            ci.inspect_guest(container, owner, ROOT, control, image_id, runtime_inputs=inputs)
            report['phase'] = variant+'-boot'
            ci.command(['/usr/bin/docker', 'start', container], timeout=30); ci.ready(container)
            unit = root/(variant+'.service'); ci.save(unit, unit_bytes(changed))
            report['phase'] = variant+'-unit'
            ci.command(['/usr/bin/docker', 'cp', str(unit), container+':/etc/systemd/system/tu1nz-rev4-native-fixture.service'], timeout=15)
            if changed: fix_copied_unit_owner(container, unit)
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
            if not changed: require(only_copied_unit_owner(value), 'PROBE_UNEXPECTED_BASELINE')
            else: require(value['guard_passed'] is True and value['manager_profile']['offenders']==[], 'PROBE_CHANGED_GUEST_RED')
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
