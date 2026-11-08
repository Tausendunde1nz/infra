"""Private native Rev4 batches in two serial Environment-protected CI jobs.

Each job admits its own image, three pinned Control blobs and public runtime
inputs. Each case gets a fresh network-none guest. Only bounded public timings
and hash bindings cross jobs. Calibration is not a timing PASS.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import tu1nz_public_operator_ci as ci
import tu1nz_public_maintenance_diagnostics as diagnostics

CASES=('original','recovery_F1','recovery_F2','recovery_F3','recovery_F4','recovery_terminal_F4')
# Closed unchanged runtime receipt, verified locally before this fixture was
# authored. Synthetic real materialized dimensions must dominate these sizes.
PRODUCTION_ARTIFACT='d42e5bd84d0fdb86f7e4c6856d67d33967215162087f9ea4ed39651fbfc268b6'
FLOORS={'runtime_objects':6260,'archive_bytes':45560268,'expanded_file_bytes':143314310,
        'lighting_objects':88,'lighting_files':82,'protected_objects':4}
MEASUREMENT_FILES=('scripts/tu1nz_public_maintenance_ci.py','tests/public_maintenance_native.py',
    'scripts/tu1nz_public_maintenance_diagnostics.py',
    'tests/public_maintenance_fixture.py','tests/public_runtime_fixture.py','tests/public_operator_native.py',
    'tests/public-operator-native.Dockerfile','tests/public_operator_native_init.py','tests/s8_native_init.py')
SCHEMA='TU1NZ_REV4_FULL_NATIVE_BATCH_V1'


def needed(value,code):ci.require(value,code)
def digest(value):return ci.operator.io.sha(ci.operator.io.canonical(value))


def validate_case(value,case,phase,hashes):
    keys={'schema','case','phase','green','production_source_files','fixture_source_files','fixture_artifact_sha256',
          'original_failed_hold_preserved','second_recovery_denied_before_SSH','run','host_acceptance'}
    needed(type(value) is dict and set(value)==keys and value['schema']=='TU1NZ_REV4_NATIVE_CASE_V1' and
        value['green'] is True and value['host_acceptance'] is False and value['case']==case and value['phase']==phase,
        'REV4_NATIVE_CASE_RED')
    needed(value['production_source_files']==hashes and type(value['fixture_source_files']) is dict and
        set(value['fixture_source_files'])==set(hashes) and
        all(value['fixture_source_files'][k]==v for k,v in hashes.items() if k!='runtime_inputs') and
        re.fullmatch('[a-f0-9]{64}',value['fixture_source_files']['runtime_inputs']) and
        re.fullmatch('[a-f0-9]{64}',value['fixture_artifact_sha256']), 'REV4_NATIVE_SOURCE_SUBSTITUTION_RED')
    needed(value['original_failed_hold_preserved'] is (case!='original') and
        value['second_recovery_denied_before_SSH'] is (case!='original'), 'REV4_NATIVE_ONCE_OR_ORIGINAL_HISTORY_RED')
    row=value['run'];terminal=case=='recovery_terminal_F4'
    times={'elapsed_milliseconds','after_ready_milliseconds','preparation_milliseconds','owner_milliseconds',
        'largest_service_action_milliseconds','terminal_prepare_milliseconds','terminal_stop_milliseconds','terminal_cleanup_milliseconds'}
    counts={'linked_records','flow_records','largest_record_bytes','owner_intents','owner_acks'}
    needed(type(row) is dict and set(row)==times|counts|{'entrypoints','status','cleanup_complete','trace_sha256','dimensions'},
        'REV4_NATIVE_MEASUREMENT_SCHEMA')
    needed(row['entrypoints']==['tu1nz_public_operator.execute_maintenance','tu1nz_public_operator_host.'+
        ('maintenance_session' if case=='original' else 'recovery_session')] and row['cleanup_complete'] is True and
        row['status']==('HOLD_KNOWN_NEW_UNITS_STOPPED' if terminal else 'COMPLETE') and
        type(row['trace_sha256']) is str and re.fullmatch('[a-f0-9]{64}',row['trace_sha256']), 'REV4_NATIVE_COMPLETE_PATH_RED')
    needed(type(row['dimensions']) is dict and set(row['dimensions'])==set(FLOORS) and all(
        type(row['dimensions'][k]) is int and v<=row['dimensions'][k]<=2**31 for k,v in FLOORS.items()) and
        all(row['dimensions'][k]==FLOORS[k] for k in ('lighting_objects','lighting_files','protected_objects')),
        'REV4_NATIVE_ACTUAL_DIMENSIONS_RED')
    needed(row['dimensions']['runtime_objects']<=16384 and
        row['dimensions']['archive_bytes']<=64*1024*1024 and
        row['dimensions']['expanded_file_bytes']<=512*1024*1024,'REV4_NATIVE_DIMENSION_BOUND')
    needed(all(type(row[k]) is int and 0<=row[k]<=600000 for k in times|counts) and
        0<row['elapsed_milliseconds']<600000 and row['preparation_milliseconds']<=120000 and
        row['owner_milliseconds']<=120000 and row['largest_service_action_milliseconds']<=20000 and
        row['owner_intents']==row['owner_acks']==(0 if terminal else 84) and
        0<row['linked_records']<=512 and 0<row['flow_records']<=128 and 0<row['largest_record_bytes']<=65536,
        'REV4_NATIVE_LIMIT_RED')
    return value


def timing(records,measurement_sha,*,production=False):
    needed(len(records)==6 and [v['case'] for v in records]==list(CASES),'REV4_NATIVE_CASE_SET_RED')
    sources={digest(v['fixture_source_files']) for v in records};artifacts={v['fixture_artifact_sha256'] for v in records}
    needed(len(sources)==len(artifacts)==1,'REV4_NATIVE_FIXTURE_INPUT_CHANGED')
    proof={'schema':'TU1NZ_REV4_FULL_NATIVE_TIMING_V1',
        'source_sha256':digest(records[0]['production_source_files']) if production else next(iter(sources)),
        'artifact_sha256':PRODUCTION_ARTIFACT if production else next(iter(artifacts)),
        'measurement_source_sha256':measurement_sha,'transport_cleanup_reserve_milliseconds':10000,
        'runs':{v['case']:v['run'] for v in records}}
    # Exercise the unmodified production arithmetic with a dimension-only
    # expected artifact. This temporary hash is NEVER published as the real
    # receipt hash; the next native pass binds its full actual fixture receipt.
    dimensions=records[0]['run']['dimensions']
    needed(all(v['run']['dimensions']==dimensions for v in records),'REV4_NATIVE_DIMENSIONS_CHANGED')
    shape={'objects':{str(n):None for n in range(dimensions['runtime_objects'])},
        'archive_bytes':dimensions['archive_bytes'],'expanded_file_bytes':dimensions['expanded_file_bytes']}
    ci.operator.io.maintenance_timing_binding({**proof,'artifact_sha256':digest(shape)},
        source_hashes=records[0]['production_source_files'] if production else records[0]['fixture_source_files'],
        artifact=shape)
    return proof


def safe_failure(value,case,phase):
    # Do not pass through private strings/tracebacks even if they look like
    # error codes. Fixed source enums/validated fixture locations only; no
    # PIDs, private paths, argv, exception text, locals or contents.
    allowed=ci.diagnostic_codes()|{'NATIVE_FULL_ENTRY_ASSERTION'}
    result={'case':case,'phase':phase,'green':False,'host_acceptance':False}
    if type(value) is not dict:return result
    if type(value.get('error_type')) is str and value['error_type'] in ci.SAFE_FAILURE_TYPES:result['error_type']=value['error_type']
    if type(value.get('code')) is str and value['code'] in allowed:result['code']=value['code']
    point=diagnostics.validated(value.get('test_failure'))
    if point is not None:result['test_failure']=point
    for route in ('original','recovery-once'):
        outer=value.get(route);inner=outer.get('result') if type(outer) is dict else None
        if type(inner) is not dict:continue
        result[route]={k:inner[k] for k in ('primary','host_primary','client_primary')
            if type(inner.get(k)) is str and inner[k] in allowed}
        if inner.get('host_primary')=='PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_START_LIMIT_STATE_NOT_ELIGIBLE':
            point=diagnostics.validated_start_limit(outer.get('start_limit_failure'))
            if point is not None:result[route]['start_limit_failure']=point
        for k in ('host_abort','host_cleanup','client_cleanup'):
            if type(inner.get(k)) is list:result[route][k]=[v for v in inner[k] if type(v) is str and v in allowed][:16]
    return result


def fix_copied_unit_owner(container,unit):
    # Only our just-created private fixture Unit in this isolated guest.
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


def case_run(workspace,control,image,image_id,owner,root,inputs,hashes,case,phase,proof=None):
    name='tu1nz-rev4-'+owner+'-'+phase+'-'+case.lower().replace('_','-');container=None
    try:
        container=name  # own label-checked cleanup even after an unclear create ACK
        ci.command(ci.native_argv(workspace,control,image,name,owner,runtime_inputs=inputs),timeout=30)
        ci.inspect_guest(name,owner,workspace,control,image_id,runtime_inputs=inputs)
        if proof is not None:
            path=root/(phase+'-'+case+'-timing.json');ci.save(path,ci.operator.io.canonical(proof))
            ci.command(['/usr/bin/docker','cp',str(path),name+':/native-timing.json'],timeout=15)
        ci.command(['/usr/bin/docker','start',name],timeout=30);ci.ready(name)
        unit=root/(phase+'-'+case+'.service')
        ci.save(unit,('[Unit]\nAfter=multi-user.target\n[Service]\nType=simple\n'
            'Environment=container=docker\n'
            'ExecStart=/usr/bin/python3 -I -B -S /source/tests/public_maintenance_native.py --case '+case+' --phase '+phase+'\n'
            'StandardOutput=null\nStandardError=append:/native-private-stderr\nTimeoutStartSec=infinity\n').encode())
        ci.command(['/usr/bin/docker','cp',str(unit),name+':/etc/systemd/system/tu1nz-rev4-native-fixture.service'],timeout=15)
        fix_copied_unit_owner(name,unit)
        ci.command(['/usr/bin/docker','exec',name,'/usr/bin/systemctl','daemon-reload'],timeout=20)
        ci.command(['/usr/bin/docker','exec',name,'/usr/bin/systemctl','start','--no-block','tu1nz-rev4-native-fixture.service'],timeout=20)
        # Wait outside the guest. No polling root process contaminates the
        # actual CurrentAuthority census during either measured lifetime.
        # Up to925s fixture ageing, two600s entries, setup and owned shutdown.
        # None of this increases an entry or a production action deadline.
        ci.command(['/usr/bin/docker','wait',name],timeout=3000)
        dest=root/(phase+'-'+case+'-result.json')
        ci.command(['/usr/bin/docker','cp',name+':/native-result.json',str(dest)],timeout=20)
        needed(dest.stat().st_size<=256*1024,'REV4_NATIVE_PRIVATE_RESULT_BOUND')
        value=json.loads(dest.read_bytes())
        if value.get('green') is not True:
            print(json.dumps({'schema':SCHEMA,'failure':safe_failure(value,case,phase)},sort_keys=True),flush=True)
        checked=validate_case(value,case,phase,hashes)
        ci.boundary.cleanup_container(container,owner);container=None
        return checked
    finally:
        if container is not None:ci.boundary.cleanup_container(container,owner)


def calibration_record(records,measurement,sha):
    return {'schema':'TU1NZ_REV4_PUBLIC_CALIBRATION_V1','source_sha':sha,
        'measurement_source_sha256':measurement,'fixture_source_files':records[0]['fixture_source_files'],
        'timing':timing(records,measurement),'host_acceptance':False}


def calibration_input(raw,hashes,measurement,sha):
    needed(type(raw) is str and 0<len(raw.encode())<=32768,'REV4_CALIBRATION_INPUT_BOUND')
    value=json.loads(raw)
    needed(type(value) is dict and set(value)=={'schema','source_sha','measurement_source_sha256',
        'fixture_source_files','timing','host_acceptance'} and value['schema']=='TU1NZ_REV4_PUBLIC_CALIBRATION_V1' and
        value['source_sha']==sha and value['measurement_source_sha256']==measurement and value['host_acceptance'] is False,
        'REV4_CALIBRATION_INPUT_BINDING')
    proof=value['timing'];records=[]
    needed(type(proof) is dict and type(proof.get('runs')) is dict and set(proof['runs'])==set(CASES),
        'REV4_CALIBRATION_CASE_SET')
    for case in CASES:
        row={'schema':'TU1NZ_REV4_NATIVE_CASE_V1','case':case,'phase':'calibration','green':True,
            'production_source_files':hashes,'fixture_source_files':value['fixture_source_files'],
            'fixture_artifact_sha256':proof['artifact_sha256'],'original_failed_hold_preserved':case!='original',
            'second_recovery_denied_before_SSH':case!='original','run':proof['runs'][case],'host_acceptance':False}
        records.append(validate_case(row,case,'calibration',hashes))
    needed(timing(records,measurement)==proof,'REV4_CALIBRATION_NOT_CANONICAL_MEASURED_BUDGET')
    return proof


def publish_calibration(record):
    # Only a finite schema produced from six validated, cleaned test guests.
    # This is a GitHub job output, never an artifact/private Source handoff.
    import stat
    raw=ci.operator.io.canonical(record)
    needed(len(raw)<=32768 and b'\n' not in raw,'REV4_CALIBRATION_OUTPUT_BOUND')
    path=Path(os.environ['GITHUB_OUTPUT'])
    fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        metadata=os.fstat(fd)
        needed(stat.S_ISREG(metadata.st_mode) and metadata.st_uid==os.geteuid() and metadata.st_nlink==1,
            'REV4_CALIBRATION_OUTPUT_PROFILE')
        with os.fdopen(fd,'wb',closefd=False) as output:
            output.write(b'rev4_calibration='+raw+b'\n');output.flush();os.fsync(fd)
    finally:os.close(fd)


def run_cases(workspace,control,image,image_id,owner,root,inputs,hashes,sha,*,phase='calibration',calibration_raw=None):
    needed(phase in ('calibration','verification'),'REV4_NATIVE_PHASE')
    measurement=digest({p:hashlib.sha256((workspace/p).read_bytes()).hexdigest() for p in MEASUREMENT_FILES})
    proof=calibration_input(calibration_raw,hashes,measurement,sha) if phase=='verification' else None
    needed(phase=='verification' or calibration_raw is None,'REV4_NATIVE_CALIBRATION_NO_PRIOR_INPUT')
    records=[]
    for case in CASES:
        value=case_run(workspace,control,image,image_id,owner,root,inputs,hashes,case,phase,proof)
        records.append(value)
        print(json.dumps({'schema':SCHEMA,'phase':phase,'case':case,'source_sha':sha,
            'elapsed_milliseconds':value['run']['elapsed_milliseconds'],
            'reserve_milliseconds':600000-value['run']['elapsed_milliseconds'],
            'owner_milliseconds':value['run']['owner_milliseconds'],
            'owner_acks':value['run']['owner_acks'],'cleanup_complete':True,
            'native_batch_pass':False,'host_acceptance':False},sort_keys=True),flush=True)
    result={'schema':SCHEMA,'green':True,'phase':phase,'source_sha':sha,'measurement_source_sha256':measurement,
        'expected_input_substitutions':['synthetic_machine_and_owner_plan','synthetic_current_custody_and_coverage',
            'synthetic_application_and_runtime_inputs','loopback_SSH_TLS_DNS_in_network_none_guest'],
        'executable_source_files':hashes,'fixture_source_sha256':digest(records[0]['fixture_source_files']),
        'native_batch_pass':phase=='verification','host_acceptance':False,
        'production_network_latency_guaranteed':False,'fixture_cleanup_complete':True}
    if phase=='calibration':result['calibration']=calibration_record(records,measurement,sha)
    else:result.update(calibration_sha256=digest(proof),timing=timing(records,measurement,production=True))
    return result


def verification(workspace,image):
    import uuid
    root=None;owner=uuid.uuid4().hex;parent=Path(os.environ.get('RUNNER_TEMP','/nonexistent'));stage='admission'
    result={'schema':SCHEMA,'green':False,'code':'REV4_VERIFICATION_RED','host_acceptance':False}
    try:
        token=os.environ.pop('CONTROL_POLICY_READ_TOKEN',None)
        sha=ci.boundary.runtime_binding(os.environ,workspace)
        needed(type(token) is str and token.startswith('github_pat_'),'READ_CREDENTIAL_MISSING')
        needed(image=='tu1nz-public-operator-private:'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT'],
            'FRESH_IMAGE_BINDING_RED')
        image_id=ci.command(['/usr/bin/docker','image','inspect','--format','{{.Id}}',image]).decode().strip()
        needed(re.fullmatch('sha256:[a-f0-9]{64}',image_id),'IMAGE_ID_RED')
        root=ci.boundary.private_root(parent,workspace);stage='private-source'
        control,hashes=ci.fetch_control(root,token);token=None
        hashes.update({n:hashlib.sha256((workspace/p).read_bytes()).hexdigest() for n,p in ci.operator.INFRA_FILES.items()})
        measurement=digest({p:hashlib.sha256((workspace/p).read_bytes()).hexdigest() for p in MEASUREMENT_FILES})
        calibration_raw=os.environ.pop('REV4_CALIBRATION')
        calibration_input(calibration_raw,hashes,measurement,sha)
        stage='runtime-public-inputs'
        import tu1nz_public_runtime_build as build
        inputs=json.loads((workspace/'manifests/public-web-runtime-r5-inputs.json').read_bytes())
        runtime_inputs=root/'runtime-inputs';runtime_inputs.mkdir(mode=0o700)
        for row in [inputs['python'],*inputs['wheels']]:ci.save(runtime_inputs/row['filename'],build.fetch(row))
        stage='verification'
        result=run_cases(workspace,control,image,image_id,owner,root,runtime_inputs,hashes,sha,
            phase='verification',calibration_raw=calibration_raw)
        result['code']='REV4_VERIFICATION_GREEN'
    except BaseException as error:
        result={'schema':SCHEMA,'green':False,'stage':stage,'code':str(error) if type(error) is ci.CIError else
            'REV4_VERIFICATION_RED','host_acceptance':False}
    finally:result=ci.cleanup_result(result,None,owner,root,parent)
    print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['green'] else 1


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--image',required=True);args=parser.parse_args()
    with ci.boundary.interrupted():raise SystemExit(verification(Path(__file__).resolve().parents[1],args.image))
