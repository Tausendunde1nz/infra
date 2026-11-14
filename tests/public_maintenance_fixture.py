"""Rev4 EXPECTED fixture data, confined to a fresh isolated native guest.

No Host observations, actions, ACKs, admission functions or deadlines are
substituted. Source constants identify only synthetic targets/receipts. The
production module exposes no fixture switch. Real SSH and sudo are required.
"""
import base64
import copy
from datetime import datetime,timezone
import hashlib
import os
from pathlib import Path
import shlex
import signal
import subprocess
import time

from tests import public_operator_native as f
from tests.public_runtime_fixture import runtime,external_dependencies,substitutions
from tests.test_public_maintenance_transport import synthetic_timing
import tu1nz_public_operator as client
io=client.io
ROOT=f.ROOT
PASSWORD=b'TU1NZ_DISPOSABLE_NATIVE_FIXTURE_ONLY'
CASES=('original','recovery_F1','recovery_F2','recovery_F3','recovery_F4','recovery_terminal_F4')
CUSTODY=Path('/Users/daniel/Developer/tu1nz/service-isolation-lighting-night-20261013/host-operator-intents')


def stamp(value):return datetime.fromtimestamp(value,timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def encode(raw):return base64.b64encode(raw).decode()
def raw(value):return io.canonical(value)


def ssh_argv(remote):
    return ['/usr/bin/ssh','-F','/dev/null','-T','-p','22222','-o','BatchMode=yes',
        '-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
        '-o','UserKnownHostsFile='+str(ROOT/'ssh-known-hosts'),'-o','GlobalKnownHostsFile=/dev/null',
        '-o','PasswordAuthentication=no','-o','ClearAllForwardings=yes','-o','ConnectTimeout=10',
        '-i',str(ROOT/'ssh-client'),'chatops@127.0.0.1',remote]


def ssh_setup():
    f.assert_guest_isolation()
    f.run('/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(ROOT/'ssh-host'))
    f.run('/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(ROOT/'ssh-client'))
    public=(ROOT/'ssh-host.pub').read_bytes().split()
    f.write(ROOT/'ssh-known-hosts',b'[127.0.0.1]:22222 '+b' '.join(public[:2])+b'\n',0o600)
    f.write('/etc/ssh/tu1nz-native-authorized-keys',(ROOT/'ssh-client.pub').read_bytes())
    f.run('/usr/sbin/chpasswd',data=b'chatops:'+PASSWORD+b'\n')
    f.write('/etc/sudoers.d/zz-tu1nz-native',b'chatops ALL=(root) ALL\n',0o440)
    f.write(ROOT/'sshd_config',('Port 22222\nListenAddress 127.0.0.1\nHostKey '+str(ROOT/'ssh-host')+
        '\nPidFile '+str(ROOT/'sshd.pid')+'\nAuthorizedKeysFile /etc/ssh/tu1nz-native-authorized-keys\n'
        'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nUsePAM no\n'
        'AllowUsers chatops\nAllowTcpForwarding no\nAllowAgentForwarding no\nX11Forwarding no\nPermitTTY no\n').encode(),0o600)
    Path('/run/sshd').mkdir(mode=0o755,exist_ok=True)
    f.write('/etc/systemd/system/tu1nz-native-sshd.service',('[Service]\nType=simple\nExecStart=/usr/sbin/sshd -D -e -f '+
        str(ROOT/'sshd_config')+'\n').encode())
    f.run('/usr/bin/systemctl','daemon-reload');f.run('/usr/bin/systemctl','start','tu1nz-native-sshd.service')


def current_profiles(s, warmup):
    observer=s.load('observe');ctx=s.load('context');until=time.monotonic()+30
    units=observer.unit_properties(f.UNITS,'MainPID',until)
    rows={};targets={int(units[u]['MainPID']) for u in f.UNITS}
    for name in sorted(os.listdir('/proc')):
        if not name.isdecimal() or int(name) in targets:continue
        try:row=observer.current_process(int(name),deadline=until)
        except observer.CurrentProcessExited:continue
        if row.get('kernel_thread')==1:continue
        if row['uid']==row['gid']==[33]*4:role='nginx_reader'
        elif int(name)==1:role='kernel_manager'
        else:role='administrative_service'
        # Fixture worker is itself a real systemd service. Docker exec's
        # short-lived launcher must be gone before this finite snapshot.
        selected={k:row[k] for k in ctx.CURRENT_SECURITY}
        key=io.sha(raw(selected))
        if key not in rows:rows[key]={**selected,'id':'native-'+key[:16],'role':role,
            'purpose':'Known isolated synthetic fixture administration; no production origin claim',
            'max_instances':1 if role=='kernel_manager' else 16}
    result=list(rows.values());ctx.current_profiles(result)
    assert warmup.poll() is None
    return result


def synthetic_backup(s,b,plan):
    """Synthetic prior receipt coordinates only; real production pins unchanged.

    Actual closed real DB/file restores remain the production evidence. This
    fixture does not claim to restore that private data or grant a Host gate.
    """
    admission=s.load('admission');model=s.load('restore');guard=s.load('guard')
    files={}
    paths={p for v in b['unit_files'].values() for p in (v['fragment'],*v['dropins'])}|set(admission.CONFIGS)|set(admission.STATE)
    objects=io.parse(plan)['capture']['objects']
    for name,row in objects.items():files[admission.LIGHTING if name=='.' else admission.LIGHTING+'/'+name]=row
    for path in paths:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:files[path]=guard.observe_fd(fd)
        finally:os.close(fd)
    # This guest's two synthetic tables receive only the bounded trigger/role
    # names required by the existing structural/rights comparator.
    sql=("CREATE ROLE tu1nz_adult_commercial_s3_runtime NOLOGIN NOINHERIT; "
        "GRANT USAGE ON SCHEMA public TO tu1nz_adult_commercial_s3_runtime; "
        "GRANT SELECT ON commercial_s7_waitlist,commercial_s7_analytics_events TO tu1nz_adult_commercial_s3_runtime; ")
    for table,name in zip(model.TABLES,model.FUNCTIONS):
        sql+=("CREATE FUNCTION public."+name+"() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'; "
            "CREATE TRIGGER native_"+name+" BEFORE INSERT ON public."+table+" FOR EACH ROW EXECUTE FUNCTION public."+name+"(); ")
    f.run('/usr/sbin/runuser','-u','postgres','--','/usr/bin/psql','-X','-qAt','-d','r4_probe','--set=ON_ERROR_STOP=1',data=sql.encode())
    prefix=('/usr/sbin/runuser','-u','chatops','--','/usr/bin/psql','-X','-qAt','-d','r4_probe','--set=ON_ERROR_STOP=1')
    cat=f.run(*prefix,data=model.catalog_transaction());rights=f.run(*prefix,data=model.rights_transaction())
    profile=model.compare_restore_catalog(cat,cat,rights,rights)
    now=float(int(time.time()));file_time=now-120;db_time=now-60
    db={'cleanup':[],'snapshot':{'snapshot_started_unix':db_time,'fingerprints':{n:{'rows':0} for n in model.TABLES}},'admission':profile}
    completion={'status':'PASS_REAL_DB_AND_FILE_RESTORES','db_result_sha256':io.sha(raw(db)),
        'file_result_sha256':io.sha(b'SYNTHETIC_FILE_RESTORE_COORDINATE_NOT_PRODUCTION_EVIDENCE'),
        'actual_local_cleanup':[],'file_manifest_sha256':io.sha(raw(files)),'db_snapshot_started_unix':db_time}
    protection={'private_completion_sha256':io.sha(raw(completion)),'private_DB_result_sha256':io.sha(raw(db)),
        'private_file_result_sha256':completion['file_result_sha256'],'file_capture_finished_utc':stamp(file_time)}
    receipts={'protection':raw(protection),'database':raw({'fixture_only':True}),'cleanup':raw({'fixture_only':True,'cleanup':[]})}
    changes={};evidence={};immutable=paths-set(admission.STATE)
    for name in (*admission.TABLES,*admission.STATE):
        is_db=name in admission.TABLES
        observed={'rows':0,'json_bytes':0} if is_db else {'bytes':files[name]['metadata']['size'],'sha256':files[name]['sha256']}
        gap=({'snapshot_unix':db_time,'observed_unix':now,'backup_rows':0,'additional_rows':0,'content_equality_proved':False}
             if is_db else {'snapshot_unix':file_time,'observed_unix':now,'backup_sha256':files[name]['sha256'],'content_changed':False})
        gap.update(remaining_exposure='Only fresh synthetic empty tables and static fixture JSON; no real provider data or backup is present.',
            adequacy_reason='Fixture-only prior receipt binding. Actual production requires independent review of its real data gap; this is not that permission.')
        row={'classification':'ASSESSED_MUTABLE_DATA_GAP' if is_db else 'UNCHANGED',
            'maximum_current_bytes':1024*1024,'maximum_current_rows':0,'observed_at_unix':now,'observed':observed,'gap_assessment':gap}
        proof={'schema':'TU1NZ_REV4_FINITE_CURRENT_WRITE_ASSESSMENT_V1','object':name,'classification':row['classification'],
            'writer_unit':admission.UNITS[0] if is_db else admission.UNITS[1 if name==admission.STATE[0] else 2],
            'target_application_commit':b['source_release']['runtime_reference']['artifact']['application']['commit'],
            'immutable_inputs_sha256':io.sha(raw({p:admission.projection(b)['files'][p] for p in sorted(immutable)})),
            'backup_reference_sha256':protection['private_DB_result_sha256'] if is_db else completion['file_manifest_sha256'],
            'observed_at_unix':now,'observed':observed,'gap_assessment_sha256':io.sha(raw(gap)),'historical_or_lossless_restore_claim':False}
        digest=io.sha(raw(proof));evidence[digest]=encode(raw(proof));row['evidence_sha256']=digest;changes[name]=row
    coverage={'schema':'TU1NZ_REV4_CURRENT_PROTECTION_COVERAGE_V1','completion':encode(raw(completion)),
        'database_result':encode(raw(db)),'file_manifest':encode(raw(files)),'source_catalog':encode(cat),'source_rights':encode(rights),
        'assessment':{'schema':'TU1NZ_REV4_MUTABLE_COVERAGE_ASSESSMENT_V1','risk':admission.RISK,
            'file_snapshot_unix':datetime.fromisoformat(stamp(file_time)).timestamp(),'db_snapshot_unix':db_time,
            'assessed_at_unix':now,'valid_until_unix':now+7200,'maximum_snapshot_age_seconds':7500,'changes':changes,'evidence':evidence}}
    return coverage,receipts


def package(s,b,plan,receipt,coverage,receipts, *, timing=None):
    admission=s.load('admission');ctx=s.load('context')
    hashes={k:io.sha(v) for k,v in s.bytes.items()};encoded={k:encode(v) for k,v in s.bytes.items()}
    now=time.time();observation={'schema':'TU1NZ_REV4_CURRENT_OBSERVATION_V1','host_id':109772243,'boot_id':b['boot_id'],
        'source_sha256':io.sha(raw(hashes)),'baseline_projection_sha256':io.sha(raw(admission.projection(b))),'coverage':coverage}
    material={'contract':b'SYNTHETIC_REV4_CONTRACT_NOT_A_PRODUCTION_APPROVAL',
        'approval':raw({'fixture_only':True}), 'current_observation':raw(observation),
        'pre_stop_protection':raw({'schema':'TU1NZ_REV4_CLOSED_REAL_RESTORE_REUSE_V1','receipts':{k:encode(v) for k,v in receipts.items()}})}
    reads={'schema':'TU1NZ_REV4_FINITE_EXECUTION_READ_SCOPE_V1','host_id':109772243,'transaction':'public-rights-20261014-1',
        'units':list(f.UNITS),'files':sorted(b['files']),'state':list(admission.STATE),'lighting_root':admission.LIGHTING,
        'lighting_objects':88,'database':b['database']['database'],'tables':list(admission.TABLES),
        'runtime_artifact_sha256':io.sha(raw(receipt)),'source_sha256':observation['source_sha256'],
        'functions':['existing_current_authority','existing_writer_and_platform_checks','existing_bound_runtime_and_file_reads',
                     's7_catalog_rights_and_counts','current_two_json_states','same_transaction_recovery_custody'],
        'historical_reader_or_claim_reuse':False,'production_data_restore':False}
    material['read_scope']=raw(reads)
    b['schema']=ctx.CURRENT_BASELINE;b['current_authority']={'schema':ctx.CURRENT_AUTHORITY,'risk':ctx.CURRENT_RISK,
        'observation_sha256':io.sha(material['current_observation'])}
    # First calibration is explicitly synthetic, never published as measured.
    # Final cases receive the six real first-pass measurements from CI.
    if timing is None:timing=synthetic_timing(hashes,receipt)
    assert timing['source_sha256']==io.sha(raw(hashes)) and timing['artifact_sha256']==io.sha(raw(receipt))
    material['native_timing']=raw(timing)
    material['current_acceptance']=raw({'schema':'TU1NZ_REV4_CURRENT_ACCEPTANCE',
        'observation_sha256':io.sha(material['current_observation']),'read_scope_sha256':io.sha(material['read_scope']),
        'machine_sha256':b['machine_sha256'],'boot_id':b['boot_id'],'transaction':'public-rights-20261014-1',
        'source_sha256':io.sha(raw(hashes)),'capture_started_at':stamp(now-10),'capture_finished_at':stamp(now-5),
        'accepted_at':stamp(now-1),'expires_at':stamp(now+7200),'risk':ctx.CURRENT_RISK})
    release={'schema':'TU1NZ_PUBLIC_OPERATOR_RELEASE_V1','files':hashes}
    scope={'schema':io.MAINTENANCE_SCOPE,'release_sha256':io.sha(raw(release)),'baseline_sha256':io.sha(raw(b)),
        'administrative_roles_sha256':io.sha(raw(b['actors'])),'baseline_origins_sha256':io.sha(raw(b['source_origin_receipts'])),
        'r3_approval_sha256':client.APPROVAL,'machine_sha256':b['machine_sha256'],'transaction':'public-rights-20261014-1',
        'owner_plan_sha256':io.sha(plan),'runtime_artifact_sha256':io.sha(raw(receipt)),'legacy_return':False,
        **{n+'_sha256':io.sha(v) for n,v in material.items()}}
    review={'schema':'TU1NZ_REV4_INDEPENDENT_EXECUTION_INPUT_REVIEW','reviewer':'SYNTHETIC_FIXTURE_ONLY_NO_HOST_REVIEW',
        'inputs':{k:scope[k+'_sha256'] for k in ('release','baseline','current_observation','current_acceptance','read_scope',
                'pre_stop_protection','native_timing','contract','approval')},'findings':[],
        'evidence_sha256':io.sha(b'SYNTHETIC_BOUND_EXPECTED_INPUT_ONLY'),'reviewed_at':stamp(now)}
    review['inputs'].update(scope_sha256=io.sha(raw(scope)),source_sha256=io.sha(raw(hashes)))
    material['review']=raw(review)
    packet=client.maintenance_package(encoded,hashes,raw(b),raw(scope),plan,raw(release),material,io.sha(material['review']))
    pins={'MAINTENANCE_MACHINE':b['machine_sha256'],'MAINTENANCE_OWNER_PLAN':io.sha(plan),
        'MAINTENANCE_DECISION_SHA':io.sha(material['contract']),'MAINTENANCE_APPROVAL_SHA':io.sha(material['approval']),
        'MAINTENANCE_RESTORE_RECEIPTS':{n:io.sha(v) for n,v in receipts.items()}}
    return packet,pins


def legacy_contexts_sha(s):
    """Bind the three synthetic stop-target profiles BEFORE either entry.

    As in the native adapter fixture, this replaces only the expected Host
    coordinate. Every later stop-context comparison still reads actual state.
    The one frozen value is reused by Recovery, never refreshed after effects.
    """
    observer=s.load('observe');until=time.monotonic()+30
    units=observer.unit_properties(f.UNITS,'MainPID',until)
    pids={u:int(units[u]['MainPID']) for u in f.UNITS}
    assert len(set(pids.values()))==3 and all(pid>0 for pid in pids.values())
    legacy={}
    for unit,pid in pids.items():
        row=observer.current_process(pid,deadline=until)
        legacy[unit]={k:row[k] for k in ('uid','gid','groups','nnp')}
        legacy[unit]['caps']={k:format(row['caps'][k],'016x') for k in ('CapInh','CapPrm','CapEff','CapAmb')}
    return io.sha(raw(legacy))


def bind_expected(s,pins,inputs,*,legacy_sha):
    """Finite synthetic EXPECTED coordinates, never observation overrides."""
    for module in (io,s.load('io')):
        for key,value in pins.items():setattr(module,key,value)
        module.ASSETS['runtime_inputs']=io.sha(raw(inputs))
    s.load('r3').MACHINE=s.load('entry').MACHINE=pins['MAINTENANCE_MACHINE']
    s.load('r3').OWNER_PLAN=pins['MAINTENANCE_OWNER_PLAN']
    artifact=s.load('artifact')
    artifact.APP=(inputs['application']['commit'],inputs['application']['tree'])
    artifact.SOURCE_MANIFEST=inputs['application']['manifest_sha256']
    artifact.INPUTS_SHA=io.sha(raw(inputs))
    s.load('observe').LEGACY_CONTEXTS_SHA=legacy_sha


def age_start_anchors(s):
    """Real fixture idle time BEFORE current capture and entry measurement.

    No limiter setting, counter, timestamp, observation or clock is changed.
    The unchanged production predicate is freshly checked after actual wait.
    """
    replacement=s.load('replacement');observer=s.load('observe')
    end=time.monotonic()+925
    providers={str(Path(p).resolve(strict=True)) for p in f.operator_dependency_names(s)
        if Path(p).name.startswith('libsystemd-shared-') and Path(p).name.endswith('.so')}
    assert len(providers)==1
    fd=os.open(next(iter(providers)),os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);bus=None
    try:
        bus=replacement.ReadOnlyBus(fd,end)
        def unit(name):return f.fixture_unit_sample(observer,name,end)
        first={u:replacement.start_limit_state_read(bus,unit,u) for u in f.UNITS}
        for value in first.values():
            assert value['properties']['StartLimitIntervalUSec']==900_000_000
            assert value['unit_state']['ActiveState']=='active' and value['unit_state']['NRestarts']=='0'
        wait_until=max(v['properties']['ActiveEnterTimestampMonotonic']+900_002_000 for v in first.values())/1e6
        assert wait_until<end
        while time.monotonic()<wait_until:time.sleep(min(30,wait_until-time.monotonic()))
        for unit_name,prior in first.items():
            current=replacement.start_limit_state_read(bus,unit,unit_name)
            assert all(current[k]==prior[k] for k in ('unit','manager_owner','properties','unit_state'))
            assert replacement.start_limit_permission(current,require_active=True)=='AGED_SUCCESSFUL_ACTIVE_INVOCATION'
    finally:
        try:
            if bus is not None:bus.close()
        finally:os.close(fd)


def retain_fixture_unit_references():
    # Match the closed Host's enabled units and the native StartLimit component.
    # A loaded target reference retains stopped Unit state; this is fixture
    # construction before ageing/baseline, never a production repair or reset.
    f.assert_guest_isolation()
    for unit in f.UNITS:f.run('/usr/bin/systemctl','enable',unit)
    f.run('/usr/bin/systemctl','daemon-reload')
    target=dict(line.split('=',1) for line in f.run('/usr/bin/systemctl','show','multi-user.target',
        '--property=ActiveState,Wants').decode().splitlines())
    assert target.get('ActiveState')=='active' and set(f.UNITS)<=set(target.get('Wants','').split()), \
        'NATIVE_FIXTURE_UNIT_REFERENCES_MISSING'


def prepare(*, timing=None):
    f.assert_guest();s,_,production_hashes=f.source();f.setup(s);ssh_setup()
    retain_fixture_unit_references()
    payload,receipt,inputs=runtime(s,maintenance_dimensions=True)
    dependencies=external_dependencies(s,payload,receipt);s._native_r5=True
    age_start_anchors(s)
    b=f.baseline(s,replacement_dependencies=dependencies)
    origin=io.sha(raw(receipt));b['source_origin_receipts'].append(origin)
    b['source_release']['runtime_reference']={'schema':'TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1',
        'artifact':receipt,'origin_sha256':origin}
    plan=f.plan(s,b['machine_sha256']);coverage,receipts=synthetic_backup(s,b,plan)
    # The same real SSH/sudo transport contexts are measured before admission.
    # No warmup marker grants production entry; close/reap before the timed run.
    remote='LC_ALL=C '+shlex.join(['/usr/bin/sudo','-S','-k','-p','','--','/usr/bin/python3','-I','-B','-S',
        '-c','import sys;print("SYNTHETIC_WARMUP_READY",flush=True);sys.stdin.buffer.read(1)'])
    warmup=subprocess.Popen(ssh_argv(remote),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    try:
        warmup.stdin.write(PASSWORD+b'\n');warmup.stdin.flush()
        import select
        assert select.select([warmup.stdout],[],[],20)[0]
        assert warmup.stdout.readline()==b'SYNTHETIC_WARMUP_READY\n'
        b['actors']=current_profiles(s,warmup)
    finally:
        warmup.stdin.close()
        try:assert warmup.wait(timeout=10)==0
        finally:
            if warmup.poll() is None:warmup.kill();warmup.wait(timeout=5)
            warmup.stdout.close()
    CUSTODY.mkdir(mode=0o700,parents=True)
    legacy_sha=legacy_contexts_sha(s)
    packet,pins=package(s,b,plan,receipt,coverage,receipts,timing=timing)
    bind_expected(s,pins,inputs,legacy_sha=legacy_sha)
    # Validate actual canonical local envelope before any timed entry. The
    # calibration timing is explicitly not a final native/production proof.
    bound=io.maintenance_packet_binding(packet,s,remaining_seconds=600)
    s.load('admission').validate(packet,s,bound,remaining_seconds=600)
    f.write(ROOT/'packet.json',raw(packet),0o600)
    f.write(ROOT/'fixture-pins.json',raw({'pins':pins,'inputs':inputs,'production_hashes':production_hashes,
        'legacy_contexts_sha256':legacy_sha}),0o600)
    f.write(ROOT/'runtime.tar.gz',payload,0o600)
    return packet,receipt,production_hashes
