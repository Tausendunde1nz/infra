"""PRIVATE Application job: actual93555 runtime, synthetic configuration only.

This checks the real artifact's imports, three unchanged helper invocations,
read-only service views, kernel credentials and HTTP. It is NOT the production
operator/Owner/Host acceptance; those have a separate full native scenario gate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request

sys.path.insert(0,'/source/scripts')
import tu1nz_public_runtime_artifact as a

UNITS=('tu1nz-adult-public-s7.service','tu1nz-adult-public-s8-landing.service','tu1nz-adult-public-s10-wms.service')
PROFILES=('s7','s8-landing','wms')
STATE=Path('/var/lib/tu1nz-adult-public-s9')
STAGE='boundary'


def run(*argv,data=None):
    result=subprocess.run(argv,input=data,capture_output=True,timeout=30,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'})
    assert result.returncode==0
    return result.stdout


def write(path,raw,mode=0o644):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:stream.write(raw)
    path.chmod(mode)


def properties(unit):
    raw=run('/usr/bin/systemctl','show',unit,'--property=ActiveState,MainPID,InvocationID,NRestarts','--no-pager')
    return dict(line.split('=',1) for line in raw.decode().splitlines())


def main():
    global STAGE
    p=argparse.ArgumentParser();p.add_argument('--receipt-sha256',required=True);args=p.parse_args()
    assert os.geteuid()==0 and sys.platform=='linux' and platform.machine()=='x86_64'
    assert Path('/.dockerenv').is_file() and Path('/proc/1/comm').read_text().strip()=='systemd'
    assert {q.name for q in Path('/sys/class/net').iterdir()}=={'lo'}
    assert not Path('/proc/net/route').read_text().splitlines()[1:]
    for path in ('/source','/artifact'):
        assert 'ro' in run('/usr/bin/findmnt','-n','-o','VFS-OPTIONS','-T',path).decode().strip().split(',')
    STAGE='artifact'
    receipt_raw=Path('/artifact/RUNTIME_ARTIFACT.json').read_bytes();assert a.sha(receipt_raw)==args.receipt_sha256
    receipt=a.parse(receipt_raw);inputs=a.parse(Path('/source/manifests/public-web-runtime-r5-inputs.json').read_bytes())
    a.validate_receipt(receipt,inputs)
    raw=Path('/artifact/runtime.tar.gz').read_bytes();a.inspect_archive(raw,receipt)
    root=Path(a.ROOT);assert not root.exists();root.mkdir(parents=True,mode=0o755)
    # Fixture materialization only, not an alternative production installer.
    # The full production materializer is tested in the separate R5 cases.
    with tarfile.open('/artifact/runtime.tar.gz','r:gz') as archive:
        for member in archive:
            q=root/member.name
            if member.isdir():q.mkdir(mode=0o755)
            elif member.issym():q.symlink_to(member.linkname)
            else:write(q,archive.extractfile(member).read(),member.mode)
    for q in sorted(root.rglob('*'),key=lambda q:len(q.parts),reverse=True):
        if q.is_dir() and not q.is_symlink():q.chmod(0o555)
    root.chmod(0o555)
    historical=Path(a.VIEW);historical.mkdir(parents=True)
    write(historical/'historical-sentinel',b'NOT_A_RUNTIME_OR_SOURCE_ORIGIN\n',0o444)
    before=a.sha((historical/'historical-sentinel').read_bytes())
    STAGE='fixture'
    import pwd
    try:pwd.getpwnam('chatops')
    except KeyError:
        run('/usr/sbin/groupadd','--gid','1001','chatops')
        run('/usr/sbin/useradd','--uid','1001','--gid','1001','--no-create-home','chatops')
    STATE.mkdir(mode=0o700,parents=True);os.chown(STATE,1001,1001)
    run('/usr/bin/systemctl','start','postgresql@16-main.service')
    run('/usr/sbin/runuser','-u','postgres','--','/usr/bin/psql','-X','-v','ON_ERROR_STOP=1',
        '-c','CREATE ROLE chatops LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;')
    run('/usr/sbin/runuser','-u','postgres','--','/usr/bin/psql','-X','-v','ON_ERROR_STOP=1',
        '-c','CREATE DATABASE r5_synthetic OWNER postgres;')
    config=root/'app/config'
    mapping={'adult-commercial-s7-public.json':'commercial-s7-public-launch.sfw.json',
        'adult-commercial-s8-landing.json':'commercial-s8-public-landing.sfw.json',
        'adult-commercial-s10-wms.json':'commercial-s10-1-wms-public.sfw.json',
        'adult-commercial-s10-wms-copy.json':'commercial-s10-1-wms-copy.v1.json',
        'adult-commercial-s10-wms-bot-identity.json':'commercial-s8-public-telegram-early-access.sfw.json',
        'adult-commercial-s10-2d-community.json':'commercial-s10-2d-community.sfw.json'}
    for name,source in mapping.items():
        body=a.parse((config/source).read_bytes())
        if name in ('adult-commercial-s7-public.json','adult-commercial-s8-landing.json','adult-commercial-s10-wms.json'):
            body['bind_host']='127.0.0.1';body['bind_port']=18071+list(mapping).index(name)
        write('/etc/tu1nz/'+name,a.canonical(body),0o644)
    write('/etc/tu1nz/adult-commercial-s7-form.secret',b'SYNTHETIC_ONLY_' + b'0'*64,0o600)
    write('/etc/tu1nz/adult-commercial-s7-database.dsn',b'postgresql:///r5_synthetic?host=/run/postgresql&user=chatops',0o600)
    helper=Path('/source/scripts/tu1nz_public_web_isolate_r1.py').read_bytes()
    write('/usr/local/bin/tu1nz_public_web_isolate_r1.py',helper,0o555)
    STAGE='imports'
    program=('import json,site,sys,psycopg,cryptography,cffi,typing_extensions\n'
        'from psycopg import pq\n'
        'assert site.ENABLE_USER_SITE is False\n'
        'assert sys.version_info[:3]==(3,12,15) and pq.__impl__=="binary"\n'
        'assert all("public-web-runtime-r5" in p for p in sys.path if p and "site-packages" in p)\n'
        'assert psycopg.__version__=="3.3.4" and cryptography.__version__=="50.0.1"\n'
        'with psycopg.connect("postgresql:///r5_synthetic?host=/run/postgresql&user=chatops",options="-c default_transaction_read_only=on") as db:\n'
        ' assert db.execute("select current_user,current_database(),current_setting(\'transaction_read_only\')").fetchone()==("chatops","r5_synthetic","on")\n'
        'print("PINNED_IMPORTS_NO_USER_OR_HOST_SITE")\n')
    def peer():os.setgroups([]);os.setgid(1001);os.setuid(1001)
    result=subprocess.run([str(root/'app/.venv/bin/python'),'-B','-c',program],capture_output=True,
        timeout=20,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'},preexec_fn=peer)
    assert result.returncode==0 and result.stdout.strip()==b'PINNED_IMPORTS_NO_USER_OR_HOST_SITE'
    STAGE='units'
    for unit,profile in zip(UNITS,PROFILES):
        body=('[Service]\nType=simple\nUser=chatops\nGroup=chatops\n'
            'WorkingDirectory='+a.VIEW+'\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n'
            'ReadWritePaths='+str(STATE)+'\n'
            'ExecStart=!/usr/bin/python3 -I -B -S /usr/local/bin/tu1nz_public_web_isolate_r1.py --profile '+profile+'\n')
        if profile=='s7':body+=('LoadCredential=s7_form_secret:/etc/tu1nz/adult-commercial-s7-form.secret\n'
            'LoadCredential=s7_database_dsn:/etc/tu1nz/adult-commercial-s7-database.dsn\n')
        write('/etc/systemd/system/'+unit,body.encode())
        write('/etc/systemd/system/'+unit+'.d/zzz-public-runtime-r5.conf',a.overlay())
    run('/usr/bin/systemctl','daemon-reload');proof=[]
    for i,unit in enumerate(UNITS):
        STAGE='start-'+str(i)
        run('/usr/bin/systemctl','start',unit);first=properties(unit)
        assert first['MainPID']!='0' and first['NRestarts']=='0' and first['InvocationID']
        target=('http://127.0.0.1:'+str(18071+i)+('/adult/health' if i<2 else '/health'))
        deadline=time.monotonic()+20;health=None
        while time.monotonic()<deadline:
            now=properties(unit);assert now==first
            try:
                with urllib.request.urlopen(target,timeout=1) as response:
                    assert response.status==200;health=response.read(1024*1024+1)
                break
            except OSError:time.sleep(.05)
        assert health is not None and len(health)<=1024*1024
        pid=int(first['MainPID']);proc=Path('/proc')/str(pid)
        status=dict(x.split(':',1) for x in (proc/'status').read_text().splitlines() if ':' in x)
        assert list(map(int,status['Uid'].split()))==[1001]*4 and list(map(int,status['Gid'].split()))==[1001]*4
        assert not status['Groups'].split() and status['NoNewPrivs'].strip()=='1'
        assert all(int(status[k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
        view=proc/'root'/a.VIEW.lstrip('/');x=view.stat();y=(root/'app').stat()
        assert (x.st_dev,x.st_ino)==(y.st_dev,y.st_ino) and os.statvfs(view).f_flag&os.ST_RDONLY
        assert os.readlink(proc/'exe')==str(root/'python/bin/python3.12')
        assert a.sha((historical/'historical-sentinel').read_bytes())==before
        proof.append({'unit_index':i,'http_sha256':a.sha(health),'same_first_invocation':True,
                      'kernel_groups_empty_caps_zero':True,'actual_readonly_artifact_view':True})
    STAGE='complete'
    print(json.dumps({'schema':'TU1NZ_PUBLIC_RUNTIME_ACTUAL_NATIVE_R5_V1','artifact_sha256':a.sha(raw),
        'receipt_sha256':a.sha(receipt_raw),'source_manifest_sha256':a.SOURCE_MANIFEST,'objects':len(receipt['objects']),
        'units':proof,'historical_sentinel_unchanged':True,'host_acceptance':False,'provider_actions':False,
        'operator_owner_acceptance':'SEPARATE_MANDATORY_NATIVE_GATE'}))


if __name__=='__main__':
    try:main()
    except BaseException as error:
        print(json.dumps({'actual_runtime_failure':{'stage':STAGE,'type':type(error).__name__}}));raise SystemExit(1)
