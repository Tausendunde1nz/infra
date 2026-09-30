"""Isolated Mommyramona compatibility test. Never attaches production resources."""
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tarfile
import uuid

IMAGE = 'sha256:f0c7c619b45ffb475d79c2339fbef21ced03c6e83d919d321ef89b40cd4889db'
SOURCE = pathlib.Path('/opt/telegram_chatbot/main.py')
SHA = 'f7119919cd3bff8193b72782ec984633cd222abad87281df011455fb7313a8bd'
HARNESS = r'''
import os, runpy, subprocess, time, urllib.request, json, requests, stat
def denied(*a, **k): raise AssertionError('EXTERNAL_REQUEST_FORBIDDEN')
requests.sessions.Session.request = denied
assert os.environ['BOT_TOKEN'] == 'offline-dummy'
assert os.environ['SECRET'] == 'offline-dummy'
assert set(os.listdir('/sys/class/net')) == {'lo'}
ns = runpy.run_path('/app/main.py', run_name='offline_import')
assert ns['app'].test_client().get('/health').status_code == 200
p = subprocess.Popen(['python', '-I', '-B', '/app/main.py'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    start = time.monotonic()
    success = 0
    while time.monotonic() - start < 12:
        assert p.poll() is None, 'APPLICATION_EXITED'
        try:
            with urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=1) as r:
                assert r.status == 200
                success += 1
        except OSError:
            pass
        if success >= 3: break
        time.sleep(.2)
    assert success >= 3, 'HEALTH_NOT_STABLE'
finally:
    p.terminate()
    try: p.wait(timeout=3)
    except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=3)
s = os.stat('/app/main.py')
print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'import':True,
                  'health_samples':success,'external_network':'none',
                  'source_uid':s.st_uid,'source_gid':s.st_gid,
                  'source_mode':oct(stat.S_IMODE(s.st_mode))}))
'''

def cmd(args, data=None):
    r = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=45)
    if r.returncode:
        raise RuntimeError('COMMAND_FAILED rc=%s stderr_sha256=%s' %
                           (r.returncode, hashlib.sha256(r.stderr).hexdigest()))
    return r.stdout

def snapshot():
    d = json.loads(cmd(['docker','inspect','telegram_bot_mommyramona']))[0]
    return {k:d[k] for k in ('Id','Image','RestartCount','State','Mounts','NetworkSettings')}

def main():
    assert os.geteuid() == 1001
    source = SOURCE.read_bytes()
    assert hashlib.sha256(source).hexdigest() == SHA
    before = snapshot()
    assert before['Image'] == IMAGE
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        for name, data in [('main.py', source), ('offline_harness.py', HARNESS.encode())]:
            info=tarfile.TarInfo(name); info.size=len(data); info.mode=0o644
            info.uid=info.gid=0; tar.addfile(info,io.BytesIO(data))
    results=[]
    for user in ('20001:20001','0:0'):
        name='tu1nz-v11-offline-'+uuid.uuid4().hex
        created=False
        try:
            cmd(['docker','create','--name',name,'--network','none','--user',user,
                 '--cap-drop','ALL','--security-opt','no-new-privileges:true',
                 '--memory','128m','--cpus','0.5','--pids-limit','64',
                 '--env','BOT_TOKEN=offline-dummy','--env','SECRET=offline-dummy',
                 '--env','PYTHONDONTWRITEBYTECODE=1',
                 '--entrypoint','python',IMAGE,'-I','-B','/app/offline_harness.py'])
            created=True
            cmd(['docker','cp','-',name+':/app/'],archive.getvalue())
            ins=json.loads(cmd(['docker','inspect',name]))[0]
            assert not ins['Mounts'] and not ins['HostConfig']['PortBindings']
            assert ins['HostConfig']['NetworkMode']=='none'
            for repeat in range(2):
                output=cmd(['docker','start','--attach',name])
                # docker start may return zero despite an application error.
                done=json.loads(cmd(['docker','inspect',name]))[0]
                assert done['State']['ExitCode']==0
                sample=json.loads(output.splitlines()[-1])
                assert sample['uid']==int(user.split(':')[0])
                assert sample['source_uid']==0 and sample['source_mode']=='0o644'
                results.append({'user':user,'repeat':repeat,**sample})
        finally:
            if created: cmd(['docker','rm','--force',name])
    assert snapshot()==before, 'PRODUCTION_SNAPSHOT_DRIFT'
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()==SHA
    print(json.dumps({'source_sha256':SHA,'image':IMAGE,'results':results,
                      'production_unchanged':True,'cleanup':True},sort_keys=True))

if __name__=='__main__': main()
