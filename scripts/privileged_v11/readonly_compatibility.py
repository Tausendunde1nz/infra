"""Offline-only compatibility; ephemeral test container, no production mounts."""
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid
import yaml

NAME='telegram_bot_mommyramona'
SOURCE=Path('/opt/telegram_chatbot')
IMAGE='sha256:f0c7c619b45ffb475d79c2339fbef21ced03c6e83d919d321ef89b40cd4889db'
HASH='f7119919cd3bff8193b72782ec984633cd222abad87281df011455fb7313a8bd'
HARNESS=r'''
import errno,json,os,runpy,subprocess,time,urllib.request,requests
assert os.getuid()==os.getgid()==20001
s=dict(x.split(':',1) for x in open('/proc/self/status') if ':' in x)
assert int(s['CapEff'].strip(),16)==0
assert int(s['CapBnd'].strip(),16)==0
assert s['NoNewPrivs'].strip()=='1'
assert set(os.listdir('/sys/class/net'))=={'lo'}
denied=[]
for name in ['/app/main.py','/app/.env','/app/new-file','/tmp/new-file','/etc/new-file']:
 try:
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
 except OSError as e:
  assert e.errno in (errno.EACCES,errno.EROFS)
  denied.append(name)
 else:
  os.close(fd);raise AssertionError('UNEXPECTED_WRITE_PERMISSION')
def no_external(*a,**k):raise AssertionError('EXTERNAL_CALL')
requests.sessions.Session.request=no_external
module=runpy.run_path('/app/main.py',run_name='offline_import')
assert module['app'].test_client().get('/health').status_code==200
p=subprocess.Popen(['python','-I','-B','/app/main.py'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
 start=time.monotonic();count=0
 while time.monotonic()-start<15:
  assert p.poll() is None
  try:
   with urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=1) as r:
    assert r.status==200;count+=1
  except OSError:pass
  if count>=3:break
  time.sleep(.25)
 assert count>=3
finally:
 p.terminate()
 try:p.wait(timeout=3)
 except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
print(json.dumps({'uid':20001,'gid':20001,'cap_eff':0,'cap_bnd':0,'no_new_privs':1,
                  'health_samples':count,'write_denied':denied,'needed_writable_paths':[]}))
'''

def run(args):
    r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
    if r.returncode:
        raise RuntimeError('command_failed:'+str(r.returncode)+':'+hashlib.sha256(r.stderr).hexdigest())
    return r.stdout

def snapshot():
    c=json.loads(run(['docker','inspect',NAME]))[0]
    return {k:c[k] for k in ['Id','Image','State','RestartCount','Config','HostConfig','Mounts','NetworkSettings']}

def main():
    assert os.geteuid()==1001
    before=snapshot();source=(SOURCE/'main.py').read_bytes()
    assert hashlib.sha256(source).hexdigest()==HASH and before['Image']==IMAGE
    name='tu1nz-v11-readonly-'+uuid.uuid4().hex
    created=False
    with tempfile.TemporaryDirectory(prefix='tu1nz-v11-readonly-') as scratch:
        root=Path(scratch);app=root/'app';app.mkdir(mode=0o755)
        for n,b in [('main.py',source),('harness.py',HARNESS.encode()),('.env',b'BOT_TOKEN=offline-dummy\nSECRET=offline-dummy\n')]:
            (app/n).write_bytes(b);os.chmod(app/n,0o644)
        compose=(SOURCE/'docker-compose.yml').read_bytes()
        original=yaml.safe_load(compose);candidate=yaml.safe_load(compose)
        service=candidate['services'][NAME]
        assert service['volumes']==['.:/app']
        service.update(user='20001:20001',cap_drop=['ALL'],security_opt=['no-new-privileges:true'],read_only=True,volumes=['.:/app:ro'])
        (root/'.env').write_bytes((app/'.env').read_bytes())
        renders=[]
        for label,value in [('original',original),('candidate',candidate)]:
            path=root/(label+'.yml');path.write_text(yaml.safe_dump(value,sort_keys=False))
            data=json.loads(run(['docker','compose','--project-name','tu1nz-v11-offline','--project-directory',str(root),'-f',str(path),'config','--format','json']))
            renders.append(data['services'][NAME])
        allowed={'user','cap_drop','security_opt','read_only','volumes'}
        changed={k for k in set(renders[0])|set(renders[1]) if renders[0].get(k)!=renders[1].get(k)}
        assert changed==allowed,changed
        assert renders[0]['ports']==renders[1]['ports']
        assert renders[0].get('networks')==renders[1].get('networks')
        try:
            run(['docker','create','--name',name,'--network','none','--user','20001:20001',
                 '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',
                 '--memory','128m','--cpus','0.5','--pids-limit','64',
                 '--mount','type=bind,src='+str(app)+',dst=/app,readonly,bind-propagation=rprivate',
                 '--env','BOT_TOKEN=offline-dummy','--env','SECRET=offline-dummy',
                 '--env','PYTHONDONTWRITEBYTECODE=1','--entrypoint','python',IMAGE,'-I','-B','/app/harness.py'])
            created=True;results=[]
            for _ in range(2):
                result=run(['docker','start','--attach',name]);c=json.loads(run(['docker','inspect',name]))[0]
                assert c['State']['ExitCode']==0
                assert c['HostConfig']['ReadonlyRootfs'] and c['Mounts'][0]['RW'] is False
                results.append(json.loads(result.splitlines()[-1]))
        finally:
            if created:run(['docker','rm','--force',name])
        assert snapshot()==before
        assert (SOURCE/'docker-compose.yml').read_bytes()==compose
        assert (SOURCE/'main.py').read_bytes()==source
        print(json.dumps({'compose_changed_keys':sorted(changed),'ports_unchanged':True,
                          'networks_unchanged_in_render':True,'results':results,
                          'source_sha256':HASH,'compose_sha256':hashlib.sha256(compose).hexdigest(),
                          'production_unchanged':True,'cleanup':True}))

if __name__=='__main__':main()
