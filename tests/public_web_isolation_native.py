"""Native systemd fixture: synthetic daemon/data/credentials, no Host sockets.

Only run inside the separately owned, network-none PID1 test container with
read-only /source. Never a production probe or a systemd ancestor experiment.
"""
from datetime import datetime,timezone
import hashlib,json,os,shutil,signal,socket,stat,subprocess,threading,time
from pathlib import Path

ROOT=Path('/source')
APP=Path('/opt/tu1nz_repos/adult-publishing-core')
STATE=Path('/var/lib/tu1nz-adult-public-s9')
UNITS=('tu1nz-adult-public-s7.service','tu1nz-adult-public-s8-landing.service','tu1nz-adult-public-s10-wms.service')
PROBE=r'''
import ctypes,hashlib,json,os,socket,sys,stat
from pathlib import Path
profile='s7' if 'tu1nz-public-s7' in sys.argv[0] else ('s8-landing' if 'tu1nz-public-s8' in sys.argv[0] else 'wms')
uid=lambda p:Path(p).read_text().strip()
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
out={'profile':profile,'uid':os.getresuid(),'gid':os.getresgid(),'groups':os.getgroups(),
     'uid_map':uid('/proc/self/uid_map'),'gid_map':uid('/proc/self/gid_map'),
     'caps':{k:status[k].strip() for k in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')},
     'no_new_privileges':status['NoNewPrivs'].strip(),'argv':sys.argv[1:]}
for name,path in (('ordinary_admin','/run/public-isolation-admin.sock'),('pg_peer','/run/public-isolation-pg.sock')):
 s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
 try:
  s.connect(path);s.sendall(b'PING');out[name]={'connected':True,'response':s.recv(100).decode()}
 except OSError as e:out[name]={'connected':False,'errno':e.errno}
 finally:s.close()
operator=int(Path('/run/public-isolation-operator.pid').read_text())
for name,path in (('docker_socket','/run/docker.sock'),('containerd','/run/containerd'),('rootless_runtime','/run/user/1001')):
 try:
  if name=='docker_socket':
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:s.connect(path)
  else:list(Path(path).iterdir())
  out[name]={'accessible':True}
 except OSError as e:out[name]={'accessible':False,'errno':e.errno}
try:out['operator_root_alias']={'accessible':True,'root':os.readlink('/proc/'+str(operator)+'/root')}
except OSError as e:out['operator_root_alias']={'accessible':False,'errno':e.errno}
try:out['operator_home']={'readable':True,'bytes':len(Path('/home/chatops/synthetic-operator-secret').read_bytes())}
except OSError as e:out['operator_home']={'readable':False,'errno':e.errno}
if profile=='s7':
 path=Path(sys.argv[sys.argv.index('--form-secret')+1]);raw=path.read_bytes()
 out['credential']={'sha256':hashlib.sha256(raw).hexdigest(),'owner':path.stat().st_uid,
                    'mode':oct(stat.S_IMODE(path.stat().st_mode)),
                    'mount_readonly':bool(os.statvfs(path).f_flag&os.ST_RDONLY)}
 assert path.stat().st_uid==os.geteuid() and stat.S_IMODE(path.stat().st_mode)==0o600
if profile!='s7':
 path=Path(sys.argv[sys.argv.index('--aggregate-state')+1]);old=json.loads(path.read_text())
 temp=path.with_name(path.name+'.native-'+profile);temp.write_text(json.dumps(old));temp.chmod(0o600);os.replace(temp,path)
 out['state']={'preserved':json.loads(path.read_text())==old,'owner':path.stat().st_uid,'mode':oct(path.stat().st_mode&0o777)}
 if profile=='wms':
  path=Path(sys.argv[sys.argv.index('--traffic-quality-state')+1]);out['traffic_state']={'owner':path.stat().st_uid,'readable':bool(path.read_bytes())}
print('PUBLIC_ISOLATION_NATIVE_REPORT '+json.dumps(out,sort_keys=True),flush=True)
'''
def cmd(*args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=20)
 if r.returncode:raise RuntimeError(json.dumps({'command':args[:2],'exit':r.returncode,'stdout':r.stdout[-2000:],'stderr':r.stderr[-2000:]}))
 return r.stdout
def put(path,raw,mode=0o644):
 path.parent.mkdir(parents=True,exist_ok=True);assert not path.exists()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
 with os.fdopen(fd,'w') as f:f.write(raw)
def server(path,gid,mode,peer=False):
 s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(str(path));os.chown(path,0,gid);os.chmod(path,mode);s.listen(8)
 def serve():
  while True:
   try:
    conn,_=s.accept()
    with conn:
     conn.recv(100)
     if peer:
      import struct
      _,uid,gid_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));reply=str(uid)+':'+str(gid_)
     else:reply='SYNTHETIC_READ_ONLY_ADMIN_PING'
     conn.sendall(reply.encode())
   except OSError:return
 threading.Thread(target=serve,daemon=True).start();return s
def main():
 assert os.geteuid()==0 and os.environ.get('container')=='docker' and Path('/.dockerenv').is_file()
 assert ROOT.is_dir() and cmd('/usr/bin/findmnt','-n','-o','OPTIONS','--target',str(ROOT)).strip().startswith('ro')
 assert Path('/proc/1/comm').read_text().strip()=='systemd'
 cmd('/usr/sbin/groupadd','--gid','1001','chatops')
 cmd('/usr/sbin/groupadd','--gid','987','fixture-docker')
 cmd('/usr/sbin/useradd','--uid','1001','--gid','1001','--groups','987,27','--create-home','--shell','/bin/bash','chatops')
 put(Path('/home/chatops/synthetic-operator-secret'),'synthetic-not-production',0o600);os.chown('/home/chatops/synthetic-operator-secret',1001,1001)
 APP.mkdir(parents=True);(APP/'.venv/bin').mkdir(parents=True);(APP/'src/tu1nz_exposure_s10').mkdir(parents=True)
 program='#!/usr/bin/python3\n'+PROBE
 for name in ('tu1nz-public-s7','tu1nz-public-s8-landing'):put(APP/'.venv/bin'/name,program,0o755)
 os.symlink('/usr/bin/python3',APP/'.venv/bin/python');put(APP/'src/tu1nz_exposure_s10/runtime.py',PROBE)
 STATE.mkdir();os.chown(STATE,1001,1001);STATE.chmod(0o700)
 for name in ('landing-aggregates.json','wms-traffic-quality.json'):
  put(STATE/name,json.dumps({'synthetic_count':7}),0o600);os.chown(STATE/name,1001,1001)
 helper=Path('/usr/local/bin/tu1nz_public_web_isolate_r1.py');shutil.copyfile(ROOT/'scripts'/helper.name,helper);helper.chmod(0o555)
 Path('/run/containerd').mkdir();Path('/run/user/1001').mkdir(parents=True)
 put(Path('/run/containerd/synthetic-api'),'synthetic-only')
 put(Path('/run/user/1001/synthetic-api'),'synthetic-only')
 docker=server(Path('/run/docker.sock'),987,0o660)
 Path('/etc/tu1nz').mkdir(exist_ok=True)
 for name in ('adult-commercial-s7-form.secret','adult-commercial-s7-database.dsn'):put(Path('/etc/tu1nz')/name,'synthetic-only-'+name,0o400)
 # Test fixture dependency only, not a production PostgreSQL operation.
 put(Path('/etc/systemd/system/postgresql.service'),'[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n')
 for unit in UNITS:
  shutil.copyfile(ROOT/'systemd'/unit,Path('/etc/systemd/system')/unit)
  dest=Path('/etc/systemd/system')/(unit+'.d');dest.mkdir()
  src=ROOT/'systemd'/(unit+'.d')
  for p in src.glob('*.conf'):
   if p.name=='s9-growth.conf' or p.name=='zz-public-isolation-r1.conf':shutil.copyfile(p,dest/p.name)
  # Synthetic program exits after recording; no fixture retry or public ports.
  put(dest/'zzz-native-fixture.conf','[Service]\nType=oneshot\nRestart=no\nRemainAfterExit=yes\n')
 admin=server(Path('/run/public-isolation-admin.sock'),987,0o660)
 pg=server(Path('/run/public-isolation-pg.sock'),0,0o666,peer=True)
 operator=subprocess.Popen(['/usr/bin/setpriv','--reuid=1001','--regid=1001','--init-groups','/bin/sleep','180'])
 put(Path('/run/public-isolation-operator.pid'),str(operator.pid))
 try:
  cmd('/usr/bin/systemctl','daemon-reload');reports=[]
  for unit in UNITS:
   started=subprocess.run(['/usr/bin/systemctl','start',unit],capture_output=True,text=True,timeout=30)
   log=cmd('/usr/bin/journalctl','-u',unit,'--no-pager','-o','cat')
   if started.returncode:
    raise RuntimeError(json.dumps({'unit':unit,'exit':started.returncode,'journal':log[-4000:]}))
   lines=[line.partition('PUBLIC_ISOLATION_NATIVE_REPORT ')[2] for line in log.splitlines() if line.startswith('PUBLIC_ISOLATION_NATIVE_REPORT ')]
   assert len(lines)==1,log
   v=json.loads(lines[0]);assert v['uid']==[1001]*3 and v['gid']==[1001]*3 and not v['groups']
   assert all(int(x,16)==0 for x in v['caps'].values()) and v['no_new_privileges']=='1'
   assert not v['ordinary_admin']['connected'] and v['ordinary_admin']['errno'] in (1,13)
   assert v['pg_peer']=={'connected':True,'response':'1001:1001'}
   assert not v['operator_root_alias']['accessible'] and not v['operator_home']['readable']
   assert all(not v[name]['accessible'] for name in ('docker_socket','containerd','rootless_runtime'))
   if v['profile']!='s7':assert v['state']=={'preserved':True,'owner':1001,'mode':'0o600'}
   reports.append(v)
  # Ordinary service restart is allowed, not an S8 Telegram one-shot. Every
  # invocation must independently remove NSS groups/caps again.
  for unit in reversed(UNITS):cmd('/usr/bin/systemctl','stop',unit)
  for unit in UNITS:
   cmd('/usr/bin/systemctl','start',unit)
   lines=[line.partition('PUBLIC_ISOLATION_NATIVE_REPORT ')[2] for line in
          cmd('/usr/bin/journalctl','-u',unit,'--no-pager','-o','cat').splitlines()
          if line.startswith('PUBLIC_ISOLATION_NATIVE_REPORT ')]
   assert len(lines)==2
   v=json.loads(lines[-1]);assert not v['groups'] and all(int(x,16)==0 for x in v['caps'].values())
  negatives=[]
  for label,argv in (
    ('nonroot',['/usr/bin/setpriv','--reuid=1001','--regid=1001','--init-groups']),
    ('nested_namespace',['/usr/bin/unshare','--user','--map-root-user'])):
   result=subprocess.run(argv+['/usr/bin/python3','-I','-B','-S',str(helper),'--profile','wms'],capture_output=True,text=True,timeout=10)
   assert result.returncode==125 and 'PUBLIC_WEB_ISOLATION_DENIED' in result.stderr
   negatives.append(label)
  result=subprocess.run(['/usr/bin/python3','-I','-B','-S',str(helper),'--profile','s7'],capture_output=True,text=True,timeout=10)
  assert result.returncode==125 and 'PUBLIC_WEB_ISOLATION_DENIED' in result.stderr
  negatives.append('missing_credentials')
  # Real kernel rejection when the manager forbids user-namespace creation.
  deny=Path('/etc/systemd/system/public-isolation-namespace-denied.service')
  put(deny,'[Service]\nType=oneshot\nUser=chatops\nGroup=chatops\nRestrictNamespaces=yes\n'
      'ExecStart=!/usr/bin/python3 -I -B -S /usr/local/bin/tu1nz_public_web_isolate_r1.py --profile wms\n')
  cmd('/usr/bin/systemctl','daemon-reload')
  result=subprocess.run(['/usr/bin/systemctl','start',deny.name],capture_output=True,text=True,timeout=15)
  assert result.returncode!=0
  log=cmd('/usr/bin/journalctl','-u',deny.name,'--no-pager','-o','cat')
  assert 'PUBLIC_WEB_ISOLATION_NAMESPACE_CREATION_RED' in log and 'PUBLIC_ISOLATION_NATIVE_REPORT' not in log
  negatives.append('kernel_namespace_denial')
  # Real fork/map cleanup; only scheduling is delayed in this synthetic harness.
  harness=Path('/run/public-isolation-interruption.py')
  put(harness,'''import importlib.util,os,signal,sys,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('isolation',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
parent=os.getpid();real_select=m.select.select;real_fork=m.os.fork
def fork():
 pid=real_fork()
 if pid:Path('/run/public-isolation-owned-child').write_text(str(pid))
 return pid
def select(*args):
 if os.getpid()==parent:
  Path('/run/public-isolation-interruption-ready').write_text('ready')
  time.sleep(15)
 return real_select(*args)
m.os.fork=fork;m.select.select=select
signal.signal(signal.SIGTERM,m.interrupted)
try:m.establish_namespace();raise AssertionError('unexpected admission')
except m.Denied as error:
 assert error.primary=='PUBLIC_WEB_ISOLATION_BOOTSTRAP_INTERRUPTED'
 assert not error.abort and not error.cleanup
 print('NATIVE_INTERRUPTION_CLEANUP_GREEN',flush=True)
''')
  child=subprocess.Popen(['/usr/bin/python3','-I','-B',str(harness),str(helper)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:
   deadline=time.monotonic()+5
   while not Path('/run/public-isolation-interruption-ready').exists():
    assert time.monotonic()<deadline;time.sleep(0.01)
   owned_pid=int(Path('/run/public-isolation-owned-child').read_text())
   child.send_signal(signal.SIGTERM)
   out,err=child.communicate(timeout=5)
   assert child.returncode==0 and b'NATIVE_INTERRUPTION_CLEANUP_GREEN' in out and not err
   assert not Path('/proc',str(owned_pid)).exists()
  finally:
   if child.poll() is None:child.kill();child.wait(timeout=5)
   child.stdout.close();child.stderr.close()
  negatives.append('actual_sigterm_owned_creator_cleanup')
  print(json.dumps({'native_public_isolation':'GREEN','profiles':len(reports),'restart_profiles':3,'negative_cases':negatives,'reports':reports,
                    'production_host_or_credentials':False,'provider_operations':0},sort_keys=True))
 finally:
  # Only our synthetic operator process and listeners; retain fixture/evidence.
  operator.terminate();operator.wait(timeout=5);admin.close();pg.close();docker.close()
if __name__=='__main__':main()
