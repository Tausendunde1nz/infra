#!/usr/bin/env python3
"""Scoped privileged TU1NZ monitoring transaction; no arbitrary command execution."""
import datetime,hashlib,json,os,pathlib,pwd,signal,subprocess,time,urllib.request,urllib.parse,tarfile
BASE=pathlib.Path('/opt/tu1nz_repos/network-hardening-private-2026-09-22')
CFG=pathlib.Path('/tausendunde1nz/05_it_security/monitoring/prometheus.yml')
COMPOSE=CFG.with_name('docker-compose.yml')
EXPECTED='081e1550575ef642607b1823f7e3f91ec63893a1d50dd121e066d562effe51be'
PROM='tu1nz_prometheus'
RULE=['allow','in','on','br-5f7adc44a8c3','proto','tcp','from','172.29.0.4','to','172.29.0.1','port','9100','comment','tu1nz-prom-node-20260922']
assert os.geteuid()==0
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
OUT=BASE/('monitor-transaction-'+stamp);OUT.mkdir(mode=0o700);os.chmod(OUT,0o700)
uid=pwd.getpwnam('chatops').pw_uid;gid=pwd.getpwnam('chatops').pw_gid
signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(RuntimeError('Termination requested')))
signal.signal(signal.SIGHUP,lambda *_: (_ for _ in ()).throw(RuntimeError('Terminal disconnected')))
os.chown(OUT,uid,gid)
def put(name,data):
 if isinstance(data,str):data=data.encode()
 p=OUT/name
 with p.open('xb') as f:f.write(data)
 os.chmod(p,0o600);os.chown(p,uid,gid)
def run(*cmd,data=None,timeout=20):
 r=subprocess.run(cmd,input=data,capture_output=True,timeout=timeout)
 if r.returncode:
  raise RuntimeError('Command failed: '+cmd[0]+' '+cmd[1]+' exit '+str(r.returncode))
 return r.stdout
ufw_sequence=0
def ufw_change(*args):
 global ufw_sequence
 ufw_sequence+=1
 for filename in ['user.rules','user6.rules']:
  put('ufw-before-write-'+str(ufw_sequence)+'-'+filename,pathlib.Path('/etc/ufw',filename).read_bytes())
 return run('ufw',*args)
def api(path):
 with urllib.request.urlopen('http://127.0.0.1:9090'+path,timeout=5) as r:return json.load(r)
def inspect(name):
 return json.loads(run('docker','inspect',name))[0]
def baseline():
 names=run('docker','ps','--format','{{.Names}}').decode().splitlines()
 return {
 n:{'id':(d:=inspect(n))['Id'],'started':d['State']['StartedAt'],
 'restarts':d['RestartCount'],'ports':d['HostConfig']['PortBindings'],
 'networks':sorted(d['NetworkSettings']['Networks']),'health':d['State'].get('Health',{}).get('Status')}
 for n in names}
def listeners():
 return sorted(x.split()[3] for x in run('ss','-H','-lnt').decode().splitlines())
def drop_check():
 d=json.loads(run('nft','-j','list','ruleset'))
 chains=[x['chain'] for x in d['nftables'] if 'chain' in x]
 for family in ['ip','ip6']:
  assert any(c.get('family')==family and c.get('name')=='INPUT' and c.get('policy')=='drop' for c in chains)
def config_write(data):
 fd=os.open(CFG,os.O_WRONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'r+b') as f:f.seek(0);f.write(data);f.truncate();f.flush();os.fsync(f.fileno())
def reload_prom():
 run('docker','kill','--signal=HUP',PROM)
def wait_marker(name,seconds):
 deadline=time.monotonic()+seconds
 while time.monotonic()<deadline:
  if (OUT/'ABORT').exists():raise RuntimeError('Operator abort')
  p=OUT/name
  if p.exists():
   assert not p.is_symlink()
   return json.loads(p.read_text())
  time.sleep(2)
 raise TimeoutError('Missing '+name)
original=CFG.read_bytes();assert hashlib.sha256(original).hexdigest()==EXPECTED
candidate=original.replace(b'localhost:9100',b'172.29.0.1:9100').replace(b'localhost:8080',b'cadvisor:8080')
assert original.count(b'localhost:9100')==original.count(b'localhost:8080')==1
assert candidate.replace(b'172.29.0.1:9100',b'localhost:9100').replace(b'cadvisor:8080',b'localhost:8080')==original
net=json.loads(run('docker','network','inspect','monitoring_default'))[0]
assert net['Id'].startswith('5f7adc44a8c3')
assert net['IPAM']['Config']==[{'Subnet':'172.29.0.0/16','Gateway':'172.29.0.1'}]
assert inspect(PROM)['NetworkSettings']['Networks']['monitoring_default']['IPAddress']=='172.29.0.4'
assert inspect('tu1nz_node_exporter')['HostConfig']['NetworkMode']=='host'
before=baseline();binds=listeners()
put('containers-before.json',json.dumps(before,indent=2))
put('listeners-before.json',json.dumps(binds))
put('prometheus-original.yml',original);put('prometheus-candidate.yml',candidate)
put('compose-original.yml',COMPOSE.read_bytes())
put('file-metadata.json',json.dumps({str(p):{'uid':p.stat().st_uid,'gid':p.stat().st_gid,'mode':oct(p.stat().st_mode&0o777),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [CFG,COMPOSE]}))
archive=OUT/'ufw-original.tar.gz'
with archive.open('xb') as f:
 with tarfile.open(fileobj=f,mode='w:gz') as t:t.add('/etc/ufw',arcname='etc/ufw')
os.chmod(archive,0o600);os.chown(archive,uid,gid)
ufwfiles={str(p):p.read_bytes() for p in pathlib.Path('/etc/ufw').rglob('*') if p.is_file() and not p.is_symlink()}
for name,cmd in [('nft-before.json',['nft','-j','list','ruleset']),('iptables-before.txt',['iptables-save','-c']),('ip6tables-before.txt',['ip6tables-save','-c']),('ufw-status.txt',['ufw','status','verbose']),('route.txt',['docker','exec',PROM,'ip','route','get','172.29.0.1'])]:
 put(name,run(*cmd))
drop_check()
put('promtool-candidate.txt',run('docker','exec','-i',PROM,'/bin/promtool','check','config','/dev/stdin',data=candidate))
put('promtool-rollback.txt',run('docker','exec','-i',PROM,'/bin/promtool','check','config','/dev/stdin',data=original))
put('ufw-add-dry-run.txt',run('ufw','--dry-run',*RULE))
delete_check=subprocess.run(['ufw','--dry-run','delete',*RULE],capture_output=True,timeout=20)
put('ufw-delete-dry-run.txt',delete_check.stdout+delete_check.stderr)
assert delete_check.returncode==0 or b'non-existent' in delete_check.stdout+delete_check.stderr
assert b'tu1nz-prom-node-20260922' not in run('ufw','status')
start=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
probe=subprocess.run(['docker','exec',PROM,'/bin/wget','-q','-T','4','-O','/dev/null','http://172.29.0.1:9100/metrics'],capture_output=True,timeout=10)
put('blocked-probe.json',json.dumps({'exit':probe.returncode,'stderr':probe.stderr.decode()}))
put('iptables-after-probe.txt',run('iptables-save','-c'))
put('kernel-probe.txt',run('journalctl','-k','--since',start,'--no-pager','-o','cat'))
put('SHA256SUMS',''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(OUT.iterdir()) if p.is_file()))
put('DIAGNOSTIC_READY.json',json.dumps({'utc':stamp,'probe_exit':probe.returncode,'live_changed':False}))
print('DIAGNOSTIC_READY',OUT,flush=True)
print('Terminal offen lassen. Codex prueft den Befund vor jeder Aktivierung.',flush=True)
rule_added=False;config_changed=False
try:
 gate=wait_marker('ACTIVATE.json',1800)
 assert gate.get('cause_confirmed') is True and gate.get('documentation_pushed') is True
 assert gate.get('config_sha256')==EXPECTED
 assert probe.returncode!=0
 assert CFG.read_bytes()==original and COMPOSE.read_bytes()==(OUT/'compose-original.yml').read_bytes()
 assert baseline()==before and listeners()==binds
 assert {str(p):p.read_bytes() for p in pathlib.Path('/etc/ufw').rglob('*') if p.is_file() and not p.is_symlink()}==ufwfiles
 rule_added=True;put('ufw-add.txt',ufw_change(*RULE))
 # Exact delete/add round-trip proves the live rollback path before config reload.
 put('ufw-delete-test.txt',ufw_change('delete',*RULE));rule_added=False
 assert {str(p):p.read_bytes() for p in pathlib.Path('/etc/ufw').rglob('*') if p.is_file() and not p.is_symlink()}==ufwfiles
 rule_added=True;put('ufw-readd.txt',ufw_change(*RULE))
 put('internal-node-test.txt',run('docker','exec',PROM,'/bin/wget','-q','-T','5','-O','/dev/null','http://172.29.0.1:9100/metrics'))
 config_changed=True;config_write(candidate)
 reload_prom()
 deadline=time.monotonic()+45
 while time.monotonic()<deadline:
  targets=api('/api/v1/targets')['data']['activeTargets']
  if len(targets)==2 and all(t['health']=='up' and not t['lastError'] for t in targets):break
  time.sleep(3)
 else:raise RuntimeError('Targets did not become healthy')
 samples=[]
 for i in range(21):
  targets=api('/api/v1/targets')['data']['activeTargets']
  assert len(targets)==2 and {t['labels']['job'] for t in targets}=={'node','cadvisor'}
  assert all(t['health']=='up' and not t['lastError'] for t in targets)
  samples.append({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'targets':[{'job':t['labels']['job'],'health':t['health'],'scrape':t['lastScrape']} for t in targets]})
  assert baseline()==before and listeners()==binds
  drop_check()
  if i<20:time.sleep(15)
 put('stable-samples.json',json.dumps(samples,indent=2))
 assert run('fail2ban-client','get','sshd','action','nftables','port').strip()==b'2222'
 put('nft-after.json',run('nft','-j','list','ruleset'))
 put('WAITING_FOR_MAC_TESTS.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stable_seconds':300}))
 print('WAITING_FOR_MAC_TESTS',OUT,flush=True)
 result=wait_marker('MAC_TESTS_PASSED.json',600)
 assert result.get('chatops_22') and result.get('chatops_2222') and result.get('metrics_valid')
 assert CFG.read_bytes()==candidate and baseline()==before and listeners()==binds
 put('COMPLETE.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'result':result}))
 print('MONITORING_COMPLETE',flush=True)
except BaseException:
 if config_changed:
  assert CFG.read_bytes() in [original,candidate], 'Concurrent config change; manual recovery required'
  put('config-before-rollback.yml',CFG.read_bytes())
  config_write(original);reload_prom()
 if rule_added:
  put('rule-rollback.txt',ufw_change('delete',*RULE))
 if config_changed or rule_added:
  assert CFG.read_bytes()==original
  assert {str(p):p.read_bytes() for p in pathlib.Path('/etc/ufw').rglob('*') if p.is_file() and not p.is_symlink()}==ufwfiles
  drop_check()
  put('ROLLED_BACK.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'original_config':True,'original_ufw_files':True}))
  print('MONITORING_ROLLED_BACK',flush=True)
 raise
