#!/usr/bin/env python3
"""External Mac supervisor. Failures trigger exact provider rollback over held SSH."""
import datetime,errno,hashlib,importlib.util,json,os,pathlib,re,signal,socket,subprocess,time
LOCAL=pathlib.Path('/Users/daniel/.codex/tu1nz-recovery/20260923T185834Z')
REMOTE='/opt/tu1nz_repos/network-hardening-private-2026-09-22/hetzner-phase4-retry-20260923T185834Z'
CHECKER=pathlib.Path('/Users/daniel/.codex/tu1nz-recovery/20260923T182627Z/tu1nz_public_port_check.py')
assert hashlib.sha256(CHECKER.read_bytes()).hexdigest()=='9ad7003f8b841b44509554ab4caa73ab923886662bf6a910f75ee2d64500cdab'
spec=importlib.util.spec_from_file_location('ports',CHECKER);ports=importlib.util.module_from_spec(spec);spec.loader.exec_module(ports)
SSH=['ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ForwardAgent=no','-o','ConnectTimeout=8']
SOCK=str(LOCAL/'ssh-control')
HELD=SSH+['-S',SOCK,'chatops@100.121.130.51']
report={'started':datetime.datetime.now(datetime.timezone.utc).isoformat(),'ports':[]}
def cmd(args,timeout=30):return subprocess.check_output(args,stderr=subprocess.PIPE,timeout=timeout)
def remote(command,timeout=30):return cmd(HELD+[command],timeout)
def remote_json(name):return json.loads(remote('cat '+REMOTE+'/'+name))
def marker(name):remote('umask 077; touch '+REMOTE+'/'+name)
def save(name,obj):
 p=LOCAL/name
 with p.open('x') as f:json.dump(obj,f,indent=2)
 os.chmod(p,0o600)
def websites():
 rows=[]
 for host,expected in [('n8n.mychatbuddy.dev',200),('lighting.tu1nz.com',200),('tu1nz.com',200),('wantmeseen.com',200),('wantmeseen.de',308)]:
  ips=sorted({r[4][0] for r in socket.getaddrinfo(host,443)});assert '91.98.112.14' in ips
  for scheme,status in [('http',301),('https',expected)]:
   raw=cmd(['curl','--silent','--show-error','--max-time','12','--dump-header','-',scheme+'://'+host+'/']).decode(errors='replace')
   headers,body=raw.split('\r\n\r\n',1) if '\r\n\r\n' in raw else raw.split('\n\n',1)
   code=int(headers.splitlines()[0].split()[1]);assert code==status,(host,scheme,code)
   title=''
   if status==200:
    match=re.search(r'<title[^>]*>(.*?)</title>',body,re.I|re.S);assert len(body)>100 and match,(host,'implausible HTML')
    title=' '.join(match.group(1).split())
   else:assert re.search(r'(?im)^location:\s*https://',headers),('missing redirect',host)
   rows.append({'host':host,'scheme':scheme,'code':code,'title':title,'dns':ips})
 return rows

def ssh_matrix():
 rows=[]
 for user,port in [('chatops',22),('chatops',2222),('root',22),('nobody',22),('daemon',22)]:
  args=SSH+['-o','ControlMaster=no','-o','ControlPath=none','-p',str(port)]
  if port==2222:args+=['-o','HostKeyAlias=100.121.130.51']
  r=subprocess.run(args+[user+'@100.121.130.51','id -un' if user=='chatops' else '/usr/bin/false'],capture_output=True,text=True,timeout=20)
  ok=(r.returncode==0 and r.stdout.strip()=='chatops') if user=='chatops' else (r.returncode==255 and 'does not permit you to SSH' in r.stderr)
  assert ok,(user,port,r.returncode)
  rows.append({'user':user,'port':port,'exit':r.returncode})
 return rows

def collect_ports():
 rows=[];deadline=time.monotonic()+90
 for address in ports.ADDRESSES:
  # Positive reachability to the same family prevents an unavailable route passing negatives.
  with socket.create_connection((address,443),timeout=5):pass
  for port in ports.PORTS:
   attempts=[]
   for attempt in range(3):
    assert time.monotonic()<deadline,'Port matrix deadline'
    result=ports.probe(address,port);attempts.append(result)
    if result in ('BLOCKED_TIMEOUT','REFUSED'):break
    if result!='FAIL_CONNECTED':raise RuntimeError(('Inconclusive port test',address,port,result))
    time.sleep(3)
   assert result in ('BLOCKED_TIMEOUT','REFUSED'),('Unexpected public admission',address,port)
   rows.append({'address':address,'port':port,'result':result,'attempts':attempts})
 assert ports.passed(rows)
 # Additional actual localhost listeners within the old broad interval.
 for address in ports.ADDRESSES:
  for port in [5432,5678]:
   try:
    with socket.create_connection((address,port),timeout=2):pass
   except OSError as e:result=ports.classify(e)
   else:result='FAIL_CONNECTED'
   assert result in ('BLOCKED_TIMEOUT','REFUSED'),(address,port,result)
   rows.append({'address':address,'port':port,'result':result})
 return rows

def main():
 master=None;tx=None;activated=False;completed=False
 try:
  # Held channel is established before arming the external failure handler.
  master=subprocess.Popen(SSH+['-M','-S',SOCK,'-o','ControlPersist=no','-N','chatops@100.121.130.51'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  end=time.monotonic()+15
  while not pathlib.Path(SOCK).exists():
   assert master.poll() is None and time.monotonic()<end,'Cannot establish held recovery channel';time.sleep(.1)
  report['web_before']=websites();report['ssh_before']=ssh_matrix()
  report['pre_privileged']=remote_json('PRE_PRIVILEGED.json')
  for key in ['default_drop','fail2ban_2222','sshd_chatops_only']:assert report['pre_privileged'][key]
  assert json.loads(remote('hcloud firewall describe 10043301 -o json'))==json.loads((LOCAL/'original-firewall.json').read_text())
  save('EXTERNAL_ROLLBACK_ARMED.json',{'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'held_ssh':True,'fallback_server_guard':True})
  activated=True
  log=(LOCAL/'transaction-output.txt').open('xb');os.chmod(LOCAL/'transaction-output.txt',0o600)
  tx=subprocess.Popen(HELD+['python3 '+REMOTE+'/transaction.py'],stdout=log,stderr=subprocess.STDOUT)
  end=time.monotonic()+90
  while time.monotonic()<end:
   if tx.poll() is not None:raise RuntimeError('Provider transaction exited before validation')
   ready=remote('test -f '+REMOTE+'/WAITING_FOR_EXTERNAL.json && echo READY || true').strip()
   if ready==b'READY':break
   time.sleep(1)
  else:raise TimeoutError('Provider action did not become ready')
  time.sleep(3) # bounded propagation delay; failed admissions receive at most two more retries
  report['web_after']=websites();assert report['web_after']==report['web_before'],'Website/DNS/title drift'
  report['ssh_after']=ssh_matrix();report['ports']=collect_ports()
  marker('CHECK_POST');end=time.monotonic()+45
  while time.monotonic()<end:
   if remote('test -f '+REMOTE+'/POST_PRIVILEGED.json && echo READY || true').strip()==b'READY':break
   time.sleep(1)
  else:raise TimeoutError('Privileged postcheck missing')
  report['post_privileged']=remote_json('POST_PRIVILEGED.json')
  for key in ['default_drop','fail2ban_2222','sshd_chatops_only']:assert report['post_privileged'][key]
  # Provider action must not change any local rule or listening address.
  pre=report['pre_privileged']['evidence'];post=report['post_privileged']['evidence']
  def normalize(x):
   if isinstance(x,dict):return {k:normalize(v) for k,v in x.items() if k not in ('handle','counter','metainfo')}
   if isinstance(x,list):return [normalize(v) for v in x]
   return x
  assert normalize(json.loads(remote('cat '+pre+'/nft.json')))==normalize(json.loads(remote('cat '+post+'/nft.json'))),'Local firewall drift'
  def bindings(data):return sorted((f[0],f[4]) for line in data.decode().splitlines()[1:] if len(f:=line.split())>=5)
  assert bindings(remote('cat '+pre+'/listeners.txt'))==bindings(remote('cat '+post+'/listeners.txt')),'Listener drift'
  report['services']=remote('systemctl show tu1nz-doc.service tu1nz-health.service tu1nz_encrypted_backup.service --property=Id,Result').decode()
  assert report['services'].count('Result=success')==3
  ts=json.loads(remote('tailscale status --json'));assert ts['BackendState']=='Running' and not ts.get('Health')
  report['tailscale_running']=True
  # At least60 seconds of guarded observation after provider readiness.
  elapsed=time.monotonic()-(end-45)
  if elapsed<30:time.sleep(30-elapsed)
  assert tx.poll() is None,'Rollback guard ended unexpectedly'
  ack={k:True for k in ['web_dns','ssh_both','forbidden_users','internal_ports_blocked','monitoring','health_backup','tailscale']}
  payload=json.dumps(ack)
  remote("python3 -c 'import pathlib,os; p=pathlib.Path(\""+REMOTE+"/VALIDATED.json\"); p.write_text(\""+payload.replace('"','\\"')+"\"); os.chmod(p,0o600)'")
  assert tx.wait(timeout=30)==0,'Provider guard did not complete'
  report['completion']=remote_json('COMPLETE.json')
  report['final_firewall']=json.loads(remote('hcloud firewall describe 10043301 -o json'))
  assert report['final_firewall']['rules']==json.loads((LOCAL/'candidate-rules.json').read_text())
  save('EXTERNAL_COMPLETE.json',report);completed=True;print('PHASE4_EXTERNAL_COMPLETE',flush=True)
 except BaseException as error:
  report['error']=type(error).__name__+': '+str(error)
  if activated and not completed:
   try:
    marker('ROLLBACK')
    if tx is not None:
     try:tx.wait(timeout=25)
     except subprocess.TimeoutExpired:pass
    original=json.loads((LOCAL/'original-firewall.json').read_text())
    current=json.loads(remote('hcloud firewall describe 10043301 -o json'))
    if current!=original:
     remote('hcloud firewall replace-rules 10043301 --rules-file '+REMOTE+'/rollback-rules.json',90)
    assert json.loads(remote('hcloud firewall describe 10043301 -o json'))==original
    report['rollback_verified']=True;report['web_rollback']=websites();report['ssh_rollback']=ssh_matrix()
   except BaseException as recovery_error:report['rollback_error']=str(recovery_error)
  save('EXTERNAL_FAILED.json',report)
  raise
 finally:
  if master is not None:
   subprocess.run(SSH+['-S',SOCK,'-O','exit','chatops@100.121.130.51'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
if __name__=='__main__':
 import sys
 if sys.argv[1:]==['--preflight']:print(json.dumps({'web':websites(),'ssh':ssh_matrix()},indent=2))
 elif sys.argv[1:]==['--apply']:main()
 else:raise SystemExit('Use --preflight or --apply')
