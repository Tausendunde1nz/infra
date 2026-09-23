#!/usr/bin/python3
"""Minimal authorized provider-only transaction; automatic exact rules rollback."""
import pathlib,subprocess,json,hashlib,time,datetime,os,signal,urllib.request
B=pathlib.Path('/opt/tu1nz_repos/network-hardening-private-2026-09-22/hetzner-phase4-20260923T182627Z')
ID='10043301'
def run(*a):return subprocess.check_output(a,stderr=subprocess.STDOUT,timeout=90)
def put(n,x):
 with (B/n).open('xb') as f:f.write(x)
 os.chmod(B/n,0o600)
def read():return json.loads(run('hcloud','firewall','describe',ID,'-o','json'))
def canon(rules):
 return sorted([dict(direction=r['direction'],protocol=r['protocol'],port=r.get('port') or None,source_ips=sorted(r.get('source_ips',[])),destination_ips=sorted(r.get('destination_ips',[])),description=r.get('description') or None) for r in rules],key=lambda r:json.dumps(r,sort_keys=True))
def containers():
 ids=run('docker','ps','-aq').decode().split()
 objects=json.loads(run('docker','inspect',*ids))
 return {c['Name']:{'id':c['Id'],'started':c['State']['StartedAt'],'restarts':c['RestartCount'],'status':c['State']['Status'],'health':c['State'].get('Health',{}).get('Status'),'ports':c['HostConfig']['PortBindings'],'networks':{k:v.get('IPAddress') for k,v in c['NetworkSettings']['Networks'].items()}} for c in objects}
def check_monitoring():
 with urllib.request.urlopen('http://127.0.0.1:9090/api/v1/targets',timeout=5) as r:j=json.load(r)
 t={x['labels']['job']:x for x in j['data']['activeTargets']}
 assert {'node','cadvisor'}<=set(t)
 for name in ['node','cadvisor']:assert t[name]['health']=='up' and not t[name]['lastError']
 return {k:{x:t[k][x] for x in ['health','lastError','lastScrape']} for k in ['node','cadvisor']}
def main():
 before=json.loads((B/'original-firewall.json').read_text());old=json.loads((B/'rollback-rules.json').read_text());new=json.loads((B/'candidate-rules.json').read_text())
 for line in (B/'SHA256SUMS').read_text().splitlines():
  h,n=line.split('  ',1);assert hashlib.sha256((B/n).read_bytes()).hexdigest()==h
 assert canon(old)==canon(before['rules'])
 assert {(r['protocol'],r['port']) for r in new}=={('tcp','80'),('tcp','443'),('icmp',None)}
 assert all(r['direction']=='in' and set(r['source_ips'])=={'0.0.0.0/0','::/0'} and not r['destination_ips'] for r in new)
 current=read();assert current==before,'Provider drift before activation'
 state=containers();check_monitoring();put('containers-before.json',json.dumps(state,sort_keys=True).encode())
 def interrupted(*a):raise RuntimeError('Signal interrupted transaction')
 for sig in [signal.SIGINT,signal.SIGTERM,signal.SIGHUP]:signal.signal(sig,interrupted)
 attempted=False
 try:
  attempted=True
  put('apply-output.txt',run('hcloud','firewall','replace-rules',ID,'--rules-file',str(B/'candidate-rules.json')))
  current=read();assert canon(current['rules'])==canon(new) and current['applied_to']==before['applied_to']
  put('after-firewall.json',json.dumps(current,indent=2).encode())
  put('WAITING_FOR_EXTERNAL.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'timeout_seconds':600}).encode())
  print('PHASE4_WAITING_FOR_EXTERNAL',B,flush=True)
  end=time.monotonic()+600;samples=[]
  while time.monotonic()<end:
   assert not (B/'ROLLBACK').exists(),'Explicit rollback'
   assert containers()==state,'Container state drift'
   samples.append(check_monitoring())
   if (B/'VALIDATED.json').exists():
    ack=json.loads((B/'VALIDATED.json').read_text())
    assert all(ack.get(k) is True for k in ['web_dns','ssh_both','forbidden_users','internal_ports_blocked','monitoring','health_backup','tailscale'])
    assert canon(read()['rules'])==canon(new)
    put('monitoring-samples.json',json.dumps(samples).encode())
    put('COMPLETE.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'validation':ack}).encode());print('PHASE4_COMPLETE',flush=True);return
   time.sleep(5)
  raise TimeoutError('External validation missing')
 except BaseException:
  if attempted:
   # Restore the exact original rules even if an interrupted apply was partial.
   put('rollback-output.txt',run('hcloud','firewall','replace-rules',ID,'--rules-file',str(B/'rollback-rules.json')))
   current=read();assert canon(current['rules'])==canon(old) and current['applied_to']==before['applied_to']
   put('ROLLED_BACK.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'firewall':current}).encode())
   print('PHASE4_ROLLED_BACK',flush=True)
  raise
if __name__=='__main__':main()
