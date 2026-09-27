#!/usr/bin/env python3
"""Read-only sequential Phase5 client/server validation; never mutates policy."""
import sys,json,subprocess,pathlib,datetime,urllib.request,hashlib
BASE=pathlib.Path('/Users/daniel/.codex/tu1nz-recovery/phase5-20260924T162425Z')
SSH=['ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ForwardAgent=no','-o','ConnectTimeout=8','-o','ControlMaster=no','-o','ControlPath=none']
def collect():
 report={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'ssh':[],'http':[]}
 for user,port in [('chatops',22),('chatops',2222),('root',22),('nobody',22),('daemon',22)]:
  args=SSH+['-p',str(port)]
  if port==2222:args+=['-o','HostKeyAlias=100.121.130.51']
  p=subprocess.run(args+[user+'@100.121.130.51','id -un' if user=='chatops' else '/usr/bin/false'],capture_output=True,text=True,timeout=20)
  assert (p.returncode==0 and p.stdout.strip()=='chatops') if user=='chatops' else (p.returncode==255 and 'does not permit you to SSH' in p.stderr),(user,port,p.returncode)
  report['ssh'].append({'user':user,'port':port,'exit':p.returncode,'verified':True})
 for port,path,expected in [(3000,'/api/health','"database": "ok"'),(8080,'/healthz','ok'),(9090,'/-/ready','Ready'),(9100,'/metrics','node_')]:
  with urllib.request.urlopen('http://100.121.130.51:%d%s'%(port,path),timeout=5) as r:
   body=r.read(4000000).decode();assert r.status==200 and expected in body
   report['http'].append({'port':port,'status':r.status,'content_ok':True})
 with urllib.request.urlopen('https://tu1nz.com',timeout=12) as r:
  body=r.read(1000000).decode();assert r.status==200 and '<title>' in body.lower()
  report['website']=True
 code="""import subprocess,json,urllib.request
out={}
names=subprocess.check_output(['docker','ps','-aq'],text=True).split()
items=json.loads(subprocess.check_output(['docker','inspect']+names,text=True))
out['containers']=[{'name':x['Name'],'id':x['Id'],'started':x['State']['StartedAt'],'restarts':x['RestartCount'],'status':x['State']['Status'],'health':x['State'].get('Health',{}).get('Status'),'ports':x['HostConfig']['PortBindings'],'networks':sorted(x['NetworkSettings']['Networks'])} for x in items]
out['containers'].sort(key=lambda x:x['name'])
s=json.loads(subprocess.check_output(['tailscale','status','--json'],text=True));assert s['BackendState']=='Running' and not s.get('Health');assert s['Self']['ExitNodeOption']
out['tailscale']={'Running':True,'exit_node':True}
t=json.load(urllib.request.urlopen('http://127.0.0.1:9090/api/v1/targets',timeout=5))['data']['activeTargets']
out['targets']=[{'job':x['labels']['job'],'health':x['health'],'error':x['lastError'],'lastScrape':x['lastScrape']} for x in t];assert {x['job'] for x in out['targets']}=={'node','cadvisor'};assert all(x['health']=='up' and not x['error'] for x in out['targets'])
out['services']=subprocess.check_output(['systemctl','show','tu1nz-doc.service','tu1nz-health.service','tu1nz_encrypted_backup.service','--property=Id,Result'],text=True);assert out['services'].count('Result=success')==3
out['firewall']=json.loads(subprocess.check_output(['hcloud','firewall','describe','10043301','-o','json'],text=True))
out['listeners']=sorted(line.split()[3] for line in subprocess.check_output(['ss','-lntH'],text=True).splitlines())
print(json.dumps(out))
"""
 r=subprocess.run(SSH+['chatops@100.121.130.51','python3 -'],input=code,text=True,capture_output=True,timeout=25);assert r.returncode==0, r.stderr
 report['server']=json.loads(r.stdout);return report
if __name__=='__main__':
 mode=sys.argv[1];assert mode in ['before','after','stable']
 report=collect()
 if mode!='before':
  old=json.loads((BASE/'before.json').read_text())
  for key in ['containers','firewall','listeners','services']:assert report['server'][key]==old['server'][key],key+' drift'
 p=BASE/(mode+'.json')
 with p.open('x') as h:json.dump(report,h,indent=2)
 p.chmod(0o600)
 print(mode.upper()+'_PASS',report['utc'],flush=True)
