#!/usr/bin/python3
"""Sequential post-policy evidence; never mutates policy or marks success."""
import importlib.util,pathlib,json,subprocess,socket,datetime,os,sys
BASE=pathlib.Path('/Users/daniel/.codex/tu1nz-recovery/api-rollback-20260926T084526Z')
PRE=BASE/'final-preflight-20260926T120858Z'
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def closed_tcp(address,port):
 try:
  with socket.create_connection((address,port),timeout=3):pass
 except (socket.timeout,TimeoutError,ConnectionRefusedError):return True
 return False
def main():
 os.umask(0o077);assert len(sys.argv)==3 and sys.argv[1] in ['phase5','accept','rollback']
 stage=sys.argv[1];out=pathlib.Path(sys.argv[2]);assert out.parent.exists() and not out.exists()
 result={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stage':stage,'complete':False}
 try:
  m=load('health','/Users/daniel/.codex/tu1nz-recovery/phase5-20260924T162425Z/phase5-check.py');r=m.collect();result['health']=r
  old=json.loads((PRE/'health.json').read_text())
  for key in ['containers','firewall','listeners','services']:assert r['server'][key]==old['server'][key],key+' changed'
  result['unchanged_server']=True;result['ipv6_ssh']=[]
  for user in ['chatops','root','nobody','daemon']:
   cmd=m.SSH+['-6','-o','HostKeyAlias=100.121.130.51',user+'@fd7a:115c:a1e0::7a32:8233','id -un' if user=='chatops' else '/usr/bin/false']
   x=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
   ok=(x.returncode==0 and x.stdout.strip()=='chatops') if user=='chatops' else (x.returncode==255 and 'does not permit you to SSH' in x.stderr)
   assert ok,'IPv6 SSH policy failed';result['ipv6_ssh'].append({'user':user,'exit':x.returncode,'verified':True})
  assert closed_tcp('fd7a:115c:a1e0::7a32:8233',2222),'IPv6 OpenSSH reachable'
  result['ipv6_2222_closed']=True
  pub=load('public',BASE/'phase5-preparation-20260926T094240Z/public-port-check.py')
  rows=[{'address':a,'port':n,'result':pub.probe(a,n)} for a in pub.ADDRESSES for n in pub.PORTS];result['public_ports']=rows;assert pub.passed(rows)
  if stage!='rollback':
   denied=[]
   for n in [5432,5678,8090,8081]:
    assert closed_tcp('100.121.130.51',n),'ungranted Tailnet port reachable'
    denied.append(n)
   result['denied_tailnet_ports']=denied
  if stage=='accept':
   result['independent_ssh_logins_no_check']=[]
   for _ in range(3):
    x=subprocess.run(m.SSH+['chatops@100.121.130.51','id -un'],capture_output=True,text=True,timeout=12)
    assert x.returncode==0 and x.stdout.strip()=='chatops' and 'login.tailscale.com' not in x.stderr and 'check' not in x.stderr.lower()
    result['independent_ssh_logins_no_check'].append(True)
  result['complete']=True
 except Exception as e:
  result['failure_kind']=type(e).__name__
 finally:
  with out.open('x') as f:json.dump(result,f,indent=2)
 print('SEQUENTIAL_CHECK_PASS' if result['complete'] else 'SEQUENTIAL_CHECK_FAILED',str(out))
 raise SystemExit(0 if result['complete'] else 1)
if __name__=='__main__':main()
