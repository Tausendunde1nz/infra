#!/usr/bin/python3
"""Read-only privileged snapshots for the approved policy transaction."""
import pathlib,subprocess,json,os,sys,datetime
BASE=pathlib.Path('/opt/tu1nz_repos/network-hardening-private-2026-09-22/api-phase5-20260926')
def main():
 assert os.geteuid()==0
 assert len(sys.argv)==2 and sys.argv[1] in ['before','after','stable','accept','final','rollback']
 os.umask(0o077);out=BASE/(sys.argv[1]+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));out.mkdir(mode=0o700)
 commands={'nft':['nft','-j','list','ruleset'],'iptables':['iptables-save'],'ip6tables':['ip6tables-save'],'ufw':['ufw','status','verbose'],'fail2ban':['fail2ban-client','status','sshd'],'actions':['fail2ban-client','get','sshd','actions'],'listeners':['ss','-H','-lntup']}
 for name,args in commands.items():
  r=subprocess.run(args,capture_output=True,text=True,timeout=15)
  f=out/(name+'.json');f.write_text(json.dumps({'args':args,'rc':r.returncode,'stdout':r.stdout,'stderr':r.stderr},indent=2)+'\n');os.chown(f,1001,1001)
  if r.returncode:raise RuntimeError('read-only check failed: '+name)
 actions=json.loads((out/'actions.json').read_text())['stdout']
 import re
 names=[s.strip() for s in actions.splitlines() if re.fullmatch(r'[A-Za-z0-9_-]+',s.strip())]
 if not names:raise RuntimeError('no loaded action identified')
 ports={}
 for name in names:
  r=subprocess.run(['fail2ban-client','get','sshd','action',name,'port'],capture_output=True,text=True,timeout=10)
  ports[name]={'rc':r.returncode,'port':r.stdout.strip()}
 f=out/'action-ports.json';f.write_text(json.dumps(ports,indent=2)+'\n');os.chown(f,1001,1001)
 assert ports and all(x['rc']==0 and x['port']=='2222' for x in ports.values()),'loaded action-port mismatch'
 f=out/'PASS.json';f.write_text(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'fail2ban_loaded_port':2222})+'\n');os.chown(f,1001,1001);os.chown(out,1001,1001)
 print('READONLY_SNAPSHOT_PASS',str(out))
if __name__=='__main__':main()
