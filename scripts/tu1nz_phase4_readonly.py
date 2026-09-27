#!/usr/bin/python3
"""Phase4 privileged read-only preflight; writes protected evidence only."""
import pathlib,subprocess,os,json,hashlib,datetime,re
assert os.geteuid()==0
base=pathlib.Path('/opt/tu1nz_repos/network-hardening-private-2026-09-22')
out=base/('phase4-privileged-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
out.mkdir(mode=0o700);os.chmod(out,0o700);os.chown(out,1001,1001)
def put(name,data):
 p=out/name
 with p.open('xb') as f:f.write(data)
 os.chmod(p,0o600);os.chown(p,1001,1001)
def run(*a):return subprocess.check_output(a,stderr=subprocess.PIPE,timeout=30)
for name,args in [('nft.json',['nft','-j','list','ruleset']),('iptables.txt',['iptables-save']),('ip6tables.txt',['ip6tables-save']),('ufw.txt',['ufw','status','verbose']),('listeners.txt',['ss','-lntup']),('sshd.txt',['sshd','-T']),('fail2ban-status.txt',['fail2ban-client','status','sshd']),('fail2ban-port.txt',['fail2ban-client','get','sshd','action','nftables','port'])]:put(name,run(*args))
# Parse configuration output in memory; persist routing directives only.
nginx=run('nginx','-T').decode()
lines=[]
for line in nginx.splitlines():
 if re.match(r'\s*(listen|server_name|proxy_pass|upstream|server\s+127\.|return\s+30[18])\b',line):
  if re.search(r'://[^/\s]+@',line):raise ValueError('Credential-bearing upstream: output blocked')
  lines.append(line.strip())
put('nginx-routing.txt',('\n'.join(lines)+'\n').encode())
put('manifest.json',json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir()},indent=2).encode())
put('COMPLETE.json',json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'read_only_live_state':True}).encode())
print('PHASE4_READONLY_COMPLETE',out,flush=True)
