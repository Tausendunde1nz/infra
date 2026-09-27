"""Read-side adapter for later activation. Import never probes production."""
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import urllib.request
import urllib.parse
import ipaddress
from audit_v9 import audit,proc_identity,socket_identity,TopologyChanged
from datetime import datetime,timezone
from command_v9 import checked
from contracts_v9 import HEALTH_UNITS,MYCB_ID,CADVISOR_ID,verify_container_continuity,verify_unit_continuity
from lifecycle_v9 import PREFIX,NAME,validate_container
from policy_v9 import Refused


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def mount_digest(mounts):
 if not isinstance(mounts,list) or len({x['Destination'] for x in mounts})!=len(mounts):raise Refused('ambiguous mounts')
 # Docker exposes this semantically unordered set in varying map iteration order.
 # Preserve every complete record; only canonicalize ordering, never fields.
 return digest(sorted(mounts,key=lambda x:x['Destination']))


def containers():
 ids=checked(PREFIX+['ps','-aq']).decode().split()
 if not ids or any(len(x)!=64 or any(c not in '0123456789abcdef' for c in x) for x in ids):
  # Docker ps defaults to abbreviated IDs; request immutable full IDs explicitly.
  ids=checked(PREFIX+['ps','-aq','--no-trunc']).decode().split()
 if not ids or any(len(x)!=64 or any(c not in '0123456789abcdef' for c in x) for x in ids):raise Refused('container ID set')
 raw=json.loads(checked(PREFIX+['inspect',*ids]))
 result={}
 for c in raw:
  name=c['Name'].lstrip('/');s=c['State']
  if name in result:raise Refused('duplicate container')
  result[name]={'id':c['Id'],'image':c['Image'],'pid':s['Pid'],'started':s['StartedAt'],
   'restarts':c['RestartCount'],'running':s['Running'],'health':s.get('Health',{}).get('Status','none'),
   'config_sha256':digest(c['Config']),'host_sha256':digest(c['HostConfig']),
   'mounts_sha256':mount_digest(c['Mounts']),'networks_sha256':digest(c['NetworkSettings']['Networks'])}
 if len(result)!=len(ids):raise Refused('container coverage')
 return result


def units():
 result={};keys=('MainPID','ExecMainStartTimestampMonotonic','ActiveState','SubState','NRestarts','Result','FragmentPath','DropInPaths','NeedDaemonReload')
 for unit in HEALTH_UNITS:
  data=checked(['/usr/bin/systemctl','show',unit,*sum((['-p',k] for k in keys),[])]).decode()
  result[unit]=dict(line.split('=',1) for line in data.splitlines())
  if set(result[unit])!=set(keys):raise Refused('unit coverage')
 return result


def long_lived_chatops_contexts():
 rows=[]
 for leader in Path('/proc').iterdir():
  if not leader.name.isdigit():continue
  try:tasks=list((leader/'task').iterdir())
  except FileNotFoundError:continue
  for proc in tasks:
   if not proc.name.isdigit():continue
   try:ident=proc_identity(proc)
   except (FileNotFoundError,ProcessLookupError):continue
   if 1001 in ident['uid']:rows.append(ident)

 return rows


def assess_clients(snapshot,baseline):
 """Accept only root daemon/monitor or the fixed independent MyCB CLI context.

 uid=0 alone is NOT a sufficient root-control proof. Bind executable/cgroup and
 container identity, and reject unknown clients. No client is killed here.
 """
 accepted=[];wait=[]
 for handle in snapshot.get('path_handles',[]):
  if 1001 in handle['identity']['uid']:raise Refused('chatops Docker socket path FD remains')
 for inode,owners in snapshot['peers'].items():
  for item in owners:
   ident=item['identity'];pid=ident['pid'];tgid=ident.get('tgid',pid);p=Path('/proc')/str(pid)
   exe=os.readlink(p/'exe');uid=ident['uid'];cg=ident['cgroup']
   if 1001 in uid:
    if exe=='/usr/bin/docker':wait.append(pid);continue
    raise Refused('chatops-controlled persistent Docker peer')
   if len(set(uid))!=1:raise Refused('mixed-UID Docker client')
   if uid[0]==0 and tgid==int(baseline['units']['docker.service']['MainPID']) and exe=='/usr/bin/dockerd' and cg.endswith('/docker.service'):
    kind='ROOT_DAEMON'
   elif uid[0]==0 and tgid==1 and int(inode) in snapshot['listener_inodes'] and exe=='/usr/lib/systemd/systemd' and cg.endswith('/init.scope'):
    kind='ROOT_SOCKET_ACTIVATOR'
   elif uid[0]==0 and tgid==baseline['containers']['tu1nz_cadvisor']['pid'] and CADVISOR_ID in cg and baseline['containers']['tu1nz_cadvisor']['id']==CADVISOR_ID and exe in ('/usr/bin/cadvisor','/cadvisor'):
    kind='PINNED_CADVISOR'
   elif uid[0]==10001 and cg.endswith('/mychatbuddy-private-alpha.service') and tgid==int(baseline['units']['mychatbuddy-private-alpha.service']['MainPID']) and exe=='/usr/bin/docker' and baseline['containers'][NAME]['id']==MYCB_ID:
    kind='INDEPENDENT_MYCB_CLI'
   else:raise Refused('unclassified Docker client')
   if proc_identity(p)!=ident:raise Refused('Docker client identity race')
   accepted.append({'inode':int(inode),'identity':ident,'kind':kind})
 return {'accepted':accepted,'wait_pids':sorted(set(wait))}


def clear_clients(baseline,seconds=20):
 deadline=time.monotonic_ns()+int(seconds*1e9)
 while True:
  try:snap=audit()
  except TopologyChanged:
   if time.monotonic_ns()>=deadline:raise Refused('Docker peer topology did not stabilize')
   time.sleep(.25);continue
  classified=assess_clients(snap,baseline)
  if not classified['wait_pids']:return {'audit':snap,'classification':classified}
  if time.monotonic_ns()>=deadline:raise Refused('short-lived Docker client did not drain')
  time.sleep(.25)


def protected_services_unchanged(baseline):
 current={'containers':containers(),'units':units()}
 verify_container_continuity(baseline['containers'],current['containers'])
 verify_unit_continuity(baseline['units'],current['units'])
 return current


def monitoring():
 # Obtain only the existing monitoring IP; never expose an endpoint or enter a
 # container. The destination must be the fixed private container's bridge IP.
 c=json.loads(checked(PREFIX+['inspect','tu1nz_prometheus']))[0]
 addresses={x['IPAddress'] for x in c['NetworkSettings']['Networks'].values() if x.get('IPAddress')}
 if len(addresses)!=1:raise Refused('ambiguous Prometheus address')
 address=addresses.pop();ip=ipaddress.ip_address(address)
 if ip.version!=4 or not ip.is_private or ip.is_loopback:raise Refused('nonprivate Prometheus target')
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 with opener.open('http://'+address+':9090/api/v1/targets',timeout=5) as response:
  raw=response.read(2_000_001)
 if len(raw)>2_000_000:raise Refused('monitoring response bound')
 data=json.loads(raw)
 if data.get('status')!='success':raise Refused('Prometheus query failed')
 targets=data['data']['activeTargets'];required={}
 for t in targets:
  # Jobs are matched by fixed scrape port/service naming, not arbitrary user URL.
  u=urllib.parse.urlsplit(t['scrapeUrl'])
  if u.hostname in ('cadvisor','tu1nz_cadvisor') or u.port==8080:
   if 'cadvisor' in required:raise Refused('duplicate cadvisor target')
   required['cadvisor']=t
  if u.hostname in ('node-exporter','node_exporter','tu1nz_node_exporter') or u.port==9100:
   if 'node-exporter' in required:raise Refused('duplicate node target')
   required['node-exporter']=t
 if set(required)!={'cadvisor','node-exporter'}:raise Refused('monitoring target coverage')
 for name,t in required.items():
  age=(datetime.now(timezone.utc)-datetime.fromisoformat(t['lastScrape'].replace('Z','+00:00'))).total_seconds()
  if not -5<=age<=120:raise Refused('stale monitoring scrape')
  if t['health']!='up' or t.get('lastError'):raise Refused('monitoring target failed: '+name)
 return {name:{'health':'up','lastScrape':t['lastScrape']} for name,t in required.items()}

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise Refused('monitoring redirect forbidden')
