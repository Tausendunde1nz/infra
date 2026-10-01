"""Isolated functional network recovery tests. Never mutates a preexisting ID.
Only UUID-labelled test networks, loopback ephemeral host port, no host mounts.
No application/webhook/Telegram/provider traffic; standard-library HTTP fixture.
"""
import copy
import os
from pathlib import Path
import hashlib
import http.client
import json
import socket
import subprocess
import time
import urllib.request
import uuid

IMAGE='sha256:f0c7c619b45ffb475d79c2339fbef21ced03c6e83d919d321ef89b40cd4889db'
SERVER='''from http.server import BaseHTTPRequestHandler,HTTPServer
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b"V11_ISOLATED_HEALTH")
 def log_message(self,*a):pass
HTTPServer(("0.0.0.0",8080),H).serve_forever()
'''
class Unix(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(15);self.sock.connect('/var/run/docker.sock')
class APIError(RuntimeError):
 def __init__(self,status,raw):
  self.detail=json.loads(raw).get('message','');self.status=status;self.address_collision=b'address already in use' in raw.lower();super().__init__('DOCKER_HTTP_'+str(status))

def api(method,path,body=None):
 c=Unix('localhost',timeout=15)
 try:
  c.request(method,'/v1.51'+path,None if body is None else json.dumps(body),{'Content-Type':'application/json'})
  r=c.getresponse();b=r.read(4000000)
  if r.status>=300:raise APIError(r.status,b)
  return json.loads(b) if b else None
 finally:c.close()

def exe(cid,code):
 r=subprocess.run(['docker','exec',cid,'python','-I','-B','-c',code],capture_output=True,timeout=12)
 if r.returncode:raise RuntimeError('TEST_EXEC_'+str(r.returncode)+'_'+hashlib.sha256(r.stderr).hexdigest()+'_'+r.stderr.decode(errors='replace')[-800:])
 return r.stdout.decode().strip()

def test_hostname_body(name,body):
 b=copy.deepcopy(body);b['Hostname']=name if len(name)<=63 else name[:40]+'-'+hashlib.sha256(name.encode()).hexdigest()[:16];return b

def main():
 prefix='tu1nz-v11-semantic-'+uuid.uuid4().hex
 nets=[];containers=[];cases=[];port='';name=prefix+'-service'
 def create(n,body):
  assert n.startswith(prefix)
  cid=api('POST','/containers/create?name='+n,test_hostname_body(n,body))['Id'];containers.append(cid);return cid
 def remove(cid):
  assert cid in containers
  api('DELETE','/containers/'+cid+'?force=1');containers.remove(cid)
 def start(cid):
  assert cid in containers;api('POST','/containers/'+cid+'/start')
 def record(case,**facts):
  row={'case':case,'pass':True,**facts};cases.append(row);print(json.dumps(row),flush=True)
 def body(ep,hostport=None):
  b={'Image':IMAGE,'Hostname':name,'User':'20001:20001','Entrypoint':['python'],
     'Cmd':['-I','-B','-c',SERVER if hostport is not None else 'import time;time.sleep(600)'],
     'Labels':{'tu1nz.isolated':prefix},
     'HostConfig':{'NetworkMode':nets[1][0],'Memory':134217728,'NanoCpus':500000000,
        'PidsLimit':64,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],
        'ReadonlyRootfs':True,'RestartPolicy':{'Name':'no'}},
     'NetworkingConfig':{'EndpointsConfig':ep}}
  if hostport is not None:
   b['ExposedPorts']={'8080/tcp':{}}
   b['HostConfig']['PortBindings']={'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':hostport}]}
  return b
 def endpoint():return {nets[0][0]:{'Aliases':['service-alias'],'IPAMConfig':{},'GwPriority':0},nets[1][0]:{'Aliases':[name,name],'IPAMConfig':None,'GwPriority':0}}
 def probe(cid):
  i=api('GET','/containers/'+cid+'/json');assert not i['Mounts']
  bindings=i['NetworkSettings']['Ports']['8080/tcp'];assert len(bindings)==1 and bindings[0]['HostIp']=='127.0.0.1'
  hp=bindings[0]['HostPort'];opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
  deadline=time.monotonic()+8
  while True:
   try:
    with opener.open('http://127.0.0.1:'+hp+'/health',timeout=1) as r:assert r.status==200 and r.read(128)==b'V11_ISOLATED_HEALTH'
    break
   except (OSError,AssertionError):
    if time.monotonic()>=deadline:raise
    time.sleep(.2)
  for dns in (name,'service-alias'):
   out=exe(consumer,'import urllib.request;op=urllib.request.build_opener(urllib.request.ProxyHandler({}));print(op.open("http://'+dns+':8080/health",timeout=2).read().decode())')
   assert out=='V11_ISOLATED_HEALTH'
  routes=exe(cid,'print(open("/proc/net/route").read())').splitlines()[1:]
  default=[x.split()[2] for x in routes if x.split()[1]=='00000000']
  assert len(default)==1
  gate=socket.inet_ntoa(bytes.fromhex(default[0])[::-1]);e=i['NetworkSettings']['Networks']
  defaultnet=[n for n,v in e.items() if v['Gateway']==gate];assert defaultnet==[nets[0][0]]
  assert set(e)=={n for n,_ in nets}
  assert set(e[nets[0][0]]['Aliases'])=={'service-alias'}
  assert set(e[nets[1][0]]['Aliases'])=={name}
  assert not any(v.get('IPAMConfig') for v in e.values())
  return i,{'default_network':defaultnet[0],'hostport':hp,'aliases':{n:sorted(set(v['Aliases'])) for n,v in e.items()}}
 def save(label,data):
  f=Path(__file__).with_name(prefix+'-'+label+'.json')
  fd=os.open(f,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  with os.fdopen(fd,'w') as h:json.dump(data,h,sort_keys=True);h.flush();os.fsync(h.fileno())
 before_prod=api('GET','/containers/json?all=1');save('baseline',before_prod)
 prod_digest=hashlib.sha256(json.dumps(before_prod,sort_keys=True).encode()).hexdigest()
 try:
  # New networks only. Docker-managed test NAT rules belong solely to these
  # networks and loopback binding; no existing firewall rule is edited.
  for suffix in ('a-shared','z-compose'):
   n=prefix+'-'+suffix
   r=api('POST','/networks/create',{'Name':n,'Driver':'bridge','Labels':{'tu1nz.isolated':prefix}});nets.append((n,r['Id']))
   ipam=api('GET','/networks/'+r['Id'])['IPAM']
   api('DELETE','/networks/'+r['Id']);nets.pop()
   r=api('POST','/networks/create',{'Name':n,'Driver':'bridge','IPAM':ipam,'Labels':{'tu1nz.isolated':prefix}});nets.append((n,r['Id']))
  original=create(name,body(endpoint(),''));start(original)
  consumer=create(prefix+'-consumer',body({nets[0][0]:{'Aliases':[]}}));start(consumer)
  old,expected=probe(original);port=expected['hostport'];record('baseline_dns_hostport_default_route')
  old_ips={n:e['IPAddress'] for n,e in old['NetworkSettings']['Networks'].items()}
  remove(original)
  contender=create(prefix+'-contender',body({n:{'Aliases':[],'IPAMConfig':{'IPv4Address':ip}} for n,ip in old_ips.items()}));start(contender)
  # A hard-coded IP now reaches the deliberate sleeper, not the service.
  stale=exe(consumer,'import socket\ns=socket.socket();s.settimeout(1)\nprint(s.connect_ex(("'+old_ips[nets[0][0]]+'",8080)))\ns.close()')
  assert stale!='0';record('hardcoded_ip_consumer_detected',connection_failed=True)
  replacement=create(name,body(endpoint(),port));start(replacement)
  new,actual=probe(replacement);assert actual==expected
  assert all(new['NetworkSettings']['Networks'][n]['IPAddress']!=ip for n,ip in old_ips.items())
  assert any(new['NetworkSettings']['Networks'][n]['MacAddress']!=old['NetworkSettings']['Networks'][n]['MacAddress'] for n,_ in nets)
  record('dynamic_recreate_with_competitor',different_ip=True,different_mac=True,hostport_forwarding_updated=True,dynamic_ipam=True)
  # Collision is explicit failure, never silently converted to dynamic IPAM.
  pinned={n:{'Aliases':[],'IPAMConfig':{'IPv4Address':ip}} for n,ip in old_ips.items()}
  collision=None
  try:
   collision=create(prefix+'-static-collision',body(pinned));start(collision)
  except APIError as e:
   assert e.status in (400,403,409,500) and e.address_collision,e.detail;record('static_ip_collision_rejected',http_status=e.status)
  else:raise AssertionError('STATIC_COLLISION_NOT_REJECTED')
  if collision:remove(collision)
  # Recovery under missing-secondary-network and recreate/health failure:
  # discard only owned candidate; regenerate same dynamic contract.
  remove(replacement)
  partial=create(name,body({nets[1][0]:endpoint()[nets[1][0]]},port));start(partial)
  assert len(api('GET','/containers/'+partial+'/json')['NetworkSettings']['Networks'])==1
  remove(partial)
  recovered=create(name,body(endpoint(),port));start(recovered)
  final,restored=probe(recovered);assert restored==expected
  record('rollback_missing_secondary_endpoint',functional_contract_restored=True)
  remove(recovered)
  # Failed health candidate: sleeper instead of HTTP service.
  badbody=body(endpoint(),port);badbody['Cmd']=['-I','-B','-c','import time;time.sleep(600)']
  failed=create(name,badbody);start(failed)
  code=exe(consumer,'import socket\ns=socket.socket();s.settimeout(1);print(s.connect_ex(("'+name+'",8080)));s.close()')
  assert code!='0';remove(failed)
  recovered=create(name,body(endpoint(),port));start(recovered);_,restored=probe(recovered);assert restored==expected
  record('rollback_failed_health',functional_contract_restored=True)
 finally:
  errors=[]
  for cid in list(reversed(containers)):
   try:remove(cid)
   except Exception as e:errors.append(type(e).__name__)
  for _,nid in reversed(nets):
   try:api('DELETE','/networks/'+nid)
   except Exception as e:errors.append(type(e).__name__)
  after=api('GET','/containers/json?all=1')
  # Dynamic Status strings (Up N hours, health cadence) are not mutations.
  fields=('Id','ImageID','Names','Ports','Mounts','NetworkSettings','State','Created')
  project=lambda rows:sorted([{k:r.get(k) for k in fields} for r in rows],key=lambda r:r['Id'])
  a=project(before_prod);b=project(after)
  for rows in (a,b):
   for row in rows:
    for k in ('Ports','Mounts','Names'):row[k]=sorted(row[k],key=lambda x:json.dumps(x,sort_keys=True))
  unchanged=a==b
  save('final',after)
  if not unchanged:
   print(json.dumps({'production_delta':[{"id":r['Id'],"fields":[k for k in fields if r.get(k)!=s.get(k)]} for r,s in zip(a,b) if r!=s]}),flush=True)
  leftover=[r for r in api('GET','/networks') if r['Name'].startswith(prefix)]
  assert not errors and not leftover and unchanged
  print(json.dumps({'cleanup':True,'production_containers_unchanged':unchanged,'test_prefix':prefix,'tests':cases}),flush=True)

if __name__=='__main__':main()
