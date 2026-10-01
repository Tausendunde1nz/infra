"""Narrow pre-mutation evidence for the ONE future V11 root transaction.

No CLI, sudo call, container exec, firewall write, API mutation or activation.
Private SQLite copies are created only within new root-owned V11 evidence staging;
production SQLite/WAL/SHM are read as bytes, never opened by SQLite itself.
No raw config, workflow, credential or NAT output is returned or logged.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import stat
import subprocess

FIXED_CONFIGS=(
 '/etc/nginx/sites-enabled/tu1nz.conf',
 '/usr/local/bin/aide_daily.sh','/usr/local/bin/backup_notify.sh',
 '/usr/local/bin/tu1nz-ape-notify-core','/usr/local/bin/doku_agent_health.sh',
 '/var/spool/cron/crontabs/root')
DB=Path('/opt/n8n/data/database.sqlite')
TERMS={'shared_ip':'172.25.0.2','compose_ip':'172.20.0.2',
 'shared_mac':'82:fb:9a:73:0e:36','compose_mac':'b2:8d:93:fa:f8:7f',
 'service':'telegram_bot_mommyramona','hostport':'8081'}
class EvidenceError(RuntimeError):pass

def refs(text):
 # Whole numeric/address tokens; 172.25.0.20 is not 172.25.0.2.
 return sorted(k for k,v in TERMS.items() if re.search(
  (r'(?<![\w.:])'+re.escape(v)+r'(?![\w.:])') if k.endswith('_mac') else
  (r'(?<![\w.])'+re.escape(v)+r'(?![\w.])'),text))

def bounded_read(path,limit=64*1024*1024,owner=None):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  a=os.fstat(f.fileno())
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>limit:raise EvidenceError('INPUT_TYPE_OR_SIZE')
  if owner is not None and a.st_uid!=owner:raise EvidenceError('INPUT_OWNER')
  raw=f.read(limit+1);b=os.fstat(f.fileno())
 if len(raw)>limit or (a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns):raise EvidenceError('INPUT_CHANGED')
 return raw,{'dev':a.st_dev,'inode':a.st_ino,'size':a.st_size,'mtime_ns':a.st_mtime_ns,'ctime_ns':a.st_ctime_ns,
              'uid':a.st_uid,'gid':a.st_gid,'mode':stat.S_IMODE(a.st_mode),'sha256':hashlib.sha256(raw).hexdigest()}

def nat_evidence(raw):
 out=[]
 for line in raw.decode('utf-8','strict').splitlines():
  if not line.startswith('-A '):continue
  t=shlex.split(line)
  def arg(flag):
   if t.count(flag)>1:raise EvidenceError('AMBIGUOUS_NAT_FLAG')
   return t[t.index(flag)+1] if flag in t and t.index(flag)+1<len(t) else None
  dest=arg('--to-destination');port=arg('--dport')
  if port=='8081' or (dest and any(dest.startswith(TERMS[k]+':') or dest==TERMS[k] for k in ('shared_ip','compose_ip'))):
   out.append({'chain':t[1],'protocol':arg('-p'),'port':port,'target':arg('-j'),
       'destination_matches_current':dest=='172.25.0.2:8080',
       'rule_sha256':hashlib.sha256(line.encode()).hexdigest()})
 exact=[r for r in out if r['chain']=='DOCKER' and r['protocol']=='tcp' and r['port']=='8081' and r['target']=='DNAT' and r['destination_matches_current']]
 return {'rules':out,'docker_chain_mapping_verified':len(exact)==1 and len(out)==1,
         'raw_sha256':hashlib.sha256(raw).hexdigest()}

def inspect_db_copy(path):
 # The caller supplies a private copy, never the live database.
 c=sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True)
 try:
  c.execute('PRAGMA query_only=ON');c.execute('PRAGMA trusted_schema=OFF');c.enable_load_extension(False)
  schema=c.execute("SELECT type FROM sqlite_master WHERE name='workflow_entity'").fetchall()
  if schema!=[('table',)]:raise EvidenceError('WORKFLOW_SCHEMA')
  count=0;matches=[]
  for nodes,connections,active in c.execute('SELECT nodes,connections,active FROM workflow_entity'):
   count+=1
   if count>10000:raise EvidenceError('WORKFLOW_COUNT')
   # Require valid workflow JSON; never silently treat parser failure as no match.
   parsed=[json.loads(nodes),json.loads(connections)]
   found=refs(json.dumps(parsed,ensure_ascii=False))
   if found:matches.append({'ordinal':count,'active':bool(active),'references':found})
  return {'workflows_scanned':count,'matches':matches}
 finally:c.close()

def private_db_evidence(scratch):
 files=(DB,Path(str(DB)+'-wal'),Path(str(DB)+'-shm'));before={};created=[]
 try:
  for p in files:
   try:raw,meta=bounded_read(p,owner=1000)
   except FileNotFoundError:
    if p==DB:raise EvidenceError('WORKFLOW_DATABASE_MISSING')
    before[p.name]=None;continue
   before[p.name]=meta
   # SHM is unnecessary: SQLite reconstructs it solely within the private copy.
   if p.name.endswith('-shm'):continue
   target=scratch/p.name;fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);created.append(target)
   with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  for p in files:
   try:_,meta=bounded_read(p,owner=1000)
   except FileNotFoundError:meta=None
   if meta!=before[p.name]:raise EvidenceError('WORKFLOW_SNAPSHOT_CHANGED')
  return {'input_metadata':before,'analysis':inspect_db_copy(scratch/DB.name)}
 finally:
  # Delete only exclusive files belonging to this invocation and SQLite-created
  # private sidecars. Never traverse or delete a live path.
  for p in (scratch/DB.name, scratch/(DB.name+'-wal'),scratch/(DB.name+'-shm')):
   if p in created or (p.name.endswith('-shm') and p.exists()):
    s=p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid():raise EvidenceError('PRIVATE_COPY_DRIFT')
    p.unlink()

def collect(scratch):
 if os.geteuid()!=0:raise EvidenceError('ROOT_TRANSACTION_REQUIRED')
 scratch=Path(scratch)
 if not re.fullmatch(r'/var/lib/tu1nz-privileged-v11/[0-9a-f]{32}/network-evidence',str(scratch)):raise EvidenceError('PRIVATE_PATH')
 for p in list(reversed(scratch.parents))+[scratch]:
  s=p.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise EvidenceError('PRIVATE_ANCESTRY')
  if any('posix_acl' in x for x in os.listxattr(p)):raise EvidenceError('PRIVATE_ACL')
 if stat.S_IMODE(scratch.stat().st_mode)!=0o700 or list(scratch.iterdir()):raise EvidenceError('PRIVATE_DIRECTORY_NOT_EMPTY')
 config=[]
 for name in FIXED_CONFIGS:
  try:raw,meta=bounded_read(Path(name),limit=2*1024*1024,owner=0)
  except FileNotFoundError:
   if name!='/var/spool/cron/crontabs/root':raise EvidenceError('CONFIG_DISAPPEARED')
   config.append({'path':name,'absent':True});continue
  config.append({'path':name,'metadata':meta,'references':refs(raw.decode('utf-8','strict'))})
 r=subprocess.run(['/usr/sbin/iptables-save','-t','nat'],stdin=subprocess.DEVNULL,
     stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},cwd='/')
 if r.returncode or r.stderr or len(r.stdout)>2*1024*1024:raise EvidenceError('NAT_READ_FAILED')
 nat=nat_evidence(r.stdout);workflows=private_db_evidence(scratch)
 direct={'shared_ip','compose_ip','shared_mac','compose_mac'}
 direct_refs=any(direct.intersection(x.get('references',[])) for x in config)
 direct_refs=direct_refs or any(direct.intersection(x['references']) for x in workflows['analysis']['matches'])
 return {'configs':config,'nat':nat,'workflows':workflows,
   'classification':'CASE_A_ROOT_COMPONENT_CLEAR' if nat['docker_chain_mapping_verified'] and not direct_refs else 'REVIEW_REQUIRED',
   'not_a_standalone_activation_authorization':True}
