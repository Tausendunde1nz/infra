"""Isolated filesystem transaction rehearsal ONLY; deliberately refuses root/live paths.
Authority cutover is a forward-only barrier. Host adapters remain separately gated.
"""
import fcntl,json,os,re,stat,time,uuid
from pathlib import Path
from authority import Refused,sha,read_bound
PHASES=('dedicated_checkout','versioned_authority','consumer_cutover','mommyramona','agentmode','token_rotation','final_verify')
BARRIER='consumer_cutover'
class Crash(BaseException):pass

def atomic(root,name,data):
 tmp=root/('.tmp-'+uuid.uuid4().hex)
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())
 os.replace(tmp,root/name);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)

class Rehearsal:
 def __init__(self,root,clock=time.monotonic_ns):
  self.clock=clock;self.root=Path(root)
  if os.geteuid()==0 or not self.root.name.startswith('tu1nz-authority-fixture-') or self.root.parent!=Path('/tmp') or self.root.is_symlink():raise Refused('ISOLATED_NONROOT_ONLY')
  s=self.root.stat()
  if s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700 or any('posix_acl' in k for k in os.listxattr(self.root)):raise Refused('FIXTURE_OWNER')
  self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:os.close(self.fd);raise Refused('CONCURRENT_WRITER')
 def close(self):os.close(self.fd)
 def write(self,state):atomic(self.root,'state.json',json.dumps(state,sort_keys=True).encode())
 def read(self):return json.loads((self.root/'state.json').read_text())
 def begin(self,expected,payload,pins,txid,boot,now,deadline,proofs):
  if (self.root/'state.json').exists():raise Refused('EXISTING_TRANSACTION')
  if not re.fullmatch('v11-[0-9a-f]{32}',txid) or deadline-now<300_000_000_000:raise Refused('WINDOW_OR_ID')
  if set(expected)!=set(PHASES) or set(payload)!=set(PHASES) or set(pins)!=set(PHASES):raise Refused('MODULE_SET')
  if proofs!={'sources_reviewed':True,'rollback_tested':True,'consumer_inventory_complete':True}:raise Refused('PREFLIGHT_PROOFS')
  originals={}
  # ALL filesystem/input checks before the first output/state mutation.
  for n in PHASES:
   if type(payload[n]) is not bytes or len(payload[n])>2_000_000 or sha(payload[n])!=pins[n]:raise Refused('PAYLOAD_PIN')
   b=read_bound(self.root/n,expected[n],os.geteuid(),os.getegid(),0o600,self.root)
   originals[n]={'bytes':b.hex(),'sha256':sha(b),'uid':os.geteuid(),'gid':os.getegid(),'mode':0o600,'acl':{}}
  s={'status':'BACKUP_VERIFIED','id':txid,'boot':boot,'deadline':deadline,'sealed':False,'intent':None,'completed':[],'backup':originals,'pins':pins,'payload':{n:b.hex() for n,b in payload.items()},'watchdog_design':'INDEPENDENT_ROOT_OWNED','live':False}
  self.write(s)
  assert self.read()==s
 def step(self,n,fail=None):
  s=self.read()
  if self.clock()>=s['deadline']:self.recover();raise Refused('DEADLINE')
  if s['status'] not in ('BACKUP_VERIFIED','PHASE_VERIFIED') or n!=PHASES[len(s['completed'])]:raise Refused('PHASE_ORDER')
  before=s['backup'][n]
  read_bound(self.root/n,before['sha256'],os.geteuid(),os.getegid(),0o600,self.root)
  if n==BARRIER:s['sealed']=True
  s.update(intent=n,status='PHASE_INTENT');self.write(s)
  if fail=='crash_before':raise Crash()
  atomic(self.root,n,bytes.fromhex(s['payload'][n]))
  if fail=='crash_after':raise Crash()
  if fail in ('signal','timeout','verify'):
   self.recover();raise Refused('INJECTED_'+fail)
  read_bound(self.root/n,s['pins'][n],os.geteuid(),os.getegid(),0o600,self.root)
  s['completed'].append(n);s.update(intent=None,status='PHASE_VERIFIED');self.write(s)
 def recover(self):
  s=self.read()
  if s['status'] in ('ROLLED_BACK','SECURED_STOP','COMPLETED'):return s['status']
  if s['sealed']:
   # No restore of an old authority after the barrier, even after ambiguous crash.
   s.update(status='SECURED_STOP',recovery='REQUIRE_VERIFIED_FORWARD_REPAIR');self.write(s)
  else:
   for n in s['completed']+([s['intent']] if s['intent'] else []):
    # Refuse to overwrite external mutation, symlink or unexpected inode type.
    p=self.root/n;t=p.lstat()
    if not stat.S_ISREG(t.st_mode) or t.st_nlink!=1 or t.st_uid!=os.geteuid() or stat.S_IMODE(t.st_mode)!=0o600:raise Refused('RECOVERY_IDENTITY')
    current=sha(p.read_bytes())
    if current not in (s['pins'][n],s['backup'][n]['sha256']):raise Refused('FOREIGN_WRITER')
    atomic(self.root,n,bytes.fromhex(s['backup'][n]['bytes']))
    read_bound(p,s['backup'][n]['sha256'],os.geteuid(),os.getegid(),0o600,self.root)
   s.update(status='ROLLED_BACK');self.write(s)
  return s['status']
 def watchdog(self,boot,now):
  s=self.read()
  if s['status'] in ('ROLLED_BACK','SECURED_STOP','COMPLETED'):return s['status']
  return self.recover() if boot!=s['boot'] or now>=s['deadline'] else 'WAIT'
 def finish(self):
  s=self.read()
  if self.clock()>=s['deadline']:self.recover();raise Refused('DEADLINE')
  if s['completed']!=list(PHASES) or s['intent']:raise Refused('INCOMPLETE')
  for n in PHASES:read_bound(self.root/n,s['pins'][n],os.geteuid(),os.getegid(),0o600,self.root)
  s['status']='COMPLETED';self.write(s)
