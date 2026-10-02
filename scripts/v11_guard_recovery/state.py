"""Append-only, root-owned Guard state; no service or network operations.
Immutable generations and a monotonic sealed latch. Unknown data always denies.
"""
import contextlib,fcntl,hashlib,json,os,re,stat,time,uuid
from pathlib import Path
ROOT='/var/lib/tu1nz-v11-guard-recovery'
PHASES=('LEGACY_ALLOWED_PRETRANSACTION','FENCE_INSTALLED_UNARMED','LEGACY_INHIBITED_PRESEAL','SECURITY_BARRIER_SEALED','NEW_CONSUMER_STAGED','NEW_CONSUMER_VERIFIED','COMPLETED')
TERMINAL={'COMPLETED','SECURED_STOP','ROLLED_BACK_PRESEAL'}
class Refused(RuntimeError):pass
class Crash(BaseException):pass

def encode(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()+b'\n'
def digest(x):return hashlib.sha256(x).hexdigest()
def strict(raw):
 def pairs(items):
  d={}
  for k,v in items:
   if k in d:raise Refused('DUPLICATE_JSON')
   d[k]=v
  return d
 try:return json.loads(raw,object_pairs_hook=pairs)
 except (ValueError,UnicodeError):raise Refused('BAD_JSON') from None

def secure_open(path,directory=False,uid=0,mode=None):
 p=Path(path);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  if not p.is_absolute() or '..' in p.parts:raise Refused('PATH')
  for i,part in enumerate(p.parts[1:]):
   last=i==len(p.parts)-2
   flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
   if not last or directory:flags|=os.O_DIRECTORY
   nxt=os.open(part,flags,dir_fd=fd);os.close(fd);fd=nxt;s=os.fstat(fd)
   if s.st_uid!=uid or s.st_mode&0o022 or any('posix_acl' in a for a in os.listxattr(fd)):raise Refused('UNTRUSTED_PATH')
   if not last and not stat.S_ISDIR(s.st_mode):raise Refused('PARENT_TYPE')
  if directory:
   if not stat.S_ISDIR(s.st_mode):raise Refused('DIRECTORY_TYPE')
  elif not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise Refused('FILE_TYPE')
  if mode is not None and stat.S_IMODE(s.st_mode)!=mode:raise Refused('MODE')
  return os.dup(fd)
 finally:os.close(fd)

class Store:
 def __init__(self,path=ROOT,fixture=False):
  self.path=Path(path);self.uid=os.geteuid() if fixture else 0;self.gid=os.getegid() if fixture else 0;self.depth=0
  if fixture:
   if os.geteuid()==0 or self.path.parent!=Path('/tmp') or not self.path.name.startswith('tu1nz-fence-test-'):raise Refused('FIXTURE')
   self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  else:
   if self.path!=Path(ROOT) or os.geteuid()!=0:raise Refused('ROOT_ONLY')
   self.fd=secure_open(self.path,True,0,0o700)
  self.check(self.fd,True,0o700)
 def check(self,fd,directory=False,mode=0o400):
  s=os.fstat(fd)
  if s.st_uid!=self.uid or s.st_gid!=self.gid or stat.S_IMODE(s.st_mode)!=mode or (not stat.S_ISDIR(s.st_mode) if directory else not stat.S_ISREG(s.st_mode) or s.st_nlink!=1) or any('posix_acl' in a for a in os.listxattr(fd)):raise Refused('METADATA')
 def close(self):os.close(self.fd)
 @contextlib.contextmanager
 def locked(self):
  if self.depth:
   yield;return
  f=os.open('lock',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.fd)
  try:
   self.check(f,mode=0o600);fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.depth=1;yield
  finally:self.depth=0;os.close(f)
 def read(self,name):
  if name not in ('SEALED','STOP','PRESEAL_INHIBIT') and not re.fullmatch(r'(?:state|intent|recovery)-[0-9]{6}\.json',name):raise Refused('NAME')
  f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
  try:
   self.check(f);before=os.fstat(f);raw=os.read(f,65537);after=os.fstat(f)
   fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
   if len(raw)>65536 or any(getattr(before,k)!=getattr(after,k) for k in fields) or after.st_ino!=os.stat(name,dir_fd=self.fd,follow_symlinks=False).st_ino:raise Refused('READ_RACE_OR_SIZE')
   return strict(raw)
  finally:os.close(f)
 def publish(self,name,value):
  if name.startswith('state-'):self.publish(name.replace('state-','intent-',1),{'name':name,'sha256':digest(encode(value))})
  if name not in ('SEALED','STOP','PRESEAL_INHIBIT') and not re.fullmatch(r'(?:state|intent|recovery)-[0-9]{6}\.json',name):raise Refused('NAME')
  tmp='.tmp-'+uuid.uuid4().hex;f=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=self.fd)
  try:
   os.fchmod(f,0o400)
   with os.fdopen(f,'wb',closefd=False) as out:out.write(encode(value));out.flush();os.fsync(f)
   os.link(tmp,name,src_dir_fd=self.fd,dst_dir_fd=self.fd,follow_symlinks=False);os.unlink(tmp,dir_fd=self.fd);os.fsync(self.fd)
  finally:
   os.close(f)
   try:os.unlink(tmp,dir_fd=self.fd)
   except FileNotFoundError:pass
 def exists(self,name):
  try:os.stat(name,dir_fd=self.fd,follow_symlinks=False);return True
  except FileNotFoundError:return False
 def current(self):
  with self.locked():return self._current()
 def _current(self):
  p=self.path.lstat();f=os.fstat(self.fd)
  if (p.st_dev,p.st_ino)!=(f.st_dev,f.st_ino):raise Refused('STATE_PARENT_REPLACED')
  self.check(self.fd,True,0o700)
  if self.exists('STOP'):self.read('STOP');raise Refused('SECURED_STOP')
  names=sorted(n for n in os.listdir(self.fd) if n.startswith('state-'))
  if not names or len(names)>128:raise Refused('MISSING_OR_OVERSIZE_STATE')
  intents=sorted(n for n in os.listdir(self.fd) if n.startswith('intent-'))
  if intents!=[n.replace('state-','intent-',1) for n in names]:raise Refused('INCOMPLETE_GENERATION')
  prev='0'*64;binding=None;last=None
  for i,n in enumerate(names):
   if n!='state-%06d.json'%i:raise Refused('GENERATION_GAP')
   x=self.read(n)
   if self.read(n.replace('state-','intent-',1))!={'name':n,'sha256':digest(encode(x))}:raise Refused('GENERATION_HASH')
   if set(x)!={'seq','previous','binding','phase','proof'} or x['seq']!=i or x['previous']!=prev:raise Refused('STATE_CHAIN')
   if binding is None:binding=x['binding'];validate_binding(binding)
   if x['binding']!=binding or x['phase'] not in PHASES+('ROLLED_BACK_PRESEAL',):raise Refused('STATE_BINDING')
   if last is None:
    if x['phase']!=PHASES[0]:raise Refused('INITIAL_PHASE')
   elif x['phase']!='ROLLED_BACK_PRESEAL' and (last['phase'] not in PHASES or PHASES.index(x['phase'])!=PHASES.index(last['phase'])+1):raise Refused('PHASE_CHAIN')
   elif x['phase']=='ROLLED_BACK_PRESEAL' and (last['phase'] not in PHASES[:3] or self.exists('SEALED')):raise Refused('ROLLBACK_SEALED')
   last=x;prev=digest(encode(x))
  sealed=self.exists('SEALED')
  if sealed and self.read('SEALED')!={'binding':binding,'sealed':True}:raise Refused('BARRIER_BINDING')
  if last['phase'] in PHASES[3:] and not sealed:raise Refused('MISSING_BARRIER')
  return dict(last,record_sha256=prev,sealed=sealed)
 def initialize(self,binding):
  validate_binding(binding)
  f=os.open('lock',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
  os.fchmod(f,0o600);os.fsync(f);os.close(f);os.fsync(self.fd)
  with self.locked():
   if any(n!='lock' for n in os.listdir(self.fd)):raise Refused('EXISTING_TRANSACTION')
   self.publish('state-000000.json',{'seq':0,'previous':'0'*64,'binding':binding,'phase':PHASES[0],'proof':{}})
 def advance(self,phase,proof,inject=lambda p:None):
  with self.locked():
   s=self.current()
   if phase==s['phase']:return s
   if s['phase'] not in PHASES[:-1] or PHASES[PHASES.index(s['phase'])+1]!=phase:raise Refused('TRANSITION')
   if phase=='SECURITY_BARRIER_SEALED':
    if proof!={'inhibit_verified':True,'blocked_start_verified':True,'recovery_verified':True,'watchdog_verified':True}:raise Refused('SEAL_PROOFS')
    if not self.exists('SEALED'):self.publish('SEALED',{'binding':s['binding'],'sealed':True})
    inject('AFTER_SEALED_LATCH')
   if phase=='NEW_CONSUMER_VERIFIED' and set(proof)!={'consumer_sha256','authority_sha256','loaded_unit_sha256','result_sha256'}:raise Refused('NEW_PROOFS')
   if phase=='NEW_CONSUMER_VERIFIED' and any(not re.fullmatch('[0-9a-f]{64}',v) for v in proof.values()):raise Refused('PROOF_HASH')
   value={'seq':s['seq']+1,'previous':s['record_sha256'],'binding':s['binding'],'phase':phase,'proof':proof}
   self.publish('state-%06d.json'%value['seq'],value);return self.current()
 def stop(self,reason):
  if not re.fullmatch('[A-Z_]{1,80}',reason):raise Refused('REASON')
  with self.locked():
   if not self.exists('STOP'):self.publish('STOP',{'status':'SECURED_STOP','reason':reason})
  return 'SECURED_STOP'
 def rollback(self,verified):
  with self.locked():
   s=self.current()
   if s['sealed'] or s['phase'] not in PHASES[:3] or verified!={'originals_identical':True,'no_foreign_writer':True,'timer_original_verified':True}:raise Refused('ROLLBACK_PROOF')
   self.publish('state-%06d.json'%(s['seq']+1),{'seq':s['seq']+1,'previous':s['record_sha256'],'binding':s['binding'],'phase':'ROLLED_BACK_PRESEAL','proof':verified})

def validate_binding(b):
 if set(b)!={'transaction','boot','deadline_ns','coordinator_pid','coordinator_start_ticks','contract_sha256'}:raise Refused('BINDING_FIELDS')
 if not re.fullmatch('v11-[0-9a-f]{32}',b['transaction']) or not re.fullmatch('[0-9a-f-]{36}',b['boot']) or not re.fullmatch('[0-9a-f]{64}',b['contract_sha256']):raise Refused('BINDING_FORMAT')
 if any(type(b[k]) is not int or b[k]<=0 for k in ('deadline_ns','coordinator_pid','coordinator_start_ticks')):raise Refused('BINDING_NUMBER')

def permit(state,consumer,verified):
 if not verified:return False
 phase=state['phase']
 if consumer=='legacy':return not state['sealed'] and phase in ('LEGACY_ALLOWED_PRETRANSACTION','ROLLED_BACK_PRESEAL')
 if consumer=='new':return state['sealed'] and phase in ('NEW_CONSUMER_VERIFIED','COMPLETED')
 return False

def decision(state,current_boot,now_ns,coordinator_alive):
 if state['phase'] in TERMINAL:return 'VERIFY_TERMINAL_ONLY'
 if current_boot!=state['binding']['boot'] or now_ns>=state['binding']['deadline_ns'] or not coordinator_alive:return 'FORWARD_OR_SECURED_STOP' if state['sealed'] else 'VERIFY_PRESEAL_ROLLBACK_OR_STOP'
 return 'WAIT'
