"""Independent persistent V11 dispatcher journal. No checkout imports at runtime.
The retained capsule is outside the inner Guard cleanup set. No generic commands.
"""
import os,stat,json,hashlib,re,fcntl,contextlib,uuid
from pathlib import Path
ROOT='/var/lib/tu1nz-v11-dispatcher'
PACKAGE='/usr/local/libexec/tu1nz-v11-dispatcher'
STEPS=('CLOSE','QUIESCE','VALIDATE','RESTORE','RELOAD','VERIFY','CLEANUP','VERIFY_CLEANUP','TIMER_INHIBITED','VERIFY_FINAL','ROLLED_BACK')
class Refused(RuntimeError):pass

def raw(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()+b'\n'
def sha(x):return hashlib.sha256(x).hexdigest()
def parse(data):
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise Refused('DUPLICATE_KEY')
   d[k]=v
  return d
 try:return json.loads(data,object_pairs_hook=unique)
 except (ValueError,UnicodeError):raise Refused('INVALID_JSON') from None

def boot_valid(x):return type(x)==str and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',x)
def binding_valid(x):
 return type(x)==dict and set(x)=={'transaction','origin_boot','contract_sha256'} and re.fullmatch('v11-[a-f0-9]{32}',x['transaction']) and boot_valid(x['origin_boot']) and re.fullmatch('[a-f0-9]{64}',x['contract_sha256'])

class Durable:
 def __init__(self,path=ROOT,fixture=False,inject=lambda p:None):
  self.path=Path(path);self.uid=os.geteuid();self.inject=inject
  if fixture:
   if self.uid==0 or self.path.parent!=Path('/tmp') or not self.path.name.startswith('tu1nz-dispatcher-test-'):raise Refused('FIXTURE_SCOPE')
  elif self.uid!=0 or self.path!=Path(ROOT):raise Refused('ROOT_SCOPE')
  if not fixture:
   for p in reversed((self.path,*self.path.parents)):
    s=p.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or os.listxattr(p,follow_symlinks=False):raise Refused('ANCESTOR')
  self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);self.check(self.fd,0o700,True)
 def close(self):os.close(self.fd)
 def check(self,fd,mode,directory=False):
  s=os.fstat(fd)
  if s.st_uid!=self.uid or s.st_gid!=os.getegid() or stat.S_IMODE(s.st_mode)!=mode or os.listxattr(fd) or (not stat.S_ISDIR(s.st_mode) if directory else not stat.S_ISREG(s.st_mode) or s.st_nlink!=1):raise Refused('METADATA')
 def identity(self):
  a=self.path.lstat();b=os.fstat(self.fd)
  if (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino):raise Refused('STATE_REPLACED')
  self.check(self.fd,0o700,True)
 def name(self,n):
  self.identity()
  if n not in ('lock','gate.json','binding.json','stop.json','release.json') and not re.fullmatch('step-[0-9]{6}.json',n):raise Refused('NAME')
 def read(self,n,mode=0o400):
  self.name(n);f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
  try:
   self.check(f,mode);a=os.fstat(f);data=os.read(f,65537);b=os.fstat(f);z=os.stat(n,dir_fd=self.fd,follow_symlinks=False)
   if len(data)>65536 or (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) or (b.st_dev,b.st_ino)!=(z.st_dev,z.st_ino):raise Refused('READ_RACE')
   return parse(data)
  finally:os.close(f)
 def put(self,n,value,replace=False):
  self.name(n)
  if replace and n!='gate.json':raise Refused('IMMUTABLE')
  mode=0o600 if replace else 0o400;tmp='.publish-'+uuid.uuid4().hex
  f=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=self.fd)
  try:
   os.fchmod(f,mode)
   with os.fdopen(f,'wb',closefd=False) as out:out.write(raw(value));out.flush();self.inject('before_fsync:'+n);os.fsync(f);self.inject('after_fsync:'+n)
   self.inject('before_publish:'+n)
   if replace:
    try:
     old=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
     try:self.check(old,0o600)
     finally:os.close(old)
    except FileNotFoundError:pass
    os.replace(tmp,n,src_dir_fd=self.fd,dst_dir_fd=self.fd)
   else:
    os.link(tmp,n,src_dir_fd=self.fd,dst_dir_fd=self.fd,follow_symlinks=False);os.unlink(tmp,dir_fd=self.fd)
   self.inject('after_publish:'+n);os.fsync(self.fd);self.inject('after_dir_fsync:'+n)
  finally:
   os.close(f)
   try:os.unlink(tmp,dir_fd=self.fd)
   except FileNotFoundError:pass
 @contextlib.contextmanager
 def locked(self):
  f=os.open('lock',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.fd)
  try:self.check(f,0o600);fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
  finally:os.close(f)
 def initialize(self,binding):
  if not binding_valid(binding) or os.listdir(self.fd):raise Refused('INITIAL_STATE')
  f=os.open('lock',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd);os.fchmod(f,0o600);os.fsync(f);os.close(f);os.fsync(self.fd)
  self.put('gate.json',{'state':'CLOSED'},True);self.put('binding.json',binding)
 def journal(self):
  b=self.read('binding.json')
  if not binding_valid(b):raise Refused('BINDING')
  names=sorted(n for n in os.listdir(self.fd) if n.startswith('step-'));prev='0'*64;rows=[]
  if len(names)>2*len(STEPS):raise Refused('SIZE')
  for i,n in enumerate(names):
   if n!='step-%06d.json'%i:raise Refused('GAP')
   r=self.read(n)
   if set(r)!={'binding','boot','seq','previous','step','state','proof'} or r['binding']!=b or not boot_valid(r['boot']) or r['seq']!=i or r['previous']!=prev or r['step']!=STEPS[i//2] or r['state']!=('INTENT' if i%2==0 else 'DONE'):raise Refused('CHAIN')
   if (i%2==0 and r['proof']!='') or (i%2 and not re.fullmatch('[a-f0-9]{64}',r['proof'])):raise Refused('PROOF')
   rows.append(r);prev=sha(raw(r))
  return b,rows,prev
 def append(self,boot,proof=''):
  b,rows,prev=self.journal();i=len(rows)
  if i>=2*len(STEPS):raise Refused('TERMINAL')
  self.put('step-%06d.json'%i,{'binding':b,'boot':boot,'seq':i,'previous':prev,'step':STEPS[i//2],'state':'INTENT' if i%2==0 else 'DONE','proof':proof})

class Dispatcher:
 def __init__(self,store,host,inject=lambda p:None):self.s=store;self.host=host;self.inject=inject
 def close_gate(self):
  self.s.put('gate.json',{'state':'CLOSED'},True)
  self.host.verify_closed(self.s)
 def run(self,boot):
  with self.s.locked():
   self.close_gate()  # before all journal/state interpretation
   try:
    if not boot_valid(boot):raise Refused('BOOT')
    if 'stop.json' in os.listdir(self.s.fd):raise Refused('STOP_LATCH')
    binding,rows,_=self.s.journal();self.host.validate_binding(binding)
    for step in STEPS[len(rows)//2:]:
     _,rows,_=self.s.journal()
     if len(rows)%2==0:self.inject('before_intent:'+step);self.s.append(boot);self.inject('after_intent:'+step)
     self.inject('before_action:'+step);proof=self.host.step(step,binding);self.inject('after_action:'+step)
     if not re.fullmatch('[a-f0-9]{64}',proof):raise Refused('HOST_PROOF')
     self.s.append(boot,proof);self.inject('after_completion:'+step)
    binding,rows,tip=self.s.journal()
    if len(rows)!=2*len(STEPS):raise Refused('NOT_TERMINAL')
    # Reverification on every restart; a terminal marker alone grants nothing.
    proof=self.host.verify_terminal(binding)
    if not re.fullmatch('[a-f0-9]{64}',proof):raise Refused('TERMINAL_PROOF')
    release={'binding':binding,'journal_sha256':tip,'proof':proof,'state':'ROLLED_BACK'}
    if 'release.json' not in os.listdir(self.s.fd):self.s.put('release.json',release)
    if self.s.read('release.json')!=release:raise Refused('RELEASE_DRIFT')
    self.inject('before_release');self.s.put('gate.json',release,True);self.inject('after_release')
    return 'ROLLED_BACK'
   except Exception:
    self.close_gate()
    if 'stop.json' not in os.listdir(self.s.fd):self.s.put('stop.json',{'state':'PRESEAL_SECURED_STOP'})
    self.host.quiesce();return 'PRESEAL_SECURED_STOP'

def permit(store,host):
 try:
  if 'stop.json' in os.listdir(store.fd):return False
  release=store.read('release.json');gate=store.read('gate.json',0o600)
  b,rows,tip=store.journal()
  return len(rows)==2*len(STEPS) and gate==release and release=={'binding':b,'journal_sha256':tip,'proof':host.verify_terminal(b),'state':'ROLLED_BACK'}
 except Exception:return False
