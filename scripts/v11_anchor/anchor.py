"""V11 recovery base v1. No import-time effects, shell, network or secret input.
Persistent phase-0 paths are never members of the phase-1 rollback set.
"""
import os,stat,json,re,hashlib,fcntl,contextlib,uuid,subprocess,signal,time
from pathlib import Path
ROOT='/var/lib/tu1nz-v11-anchor'
VALIDATION_ROOT='/run/tu1nz-v11-anchor-validation'
VERSION=1
TERMINAL='ROLLED_BACK_WITH_RECOVERY_BASE'
LIMIT=8_000_000
class Refused(RuntimeError):pass
def encode(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()+b'\n'
def digest(b):return hashlib.sha256(b).hexdigest()
def parse(b):
 def pairs(rows):
  d={}
  for k,v in rows:
   if k in d:raise Refused('DUPLICATE_FIELD')
   d[k]=v
  return d
 try:return json.loads(b,object_pairs_hook=pairs)
 except (ValueError,UnicodeError):raise Refused('JSON') from None
def pin(x):return type(x)==str and re.fullmatch('[a-f0-9]{64}',x) is not None
def tx(x):return type(x)==str and re.fullmatch('v11-[a-f0-9]{32}',x) is not None

def phase1_scope(paths):
 protected=(ROOT,VALIDATION_ROOT,
 '/etc/systemd/system/tu1nz-v11-anchor.service',
 '/etc/systemd/system/tu1nz-v11-anchor-watch.timer',
 '/etc/systemd/system/tu1nz_delete_guard.service.d/99-v11-anchor.conf',
 '/run/systemd/system/tu1nz-v11-validation-anchor.service',
 '/run/systemd/system/tu1nz-v11-validation-watch.timer',
 '/run/systemd/system/tu1nz-v11-validation-consumer.service.d/99-v11-anchor.conf')
 if type(paths)!=list or not paths or any(type(p)!=str for p in paths) or len(set(paths))!=len(paths):raise Refused('PHASE1_SCOPE')
 for p in paths:
  if not p.startswith('/') or str(Path(p))!=p or '..' in Path(p).parts:raise Refused('PHASE1_SCOPE')
  if any(p==q or p.startswith(q+'/') or q.startswith(p.rstrip('/')+'/') for q in protected):raise Refused('PHASE0_IN_ROLLBACK')
 return True

def metadata(fd,uid,mode,directory=False):
 s=os.fstat(fd)
 if s.st_uid!=uid or s.st_gid!=(0 if uid==0 else os.getegid()) or stat.S_IMODE(s.st_mode)!=mode or os.listxattr(fd):raise Refused('METADATA')
 if directory:
  if not stat.S_ISDIR(s.st_mode):raise Refused('DIRECTORY_TYPE')
 elif not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise Refused('FILE_TYPE_LINKS')
 return s

def trusted_program(path,expected):
 # Canonical interpreter path, never /usr/bin/python3 symlink or PATH lookup.
 if not pin(expected) or not path.startswith('/') or str(Path(path))!=path:raise Refused('INTERPRETER_PATH')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  parts=Path(path).parts[1:]
  for i,n in enumerate(parts):
   child=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_DIRECTORY if i<len(parts)-1 else 0),dir_fd=fd);os.close(fd);fd=child;s=os.fstat(fd)
   if s.st_uid!=0 or s.st_gid!=0 or s.st_mode&0o022 or os.listxattr(fd):raise Refused('INTERPRETER_PARENT')
  if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or not s.st_mode&0o111:raise Refused('INTERPRETER_TYPE')
  h=hashlib.sha256()
  while True:
   b=os.read(fd,65536)
   if not b:break
   h.update(b)
  if h.hexdigest()!=expected:raise Refused('INTERPRETER_HASH')
  os.lseek(fd,0,os.SEEK_SET);return fd
 except BaseException:os.close(fd);raise

class Store:
 def __init__(self,path=ROOT,fixture=False,create=False,inject=lambda point:None,validation=False,created=lambda identity:None):
  self.path=Path(path);self.uid=os.geteuid();self.inject=inject;self.fixture=fixture
  if fixture:
   if self.uid==0 or self.path.parent!=Path('/tmp') or not self.path.name.startswith('tu1nz-anchor-test-'):raise Refused('FIXTURE_SCOPE')
  else:
   if self.uid!=0 or str(self.path)!=(VALIDATION_ROOT if validation else ROOT):raise Refused('ROOT_SCOPE')
   for p in reversed(self.path.parents):
    s=p.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_mode&0o022 or os.listxattr(p,follow_symlinks=False):raise Refused('PARENT')
  if create:
   self.path.mkdir(mode=0o700)
   identity=self.path.lstat();created((identity.st_dev,identity.st_ino))
   parent=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
   try:os.fsync(parent)
   finally:os.close(parent)
  self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);self.identity=metadata(self.fd,self.uid,0o700,True)
  if create:self.write('lock',b'',0o600)
 def close(self):os.close(self.fd)
 def check(self):
  s=self.path.lstat();metadata(self.fd,self.uid,0o700,True)
  if (s.st_dev,s.st_ino)!=(self.identity.st_dev,self.identity.st_ino):raise Refused('PATH_REPLACED')
 def name(self,n):
  self.check()
  if n not in ('lock','base.json','selection.json','fence.json','stop.json','phase1.json','terminal.json','phase0.json','anchor.py','guard-binding.json','bootstrap.json') and not re.fullmatch(r'(?:slot-[AB]\.(?:py|json)|event-[0-9]{6}\.json|attestation(?:-commit|-use)?-[0-9]{6}\.json)',n):raise Refused('NAME')
 def read(self,n,mode=0o400):
  f=self.open(n,mode)
  try:
   a=os.fstat(f);b=os.read(f,LIMIT+1);z=os.fstat(f);p=os.stat(n,dir_fd=self.fd,follow_symlinks=False)
   if len(b)>LIMIT or (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns) or (p.st_dev,p.st_ino)!=(z.st_dev,z.st_ino):raise Refused('READ_RACE_SIZE')
   return b
  finally:os.close(f)
 def open(self,n,mode):
  self.name(n);f=os.open(n,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=self.fd)
  try:metadata(f,self.uid,mode);return f
  except BaseException:os.close(f);raise
 def exists(self,n):
  self.name(n)
  try:os.stat(n,dir_fd=self.fd,follow_symlinks=False);return True
  except FileNotFoundError:return False
 def write(self,n,data,mode=0o400,replace=False):
  self.name(n)
  if type(data)!=bytes or len(data)>LIMIT:raise Refused('WRITE_SIZE')
  if replace and n not in ('selection.json','fence.json','phase1.json','phase0.json','slot-A.py','slot-A.json','slot-B.py','slot-B.json'):raise Refused('IMMUTABLE')
  if self.exists(n):
   if not replace:raise Refused('EXISTS')
   f=self.open(n,mode);os.close(f)
  t='.new-'+uuid.uuid4().hex;f=os.open(t,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=self.fd)
  try:
   os.fchmod(f,mode)
   with os.fdopen(f,'wb',closefd=False) as out:
    out.write(data);out.flush();self.inject('before_file_fsync:'+n);os.fsync(f);self.inject('after_file_fsync:'+n)
   metadata(f,self.uid,mode);self.check();self.inject('before_publish:'+n)
   if replace:os.replace(t,n,src_dir_fd=self.fd,dst_dir_fd=self.fd)
   else:
    # renameat2 NOREPLACE avoids link-count ambiguity in immutable records.
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.renameat2(self.fd,t.encode(),self.fd,n.encode(),1)!=0:raise OSError(ctypes.get_errno(),'NOREPLACE')
   self.inject('after_publish:'+n);self.inject('before_directory_fsync:'+n);os.fsync(self.fd);self.inject('after_directory_fsync:'+n);self.check()
  finally:
   os.close(f)
   try:os.unlink(t,dir_fd=self.fd);os.fsync(self.fd)
   except FileNotFoundError:pass
 @contextlib.contextmanager
 def locked(self):
  f=self.open('lock',0o600)
  try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
  finally:os.close(f)
 def journal(self):
  names=sorted(n for n in os.listdir(self.fd) if n.startswith('event-'));prev='0'*64;rows=[]
  if len(names)>4096:raise Refused('JOURNAL_LIMIT')
  for i,n in enumerate(names):
   row=parse(self.read(n))
   if n!='event-%06d.json'%i or set(row)!={'seq','previous','event'} or row['seq']!=i or row['previous']!=prev:raise Refused('JOURNAL_CHAIN')
   rows.append(row);prev=digest(encode(row))
  return rows,prev
 def record(self,event):
  rows,prev=self.journal();self.write('event-%06d.json'%len(rows),encode({'seq':len(rows),'previous':prev,'event':event}))
 def closed(self):return parse(self.read('fence.json',0o600))=={'state':'CLOSED'}
 def close_fence(self):self.write('fence.json',encode({'state':'CLOSED'}),0o600,True)
 def stop(self,code):
  self.close_fence()
  if not self.exists('stop.json'):self.write('stop.json',encode({'state':'SECURED_STOP','reason':code if re.fullmatch('[A-Z_]+',code) else 'UNCLASSIFIED'}))
  return 'SECURED_STOP'
 def base(self):
  b=parse(self.read('base.json'))
  if set(b)!={'schema','anchor_sha256','interpreter','interpreter_sha256','workers','phase1_paths'} or b['schema']!=VERSION or not pin(b['anchor_sha256']) or digest(self.read('anchor.py',0o500))!=b['anchor_sha256']:raise Refused('BASE')
  if type(b['workers'])!=list or not b['workers'] or len(set(b['workers']))!=len(b['workers']) or not all(pin(p) for p in b['workers']):raise Refused('WORKER_PINS')
  phase1_scope(b['phase1_paths'])
  if not self.fixture:f=trusted_program(b['interpreter'],b['interpreter_sha256']);os.close(f)
  return b
 def slot(self,name,want):
  if name not in ('A','B') or not pin(want):raise Refused('SLOT_NAME_PIN')
  b=self.base();m=parse(self.read('slot-'+name+'.json'))
  if set(m)!={'schema','slot','worker_sha256','base_sha256'} or m!={'schema':1,'slot':name,'worker_sha256':want,'base_sha256':digest(self.read('base.json'))} or want not in b['workers']:raise Refused('SLOT_MANIFEST')
  if digest(self.read('slot-'+name+'.py',0o500))!=want:raise Refused('SLOT_HASH')
  return m
 def selection(self):
  v=parse(self.read('selection.json',0o600))
  if set(v)!={'active','previous','generation'} or type(v['generation'])!=int or v['generation']<0:raise Refused('SELECTION_SCHEMA')
  names=[]
  for k in ('active','previous'):
   r=v[k]
   if r is None and k=='previous':continue
   if type(r)!=dict or set(r)!={'slot','sha256'} or r['slot'] not in ('A','B') or not pin(r['sha256']):raise Refused('SELECTION_ROW')
   names.append(r['slot'])
  if len(set(names))!=len(names):raise Refused('SELECTION_ALIAS')
  return v
 def choose(self):
  v=self.selection()
  for key in ('active','previous'):
   r=v[key]
   if r is None:continue
   try:self.slot(r['slot'],r['sha256']);return r
   except (Refused,OSError):continue
  raise Refused('NO_VALID_SLOT')
 def publish_slot(self,name,data):
  with self.locked():
   b=self.base();want=digest(data)
   if name not in ('A','B') or want not in b['workers']:raise Refused('UNPINNED_WORKER')
   old=self.selection() if self.exists('selection.json') else None
   if old and old['active']['slot']==name:raise Refused('ACTIVE_SLOT_IMMUTABLE')
   if old and old['previous'] and old['previous']['slot']==name:raise Refused('PREVIOUS_SLOT_RETAINED')
   self.record({'operation':'publish_slot','slot':name,'sha256':want,'state':'INTENT'})
   self.write('slot-'+name+'.py',data,0o500,True)
   self.write('slot-'+name+'.json',encode({'schema':1,'slot':name,'worker_sha256':want,'base_sha256':digest(self.read('base.json'))}),0o400,True)
   self.slot(name,want);self.inject('before_select')
   self.write('selection.json',encode({'active':{'slot':name,'sha256':want},'previous':old['active'] if old else None,'generation':old['generation']+1 if old else 0}),0o600,True)
   self.record({'operation':'publish_slot','slot':name,'sha256':want,'state':'DONE'})

class Anchor:
 def __init__(self,store,host):self.s=store;self.h=host
 def run(self):
  with self.s.locked():
   try:
    self.s.close_fence();self.h.confirm_closed()
    self.s.base();self.s.journal()
    if self.s.exists('stop.json'):return 'SECURED_STOP'
    selected=self.s.choose();self.h.verify_base()
    if not self.s.exists('phase1.json'):return 'RECOVERY_BASE_READY'
    phase=parse(self.s.read('phase1.json',0o600))
    if set(phase)!={'transaction','manifest_sha256','paths'} or not tx(phase['transaction']) or not pin(phase['manifest_sha256']) or phase['paths']!=self.s.base()['phase1_paths']:raise Refused('TRANSACTION_MANIFEST')
    if self.s.exists('terminal.json'):
     terminal=parse(self.s.read('terminal.json'))
     if terminal!={'state':TERMINAL,'phase1_sha256':digest(encode(phase)),'base_sha256':digest(self.s.read('base.json'))}:raise Refused('TERMINAL_BINDING')
     self.h.verify_rollback(phase);self.h.no_worker();self.h.quiesce_watchdog();return TERMINAL
    self.s.record({'operation':'worker','state':'INTENT','slot':selected,'phase1_sha256':digest(encode(phase))})
    result=self.h.run_worker(selected,phase)
    if result!=TERMINAL:raise Refused('WORKER_RESULT')
    self.h.no_worker();self.h.verify_rollback(phase);self.h.verify_base();self.h.confirm_closed();self.h.quiesce_watchdog()
    self.s.record({'operation':'worker','state':'DONE','slot':selected,'phase1_sha256':digest(encode(phase))})
    self.s.write('terminal.json',encode({'state':TERMINAL,'phase1_sha256':digest(encode(phase)),'base_sha256':digest(self.s.read('base.json'))}))
    return TERMINAL
   except Exception as error:
    self.s.stop(str(error));self.h.confirm_closed();return 'SECURED_STOP'
