"""Durable forward-only barrier, no host mutations or executable launcher.
A provider action may be offered ONLY after handoff() returns successfully.
Callers must bind the independent watchdog and verified consumer stop separately.
The immutable barrier overrides an older state after a crash; uncertain data refuses.
"""
import contextlib,fcntl,hashlib,json,os,re,stat,uuid
class Refused(RuntimeError):pass
PHASES=('CONSUMERS_QUIESCED','PROVIDER_HANDOFF_INTENT','PROVIDER_REPLACED',
        'NEW_CREDENTIAL_INSTALLED','NEW_CREDENTIAL_VERIFIED','COMPLETED')
def encoded(obj):return json.dumps(obj,sort_keys=True,separators=(',',':')).encode()+b'\n'
class Journal:
 def __init__(self,path,transaction,manifest_sha,fixture=False):
  if not re.fullmatch(r'tu1nz-privileged-v11-[a-f0-9]{32}',transaction) or not re.fullmatch(r'[a-f0-9]{64}',manifest_sha):raise Refused('BINDING')
  if not fixture and os.geteuid()!=0:raise Refused('ROOT_REQUIRED')
  self.uid=os.geteuid();self.binding={'transaction':transaction,'manifest_sha256':manifest_sha}
  parts=os.fspath(path).split('/')
  if not os.path.isabs(path) or any(x in ('.','..') for x in parts):raise Refused('PATH')
  fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
  try:
   for part in (x for x in parts if x):
    nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
    st=os.fstat(fd)
    if not fixture and (st.st_uid!=0 or st.st_mode&0o022 or any(x.startswith('system.posix_acl_') for x in os.listxattr(fd))):raise Refused('PARENT')
   self.fd=os.dup(fd)
  finally:os.close(fd)
  try:self.check(self.fd,0o700,True)
  except BaseException:os.close(self.fd);raise
 def close(self):os.close(self.fd)
 def check(self,fd,mode,directory=False):
  s=os.fstat(fd)
  if s.st_uid!=self.uid or stat.S_IMODE(s.st_mode)!=mode or (not stat.S_ISDIR(s.st_mode) if directory else not stat.S_ISREG(s.st_mode) or s.st_nlink!=1):raise Refused('METADATA')
  if any(x in os.listxattr(fd) for x in ('system.posix_acl_access','system.posix_acl_default')):raise Refused('ACL')
 def read(self,name):
  try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
  except FileNotFoundError:return None
  try:
   self.check(fd,0o600);data=os.read(fd,8193)
   if len(data)>8192:raise Refused('SIZE')
   try:o=json.loads(data)
   except (ValueError,UnicodeError):raise Refused('JSON') from None
   if type(o) is not dict or set(o)!={'payload','sha256'} or hashlib.sha256(encoded(o['payload'])).hexdigest()!=o['sha256']:raise Refused('CHECKSUM')
   v=o['payload']
   if type(v) is not dict or any(v.get(k)!=x for k,x in self.binding.items()):raise Refused('BINDING')
   return v
  finally:os.close(fd)
 def publish(self,name,payload,replace=False):
  data=encoded({'payload':payload,'sha256':hashlib.sha256(encoded(payload)).hexdigest()});tmp='.tmp-'+uuid.uuid4().hex
  fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
  try:
   os.fchmod(fd,0o600);self.check(fd,0o600)
   with os.fdopen(fd,'wb',closefd=False) as f:f.write(data);f.flush();os.fsync(fd)
   if replace:os.replace(tmp,name,src_dir_fd=self.fd,dst_dir_fd=self.fd)
   else:
    # link gives no-replace atomic publication; remove our temporary link before read.
    os.link(tmp,name,src_dir_fd=self.fd,dst_dir_fd=self.fd,follow_symlinks=False);os.unlink(tmp,dir_fd=self.fd)
   os.fsync(self.fd)
  finally:
   os.close(fd)
   try:os.unlink(tmp,dir_fd=self.fd)
   except FileNotFoundError:pass
 @contextlib.contextmanager
 def locked(self):
  self.check(self.fd,0o700,True)
  fd=os.open('journal.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self.fd)
  try:
   self.check(fd,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
  finally:os.close(fd)
 def _state(self):
  s=self.read('rotation.json')
  if s is None or set(s)!=set(self.binding)|{'phase'} or s['phase'] not in PHASES:raise Refused('STATE')
  return s
 def _barrier(self):
  b=self.read('forward-only.json')
  if b is not None and b!={**self.binding,'forward_only':True}:raise Refused('BARRIER')
  return b
 def initialize(self):
  with self.locked():
   if self._barrier() is not None or self.read('rotation.json') is not None:raise Refused('EXISTING')
   self.publish('rotation.json',{**self.binding,'phase':PHASES[0]})
 def handoff(self):
  with self.locked():
   s=self._state()
   if s['phase']!=PHASES[0]:raise Refused('PHASE')
   if self._barrier() is None:self.publish('forward-only.json',{**self.binding,'forward_only':True})
   self.publish('rotation.json',{**self.binding,'phase':PHASES[1]},replace=True)
 def advance(self,phase):
  with self.locked():
   s=self._state()
   if self._barrier() is None or phase not in PHASES[2:] or PHASES.index(phase)!=PHASES.index(s['phase'])+1:raise Refused('PHASE')
   self.publish('rotation.json',{**self.binding,'phase':phase},replace=True)
 def decision(self):
  with self.locked():
   s=self._state();b=self._barrier()
   if b is None and s['phase']!=PHASES[0]:raise Refused('MISSING_BARRIER')
   if b is not None:return 'FORWARD_ONLY_VERIFY_NEW_OR_SECURED_STOP'
   return 'ROLLBACK_VERIFIED_OWNED_CHANGES'
