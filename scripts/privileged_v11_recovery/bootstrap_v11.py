"""Root-owned bundle publication primitive. No entrypoint, sudo or live calls.
An unpublished failed stage is retained as evidence, never reused.
"""
import ctypes,errno,fcntl,hashlib,json,os,re,stat,time,uuid
from pathlib import Path
class Refused(RuntimeError):pass

def fresh_window(observed_ns,deadline_ns,now_ns,budget_seconds=3600):
 if any(type(x) is not int for x in (observed_ns,deadline_ns,now_ns,budget_seconds)):raise Refused('TIME_TYPES')
 if not 1800<=budget_seconds<=7200 or not 0<=now_ns-observed_ns<=120_000_000_000 or deadline_ns-now_ns<(budget_seconds+300)*1_000_000_000:raise Refused('WINDOW_NOT_FRESH_OR_TOO_SHORT')

def write_file(fd,name,data):
 f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
 with os.fdopen(f,'wb') as out:os.fchmod(out.fileno(),0o600);out.write(data);out.flush();os.fsync(out.fileno())

def publish(parent,transaction_id,payload,pins,observed_ns,deadline_ns,preflight,clock=time.monotonic_ns,fixture=False):
 # Every check below runs before a new directory, lock or marker exists.
 fresh_window(observed_ns,deadline_ns,clock())
 if fixture:
  if os.geteuid()==0:raise Refused('ROOT_FIXTURE_FORBIDDEN')
 elif os.geteuid()!=0:raise Refused('ROOT_REQUIRED')
 if not re.fullmatch('tu1nz-privileged-v11-[0-9a-f]{32}',transaction_id):raise Refused('TRANSACTION_ID')
 if type(payload) is not dict or type(pins) is not dict:raise Refused('BUNDLE_TYPES')
 payload=payload.copy();pins=pins.copy()
 if not 1<=len(payload)<=128 or set(payload)!=set(pins):raise Refused('BUNDLE_SET')
 for n,b in payload.items():
  if n in {'manifest.json','state.json'} or not re.fullmatch(r'[a-z][a-z0-9_]{0,60}\.(py|sh|json)',n) or type(b) is not bytes or len(b)>2000000 or hashlib.sha256(b).hexdigest()!=pins[n]:raise Refused('BUNDLE_HASH_OR_PATH')
 if sum(len(v) for v in payload.values())>64000000:raise Refused('BUNDLE_SIZE')
 parent=Path(parent)
 if not fixture and parent!=Path('/var/lib'):raise Refused('FIXED_ROOT_PARENT')
 chain=[parent] if fixture else [*reversed(parent.parents),parent]
 for p in chain:
  s=p.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o022 or any('posix_acl' in a for a in os.listxattr(p,follow_symlinks=False)):raise Refused('UNTRUSTED_PARENT')
 if fixture and stat.S_IMODE(parent.stat().st_mode)!=0o700:raise Refused('PARENT_MODE')
 fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:raise Refused('CONCURRENT_BOOTSTRAP')
  if any(n.startswith(('tu1nz-privileged-v11-','.tu1nz-privileged-v11-')) for n in os.listdir(fd)):raise Refused('EXISTING_PREPARATION_OR_TRANSACTION')
  if preflight() is not True:raise Refused('LIVE_DRIFT_OR_MISSING_PRECONDITION')
  fresh_window(observed_ns,deadline_ns,clock())
  lib=ctypes.CDLL(None,use_errno=True)
  if not hasattr(lib,'renameat2'):raise Refused('ATOMIC_NOREPLACE_UNAVAILABLE')
  lib.renameat2.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];lib.renameat2.restype=ctypes.c_int
  hidden='.'+transaction_id+'-bootstrap-'+uuid.uuid4().hex
  os.mkdir(hidden,0o700,dir_fd=fd);os.chmod(hidden,0o700,dir_fd=fd,follow_symlinks=False);sfd=os.open(hidden,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
  try:
   write_file(sfd,'ROOT_STARTED',json.dumps({'transaction_id':transaction_id,'monotonic_ns':clock()},sort_keys=True).encode())
   os.fsync(sfd);os.fsync(fd)
   boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
   if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot):raise Refused('BOOT_ID')
   state={'status':'ROOT_STARTED','transaction_id':transaction_id,'boot_id':boot}
   canonical=json.dumps(state,sort_keys=True,separators=(',',':')).encode()
   write_file(sfd,'state.json',json.dumps({'state':state,'sha256':hashlib.sha256(canonical).hexdigest()},sort_keys=True,separators=(',',':')).encode())
   for n,b in payload.items():write_file(sfd,n,b)
   for n,b in payload.items():
    r=os.open(n,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=sfd)
    with os.fdopen(r,'rb') as inp:
     s=os.fstat(inp.fileno())
     if s.st_uid!=os.geteuid() or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or hashlib.sha256(inp.read()).hexdigest()!=pins[n]:raise Refused('STAGED_COPY_VERIFY')
   write_file(sfd,'manifest.json',json.dumps({'transaction_id':transaction_id,'files':pins,'status':'ROOT_STARTED'},sort_keys=True).encode());os.fsync(sfd)
   rc=lib.renameat2(fd,hidden.encode(),fd,transaction_id.encode(),1)
   if rc!=0:raise OSError(ctypes.get_errno(),'PUBLISH_FAILED')
   os.fsync(fd)
  finally:os.close(sfd)
 finally:os.close(fd)
 return parent/transaction_id

def watchdog_decision(state,current_boot,now_ns):
 required={'status','boot_id','deadline_ns','sealed'}
 allowed={'ROOT_STARTED','BACKUP_VERIFIED','PHASE_INTENT','PHASE_VERIFIED','COMMIT_RECORDED','COMPLETED','ROLLBACK_INTENT','ROLLED_BACK','ROLLBACK_FAILED','SECURED_STOP'}
 if type(state) is not dict or not required<=set(state):raise Refused('WATCHDOG_STATE')
 if state['status'] not in allowed or type(state['sealed']) is not bool or type(state['boot_id']) is not str or not state['boot_id'] or type(current_boot) is not str or not current_boot or type(now_ns) is not int or now_ns<0 or type(state['deadline_ns']) is not int or state['deadline_ns']<=0:raise Refused('WATCHDOG_STATE')
 if state['status'] in ('COMPLETED','ROLLED_BACK','SECURED_STOP'):return 'VERIFY_CLEANUP_ONLY'
 if state['status']=='COMMIT_RECORDED':return 'FINISH_VERIFIED_CLEANUP'
 if state['status']=='ROLLBACK_FAILED':return 'MANUAL_RECOVERY_NO_REPLAY'
 if state['boot_id']!=current_boot or now_ns>=state['deadline_ns']:return 'FAIL_CLOSED_RECOVERY' if state['sealed'] else 'ROLLBACK_OWNED_CHANGES'
 return 'WAIT'
