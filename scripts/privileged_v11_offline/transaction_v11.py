"""New V11 durable coordinator; no host action on import, no V9 state reuse.

The host adapter must implement every declared verification and mutation. An
incomplete adapter or evidence bundle refuses before the first mutation.
"""
import fcntl,hashlib,json,os,re,stat,time
from pathlib import Path

PHASES=('install_broker','install_replacements','verify_replacements',
        'mommy_nonroot','verify_mommy','socket_persistence','seal_authority',
        'socket_cutover','remove_docker_membership','remove_unsafe_sudo',
        'quarantine_unsafe_triggers','verify_authority','verify_all_services')
SEAL='seal_authority'
TERMINAL={'COMPLETED','ROLLED_BACK','SECURED_STOP','ROLLBACK_FAILED','ABORTED_BEFORE_MUTATION'}
REQUIRED_PROOFS={'current_baseline','network_contract','n8n_semantics','apparmor',
                 'broker','doc_replacement','trendwatch_replacement','socket_clients',
                 'sudo_candidate','mychatbuddy_frozen','rollback','workflow'}
class Refused(RuntimeError):pass

def encode(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def digest(b):return hashlib.sha256(b).hexdigest()

def window(available_seconds,budget_seconds):
 if isinstance(available_seconds,bool) or isinstance(budget_seconds,bool) or not 1800<=budget_seconds<=7200 or available_seconds<budget_seconds+300:
  raise Refused('INSUFFICIENT_FRESH_WINDOW')

def validate_proofs(proofs):
 if set(proofs)!=REQUIRED_PROOFS:raise Refused('PROOF_SET')
 for name,row in proofs.items():
  if set(row)!={'passed','sha256'} or row['passed'] is not True or not re.fullmatch('[0-9a-f]{64}',row['sha256']):raise Refused('PROOF_'+name)

class Store:
 def __init__(self,path,fixture=False):
  self.path=Path(path);self.fixture=fixture
  if fixture and os.geteuid()==0:raise Refused('ROOT_FIXTURE')
  if not fixture and os.geteuid()!=0:raise Refused('ROOT_REQUIRED')
  self.guard()
  self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  self.lock=os.open('lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self.fd)
  try:
   st=os.fstat(self.lock)
   if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600:raise Refused('LOCK_IDENTITY')
   fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BaseException:os.close(self.lock);os.close(self.fd);raise
 def guard(self):
  paths=[self.path] if self.fixture else [*reversed(self.path.parents),self.path]
  for p in paths:
   s=p.lstat()
   if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o022:raise Refused('STORE_PATH')
   if hasattr(os,'listxattr') and any('posix_acl' in x for x in os.listxattr(p,follow_symlinks=False)):raise Refused('STORE_ACL')
  if stat.S_IMODE(self.path.stat().st_mode)!=0o700:raise Refused('STORE_MODE')
 def read(self):
  fd=os.open('state.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
  with os.fdopen(fd,'rb') as f:
   s=os.fstat(f.fileno())
   if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:raise Refused('STATE_IDENTITY')
   b=f.read(4_000_001)
  if len(b)>4_000_000:raise Refused('STATE_SIZE')
  x=json.loads(b)
  if digest(encode(x['state']))!=x['sha256']:raise Refused('STATE_HASH')
  return x['state']
 def write(self,state,initial=False):
  if initial:
   try:os.stat('state.json',dir_fd=self.fd,follow_symlinks=False)
   except FileNotFoundError:pass
   else:raise Refused('EXISTING_TRANSACTION')
  else:self.read()
  b=encode({'state':state,'sha256':digest(encode(state))});name='.state-'+os.urandom(16).hex()
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
  try:
   with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(b);f.flush();os.fsync(f.fileno())
   if initial:os.link(name,'state.json',src_dir_fd=self.fd,dst_dir_fd=self.fd,follow_symlinks=False);os.unlink(name,dir_fd=self.fd)
   else:os.replace(name,'state.json',src_dir_fd=self.fd,dst_dir_fd=self.fd)
   os.fsync(self.fd)
  finally:
   try:os.unlink(name,dir_fd=self.fd)
   except FileNotFoundError:pass
 def close(self):os.close(self.lock);os.close(self.fd)

class Coordinator:
 def __init__(self,store,host,clock=time.monotonic_ns):self.store=store;self.host=host;self.clock=clock
 def start(self,transaction_id,boot_id,available_seconds,budget_seconds,proofs):
  # The inline bootstrap records ROOT_STARTED before entering this coordinator.
  # Only a fresh bootstrap state is accepted; no existing/prepared run reused.
  window(available_seconds,budget_seconds);validate_proofs(proofs)
  s=self.store.read()
  if s!={'status':'ROOT_STARTED','transaction_id':transaction_id,'boot_id':boot_id}:raise Refused('BOOTSTRAP_STATE')
  if not re.fullmatch('[a-z0-9-]{16,96}',transaction_id):raise Refused('TRANSACTION_ID')
  if self.host.preflight(proofs) is not True:raise Refused('HOST_PREFLIGHT')
  s.update(status='PRECHECK_ONLY',deadline_ns=self.clock()+budget_seconds*1_000_000_000,sealed=False,steps=[],proofs=proofs);self.store.write(s)
  backup=self.host.backup()
  if self.host.verify_backup(backup) is not True:raise Refused('BACKUP_VERIFY')
  s.update(status='BACKUP_VERIFIED',backup=backup);self.store.write(s)
  if self.host.arm_watchdog(s) is not True:raise Refused('WATCHDOG_NOT_VERIFIED')
  s['watchdog_active']=True;self.store.write(s)
 def step(self,phase):
  s=self.store.read()
  if s['status'] not in ('BACKUP_VERIFIED','PHASE_VERIFIED') or len(s['steps'])>=len(PHASES) or PHASES[len(s['steps'])]!=phase:raise Refused('PHASE_ORDER')
  if self.clock()+300_000_000_000>=s['deadline_ns']:raise Refused('ROLLBACK_MARGIN')
  checkpoint=self.host.checkpoint(phase)
  if self.host.precondition(phase,checkpoint,s) is not True:raise Refused('PHASE_PRECONDITION')
  if self.host.verify_checkpoint(phase,checkpoint) is not True:raise Refused('CHECKPOINT_UNVERIFIED')
  if phase==SEAL:s['sealed']=True
  s['steps'].append({'phase':phase,'before':checkpoint,'status':'INTENT'});s['status']='PHASE_INTENT';self.store.write(s)
  try:
   self.host.apply(phase,s)
   if self.host.verify(phase,s) is not True:raise Refused('PHASE_VERIFY')
   s['steps'][-1]['status']='VERIFIED';s['status']='PHASE_VERIFIED';self.store.write(s)
  except Exception:
   self.recover();raise
 def recover(self):
  s=self.store.read()
  if s['status']=='COMMIT_RECORDED':
   return self.finish_committed()['status']
  if s['status'] in TERMINAL:
   if s['status']=='ROLLBACK_FAILED':raise Refused('MANUAL_RECOVERY_REQUIRED')
   return s['status']
  s['status']='RECOVERY_INTENT';self.store.write(s)
  try:
   if s.get('sealed'):
    # First close authority even if a crash occurred during its original cutover.
    if self.host.secure_fail_closed(s) is not True:raise Refused('AUTHORITY_NOT_CLOSED')
   for row in reversed(s.get('steps',[])):
    if row['status']=='RECOVERED':continue
    self.host.restore(row['phase'],row['before'],sealed=s.get('sealed',False))
    if self.host.verify_restore(row['phase'],row['before'],sealed=s.get('sealed',False)) is not True:raise Refused('RESTORE_VERIFY')
    row['status']='RECOVERED';self.store.write(s)
   if self.host.verify_frozen(s) is not True:raise Refused('FROZEN_SERVICE_DRIFT')
   s['status']='SECURED_STOP' if s.get('sealed') else 'ROLLED_BACK';self.store.write(s)
   return s['status']
  except Exception:
   s['status']='ROLLBACK_FAILED';self.store.write(s);raise
 def finish(self):
  s=self.store.read()
  if s['status']!='PHASE_VERIFIED' or [x['phase'] for x in s['steps']]!=list(PHASES) or any(x['status']!='VERIFIED' for x in s['steps']):raise Refused('INCOMPLETE')
  if self.clock()+300_000_000_000>=s['deadline_ns']:raise Refused('FINAL_MARGIN')
  if self.host.final_verify(s) is not True:raise Refused('FINAL_VERIFY')
  # Commit the verified decision before cancellation, so a crash after
  # cancellation cannot leave an unprotected pre-commit transaction.
  s.update(status='COMMIT_RECORDED',final_verified=True);self.store.write(s)
  return self.finish_committed()
 def finish_committed(self):
  s=self.store.read()
  if s.get('status')!='COMMIT_RECORDED' or s.get('final_verified') is not True or [x['phase'] for x in s['steps']]!=list(PHASES) or any(x['status']!='VERIFIED' for x in s['steps']):raise Refused('COMMIT_RECORD')
  # Recovery of COMMIT_RECORDED only retries verified watchdog cleanup.
  # It never replays mutations or reopens revoked authority.
  if self.host.disarm_watchdog(s) is not True:raise Refused('WATCHDOG_DISARM')
  s.update(status='COMPLETED',watchdog_active=False);self.store.write(s)
  return s

def watchdog_due(state,boot_id,now_ns):
 if state['status'] in TERMINAL:return False
 if state['status']=='COMMIT_RECORDED':return True
 return state.get('boot_id')!=boot_id or now_ns>=state.get('deadline_ns',0)
