"""Durable preseal rollback sequencing. No implicit fence removal on restart.
The production adapter must verify each fixed operation; this module has no CLI.
"""
from state import *
STEPS=('INHIBIT','VALIDATE_ORIGINALS','QUIESCE','RESTORE_PAYLOADS','RESTORE_UNITS','RELOAD','VERIFY_MANAGER','RESTORE_TIMER_INHIBITED','VERIFY_ORIGINALS','ROLLBACK_COMMITTED','REMOVE_FENCE','CLEANUP','ROLLED_BACK')

class Journal:
 def __init__(self,store):self.store=store
 @contextlib.contextmanager
 def locked(self):
  name='recovery.lock'
  try:
   fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.store.fd);os.fchmod(fd,0o600);os.fsync(fd);os.fsync(self.store.fd)
  except FileExistsError:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.store.fd)
  try:
   self.store.check(fd,mode=0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
  finally:os.close(fd)
 def read(self):
  state=self.store.current()
  if state['sealed']:raise Refused('PRESEAL_REPAIR_AFTER_SEAL')
  names=sorted(n for n in os.listdir(self.store.fd) if n.startswith('recovery-'))
  previous='0'*64;rows=[]
  if len(names)>2*len(STEPS):raise Refused('RECOVERY_SIZE')
  for i,n in enumerate(names):
   if n!='recovery-%06d.json'%i:raise Refused('RECOVERY_GAP')
   x=self.store.read(n)
   if set(x)!={'binding','seq','previous','step','status','proof'} or x['seq']!=i or x['binding']!=state['binding'] or x['previous']!=previous or x['step']!=STEPS[i//2] or x['status']!=('INTENT' if i%2==0 else 'VERIFIED'):raise Refused('RECOVERY_CHAIN')
   if i%2 and not re.fullmatch('[0-9a-f]{64}',x['proof']):raise Refused('RECOVERY_PROOF')
   previous=digest(encode(x));rows.append(x)
  return state,rows,previous
 def append(self,step,status,proof=''):
  state,rows,previous=self.read();i=len(rows)
  if i>=2*len(STEPS) or step!=STEPS[i//2] or status!=('INTENT' if i%2==0 else 'VERIFIED'):raise Refused('RECOVERY_ORDER')
  x={'binding':state['binding'],'seq':i,'previous':previous,'step':step,'status':status,'proof':proof}
  self.store.publish('recovery-%06d.json'%i,x)
 def inhibit(self):
  state,_,_=self.read()
  expected={'binding':state['binding'],'status':'PRESEAL_RECOVERY'}
  if not self.store.exists('PRESEAL_INHIBIT'):self.store.publish('PRESEAL_INHIBIT',expected)
  if self.store.read('PRESEAL_INHIBIT')!=expected:raise Refused('INHIBIT_BINDING')

class Recovery:
 def __init__(self,store,host,inject=lambda point:None):self.store=store;self.host=host;self.inject=inject;self.journal=Journal(store)
 def run(self,current_boot):
  if self.host.preseal_admitted() is not True:raise Refused('PRESEAL_PRODUCTION_ADMISSION_CLOSED')
  if not re.fullmatch('[a-f0-9-]{36}',current_boot):raise Refused('RECOVERY_BOOT')
  with self.journal.locked():
   self.journal.inhibit()
   state,rows,_=self.journal.read()
   if len(rows)==2*len(STEPS):return 'ROLLED_BACK'
   try:
    for step in STEPS[len(rows)//2:]:
     _,rows,_=self.journal.read()
     if len(rows)%2==0:self.journal.append(step,'INTENT')
     self.inject('before:'+step)
     # Method names are fixed source, never read from a manifest or journal.
     proof=self.host.preseal_step(step,state['binding'],current_boot)
     if type(proof)!=dict or set(proof)!={'verified','sha256'} or proof['verified'] is not True or not re.fullmatch('[0-9a-f]{64}',proof['sha256']):raise Refused('PRESEAL_STEP_VERIFY')
     self.inject('after_action:'+step)
     self.journal.append(step,'VERIFIED',proof['sha256']);self.inject('after_commit:'+step)
    return 'ROLLED_BACK'
   except Exception:
    # Do not blindly remove the fence or reopen the legacy timer on an error.
    self.store.stop('PRESEAL_SECURED_STOP')
    self.host.preseal_secured_stop()
    return 'PRESEAL_SECURED_STOP'
