"""Transactional fixed-scope publication; independent rescue journal is retained.
No CLI, environmental configuration, or implicit production admission. Manager is
an explicitly supplied bounded adapter; offline model is never root authority.
"""
import os,stat,json,hashlib,fcntl,re,contextlib,base64
from pathlib import Path
from files import Files,rename_no_replace
from core import Refused,raw,sha,parse
import units
TARGETS=tuple(sorted([units.PACKAGE+'/'+n for n in ('dispatcher.py','watchdog.py','installer.py')]+['/etc/tu1nz/v11-dispatcher/manifest.json']+['/etc/systemd/system/'+n for n in units.templates('0'*64)]))
DIRECTORIES={units.PACKAGE:(0,0,0o755),'/etc/tu1nz/v11-dispatcher':(0,0,0o700),'/etc/systemd/system/'+units.GUARD+'.d':(0,0,0o755),'/etc/systemd/system/'+units.LEGACY_TIMER+'.d':(0,0,0o755)}
PHASES=('PUBLISHED','RELOADED','MANAGER_VERIFIED','FENCE_BOUND','BOOT_ARMED','WORKER_BOUND','WATCHDOG_ARMED')
class PublicationFiles(Files):
 targets=TARGETS
 directories=DIRECTORIES

class Journal:
 """Full-state immutable generations; root-owned rescue path outside payloads."""
 def __init__(self,path,create=False):
  self.path=Path(path);self.uid=os.geteuid()
  if create: self.path.mkdir(mode=0o700)
  self.fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY)
  self.identity=os.fstat(self.fd)
  if not stat.S_ISDIR(self.identity.st_mode) or self.identity.st_uid!=self.uid or stat.S_IMODE(self.identity.st_mode)!=0o700 or os.listxattr(self.fd):raise Refused('JOURNAL_DIRECTORY')
  if create:
   f=os.open('lock',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600,dir_fd=self.fd);os.fchmod(f,0o600);os.fsync(f);os.close(f);os.fsync(self.fd)
 def close(self):os.close(self.fd)
 def check(self):
  s=self.path.lstat()
  if (s.st_dev,s.st_ino)!=(self.identity.st_dev,self.identity.st_ino) or s.st_uid!=self.uid or stat.S_IMODE(s.st_mode)!=0o700 or os.listxattr(self.fd):raise Refused('JOURNAL_REPLACED')
 @contextlib.contextmanager
 def locked(self):
  self.check();f=os.open('lock',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.fd)
  try:
   s=os.fstat(f)
   if not stat.S_ISREG(s.st_mode) or s.st_uid!=self.uid or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise Refused('LOCK_IDENTITY')
   fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
  finally:os.close(f)
 def load(self):
  self.check();names=sorted(n for n in os.listdir(self.fd) if n.startswith('record-'));last=None;previous='0'*64
  for i,n in enumerate(names):
   if n!='record-%06d.json'%i:raise Refused('JOURNAL_GAP')
   f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
   try:
    s=os.fstat(f)
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=self.uid or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o400 or os.listxattr(f):raise Refused('JOURNAL_FILE')
    data=os.read(f,16000001)
    if len(data)>16000000:raise Refused('JOURNAL_SIZE')
   finally:os.close(f)
   row=parse(data)
   if set(row)!={'seq','previous','state'} or row['seq']!=i or row['previous']!=previous:raise Refused('JOURNAL_CHAIN')
   last=row['state'];previous=sha(data)
  return last,len(names),previous
 def save(self,state):
  _,seq,previous=self.load();data=raw({'seq':seq,'previous':previous,'state':state})
  # A prior uncommitted temporary file cannot be adopted as a journal record.
  name='.pending-%06d'%seq
  if name in os.listdir(self.fd):raise Refused('INCOMPLETE_JOURNAL_PUBLICATION')
  f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=self.fd)
  try:
   os.fchmod(f,0o400)
   with os.fdopen(f,'wb',closefd=False) as out:out.write(data);out.flush();os.fsync(f)
   rename_no_replace(self.path/name,self.path/('record-%06d.json'%seq));os.fsync(self.fd)
  finally:os.close(f)

def payloads(capsule):
 if sha(capsule['manifest'])!=capsule['manifest_sha256']:raise Refused('CAPSULE_MANIFEST')
 m=parse(capsule['manifest']);out={}
 if set(capsule['artifacts'])!=set(m['artifacts']):raise Refused('CAPSULE_SET')
 for n,data in capsule['artifacts'].items():
  if n not in ('dispatcher.py','watchdog.py','installer.py') or sha(data)!=m['artifacts'][n]:raise Refused('CAPSULE_ARTIFACT')
  out[units.PACKAGE+'/'+n]=(data,0o500)
 out['/etc/tu1nz/v11-dispatcher/manifest.json']=(capsule['manifest'],0o400)
 expected={n:s.replace('@MANIFEST_SHA@',capsule['manifest_sha256']).encode() for n,s in m['unit_templates'].items()}
 if capsule['units']!=expected:raise Refused('UNIT_HASH_BINDING')
 for n,data in capsule['units'].items():out['/etc/systemd/system/'+n]=(data,0o644)
 if set(out)!=set(TARGETS):raise Refused('FIXED_PUBLICATION_SCOPE')
 return {n:{'bytes':v,'sha256':sha(v),'mode':mode,'uid':0,'gid':0} for n,(v,mode) in out.items()}

class Installer:
 def __init__(self,files,journal,manager,inject=lambda p:None):
  # Until the real manager/bootstrap admission is independently validated,
  # this engine is restricted to nonroot filesystem fixtures.
  if not files.fixture or os.geteuid()==0:raise Refused('PUBLICATION_PRODUCTION_ADMISSION_CLOSED')
  self.f=files;self.j=journal;self.m=manager;self.inject=inject;self.state=None
  self.f.save=self.receipt
 def persist(self):self.j.save(self.state)
 def receipt(self,value):
  self.state['files']=value;self.persist()
  if not value['receipts']:self.inject('directory_receipt')
  for receipt in value['receipts'].values():self.inject('receipt:'+receipt['status'])
 def resume(self):
  self.state,_,_=self.j.load()
  if self.state is None:raise Refused('NO_ROOT_STARTED')
  self.f.receipts=self.state['files']['receipts'];self.f.created=self.state['files']['created_directories']
 def start(self,transaction,candidates,admission):
  with self.j.locked():
   if self.j.load()[0] is not None:raise Refused('DUPLICATE_START')
   if not re.fullmatch('v11-[a-f0-9]{32}',transaction) or set(candidates)!=set(TARGETS):raise Refused('TRANSACTION_SCOPE')
   for n,v in candidates.items():
    if sha(v['bytes'])!=v['sha256'] or v['uid']!=0 or v['gid']!=0 or v['mode'] not in (0o400,0o500,0o644):raise Refused('CANDIDATE')
   before=self.f.snapshot(TARGETS,DIRECTORIES)
   # Adapter must verify exact freeze, pins, loaded state, no other writer,
   # capacity, root recovery anchor, and fixed executable/unit allowlists.
   manager_before=self.m.preflight(admission,before,{n:v['sha256'] for n,v in candidates.items()})
   self.state={'transaction':transaction,'status':'ROOT_STARTED','sealed':False,'originals':before,'manager_before':manager_before,'files':{'receipts':{},'created_directories':[]},'phase':None,'completed':[],'candidate_pins':{n:v['sha256'] for n,v in candidates.items()}}
   self.persist();self.inject('ROOT_STARTED');self.state['status']='BACKUP_VERIFIED';self.persist();self.inject('BACKUP_VERIFIED')
   try:
    self.f.create_declared_directories(DIRECTORIES)
    for n in TARGETS:
     self.inject('before:'+n);self.f.install_exact(n,candidates[n],before);self.inject('after:'+n)
    for phase in PHASES:
     self.state['phase']={'name':phase,'state':'INTENT'};self.persist();self.inject('intent:'+phase)
     if phase=='PUBLISHED':
      for n in TARGETS:self.f.verify_exact(n,candidates[n])
     proof=self.m.apply(phase,self.state)
     if not re.fullmatch('[a-f0-9]{64}',proof):raise Refused('MANAGER_PROOF')
     self.inject('action:'+phase);self.state['phase']={'name':phase,'state':'DONE','proof':proof};self.state['completed'].append(phase);self.persist();self.inject('done:'+phase)
    self.state['status']='PRESEAL_PUBLISHED';self.persist();return self.state['status']
   except Exception:
    return self._rollback()
 def rollback(self):
  with self.j.locked():self.resume();return self._rollback()
 def _rollback(self):
  try:
   if self.state['sealed']:
    self.m.close_fence();self.state['status']='SECURED_STOP';self.persist();return 'SECURED_STOP'
   if self.state['status']=='ROLLED_BACK':
    if not self.f.same_restored_snapshot(self.state['originals']) or not self.m.verify_restored(self.state['manager_before']):raise Refused('TERMINAL_DRIFT')
    return 'ROLLED_BACK'
   self.state['status']='ROLLBACK_INTENT';self.persist();self.inject('rollback_intent')
   self.m.close_fence();self.m.quiesce_owned();self.inject('rollback_quiesced')
   self.f.restore_owned_changes(self.state['originals'],cleanup=False);self.inject('rollback_files')
   self.m.restore(self.state['manager_before']);self.inject('rollback_manager')
   if not self.f.same_restored_snapshot(self.state['originals']) or not self.m.verify_restored(self.state['manager_before']):raise Refused('ROLLBACK_VERIFICATION')
   self.f.restore_owned_changes(self.state['originals'],cleanup=True);self.inject('rollback_cleanup')
   if not self.f.same_restored_snapshot(self.state['originals']):raise Refused('ROLLBACK_FINAL')
   self.state['status']='ROLLED_BACK';self.persist();return 'ROLLED_BACK'
  except Exception as error:
   self.state['failure']=str(error) if re.fullmatch('[A-Z_]+',str(error)) else type(error).__name__
   self.m.close_fence();self.state['status']='SECURED_STOP' if self.state['sealed'] else 'PRESEAL_SECURED_STOP';self.persist();return self.state['status']
