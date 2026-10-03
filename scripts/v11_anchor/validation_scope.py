"""Outer exact-prestate restoration for the isolated ROOT VALIDATION ONLY.
This is not production rollback and cannot name a production artifact.
"""
import os,stat
from pathlib import Path
from anchor import Refused,Store,encode,parse,digest,VALIDATION_ROOT
import manager,host,install,decommission
from publication import Journal
from isolated_runtime import GUARD,SHADOW
from root_validation import safe_tree_inventory,remove_test_tree
SCOPE=(VALIDATION_ROOT,GUARD,SHADOW,host.VALIDATION_PAYLOAD)
CONSUMER='/run/systemd/system/tu1nz-v11-validation-consumer.service'

class Scope:
 def __init__(self,evidence,capsule):
  if os.geteuid()!=0 or capsule['profile']!='validation':raise Refused('OUTER_VALIDATION_ONLY')
  self.evidence=Path(evidence);self.capsule=capsule;self.ledger=self.evidence/'owned.json'
  self.m=manager.Manager('validation',lambda e:None,lambda:None)
  self.original={r:self.m.show(r) for r in ('anchor','watch','consumer')}
  if any(r['LoadState']!='not-found' or r['ActiveState']!='inactive' for r in self.original.values()):raise Refused('OUTER_PREEXISTING_UNIT')
  if 'LoadState=not-found' not in self.m.call(('show','--property=LoadState','--',host.VALIDATION_MAIN)):raise Refused('OUTER_PREEXISTING_MAIN')
  extra=[CONSUMER,*host.VALIDATION_TARGETS,*[self.m.p['unitdir']+'/'+n for n in manager.templates('validation','0'*64,'/usr/bin/python3.12')],self.m.p['unitdir']+'/sysinit.target.wants/'+self.m.p['anchor'],self.m.p['unitdir']+'/timers.target.wants/'+self.m.p['watch']]
  if any(Path(p).exists() or Path(p).is_symlink() for p in (*SCOPE,*extra)):raise Refused('OUTER_PREEXISTING_SCOPE')
  manager.no_foreign_reload(self.m.call(('show','--property=Id,NeedDaemonReload','--','*')),set())
  self.save({'schema':1,'owned':{}})
 def save(self,row):
  raw=encode(row);tmp=self.evidence/'.owned-new';fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:os.write(fd,raw);os.fsync(fd)
  finally:os.close(fd)
  os.replace(tmp,self.ledger);fd=os.open(self.evidence,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(fd)
  finally:os.close(fd)
 def load(self):
  fd=os.open(self.ledger,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   st=os.fstat(fd)
   if st.st_uid!=0 or st.st_gid!=0 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or os.listxattr(fd):raise Refused('OUTER_LEDGER_METADATA')
   row=parse(os.read(fd,65537))
  finally:os.close(fd)
  if set(row)!={'schema','owned'} or row['schema']!=1 or not set(row['owned'])<=set((*SCOPE,CONSUMER)):raise Refused('OUTER_LEDGER_SCOPE')
  return row
 def note(self,path,identity):
  p=str(path)
  if p not in (*SCOPE,CONSUMER):return
  row=self.load()
  if p in row['owned'] and row['owned'][p]!=list(identity):raise Refused('OUTER_REPLACED_SCOPE')
  row['owned'][p]=list(identity);self.save(row)
 def restore(self,reason):
  row=self.load();result={'schema':1,'reason':reason,'status':'INCOMPLETE','scope':'ISOLATED_VALIDATION_ONLY'};s=None;j0=j1=None
  try:
   # Stop only literal, owned test units. Unknown loaded fragments refuse.
   for role in ('watch','anchor'):
    r=self.m.show(role)
    if r['LoadState']=='loaded' and r['FragmentPath']!=self.m.p['unitdir']+'/'+self.m.p[role]:raise Refused('OUTER_FOREIGN_FRAGMENT')
    if r['ActiveState']!='inactive':self.m.action('stop',role)
    if r['UnitFileState'].startswith('enabled'):self.m.action('disable',role)
   main=self.m.call(('show','--property=Id,LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,ExecStart,NeedDaemonReload','--',host.VALIDATION_MAIN))
   loaded=dict(x.split('=',1) for x in main.splitlines())
   if loaded.get('LoadState')=='loaded' and loaded.get('FragmentPath')!='/run/systemd/system/'+host.VALIDATION_MAIN:raise Refused('OUTER_FOREIGN_MAIN')
   if loaded.get('ActiveState')!='inactive':self.m.call(('stop','--',host.VALIDATION_MAIN))
   if Path(VALIDATION_ROOT).exists():
    if VALIDATION_ROOT not in row['owned']:raise Refused('OUTER_UNOWNED_BASE')
    s=Store(VALIDATION_ROOT,validation=True)
    # An early preparation crash may precede base.json; no units may have
    # been published yet. A completed base must match the pinned capsule.
    if s.exists('base.json'):
     b=s.base()
     if b['anchor_sha256']!=digest(self.capsule['anchor']) or not set(b['workers'])<=set(self.capsule['worker_pins']):raise Refused('OUTER_BASE_DRIFT')
    if s.exists('shadow-ownership.json'):
     own=parse(s.read('shadow-ownership.json'))
     if set(own)!={'dev','inode'}:raise Refused('OUTER_SHADOW_OWNERSHIP')
     self.note(SHADOW,(own['dev'],own['inode']));row=self.load()
    if (s.path/'publication').exists():
     j1=Journal(s.path/'publication');state,_,_=j1.load()
     if state is not None:
      f=host.ValidationFiles()
      if set(state['before'])!=set(host.VALIDATION_TARGETS) or any(r!={'absent':True} for r in state['before'].values()):raise Refused('OUTER_ORIGINAL_SCOPE')
      f.receipts=state['files']['receipts'];f.created=state['files']['created_directories'];
      def save_phase1(v):state['files']=v;j1.save(state)
      f.save=save_phase1
      f.restore_owned_changes(state['before'])
      if not f.same_restored_snapshot(state['before']):raise Refused('OUTER_PHASE1_RESTORE')
    if (s.path/'phase0-journal').exists():
     j0=Journal(s.path/'phase0-journal');state,_,_=j0.load()
     if state is not None:
      f=install.file_backend('validation')
      if set(state['before'])!=set(f.targets) or any(r!={'absent':True} for r in state['before'].values()):raise Refused('OUTER_PHASE0_SCOPE')
      f.receipts=state['files']['receipts'];f.created=state['files']['created_directories'];
      def save_phase0(v):state['files']=v;j0.save(state)
      f.save=save_phase0
      f.restore_owned_changes(state['before'])
      if not f.same_restored_snapshot(state['before']):raise Refused('OUTER_PHASE0_RESTORE')
   consumer=Path(CONSUMER)
   if consumer.exists() or consumer.is_symlink():
    st=consumer.lstat()
    if row['owned'].get(CONSUMER)!=[st.st_dev,st.st_ino] or not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1 or os.listxattr(consumer,follow_symlinks=False):raise Refused('OUTER_FOREIGN_CONSUMER')
    consumer.unlink()
   self.m.action('daemon-reload')
   if any(decommission.normalized(self.m.show(r))!=decommission.normalized(self.original[r]) for r in self.original):raise Refused('OUTER_MANAGER_NOT_RESTORED')
   if 'LoadState=not-found' not in self.m.call(('show','--property=LoadState','--',host.VALIDATION_MAIN)):raise Refused('OUTER_MAIN_REMAINS')
   if j1:j1.close();j1=None
   if j0:j0.close();j0=None
   if s:s.close();s=None
   for path in (SHADOW,GUARD,VALIDATION_ROOT):
    p=Path(path)
    if not p.exists():continue
    st=p.lstat();identity=row['owned'].get(path)
    if identity!=[st.st_dev,st.st_ino]:raise Refused('OUTER_FOREIGN_DIRECTORY')
    rows=safe_tree_inventory(p)
    # Private evidence is retained before deleting only this newly owned scope.
    from root_validation import exclusive_file
    exclusive_file(self.evidence/(p.name+'-final-inventory.json'),encode(rows),0o600)
    remove_test_tree(p,tuple(identity),rows)
   if any(Path(p).exists() or Path(p).is_symlink() for p in (*SCOPE,CONSUMER,*host.VALIDATION_TARGETS)):raise Refused('OUTER_SCOPE_REMAINS')
   result['status']='EXACT_PRESTATE_RESTORED';return True
  except BaseException as e:
   result['error']=type(e).__name__;result['code']=str(e) if str(e).replace('_','').isalnum() and len(str(e))<100 else 'REDACTED';return False
  finally:
   if j1:j1.close()
   if j0:j0.close()
   if s:s.close()
   from root_validation import exclusive_file
   exclusive_file(self.evidence/'supervisor-result.json',encode(result),0o600)
