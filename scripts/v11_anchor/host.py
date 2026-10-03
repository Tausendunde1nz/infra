"""Root-only adapters shared by the embedded anchor and pinned recovery slot."""
import os
from anchor import *
import manager,worker,phase1
from publication import PublicationFiles,Journal
from files import Files
import systemd_adapter
VALIDATION_MAIN='tu1nz-v11-validation-main.service'
VALIDATION_PAYLOAD='/run/tu1nz-v11-phase1-validation'
VALIDATION_TARGETS=(VALIDATION_PAYLOAD+'/worker.py',VALIDATION_PAYLOAD+'/config.json','/run/systemd/system/'+VALIDATION_MAIN)
class ValidationFiles(Files):
 targets=VALIDATION_TARGETS
 directories={VALIDATION_PAYLOAD:(0,0,0o700)}
def backend(profile):
 if profile=='validation':return ValidationFiles()
 if profile=='production':return PublicationFiles()
 raise Refused('PROFILE')
from base_host import RootHost
class Phase1Host:
 def __init__(self,store,profile):
  self.base=RootHost(store,profile);self.s=store;self.profile=profile
  self.systemd=systemd_adapter.Systemd(store.record,store.close_fence) if profile=='production' else None
 def verify_base(self):self.base.verify_base()
 def confirm_closed(self):self.base.confirm_closed()
 def no_worker(self):pass # Worker is this process; external anchor verifies exit.
 def test_show(self):
  # One literal validation unit only, no caller-supplied unit or command.
  text=self.base.manager.call(('show','--property=Id,LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,ExecStart,NeedDaemonReload','--',VALIDATION_MAIN))
  d={}
  for line in text.splitlines():
   k,v=line.split('=',1)
   if k in d:raise Refused('VALIDATION_SHOW_DUPLICATE')
   d[k]=v
  if set(d)!={'Id','LoadState','ActiveState','SubState','MainPID','FragmentPath','DropInPaths','ExecStart','NeedDaemonReload'} or d['Id']!=VALIDATION_MAIN:raise Refused('VALIDATION_SHOW')
  return d
 def manager_before(self):
  if self.systemd:
   before=self.systemd.snapshot()
   if any(before[n]['LoadState']!='not-found' or before[n]['ActiveState']!='inactive' for n in systemd_adapter.OWNED):raise Refused('PHASE1_MANAGER_PRESTATE')
   return before
  before=self.test_show()
  if before['LoadState']!='not-found' or before['ActiveState']!='inactive':raise Refused('VALIDATION_PRESTATE')
  return before
 def reload(self):self.base.manager.action('daemon-reload')
 def verify_published(self,candidates):
  f=backend(self.profile)
  for p,row in candidates.items():f.verify_exact(p,row)
  self.verify_base();self.confirm_closed()
  if self.profile=='validation':
   row=self.test_show()
   if row['LoadState']!='loaded' or row['NeedDaemonReload']!='no' or row['ActiveState']!='inactive':raise Refused('VALIDATION_PUBLISHED')
 def quiesce_phase1(self):
  if self.systemd:
   for n in (systemd_adapter.units.TIMER,systemd_adapter.units.WATCH,systemd_adapter.units.WORK,systemd_adapter.units.BOOT):
    if self.systemd.show(n)['ActiveState']!='inactive':self.systemd.action('stop',n)
  else:
   before=self.test_show()
   if before['MainPID']==str(os.getpid()):raise Refused('SELF_STOP')
   if before['ActiveState']!='inactive':
    self.s.record({'operation':'validation_stop','state':'INTENT'})
    self.base.manager.call(('stop','--',VALIDATION_MAIN))
    if self.test_show()['ActiveState']!='inactive':raise Refused('VALIDATION_STOP')
    self.s.record({'operation':'validation_stop','state':'DONE'})
 def restore_manager(self,before):
  if self.systemd:self.systemd.restore(before)
  else:self.reload();self.verify_restored(before)
 def verify_restored(self,before):
  if self.systemd:return self.systemd.verify_restored(before)
  actual=self.test_show()
  # Execution history is not configuration; removal and inactive state are.
  for key in ('Id','LoadState','ActiveState','FragmentPath','DropInPaths','ExecStart','NeedDaemonReload'):
   if actual[key]!=before[key]:raise Refused('VALIDATION_RESTORE_MANAGER')
  if actual['MainPID'] not in ('0',''):raise Refused('VALIDATION_WORKER_RUNNING')
  return digest(encode(actual))
def recover_entry(profile,expected,mode):
 p=manager.profile(profile);s=Store(p['root'],validation=profile=='validation');j=Journal(s.path/'publication')
 try:
  phase=parse(s.read('phase1.json',0o600))
  if digest(encode(phase))!=expected:raise Refused('WORKER_PHASE_PIN')
  f=backend(profile);h=Phase1Host(s,profile);i=phase1.Installer(s,f,j,h)
  if mode=='recover':result=i.recover(phase)
  elif mode=='verify':
   with j.locked():result=i.verify(phase)
  else:raise Refused('MODE')
  if result!=TERMINAL:raise Refused('NONTERMINAL')
  return {'state':TERMINAL,'phase1_sha256':expected,'mode':mode}
 finally:j.close();s.close()
