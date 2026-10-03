"""Minimal retained anchor host: fixed units, file attestations, pinned worker.
No publication, Guard migration, application or recovery business logic is embedded.
Production admission remains CLOSED until the inner transaction is bound.
"""
import os,stat
from pathlib import Path
from anchor import *
import manager,worker

def trusted_file(path,mode):
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  parts=Path(path).parts[1:]
  for i,n in enumerate(parts):
   child=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_DIRECTORY if i<len(parts)-1 else 0),dir_fd=fd);os.close(fd);fd=child
   st=os.fstat(fd)
   if st.st_uid!=0 or st.st_gid!=0 or st.st_mode&0o022 or os.listxattr(fd):raise Refused('BASE_FILE_PARENT')
  metadata(fd,0,mode)
  raw=os.read(fd,LIMIT+1)
  if len(raw)>LIMIT:raise Refused('BASE_FILE_SIZE')
  return raw
 finally:os.close(fd)

class RootHost:
 def __init__(self,store,profile):
  if os.geteuid()!=0 or store.fixture:raise Refused('ROOT_HOST')
  if profile!='validation':raise Refused('PRODUCTION_INNER_TRANSACTION_NOT_BOUND')
  self.s=store;self.profile=profile;self.p=manager.profile(profile)
  if str(store.path)!=self.p['root']:raise Refused('HOST_ROOT_BINDING')
  self.transport=worker.Worker(store);self.manager=manager.Manager(profile,store.record,store.close_fence)
 def confirm_closed(self):
  if not self.s.closed():raise Refused('FENCE_OPEN')
  self.manager.verify(digest(self.s.read('base.json')),self.s.base()['interpreter'])
 def verify_base(self):
  b=self.s.base();self.s.choose();self.s.journal()
  for name,data in manager.templates(self.profile,digest(self.s.read('base.json')),b['interpreter']).items():
   if trusted_file(self.p['unitdir']+'/'+name,0o644)!=data:raise Refused('BASE_UNIT_BYTES')
  self.manager.verify(digest(self.s.read('base.json')),b['interpreter'])
  if self.manager.show('anchor')['UnitFileState']!=('enabled-runtime' if self.profile=='validation' else 'enabled'):raise Refused('BOOT_RECOVERY_NOT_ENABLED')
 def run_worker(self,selected,phase):return self.transport.invoke(selected,phase,'recover')
 def verify_rollback(self,phase):
  if self.transport.invoke(self.s.choose(),phase,'verify')!=TERMINAL:raise Refused('ROLLBACK_UNPROVEN')
 def no_worker(self):self.transport.no_worker()
 def quiesce_watchdog(self):
  row=self.manager.show('watch')
  if row['ActiveState']!='inactive':self.manager.action('stop','watch')
  if row['UnitFileState'].startswith('enabled'):self.manager.action('disable','watch')
  after=self.manager.show('watch')
  if after['ActiveState']!='inactive' or after['UnitFileState'].startswith('enabled'):raise Refused('WATCHDOG_NOT_QUIESCENT')

 def run_directional(self):
  import routing
  with self.s.locked():
   self.verify_base();self.confirm_closed();self.no_worker()
   c=routing.Chain(self.s).context();selected=self.s.choose()
  result=self.transport.invoke_directional(selected,c,'directional-recover')
  self.no_worker()
  with self.s.locked():
   self.verify_base();routing.verify(self.s,self.manager,result,trusted_file)
  return result
