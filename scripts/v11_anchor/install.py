"""Concrete phase-0 file/systemd installation; no phase-1 mutation allowed."""
import os
from pathlib import Path
from anchor import Refused,encode,digest,parse
from files import Files
from publication import Journal
import manager

def file_backend(profile_name,prefix='/',fixture=False,save=None):
 p=manager.profile(profile_name);paths=tuple(p['unitdir']+'/'+n for n in manager.templates(profile_name,'0'*64,'/usr/bin/python3.12'))
 class Phase0Files(Files):
  targets=paths
  directories={p['unitdir']+'/'+p['consumer']+'.d':(0,0,0o755)}
 return Phase0Files(prefix,fixture=fixture,save=save)
class Install:
 def __init__(self,store,journal,files,systemd,profile_name):
  self.s=store;self.j=journal;self.f=files;self.m=systemd;self.profile=profile_name;self.state=None;self.f.save=self.receipt
  p=manager.profile(profile_name)
  if set(files.targets)!={p['unitdir']+'/'+n for n in manager.templates(profile_name,'0'*64,'/usr/bin/python3.12')}:raise Refused('PHASE0_FILE_SCOPE')
 def receipt(self,value):self.state['files']=value;self.j.save(self.state)
 def verify(self):
  base=self.s.base();self.s.choose();p=manager.profile(self.profile);pin=digest(self.s.read('base.json'));payload=manager.templates(self.profile,pin,base['interpreter'])
  for name,data in payload.items():self.f.verify_exact(p['unitdir']+'/'+name,{'bytes':data,'sha256':digest(data),'uid':0,'gid':0,'mode':0o644})
  self.m.verify(pin,base['interpreter'])
  if not self.s.closed():raise Refused('FENCE_NOT_CLOSED')
  return True
 def run(self):
  with self.s.locked(),self.j.locked():
   self.s.base();self.s.choose();self.s.close_fence();self.state,_,_=self.j.load()
   if self.state is not None:
    if self.state.get('base_sha256')!=digest(self.s.read('base.json')):raise Refused('PHASE0_JOURNAL_BINDING')
    self.f.receipts=self.state['files']['receipts'];self.f.created=self.state['files']['created_directories']
    if self.state['status']=='PHASE0_VERIFIED':self.verify();return 'PHASE0_VERIFIED'
    # Resume the same exact publication receipts, never adopt foreign files.
   else:
    before=self.f.snapshot(self.f.targets,self.f.directories)
    if any(row!={'absent':True} for row in before.values()):raise Refused('PREEXISTING_PHASE0_ARTIFACT')
    observed={r:self.m.show(r) for r in ('anchor','watch','consumer')}
    if any(observed[r]['LoadState']!='not-found' or observed[r]['ActiveState']!='inactive' for r in ('anchor','watch')) or observed['consumer']['ActiveState']!='inactive':raise Refused('PHASE0_MANAGER_PRESTATE')
    self.state={'base_sha256':digest(self.s.read('base.json')),'status':'PHASE0_INSTALLING','before':before,'manager_before':observed,'files':{'receipts':{},'created_directories':[]}}
    self.j.save(self.state)
   self.f.create_declared_directories(self.f.directories)
   base=self.s.base();p=manager.profile(self.profile);payload=manager.templates(self.profile,digest(self.s.read('base.json')),base['interpreter'])
   for name,data in payload.items():self.f.install_exact(p['unitdir']+'/'+name,{'bytes':data,'sha256':digest(data),'uid':0,'gid':0,'mode':0o644},self.state['before'])
   self.m.action('daemon-reload');self.verify();self.m.action('enable','anchor')
   # Anchor has no phase-1 manifest yet, so a successful boot-style invocation
   # closes/verifies the fence and returns without starting a migration worker.
   # Do not start while holding its recovery lock. A separate verify_start()
   # performs that handshake after this context releases the lock.
   self.state['status']='PHASE0_PUBLISHED';self.j.save(self.state);return 'PHASE0_PUBLISHED'
 def verify_start(self):
  self.m.action('start','anchor')
  with self.s.locked(),self.j.locked():
   self.verify();self.state,_,_=self.j.load()
   if self.state['status'] not in ('PHASE0_PUBLISHED','PHASE0_VERIFIED'):raise Refused('PHASE0_ORDER')
   self.state['status']='PHASE0_VERIFIED';self.j.save(self.state)
   self.s.write('phase0.json',encode({'state':'PHASE0_VERIFIED','base_sha256':digest(self.s.read('base.json'))}),0o600,True)
   return 'PHASE0_VERIFIED'
