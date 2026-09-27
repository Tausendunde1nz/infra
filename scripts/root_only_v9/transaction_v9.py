"""Durable phase orchestration; host operations supplied by the pinned adapter.

No action on import. No countdown starts until an explicitly authorized installer
invokes execute. Security sealing precedes revocation, making recovery fail-closed.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time
from policy_v9 import PHASES,SEAL_PHASE,Refused,rollback_policy


def encoded(data):return json.dumps(data,sort_keys=True,separators=(',',':')).encode()

class Store:
 def __init__(self,path,fixture=False):
  self.path=Path(path);self.fixture=fixture
  if fixture and os.geteuid()==0:raise Refused('root fixture forbidden')
  if not fixture and os.geteuid()!=0:raise Refused('root store required')
  targets=[self.path] if fixture else list(reversed(self.path.parents))+[self.path]
  for p in targets:
   s=p.lstat()
   if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o022:raise Refused('store ancestry')
   if hasattr(os,'listxattr') and any('posix_acl' in x for x in os.listxattr(p)):raise Refused('store ACL')
  if stat.S_IMODE(self.path.stat().st_mode)!=0o700:raise Refused('store mode')
  self.dirfd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  self.lock=os.open('lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self.dirfd)
  try:self.validate(os.fstat(self.lock));fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BaseException:os.close(self.lock);os.close(self.dirfd);raise
 def validate(self,s):
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise Refused('checkpoint identity')
 def read(self):
  try:fd=os.open('state.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.dirfd)
  except FileNotFoundError:return None
  with os.fdopen(fd,'rb') as f:self.validate(os.fstat(f.fileno()));raw=f.read(8_000_001)
  if len(raw)>8_000_000:raise Refused('checkpoint size')
  e=json.loads(raw)
  if hashlib.sha256(encoded(e['data'])).hexdigest()!=e['sha256']:raise Refused('checkpoint digest')
  return e['data']
 def write(self,value):
  # Check target before atomic replacement, including an adversarial link.
  self.read()
  data=encoded({'data':value,'sha256':hashlib.sha256(encoded(value)).hexdigest()})
  if len(data)>8_000_000:raise Refused('checkpoint size')
  name='.pending-'+secrets.token_hex(12)
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.dirfd)
  try:
   with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
   os.replace(name,'state.json',src_dir_fd=self.dirfd,dst_dir_fd=self.dirfd);os.fsync(self.dirfd)
   if not self.fixture:
    from public_v9 import publish
    publish(value)
  finally:
   try:os.unlink(name,dir_fd=self.dirfd)
   except FileNotFoundError:pass
 def close(self):os.close(self.lock);os.close(self.dirfd)

class Transaction:
 def __init__(self,store,adapter,clock=time.monotonic_ns):self.store=store;self.adapter=adapter;self.clock=clock
 def begin(self,boot_id,budget_seconds=2700,capsule_sha256=None):
  if self.store.read() is not None:raise Refused('transaction exists')
  if not 1800<=budget_seconds<=7200:raise Refused('watchdog budget')
  self.store.write({'capsule_sha256':capsule_sha256,'version':9,'status':'PREPARED','boot_id':boot_id,'deadline_ns':self.clock()+budget_seconds*1_000_000_000,'sealed':False,'steps':[]})
 def step(self,phase):
  state=self.store.read()
  if state is None or state['status'] not in ('PREPARED','CHECKPOINT'):raise Refused('state not executable')
  if len(state['steps'])>=len(PHASES) or PHASES[len(state['steps'])]!=phase:raise Refused('phase order')
  if self.clock()>=state['deadline_ns']:raise Refused('deadline expired')
  before=self.adapter.snapshot(phase)
  if self.adapter.preflight(phase,before) is not True:raise Refused('phase precondition')
  if phase==SEAL_PHASE:state['sealed']=True
  state['steps'].append({'phase':phase,'status':'INTENT','before':before,'started_ns':self.clock()});state['status']='INTENT';self.store.write(state)
  try:
   self.adapter.apply(phase,state)
   after=self.adapter.snapshot(phase)
   if self.adapter.verify(phase,before,after,state) is not True:raise Refused('phase verification')
   state['steps'][-1].update(status='DONE',after=after,finished_ns=self.clock());state['status']='CHECKPOINT';self.store.write(state)
  except BaseException:
   self.rollback();raise
 def rollback(self):
  state=self.store.read()
  if state is None:raise Refused('no transaction')
  if state['status']=='COMPLETE':raise Refused('completed transaction cannot auto-rollback')
  policy=rollback_policy(state['sealed'],[x['phase'] for x in state['steps']])
  state['status']='ROLLBACK_INTENT';self.store.write(state)
  try:
   for step in reversed(state['steps']):
    if step['status'] in ('RESTORED','SECURED'):continue
    self.adapter.restore(step['phase'],step['before'],policy)
    if self.adapter.verify_restore(step['phase'],step['before'],policy) is not True:raise Refused('rollback verification')
    step['status']='SECURED' if state['sealed'] else 'RESTORED';self.store.write(state)
   state['status']='SECURED_STOP' if state['sealed'] else 'ROLLED_BACK';self.store.write(state)
  except BaseException:
   state['status']='ROLLBACK_FAILED';self.store.write(state);raise
 def finish(self):
  state=self.store.read()
  if state['status']!='CHECKPOINT' or [x['phase'] for x in state['steps']]!=list(PHASES) or any(x['status']!='DONE' for x in state['steps']):raise Refused('incomplete transaction')
  if self.adapter.final_verify(state) is not True:raise Refused('final verification')
  if self.clock()>=state['deadline_ns']-30_000_000_000:raise Refused('finalization deadline margin')
  state['watchdog_disabled']=False
  state['status']='COMPLETE';state['completed_ns']=self.clock();self.store.write(state)
  self.adapter.disable_watchdog()
  state['watchdog_disabled']=True;self.store.write(state)


def watchdog_due(state,boot_id,now_ns):
 if state is None or state['status'] in ('COMPLETE','ROLLED_BACK','SECURED_STOP'):return False
 return state['boot_id']!=boot_id or now_ns>=state['deadline_ns']
