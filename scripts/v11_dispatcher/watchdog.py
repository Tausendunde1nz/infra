"""Independent watchdog policy plus fixed root adapter; never releases a fence."""
import os,time
from pathlib import Path
import core,adapter,units,systemd_adapter
import state as inner_state
import runtime as inner_runtime
from recovery_route import route
STALL_NS=300_000_000_000
MAX_RESTARTS=2

def tick(host):
 try:
  binding,current,boot,now,alive=host.observe()
  action=route(binding,current,boot,now,alive)
  if action=='WAIT':return 'WAIT'
  if action=='VERIFY_FORWARD_TERMINAL':
   # No preseal restoration after the seal, even on failed verification.
   if host.forward_terminal(binding):return 'VERIFIED_FORWARD_TERMINAL'
   raise core.Refused('FORWARD_TERMINAL_UNPROVEN')
  if action=='VERIFY_PRESEAL_TERMINAL' and host.preseal_terminal(binding):return 'VERIFIED_PRESEAL_TERMINAL'
  host.close_fence()
  if action=='SECURED_STOP':return host.secured()
  tip=host.progress();old=host.read_watchdog()
  if old is None:old={'binding':binding,'boot':boot,'tip':tip,'last_progress_ns':now,'restarts':0}
  if set(old)!={'binding','boot','tip','last_progress_ns','restarts'} or old['binding']!=binding or type(old['restarts'])!=int or not 0<=old['restarts']<=MAX_RESTARTS or type(old['last_progress_ns'])!=int:raise core.Refused('WATCHDOG_STATE')
  changed=old['boot']!=boot or old['tip']!=tip
  if changed:old.update(boot=boot,tip=tip,last_progress_ns=now)
  if now<old['last_progress_ns']:raise core.Refused('MONOTONIC_REWIND')
  worker=host.worker()
  stalled=now-old['last_progress_ns']>=STALL_NS
  if stalled:
   if old['restarts']>=MAX_RESTARTS:return host.secured()
   host.stop_worker();old['restarts']+=1;old['last_progress_ns']=now
  host.write_watchdog(old)
  if stalled or worker in ('inactive','failed'):host.dispatch();return 'DISPATCHED'
  if worker not in ('active','activating','deactivating'):raise core.Refused('WORKER_STATE')
  return 'WORKER_RUNNING'
 except Exception:return host.secured()

class RootHost:
 def __init__(self,pin,binding):
  if os.geteuid()!=0:raise core.Refused('ROOT_WATCHDOG')
  self.store=core.Durable();self.pin=pin;self.binding=binding;self.inner=None
  self.manager=systemd_adapter.Systemd(self.record,self.close_fence)
 def close(self):
  if self.inner:self.inner.close()
  self.store.close()
 def record(self,event):
  names=sorted(n for n in os.listdir(self.store.fd) if n.startswith('watch-'))
  if len(names)>=8192:raise core.Refused('WATCH_EVENT_LIMIT')
  previous='0'*64
  for i,n in enumerate(names):
   row=self.store.read(n)
   if n!='watch-%06d.json'%i or set(row)!={'binding','seq','previous','event'} or row['binding']!=self.binding or row['seq']!=i or row['previous']!=previous:raise core.Refused('WATCH_EVENT_CHAIN')
   previous=core.sha(core.raw(row))
  self.store.put('watch-%06d.json'%len(names),{'binding':self.binding,'seq':len(names),'previous':previous,'event':event})
 def observe(self):
  if self.store.read('binding.json')!=self.binding:raise core.Refused('WATCHDOG_BINDING')
  if 'stop.json' in os.listdir(self.store.fd):raise core.Refused('STOP_LATCH')
  self.inner=inner_state.Store();current=self.inner.current()
  return self.binding,current,Path('/proc/sys/kernel/random/boot_id').read_text().strip(),time.monotonic_ns(),inner_runtime.alive(current['binding'])
 def close_fence(self):
  self.store.put('gate.json',{'state':'CLOSED'},True)
  adapter.Host(self.pin).verify_closed(self.store)
 def secured(self):
  # Persistent STOP overrides any concurrent release; failed reads never grant
  # permission. Do not touch application services to diagnose a broken manager.
  try:self.store.put('gate.json',{'state':'CLOSED'},True)
  finally:
   if 'stop.json' not in os.listdir(self.store.fd):self.store.put('stop.json',{'state':'SECURED_STOP'})
  try:
   if self.manager.show(units.WORK)['ActiveState'] not in ('inactive','failed'):
    self.record({'operation':'stop','unit':units.WORK,'stage':'INTENT'})
    self.manager._run(('stop','--no-block','--',units.WORK))
    self.record({'operation':'stop','unit':units.WORK,'stage':'QUEUED'})
  except Exception:pass  # STOP remains dominant even if D-Bus is unavailable.
  return 'SECURED_STOP'
 def progress(self):
  try:return self.store.journal()[2]
  except core.Refused:
   names=sorted(n for n in os.listdir(self.store.fd) if n.startswith('step-'))
   if names and os.stat(names[-1],dir_fd=self.store.fd,follow_symlinks=False).st_nlink==2:
    # An immutable record is between link and unlink. Never use it as proof.
    old=self.read_watchdog();return old['tip'] if old else '0'*64
   raise
 def read_watchdog(self):
  try:return self.store.read('watchdog.json',0o600)
  except FileNotFoundError:return None
 def write_watchdog(self,value):self.store.put('watchdog.json',value,True)
 def worker(self):return self.manager.show(units.WORK)['ActiveState']
 def stop_worker(self):self.manager.action('stop',units.WORK)
 def dispatch(self):self.manager.dispatch()
 def preseal_terminal(self,binding):return core.permit(self.store,adapter.Host(self.pin))
 def forward_terminal(self,binding):
  contract=inner_runtime.contract(binding['contract_sha256'])
  return inner_runtime.condition(self.inner,contract,binding['contract_sha256'])
