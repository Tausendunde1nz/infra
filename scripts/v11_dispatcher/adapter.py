"""Fixed root adapter; inner recovery artifacts may be removed, outer stays.
No user commands, no source imports from the author checkout when bundled.
"""
import os,json,base64,re,subprocess,time,hashlib
from pathlib import Path
import core
import runtime as g
import state as old
from files import Files,TARGETS,DIRECTORIES
BOOT='tu1nz-v11-dispatcher-boot.service'
WORK='tu1nz-v11-dispatcher.service'
WATCH='tu1nz-v11-dispatcher-watch.timer'
FENCE='/etc/systemd/system/'+g.GUARD+'.d/99-v11-dispatcher.conf'
TIMER='/etc/systemd/system/'+g.TIMER+'.d/99-v11-dispatcher.conf'
PROPERTIES='LoadState,UnitFileState,FragmentPath,ExecStart,ExecCondition,DropInPaths,Requires,After,ActiveState,MainPID'
SHOW=('/usr/bin/systemctl','show','--property='+PROPERTIES,'--',g.GUARD,g.TIMER)
COMMANDS={('daemon-reload',),('stop','--',g.TIMER),('start','--job-mode=fail','--',g.TIMER)}
for unit in (g.RECOVERY,g.WATCHDOG):COMMANDS.add(('disable','--',unit));COMMANDS.add(('stop','--',unit))
def run(args):
 if os.geteuid()!=0 or tuple(args) not in COMMANDS:raise core.Refused('COMMAND_SCOPE')
 r=subprocess.run(('/usr/bin/systemctl',)+tuple(args),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=g.ENV,cwd='/',timeout=180)
 if r.returncode or len(r.stdout)>65536:raise core.Refused('SYSTEMD_ACTION')
def show():
 r=subprocess.run(SHOW,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=g.ENV,cwd='/',timeout=30)
 if r.returncode or len(r.stdout)>65536:raise core.Refused('MANAGER_READ')
 rows=[g.properties(x) for x in r.stdout.decode().strip().split('\n\n')]
 if len(rows)!=2:raise core.Refused('MANAGER_ROWS')
 return rows
class Host:
 def __init__(self,pin):
  if os.geteuid()!=0 or not re.fullmatch('[a-f0-9]{64}',pin):raise core.Refused('ROOT_ONLY')
  self.pin=pin;self.files=Files(save=self.save);self.binding=None
 def verify_closed(self,store):
  if store.read('gate.json',0o600)!={'state':'CLOSED'}:raise core.Refused('GATE_NOT_CLOSED')
  a,b=show();expected='/usr/bin/python3 -I -B '+core.PACKAGE+'/dispatcher.py condition '+self.pin
  if a['LoadState']!='loaded' or b['LoadState']!='loaded' or FENCE not in a['DropInPaths'].split() or TIMER not in b['DropInPaths'].split():raise core.Refused('OUTER_FENCE_NOT_LOADED')
  if re.findall(r'argv\[\]=(.*?) ;',a['ExecCondition'])[-1:]!=[expected]:raise core.Refused('OUTER_EXEC_CONDITION')
  if any(BOOT not in r['Requires'].split() or BOOT not in r['After'].split() for r in (a,b)):raise core.Refused('BOOT_ORDER')
  for path in (FENCE,TIMER):g.bound_read(path,0o644)
 def validate_binding(self,binding):
  self.binding=binding;self.inner=old.Store();current=self.inner.current()
  if current['sealed']:raise core.Refused('POSTSEAL_NOT_ROLLBACK')
  expected={'transaction':current['binding']['transaction'],'origin_boot':current['binding']['boot'],'contract_sha256':current['binding']['contract_sha256']}
  if binding!=expected:raise core.Refused('INNER_BINDING')
  self.before=old.strict(g.bound_read(g.ROOT+'/originals.json',0o600,limit=64000000))
  bundle=old.strict(g.bound_read(g.ROOT+'/rollback-bundle.json',0o600,limit=64000000))
  if set(self.before)!=set(TARGETS) or bundle['contract_sha256']!=binding['contract_sha256'] or old.digest(old.encode(bundle['contract']))!=binding['contract_sha256']:raise core.Refused('ORIGINAL_BINDING')
  self.contract=bundle['contract'];self.counter=0;self.previous='0'*64
  names=sorted(n for n in os.listdir(self.inner.fd) if n.startswith('receipt-'))
  if len(names)>4096:raise core.Refused('RECEIPT_SIZE')
  for i,n in enumerate(names):
   if n!='receipt-%06d.json'%i:raise core.Refused('RECEIPT_GAP')
   r=old.strict(g.bound_read(g.ROOT+'/'+n,0o600,limit=64000000))
   if set(r)!={'seq','binding','previous','payload'} or r['seq']!=i or r['binding']!=current['binding'] or r['previous']!=self.previous:raise core.Refused('RECEIPT_CHAIN')
   payload=r['payload']
   if set(payload)!={'receipts','created_directories'} or not set(payload['receipts'])<=set(TARGETS) or any(x['path'] not in DIRECTORIES for x in payload['created_directories']):raise core.Refused('RECEIPT_SCOPE')
   self.files.receipts=payload['receipts'];self.files.created=payload['created_directories'];self.previous=old.digest(old.encode(r));self.counter+=1
  self.old_binding=current['binding']
 def save(self,payload):
  r={'seq':self.counter,'binding':self.old_binding,'previous':self.previous,'payload':payload};data=old.encode(r);name='receipt-%06d.json'%self.counter
  tmp='.outer-'+os.urandom(16).hex();f=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.inner.fd)
  try:
   with os.fdopen(f,'wb',closefd=False) as out:os.fchmod(f,0o600);out.write(data);out.flush();os.fsync(f)
   os.link(tmp,name,src_dir_fd=self.inner.fd,dst_dir_fd=self.inner.fd,follow_symlinks=False);os.unlink(tmp,dir_fd=self.inner.fd);os.fsync(self.inner.fd)
  finally:os.close(f)
  self.previous=old.digest(data);self.counter+=1
 def quiesce(self):
  run(('stop','--',g.TIMER));run(('stop','--',g.WATCHDOG));run(('stop','--',g.RECOVERY));deadline=time.monotonic()+150
  while True:
   a,b=show()
   if b['ActiveState']=='inactive' and a['ActiveState']=='inactive' and a['MainPID']=='0':return
   if time.monotonic()>=deadline:raise core.Refused('NOT_QUIESCENT')
   time.sleep(.1)
 def restored(self,terminal=False):
  if not self.files.same_restored_snapshot(self.before):raise core.Refused('ORIGINALS_NOT_RESTORED')
  a,b=show()
  if a['LoadState']!='loaded' or b['LoadState']!='loaded' or a['UnitFileState']=='masked' or b['UnitFileState']!='enabled' or re.findall(r'argv\[\]=(.*?) ;',a['ExecStart'])!=[g.LEGACY] or a['DropInPaths']!=FENCE or b['DropInPaths']!=TIMER:raise core.Refused('RESTORED_MANAGER')
  if not terminal and (a['ActiveState']!='inactive' or a['MainPID']!='0'):raise core.Refused('CONSUMER_RUNNING')
  g.bound_read(g.LEGACY,self.contract['files'][g.LEGACY]['mode'],self.contract['files'][g.LEGACY]['sha256'])
 def step(self,step,binding):
  if binding!=self.binding or step not in core.STEPS:raise core.Refused('STEP_BINDING')
  if step=='QUIESCE':self.quiesce()
  elif step=='VALIDATE':
   # Files restore validates exact postimage identity before each mutation.
   for p in TARGETS:self.files.snapshot_one(p)
  elif step=='RESTORE':self.files.restore_owned_changes(self.before,cleanup=False)
  elif step=='RELOAD':run(('daemon-reload',))
  elif step=='VERIFY':self.restored()
  elif step=='CLEANUP':
   # Outer code/unit/state paths are NOT members of this cleanup set.
   for unit,wants in ((g.RECOVERY,'sysinit.target.wants'),(g.WATCHDOG,'multi-user.target.wants')):
    link=Path('/etc/systemd/system')/wants/unit
    if link.is_symlink():
     if link.lstat().st_uid!=0 or os.path.realpath(link)!='/etc/systemd/system/'+unit:raise core.Refused('FOREIGN_ENABLEMENT')
     run(('disable','--',unit))
    elif link.exists():raise core.Refused('ENABLEMENT_TYPE')
   self.files.restore_owned_changes(self.before);run(('daemon-reload',))
  elif step in ('VERIFY_CLEANUP','VERIFY_FINAL','ROLLED_BACK'):self.restored()
  elif step=='TIMER_INHIBITED':run(('start','--job-mode=fail','--',g.TIMER))
  return core.sha(core.raw({'step':step,'binding':binding}))
 def verify_terminal(self,binding):
  if self.binding is None:self.validate_binding(binding)
  if self.binding!=binding:raise core.Refused('TERMINAL_BINDING')
  self.restored(terminal=True);a,b=show()
  if b['ActiveState']!='active':raise core.Refused('TIMER_NOT_RESTORED')
  return core.sha(core.raw({p:self.files.snapshot_one(p) for p in TARGETS}))
