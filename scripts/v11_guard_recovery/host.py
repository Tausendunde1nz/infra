"""Concrete fixed Guard host. Constructed only from a verified root capsule."""
import base64,subprocess
from runtime import *
from files import Files,TARGETS,DIRECTORIES
SYSTEMCTL=('/usr/bin/systemctl',)
ACTIONS={n:SYSTEMCTL+args for n,args in {
'reload':('daemon-reload',),
'stop_watchdog':('stop','--',WATCHDOG),
'stop_recovery':('stop','--',RECOVERY),
'disable_watchdog':('disable','--',WATCHDOG),
'disable_recovery':('disable','--',RECOVERY),
'enable_recovery':('enable','--',RECOVERY),
'start_recovery':('start','--job-mode=fail','--',RECOVERY),
'enable_watchdog':('enable','--',WATCHDOG),
'start_watchdog':('start','--job-mode=fail','--',WATCHDOG),
'start_guard':('start','--job-mode=fail','--',GUARD),
'stop_timer':('stop','--job-mode=fail','--',TIMER),
'start_timer':('start','--job-mode=fail','--',TIMER),
'show_watchdog':('show','--property=MainPID,ActiveState,UnitFileState,ExecStart','--',WATCHDOG),
'show_recovery':('show','--property=ActiveState,UnitFileState,Result,ExecStart','--',RECOVERY),
'show_execution':('show','--property=ExecMainStartTimestampMonotonic,ExecCondition,ActiveState,MainPID,Job','--',GUARD)}.items()}
def execute(argv):
 if tuple(argv) in COMMANDS:return command(argv)
 if os.geteuid()!=0 or tuple(argv) not in ACTIONS.values():raise Refused('FIXED_HOST_ACTION')
 p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,cwd='/',timeout=180)
 if p.returncode or len(p.stdout)>32768:raise Refused('SYSTEMD_ACTION')
 return p.stdout.decode()

class Host:
 def __init__(self,store,bundle,original_pins,run=execute):
  if os.geteuid()!=0:raise Refused('ROOT_HOST_ONLY')
  self.store=store;self.bundle=bundle;self.pin=bundle['contract_sha256'];self.c=bundle['contract'];self.run=run;self.original_pins=original_pins;self.counter=0
  self.files=Files(save=self.save_receipts)
  if store.current()['binding']['contract_sha256']!=self.pin or digest(encode(self.c))!=self.pin:raise Refused('BUNDLE_PIN')
 def evidence(self,name,value):
  if name not in ('originals.json','receipt-%06d.json'%self.counter):raise Refused('EVIDENCE_NAME')
  # Immutable generation, fsync, no overwrite. A root capsule owns the directory.
  raw=encode(value);tmp='.evidence-'+uuid.uuid4().hex
  fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.store.fd)
  try:
   with os.fdopen(fd,'wb',closefd=False) as f:os.fchmod(fd,0o600);f.write(raw);f.flush();os.fsync(fd)
   os.link(tmp,name,src_dir_fd=self.store.fd,dst_dir_fd=self.store.fd,follow_symlinks=False);os.unlink(tmp,dir_fd=self.store.fd);os.fsync(self.store.fd)
  finally:
   os.close(fd)
   try:os.unlink(tmp,dir_fd=self.store.fd)
   except FileNotFoundError:pass
 def save_receipts(self,value):self.evidence('receipt-%06d.json'%self.counter,value);self.counter+=1
 def preflight(self):
  if set(self.bundle['payloads'])!=set(TARGETS):raise Refused('PAYLOAD_SET')
  for path,row in self.bundle['payloads'].items():
   if digest(row['bytes'])!=row['sha256'] or row['uid']!=0 or row['gid']!=0:raise Refused('PAYLOAD')
  for wants,unit in (('sysinit.target.wants',RECOVERY),('multi-user.target.wants',WATCHDOG)):
   link=Path('/etc/systemd/system')/wants/unit
   if link.exists() or link.is_symlink():raise Refused('PREEXISTING_ENABLEMENT')
  self.before=self.files.snapshot(TARGETS,DIRECTORIES)
  if set(self.original_pins)!=set(TARGETS):raise Refused('ORIGINAL_SET')
  for path,pin in self.original_pins.items():
   if any(self.before[path].get(k)!=v for k,v in pin.items()):raise Refused('ORIGINAL_DRIFT')
  if self.store.current()['phase']!='LEGACY_ALLOWED_PRETRANSACTION':raise Refused('NOT_FRESH')
  if properties(self.run(SHOW_GUARD))['ActiveState']!='inactive':raise Refused('GUARD_RUNNING')
  timer=properties(self.run(SHOW_TIMER))
  if timer['ActiveState']!='active' or timer['UnitFileState']!='enabled':raise Refused('TIMER_DRIFT')
  return True
 def backup(self):self.evidence('originals.json',self.before);return True
 def install(self,path):self.files.install_exact(path,self.bundle['payloads'][path],self.before);self.files.verify_exact(path,self.bundle['payloads'][path])
 def install_fence_recovery(self):
  self.files.create_declared_directories(DIRECTORIES)
  for p in (PROGRAM,CONTRACT,'/etc/systemd/system/'+RECOVERY,'/etc/systemd/system/'+WATCHDOG,FENCE,TIMER_DEP):self.install(p)
 def reload_fence(self):self.run(ACTIONS['reload'])
 def verify_fence_loaded(self):verify_files(self.c,self.pin,False);loaded(self.pin,False,self.run)
 def enable_recovery(self):self.run(ACTIONS['enable_recovery'])
 def start_recovery(self):self.run(ACTIONS['start_recovery'])
 def enable_watchdog(self):self.run(ACTIONS['enable_watchdog'])
 def start_watchdog(self):self.run(ACTIONS['start_watchdog'])
 def verify_watchdog(self):
  r=properties(self.run(ACTIONS['show_recovery']));w=properties(self.run(ACTIONS['show_watchdog']))
  if r['ActiveState']!='active' or r['UnitFileState']!='enabled' or r['Result']!='success' or w['ActiveState']!='active' or w['UnitFileState']!='enabled' or not w['MainPID'].isdigit() or int(w['MainPID'])<=0:raise Refused('RECOVERY_NOT_READY')
  for row,mode in ((r,'recover'),(w,'watchdog')):
   if re.findall(r'argv\[\]=(.*?) ;',row['ExecStart'])!=['/usr/bin/python3 -I -B '+PROGRAM+' '+mode+' '+self.pin]:raise Refused('RECOVERY_EXEC')
  # Independent process identity is required; never accept coordinator PID.
  if int(w['MainPID'])==self.store.current()['binding']['coordinator_pid']:raise Refused('NOT_INDEPENDENT')
  end=time.monotonic()+10
  while True:
   try:
    h=strict(bound_read(ROOT+'/watchdog-heartbeat.json',0o600,limit=4096))
    b=self.store.current()['binding']
    if set(h)!={'transaction','contract_sha256','boot','pid','start_ticks','monotonic_ns'} or h['transaction']!=b['transaction'] or h['contract_sha256']!=self.pin or h['boot']!=b['boot'] or h['pid']!=int(w['MainPID']) or not 0<=time.monotonic_ns()-h['monotonic_ns']<=5_000_000_000 or not alive({'coordinator_pid':h['pid'],'coordinator_start_ticks':h['start_ticks']}):raise Refused('WATCHDOG_HEARTBEAT')
    break
   except (OSError,Refused):
    if time.monotonic()>=end:raise Refused('WATCHDOG_NO_HANDSHAKE')
    time.sleep(.1)
  self.verify_fence_loaded()
 def quiesce_prearm(self):
  # UNARMED already denies starts. Drain a start admitted before UNARMED;
  # never kill an old invocation or seal while one is still running.
  end=time.monotonic()+150
  while time.monotonic()<end:
   s=properties(self.run(ACTIONS['show_execution']))
   if s['ActiveState']=='inactive' and s['MainPID']=='0' and s['Job'] in ('','0'):return True
   time.sleep(.1)
  raise Refused('LEGACY_START_STILL_PENDING')
 def blocked_start(self):
  self.verify_watchdog()
  before=properties(self.run(ACTIONS['show_execution']))
  if before['ActiveState']!='inactive':raise Refused('GUARD_ALREADY_RUNNING')
  self.run(ACTIONS['start_guard'])
  after=properties(self.run(ACTIONS['show_execution']))
  if after['ActiveState']!='inactive' or after['ExecMainStartTimestampMonotonic']!=before['ExecMainStartTimestampMonotonic'] or not re.search(r'status=1(?:/| ;)',after['ExecCondition']):raise Refused('FENCE_NOT_EXECUTED_OR_NOT_BLOCKED')
  return True
 def stop_timer(self):
  self.run(ACTIONS['stop_timer'])
  if properties(self.run(SHOW_TIMER))['ActiveState']!='inactive':raise Refused('TIMER_NOT_STOPPED')
 def install_guard(self):self.install(NEW)
 def install_authority(self):self.install(AUTH)
 def install_consumer(self):self.install(CONSUMER)
 def install_checksum(self):self.install(CHECKSUM)
 def reload_consumer(self):self.run(ACTIONS['reload'])
 def verify_new_loaded(self):verify_files(self.c,self.pin,True);loaded(self.pin,True,self.run)
 def probe_new(self):self.verify_new_loaded();self.run(NEW_PROBE)
 def verify_result(self):
  self.run(STATUS_PROBE)
  fd=secure_open(STATUS,False,0,0o640)
  try:
   s=os.fstat(fd)
   if s.st_gid!=1001:raise Refused('STATUS_GROUP')
   raw=os.read(fd,16385)
  finally:os.close(fd)
  x=strict(raw);now=time.monotonic_ns()
  if len(raw)>16384 or x['passed'] is not True or x['authority_sha256']!=self.c['new_authority_sha256'] or x['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip() or not 0<=now-x['monotonic_ns']<=150_000_000_000:raise Refused('RESULT')
  return {'consumer_sha256':self.c['files'][NEW]['sha256'],'authority_sha256':self.c['new_authority_sha256'],'loaded_unit_sha256':digest(self.c['unit_templates'][CONSUMER].replace('@CONTRACT_SHA@',self.pin).encode()),'result_sha256':digest(raw)}
 def start_timer(self):
  if not condition(self.store,self.c,self.pin,self.run):raise Refused('FENCE_NEW_NOT_PERMITTED')
  self.run(ACTIONS['start_timer'])
 def final_verify(self):
  end=time.monotonic()+150
  while properties(self.run(SHOW_GUARD))['ActiveState']!='inactive':
   if time.monotonic()>=end:raise Refused('NEW_GUARD_NOT_SETTLED')
   time.sleep(.1)
  self.verify_new_loaded();self.verify_result()
  t=properties(self.run(SHOW_TIMER))
  if t['ActiveState']!='active' or t['UnitFileState']!='enabled' or not condition(self.store,self.c,self.pin,self.run):raise Refused('FINAL_VERIFY')
  return True
 def rollback_preseal(self):
  s=self.store.current()
  if s['sealed']:raise Refused('ROLLBACK_AFTER_SEAL')
  # Validate every original/postimage first, before removing any protective unit.
  for path,original in self.before.items():
   actual=self.files.snapshot_one(path)
   receipt=self.files.receipts.get(path)
   expected=receipt.get('after') if receipt else original
   if actual!=expected:raise Refused('FOREIGN_WRITER_DURING_ROLLBACK')
  if self.files.receipts:
   self.stop_timer()
   if properties(self.run(SHOW_GUARD))['ActiveState']!='inactive':raise Refused('GUARD_RUNNING_DURING_ROLLBACK')
  return {'originals_identical':True,'no_foreign_writer':True,'timer_original_verified':True}
 def finish_rollback(self):
  s=self.store.current()
  if s['sealed'] or s['phase']!='ROLLED_BACK_PRESEAL':raise Refused('ROLLBACK_STATE')
  # Only this transaction's originally absent support units may be disabled.
  for key,unit,wants in (('watchdog',WATCHDOG,'multi-user.target.wants'),('recovery',RECOVERY,'sysinit.target.wants')):
   path='/etc/systemd/system/'+unit
   if path in self.files.receipts:
    self.files.verify_exact(path,self.bundle['payloads'][path])
    self.run(ACTIONS['stop_'+key])
    link=Path('/etc/systemd/system')/wants/unit
    if link.is_symlink():
     if link.lstat().st_uid!=0 or os.path.realpath(link)!=path:raise Refused('FOREIGN_ENABLEMENT')
     self.run(ACTIONS['disable_'+key])
    elif link.exists():raise Refused('ENABLEMENT_TYPE')
  self.files.restore_owned_changes(self.before)
  if not self.files.same_restored_snapshot(self.before):raise Refused('RESTORE_BYTES_METADATA')
  self.run(ACTIONS['reload'])
  self.run(ACTIONS['start_timer'])
  t=properties(self.run(SHOW_TIMER))
  if t['ActiveState']!='active' or t['UnitFileState']!='enabled':raise Refused('ORIGINAL_TIMER_STATE')
  return 'ROLLED_BACK_PRESEAL'
