"""Fixed root condition/recovery/watchdog. Embedded with state.py for installation.
No production checkout imports. No baseline regeneration. No dynamic commands.
"""
import subprocess,sys,signal
from state import *
PACKAGE='/usr/local/libexec/tu1nz-v11-guard-recovery'
PROGRAM=PACKAGE+'/runtime.py'
CONTRACT=ROOT+'/contract.json'
GUARD='tu1nz_delete_guard.service'
TIMER='tu1nz_delete_guard.timer'
RECOVERY='tu1nz-v11-guard-recovery.service'
WATCHDOG='tu1nz-v11-guard-watchdog.service'
LEGACY='/usr/local/bin/tu1nz_delete_guard.sh'
NEW='/usr/local/libexec/tu1nz-docs-authority-v11/guard.py'
AUTH='/etc/tu1nz/docs-authority-v11/authority.json'
FENCE='/etc/systemd/system/'+GUARD+'.d/80-v11-start-fence.conf'
CONSUMER='/etc/systemd/system/'+GUARD+'.d/90-v11-authority.conf'
TIMER_DEP='/etc/systemd/system/'+TIMER+'.d/80-v11-recovery.conf'
STATUS='/var/lib/tu1nz-docs-authority-v11/status.json'
CHECKSUM='/usr/local/bin/checksum_verify'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/var/empty'}
ALLOWED_PATHS={PROGRAM,LEGACY,NEW,AUTH,FENCE,CONSUMER,TIMER_DEP,CHECKSUM,'/etc/systemd/system/'+RECOVERY,'/etc/systemd/system/'+WATCHDOG}
SHOW_GUARD=('/usr/bin/systemctl','show','--property=ExecStart,ExecCondition,DropInPaths,Requires,After,ActiveState','--',GUARD)
SHOW_TIMER=('/usr/bin/systemctl','show','--property=Requires,After,DropInPaths,ActiveState,UnitFileState','--',TIMER)
STOP_TIMER=('/usr/bin/systemctl','stop','--no-block','--',TIMER)
START_TIMER=('/usr/bin/systemctl','start','--no-block','--',TIMER)
NEW_PROBE=('/usr/bin/python3','-I','-B',NEW)
STATUS_PROBE=('/usr/bin/python3','-I','-B',CHECKSUM)
COMMANDS=(SHOW_GUARD,SHOW_TIMER,STOP_TIMER,START_TIMER,NEW_PROBE,STATUS_PROBE)

def command(argv):
 if os.geteuid()!=0 or tuple(argv) not in COMMANDS:raise Refused('COMMAND_SCOPE')
 r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,cwd='/',timeout=150)
 if r.returncode or len(r.stdout)>32768:raise Refused('FIXED_COMMAND_FAILED')
 return r.stdout.decode()

def bound_read(path,mode,expected=None,limit=4_000_000):
 fd=secure_open(path,False,0,mode)
 try:
  a=os.fstat(fd);b=os.read(fd,limit+1);z=os.fstat(fd)
  def identity(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  # Verify the final pathname through the protected ancestor walk again. An
  # opened old inode must not authorize a replacement at the installed path.
  check=secure_open(path,False,0,mode)
  try:current=os.fstat(check)
  finally:os.close(check)
  if len(b)>limit or identity(a)!=identity(z) or identity(a)!=identity(current):raise Refused('READ_DRIFT')
  if expected is not None and digest(b)!=expected:raise Refused('HASH')
  return b
 finally:os.close(fd)

def contract(expected):
 if not re.fullmatch('[0-9a-f]{64}',expected):raise Refused('CONTRACT_PIN')
 c=strict(bound_read(CONTRACT,0o400,expected))
 if set(c)!={'schema','files','unit_templates','new_authority_sha256'} or c['schema']!=1:raise Refused('CONTRACT_SCHEMA')
 if set(c['files'])!={PROGRAM,LEGACY,NEW,AUTH,CHECKSUM} or set(c['unit_templates'])!={FENCE,CONSUMER,TIMER_DEP,'/etc/systemd/system/'+RECOVERY,'/etc/systemd/system/'+WATCHDOG}:raise Refused('CONTRACT_PATHS')
 if c['new_authority_sha256']!=c['files'][AUTH]['sha256']:raise Refused('AUTHORITY_BINDING')
 return c

def verify_files(c,pin,new=False):
 paths=[PROGRAM]+([NEW,AUTH,CHECKSUM] if new else [LEGACY])
 for path in paths:
  row=c['files'][path]
  if set(row)!={'sha256','mode','uid','gid'} or row['uid']!=0 or row['gid']!=0:raise Refused('PAYLOAD_IDENTITY')
  raw=bound_read(path,row['mode'],row['sha256'])
  if os.stat(path,follow_symlinks=False).st_gid!=row['gid']:raise Refused('PAYLOAD_GROUP')
 for path,template in c['unit_templates'].items():
  if path==CONSUMER and not new:continue
  raw=bound_read(path,0o644)
  if raw!=template.replace('@CONTRACT_SHA@',pin).encode():raise Refused('UNIT_BYTES')
 return True

def properties(raw):
 result={}
 for line in raw.splitlines():
  k,v=line.split('=',1)
  if k in result:raise Refused('DUPLICATE_PROPERTY')
  result[k]=v
 return result

def loaded(pin,new,run=command):
 g=properties(run(SHOW_GUARD));t=properties(run(SHOW_TIMER))
 if set(g)!={'ExecStart','ExecCondition','DropInPaths','Requires','After','ActiveState'} or set(t)!={'Requires','After','DropInPaths','ActiveState','UnitFileState'}:raise Refused('LOADED_FIELDS')
 def argv(value):return re.findall(r'argv\[\]=(.*?) ;',value)
 if argv(g['ExecCondition'])!=['/usr/bin/python3 -I -B '+PROGRAM+' condition '+pin]:raise Refused('LOADED_FENCE')
 if argv(g['ExecStart'])!=[('/usr/bin/python3 -I -B '+NEW) if new else LEGACY]:raise Refused('LOADED_CONSUMER')
 if set(g['DropInPaths'].split())!=({FENCE,CONSUMER} if new else {FENCE}) or t['DropInPaths']!=TIMER_DEP:raise Refused('LOADED_DROPINS')
 for u in (g,t):
  if RECOVERY not in u['Requires'].split() or RECOVERY not in u['After'].split():raise Refused('LOADED_ORDERING')
 return g,t

def condition(store,c,pin,run=command,verify=verify_files):
 try:
  s=store.current()
  if store.exists('PRESEAL_INHIBIT'):return False
  if s['binding']['contract_sha256']!=pin:return False
  new=s['phase'] in ('NEW_CONSUMER_VERIFIED','COMPLETED')
  verify(c,pin,new);loaded(pin,new,run)
  if new:
   records=[store.read(n) for n in sorted(os.listdir(store.fd)) if re.fullmatch(r'state-[0-9]{6}\.json',n)]
   proof=next(x['proof'] for x in records if x['phase']=='NEW_CONSUMER_VERIFIED')
   if proof['consumer_sha256']!=c['files'][NEW]['sha256'] or proof['authority_sha256']!=c['files'][AUTH]['sha256'] or proof['loaded_unit_sha256']!=digest(c['unit_templates'][CONSUMER].replace('@CONTRACT_SHA@',pin).encode()):return False
  return permit(s,'new' if new else 'legacy',True)
 except Exception:return False

def alive(binding):
 try:
  raw=Path('/proc/'+str(binding['coordinator_pid'])+'/stat').read_text();tail=raw[raw.rindex(')')+2:].split()
  return int(tail[19])==binding['coordinator_start_ticks'] and tail[0] not in ('Z','X')
 except (OSError,ValueError,IndexError):return False

def secured(store,reason,run=command):
 # Persistent STOP takes precedence even if stopping the timer or DBus fails.
 store.stop(reason)
 try:run(STOP_TIMER)
 except Exception:pass
 return 'SECURED_STOP'

def recover_once(store,c,pin,boot,now,run=command,verify=verify_files,owner_alive=alive,mode='recover'):
 try:
  s=store.current()
  if s['binding']['contract_sha256']!=pin:raise Refused('TRANSACTION_PIN')
  d=decision(s,boot,now,owner_alive(s['binding']))
  if d=='WAIT':return 'WAIT'
  if s['phase'] in ('NEW_CONSUMER_VERIFIED','COMPLETED'):
   verify(c,pin,True);loaded(pin,True,run)
   # Recovery service must not synchronously start a unit requiring itself.
   if s['phase']=='COMPLETED':return 'COMPLETED'
   if mode=='recover':return 'VERIFIED_NEW_BOOT'
   if not condition(store,c,pin,run,verify):raise Refused('NEW_PROOF_BINDING')
   run(NEW_PROBE);run(STATUS_PROBE);run(START_TIMER)
   if not condition(store,c,pin,run,verify):raise Refused('NEW_PROOF_DRIFT')
   _,timer=loaded(pin,True,run)
   if timer['ActiveState']!='active' or timer['UnitFileState']!='enabled':return 'WAIT_TIMER'
   if s['phase']!='COMPLETED':store.advance('COMPLETED',{'recovered_new_consumer':True})
   return 'COMPLETED'
  if s['phase']=='ROLLED_BACK_PRESEAL':
   verify(c,pin,False);loaded(pin,False,run);return 'ROLLED_BACK_PRESEAL'
  # Never infer original integrity from phase names. A preseal rollback belongs
  # to the separately verified original-byte adapter; absent proof stops safely.
  return secured(store,'RECOVERY_REQUIRES_VERIFIED_REPAIR',run)
 except BlockingIOError:return 'WAIT'
 except Exception:return secured(store,'CORRUPT_OR_UNKNOWN',run)

def heartbeat(store,pin,run=command):
 # Prove private-state write and fixed DBus access from the independent process.
 run(SHOW_TIMER);current=store.current()
 raw=Path('/proc/self/stat').read_text();ticks=int(raw[raw.rindex(')')+2:].split()[19])
 value={'transaction':current['binding']['transaction'],'contract_sha256':pin,'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'pid':os.getpid(),'start_ticks':ticks,'monotonic_ns':time.monotonic_ns()}
 tmp='.heartbeat-'+uuid.uuid4().hex;fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=store.fd)
 try:
  with os.fdopen(fd,'wb',closefd=False) as f:os.fchmod(fd,0o600);f.write(encode(value));f.flush();os.fsync(fd)
  try:
   st=os.stat('watchdog-heartbeat.json',dir_fd=store.fd,follow_symlinks=False)
   if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:raise Refused('HEARTBEAT_POSTIMAGE')
  except FileNotFoundError:pass
  os.replace(tmp,'watchdog-heartbeat.json',src_dir_fd=store.fd,dst_dir_fd=store.fd);os.fsync(store.fd)
 finally:
  os.close(fd)
  try:os.unlink(tmp,dir_fd=store.fd)
  except FileNotFoundError:pass

def main():
 if os.geteuid()!=0 or not sys.flags.isolated or not sys.dont_write_bytecode or len(sys.argv)!=3 or sys.argv[1] not in ('condition','recover','watchdog'):return 78
 mode,pin=sys.argv[1:];os.environ.clear();os.environ.update(ENV);os.umask(0o077)
 try:
  c=contract(pin);bound_read(PROGRAM,0o600,c['files'][PROGRAM]['sha256']);store=Store()
  try:
   if mode=='condition':return 0 if condition(store,c,pin) else 1
   while True:
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    outcome=recover_once(store,c,pin,boot,time.monotonic_ns(),mode=mode)
    if mode=='recover':return 0 if outcome in ('WAIT','VERIFIED_NEW_BOOT','COMPLETED','ROLLED_BACK_PRESEAL') else 1
    if outcome in ('COMPLETED','ROLLED_BACK_PRESEAL','SECURED_STOP'):return 0
    heartbeat(store,pin)
    time.sleep(1)
  finally:store.close()
 except Exception:return 78
if __name__=='__main__':raise SystemExit(main())
