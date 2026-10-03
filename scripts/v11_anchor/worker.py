"""Exact pinned worker transport. Never selects commands from transaction data."""
import os,subprocess,signal,hashlib,json,time,sys
from pathlib import Path
from anchor import Refused,digest,encode,parse,metadata,trusted_program,TERMINAL
ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/var/empty','PYTHONDONTWRITEBYTECODE':'1'}
def group_members(pgid):
 # Process names and arguments are never emitted; only the private session's
 # group identity is inspected. Zombies cannot execute or mutate files.
 rows=[]
 for item in os.scandir('/proc'):
  if not item.name.isdecimal():continue
  try:
   with open(item.path+'/stat') as f:raw=f.read()
  except (FileNotFoundError,ProcessLookupError):continue
  end=raw.rfind(')');fields=raw[end+2:].split()
  if end<0 or len(fields)<20:raise Refused('PROCESS_IDENTITY')
  if fields[2]==str(pgid) and fields[0] not in ('Z','X'):rows.append((int(item.name),fields[19]))
 return rows

class Worker:
 def __init__(self,store,timeout=300):
  if timeout!=300:raise Refused('WORKER_TIMEOUT_POLICY')
  self.store=store;self.process=None
 def invoke_directional(self,selected,context,mode):
  if mode not in ('directional-recover','directional-verify','directional-activate','directional-cleanup'):raise Refused('WORKER_MODE')
  from seal_boundary import valid_context
  valid_context(context,self.store)
  return self._invoke(selected,context,mode,True)
 def invoke(self,selected,phase,mode):
  if mode not in ('recover','verify'):raise Refused('WORKER_MODE')
  return self._invoke(selected,phase,mode,False)
 def _invoke(self,selected,phase,mode,directional):
  if self.process is not None:raise Refused('WORKER_ALREADY_RUNNING')
  self.store.slot(selected['slot'],selected['sha256']);base=self.store.base()
  interpreter=trusted_program(base['interpreter'],base['interpreter_sha256']);worker=self.store.open('slot-'+selected['slot']+'.py',0o500)
  try:
   raw=os.read(worker,8_000_001)
   if digest(raw)!=selected['sha256']:raise Refused('OPEN_WORKER_HASH')
   os.lseek(worker,0,os.SEEK_SET)
   # The executable and source are the verified open inodes. A subsequent
   # pathname replacement cannot select another interpreter or worker.
   argv=('/proc/self/fd/'+str(interpreter),'-I','-B','/proc/self/fd/'+str(worker),mode,digest(encode(phase)))
   gate=None
   if os.geteuid()==0:
    gate=os.pipe();argv=(*argv,str(gate[0]))
   try:self.process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,cwd='/',pass_fds=(interpreter,worker,gate[0]) if gate else (interpreter,worker),start_new_session=True)
   except BaseException:
    if gate:
     os.close(gate[0]);os.close(gate[1])
    raise
   p=self.process
   try:
    if gate:
     os.close(gate[0]);supervisor=sys.modules.get('outer_supervisor')
     if supervisor is not None and supervisor.ACTIVE_CHANNEL is not None:supervisor.register(p)
     else:
      groups=Path('/proc/self/cgroup').read_text().splitlines()
      if not any(row.endswith('/system.slice/tu1nz-v11-validation-anchor.service') for row in groups):raise Refused('WORKER_LIFETIME_NOT_BOUND')
     os.write(gate[1],b'G');os.close(gate[1]);gate=None
    # A worker may emit only the fixed small result object. Stream with a bound
    # rather than buffer unbounded output from a faulty pinned implementation.
    import selectors
    sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ);out=bytearray();deadline=time.monotonic()+300
    try:
     while sel.get_map():
      remaining=deadline-time.monotonic()
      if remaining<=0:raise Refused('WORKER_TIMEOUT')
      for key,_ in sel.select(min(remaining,1)):
       part=os.read(key.fileobj.fileno(),4096)
       if not part:sel.unregister(key.fileobj);break
       out.extend(part)
       if len(out)>4096:raise Refused('WORKER_OUTPUT_LIMIT')
     rc=p.wait(timeout=max(.01,deadline-time.monotonic()))
    finally:sel.close();p.stdout.close()
    if group_members(p.pid):raise Refused('WORKER_DESCENDANTS')
    if rc!=0:raise Refused('WORKER_NONZERO')
    x=parse(bytes(out))
    if directional:
     from seal_boundary import UNKNOWN,SEALED_STOP
     if type(x)!=dict or set(x)!={'state','context_sha256','mode'} or x['state'] not in (TERMINAL,'COMPLETE',UNKNOWN,SEALED_STOP) or x['context_sha256']!=digest(encode(phase)) or x['mode']!=mode:raise Refused('WORKER_PROOF')
     return x['state']
    expected={'state':TERMINAL,'phase1_sha256':digest(encode(phase)),'mode':mode}
    if x!=expected:raise Refused('WORKER_PROOF')
    return TERMINAL
   except BaseException:
    # Popen retains child identity until wait; no PID read from a journal.
    if p.poll() is None or group_members(p.pid):
     try:os.killpg(p.pid,signal.SIGKILL)
     except ProcessLookupError:pass
    p.wait()
    deadline=time.monotonic()+5
    while group_members(p.pid):
     if time.monotonic()>=deadline:raise Refused('WORKER_CLEANUP_FAILED')
     time.sleep(.01)
    raise
   finally:
    if gate:
     try:os.close(gate[1])
     except OSError:pass
    self.process=None
  finally:os.close(interpreter);os.close(worker)
 def no_worker(self):
  if self.process is not None:raise Refused('WORKER_STILL_RUNNING')
