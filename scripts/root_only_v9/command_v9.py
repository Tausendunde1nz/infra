"""Bounded direct argv execution. Child groups reaped on timeout/interruption."""
import os
import selectors
import signal
import subprocess
import time
from policy_v9 import Refused
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C','HOME':'/var/empty'}

def command(argv,timeout=20,limit=4_000_000,environment=None):
 if not isinstance(argv,(list,tuple)) or not argv or not argv[0].startswith('/') or any(not isinstance(x,str) or '\0' in x for x in argv):raise Refused('argv contract')
 env=dict(ENV)
 if environment:env.update(environment)
 start=time.monotonic_ns()
 with subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd='/',env=env,start_new_session=True) as p:
  sel=selectors.DefaultSelector();out=bytearray();err=bytearray()
  try:
   sel.register(p.stdout,selectors.EVENT_READ,out);sel.register(p.stderr,selectors.EVENT_READ,err)
   while sel.get_map():
    remaining=None if timeout is None else timeout-(time.monotonic_ns()-start)/1e9
    if remaining is not None and remaining<=0:raise Refused('command timeout')
    for key,_ in sel.select(0.1 if remaining is None else min(remaining,0.1)):
     block=os.read(key.fileobj.fileno(),65536)
     if not block:sel.unregister(key.fileobj);continue
     key.data.extend(block)
     if len(out)+len(err)>limit:raise Refused('command output limit')
   remaining=None if timeout is None else max(.001,timeout-(time.monotonic_ns()-start)/1e9)
   rc=p.wait(timeout=remaining)
   return rc,bytes(out),bytes(err)
  finally:
   sel.close()
   if p.returncode is None:
    try:os.killpg(p.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    p.wait()

def checked(argv,**kw):
 rc,out,err=command(argv,**kw)
 if rc or err:raise Refused('command rejected: '+argv[0].rsplit('/',1)[-1])
 return out
