"""Later one-prompt Mac controller. Inert on import; never run during preparation.

Activation accepts only a capsule whose SHA was pinned into the final private
launcher. No passwords, raw SSH diagnostics or production response bodies saved.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import time

IP='100.121.130.51'
BASE=['/usr/bin/ssh','-F','/dev/null','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ConnectTimeout=10','-o','HostKeyAlias='+IP,'-o','BatchMode=yes']
STATUS='/run/tu1nz-root-only-v9.status.json'
BROKER='/usr/local/sbin/tu1nz-codex-ops'


def argv(port,command,tty=False):
 return BASE+(['-t'] if tty else [])+['-p',str(port),'chatops@'+IP,command]


def capture(command,timeout=20,input=None):
 r=subprocess.run(command,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 if r.returncode or len(r.stdout)>1_000_000:raise RuntimeError('fixed client check failed')
 return r.stdout


def client_checks():
 for port in (22,2222):
  raw=capture(argv(port,"/usr/bin/id -un"))
  if raw!=b'chatops\n':raise RuntimeError('SSH identity check')
 for url in ('https://tu1nz.com','https://api.mychatbuddy.dev/mommyramona/health'):
  raw=capture(['/usr/bin/curl','--noproxy','*','--silent','--show-error','--max-time','10','--output','/dev/null','--write-out','%{http_code}',url],15)
  if raw!=b'200':raise RuntimeError('HTTP health status')
 raw=json.loads(capture(argv(2222,'/usr/bin/sudo -n '+BROKER+' status')))
 if raw.get('status')!='OK':raise RuntimeError('broker client status')


def activate(capsule,expected):
 p=Path(capsule);s=p.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise RuntimeError('local capsule metadata')
 raw=p.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=expected:raise RuntimeError('local capsule SHA')
 # Private single-use staging. Existing paths, symlinks and a replaced inode fail.
 staging='/home/chatops/.tu1nz-root-only-v9-'+expected
 code="import os,sys; p="+repr(staging)+"; os.umask(0o077); os.mkdir(p,0o700); os.chmod(p,0o700); f=os.open(p+'/capsule.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); data=sys.stdin.buffer.read(4000000); out=os.fdopen(f,'wb'); out.write(data); out.flush(); os.fsync(out.fileno()); out.close()"
 capture(argv(2222,'/usr/bin/python3 -I -S -c '+shlex.quote(code)),input=raw)
 rootcode="import os,stat,hashlib; p="+repr(staging+'/capsule.py')+"; f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); s=os.fstat(f); assert stat.S_ISREG(s.st_mode) and s.st_uid==1001 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1; raw=os.read(f,4000001); os.close(f); h=hashlib.sha256(raw).hexdigest(); assert len(raw)<=4000000 and h=="+repr(expected)+"; exec(compile(raw,'<pinned-root-capsule>','exec'),{'__name__':'__main__','CAPSULE_SHA256':h})"
 # The only interactive sudo command. Inherited terminal owns all secret input.
 r=subprocess.run(argv(2222,'/usr/bin/sudo -- /usr/bin/python3 -I -S -c '+shlex.quote(rootcode),tty=True))
 if r.returncode:raise RuntimeError('bootstrap failed; do not retry blindly')
 deadline=time.monotonic()+3600;confirmed=set();last=None
 while time.monotonic()<deadline:
  state=json.loads(capture(argv(2222,'/usr/bin/cat '+STATUS)))
  if state.get('capsule_sha256')!=expected:raise RuntimeError('status capsule mismatch')
  marker=(state['status'],state.get('phase'),state.get('awaiting_client'))
  if marker!=last:print(json.dumps({'status':marker[0],'phase':marker[1]},sort_keys=True),flush=True);last=marker
  if state['status'] in ('ROLLED_BACK','SECURED_STOP','ROLLBACK_FAILED'):raise RuntimeError('transaction stopped: '+state['status'])
  if state['status']=='COMPLETE':
   client_checks();print('COMPLETE: watchdog disabled; fresh SSH and web checks passed',flush=True);return
  phase=state.get('phase')
  if state.get('awaiting_client') and phase not in confirmed:
   if phase not in ('application_checks','finalize'):raise RuntimeError('unexpected receipt phase')
   client_checks()
   receipt=json.loads(capture(argv(2222,'/usr/bin/sudo -n '+BROKER+' migration-confirm')))
   if receipt.get('status')!='OK' or receipt.get('result',{}).get('phase')!=phase:raise RuntimeError('receipt refused')
   confirmed.add(phase)
  time.sleep(2)
 raise RuntimeError('client deadline; independent watchdog remains responsible')
