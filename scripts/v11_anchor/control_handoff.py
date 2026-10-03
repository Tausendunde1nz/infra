"""Read-only admission after official owning-block recovery handoff.
No recovery, permission repair, index refresh or causal investigation here.
"""
import os,stat,subprocess,hashlib
from pathlib import Path
from anchor import Refused,encode,digest,pin
from seal_boundary import CONTROL,TREE
ROOT='/opt/tu1nz_repos/control'
FIELDS={'schema','owner','status','control_commit','control_tree','index_sha256','metadata_sha256','no_locks','no_writers','recovery_terminal','no_rc5_activation','no_content_drift'}
def admitted(receipt,expected):
 if receipt is None:raise Refused('WAITING_FOR_CONTROL_HANDOFF')
 if type(receipt)!=dict or set(receipt)!=FIELDS or receipt['schema']!=1 or receipt['owner']!='Adult Publishing S12.1-R9' or receipt['status']!='CONTROL_HANDOFF_COMPLETE' or receipt['control_commit']!=CONTROL or receipt['control_tree']!=TREE:raise Refused('CONTROL_HANDOFF_PROVENANCE')
 if any(receipt[k] is not True for k in ('no_locks','no_writers','recovery_terminal','no_rc5_activation','no_content_drift')):raise Refused('CONTROL_HANDOFF_NOT_TERMINAL')
 if not pin(receipt['index_sha256']) or not pin(receipt['metadata_sha256']):raise Refused('CONTROL_HANDOFF_METADATA_PIN')
 if digest(encode(receipt))!=expected:raise Refused('CONTROL_HANDOFF_PIN')
 return receipt
def verify(receipt,expected):
 receipt=admitted(receipt,expected) # Before touching production Git metadata.
 root=Path(ROOT);meta=root/'.git';rows={}
 for p in (root,meta):
  s=p.lstat()
  if not stat.S_ISDIR(s.st_mode) or p.is_symlink():raise Refused('CONTROL_HANDOFF_PATH')
 for p in sorted(meta.rglob('*')):
  s=p.lstat()
  if p.name.endswith('.lock'):raise Refused('CONTROL_HANDOFF_LOCK')
  if not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)) or p.is_symlink():raise Refused('CONTROL_HANDOFF_TYPE')
  attrs={a:os.getxattr(p,a,follow_symlinks=False).hex() for a in os.listxattr(p,follow_symlinks=False)}
  rows[str(p.relative_to(root))]={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'xattrs':attrs}
 index=meta/'index'
 if digest(index.read_bytes())!=receipt['index_sha256'] or digest(encode(rows))!=receipt['metadata_sha256']:raise Refused('CONTROL_HANDOFF_METADATA_DRIFT')
 # No -w, checkout, refresh or repair; prevent optional index locking and hooks.
 env={'PATH':'/usr/bin:/bin','HOME':'/var/empty','LC_ALL':'C','GIT_OPTIONAL_LOCKS':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
 def git(args):
  r=subprocess.run(('/usr/bin/git','-c','safe.directory='+ROOT,'-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',*args),cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
  if r.returncode or len(r.stdout)>2_000_000:raise Refused('CONTROL_HANDOFF_GIT_READ')
  return r.stdout
 if git(('rev-parse','HEAD')).strip().decode()!=CONTROL or git(('rev-parse','HEAD^{tree}')).strip().decode()!=TREE or git(('status','--porcelain=v1','--untracked-files=all')):raise Refused('CONTROL_HANDOFF_CONTENT_DRIFT')
 # The owner must supply the exact terminal contract; contradictory active
 # writer descriptors are a new failure, not grounds to repair their checkout.
 for proc in Path('/proc').iterdir():
  if not proc.name.isdecimal() or int(proc.name)==os.getpid():continue
  try:
   for f in (proc/'fd').iterdir():
    target=os.readlink(f)
    if target.startswith(ROOT+'/'):
     info=(proc/'fdinfo'/f.name).read_text();flags=[x.split(':',1)[1].strip() for x in info.splitlines() if x.startswith('flags:')]
     if len(flags)!=1 or int(flags[0],8)&os.O_ACCMODE!=os.O_RDONLY:raise Refused('CONTROL_HANDOFF_ACTIVE_WRITER')
  except (FileNotFoundError,ProcessLookupError):continue
  except PermissionError:raise Refused('CONTROL_HANDOFF_WRITER_VISIBILITY') from None
 return {'state':'CONTROL_HANDOFF_VERIFIED','commit':CONTROL,'tree':TREE,'receipt_sha256':expected,'index_sha256':receipt['index_sha256'],'metadata_sha256':receipt['metadata_sha256']}
