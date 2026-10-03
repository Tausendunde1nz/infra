"""Prepared root-only, fixed-scope Control metadata audit. Import has no effects.
No permissions, files, refs, indexes, services or rules are changed. Payload,
environment, command-line and raw journal text are never returned.
"""
import os,stat,hashlib,subprocess,re
from pathlib import Path
ROOT='/opt/tu1nz_repos/control'
GIT=('/usr/bin/git','--no-optional-locks','-c','safe.directory='+ROOT,'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','core.preloadIndex=false','-C',ROOT)
OPS=(('rev-parse','HEAD'),('rev-parse','HEAD^{tree}'),('rev-parse','--is-inside-work-tree'),('reflog','-10','--format=%H %gD'),('config','--local','--get','core.sparseCheckout'),('config','--local','--get','extensions.worktreeConfig'),('worktree','list','--porcelain'))
ENV={'PATH':'/usr/bin:/bin','HOME':'/var/empty','LC_ALL':'C','GIT_OPTIONAL_LOCKS':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_INDEX_FILE':'/dev/null'}
def metadata(p,hash_contents=False):
 p=Path(p);a=p.lstat();row={'path':str(p),'uid':a.st_uid,'gid':a.st_gid,'mode':oct(stat.S_IMODE(a.st_mode)),'dev':a.st_dev,'inode':a.st_ino,'nlink':a.st_nlink,'size':a.st_size,'mtime_ns':a.st_mtime_ns,'ctime_ns':a.st_ctime_ns,'type':'directory' if stat.S_ISDIR(a.st_mode) else 'regular' if stat.S_ISREG(a.st_mode) else 'other','xattr_names':sorted(os.listxattr(p,follow_symlinks=False))}
 if hash_contents:
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1:raise RuntimeError('AUDIT_INDEX_TYPE')
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   opened=os.fstat(fd);h=hashlib.sha256();count=0
   while True:
    data=os.read(fd,65536)
    if not data:break
    count+=len(data)
    if count>16000000:raise RuntimeError('AUDIT_INDEX_LIMIT')
    h.update(data)
   after=os.fstat(fd);last=p.lstat()
   sig=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   if len({sig(x) for x in (a,opened,after,last)})!=1:raise RuntimeError('AUDIT_INDEX_DRIFT')
   row['sha256']=h.hexdigest()
   acl=os.getxattr(fd,'system.posix_acl_access') if 'system.posix_acl_access' in os.listxattr(fd) else b''
   row['acl_hex']=acl.hex() # Kernel ACL metadata only; not file contents.
  finally:os.close(fd)
 return row
def git_read(op,runner=subprocess.run):
 if os.geteuid()!=0 or tuple(op) not in OPS:raise RuntimeError('AUDIT_FIXED_SCOPE')
 p=runner((*GIT,*op),cwd='/',env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20)
 if p.returncode not in (0,1) or len(p.stdout)>32768:raise RuntimeError('AUDIT_GIT_READ_FAILED')
 text=p.stdout.decode().strip()
 if op[:1]==('rev-parse',):
  if op[-1] in ('HEAD','HEAD^{tree}') and not re.fullmatch('[0-9a-f]{40}',text):raise RuntimeError('AUDIT_OBJECT_FORMAT')
  if op[-1]=='--is-inside-work-tree' and text not in ('true','false'):raise RuntimeError('AUDIT_BOOL_FORMAT')
 elif op[:1]==('config',):
  if text not in ('','true','false','0','1','yes','no'):raise RuntimeError('AUDIT_CONFIG_FORMAT')
 elif op[:1]==('reflog',):
  if any(not re.fullmatch(r'[0-9a-f]{40} [A-Za-z0-9_/.-]+@\{[0-9]+\}',line) for line in text.splitlines()):raise RuntimeError('AUDIT_REFLOG_FORMAT')
 elif op[:1]==('worktree',):
  # Return only topology counts: author paths/branch names are not needed.
  return {'rc':p.returncode,'worktrees':sum(x.startswith('worktree ') for x in text.splitlines())}
 return {'rc':p.returncode,'value':text}
def collect():
 if os.geteuid()!=0:raise RuntimeError('AUDIT_ROOT_ONLY')
 # Literal path, no symlink or bind-path substitution accepted.
 rows=[]
 for p in ('/opt','/opt/tu1nz_repos',ROOT,ROOT+'/.git'):
  row=metadata(p)
  if row['type']!='directory':raise RuntimeError('AUDIT_PATH_TYPE')
  rows.append(row)
 result={'schema':1,'production_repair_permitted':False,'metadata':rows,'mechanism':'UNATTRIBUTED_FROM_AVAILABLE_METADATA','git':{},'locks':[],'writer_references':[],'index':None,'missing_reads':[]}
 try:result['index']=metadata(ROOT+'/.git/index',True)
 except (OSError,RuntimeError) as e:result['missing_reads'].append({'field':'index','error':type(e).__name__})
 for op in OPS:
  try:result['git'][' '.join(op)]=git_read(op)
  except (OSError,RuntimeError,subprocess.TimeoutExpired) as e:result['missing_reads'].append({'field':'git '+' '.join(op),'error':type(e).__name__})
 # Direct readable lock metadata; never read its payload or remove a lock.
 for p in Path(ROOT+'/.git').rglob('*.lock'):
  result['locks'].append(metadata(p))
 for p in Path('/proc').iterdir():
  if not p.name.isdecimal():continue
  refs=[]
  for name in ('cwd','exe'):
   try:
    x=os.readlink(p/name)
    if x==ROOT or x.startswith(ROOT+'/'):refs.append({'kind':name,'path':x})
   except OSError:pass
  try:
   for fd in (p/'fd').iterdir():
    try:
     x=os.readlink(fd)
     if x==ROOT or x.startswith(ROOT+'/'):
      flags=next(v.split()[1] for v in (p/'fdinfo'/fd.name).read_text().splitlines() if v.startswith('flags:'))
      refs.append({'kind':'fd','path':x,'writable':bool(int(flags,8)&3)})
    except (OSError,StopIteration):pass
  except OSError:pass
  if refs:result['writer_references'].append({'pid':int(p.name),'references':refs})
 if result['index'] is not None and metadata(ROOT+'/.git/index',True)!=result['index']:raise RuntimeError('AUDIT_INDEX_CHANGED')
 result['classification']='ACTIVE_EXTERNAL_TRANSACTION' if result['locks'] or any(v.get('writable') for p in result['writer_references'] for v in p['references']) else 'UNRESOLVED_PRODUCTION_DRIFT'
 return result
