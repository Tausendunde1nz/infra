"""Read-only descriptor-based Docs measurement. No self-update, shell or network."""
import hashlib,json,os,stat,time,uuid
from pathlib import Path
from manifest import Refused,name,canonical,digest
MAX_FILE=64*1024*1024
MAX_ENTRIES=30000

def sig(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def measure(rootfd,relative,hook=None):
 parts=name(relative).split('/');fds=[os.dup(rootfd)];links=[]
 try:
  for part in parts[:-1]:
   parent=fds[-1];n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(n);links.append((parent,part,os.fstat(n)))
  f=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[-1])
  try:
   a=os.fstat(f)
   if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>MAX_FILE:raise Refused('FILE_TYPE_LINK_OR_SIZE')
   if hook:hook()
   h=hashlib.sha256();total=0
   while True:
    b=os.read(f,65536)
    if not b:break
    total+=len(b)
    if total>MAX_FILE:raise Refused('FILE_TOO_LARGE')
    h.update(b)
   if sig(a)!=sig(os.fstat(f)) or sig(a)!=sig(os.stat(parts[-1],dir_fd=fds[-1],follow_symlinks=False)):raise Refused('FILE_RACE')
   for parent,part,before in links:
    now=os.stat(part,dir_fd=parent,follow_symlinks=False)
    if not stat.S_ISDIR(now.st_mode) or (now.st_dev,now.st_ino)!=(before.st_dev,before.st_ino):raise Refused('PARENT_REPLACEMENT')
   return h.hexdigest()
  finally:os.close(f)
 finally:
  for fd in reversed(fds):os.close(fd)

def enumerate_paths(rootfd):
 found=[]
 def walk(fd,prefix,depth):
  if depth>64:raise Refused('DEPTH_LIMIT')
  for n in sorted(os.listdir(fd)):
   if n=='.git':continue
   rel=prefix+n;name(rel)
   if len(found)>=MAX_ENTRIES:raise Refused('ENTRY_LIMIT')
   s=os.stat(n,dir_fd=fd,follow_symlinks=False)
   if stat.S_ISDIR(s.st_mode):
    child=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
    try:
     if (os.fstat(child).st_dev,os.fstat(child).st_ino)!=(s.st_dev,s.st_ino):raise Refused('DIRECTORY_RACE')
     walk(child,rel+'/',depth+1)
    finally:os.close(child)
   else:found.append(rel)
 walk(rootfd,'',0)
 return found

def observe(root,authority,expected_root=None):
 root=Path(root)
 if not root.is_absolute() or '..' in root.parts:raise Refused('ROOT_PATH')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in root.parts[1:]:
   n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=n
  before=os.fstat(fd)
  if expected_root is not None and (before.st_dev,before.st_ino,before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))!=expected_root:raise Refused('ROOT_PIN')
 except BaseException:os.close(fd);raise
 start=time.monotonic_ns();rows=[]
 try:
  for e in authority['entries']:
   try:
    h=measure(fd,e['path']);status='MATCH' if h==e['sha256'] else 'CONTENT_MISMATCH'
   except FileNotFoundError:h=None;status='MISSING'
   except (OSError,Refused) as exc:h=None;status='UNSAFE_OR_UNREADABLE';error=type(exc).__name__
   rows.append({'path':e['path'],'status':status,'sha256':h})
  try:
   actual=set(enumerate_paths(fd));extras=sorted(actual-{x['path'] for x in authority['entries']});scan='COMPLETE'
  except (OSError,Refused):extras=[];scan='INCOMPLETE'
  after=root.lstat()
  if not stat.S_ISDIR(after.st_mode) or (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):raise Refused('ROOT_REPLACEMENT')
 finally:os.close(fd)
 return {'schema':1,'kind':'RUNTIME_OBSERVATION','authority_sha256':digest(canonical(authority)),'start_monotonic_ns':start,'end_monotonic_ns':time.monotonic_ns(),'entries':rows,'additional_paths':extras,'additional_scan':scan,'passed':all(x['status']=='MATCH' for x in rows) and scan=='COMPLETE','authority_updated':False}

def publish_report(directory,result,owner=0):
 """Immutable unique report: never overwrite a prior report or follow a target."""
 directory=Path(directory)
 for p in [*reversed(directory.parents),directory]:
  s=p.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=owner or s.st_mode&0o022 or any('posix_acl' in k for k in os.listxattr(p,follow_symlinks=False)):raise Refused('REPORT_PARENT')
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);n='observation-'+uuid.uuid4().hex+'.json';tmp='.'+n
 try:
  f=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
  with os.fdopen(f,'wb') as out:os.fchmod(out.fileno(),0o600);out.write(canonical(result));out.flush();os.fsync(out.fileno())
  os.link(tmp,n,src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False);os.unlink(tmp,dir_fd=fd);os.fsync(fd)
 finally:os.close(fd)
 return n
