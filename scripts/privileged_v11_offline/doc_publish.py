"""Fixed data-only publication. Never parses/executes HTML, PDF, or user code."""
import hashlib,json,os,stat,time
from pathlib import Path
SOURCE=Path('/var/lib/tu1nz-privileged-v11-doc-render')
TARGET=Path('/opt/Tausendunde1nz/_Doku')
MARKDOWN=TARGET/'System_Dokumentation.md'
class Refused(RuntimeError):pass

def sha(b):return hashlib.sha256(b).hexdigest()
def read_file(rootfd,name,uid,limit):
 if name not in {'manifest.json','document.html','document.pdf','System_Dokumentation.md','System_Dokumentation.html','System_Dokumentation_latest.pdf'}:raise Refused('NAME')
 fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=rootfd)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or s.st_nlink!=1 or s.st_mode&0o022 or (hasattr(os,'listxattr') and any('posix_acl' in x for x in os.listxattr(f.fileno()))):raise Refused('FILE_IDENTITY')
  b=f.read(limit+1);z=os.fstat(f.fileno())
  if len(b)>limit or (s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise Refused('FILE_DRIFT')
 return b

def validate(source,markdown_sha,uid=1001):
 fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd)
  if s.st_uid!=uid or stat.S_IMODE(s.st_mode)!=0o700:raise Refused('SOURCE_DIRECTORY')
  manifest=json.loads(read_file(fd,'manifest.json',uid,4096))
  if set(manifest)!={'source_sha256','sha256'} or manifest['source_sha256']!=markdown_sha or set(manifest['sha256'])!={'document.html','document.pdf'}:raise Refused('MANIFEST')
  data={n:read_file(fd,n,uid,32_000_000) for n in manifest['sha256']}
  if any(sha(b)!=manifest['sha256'][n] for n,b in data.items()):raise Refused('ARTIFACT_HASH')
  if not data['document.pdf'].startswith(b'%PDF-') or b'%%EOF' not in data['document.pdf'][-1024:]:raise Refused('PDF')
  if not data['document.html'].startswith(b'<!doctype html>'):raise Refused('HTML')
  return data
 finally:os.close(fd)

def trusted_directory(path):
 for p in [*reversed(path.parents),path]:
  s=p.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or any('posix_acl' in x for x in os.listxattr(p,follow_symlinks=False)):raise Refused('TARGET_DIRECTORY')
 return os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)

def atomic(fd,name,data,mode=0o644,replace=True):
 temp='.v11-publish-'+os.urandom(16).hex();f=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=fd)
 try:
  with os.fdopen(f,'wb') as o:os.fchmod(o.fileno(),mode);o.write(data);o.flush();os.fsync(o.fileno())
  if replace:os.replace(temp,name,src_dir_fd=fd,dst_dir_fd=fd)
  else:os.link(temp,name,src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False);os.unlink(temp,dir_fd=fd)
  os.fsync(fd)
 finally:
  try:os.unlink(temp,dir_fd=fd)
  except FileNotFoundError:pass

def identity(fd,name):
 try:
  st=os.stat(name,dir_fd=fd,follow_symlinks=False)
 except FileNotFoundError:return None
 return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)

def publish_pair(fd,names,previous,identities,writer=atomic):
 """Restore only files demonstrably written by this invocation.

 A root-only directory plus the publication lock prevents an untrusted rename
 between checks. Another root writer is still detected and never overwritten.
 A failed atomic write may have completed replace before directory fsync failed;
 it is therefore attributed from its new inode and candidate digest as well.
 """
 written={}
 try:
  for n,b in names.items():
   if identity(fd,n)!=identities[n]:raise Refused('DESTINATION_DRIFT')
   try:writer(fd,n,b)
   except BaseException:
    current=identity(fd,n)
    if current!=identities[n] and current is not None:
     try:
      if read_file(fd,n,os.geteuid(),32_000_000)==b:written[n]=current
     except (OSError,Refused):pass
    raise
   written[n]=identity(fd,n)
   if read_file(fd,n,os.geteuid(),32_000_000)!=b:raise Refused('WRITE_VERIFY')
 except BaseException as original:
  failures=[]
  for n in reversed(written):
   try:
    if identity(fd,n)!=written[n] or read_file(fd,n,os.geteuid(),32_000_000)!=names[n]:
     raise Refused('FOREIGN_DRIFT_DURING_ROLLBACK')
    if previous[n] is None:os.unlink(n,dir_fd=fd);os.fsync(fd)
    else:atomic(fd,n,previous[n])
    if previous[n] is None:
     if identity(fd,n) is not None:raise Refused('RESTORE_ABSENCE')
    elif read_file(fd,n,os.geteuid(),32_000_000)!=previous[n]:raise Refused('RESTORE_VERIFY')
   except BaseException:failures.append(n)
  if failures:raise Refused('ROLLBACK_CONFLICT_OR_IO_FAILURE') from original
  raise

def main():
 import sys,fcntl
 if sys.platform!='linux' or not hasattr(os,'listxattr') or os.geteuid()!=0 or len(sys.argv)!=1 or not sys.flags.isolated or not sys.dont_write_bytecode:raise Refused('ROOT_ENTRY')
 os.umask(0o077);fd=trusted_directory(TARGET)
 lock=os.open('/var/lib/tu1nz-privileged-v11-doc-publish.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(lock)
  if s.st_uid!=0 or not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise Refused('LOCK')
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  md=read_file(fd,'System_Dokumentation.md',0,8_000_000);data=validate(SOURCE,sha(md))
  names={'System_Dokumentation.html':data['document.html'],'System_Dokumentation_latest.pdf':data['document.pdf']}
  previous={};identities={}
  for n in names:
   identities[n]=identity(fd,n)
   if identities[n] is None:previous[n]=None;continue
   st=os.stat(n,dir_fd=fd,follow_symlinks=False)
   if st.st_uid!=0 or st.st_gid!=0 or stat.S_IMODE(st.st_mode)!=0o644:raise Refused('DESTINATION_METADATA')
   previous[n]=read_file(fd,n,0,32_000_000)
   if identity(fd,n)!=identities[n]:raise Refused('BACKUP_DRIFT')
  archive=Path('/var/lib/tu1nz-privileged-v11-doc-backups')
  afd=trusted_directory(archive);folder=str(time.time_ns())+'-'+os.urandom(8).hex();os.mkdir(folder,0o700,dir_fd=afd);os.fsync(afd)
  bfd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=afd)
  try:
   for n,b in previous.items():
    if b is not None:atomic(bfd,n,b,0o600)
   atomic(bfd,'manifest.json',json.dumps({n:{'sha256':None if b is None else sha(b),'identity':identities[n]} for n,b in previous.items()},sort_keys=True).encode(),0o600)
  finally:os.close(bfd);os.close(afd)
  if sha(read_file(fd,'System_Dokumentation.md',0,8_000_000))!=sha(md):raise Refused('SOURCE_DRIFT')
  stamp=time.strftime('%Y-%m-%d_%H%M%S',time.gmtime())+'_'+os.urandom(8).hex()
  version='System_Dokumentation_'+stamp+'.pdf'
  # A unique PDF version is retained as evidence even if the pair is rolled back.
  atomic(fd,version,data['document.pdf'],replace=False)
  publish_pair(fd,names,previous,identities)
 finally:os.close(lock);os.close(fd)
if __name__=='__main__':
 try:main()
 except Exception:raise SystemExit(2)
