"""Fixed guard file backend; root production and explicit nonroot /tmp test backend."""
import os,stat,hashlib,base64,uuid,ctypes
from pathlib import Path
from runtime import *
TARGETS=tuple(sorted((ALLOWED_PATHS-{LEGACY})|{CONTRACT}))
DIRECTORIES={PACKAGE:(0,0,0o755),ROOT:(0,0,0o700),'/usr/local/libexec/tu1nz-docs-authority-v11':(0,0,0o755),'/etc/tu1nz/docs-authority-v11':(0,0,0o700),'/var/lib/tu1nz-docs-authority-v11':(0,1001,0o750),'/var/lib/tu1nz-docs-authority-v11/results':(0,0,0o700),'/etc/systemd/system/'+GUARD+'.d':(0,0,0o755),'/etc/systemd/system/'+TIMER+'.d':(0,0,0o755)}

def rename_no_replace(source,target):
 libc=ctypes.CDLL(None,use_errno=True)
 fn=getattr(libc,'renameat2',None)
 if fn is None:raise Refused('ATOMIC_NOREPLACE_UNAVAILABLE')
 fn.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint);fn.restype=ctypes.c_int
 if fn(-100,os.fsencode(source),-100,os.fsencode(target),1):
  error=ctypes.get_errno();raise OSError(error,os.strerror(error))

class Files:
 targets=TARGETS
 directories=DIRECTORIES
 def __init__(self,prefix='/',fixture=False,save=None):
  self.prefix=Path(prefix);self.fixture=fixture;self.uid=os.geteuid() if fixture else 0;self.save=save;self.receipts={};self.created=[]
  if fixture:
   if os.geteuid()==0 or self.prefix.parent!=Path('/tmp') or not self.prefix.name.startswith('tu1nz-fence-files-'):raise Refused('FIXTURE_SCOPE')
  elif self.prefix!=Path('/') or os.geteuid()!=0:raise Refused('ROOT_ONLY')
 def path(self,n):
  if n not in self.targets and n not in self.directories:raise Refused('FIXED_PATH')
  return self.prefix/n.lstrip('/')
 def chain(self,p):
  try:rel=p.relative_to(self.prefix)
  except ValueError:raise Refused('ROOT_ESCAPE')
  for d in [self.prefix,*[self.prefix.joinpath(*rel.parts[:i]) for i in range(1,len(rel.parts)+1)]]:
   s=d.lstat()
   if not stat.S_ISDIR(s.st_mode) or s.st_uid!=self.uid or s.st_mode&0o022 or os.listxattr(d,follow_symlinks=False):raise Refused('PARENT_IDENTITY')
 def snapshot_one(self,n):
  p=self.path(n);parent=p.parent
  while not parent.exists():
   if parent.is_symlink():raise Refused('PARENT_SYMLINK')
   parent=parent.parent
  self.chain(parent)
  try:s=p.lstat()
  except FileNotFoundError:return {'absent':True}
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=self.uid or s.st_mode&0o022 or s.st_nlink!=1 or s.st_size>4_000_000 or os.listxattr(p,follow_symlinks=False):raise Refused('FILE_IDENTITY')
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|getattr(os,'O_NOATIME',0))
  with os.fdopen(fd,'rb') as f:b=f.read(4_000_001);z=os.fstat(f.fileno())
  def sig(x):return (x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  if sig(s)!=sig(z) or sig(s)!=sig(p.lstat()) or len(b)>4_000_000:raise Refused('READ_RACE')
  return {'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'dev':s.st_dev,'inode':s.st_ino,'atime_ns':s.st_atime_ns,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'sha256':hashlib.sha256(b).hexdigest(),'bytes':base64.b64encode(b).decode(),'acls':{}}
 def snapshot(self,targets,dirs):
  if set(targets)!=set(self.targets) or dirs!=self.directories:raise Refused('SNAPSHOT_SCOPE')
  return {n:self.snapshot_one(n) for n in targets}
 def matches(self,snapshot,pins):
  return set(snapshot)==set(pins) and all(snapshot[n]==pins[n] for n in pins)
 def same_snapshot(self,s):return all(self.snapshot_one(n)==v for n,v in s.items())
 def originals_unchanged(self,paths,s):return all(self.snapshot_one(n)==s[n] for n in paths)
 def persist(self):
  if self.save is None:raise Refused('DURABLE_RECEIPT_REQUIRED')
  self.save({'receipts':self.receipts,'created_directories':self.created})
 def create_declared_directories(self,dirs):
  if dirs!=self.directories:raise Refused('DIRECTORY_SCOPE')
  for n,(uid,gid,mode) in sorted(dirs.items(),key=lambda x:len(x[0])):
   p=self.path(n);self.chain(p.parent)
   if p.exists():
    self.chain(p)
    if stat.S_IMODE(p.stat().st_mode)!=mode or p.stat().st_gid!=(os.getegid() if self.fixture else gid):raise Refused('DIRECTORY_MODE')
   else:
    self.created.append({'path':n,'status':'INTENT'});self.persist()
    tmp=p.parent/('.v11-dir-'+uuid.uuid4().hex);os.mkdir(tmp,0o700)
    try:
     os.chown(tmp,self.uid,os.getegid() if self.fixture else gid);os.chmod(tmp,mode)
     fd=os.open(tmp,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);identity=os.fstat(fd);os.close(fd)
     self.created[-1].update(status='PUBLISH_READY',temporary=str(tmp),inode=identity.st_ino,dev=identity.st_dev,uid=identity.st_uid,gid=identity.st_gid,mode=mode);self.persist()
     rename_no_replace(tmp,p);fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
     self.created[-1].update(status='CREATED');self.persist()
    finally:
     if tmp.exists():tmp.rmdir()
 def install_exact(self,n,candidate,originals):
  if n not in self.targets or hashlib.sha256(candidate['bytes']).hexdigest()!=candidate['sha256']:raise Refused('PAYLOAD')
  p=self.path(n);self.chain(p.parent);before=self.snapshot_one(n)
  expected=self.receipts.get(n,{}).get('after',originals[n])
  if before!=expected:raise Refused('FOREIGN_WRITER')
  self.receipts[n]={'before':originals[n],'candidate_sha256':candidate['sha256'],'candidate_mode':candidate['mode'],'candidate_gid':os.getegid() if self.fixture else candidate['gid'],'status':'INTENT','preimage':before};self.persist()
  tmp=p.parent/('.v11-'+uuid.uuid4().hex);fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(fd,'wb') as f:
    os.fchown(f.fileno(),self.uid,os.getegid() if self.fixture else candidate['gid']);os.fchmod(f.fileno(),candidate['mode']);f.write(candidate['bytes']);f.flush();os.fsync(f.fileno())
   if self.snapshot_one(n)!=before:raise Refused('PRE_REPLACE_DRIFT')
   staged=tmp.lstat()
   self.receipts[n].update(status='PUBLISH_READY',temporary=str(tmp),staged={'dev':staged.st_dev,'inode':staged.st_ino,'uid':staged.st_uid,'gid':staged.st_gid,'mode':stat.S_IMODE(staged.st_mode),'size':staged.st_size,'mtime_ns':staged.st_mtime_ns,'sha256':candidate['sha256']})
   self.persist()  # Bind the exact inode BEFORE atomic publication.
   os.replace(tmp,p);d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
  finally:
   if tmp.exists():tmp.unlink()
  self.verify_exact(n,candidate);self.receipts[n].update(status='VERIFIED',after=self.snapshot_one(n));self.persist()
 def verify_exact(self,n,c):
  r=self.snapshot_one(n)
  if r.get('sha256')!=c['sha256'] or r['uid']!=self.uid or r['mode']!=c['mode'] or r['gid']!=(os.getegid() if self.fixture else c['gid']):raise Refused('POSTIMAGE')
 def cleanup_staged(self,n,receipt,directory=False):
  temporary=receipt.get('temporary')
  if temporary is None:return
  p=Path(temporary);target=self.path(n)
  if p.parent!=target.parent or not p.name.startswith('.v11-'):raise Refused('STAGING_PATH')
  try:s=p.lstat()
  except FileNotFoundError:return
  self.chain(p.parent)
  proof=receipt if directory else receipt.get('staged',{})
  if any(getattr(s,'st_'+key)!=proof.get(key) for key in ('dev','inode') if key!='inode'):raise Refused('STAGING_IDENTITY')
  if (s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))!=(proof.get('inode'),proof.get('uid'),proof.get('gid'),proof.get('mode')) or os.listxattr(p,follow_symlinks=False):raise Refused('STAGING_IDENTITY')
  if directory:
   if not stat.S_ISDIR(s.st_mode):raise Refused('STAGING_TYPE')
   p.rmdir()
  else:
   if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise Refused('STAGING_TYPE')
   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NOATIME)
   try:
    if hashlib.sha256(os.read(fd,4000001)).hexdigest()!=proof.get('sha256'):raise Refused('STAGING_HASH')
   finally:os.close(fd)
   p.unlink()
  fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
 def restore_owned_changes(self,originals,only=None,cleanup=True):
  if only is not None and not set(only)<=set(self.targets):raise Refused('RESTORE_SCOPE')
  for n,receipt in reversed(list(self.receipts.items())):
   if only is not None and n not in only:continue
   current=self.snapshot_one(n)
   self.cleanup_staged(n,receipt)
   if current==originals[n]:continue
   if receipt.get('status') in ('INTENT','PUBLISH_READY') and current==receipt.get('preimage'):
    # An interrupted restore has not published its replacement. Its exact
    # previously verified postimage remains owned; no content-only adoption.
    receipt.update(status='VERIFIED',after=current);self.persist()
   if receipt.get('status')=='RESTORE_TIMES_PENDING':
    old=receipt['after'];wanted=receipt['restore_times']
    stable=('dev','inode','uid','gid','mode','sha256','bytes','acls')
    if any(current.get(k)!=old.get(k) for k in stable) or (current.get('atime_ns'),current.get('mtime_ns')) not in ((old['atime_ns'],old['mtime_ns']),tuple(wanted)):raise Refused('RESTORE_TIME_DRIFT')
    os.utime(self.path(n),ns=tuple(wanted));fd=os.open(self.path(n),os.O_RDONLY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
    receipt.update(status='RESTORED',restored=self.snapshot_one(n));self.persist();continue
   if receipt.get('status')=='RESTORED':
    if current!=receipt.get('restored'):raise Refused('RESTORED_POSTIMAGE_DRIFT')
    continue
   # The rename can finish before VERIFIED is journaled. A durable staged
   # inode plus exact bytes/metadata identifies that publication; a same-byte
   # replacement inode is not sufficient. Rename changes ctime, not mtime.
   if receipt.get('status')=='PUBLISH_READY':
    staged=receipt.get('staged',{})
    if set(staged)!={'dev','inode','uid','gid','mode','size','mtime_ns','sha256'} or any(current.get(k)!=v for k,v in staged.items() if k!='size') or len(base64.b64decode(current.get('bytes',''),validate=True))!=staged['size']:raise Refused('UNPROVEN_PUBLICATION')
    receipt.update(status='VERIFIED',after=current);self.persist()
   # Content alone cannot identify our postimage: preserve foreign chmod,
   # chown, replacement and timestamp changes even when bytes stayed equal.
   if receipt.get('status')!='VERIFIED' or current!=receipt.get('after'):raise Refused('RECOVERY_FOREIGN_WRITER_OR_INCOMPLETE_RECEIPT')
   before=originals[n]
   if before.get('absent'):
    p=self.path(n);p.unlink();fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
   else:
    data=base64.b64decode(before['bytes'],validate=True)
    self.receipts[n]['after']=current
    self.install_exact(n,{'bytes':data,'sha256':before['sha256'],'mode':before['mode'],'gid':before['gid'],'uid':before['uid']},originals)
    self.receipts[n].update(status='RESTORE_TIMES_PENDING',restore_times=[before['atime_ns'],before['mtime_ns']]);self.persist()
    os.utime(self.path(n),ns=(before['atime_ns'],before['mtime_ns']))
    fd=os.open(self.path(n),os.O_RDONLY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
   self.receipts[n].update(status='RESTORED',restored=self.snapshot_one(n));self.persist()
  for r in reversed(self.created) if cleanup else ():
   p=self.path(r['path']);self.cleanup_staged(r['path'],r,directory=True)
   if not p.exists():continue
   st=p.lstat()
   if r.get('status') not in ('CREATED','PUBLISH_READY') or p.is_symlink() or not stat.S_ISDIR(st.st_mode):raise Refused('DIRECTORY_OWNERSHIP_UNPROVEN')
   if (st.st_ino,st.st_dev,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(r['inode'],r['dev'],r['uid'],r['gid'],r['mode']):raise Refused('DIRECTORY_OWNERSHIP_UNPROVEN')
   p.rmdir();fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
  # Atomic replacement necessarily changes inode/ctime; compare restorable metadata.
 def same_restored_snapshot(self,s):
  for n,before in s.items():
   after=self.snapshot_one(n)
   if before.get('absent'):
    if after!=before:return False
   elif any(after.get(k)!=before.get(k) for k in ('uid','gid','mode','sha256','acls','mtime_ns','atime_ns')):return False
  return True
