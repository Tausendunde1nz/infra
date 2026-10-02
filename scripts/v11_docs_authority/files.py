"""Fixed guard file backend; root production and explicit nonroot /tmp test backend."""
import os,stat,hashlib,base64,uuid
from pathlib import Path
from adapter import TARGETS,DIRECTORIES,UNIT,PACKAGE,execute
from manifest import Refused
class Files:
 def __init__(self,prefix='/',fixture=False,save=None):
  self.prefix=Path(prefix);self.fixture=fixture;self.uid=os.geteuid() if fixture else 0;self.save=save;self.receipts={};self.created=[]
  if fixture:
   if os.geteuid()==0 or self.prefix.parent!=Path('/tmp') or not self.prefix.name.startswith('tu1nz-docs-fixture-'):raise Refused('FIXTURE_SCOPE')
  elif self.prefix!=Path('/') or os.geteuid()!=0:raise Refused('ROOT_ONLY')
 def path(self,n):
  if n not in TARGETS and n not in DIRECTORIES:raise Refused('FIXED_PATH')
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
  if set(targets)!=set(TARGETS) or dirs!=DIRECTORIES:raise Refused('SNAPSHOT_SCOPE')
  return {n:self.snapshot_one(n) for n in targets}
 def matches(self,snapshot,pins):
  return set(snapshot)==set(pins) and all(snapshot[n]==pins[n] for n in pins)
 def same_snapshot(self,s):return all(self.snapshot_one(n)==v for n,v in s.items())
 def originals_unchanged(self,paths,s):return all(self.snapshot_one(n)==s[n] for n in paths)
 def persist(self):
  if self.save is None:raise Refused('DURABLE_RECEIPT_REQUIRED')
  self.save({'receipts':self.receipts,'created_directories':self.created})
 def create_declared_directories(self,dirs):
  if dirs!=DIRECTORIES:raise Refused('DIRECTORY_SCOPE')
  for n,(uid,gid,mode) in sorted(dirs.items(),key=lambda x:len(x[0])):
   p=self.path(n);self.chain(p.parent)
   if p.exists():
    self.chain(p)
    if stat.S_IMODE(p.stat().st_mode)!=mode or p.stat().st_gid!=(os.getegid() if self.fixture else gid):raise Refused('DIRECTORY_MODE')
   else:
    self.created.append({'path':n,'status':'INTENT'});self.persist();os.mkdir(p,mode);os.chmod(p,mode)
    os.chown(p,self.uid,os.getegid() if self.fixture else gid)
    self.created[-1].update(status='CREATED',inode=p.stat().st_ino);self.persist()
 def install_exact(self,n,candidate,originals):
  if n not in TARGETS or hashlib.sha256(candidate['bytes']).hexdigest()!=candidate['sha256']:raise Refused('PAYLOAD')
  p=self.path(n);self.chain(p.parent);before=self.snapshot_one(n)
  expected=self.receipts.get(n,{}).get('after',originals[n])
  if before!=expected:raise Refused('FOREIGN_WRITER')
  self.receipts[n]={'before':originals[n],'candidate_sha256':candidate['sha256'],'status':'INTENT'};self.persist()
  tmp=p.parent/('.v11-'+uuid.uuid4().hex);fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(fd,'wb') as f:
    os.fchown(f.fileno(),self.uid,os.getegid() if self.fixture else candidate['gid']);os.fchmod(f.fileno(),candidate['mode']);f.write(candidate['bytes']);f.flush();os.fsync(f.fileno())
   if self.snapshot_one(n)!=before:raise Refused('PRE_REPLACE_DRIFT')
   os.replace(tmp,p);d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
  finally:
   if tmp.exists():tmp.unlink()
  self.verify_exact(n,candidate);self.receipts[n].update(status='VERIFIED',after=self.snapshot_one(n));self.persist()
 def verify_exact(self,n,c):
  r=self.snapshot_one(n)
  if r.get('sha256')!=c['sha256'] or r['uid']!=self.uid or r['mode']!=c['mode'] or r['gid']!=(os.getegid() if self.fixture else c['gid']):raise Refused('POSTIMAGE')
 def restore_owned_changes(self,originals):
  for n,receipt in reversed(list(self.receipts.items())):
   current=self.snapshot_one(n)
   if current==originals[n]:continue
   if current.get('sha256')!=receipt['candidate_sha256']:raise Refused('RECOVERY_FOREIGN_WRITER')
   before=originals[n]
   if before.get('absent'):
    p=self.path(n);p.unlink();fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
   else:
    data=base64.b64decode(before['bytes'],validate=True)
    self.receipts[n]['after']=current
    self.install_exact(n,{'bytes':data,'sha256':before['sha256'],'mode':before['mode'],'gid':before['gid'],'uid':before['uid']},originals)
    os.utime(self.path(n),ns=(before['atime_ns'],before['mtime_ns']))
  for r in reversed(self.created):
   p=self.path(r['path'])
   if not p.exists():continue
   if r.get('status')!='CREATED' or p.is_symlink() or p.stat().st_ino!=r['inode']:raise Refused('DIRECTORY_OWNERSHIP_UNPROVEN')
   p.rmdir()
  # Atomic replacement necessarily changes inode/ctime; compare restorable metadata.
 def same_restored_snapshot(self,s):
  for n,before in s.items():
   after=self.snapshot_one(n)
   if before.get('absent'):
    if after!=before:return False
   elif any(after.get(k)!=before.get(k) for k in ('uid','gid','mode','sha256','acls','mtime_ns','atime_ns')):return False
  return True
 def verify_loaded_consumer(self,unit,path):
  if self.fixture:raise Refused('FIXTURE_CANNOT_VERIFY_SYSTEMD')
  import subprocess
  r=subprocess.run(['/usr/bin/systemctl','show','--property=ExecStart','--value','--',UNIT],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},timeout=5)
  expected='argv[]=/usr/bin/python3 -I -B '+PACKAGE+'/guard.py ;'
  if r.returncode or r.stdout.decode().count(expected)!=1 or '/usr/local/bin/tu1nz_delete_guard.sh' in r.stdout.decode():raise Refused('LOADED_CONSUMER')
 def verify_fresh_status(self,authority):
  if self.fixture:raise Refused('FIXTURE_CANNOT_VERIFY_LIVE_STATUS')
  import subprocess
  r=subprocess.run(['/usr/bin/python3','-I','-B','/usr/local/bin/checksum_verify'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},timeout=10)
  if r.returncode:raise Refused('FRESH_STATUS')
