"""One bounded root preparation read. Never installs candidates or emits source bytes."""
import hashlib,json,os,stat,signal,time
from pathlib import Path
PATHS=('/etc/sudoers','/etc/sudoers.d/99-dokuagent-pandoc','/etc/sudoers.d/chatops-nopass','/etc/gshadow')
PINS=('/etc/sudoers','7b68bd1a3e600364a35ef71bbccfc671735ff840c14ed0a15fad5cebd4020b47'),('/etc/sudoers.d/99-dokuagent-pandoc','485957ca0f803a4f02216ea12625aaa338513bc20195d739c76d9bd993bae97c'),('/etc/sudoers.d/chatops-nopass','c153102adf2f49433b89db411e87107cc8f2bda2a2c26c2da75cfecaab91388e')
REMOVALS=(b'chatops ALL=(ALL) NOPASSWD: /usr/bin/tee -a /opt/docs/upload_log.txt',b'chatops ALL=(root) NOPASSWD: /opt/tu1nz_repos/infra/t1nz_create_golden.sh')
class Refused(RuntimeError):pass

def digest(b):return hashlib.sha256(b).hexdigest()
def transform(originals,pins=None):
 pins=dict(PINS) if pins is None else pins
 if set(originals)!=set(PATHS) or set(pins)!=set(PATHS[:3]):raise Refused('PATH_SET')
 for p,h in pins.items():
  if digest(originals[p])!=h:raise Refused('SUDO_BASELINE_DRIFT')
 lines=originals[PATHS[0]].splitlines(keepends=True)
 if any(sum(x.rstrip(b'\r\n')==r for x in lines)!=1 for r in REMOVALS):raise Refused('GRANT_COUNT')
 out={PATHS[0]:b''.join(x for x in lines if x.rstrip(b'\r\n') not in REMOVALS),PATHS[1]:None,PATHS[2]:None}
 rows=originals[PATHS[3]].splitlines(keepends=True);result=[];count=0
 for line in rows:
  if line.startswith(b'docker:'):
   f=line.rstrip(b'\n').split(b':')
   if len(f)!=4 or f[3].split(b',').count(b'chatops')!=1:raise Refused('GROUP_FORMAT')
   f[3]=b','.join(x for x in f[3].split(b',') if x!=b'chatops');line=b':'.join(f)+b'\n';count+=1
  result.append(line)
 if count!=1:raise Refused('DOCKER_GROUP_COUNT')
 out[PATHS[3]]=b''.join(result)
 return out

def read_fixed(path):
 if path not in PATHS:raise Refused('PATH')
 p=Path(path);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in p.parts[1:-1]:
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
   s=os.fstat(fd)
   if s.st_uid!=0 or s.st_mode&0o022 or os.listxattr(fd):raise Refused('PARENT')
  f=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|getattr(os,'O_NOATIME',0),dir_fd=fd)
  with os.fdopen(f,'rb') as inp:
   s=os.fstat(inp.fileno())
   if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or s.st_size>262144 or s.st_mode&0o022 or os.listxattr(inp.fileno()):raise Refused('IDENTITY')
   b=inp.read(262145);z=os.fstat(inp.fileno())
  def sig(x):return (x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_mode,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_nlink)
  if len(b)>262144 or sig(s)!=sig(z) or sig(s)!=sig(os.stat(p.name,dir_fd=fd,follow_symlinks=False)):raise Refused('RACE')
  return b,{'path':path,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'inode':s.st_ino,'sha256':digest(b),'acl':'ABSENT'}
 finally:os.close(fd)

def atomic(root,name,b,mode=0o600,gid=0):
 if '/' in name or name.startswith('.'):raise Refused('OUTPUT_NAME')
 tmp=root/('.'+name+'-'+os.urandom(8).hex());fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as out:os.fchmod(out.fileno(),mode);os.fchown(out.fileno(),0,gid);out.write(b);out.flush();os.fsync(out.fileno())
 os.link(tmp,root/name,follow_symlinks=False);tmp.unlink();fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)

def collect(read,save,derive=transform):
 rows=[];values={}
 try:
  for i,p in enumerate(PATHS):
   b,meta=read(p);save('original-%d.bin'%i,b);values[p]=b;rows.append(meta)
  candidate=derive(values)
  for i,p in enumerate(PATHS):
   b=candidate[p];rows[i]['candidate_sha256']=digest(b) if b is not None else None;rows[i]['candidate_action']='REPLACE' if b is not None else 'REMOVE'
   if b is not None:save('candidate-%d.bin'%i,b)
  for p in PATHS:
   b,_=read(p)
   if b!=values[p]:raise Refused('POST_READ_DRIFT')
  return {'status':'COMPLETE','error_class':None,'files':rows}
 except BaseException as exc:return {'status':'INCOMPLETE','error_class':type(exc).__name__,'files':rows}

def main():
 import re
 root=Path(__file__).parent.parent
 if os.geteuid()!=0 or Path(__file__).parent.name!='staging' or root.parent!=Path('/var/lib') or not re.fullmatch('tu1nz-v11-production-inputs-[a-z0-9_]+',root.name):raise Refused('ROOT_OUTPUT')
 for d in (root,root/'staging'):
  s=d.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or os.listxattr(d):raise Refused('OUTPUT_IDENTITY')
 os.umask(0o077);out=root/'private';out.mkdir(mode=0o700);rows=[];values={};status='INCOMPLETE';error=None
 def interrupt(*a):raise Refused('INTERRUPTED')
 signal.signal(signal.SIGINT,interrupt);signal.signal(signal.SIGTERM,interrupt);signal.signal(signal.SIGALRM,interrupt)
 try:
  def read(p):
   signal.alarm(10)
   try:return read_fixed(p)
   finally:signal.alarm(0)
  result=collect(read,lambda name,data:atomic(out,name,data))
  rows=result['files'];status=result['status'];error=result['error_class']
 except BaseException as exc:error=type(exc).__name__
 finally:
  signal.alarm(0);signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
  report={'schema':1,'status':status,'error_class':error,'files':rows,'source_sha256':digest(Path(__file__).read_bytes()),'live_mutation':False,'commands_executed':False}
  raw=json.dumps(report,sort_keys=True).encode()+b'\n';atomic(out,'manifest.json',raw)
  export=root/'redacted';export.mkdir(mode=0o750);os.chown(export,0,1001);os.chmod(export,0o750);atomic(export,'manifest.json',raw,0o640,1001)
  print(json.dumps({'root':str(root),'status':status,'manifest_sha256':digest(raw)}),flush=True)
 return 0 if status=='COMPLETE' else 2
if __name__=='__main__':raise SystemExit(main())
