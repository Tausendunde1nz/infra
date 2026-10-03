"""Single-use root ExecStartPre claim for the V11 Agentmode observer.
Prepared only; not installed. Standalone stdlib code, no checkout imports.
"""
import hashlib,json,os,re,stat,subprocess,sys,time,uuid
from pathlib import Path
ROOT='/var/lib/tu1nz-privileged-v11-agentmode'
PROGRAM='/usr/local/libexec/tu1nz-privileged-v11/agentmode_claim.py'
OBSERVER='/usr/local/libexec/tu1nz-privileged-v11/agentmode_observer.sh'
DROPIN='/etc/systemd/system/tu1nz_agentmode.service.d/90-v11-observer.conf'
UNIT='/etc/systemd/system/tu1nz_agentmode.service'
HEAD='2281b2b397c017bc370ba108eab3dc00c989eaa5'
SHOW=('/usr/bin/systemctl','show','--property=Id,InvocationID,ControlPID,NeedDaemonReload,DropInPaths,User,Group','--','tu1nz_agentmode.service')
class Refused(RuntimeError):pass

def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pairs(rows):
 result={}
 for k,v in rows:
  if k in result:raise Refused('DUPLICATE_KEY')
  result[k]=v
 return result

def read(path,mode,limit=262144):
 if path not in (PROGRAM,OBSERVER,DROPIN,UNIT,ROOT+'/intent.json'):raise Refused('PATH')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  pieces=Path(path).parts[1:]
  for part in pieces[:-1]:
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt;s=os.fstat(fd)
   if s.st_uid!=0 or s.st_gid!=0 or s.st_mode&0o022 or any('posix_acl' in x for x in os.listxattr(fd)):raise Refused('PARENT')
  leaf=os.open(pieces[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
  try:
   a=os.fstat(leaf)
   if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_gid!=0 or a.st_nlink!=1 or stat.S_IMODE(a.st_mode)!=mode or os.listxattr(leaf):raise Refused('FILE')
   raw=os.read(leaf,limit+1);z=os.fstat(leaf);last=os.stat(pieces[-1],dir_fd=fd,follow_symlinks=False)
   def signature(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   if len(raw)>limit or signature(a)!=signature(z) or signature(a)!=signature(last):raise Refused('DRIFT')
   return raw
  finally:os.close(leaf)
 finally:os.close(fd)

def validate(intent,pin,boot,now,invocation,pid,cgroup,unit,files):
 keys={'schema','transaction','boot','deadline_ns','source_sha256','program_sha256','base_unit_sha256','dropin_template','head','status'}
 if type(intent)!=dict or set(intent)!=keys or sha(encode(intent))!=pin or intent['schema']!=1 or intent['status']!='START_INTENT':raise Refused('INTENT')
 if not re.fullmatch(r'tu1nz-privileged-v11-[a-f0-9]{32}',intent['transaction']) or intent['boot']!=boot or intent['head']!=HEAD:raise Refused('BINDING')
 if type(intent['deadline_ns'])!=int or type(now)!=int or now+300_000_000_000>=intent['deadline_ns']:raise Refused('DEADLINE')
 if not re.fullmatch('[0-9a-f]{32}',invocation) or type(pid)!=int or pid<=0:raise Refused('INVOCATION')
 if cgroup!='0::/system.slice/tu1nz_agentmode.service':raise Refused('CGROUP')
 expected={'Id':'tu1nz_agentmode.service','InvocationID':invocation,'ControlPID':str(pid),'NeedDaemonReload':'no','DropInPaths':DROPIN,'User':'chatops','Group':'chatops'}
 if unit!=expected:raise Refused('SYSTEMD_OWNERSHIP')
 if set(files)!={PROGRAM,OBSERVER,UNIT,DROPIN}:raise Refused('FILES')
 for path,key in ((PROGRAM,'program_sha256'),(OBSERVER,'source_sha256'),(UNIT,'base_unit_sha256')):
  if not re.fullmatch('[a-f0-9]{64}',intent[key]) or sha(files[path])!=intent[key]:raise Refused('PAYLOAD')
 if files[DROPIN]!=intent['dropin_template'].replace('@INTENT_SHA@',pin).encode():raise Refused('DROPIN')
 return {'schema':1,'status':'START_CLAIMED','transaction':intent['transaction'],'intent_sha256':pin,'boot':boot,'invocation':invocation,'claim_ns':now,'prologue_pid':pid,'source_sha256':intent['source_sha256']}

def publish(fd,receipt):
 # No overwrite: a second invocation cannot adopt the first invocation's claim.
 name='.claim-'+uuid.uuid4().hex;leaf=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=fd)
 try:
  with os.fdopen(leaf,'wb',closefd=False) as f:os.fchmod(leaf,0o400);f.write(encode(receipt));f.flush();os.fsync(leaf)
  os.link(name,'claim.json',src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False);os.unlink(name,dir_fd=fd);os.fsync(fd)
 finally:
  os.close(leaf)
  try:os.unlink(name,dir_fd=fd)
  except FileNotFoundError:pass

def main():
 if os.geteuid()!=0 or not sys.flags.isolated or not sys.dont_write_bytecode or len(sys.argv)!=2 or not re.fullmatch('[a-f0-9]{64}',sys.argv[1]):return 78
 pin=sys.argv[1];invocation=os.environ.get('INVOCATION_ID','');os.environ.clear();os.umask(0o077)
 try:
  intent=json.loads(read(ROOT+'/intent.json',0o400),object_pairs_hook=pairs)
  p=subprocess.run(SHOW,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},cwd='/',timeout=10)
  if p.returncode or len(p.stdout)>8192:raise Refused('SYSTEMD')
  unit=pairs(x.split('=',1) for x in p.stdout.decode().splitlines())
  files={PROGRAM:read(PROGRAM,0o600),OBSERVER:read(OBSERVER,0o755),UNIT:read(UNIT,0o644),DROPIN:read(DROPIN,0o644)}
  boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();cgroup=Path('/proc/self/cgroup').read_text().strip()
  receipt=validate(intent,pin,boot,time.monotonic_ns(),invocation,os.getpid(),cgroup,unit,files)
  fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   s=os.fstat(fd)
   if s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=0o700 or os.listxattr(fd):raise Refused('STATE_DIRECTORY')
   publish(fd,receipt)
  finally:os.close(fd)
  return 0
 except Exception:return 78
if __name__=='__main__':raise SystemExit(main())
