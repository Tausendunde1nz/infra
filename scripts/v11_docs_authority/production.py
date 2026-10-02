"""Fixed production candidates. Pure builders; never install or call systemd here."""
import hashlib,json
from pathlib import Path
PACKAGE='/usr/local/libexec/tu1nz-docs-authority-v11'
AUTHORITY='/etc/tu1nz/docs-authority-v11/authority.json'
STATE='/var/lib/tu1nz-docs-authority-v11'
DOCS='/tausendunde1nz/07_docs'
COMMIT='537aa8fd69d755c641246cc1b507c69b3e1cd5f5'
TREE='910f981134ad82a171cc0d727604315d50bba4fa'
AUTH_SHA='5576dbbd0c3fd15048dad66ddd93651bf493b23e7f4c9841d23afe56f3054c55'

def entry(manifest_source,guard_source,reader_source):
 # Embed only versioned, reviewed source bytes into a standalone isolated Python entry.
 # No chatops import path, shell, external helper or runtime-provided code.
 prefix=reader_source.split('def safe_name(')[0]
 # read_bound is a closed descriptor reader; its unused old BASE pin is omitted.
 prefix='\n'.join(l for l in prefix.splitlines() if not l.startswith(('BASE=','TREE=','CHECKOUT=')))+'\n'
 m=manifest_source.replace('class Refused(RuntimeError):pass','')
 g=guard_source.replace('from manifest import Refused,name,canonical,digest','')
 body=f'''\n# Fixed authority and observation entry; no arguments, defined environment.
if __name__ == '__main__':
 import sys
 if os.geteuid()!=0 or len(sys.argv)!=1:raise SystemExit(78)
 os.umask(0o077)
 try:
  raw=read_bound({AUTHORITY!r},{AUTH_SHA!r},0,0,0o600)
  a=parse(raw,{AUTH_SHA!r},{COMMIT!r},{TREE!r})
  observation=observe({DOCS!r},a,(2049,1453870,1001,1001,0o755))
 except Exception as exc:
  observation={{'kind':'RUNTIME_OBSERVATION','passed':False,'entries':[],'additional_paths':[],'additional_scan':'INCOMPLETE','authority_updated':False,'error_class':type(exc).__name__}}
 report=publish_report({STATE+'/results'!r},observation)
 boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 summary={{'schema':1,'authority_sha256':{AUTH_SHA!r},'boot_id':boot,'monotonic_ns':time.monotonic_ns(),'passed':observation['passed'],'report':report,'report_sha256':digest(canonical(observation)),'counts':{{s:sum(x['status']==s for x in observation['entries']) for s in ('MATCH','MISSING','CONTENT_MISMATCH','UNSAFE_OR_UNREADABLE')}},'additional_count':len(observation['additional_paths'])}}
 parent=Path({STATE!r})
 for p in [*reversed(parent.parents),parent]:
  st=p.lstat()
  if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or any('posix_acl' in k for k in os.listxattr(p,follow_symlinks=False)):raise Refused('STATUS_PARENT')
 target=parent/'status.json'
 try:
  st=target.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=1001 or stat.S_IMODE(st.st_mode)!=0o640 or st.st_nlink!=1:raise Refused('STATUS_IDENTITY')
 except FileNotFoundError:pass
 tmp=parent/('.status-'+uuid.uuid4().hex)
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
 with os.fdopen(fd,'wb') as out:os.fchmod(out.fileno(),0o640);os.fchown(out.fileno(),0,1001);out.write(canonical(summary));out.flush();os.fsync(out.fileno())
 os.replace(tmp,target);fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 raise SystemExit(0 if observation['passed'] else 1)
'''
 return ('#!/usr/bin/python3\n'+prefix+m+'\n'+g+body).encode()

def service_dropin():
 return f'''[Service]
User=root
Group=root
ExecStart=
ExecStart=/usr/bin/python3 -I -B {PACKAGE}/guard.py
Environment=
Environment=PATH=/usr/bin:/bin LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths={DOCS} /etc/tu1nz/docs-authority-v11 {PACKAGE}
ReadWritePaths={STATE}
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_CHOWN
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_CHOWN
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=256M
TasksMax=8
LimitNOFILE=128
CPUQuota=25%
TimeoutStartSec=120
'''.encode()

def status_reader():
 return f'''#!/usr/bin/python3
import os,stat,json,time,subprocess
from pathlib import Path
p=Path({STATE+'/status.json'!r})
for d in [*reversed(p.parent.parents),p.parent]:
 s=d.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or any('posix_acl' in x for x in os.listxattr(d,follow_symlinks=False)):raise SystemExit(1)
f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(f,'rb') as h:
 a=os.fstat(h.fileno())
 if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_gid!=1001 or stat.S_IMODE(a.st_mode)!=0o640 or a.st_nlink!=1 or a.st_size>16384:raise SystemExit(1)
 b=h.read(16385);z=os.fstat(h.fileno())
 if (a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise SystemExit(1)
q=subprocess.run(['/usr/bin/systemctl','show','--property=Result,ExecMainStatus,ActiveState','--','tu1nz_delete_guard.service'],env={{'PATH':'/usr/bin:/bin','LC_ALL':'C'}},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
if q.returncode or len(q.stdout)>2048:raise SystemExit(1)
u=dict(line.split('=',1) for line in q.stdout.decode().splitlines())
if u!={{'Result':'success','ExecMainStatus':'0','ActiveState':'inactive'}}:raise SystemExit(1)
x=json.loads(b);boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();age=time.monotonic_ns()-x['monotonic_ns']
raise SystemExit(0 if x['schema']==1 and x['authority_sha256']=={AUTH_SHA!r} and x['boot_id']==boot and 0<=age<=86700_000_000_000 and x['passed'] is True else 1)
'''.encode()

def payloads(directory):
 directory=Path(directory)
 source=entry((directory/'manifest.py').read_text(),(directory/'guard.py').read_text(),(directory.parent/'v11_authority/authority.py').read_text())
 return {PACKAGE+'/guard.py':{'bytes':source,'uid':0,'gid':0,'mode':0o600},'/etc/systemd/system/tu1nz_delete_guard.service.d/90-v11-authority.conf':{'bytes':service_dropin(),'uid':0,'gid':0,'mode':0o644},'/usr/local/bin/checksum_verify':{'bytes':status_reader(),'uid':0,'gid':0,'mode':0o755}}
