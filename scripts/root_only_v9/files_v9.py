"""Protected file journal for exact allowlisted installation targets."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
from policy_v9 import Refused

PACKAGE='/usr/local/libexec/tu1nz-root-only-v9'
FIXED={'/usr/local/sbin/tu1nz-codex-ops','/usr/local/sbin/tu1nz-mychatbuddy-lifecycle',
 '/etc/systemd/system/mychatbuddy-private-alpha.service',
 '/etc/systemd/system/docker.socket.d/90-tu1nz-root-only.conf',
 '/etc/systemd/system/tu1nz-root-only-v9.service',
 '/etc/systemd/system/tu1nz-root-only-v9-watchdog.service',
 '/etc/systemd/system/tu1nz-root-only-v9-watchdog.timer',
 '/etc/sudoers','/etc/sudoers.d/99-dokuagent-pandoc','/etc/sudoers.d/chatops-nopass',
 '/etc/sudoers.d/90-tu1nz-codex-ops','/etc/group','/etc/gshadow',
 '/etc/cron.d/system_doc_build','/etc/cron.d/system_doc_check',
 '/etc/systemd/system/tu1nz-bot.service','/usr/local/bin/backup_notify.sh','/usr/local/bin/trendwatch_post.sh'}|{'/etc/systemd/system/trendwatch2-'+slot+'.timer' for slot in ('morning','midday','afternoon','evening')}|{'/etc/systemd/system/trendwatch2-'+slot+'.service' for slot in ('morning','midday','afternoon','evening')}
PACKAGE_FILES={'command_v9.py','contracts_v9.py','runtime_v9.py','graph_v9.py','policy_v9.py','audit_v9.py','probes_v9.py','transaction_v9.py','files_v9.py','host_v9.py','entry_v9.py','lifecycle_v9.py','quarantine_v8.py','sudo_candidate_v9.py','manifest.json'}


def authorized(path):
 p=Path(path)
 if str(p) in FIXED:return True
 return str(p.parent)==PACKAGE and p.name in PACKAGE_FILES


def safe_chain(path,uid=0):
 p=Path(path)
 for part in list(reversed(p.parents))+[p]:
  s=part.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=uid or s.st_mode&0o022:raise Refused('unsafe directory')
  if any('posix_acl' in x for x in os.listxattr(part)):raise Refused('directory ACL')


def read_file(path,limit=4_000_000):
 p=Path(path);safe_chain(p.parent)
 try:s=p.lstat()
 except FileNotFoundError:return {'absent':True}
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or s.st_nlink!=1:raise Refused('file metadata')
 if os.listxattr(p):raise Refused('file xattrs require explicit contract')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|getattr(os,'O_NOATIME',0))
 with os.fdopen(fd,'rb') as f:
  before=os.fstat(f.fileno());raw=f.read(limit+1);after=os.fstat(f.fileno())
 attrs=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_nlink)
 if len(raw)>limit or attrs(s)!=attrs(before) or attrs(before)!=attrs(after):raise Refused('file read drift')
 return {'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'dev':s.st_dev,'ino':s.st_ino,'mtime_ns':s.st_mtime_ns,'atime_ns':s.st_atime_ns,
 'sha256':hashlib.sha256(raw).hexdigest(),'data':base64.b64encode(raw).decode(),'acl':'ABSENT','xattrs':'ABSENT'}


def bytes_of(record):
 if record.get('absent'):return None
 raw=base64.b64decode(record['data'],validate=True)
 if hashlib.sha256(raw).hexdigest()!=record['sha256']:raise Refused('backup digest')
 return raw


def same_content(a,b):
 if a.get('absent') or b.get('absent'):return a==b
 return all(a.get(k)==b.get(k) for k in ('uid','gid','mode','sha256','acl','xattrs'))


def same_identity(a,b):
 # atime may change as a consequence of this reader itself.
 return {k:v for k,v in a.items() if k!='atime_ns'}=={k:v for k,v in b.items() if k!='atime_ns'}


def write_exact(path,data,expected,mode=0o644,gid=0,timestamps=None):
 if os.geteuid()!=0 or not authorized(path):raise Refused('write not authorized')
 p=Path(path);safe_chain(p.parent)
 current=read_file(p)
 if not same_identity(current,expected):raise Refused('pre-write identity drift')
 if data is None:
  if not current.get('absent'):p.unlink()
  d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d);return {'absent':True}
 name='.tu1nz-new-'+secrets.token_hex(12);fd=os.open(p.parent/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 try:
  with os.fdopen(fd,'wb') as f:
   os.fchown(f.fileno(),0,gid);os.fchmod(f.fileno(),mode);f.write(data);f.flush()
   if timestamps is not None:os.utime(f.fileno(),ns=timestamps)
   os.fsync(f.fileno())
  if not same_identity(read_file(p),expected):raise Refused('pre-replace identity drift')
  os.replace(p.parent/name,p);d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
 finally:
  try:(p.parent/name).unlink()
  except FileNotFoundError:pass
 after=read_file(p)
 if bytes_of(after)!=data or after['mode']!=mode or after['gid']!=gid:raise Refused('write verification')
 return after
