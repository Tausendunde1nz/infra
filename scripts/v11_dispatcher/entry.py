"""Root-only entry prelude, prepended to statically embedded modules."""
import os,sys,json,hashlib,stat,re
from pathlib import Path
BASE='/usr/local/libexec/tu1nz-v11-dispatcher'
MANIFEST='/etc/tu1nz/v11-dispatcher/manifest.json'
def trusted(path,mode):
 p=Path(path);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for i,name in enumerate(p.parts[1:]):
   last=i==len(p.parts)-2;n=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|(0 if last else os.O_DIRECTORY),dir_fd=fd);os.close(fd);fd=n;s=os.fstat(fd)
   if s.st_uid!=0 or s.st_gid!=0 or s.st_mode&0o022 or os.listxattr(fd):raise RuntimeError('UNTRUSTED_PATH')
  if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=mode:raise RuntimeError('FILE_METADATA')
  raw=os.read(fd,8000001)
  if len(raw)>8000000:raise RuntimeError('SIZE')
  return raw
 finally:os.close(fd)
def checked_manifest(pin,own):
 if os.geteuid()!=0 or not sys.flags.isolated or not sys.dont_write_bytecode or not re.fullmatch('[a-f0-9]{64}',pin):raise RuntimeError('ROOT_ISOLATION_PIN')
 raw=trusted(MANIFEST,0o400)
 if hashlib.sha256(raw).hexdigest()!=pin:raise RuntimeError('MANIFEST_HASH')
 m=json.loads(raw)
 if set(m)!= {'schema','basis','binding','artifacts','unit_templates','production_admitted'} or m['schema']!=1 or set(m['artifacts'])!={'dispatcher.py','watchdog.py','installer.py'}:raise RuntimeError('MANIFEST_SCHEMA')
 if m['production_admitted'] is not True:raise RuntimeError('PRODUCTION_ADMISSION_CLOSED')
 for name,want in m['artifacts'].items():
  if hashlib.sha256(trusted(BASE+'/'+name,0o500)).hexdigest()!=want:raise RuntimeError('ARTIFACT_HASH')
 if str(Path(sys.argv[0]))!=BASE+'/'+own:raise RuntimeError('ENTRY_PATH')
 os.environ.clear();os.environ.update({'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/var/empty'});os.umask(0o077)
 return m
