"""Memory-only package loader for a root-owned fixed module capsule."""
import hashlib
import importlib.abc
import importlib.util
import os
from pathlib import Path
import stat
import sys

ROOT=Path('/usr/local/libexec/tu1nz-root-only-v9')
NAMES=frozenset(('policy_v9','audit_v9','probes_v9','transaction_v9','files_v9','command_v9','contracts_v9','runtime_v9','graph_v9','verification_v9','namespaces_v9','host_v9','candidates_v9','lifecycle_v9','sudo_candidate_v9','tu1nz_codex_broker_v9','prepare_v9','entry_v9','loader_v9','public_v9'))


def protected_read(path,limit=8_000_000):
 p=Path(path)
 for part in list(reversed(p.parents))+[p]:
  s=part.lstat()
  if stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('root capsule metadata')
  if any('posix_acl' in x for x in os.listxattr(part)):raise RuntimeError('root capsule ACL')
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise RuntimeError('root capsule file type')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  b=os.fstat(f.fileno());data=f.read(limit+1);a=os.fstat(f.fileno())
 if (s.st_dev,s.st_ino)!=(b.st_dev,b.st_ino) or (b.st_size,b.st_mtime_ns,b.st_ctime_ns)!=(a.st_size,a.st_mtime_ns,a.st_ctime_ns) or len(data)>limit:raise RuntimeError('root capsule drift')
 return data

class Loader(importlib.abc.MetaPathFinder,importlib.abc.Loader):
 def __init__(self,sources):
  if set(sources)!=NAMES:raise RuntimeError('capsule module coverage')
  self.sources=sources
 def find_spec(self,fullname,path=None,target=None):
  if fullname in self.sources:return importlib.util.spec_from_loader(fullname,self,origin=str(ROOT/(fullname+'.py')))
  return None
 def create_module(self,spec):return None
 def exec_module(self,module):
  name=module.__name__;module.__file__=str(ROOT/(name+'.py'))
  exec(compile(self.sources[name],module.__file__,'exec',dont_inherit=True),module.__dict__)


def install(hashes):
 if os.geteuid()!=0 or set(hashes)!=NAMES:raise RuntimeError('root capsule manifest')
 sources={}
 for name in sorted(NAMES):
  raw=protected_read(ROOT/(name+'.py'))
  if hashlib.sha256(raw).hexdigest()!=hashes[name]:raise RuntimeError('root capsule checksum')
  sources[name]=raw
 loader=Loader(sources);sys.dont_write_bytecode=True;sys.meta_path.insert(0,loader)
 return loader
