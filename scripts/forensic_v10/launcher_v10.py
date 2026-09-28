"""Fixed read-only collector launcher; inert on import; no writes of its own."""
import hashlib
import os
from pathlib import Path
import stat
import sys

COLLECTOR_PATH='/opt/tu1nz_repos/worktrees/codex-privileged-ops-2026-09-27/scripts/forensic_v10/collector_v10.py'
COLLECTOR_SHA256='214aaa592b8d1d75f22a1a380e7186d699cc910386ef7bfed6b5a3cbb7d4a8ed'

def verified_bytes(path,expected):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|getattr(os,'O_NOATIME',0))
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno())
  if not stat.S_ISREG(st.st_mode) or st.st_size>500000:raise RuntimeError('source type or bound')
  data=f.read(500001)
 if hashlib.sha256(data).hexdigest()!=expected:raise RuntimeError('source digest mismatch')
 return data

def main():
 if os.geteuid()!=0 or not sys.dont_write_bytecode or sys.argv[1:]:raise RuntimeError('fixed root entry only')
 raw=verified_bytes(COLLECTOR_PATH,COLLECTOR_SHA256)
 ns={'__name__':'__main__','__file__':COLLECTOR_PATH,'VERIFIED_SOURCE_SHA256':COLLECTOR_SHA256}
 exec(compile(raw,COLLECTOR_PATH,'exec',dont_inherit=True),ns)

if __name__=='__main__':main()
