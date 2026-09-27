"""Generate, but never run, one root-private V5 collection command."""
import base64
import hashlib
import re
import shlex
WORKTREE='/opt/tu1nz_repos/worktrees/codex-privileged-ops-2026-09-27'

def build(script,commit):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('commit')
    compile(script,'<root-trust-v5>','exec')
    digest=hashlib.sha256(script).hexdigest();payload=base64.b64encode(script).decode()
    root=("import base64,hashlib,sys;d=base64.b64decode("+repr(payload)+",validate=True);"
          "assert hashlib.sha256(d).hexdigest()=="+repr(digest)+";"
          "sys.argv=['root-trust-v5'];exec(compile(d,'<hash-bound-root-trust-v5>','exec'),"
          "{'__name__':'__main__','_VERIFIED_SOURCE_SHA256':hashlib.sha256(d).hexdigest()})")
    remote=("import subprocess,hashlib,pathlib,sys;w="+repr(WORKTREE)+";"
            "assert subprocess.check_output(['/usr/bin/git','-C',w,'rev-parse','HEAD'],text=True).strip()=="+repr(commit)+";"
            "d=(pathlib.Path(w)/'scripts/tu1nz_root_trust_v5.py').read_bytes();"
            "assert hashlib.sha256(d).hexdigest()=="+repr(digest)+";"
            "sys.exit(subprocess.call(['/usr/bin/sudo','--','/usr/bin/python3','-I','-S','-c',"+repr(root)+"]))")
    argv=['/usr/bin/ssh','-tt','-F','/dev/null','-p','2222','-o','HostKeyAlias=100.121.130.51','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','BatchMode=yes','chatops@100.121.130.51','/usr/bin/python3 -I -S -c '+shlex.quote(remote)]
    return {'sha256':digest,'commit':commit,'argv':argv}
