"""Build one inert, hash-bound reader command. Never executes it."""
import base64
import hashlib
import re
import shlex

WORKTREE = '/opt/tu1nz_repos/worktrees/codex-privileged-ops-2026-09-27'


def build(script, commit):
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('commit')
    compile(script, '<reviewed-readonly-v4>', 'exec')
    digest = hashlib.sha256(script).hexdigest()
    payload = base64.b64encode(script).decode()
    root = ("import base64,hashlib,sys;"
            "d=base64.b64decode(" + repr(payload) + ",validate=True);"
            "assert hashlib.sha256(d).hexdigest()==" + repr(digest) + ";"
            "sys.argv=['tu1nz-privilege-readonly-v4'];"
            "exec(compile(d,'<hash-bound-readonly-v4>','exec'),{'__name__':'__main__','_VERIFIED_SOURCE_SHA256':hashlib.sha256(d).hexdigest()})")
    remote = ("import subprocess,hashlib,pathlib,sys;"
              "w=" + repr(WORKTREE) + ";"
              "assert subprocess.check_output(['/usr/bin/git','-C',w,'rev-parse','HEAD'],text=True).strip()==" + repr(commit) + ";"
              "d=(pathlib.Path(w)/'scripts/tu1nz_privilege_readonly_v4.py').read_bytes();"
              "assert hashlib.sha256(d).hexdigest()==" + repr(digest) + ";"
              "sys.exit(subprocess.call(['/usr/bin/sudo','--','/usr/bin/python3','-I','-S','-c'," + repr(root) + "]))")
    command = ['/usr/bin/ssh', '-tt', '-F', '/dev/null', '-p', '2222',
               '-o', 'HostKeyAlias=100.121.130.51', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UpdateHostKeys=no', '-o', 'BatchMode=yes',
               'chatops@100.121.130.51', '/usr/bin/python3 -I -S -c ' + shlex.quote(remote)]
    return {'sha256': digest, 'commit': commit, 'argv': command,
            'shell_line': shlex.join(command)}
