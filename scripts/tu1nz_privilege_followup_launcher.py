"""Generate (never execute) the one-shot, pinned v3 SSH/sudo invocation."""
import re
import shlex


def generate(commit,sha):
 if not re.fullmatch('[a-f0-9]{40}',commit) or not re.fullmatch('[a-f0-9]{64}',sha):raise ValueError('binding')
 bootstrap='''import os,sys,subprocess,hashlib
w='/opt/tu1nz_repos/worktrees/codex-privileged-ops-2026-09-27'
expected=EXPECTED_COMMIT
sha=EXPECTED_SHA
if os.getuid()!=1001:raise SystemExit('Unexpected SSH user')
if subprocess.check_output(['/usr/bin/git','-C',w,'rev-parse','HEAD'],text=True).strip()!=expected:raise SystemExit('Commit mismatch; no sudo')
fd=os.open(w+'/scripts/tu1nz_privilege_followup_v3.py',os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as f:source=f.read(1048576)
if hashlib.sha256(source).hexdigest()!=sha:raise SystemExit('SHA mismatch; no sudo')
if subprocess.check_output(['/usr/bin/git','-C',w,'show',expected+':scripts/tu1nz_privilege_followup_v3.py'])!=source:raise SystemExit('Git source mismatch; no sudo')
pid=os.getpid()
with open('/proc/'+str(pid)+'/stat') as f:ticks=f.read().rsplit(')',1)[1].split()[19]
subject=str(pid)+','+ticks+',1001'
context={'__name__':'__main__','PINNED_COMMIT':expected,'PINNED_SHA':sha,'PINNED_SUBJECT':subject}
root_code='import hashlib; source='+repr(source)+'; assert hashlib.sha256(source).hexdigest()=='+repr(sha)+'; exec(compile(source,"<verified-followup-v3>","exec"),'+repr(context)+')'
sys.exit(subprocess.run(['/usr/bin/sudo','/usr/bin/python3','-I','-B','-c',root_code]).returncode)
'''.replace('EXPECTED_COMMIT',repr(commit)).replace('EXPECTED_SHA',repr(sha))
 compile(bootstrap,'bootstrap','exec')
 args=['/usr/bin/ssh','-tt','-F','/dev/null','-p','2222','-o','HostKeyAlias=100.121.130.51','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','chatops@100.121.130.51','/usr/bin/python3 -I -B -c '+shlex.quote(bootstrap)]
 return '#!/bin/sh\nexec '+shlex.join(args)+'\n'
