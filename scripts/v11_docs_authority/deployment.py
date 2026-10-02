"""New dedicated Control candidate only. Never touches old shared Gitdir or consumers."""
import os,subprocess
from manifest import Refused
TARGET='/opt/tu1nz_repos/control-deployment-v11-candidate'
COMMIT='05b127033d734aa4abce10b2e5b7d513b99ed5d2'
TREE='5459b09c4f986ac947dff1466b490a61238cb676'
ORIGIN='git@github.com:Tausendunde1nz/control.git'
PREFIX=('/usr/sbin/runuser','-u','chatops','--','/usr/bin/env','-i','HOME=/home/chatops','PATH=/usr/bin:/bin','GIT_OPTIONAL_LOCKS=0','GIT_CONFIG_NOSYSTEM=1','GIT_CONFIG_GLOBAL=/dev/null')
GIT=('/usr/bin/git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','safe.directory='+TARGET)
OPERATIONS=(PREFIX+GIT+('init','--',TARGET),PREFIX+GIT+('-C',TARGET,'remote','add','origin',ORIGIN),PREFIX+GIT+('-C',TARGET,'fetch','--no-tags','--depth=1','origin',COMMIT),PREFIX+GIT+('-C',TARGET,'-c','advice.detachedHead=false','checkout','--detach',COMMIT),PREFIX+('/usr/bin/chmod','0600',TARGET+'/.git/index'),PREFIX+GIT+('-C',TARGET,'rev-parse','HEAD'),PREFIX+GIT+('-C',TARGET,'rev-parse','HEAD^{tree}'))
def execute(argv):
 if os.geteuid()!=0 or tuple(argv) not in OPERATIONS:raise Refused('FIXED_GIT_CANDIDATE_OPERATION')
 p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},cwd='/',timeout=180)
 if p.returncode or len(p.stdout)>100000:raise Refused('CANDIDATE_GIT_FAILED')
 return p.stdout.decode().strip()
class Adapter:
 def __init__(self,files,journal,run=execute):self.files=files;self.journal=journal;self.run=run
 def stage(self):
  # Backend checks exact new parent, source pin and no preexisting candidate BEFORE init.
  original=self.files.verify_original_control_unchanged()
  self.files.verify_new_candidate_absent(TARGET)
  self.journal.intent('DEDICATED_CONTROL_CANDIDATE',{'target':TARGET,'original':original},sealed=False)
  for op in OPERATIONS[:5]:self.run(op)
  if self.run(OPERATIONS[5])!=COMMIT or self.run(OPERATIONS[6])!=TREE:raise Refused('PIN_MISMATCH')
  self.files.verify_candidate_tree_bytes_index(TARGET,COMMIT,TREE,1001,1001,0o600)
  self.files.verify_no_alternates_or_shared_gitdir(TARGET)
  if self.files.verify_original_control_unchanged()!=original:raise Refused('ORIGINAL_DRIFT')
  self.journal.verified('DEDICATED_CONTROL_CANDIDATE')
  # No automatic deployment/publishing switch. Explicit consumer migration is separate.
