"""Nonprivileged deterministic renderer. Produces one SSH / one sudo command."""
import hashlib
import shlex

SOURCE='/opt/tu1nz_repos/worktrees/codex-privileged-ops-2026-09-27/scripts/v11_untracked_impact/collector.py'
def build(bootstrap,bootstrap_sha,collector_sha):
 if hashlib.sha256(bootstrap).hexdigest()!=bootstrap_sha:raise ValueError('BOOTSTRAP_HASH')
 if len(collector_sha)!=64 or any(x not in '0123456789abcdef' for x in collector_sha):raise ValueError('COLLECTOR_HASH')
 remote=shlex.join(['sudo','/usr/bin/python3','-I','-B','-c',bootstrap.decode(),SOURCE,collector_sha])
 return shlex.join(['ssh','-tt','-F','/dev/null','-p','2222','-o','HostKeyAlias=100.121.130.51','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','chatops@100.121.130.51',remote])
