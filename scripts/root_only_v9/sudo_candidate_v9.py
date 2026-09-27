"""Versioned copy of the unchanged historical exact five-grant transformation."""
import hashlib
BASELINES={
 '/etc/sudoers':'7b68bd1a3e600364a35ef71bbccfc671735ff840c14ed0a15fad5cebd4020b47',
 '/etc/sudoers.d/99-dokuagent-pandoc':'485957ca0f803a4f02216ea12625aaa338513bc20195d739c76d9bd993bae97c',
 '/etc/sudoers.d/chatops-nopass':'c153102adf2f49433b89db411e87107cc8f2bda2a2c26c2da75cfecaab91388e'}
REMOVALS=(b'chatops ALL=(ALL) NOPASSWD: /usr/bin/tee -a /opt/docs/upload_log.txt',b'chatops ALL=(root) NOPASSWD: /opt/tu1nz_repos/infra/t1nz_create_golden.sh')
def prepare(originals):
 if set(originals)!=set(BASELINES):raise ValueError('path set')
 for p,h in BASELINES.items():
  if hashlib.sha256(originals[p]).hexdigest()!=h:raise ValueError('sudo baseline drift')
 lines=originals['/etc/sudoers'].splitlines(keepends=True)
 for r in REMOVALS:
  if sum(x.rstrip(b'\r\n')==r for x in lines)!=1:raise ValueError('grant count')
 return {'/etc/sudoers':b''.join(x for x in lines if x.rstrip(b'\r\n') not in REMOVALS),'/etc/sudoers.d/99-dokuagent-pandoc':None,'/etc/sudoers.d/chatops-nopass':None}
