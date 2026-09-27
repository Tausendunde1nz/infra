"""Pure byte transformation only. No file I/O, sudo, installer or broker grant."""
import hashlib
BASELINES = {
 '/etc/sudoers': '7b68bd1a3e600364a35ef71bbccfc671735ff840c14ed0a15fad5cebd4020b47',
 '/etc/sudoers.d/99-dokuagent-pandoc': '485957ca0f803a4f02216ea12625aaa338513bc20195d739c76d9bd993bae97c',
 '/etc/sudoers.d/chatops-nopass': 'c153102adf2f49433b89db411e87107cc8f2bda2a2c26c2da75cfecaab91388e',
}
REMOVALS = (
 b'chatops ALL=(ALL) NOPASSWD: /usr/bin/tee -a /opt/docs/upload_log.txt',
 b'chatops ALL=(root) NOPASSWD: /opt/tu1nz_repos/infra/t1nz_create_golden.sh',
)

def remove_exact_lines(data, lines):
    chunks=data.splitlines(keepends=True)
    for line in lines:
        if sum(c.rstrip(b'\r\n')==line for c in chunks)!=1:
            raise ValueError('missing_or_duplicate_grant')
    return b''.join(c for c in chunks if c.rstrip(b'\r\n') not in lines)

def prepare(originals):
    if set(originals)!=set(BASELINES):raise ValueError('path_set')
    for path,sha in BASELINES.items():
        if hashlib.sha256(originals[path]).hexdigest()!=sha:raise ValueError('baseline_drift')
    return {'/etc/sudoers':remove_exact_lines(originals['/etc/sudoers'],REMOVALS),
            '/etc/sudoers.d/99-dokuagent-pandoc':None,
            '/etc/sudoers.d/chatops-nopass':None}
