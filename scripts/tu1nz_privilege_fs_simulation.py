"""Isolated filesystem rollback laboratory. No live adapter and no CLI.
Only accepts a newly empty, user-owned 0700 directory with a fixture prefix.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat


def sha(data):return hashlib.sha256(data).hexdigest()


class Laboratory:
    def __init__(self,root):
        self.root=Path(root)
        s=self.root.lstat()
        if self.root.is_symlink() or not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:
            raise ValueError('unsafe_lab')
        if not self.root.name.startswith('privilege-fixture-') or list(self.root.iterdir()):raise ValueError('not_empty_fixture')
        self.tree=self.root/'tree';self.tree.mkdir(mode=0o700)
        self.original=None;self.services={'core':'active','landing':'active','telegram':'active','wms':'active'}
        self.events=[];self.watchdog=False

    def path(self,name):
        p=Path(name)
        if p.is_absolute() or '..' in p.parts:raise ValueError('escape')
        result=self.tree/p
        for ancestor in result.parents:
            if ancestor==self.tree:break
            if ancestor.is_symlink():raise ValueError('symlink_ancestor')
        return result

    def fixture(self):
        for d in ('etc','etc/sudoers.d','etc/polkit-1','etc/systemd','usr','usr/local','usr/local/sbin','state'):
            self.path(d).mkdir(mode=0o750)
        data={'etc/sudoers':b'root ALL=(ALL:ALL) ALL\nchatops OLD_GRANT\n',
              'etc/sudoers.d/legacy':b'old exact rule\n','etc/polkit-1/rule':b'old fixture policy\n',
              'etc/group':b'docker:x:987:chatops\n','etc/gshadow':b'docker:!:chatops:chatops\n',
              'etc/systemd/core.service':b'User=chatops\n','state/state.json':b'{"ready":true}\n'}
        for name,content in data.items():self.path(name).write_bytes(content);self.path(name).chmod(0o640)
        self.path('etc/systemd/alias.service').symlink_to('core.service')

    def snapshot(self):
        result={}
        for p in sorted(self.tree.rglob('*')):
            s=p.lstat();entry={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'mtime_ns':s.st_mtime_ns}
            if p.is_symlink():entry.update(kind='link',target=os.readlink(p))
            elif p.is_dir():entry['kind']='directory'
            else:
                data=p.read_bytes();entry.update(kind='file',data=base64.b64encode(data).decode(),sha256=sha(data))
            entry['xattrs']={n:base64.b64encode(os.getxattr(p,n,follow_symlinks=False)).decode() for n in os.listxattr(p,follow_symlinks=False)}
            result[str(p.relative_to(self.tree))]=entry
        return result

    def backup(self):
        self.original=self.snapshot();self.service_backup=dict(self.services)
        p=self.root/'before.json';p.write_text(json.dumps(self.original,sort_keys=True));p.chmod(0o600)
        self.before_sha=sha(p.read_bytes())

    def restore(self):
        if sha((self.root/'before.json').read_bytes())!=self.before_sha:raise ValueError('backup_corruption')
        # Only the private fixture tree can be affected; never follow links.
        for p in sorted(self.tree.rglob('*'),key=lambda p:len(p.parts),reverse=True):
            if p.is_symlink() or not p.is_dir():p.unlink()
            else:p.rmdir()
        for name,e in sorted(self.original.items(),key=lambda x:len(Path(x[0]).parts)):
            p=self.path(name)
            if e['kind']=='directory':p.mkdir(mode=0o700)
            elif e['kind']=='link':p.symlink_to(e['target'])
            else:
                data=base64.b64decode(e['data'])
                if sha(data)!=e['sha256']:raise ValueError('data_corruption')
                p.write_bytes(data)
        # Children first: restrictive ACLs/modes must not prevent restoring descendants.
        for name,e in sorted(self.original.items(),key=lambda x:len(Path(x[0]).parts),reverse=True):
            p=self.path(name)
            for n in os.listxattr(p,follow_symlinks=False):os.removexattr(p,n,follow_symlinks=False)
            for n,v in e['xattrs'].items():os.setxattr(p,n,base64.b64decode(v),follow_symlinks=False)
            if e['kind']!='link':os.chmod(p,e['mode'])
            os.utime(p,ns=(p.lstat().st_atime_ns,e['mtime_ns']),follow_symlinks=False)
            if p.lstat().st_uid!=e['uid'] or p.lstat().st_gid!=e['gid']:raise ValueError('ownership_not_reproducible')
        self.services=dict(self.service_backup)
        if self.snapshot()!=self.original:raise ValueError('restore_mismatch')
        self.watchdog=False

    def execute(self,fail=None):
        if self.original is None:raise ValueError('no_backup')
        if self.snapshot()!=self.original:raise ValueError('unexpected_baseline')
        steps=('broker','sudoers','polkit','group','unit','services','ssh','finalize')
        self.watchdog=True
        try:
            for step in steps:
                if fail=='before:'+step:raise RuntimeError('injected')
                if step=='broker':self.path('usr/local/sbin/broker').write_bytes(b'fixture broker')
                elif step=='sudoers':self.path('etc/sudoers').write_bytes(b'reviewed fixture candidate');self.path('etc/sudoers.d/legacy').unlink()
                elif step=='polkit':self.path('etc/polkit-1/rule').write_bytes(b'fixture deny')
                elif step=='group':self.path('etc/group').write_bytes(b'docker:x:987:\n');self.path('etc/gshadow').write_bytes(b'docker:!::\n')
                elif step=='unit':self.path('etc/systemd/alias.service').unlink();self.path('etc/systemd/alias.service').symlink_to('new-target.service')
                elif step=='services':
                    for name in ('wms','telegram','landing','core'):self.services[name]='inactive';self.events.append('stop:'+name)
                    for name in ('core','landing','telegram','wms'):
                        if fail=='service:'+name:raise RuntimeError('service_failure')
                        self.services[name]='active';self.events.append('start:'+name)
                elif step=='ssh' and fail=='disconnect':raise ConnectionError('lost_ssh')
                elif step=='finalize':self.watchdog=False
                if fail in ('after:'+step,'watchdog:'+step):raise RuntimeError('injected')
        except (RuntimeError,ConnectionError):
            self.restore();return 'ROLLED_BACK_FIXTURE'
        return 'FIXTURE_SUCCESS'
