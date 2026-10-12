"""Fresh-process native scenarios on a newly allocated private ext4 fixture.

Keys/data are SYNTHETIC, not real operator credentials. The model covers
inode/namespace writers, not kernel/raw backing-device administrators.
Never mount historical/server paths or repeat the blocked systemd experiment.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import zlib
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_control_recovery_contract as c
import tu1nz_control_recovery as r
import tu1nz_control_recovery_authority as a
from tu1nz_control_recovery_release import build_capsule


def command(*argv,cwd=None):
    result=subprocess.run(argv,cwd=cwd,capture_output=True,timeout=10,
                          env={**os.environ,'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null'})
    assert result.returncode==0,(argv[0],result.returncode,result.stderr.decode())
    return result.stdout


def init_repo(path,url,text):
    path.mkdir();command('git','init','-q',str(path))
    command('git','config','user.name','Synthetic',cwd=path)
    command('git','config','user.email','synthetic@example.invalid',cwd=path)
    command('git','remote','add','origin',url,cwd=path)
    (path/'tracked.txt').write_text(text)
    (path/'nested').mkdir();(path/'nested'/'tool.sh').write_text('#!/bin/sh\nexit 0\n')
    (path/'nested'/'tool.sh').chmod(0o755)
    command('git','add','.',cwd=path);command('git','commit','-qm','Synthetic source',cwd=path)
    commit=command('git','rev-parse','HEAD',cwd=path).decode().strip()
    tree=command('git','rev-parse','HEAD^{tree}',cwd=path).decode().strip()
    return commit,tree


def fixture(base):
    assert os.geteuid()==0 and os.environ.get('container')=='docker'
    base.mkdir();parent=base/'parent';parent.mkdir()
    historical=parent/'control'
    commit,tree=init_repo(historical,'https://github.com/Tausendunde1nz/infra','historical bytes\n')
    (historical/'.git').rename(historical/'.git.s12-1-recovery')
    (historical/'.git').mkdir();(historical/'.git').chmod(0)
    os.chown(historical,0,1001);historical.chmod(0o2550)
    (historical/'private-unversioned.txt').write_bytes(b'SYNTHETIC UNTRACKED KEEP\n')
    (historical/'relative-link').symlink_to('tracked.txt')
    key=base/'synthetic-key.pem'
    command('openssl','genpkey','-algorithm','ED25519','-out',str(key));key.chmod(0o400)
    public=command('openssl','pkey','-in',str(key),'-pubout')
    target_repo=base/'target-input'
    target_commit,target_tree=init_repo(target_repo,c.TARGET['repository'],'new target bytes\n')
    spec={'repository':c.TARGET['repository'],'commit':target_commit,'tree':target_tree}
    capsule=c.Capsule(build_capsule(target_repo,spec),spec)
    app=parent/'application';app.mkdir();(app/'.git').mkdir();(app/'.git').chmod(0)
    (app/'keep.txt').write_text('SYNTHETIC APPLICATION KEEP\n')
    (app/'nested').mkdir();(app/'nested/keep.txt').write_text('SYNTHETIC DEEP APPLICATION KEEP\n')
    state=base/'state';state.mkdir();aborted=state/'aborted.json';aborted.write_bytes(b'{"phase":"ABORTED","cause":"UNKNOWN"}\n')
    absent=state/'r15-absent.json'
    layout=c.Layout(historical,parent/'control-only-recovery-r1',(app,app/'.git',aborted,absent),
        r.identity(historical),r.identity(historical/'.git'),r.identity(historical/'.git.s12-1-recovery'),
        c.digest(Path('/etc/machine-id').read_bytes()),commit,tree,{str(aborted):c.digest(aborted.read_bytes())})
    authority=base/'synthetic-authority';mirror=base/'synthetic-authority-mirror'
    authority.mkdir(mode=0o700);mirror.mkdir(mode=0o700)
    return layout,capsule,key,public,authority,mirror


def scenario(base,name):
    layout,capsule,key,public,authority,mirror=fixture(base)
    if name=='entry':
        import io
        from tu1nz_control_recovery_entry import serve
        writer=io.BytesIO()
        a.spend_before_dispatch(authority,mirror,release={'synthetic':True})
        class Reader:
            calls=0
            def readline(self,bound):
                assert bound==65537 and self.calls==0;self.calls+=1
                hello=json.loads(writer.getvalue())
                assert hello['schema']==c.SCHEMA+'_HELLO'
                self.grant=a.sign_for_dispatched_session(hello['body'],key,authority,mirror,target=capsule.target)
                return c.canonical(self.grant)+b'\n'
        reader=Reader()
        assert serve(capsule,public,layout=layout,reader=reader,writer=writer)==0
        hello,result=map(json.loads,writer.getvalue().splitlines())
        assert result['accepted'] and reader.calls==1
        a.accept_final(result,reader.grant,authority,mirror)
        r.verify_completed_view(layout,capsule,reader.grant,public)
        return {'passed':True,'entry_calls':1,'host_calls':0,'synthetic_protocol_only':True}
    original={(str(p.relative_to(layout.historical))):p.read_bytes() for p in layout.historical.rglob('*')
              if p.is_file() and not p.is_symlink()}
    before=r.preserved_state(layout)
    writer=None;retained=None
    if name=='source-origin':
        config=layout.historical/'.git.s12-1-recovery/config'
        config.write_text(config.read_text().replace('https://github.com/Tausendunde1nz/infra','https://example.invalid/wrong'))
    if name=='missing-worktree':(layout.historical/'tracked.txt').unlink()
    if name=='bad-index':(layout.historical/'.git.s12-1-recovery/index').write_bytes(b'CORRUPT')
    if name in ('missing-head-subtree','corrupt-head-subtree'):
        gitdir=layout.historical/'.git.s12-1-recovery'
        child=command('git','--git-dir',str(gitdir),'rev-parse',layout.old_commit+':nested').decode().strip()
        object_path=gitdir/'objects'/child[:2]/child[2:]
        if name=='missing-head-subtree':object_path.rename(object_path.with_name(object_path.name+'-preserved'))
        else:
            raw=b'100644 different.txt\0'+bytes.fromhex('a'*40)
            object_path.write_bytes(zlib.compress(b'tree '+str(len(raw)).encode()+b'\0'+raw))
    if name=='hardlinks':os.link(layout.historical/'private-unversioned.txt',layout.historical/'private-alias.txt')
    if name=='large-stock':
        (layout.historical/'synthetic-unversioned').mkdir()
        for number in range(1600):
            (layout.historical/'synthetic-unversioned'/str(number)).write_bytes(('SYNTHETIC '+str(number)+'\n').encode())
    if name=='writer':retained=os.open(layout.historical/'tracked.txt',os.O_RDWR)
    if name=='acl':
        # Effective write permission is NOT trusted; the kernel fence and
        # exact raw ACL readback/restore must remain operative.
        command('setfacl','-m','u:1002:rw-,m::rw-',str(layout.historical/'tracked.txt'))
        command('setfacl','-d','-m','u:1002:rwx,m::rwx',str(layout.historical/'nested'))
    if name=='existing-anchor':layout.anchor.mkdir()
    try:session=r.Session(layout,capsule)
    except c.RecoveryError:
        assert name=='existing-anchor';assert layout.anchor.is_dir()
        return {'case':name,'outcome':'DENIED_BEFORE_MUTATION','passed':True}
    a.spend_before_dispatch(authority,mirror,release={'synthetic':True,'capsule_sha256':capsule.sha256})
    grant=a.sign_for_dispatched_session(session.body,key,authority,mirror,target=capsule.target)
    if name=='wrong-signature':grant['signature']=base64.b64encode(b'x'*64).decode()
    if name=='wrong-target':grant['body']={**grant['body'],'target':{**capsule.target,'commit':'f'*40}}
    def capless(code,*args):
        return command('setpriv','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',
                       sys.executable,'-I','-B','-c',code,*map(str,args))
    def boundary(phase):
        if name=='competing-anchor' and phase=='BEFORE_CLAIM':
            layout.anchor.mkdir();(layout.anchor/'FOREIGN').write_text('KEEP')
        if name=='application-change' and phase=='BACKUP_READBACK':
            (layout.preserved[0]/'nested/keep.txt').chmod(0o600)
        if name=='multiple-errors' and phase=='RECEIPT_WRITTEN':
            (layout.anchor/'journal/denied.json').write_bytes(b'FOREIGN KEEP')
            (layout.historical/'tracked.txt').chmod(0o600)
            raise KeyboardInterrupt()
        if name=='ancestor-replay' and phase=='CLAIM_DURABLE':raise KeyboardInterrupt()
        if name=='capless-metadata' and phase=='BACKUP_READBACK':
            capless('''import os,sys
assert os.geteuid()==0
assert next(x for x in open('/proc/self/status') if x.startswith('CapEff:')).split()[1]=='0000000000000000'
os.chmod(sys.argv[1],0o600);os.chmod(sys.argv[1],0o644)
''',layout.historical/'tracked.txt')
        if name.startswith('interrupt-') and phase==name[len('interrupt-'):]:raise KeyboardInterrupt()
        if name=='namespace-source' and phase=='BACKUP_READBACK':
            source=layout.historical/'private-unversioned.txt';source.rename(layout.historical/'renamed-foreign.txt')
        if name=='extra-output' and phase=='BACKUP_READBACK':
            (layout.anchor/'release'/'unknown.txt').write_bytes(b'FOREIGN KEEP')
        if name=='corrupt-backup' and phase=='BACKUP_READBACK':
            backup=layout.anchor/'backup/data'
            blob=next(p for p in backup.iterdir() if p.name!='manifest.json')
            fd=os.open(blob,os.O_RDONLY);r.set_flags(fd,r.flags(fd)&~r.IMMUTABLE);os.close(fd)
            blob.write_bytes(b'DAMAGED')
        if name=='marker-change' and phase=='RESTORE_TESTED':
            (base/'state/r15-absent.json').write_text('SYNTHETIC UNEXPECTED MARKER')
        if name=='metadata-aba' and phase=='BACKUP_READBACK':
            path=layout.historical/'tracked.txt';path.chmod(0o600);path.chmod(0o644)
    result=r.recover_view(layout,capsule,session,grant,public,boundary=boundary)
    if retained is not None:os.close(retained)
    success=name in ('success','large-stock','hardlinks','acl','lost-confirmation','capless-sealed','revoke','revoke-failure',
                     'late-completion-failure','missing-completion','completion-drift')
    if name=='interrupt-COMPLETION_WRITTEN':
        assert result['primary'] is None and result['cleanup'] and not result['accepted'],result
    assert result['accepted']==success,json.dumps(result,sort_keys=True)
    assert result['historical_mutated'] is False and result['consumer_activation'] is False
    assert result['fd_baseline_restored'],result
    if name not in ('marker-change',):assert r.preserved_state(layout)==before
    if success:
        release=layout.anchor/'release'
        assert command('git','--no-optional-locks','-c','safe.directory='+str(release),'-C',str(release),
                       'rev-parse','HEAD').decode().strip()==capsule.target['commit']
        assert command('git','--no-optional-locks','-c','safe.directory='+str(release),'-C',str(release),
                       'status','--porcelain=v1','--untracked-files=all')==b''
        assert command('git','-c','safe.directory='+str(release),'-C',str(release),'fsck','--strict')==b''
        assert (layout.historical/'.git').stat().st_mode&0o777==0
        assert (layout.historical/'private-unversioned.txt').read_bytes()==b'SYNTHETIC UNTRACKED KEEP\n'
        assert (layout.anchor/'journal/completion.json').is_file()
        r.verify_completed_view(layout,capsule,grant,public)
        if name!='lost-confirmation':
            a.accept_final(result,grant,authority,mirror)
            assert a.read_acceptance(authority,mirror)['deployment_authority'] is False
        else:
            try:a.read_acceptance(authority,mirror)
            except FileNotFoundError:pass
            else:raise AssertionError('lost reply inferred from host completion')
        if name in ('missing-completion','completion-drift'):
            file=layout.anchor/'journal/completion.json'
            fd=os.open(file,os.O_RDONLY);r.set_flags(fd,r.flags(fd)&~r.IMMUTABLE);os.close(fd)
            if name=='missing-completion':file.rename(file.with_name('preserved-orphan.json'))
            else:file.write_bytes(b'{}')
            try:r.verify_completed_view(layout,capsule,grant,public)
            except (c.RecoveryError,FileNotFoundError):pass
            else:raise AssertionError('invalid completion accepted')
        if name=='late-completion-failure':
            denied={**result,'accepted':False,'cleanup':[{'code':'UNKNOWN','errno':5}]}
            try:a.accept_final(denied,grant,authority,mirror)
            except c.RecoveryError:pass
            else:raise AssertionError('late cleanup error accepted')
        if name in ('revoke','revoke-failure'):
            if name=='revoke':a.revoke_acceptance(authority,mirror)
            else:
                real_new=a.new
                def fail_mirror(path,raw):
                    if path.parent==mirror and path.name.endswith('.revoked.json'):raise OSError(5,'synthetic')
                    real_new(path,raw)
                with patch.object(a,'new',fail_mirror):
                    try:a.revoke_acceptance(authority,mirror)
                    except OSError:pass
                    else:raise AssertionError('missing fault')
            try:a.read_acceptance(authority,mirror)
            except c.RecoveryError:pass
            else:raise AssertionError('revoked view still accepted')
            assert (layout.historical/'private-unversioned.txt').read_bytes()==b'SYNTHETIC UNTRACKED KEEP\n'
        # A later invocation cannot mint another grant or bootstrap another view.
        try:a.spend_before_dispatch(authority,mirror,release={'synthetic':True})
        except c.RecoveryError:pass
        else:raise AssertionError('external spent slot reopened')
        try:r.Session(layout,capsule)
        except c.RecoveryError:pass
        else:raise AssertionError('host anchor adopted')
        if name=='capless-sealed':
            capless('''import errno,os,sys
assert os.geteuid()==0
assert next(x for x in open('/proc/self/status') if x.startswith('CapEff:')).split()[1]=='0000000000000000'
for kind,path in (('write',sys.argv[1]),('chmod',sys.argv[1]),('rename',sys.argv[2])):
 try:
  if kind=='write': fd=os.open(path,os.O_WRONLY|os.O_NONBLOCK);os.close(fd)
  elif kind=='chmod': os.chmod(path,0o777)
  else: os.rename(path,path+'-reused')
 except OSError as e: assert e.errno in (errno.EPERM,errno.EACCES)
 else: raise AssertionError('capless modification allowed')
''',release/'tracked.txt',layout.anchor)
    elif name not in ('wrong-target','wrong-signature','competing-anchor','interrupt-COMPLETION_WRITTEN'):
        assert result['slot_consumed']
        assert result['primary'] is not None
        assert result['accepted'] is False
    expected={
        'source-origin':'CONTROL_RECOVERY_HISTORICAL_ORIGIN_UNREGISTERED',
        'missing-worktree':'CONTROL_RECOVERY_WORKTREE_INCOMPLETE',
        'bad-index':'CONTROL_RECOVERY_INDEX_INVALID',
        'writer':'S8_EXECUTION_HISTORICAL_WRITER_EXCLUSION_UNAVAILABLE',
        'namespace-source':'S8_EXECUTION_HISTORICAL_READ_CHANGED',
        'extra-output':'CONTROL_RECOVERY_FOREIGN_OUTPUT',
        'corrupt-backup':'CONTROL_RECOVERY_BACKUP_CORRUPT',
        'marker-change':'S8_EXECUTION_HISTORICAL_READ_CHANGED',
        'metadata-aba':'S8_EXECUTION_HISTORICAL_READ_CHANGED',
        'wrong-target':'CONTROL_RECOVERY_GRANT_BINDING_RED',
        'wrong-signature':'CONTROL_RECOVERY_GRANT_SIGNATURE_RED',
        'capless-metadata':'S8_EXECUTION_HISTORICAL_READ_CHANGED',
        'application-change':'S8_EXECUTION_HISTORICAL_READ_CHANGED',
        'missing-head-subtree':'S8_EXECUTION_HISTORICAL_READ_UNAVAILABLE',
        'corrupt-head-subtree':'S8_EXECUTION_HISTORICAL_CONTENT_RED',
    }
    if name in expected:assert result['primary']['code']==expected[name],result
    if name.startswith('interrupt-') and name!='interrupt-COMPLETION_WRITTEN':
        assert result['phase']==name[len('interrupt-'):] and result['primary']['type']=='KeyboardInterrupt',result
    if name=='extra-output':assert (layout.anchor/'release/unknown.txt').read_bytes()==b'FOREIGN KEEP'
    if name=='competing-anchor':
        assert not result['slot_consumed'] and result['primary']['errno']==17
        assert (layout.anchor/'FOREIGN').read_text()=='KEEP'
    if name=='multiple-errors':
        assert result['primary']['type']=='KeyboardInterrupt' and result['abort'] is not None and result['cleanup']
        assert (layout.anchor/'journal/denied.json').read_bytes()==b'FOREIGN KEEP'
    if name=='ancestor-replay':
        parent=layout.historical.parent;moved=parent.with_name('parent-moved')
        capless('''import os,sys
assert os.geteuid()==0
assert next(x for x in open('/proc/self/status') if x.startswith('CapEff:')).split()[1]=='0000000000000000'
old,moved=sys.argv[1:];os.rename(old,moved);os.mkdir(old)
os.chmod(moved+'/control',0o750)
os.rename(moved+'/control',old+'/control')
os.chmod(old+'/control',0o2550)
''',parent,moved)
        # Historical leaf inode is STILL the same: leaf identity alone would
        # not be durable admission. The old signed session and client slot deny.
        assert r.identity(layout.historical)==layout.pin
        fresh=r.Session(layout,capsule)
        rejected=r.recover_view(layout,capsule,fresh,grant,public)
        assert not rejected['accepted'] and not rejected['slot_consumed']
        assert rejected['primary']['code']=='CONTROL_RECOVERY_GRANT_BINDING_RED'
        assert not layout.anchor.exists()
        try:a.sign_for_dispatched_session(fresh.body,key,authority,mirror,target=capsule.target)
        except c.RecoveryError:pass
        else:raise AssertionError('new session grant after ancestor/name reuse')
    return {'case':name,'passed':True,'view_ready':result['accepted'],
            'primary':result['primary'],'abort':result['abort'],'cleanup':result['cleanup'],
            'slot_consumed':result['slot_consumed'],'historical_own_mutation':False,
            'real_provider_actions':0,'production_host_acceptance':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--case',required=True);parser.add_argument('--base',type=Path,required=True)
    args=parser.parse_args()
    value=scenario(args.base,args.case)
    print(json.dumps(value,sort_keys=True))
