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
import tu1nz_control_recovery_governance as g


def governance_scenario(base,name):
    """Real pinned target preflight, synthetic Host/keys and private ext4 only.

    Synthetic library Layout is not a production CLI path override. Host
    release/signer authority is not inferred from this offline witness.
    """
    layout,_,key,public,authority,mirror=fixture(base)
    capsule=c.Capsule(Path(os.environ['TU1NZ_CONTROL_POLICY_CAPSULE']).read_bytes())
    source={'tag':g.FREEZE_TAG,'tag_object':'1'*40,'commit':'2'*40,'tree':'3'*40,
            'executor_sha256':'4'*64}
    if name=='governance-production-client':
        return production_client_case(base,layout,capsule,key,authority,mirror,source)
    if name in ('governance-policy-missing','governance-policy-tampered'):
        if name.endswith('missing'):del capsule.files['AGENTS.md']
        else:capsule.files['AGENTS.md']={**capsule.files['AGENTS.md'],'bytes':b'permissive policy'}
    if name=='governance-source-r1':source['tag']='control-only-recovery-source-freeze-r1'
    if name=='governance-source-incomplete':del source['executor_sha256']
    if name=='governance-host':layout=c.Layout(**{**layout.__dict__,'host':'f'*64})
    predenied=name in ('governance-policy-missing','governance-policy-tampered',
        'governance-source-r1','governance-source-incomplete','governance-host')
    try:session=r.Session(layout,capsule,source=source)
    except c.RecoveryError as error:
        assert predenied and not layout.anchor.exists(),str(error)
        assert not list(authority.iterdir()) and not list(mirror.iterdir())
        return {'case':name,'passed':True,'denied_before_mutation_and_spend':True,'error':str(error)}
    assert not predenied
    # Test key only, finite signed engine transaction. No operator key or
    # production signer/Host permission is involved in synthetic Layout.
    a.spend_before_dispatch(authority,mirror,release={'synthetic':True,'source_release':source})
    body=c.canonical(session.body);path=base/'synthetic-body.json';a.new(path,body)
    signature=command('openssl','pkeyutl','-sign','-inkey',str(key),'-rawin','-in',str(path))
    grant={'body':json.loads(body),'signature':base64.b64encode(signature).decode()}
    for parent in (authority,mirror):a.new(parent/(c.SLOT+'.grant.json'),c.canonical(grant))
    if name=='governance-bootstrap-changed':session.governance['reader']['uid']=1002
    if name=='governance-unsigned-user':grant['body']['governance']['reader']['uid']=1002
    if name=='governance-unsigned-path':grant['body']['governance']['cwd']='/wrong'
    before=r.preserved_state(layout)
    def boundary(phase):
        if name=='governance-interrupt' and phase=='CONTEXT_SEALED':raise KeyboardInterrupt()
        if phase=='CONTEXT_SEALED' and name in ('governance-override','governance-config'):
            path=layout.anchor/'governance-context'/('AGENTS.override.md' if name.endswith('override') else 'config.toml')
            fd=os.open(path.parent,os.O_RDONLY);r.set_flags(fd,r.flags(fd)&~r.IMMUTABLE);os.close(fd)
            path.write_bytes(b'FOREIGN KEEP')
        if phase=='CONTEXT_SEALED' and name=='governance-context-tampered':
            path=layout.anchor/'governance-context/AGENTS.md'
            fd=os.open(path,os.O_RDONLY);r.set_flags(fd,r.flags(fd)&~r.IMMUTABLE);os.close(fd)
            path.write_bytes(b'permissive policy')
    result=r.recover_view(layout,capsule,session,grant,public,boundary=boundary)
    success=name=='governance-success'
    assert result['accepted']==success,result
    assert r.preserved_state(layout)==before and result['historical_mutated'] is False
    assert result['fd_baseline_restored'],result
    if success:
        assert result['consumer']['governance']=='GREEN_ISOLATED_V1_1_CURRENT_NEW_CWD_ONLY'
        proof=result['consumer']['governance_binding']
        assert proof['transaction_sha256']==c.digest(body)
        a.accept_final(result,grant,authority,mirror)
        r.verify_completed_view(layout,capsule,grant,public)
        release=layout.anchor/'release'
        def drop():os.setgroups([1001]);os.setgid(1001);os.setuid(1001)
        # No isolated argument: a missing real global instruction layer is
        # still RED. The successful explicit invocation did not create it.
        env={'PATH':'/usr/bin:/bin','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null',
             'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'safe.directory','GIT_CONFIG_VALUE_0':str(release)}
        default=subprocess.run([sys.executable,'-I','-B',str(release/'governance/preflight.py'),
            '--cwd',str(release)],cwd=release,env=env,preexec_fn=drop,capture_output=True,timeout=10)
        assert default.returncode!=0 and b'missing global instruction layer' in default.stderr,default.stderr
    else:
        assert result['primary'] is not None,result
        if name in ('governance-bootstrap-changed','governance-unsigned-user','governance-unsigned-path'):
            assert not result['slot_consumed'] and not layout.anchor.exists(),result
        else:assert result['slot_consumed'],result
    try:a.spend_before_dispatch(authority,mirror,release={'new_freeze':'not_a_new_slot'})
    except c.RecoveryError:pass
    else:raise AssertionError('new freeze reopened same slot')
    return {'case':name,'passed':True,'accepted':result['accepted'],'primary':result['primary'],
            'abort':result['abort'],'cleanup':result['cleanup'],'synthetic_only':True}


def production_client_case(base,layout,capsule,key,authority,mirror,source):
    """Production branches, synthetic frozen IDs/key, no transport/Host call."""
    from tu1nz_control_recovery_entry import MODULES,PUBLIC_SHA,executor_digest
    root=Path(__file__).resolve().parents[1]
    modules={n:base64.b64encode((root/'scripts'/(n+'.py')).read_bytes()).decode() for n in MODULES}
    source={**source,'executor_sha256':executor_digest(modules)}
    value={'schema':c.SCHEMA+'_MEMORY_PACKET','source':source,'modules':modules,
        'public':base64.b64encode((root/'config/control-only-recovery/authority-ed25519.pub').read_bytes()).decode(),
        'capsule':base64.b64encode(capsule.raw).decode()}
    assert c.digest(base64.b64decode(value['public']))==PUBLIC_SHA
    plan=g.prepare(capsule,c.Layout.production(),source)
    release={'source_release':source,'capsule_sha256':capsule.sha256,
        'governance_intent_sha256':c.digest(c.canonical(g.intent(plan))),
        'host_gates':{'protected_current_read':'GREEN','tools_kernel_tcb':'GREEN',
        'writer_device_boundary':'GREEN','capacity_filesystem':'GREEN','public_and_consumer_baseline':'GREEN',
        'authenticated_isolated_bootstrap_intent':'GREEN','exact_host_scope_authorized':'GREEN'}}
    for defect in ('module','source','intent','old-packet'):
        data=json.loads(c.canonical(value));record=json.loads(c.canonical(release))
        if defect=='module':data['modules'][MODULES[0]]=base64.b64encode(b'changed').decode()
        if defect=='source':data['source']['tag_object']='9'*40
        if defect=='intent':record['governance_intent_sha256']='9'*64
        if defect=='old-packet':del data['source']
        packet=c.canonical(data);record['packet_sha256']=c.digest(packet)
        try:a.transport_once(lambda:(_ for _ in ()).throw(AssertionError('unauthorized launch')),packet,
                key,authority,mirror,release=record)
        except c.RecoveryError:pass
        else:raise AssertionError('invalid production bootstrap not rejected before spend')
        assert not list(authority.iterdir()) and not list(mirror.iterdir())
    # An exactly bound valid input gets only ONE synthetic factory call; a
    # lost outcome consumes forever. This does not contact the network.
    packet=c.canonical(value);release['packet_sha256']=c.digest(packet);calls=[]
    def factory():calls.append(1);raise RuntimeError('synthetic unavailable transport')
    result=a.transport_once(factory,packet,key,authority,mirror,release=release)
    assert not result['accepted'] and calls==[1]
    result=a.transport_once(factory,packet,key,authority,mirror,release=release)
    assert not result['accepted'] and calls==[1]
    body={'schema':c.SCHEMA+'_GRANT','slot':c.SLOT,'target':c.TARGET,'nonce':'a'*64,'pid':123,
        'host':c.MACHINE,'historical_root':list(c.R6_ROOT),'historical_guard':list(c.R6_GUARD),
        'quarantined_git':list(c.R6_QUARANTINE),'capsule_sha256':capsule.sha256,'governance':g.intent(plan)}
    for defect in ('source','intent'):
        altered=json.loads(c.canonical(body))
        if defect=='source':altered['governance']['source_release']['tag_object']='9'*40
        else:altered['governance']['reader']['uid']=1002
        try:a.sign_for_dispatched_session(altered,key,authority,mirror)
        except c.RecoveryError:pass
        else:raise AssertionError('mismatched HELLO signed')
        assert not (authority/(c.SLOT+'.signature-reserved.json')).exists()
        assert not (mirror/(c.SLOT+'.signature-reserved.json')).exists()
    grant=a.sign_for_dispatched_session(body,key,authority,mirror)
    r.verify_signature(command('openssl','pkey','-in',str(key),'-pubout'),c.canonical(body),
                       base64.b64decode(grant['signature']))
    assert not layout.anchor.exists()
    return {'case':'governance-production-client','passed':True,'factory_calls':1,
            'host_calls':0,'synthetic_only':True}


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
    value=(governance_scenario if args.case.startswith('governance-') else scenario)(args.base,args.case)
    print(json.dumps(value,sort_keys=True))
