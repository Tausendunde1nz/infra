"""R12: real isolated Linux metadata, kernel guards and crash boundaries."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from unittest import mock

from scripts import tu1nz_adult_commercial_s12_1_runtime as r

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'manifests/s12-1-r12-metadata-contract.json'


class ContractTests(unittest.TestCase):
    def test_exact_audited_set_and_nonhistorical_assignments(self):
        value = json.loads(CONTRACT.read_bytes())
        self.assertEqual(hashlib.sha256(CONTRACT.read_bytes()).hexdigest(), r.R12_CONTRACT_SHA256)
        self.assertEqual(value['evidence_sha256'], '9624ea3d41804d0ef7c13350e69075fce469250e0871d35e0b76599eb28c11ad')
        entries = value['entries']
        self.assertEqual(len(entries), 254)
        self.assertEqual(len({(e['repository'],e['path']) for e in entries}),254)
        self.assertEqual(sum(e['historical_record'] is None for e in entries),16)
        self.assertFalse(value['runtime_authorized'])
        for e in entries:
            self.assertFalse(e['historical_continuity'])
            self.assertNotIn('..', Path(e['path']).parts)
            self.assertFalse(Path(e['path']).is_absolute())
            old = e['historical_record']
            if old is None:
                self.assertEqual(e['provenance'],'NEW_CANONICAL_ASSIGNMENT')
                self.assertEqual(e['target'], dict(uid=1001,gid=1001,mode='2770' if e['admission']['kind']=='directory' else '0660',xattrs={}))
            else:
                self.assertNotEqual(old['inode'], e['admission']['inode'])
                self.assertEqual(e['provenance'],'NEW_SUCCESSOR_ASSIGNMENT')
                self.assertEqual(r._r12_xattr_fingerprint(Path(value['roots'][e['repository']])/e['path'],old,e['target']['xattrs']),old['xattr_fingerprint'])

    def test_no_implicit_reconciliation_in_deploy_or_recover(self):
        import inspect
        self.assertNotIn('reconcile_metadata',inspect.getsource(r._deploy_locked))
        self.assertNotIn('reconcile_metadata',inspect.getsource(r._recover_locked))
        source=inspect.getsource(r._r12_reconcile_locked)
        for forbidden in ('rollback_once(', '_remove_repository_recovery_barrier(', '_run(', 'deploy('):
            self.assertNotIn(forbidden,source)

    def test_full_254_path_ledger_fits_durable_bound(self):
        contract=json.loads(CONTRACT.read_bytes())
        bindings=[]
        for entry in contract['entries']:
            initial=dict(metadata=entry['admission'],birth=[1791000000,123456789],xattrs=entry['admission_xattrs'])
            bindings.append(dict(path=contract['roots'][entry['repository']]+'/'+entry['path'],
                historical_record=entry['historical_record'],successor=entry['target'],
                states=r._r12_plan(entry,initial),step=0,intent=None,provenance=entry['provenance']))
        encoded=json.dumps(dict(bindings=bindings,contract_sha256=r.R12_CONTRACT_SHA256),sort_keys=True,separators=(',',':')).encode()
        self.assertLess(len(encoded)+8192,r.BARRIER_JOURNAL_MAX_BYTES)


def acl(mode=0o770):
    return struct.pack('<I',2)+b''.join(struct.pack('<HHI',*item) for item in (
        (1,(mode>>6)&7,0xffffffff),(2,7,1001),(4,7,0xffffffff),
        (8,5,1001),(16,(mode>>3)&7,0xffffffff),(32,mode&7,0xffffffff)))


def private_json(path,value):
    path.write_text(json.dumps(value,sort_keys=True)+'\n')
    path.chmod(0o600)


@contextmanager
def fixture(*, complete_backup=False):
    # /root is private; /tmp would correctly fail the private-chain contract.
    with tempfile.TemporaryDirectory(prefix='s12-r12-',dir='/root') as name, ExitStack() as stack:
        base=Path(name)
        repos=base/'repos';repos.mkdir(mode=0o750)
        app,control=repos/'app',repos/'control'
        state=base/'private'/'state';state.mkdir(parents=True,mode=0o700)
        backup=base/'private'/'backups'/'fixture';backup.mkdir(parents=True,mode=0o700)
        def git(root,*args):
            return subprocess.run(['git','-c',f'safe.directory={root}','-C',str(root),*args],check=True,capture_output=True).stdout
        for root in (app,control):
            root.mkdir()
            git(root,'init','-b','control-main' if complete_backup and root==control else 'main')
            git(root,'config','user.name','R12 Fixture')
            git(root,'config','user.email','fixture@example.invalid')
            (root/'kept').write_bytes(b'original\n')
            if complete_backup and root==app:
                (root/'.gitignore').write_text('.venv/\n')
                interpreter=root/'.venv'/'bin'/'python';interpreter.parent.mkdir(parents=True)
                interpreter.write_bytes(b'#!/bin/sh\n# OFFLINE fixture, never provider execution\nexit 1\n')
                interpreter.chmod(0o755)
            if complete_backup and root==control:
                for relative in ('systemd/'+r.UNIT_NAME,'nginx/current/wantmeseen.s12-1-acceptance.conf',
                                 'scripts/tu1nz_adult_public_s11_2_control.sh'):
                    target=root/relative;target.parent.mkdir(parents=True,exist_ok=True)
                    target.write_bytes((ROOT/relative).read_bytes())
            git(root,'add','.');git(root,'commit','-m','before')
            if complete_backup:
                for path in root.rglob('*'):
                    if '.git' in path.parts or '.venv' in path.parts:continue
                    os.chown(path,1001,1001);path.chmod(0o2770 if path.is_dir() else 0o660)
            os.chown(root,1001,1001);root.chmod(0o2770)
            os.chown(root/'kept',1001,1001);(root/'kept').chmod(0o660)
        os.setxattr(app,'system.posix_acl_default',acl())
        os.setxattr(app/'kept','system.posix_acl_access',acl(0o660))
        for key,value in dict(APPLICATION_ROOT=app,CONTROL_ROOT=control,DEPLOYMENT_LOCK_ROOT=repos,
                              PRIVATE_ROOT=base/'private',STATE_ROOT=state,BACKUP_ROOT=backup.parent,
                              ATTEMPT_MARKER=state/'deployment-attempted.json',
                              BARRIER_MARKER=state/'repository-barrier.json',CHATOPS_USER='root').items():
            stack.enter_context(mock.patch.object(r,key,value))
        if complete_backup:
            for key,value in dict(BARRIER_RELEASE_BACKUP=state/'repository-barrier.release-backup.json',
                    BARRIER_RELEASE_COMPLETION=state/'repository-barrier.release-complete.json',
                    RELEASE_ROOT=base/'private'/'release',RELEASE_STAGING_ROOT=base/'private'/'.release-staging',
                    RELEASE_APPLICATION_ROOT=base/'private'/'release'/'application',
                    RELEASE_CONTROL_ROOT=base/'private'/'release'/'control',
                    RELEASE_VENV_ROOT=base/'private'/'release'/'venv',
                    RELEASE_ENVIRONMENT=base/'private'/'release'/'runtime-environment.json',
                    FETCH_ROOT=repos/'.s12-1-fetch', UNIT_PATH=base/'unit',RUNTIME_CONTRACT=base/'runtime.json',
                    NGINX_SITE=base/'nginx',NGINX_ENABLED=base/'nginx-enabled',
                    SDK_ID=base/'sdk-id',PRIVATE_KEY=base/'key').items():
                stack.enter_context(mock.patch.object(r,key,value))
            for path in (r.SDK_ID,r.PRIVATE_KEY):
                path.write_bytes(b'synthetic-not-a-credential');path.chmod(0o600)
            r.NGINX_SITE.write_bytes((ROOT/'nginx/current/wantmeseen.s10-1-final.conf').read_bytes())
        records={root:r._repository_path_metadata(root) for root in (app,control)}
        for root in records:
            records[root]['root_xattr_fingerprint']=r._repository_root_xattr_fingerprint(root)
        original=r._capture_worktree_write_barrier((app,control),records)
        parent=dict(path=str(repos),uid=0,gid=0,mode='0750',xattr_fingerprint=r._repository_parent_xattr_fingerprint())
        journal=dict(schema=r.BARRIER_SCHEMA,created_at='fixture',
                     repositories={key:dict(root=str(root),**records[root]) for key,root in [('application',app),('control',control)]},
                     repository_parent=parent,worktree_write_barrier=r._worktree_barrier_payload((app,control),original))
        private_json(r.BARRIER_MARKER,journal)
        private_json(r.ATTEMPT_MARKER,dict(attempt=1))
        index={}
        if complete_backup:
            with mock.patch.object(r,'FREEZE_TAG','s12-yoti-sandbox-runtime-freeze-r9'):
                backup,index=r.create_backup(path_records=records,parent_record=parent)
        for key in (() if complete_backup else ('application','control')):
            root=app if key=='application' else control
            commit=git(root,'rev-parse','HEAD').decode().strip()
            index[key]=dict(commit=commit,tree=git(root,'rev-parse','HEAD^{tree}').decode().strip())
            blob=backup/(key+'.bundle');git(root,'bundle','create',str(blob),'HEAD','refs/heads/main');blob.chmod(0o600)
            index[key]['bundle_sha256']=hashlib.sha256(blob.read_bytes()).hexdigest()
            blob=backup/(key+'.tracked-path-hashes')
            blob.write_bytes(r._tracked_path_hash_payload(r._tracked_tree_paths(root,root/'.git',commit,r.R12_RED)));blob.chmod(0o600)
            index[key]['tracked_path_hashes_sha256']=hashlib.sha256(blob.read_bytes()).hexdigest()
            logs=backup/(key+'.reflogs');logs.mkdir(mode=0o700)
            index[key]['reflog_snapshot_sha256']=r._reflog_tree_digest(logs)
        private_json(backup/'restore-index.json',index)
        r._lock_worktree_write_barrier(original)
        (app/'kept').rename(base/'predecessor')
        (app/'kept').write_bytes(b'target\n');os.chown(app/'kept',0,1001);(app/'kept').chmod(0o660)
        (app/'created').mkdir();os.chown(app/'created',0,1001);(app/'created').chmod(0o2770)
        (app/'created'/'new').write_bytes(b'new\n');os.chown(app/'created'/'new',0,1001);(app/'created'/'new').chmod(0o660)
        (control/'scripts').mkdir();os.chown(control/'scripts',1001,1001);(control/'scripts').chmod(0o2775)
        (control/'scripts'/'tool').write_bytes(b'tool\n');os.chown(control/'scripts'/'tool',0,1001);(control/'scripts'/'tool').chmod(0o440)
        unrelated=control/'unlisted'/'nested';unrelated.mkdir(parents=True)
        (unrelated/'readme').write_bytes(b'outside contract\n')
        for path in (unrelated.parent,unrelated,unrelated/'readme'):
            os.chown(path,0,1001);path.chmod(0o550 if path.is_dir() else 0o440)
        external=base/'outside-repository';external.write_bytes(b'unrelated target\n')
        link=control/'index-links'/'nested'/'link';link.parent.mkdir(parents=True)
        link.symlink_to('../../kept' if complete_backup else external)
        missing=control/'index-missing'/'nested'/'file';missing.parent.mkdir(parents=True)
        missing.write_bytes(b'indexed then absent\n')
        git(control,'add','.')
        if not complete_backup:missing.unlink()
        release_commits={}
        for root in (app,control):
            if root==app:git(root,'add','.')
            git(root,'commit','-m','target')
            release_commits['application' if root==app else 'control']=git(root,'rev-parse','HEAD').decode().strip()
            os.chown(root,0,1001);root.chmod(0o2550)
            (root/'.git').rename(root/r.RECOVERY_GIT_DIRECTORY)
            (root/r.RECOVERY_GIT_DIRECTORY).chmod(0o700)
            os.chown(root/r.RECOVERY_GIT_DIRECTORY,0,0)
            (root/'.git').mkdir(mode=0)
            os.chown(root/'.git',0,0)
            (root/'.git').chmod(0)
        selected=[('application',app,app/'kept'),('application',app,app/'created'),
                  ('application',app,app/'created'/'new'),('control',control,control/'scripts')]
        entries=[]
        for key,root,path in selected:
            fd=r._r12_open(path)
            try:
                admission=r._r12_stat(fd);attrs=r._r12_attrs(fd)
            finally:os.close(fd)
            old=original[root].get(path)
            entries.append(dict(repository=key,path=str(path.relative_to(root)),
                historical_record=old,provenance='NEW_SUCCESSOR_ASSIGNMENT' if old else 'NEW_CANONICAL_ASSIGNMENT',
                historical_continuity=False,admission=admission,admission_xattrs=attrs,
                content_sha256=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
                git_class='100644' if path.is_file() else 'directory',
                target=dict(uid=1001,gid=1001,mode=old['mode'] if old else '0660' if path.is_file() else '2770',xattrs=attrs if old else {})))
        guards=[]
        for key,root in [('application',app),('control',control)]:
            for basename in ('.git',r.RECOVERY_GIT_DIRECTORY):
                fd=r._r12_open(root/basename)
                try:guards.append(dict(repository=key,name=basename,metadata=r._r12_stat(fd)))
                finally:os.close(fd)
        contract=dict(schema='TU1NZ_S12_1_R12_METADATA_CONTRACT_V1',roots=dict(application=str(app),control=str(control)),
                      backup_name=backup.name,entries=entries,guards=guards,release_commits=release_commits,
                      protected_inputs={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (r.BARRIER_MARKER,r.ATTEMPT_MARKER,backup/'restore-index.json')})
        if complete_backup:
            private_json(r.ATTEMPT_MARKER,dict(attempt=1,backup=str(backup),started_at='fixture',
                release_repository_state=r._release_repository_states(
                    {root:root/r.RECOVERY_GIT_DIRECTORY for root in (app,control)},records,
                    control_freeze_ref='refs/tags/s12-yoti-sandbox-runtime-freeze-r9')))
            contract['protected_inputs'][r.ATTEMPT_MARKER.name]=hashlib.sha256(r.ATTEMPT_MARKER.read_bytes()).hexdigest()
        contract_path=base/'contract.json';private_json(contract_path,contract)
        stack.enter_context(mock.patch.object(r,'R12_CONTRACT_SHA256',hashlib.sha256(contract_path.read_bytes()).hexdigest()))
        yield dict(contract=contract_path,app=app,control=control,state=state,entries=entries,original=journal,base=base,
                   backup=backup,index=index)


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'isolated Linux root + SYS_ADMIN/SYS_PTRACE required')
class LinuxTests(unittest.TestCase):
    def test_complete_real_metadata_and_original_journal_preserved(self):
        with fixture() as f:
            result=r.reconcile_metadata(f['contract'])
            self.assertEqual(result['bound_paths'],4)
            self.assertFalse(result['recovery_started'])
            self.assertEqual(json.loads((f['state']/'repository-barrier.r12-original.json').read_bytes()),f['original'])
            records,parent,barrier,schema=r._load_barrier_journal()
            self.assertEqual(schema,r.R12_BARRIER_SCHEMA)
            with self.assertRaisesRegex(r.S12ControlError,'ALREADY_SEALED_RECOVERY_PREFLIGHT_REQUIRED'):
                r.reconcile_metadata(f['contract'])
            for root in (f['app'],f['control']):
                self.assertEqual(stat.S_IMODE((root/'.git').stat().st_mode),0)
            ledger=json.loads((f['state']/'repository-barrier.r12-bindings.json').read_bytes())
            for b in ledger['bindings']:
                path=Path(b['path']);meta=path.stat()
                self.assertEqual(meta.st_uid,0)
                self.assertFalse(stat.S_IMODE(meta.st_mode)&0o222)
                r._assert_worktree_path_xattrs(path,b['successor'],barrier_locked=True)

    def test_admission_drift_fails_before_target_mutation(self):
        for mutation in ('content','owner','mode','xattr','replacement','symlink','hardlink'):
            with self.subTest(mutation=mutation), fixture() as f:
                path=f['app']/'kept'
                if mutation=='content':path.write_bytes(b'wrong')
                elif mutation=='owner':os.chown(path,1002,1001)
                elif mutation=='mode':path.chmod(0o664)
                elif mutation=='xattr':os.setxattr(path,'user.unbound',b'data')
                elif mutation=='replacement':
                    path.rename(f['base']/'old');path.write_bytes(b'target\n')
                elif mutation=='symlink':
                    path.rename(f['base']/'old');path.symlink_to(f['base']/'old')
                else:os.link(path,f['base']/'alias')
                with self.assertRaises(r.S12ControlError):r.reconcile_metadata(f['contract'])
                self.assertEqual(json.loads(r.BARRIER_MARKER.read_bytes())['schema'],r.BARRIER_SCHEMA)

    def test_interruption_after_each_metadata_syscall_resumes(self):
        class Interrupted(BaseException):pass
        for function in ('fchown','setxattr','fchmod','removexattr'):
            with self.subTest(function=function), fixture() as f:
                original=getattr(os,function);fired=False
                def interrupt(*args,**kwargs):
                    nonlocal fired
                    result=original(*args,**kwargs)
                    # Only descriptor-bound worktree calls, not private writes.
                    if isinstance(args[0],int) and not fired:
                        target=os.readlink(f'/proc/self/fd/{args[0]}')
                        if target.startswith(str(f['app'])) or target.startswith(str(f['control'])):
                            fired=True;raise Interrupted
                    return result
                with mock.patch.object(os,function,side_effect=interrupt):
                    with self.assertRaises(Interrupted):r.reconcile_metadata(f['contract'])
                self.assertTrue(fired)
                self.assertEqual(r.reconcile_metadata(f['contract'])['safe_code'],'S12_1_R12_METADATA_SEALED')

    def test_foreign_attribute_event_is_rejected_even_if_restored(self):
        with fixture() as f:
            path=f['app']/'kept'
            guard=r._R12AttributeGuard((path,))
            try:
                subprocess.run([sys.executable,'-c','import os,sys;os.chmod(sys.argv[1],0o640);os.chmod(sys.argv[1],0o660)',str(path)],check=True)
                with self.assertRaises(r.S12ControlError):guard.assert_quiet()
            finally:guard.close()

    def test_birth_binding_rejects_resume_object_replacement(self):
        class Interrupted(BaseException):pass
        with fixture() as f:
            write=r._atomic_barrier_json
            def interrupt(path,payload):
                write(path,payload)
                if path.name.endswith('r12-bindings.json'):raise Interrupted
            with mock.patch.object(r,'_atomic_barrier_json',side_effect=interrupt):
                with self.assertRaises(Interrupted):r.reconcile_metadata(f['contract'])
            path=f['app']/'kept';path.rename(f['base']/'moved');path.write_bytes(b'target\n')
            with self.assertRaises(r.S12ControlError):r.reconcile_metadata(f['contract'])
            self.assertEqual(json.loads((f['state']/'repository-barrier.r12-bindings.json').read_bytes())['phase'],'ABORTED')

    def test_retained_writer_is_not_adopted(self):
        with fixture() as f:
            child=subprocess.Popen([sys.executable,'-c',
                'import os,sys;f=open(sys.argv[1],"r+b");print("ready",flush=True);sys.stdin.read()',str(f['app']/'kept')],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(),'ready')
                with self.assertRaisesRegex(r.S12ControlError,'GIT_ACTIVE_RED'):
                    r.reconcile_metadata(f['contract'])
                self.assertFalse((f['state']/'repository-barrier.r12-bindings.json').exists())
            finally:
                child.communicate('',timeout=5)

    def test_backup_drift_and_wrong_contract_fail_closed(self):
        for which in ('backup','contract'):
            with self.subTest(which=which),fixture() as f:
                target=(r.BACKUP_ROOT/'fixture'/'application.bundle') if which=='backup' else f['contract']
                target.write_bytes(target.read_bytes()+b' ')
                with self.assertRaises(r.S12ControlError):r.reconcile_metadata(f['contract'])
                self.assertFalse((f['state']/'repository-barrier.r12-bindings.json').exists())

    def test_completed_ledger_before_journal_commit_resumes(self):
        class Interrupted(BaseException):pass
        with fixture() as f:
            original=r._atomic_barrier_json
            def stop(path,payload):
                if path==r.BARRIER_MARKER and payload.get('schema')==r.R12_BARRIER_SCHEMA:
                    raise Interrupted
                original(path,payload)
            with mock.patch.object(r,'_atomic_barrier_json',side_effect=stop):
                with self.assertRaises(Interrupted):r.reconcile_metadata(f['contract'])
            self.assertEqual(r.reconcile_metadata(f['contract'])['safe_code'],'S12_1_R12_METADATA_SEALED')

    def test_late_writer_outside_254_contract_is_rejected(self):
        with fixture() as f:
            original=r._atomic_barrier_json;fired=False
            def inject(path,payload):
                nonlocal fired
                original(path,payload)
                if path.name.endswith('r12-bindings.json') and not fired:
                    fired=True
                    subprocess.run([sys.executable,'-c',
                        'import sys;open(sys.argv[1],"wb").write(b"external writer")',
                        str(f['control']/'unlisted'/'nested'/'readme')],check=True)
            with mock.patch.object(r,'_atomic_barrier_json',side_effect=inject):
                with self.assertRaisesRegex(r.S12ControlError,'WORKTREE_BARRIER_RED'):
                    r.reconcile_metadata(f['contract'])
            self.assertTrue(fired)
            self.assertEqual(json.loads(r.BARRIER_MARKER.read_bytes())['schema'],r.BARRIER_SCHEMA)
            self.assertEqual(json.loads((f['state']/'repository-barrier.r12-bindings.json').read_bytes())['phase'],'ABORTED')

    def test_all_index_names_guard_ancestors_without_following_symlink(self):
        with fixture() as f:
            guarded=r._r12_index_guard_paths((f['app'],f['control']))
            for name in ('index-links','index-missing'):
                self.assertIn(f['control']/name/'nested',guarded)
            self.assertNotIn(f['control']/'index-links'/'nested'/'link',guarded)
            self.assertNotIn(f['base']/'outside-repository',guarded)

    def test_late_missing_or_symlink_index_change_is_rejected(self):
        for kind in ('missing-file','symlink','missing-ancestors'):
            with self.subTest(kind=kind),fixture() as f:
                target=f['control']/('index-links/nested/link' if kind=='symlink' else 'index-missing/nested/file')
                if kind=='missing-ancestors':
                    (f['control']/'index-missing').rename(f['base']/'removed-ancestors')
                original=r._atomic_barrier_json;fired=False
                def inject(path,payload):
                    nonlocal fired
                    original(path,payload)
                    if path.name.endswith('r12-bindings.json') and not fired:
                        fired=True
                        code=('from pathlib import Path;import sys;p=Path(sys.argv[1]);'
                              'p.unlink();p.symlink_to("different-target")' if kind=='symlink' else
                              'from pathlib import Path;import sys;p=Path(sys.argv[1]);'
                              'p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b"new writer")')
                        subprocess.run([sys.executable,'-c',code,str(target)],check=True)
                with mock.patch.object(r,'_atomic_barrier_json',side_effect=inject):
                    with self.assertRaisesRegex(r.S12ControlError,'WORKTREE_BARRIER_RED'):
                        r.reconcile_metadata(f['contract'])
                self.assertTrue(fired)
                self.assertEqual(json.loads(r.BARRIER_MARKER.read_bytes())['schema'],r.BARRIER_SCHEMA)
                self.assertEqual(json.loads((f['state']/'repository-barrier.r12-bindings.json').read_bytes())['phase'],'ABORTED')

    def test_symlink_index_ancestor_fails_before_metadata_assignment(self):
        with fixture() as f:
            directory=f['control']/'index-links'
            directory.rename(f['base']/'outside-index-parent')
            directory.symlink_to(f['base']/'outside-index-parent')
            with self.assertRaisesRegex(r.S12ControlError,'R12_METADATA_RECONCILIATION_RED'):
                r.reconcile_metadata(f['contract'])
            self.assertFalse((f['state']/'repository-barrier.r12-bindings.json').exists())

    def test_late_failure_restores_loadable_original_journal(self):
        for check in ('finalize','attributes'):
            with self.subTest(check=check),fixture() as f:
                original=f['original']
                if check=='finalize':
                    patch=mock.patch.object(r._WorktreeReleaseGuard,'finalize_release',
                        side_effect=r.S12ControlError('injected late guard failure'))
                else:
                    quiet=r._R12AttributeGuard.assert_quiet
                    def late(self):
                        quiet(self)
                        if json.loads(r.BARRIER_MARKER.read_bytes())['schema']==r.R12_BARRIER_SCHEMA:
                            raise r.S12ControlError('injected late guard failure')
                    patch=mock.patch.object(r._R12AttributeGuard,'assert_quiet',late)
                with patch:
                    with self.assertRaisesRegex(r.S12ControlError,'injected late'):
                        r.reconcile_metadata(f['contract'])
                self.assertEqual(r._load_barrier_journal()[3],r.BARRIER_SCHEMA)
                self.assertEqual(json.loads(r.BARRIER_MARKER.read_bytes()),original)
                self.assertEqual(r.BARRIER_MARKER.read_bytes(),(f['state']/'repository-barrier.r12-original.json').read_bytes())
                self.assertEqual(json.loads((f['state']/'repository-barrier.r12-bindings.json').read_bytes())['phase'],'ABORTED')
                with self.assertRaisesRegex(r.S12ControlError,'ABORTED_NO_RETRY'):
                    r.reconcile_metadata(f['contract'])
                for root in (f['app'],f['control']):
                    self.assertEqual(stat.S_IMODE((root/'.git').stat().st_mode),0)

    def test_interrupted_abort_only_completes_journal_finalization(self):
        class Interrupted(BaseException):pass
        for boundary in ('before-v3-restore','before-aborted-ledger'):
            with self.subTest(boundary=boundary),fixture() as f,ExitStack() as stack:
                stack.enter_context(mock.patch.object(r._WorktreeReleaseGuard,'finalize_release',
                    side_effect=r.S12ControlError('injected late guard failure')))
                if boundary=='before-v3-restore':
                    original=r._atomic_copy
                    def stop(source,destination,*args):
                        if destination==r.BARRIER_MARKER:raise Interrupted
                        return original(source,destination,*args)
                    stack.enter_context(mock.patch.object(r,'_atomic_copy',side_effect=stop))
                else:
                    original=r._atomic_barrier_json
                    def stop(path,payload):
                        if path.name.endswith('r12-bindings.json') and payload['phase']=='ABORTED':raise Interrupted
                        return original(path,payload)
                    stack.enter_context(mock.patch.object(r,'_atomic_barrier_json',side_effect=stop))
                with self.assertRaises(Interrupted):r.reconcile_metadata(f['contract'])
                stack.close()
                self.assertTrue((f['state']/'repository-barrier.r12-abort.json').is_file())
                if boundary=='before-v3-restore':
                    journal=json.loads(r.BARRIER_MARKER.read_bytes())
                    ledger=f['state']/'repository-barrier.r12-bindings.json'
                    self.assertEqual(journal['r12_metadata_reconciliation']['ledger_sha256'],hashlib.sha256(ledger.read_bytes()).hexdigest())
                    with self.assertRaisesRegex(r.S12ControlError,'ABORT_FINALIZATION_REQUIRED'):
                        r._load_barrier_journal()
                with mock.patch.object(r,'_r12_plan',side_effect=AssertionError('must not retry assignment')):
                    with self.assertRaisesRegex(r.S12ControlError,'ABORTED_NO_RETRY'):
                        r.reconcile_metadata(f['contract'])
                self.assertEqual(r._load_barrier_journal()[3],r.BARRIER_SCHEMA)
                self.assertEqual(r.BARRIER_MARKER.read_bytes(),(f['state']/'repository-barrier.r12-original.json').read_bytes())
                self.assertEqual(json.loads((f['state']/'repository-barrier.r12-bindings.json').read_bytes())['phase'],'ABORTED')

    def test_quarantined_head_or_index_drift_is_rejected(self):
        for drift in ('head','index-omission','index-blob','replacement-ref'):
            with self.subTest(drift=drift),fixture() as f:
                root=f['control'];gitdir=root/r.RECOVERY_GIT_DIRECTORY
                args=('update-ref','HEAD','HEAD^') if drift=='head' else (
                    ('update-index','--force-remove','unlisted/nested/readme') if drift=='index-omission' else
                    ('replace','HEAD','HEAD^') if drift=='replacement-ref' else
                    ('update-index','--add','--cacheinfo','100644',
                     r._selected_git(root,gitdir,'rev-parse','HEAD:kept'),'unlisted/nested/readme'))
                subprocess.run(r._selected_git_arguments(root,gitdir,*args),check=True,capture_output=True)
                with self.assertRaises(r.S12ControlError):r.reconcile_metadata(f['contract'])
                self.assertFalse((f['state']/'repository-barrier.r12-bindings.json').exists())

    def test_guard_installation_race_rejects_write_and_reverted_write(self):
        for reverted in (False,True):
            with self.subTest(reverted=reverted),fixture() as f:
                target=f['control']/'unlisted'/'nested'/'readme'
                original=r._WorktreeReleaseGuard.__init__
                def install(self,*args,**kwargs):
                    subprocess.run([sys.executable,'-c',
                        'from pathlib import Path;import os,sys;p=Path(sys.argv[1]);s=p.stat();b=p.read_bytes();'
                        'p.write_bytes(b"short lived writer");'
                        'p.write_bytes(b) if sys.argv[2]=="True" else None;'
                        'os.utime(p,ns=(s.st_atime_ns,s.st_mtime_ns))',str(target),str(reverted)],check=True)
                    original(self,*args,**kwargs)
                with mock.patch.object(r._WorktreeReleaseGuard,'__init__',install):
                    with self.assertRaisesRegex(r.S12ControlError,'R12_METADATA_RECONCILIATION_RED'):
                        r.reconcile_metadata(f['contract'])
                self.assertFalse((f['state']/'repository-barrier.r12-bindings.json').exists())

    def test_git_guard_installation_race_rejects_reverted_metadata_write(self):
        for name in ('HEAD','index'):
            with self.subTest(name=name),fixture() as f:
                target=f['control']/r.RECOVERY_GIT_DIRECTORY/name
                original=r._GitMetadataTransitionGuard.__init__
                def install(self,*args,**kwargs):
                    subprocess.run([sys.executable,'-c',
                        'from pathlib import Path;import os,sys;p=Path(sys.argv[1]);s=p.stat();b=p.read_bytes();'
                        'p.write_bytes(b"short lived Git writer");p.write_bytes(b);'
                        'os.utime(p,ns=(s.st_atime_ns,s.st_mtime_ns))',str(target)],check=True)
                    original(self,*args,**kwargs)
                with mock.patch.object(r._GitMetadataTransitionGuard,'__init__',install):
                    with self.assertRaisesRegex(r.S12ControlError,'GIT_ACTIVE_RED'):
                        r.reconcile_metadata(f['contract'])
                self.assertFalse((f['state']/'repository-barrier.r12-bindings.json').exists())


if __name__=='__main__':unittest.main()
