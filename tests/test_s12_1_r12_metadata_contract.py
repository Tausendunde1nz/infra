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
def fixture():
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
            git(root,'init','-b','main')
            git(root,'config','user.name','R12 Fixture')
            git(root,'config','user.email','fixture@example.invalid')
            (root/'kept').write_bytes(b'original\n')
            git(root,'add','kept');git(root,'commit','-m','before')
            os.chown(root,1001,1001);root.chmod(0o2770)
            os.chown(root/'kept',1001,1001);(root/'kept').chmod(0o660)
        os.setxattr(app,'system.posix_acl_default',acl())
        os.setxattr(app/'kept','system.posix_acl_access',acl(0o660))
        for key,value in dict(APPLICATION_ROOT=app,CONTROL_ROOT=control,DEPLOYMENT_LOCK_ROOT=repos,
                              PRIVATE_ROOT=base/'private',STATE_ROOT=state,BACKUP_ROOT=backup.parent,
                              ATTEMPT_MARKER=state/'deployment-attempted.json',
                              BARRIER_MARKER=state/'repository-barrier.json',CHATOPS_USER='root').items():
            stack.enter_context(mock.patch.object(r,key,value))
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
        for key in ('application','control'):
            index[key]={}
            for suffix,field in (('.bundle','bundle_sha256'),('.tracked-path-hashes','tracked_path_hashes_sha256')):
                blob=backup/(key+suffix);blob.write_bytes(b'authenticated isolated fixture\n');blob.chmod(0o600)
                index[key][field]=hashlib.sha256(blob.read_bytes()).hexdigest()
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
        for root in (app,control):
            git(root,'add','.')
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
                      backup_name='fixture',entries=entries,guards=guards,
                      protected_inputs={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (r.BARRIER_MARKER,r.ATTEMPT_MARKER,backup/'restore-index.json')})
        contract_path=base/'contract.json';private_json(contract_path,contract)
        stack.enter_context(mock.patch.object(r,'R12_CONTRACT_SHA256',hashlib.sha256(contract_path.read_bytes()).hexdigest()))
        yield dict(contract=contract_path,app=app,control=control,state=state,entries=entries,original=journal,base=base)


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


if __name__=='__main__':unittest.main()
