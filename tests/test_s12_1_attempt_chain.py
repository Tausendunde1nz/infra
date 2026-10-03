"""Integrated offline chain: real Git, backup, metadata and recovery guards.

Only systemd/nginx process boundaries are simulated. No server or provider is
contacted; no successful recovery/metadata result is substituted.
"""
import os
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import copy
import shutil
import unittest
from unittest import mock
from contextlib import ExitStack

from scripts import tu1nz_adult_commercial_s12_1_runtime as r
from tests.test_s12_1_r12_metadata_contract import fixture, private_json


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,
                     'native Linux protected receipt checks required')
class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.base=Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir='/root')))
        self.state=self.base/'state';self.state.mkdir(mode=0o700)
        for key,value in dict(PRIVATE_ROOT=self.base,STATE_ROOT=self.state,
                BACKUP_ROOT=self.base/'backups',DEPLOYMENT_LOCK_ROOT=self.base).items():
            self.stack.enter_context(mock.patch.object(r,key,value))
        self.stack.enter_context(mock.patch.object(r,'_trusted_controller_digest',return_value='c'*64))
        self.stack.enter_context(mock.patch.dict(os.environ,{
            r.APPLICATION_BUNDLE_DIGEST_ENV:'a'*64,r.CONTROL_BUNDLE_DIGEST_ENV:'b'*64}))
        self.path=self.base/'authorizations'/(r.FOLLOWUP_SLOT+'.json')
        self.path.parent.mkdir(mode=0o700)
        self.grant=dict(schema='TU1NZ_S12_1_FOLLOWUP_AUTHORIZATION_V1',slot=r.FOLLOWUP_SLOT,
            human_authorization_sha256='d'*64,
            acknowledgment='AUTHORIZE_ONE_SYNTHETIC_SANDBOX_DEPLOYMENT_AFTER_RECOVERY',
            authorized_at=int(time.time())-1,expires_at=int(time.time())+3600,
            parent_proof={**r.FOLLOWUP_PARENT,**{k:'e'*64 for k in ('rollback','progress','recovery','r12_ledger')}},
            release=dict(tag=r.FREEZE_TAG,tag_object='a'*40,control_commit='b'*40,control_tree='c'*40,
                application_commit=r.APPLICATION_COMMIT,application_tree=r.APPLICATION_TREE,
                controller_sha256='c'*64,application_bundle_sha256='a'*64,control_bundle_sha256='b'*64))

    def write(self,value=None):
        private_json(self.path,self.grant if value is None else value)
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_exact_grant_and_recovery_after_expiry(self):
        digest=self.write()
        self.assertEqual(r._followup_authorization(self.path,digest,recovering=False),self.grant)
        self.grant.update(authorized_at=int(time.time())-7200,expires_at=int(time.time())-3600)
        digest=self.write()
        with self.assertRaises(r.S12ControlError):r._followup_authorization(self.path,digest,recovering=False)
        self.assertEqual(r._followup_authorization(self.path,digest,recovering=True),self.grant)

    def test_authority_release_parent_and_time_negative_cases(self):
        mutations=[lambda v:v.update(slot='another-attempt'),lambda v:v.update(acknowledgment='YES'),
            lambda v:v.update(human_authorization_sha256='0'*64),
            lambda v:v.update(authorized_at=True),lambda v:v.update(expires_at=v['authorized_at']+86401),
            lambda v:v.update(authorized_at=int(time.time())+100,expires_at=int(time.time())+200),
            lambda v:v['release'].update(tag=r.FREEZE_TAG+'-new'),
            lambda v:v['release'].update(application_commit='0'*40),
            lambda v:v['release'].update(controller_sha256='0'*64),
            lambda v:v['release'].update(control_bundle_sha256='0'*64),
            lambda v:v['parent_proof'].update(attempt='0'*64),
            lambda v:v['release'].update(extra='not-allowed'),lambda v:v.pop('human_authorization_sha256')]
        for index,change in enumerate(mutations):
            with self.subTest(index=index):
                value=copy.deepcopy(self.grant);change(value);digest=self.write(value)
                with self.assertRaises(r.S12ControlError):r._followup_authorization(self.path,digest,recovering=False)

    def test_receipt_digest_rights_and_hardlink_fail_closed(self):
        digest=self.write()
        with self.assertRaises(r.S12ControlError):r._followup_authorization(self.path,'0'*64,recovering=False)
        self.path.chmod(0o640)
        with self.assertRaises(r.S12ControlError):r._followup_authorization(self.path,digest,recovering=False)
        self.path.chmod(0o600)
        os.link(self.path,self.base/'linked')
        with self.assertRaises(r.S12ControlError):r._followup_authorization(self.path,digest,recovering=False)

    def test_crash_after_admission_burns_slot_and_only_allows_recovery(self):
        digest=self.write()
        with mock.patch.object(r,'_followup_parent_closed'), mock.patch.object(r,'read_only_preflight'), \
                mock.patch.object(r,'_deploy_locked',side_effect=KeyboardInterrupt) as deploy:
            with self.assertRaises(KeyboardInterrupt):r.followup(self.path,digest)
            claim=self.state/(r.FOLLOWUP_SLOT+'.consumed.json');original=claim.read_bytes()
            with self.assertRaisesRegex(r.S12ControlError,'ALREADY_CONSUMED'):r.followup(self.path,digest)
            self.grant['expires_at']+=1;different=self.write()
            with self.assertRaisesRegex(r.S12ControlError,'ALREADY_CONSUMED'):r.followup(self.path,different)
            deploy.assert_called_once()
            self.assertEqual(claim.read_bytes(),original)
        self.grant['expires_at']-=1;self.assertEqual(self.write(),digest)
        def recovered():
            self.assertEqual(r.STATE_ROOT,self.state/'attempts'/r.FOLLOWUP_SLOT)
            r.STATE_ROOT.mkdir(parents=True,mode=0o700)
            return dict(ok=True,safe_code='S12_1_NO_PENDING_RECOVERY')
        with mock.patch.object(r,'_recover_locked',side_effect=recovered), \
                mock.patch.object(r,'_followup_parent_closed'),mock.patch.object(r,'read_only_preflight'), \
                mock.patch.object(r,'_deploy_locked') as deploy:
            result=r.followup(self.path,digest,recovering=True)
            self.assertEqual(result['safe_code'],'S12_1_FOLLOWUP_CONSUMED_WITHOUT_DEPLOYMENT')
            deploy.assert_not_called()
        self.assertEqual(claim.read_bytes(),original)
        self.assertEqual(r.STATE_ROOT,self.state)

    def test_partial_claim_and_unknown_existing_namespace_both_block(self):
        digest=self.write()
        claim=self.state/(r.FOLLOWUP_SLOT+'.consumed.json');claim.touch(mode=0o600)
        with mock.patch.object(r,'_deploy_locked') as deploy:
            with self.assertRaisesRegex(r.S12ControlError,'ALREADY_CONSUMED'):r.followup(self.path,digest)
            with self.assertRaises(r.S12ControlError):r.followup(self.path,digest,recovering=True)
            deploy.assert_not_called()
        # New isolated fixture slot, not a production reset.
        claim.unlink();(self.state/'attempts'/r.FOLLOWUP_SLOT).mkdir(parents=True)
        with self.assertRaises(r.S12ControlError):r.followup(self.path,digest)

    def test_parent_failure_does_not_consume_and_never_deploys(self):
        digest=self.write()
        with mock.patch.object(r,'_followup_parent_closed',side_effect=r.S12ControlError('PARENT_RED')), \
                mock.patch.object(r,'_deploy_locked') as deploy:
            with self.assertRaisesRegex(r.S12ControlError,'PARENT_RED'):r.followup(self.path,digest)
            deploy.assert_not_called()
        self.assertFalse((self.state/(r.FOLLOWUP_SLOT+'.consumed.json')).exists())


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,
                     'native Linux root + kernel guards required')
class IntegratedChainTests(unittest.TestCase):
    def host_boundary(self, argv, **kwargs):
        if argv[0]=='systemctl':
            if 'start' in argv:
                self.starts += 1
                self.start_witness.write_text(str(self.starts))
                self.assertEqual(argv,['systemctl','start',r.UNIT_NAME])
                self.assertEqual(r.STATE_ROOT.name,r.FOLLOWUP_SLOT)
                if self.provider_failure:
                    return subprocess.CompletedProcess(argv,1,'','')
                r._atomic_json(r.STATE_ROOT/'acceptance.json',dict(
                    safe_code='S12_1_SANDBOX_RUNTIME_ACCEPTANCE_GREEN',hard_gates_closed=True,runtime_active=False))
                r._atomic_json(r.STATE_ROOT/'final-state.json',dict(
                    safe_code='S12_RUNTIME_CONTROLLED_INACTIVE',hard_gates_closed=True,runtime_active=False,callback='INACTIVE'))
                return subprocess.CompletedProcess(argv,0,'','')
            if 'is-enabled' in argv:
                output='enabled\n' if argv[-1]==r.S11_TIMER else 'static\n' if r.UNIT_PATH.exists() else 'not-found\n'
            elif '--property=LoadState,ActiveState,SubState' in argv:
                output='LoadState=not-found\nActiveState=inactive\nSubState=dead\n'
            elif '-p' in argv:
                name=argv[argv.index('-p')+1]
                output={'ActiveState':'active','NRestarts':'0','SubState':'waiting','Result':'success',
                        'ExecMainStatus':'0','FragmentPath':str(r.UNIT_PATH),
                        'NextElapseUSecRealtime':'2099-01-01 00:00:00 UTC'}.get(name,'')
            else:output=''
            return subprocess.CompletedProcess(argv,0,output,'')
        if argv[0]=='nginx':return subprocess.CompletedProcess(argv,0,'','')
        if argv[0]=='curl':return subprocess.CompletedProcess(argv,0,'308' if '.de/' in argv[-1] else '200','')
        return self.real_run(argv,**kwargs)

    def full_chain(self, *, provider_failure=False, crash_at=None, attack=None,
                   attack_at='OBJECT_BOUND', tamper=None):
        with fixture(complete_backup=True) as f, ExitStack() as patches:
            self.real_run=r._run;self.starts=0;self.provider_failure=provider_failure
            self.start_witness=f['base']/'isolated-start-count'
            patches.enter_context(mock.patch.object(r,'_run',side_effect=self.host_boundary))
            # The offline interpreter is synthetic. All copy/hash/ownership and
            # immutable-tree checks run on its real bytes; no provider executes.
            patches.enter_context(mock.patch.object(r,'RUNTIME_PYTHON_SHA256',r._sha256(f['app']/'.venv/bin/python')))
            patches.enter_context(mock.patch.object(r,'RUNTIME_VENV_SHA256',
                r._runtime_environment_fingerprint(f['app']/'.venv',allow_file_symlinks=True)))
            patches.enter_context(mock.patch.object(r,'_runtime_dependency_versions',return_value=r.RUNTIME_DEPENDENCY_VERSIONS))
            trusted=f['base']/'controller.py'
            trusted.write_bytes(Path(r.__file__).read_bytes());trusted.chmod(0o500)
            controller_hash=hashlib.sha256(trusted.read_bytes()).hexdigest()
            patches.enter_context(mock.patch.object(r,'__file__',str(trusted)))
            patches.enter_context(mock.patch.object(r,'TRUSTED_CONTROLLER_PATH',trusted))
            release=json.loads(f['contract'].read_bytes())['release_commits']
            exports={}
            for key,root in [('application',f['app']),('control',f['control'])]:
                bare=f['base']/(key+'.git')
                self.real_run(['git','clone','--bare','--no-hardlinks',str(root/r.RECOVERY_GIT_DIRECTORY),str(bare)])
                exports[key]=bare
            app_sha=release['application'];control_sha=release['control']
            app_tree=r._bare_root_git(exports['application'],'rev-parse',app_sha+'^{tree}')
            control_tree=r._bare_root_git(exports['control'],'rev-parse',control_sha+'^{tree}')
            self.real_run(['git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                '--git-dir='+str(exports['control']),'tag','-a',r.FREEZE_TAG,'-m',
                'control_runtime_sha256='+controller_hash,control_sha])
            tag_object=r._bare_root_git(exports['control'],'rev-parse',r.FREEZE_TAG)
            inputs=f['base']/'inputs';inputs.mkdir(mode=0o700)
            digests={}
            for key,branch in [('application','main'),('control','control-main')]:
                bundle=inputs/(key+'.bundle')
                refs=['refs/heads/'+branch]+(['refs/tags/'+r.FREEZE_TAG] if key=='control' else [])
                self.real_run(['git','--git-dir='+str(exports[key]),'bundle','create',str(bundle),*refs])
                bundle.chmod(0o600);digests[key]=hashlib.sha256(bundle.read_bytes()).hexdigest()
            for key,value in dict(APPLICATION_COMMIT=app_sha,APPLICATION_TREE=app_tree,
                    RELEASE_INPUT_ROOT=inputs,APPLICATION_INPUT_BUNDLE=inputs/'application.bundle',
                    CONTROL_INPUT_BUNDLE=inputs/'control.bundle').items():
                patches.enter_context(mock.patch.object(r,key,value))
            patches.enter_context(mock.patch.dict(os.environ,{
                r.TRUSTED_CONTROLLER_DIGEST_ENV:controller_hash,
                r.APPLICATION_BUNDLE_DIGEST_ENV:digests['application'],
                r.CONTROL_BUNDLE_DIGEST_ENV:digests['control']}))
            historical=r.ATTEMPT_MARKER.read_bytes()
            self.assertTrue(r.reconcile_metadata(f['contract'])['ok'])
            self.assertTrue(r.recover()['ok'])
            proof={key:hashlib.sha256(path.read_bytes()).hexdigest() for key,path in dict(
                attempt=r.ATTEMPT_MARKER,index=f['backup']/'restore-index.json',
                rollback=f['backup']/'rollback-complete.json',progress=f['backup']/'rollback-progress.json',
                recovery=f['state']/'recovery-result.json',r12_original=f['state']/'repository-barrier.r12-original.json',
                r12_ledger=f['state']/'repository-barrier.r12-bindings.json').items()}
            patches.enter_context(mock.patch.object(r,'FOLLOWUP_PARENT',
                {key:proof[key] for key in r.FOLLOWUP_PARENT}))
            import time
            grant=dict(schema='TU1NZ_S12_1_FOLLOWUP_AUTHORIZATION_V1',slot=r.FOLLOWUP_SLOT,
                human_authorization_sha256=hashlib.sha256(b'ISOLATED TEST ONLY').hexdigest(),
                acknowledgment='AUTHORIZE_ONE_SYNTHETIC_SANDBOX_DEPLOYMENT_AFTER_RECOVERY',
                authorized_at=int(time.time())-1,expires_at=int(time.time())+3600,parent_proof=proof,
                release=dict(tag=r.FREEZE_TAG,tag_object=tag_object,control_commit=control_sha,
                    control_tree=control_tree,application_commit=app_sha,application_tree=app_tree,
                    controller_sha256=controller_hash,application_bundle_sha256=digests['application'],
                    control_bundle_sha256=digests['control']))
            authorization=r.PRIVATE_ROOT/'authorizations'/(r.FOLLOWUP_SLOT+'.json')
            authorization.parent.mkdir(mode=0o700);private_json(authorization,grant)
            grant_hash=hashlib.sha256(authorization.read_bytes()).hexdigest()
            # Fixture commits differ from production; validate its real tag and
            # target identities. Canonical all-artifact freeze verification is
            # separately mandatory in the source suite and release completion.
            def fixture_freeze():
                self.assertEqual(r._verify_immutable_release_stage(),(control_sha,control_tree))
                self.assertEqual(r._root_git(r.RELEASE_CONTROL_ROOT,'rev-parse',r.FREEZE_TAG),tag_object)
            patches.enter_context(mock.patch.object(r,'_verify_release_freeze',side_effect=fixture_freeze))
            if crash_at:
                pid=os.fork()
                if pid==0:
                    def terminate(name):
                        if name==crash_at:os._exit(73)
                    try:
                        with mock.patch.object(r,'_r13_boundary',side_effect=terminate):
                            r.followup(authorization,grant_hash)
                    except BaseException:
                        import traceback
                        traceback.print_exc()
                    os._exit(74)  # Fault seam not reached is a test failure.
                _,status=os.waitpid(pid,0)
                self.assertEqual(os.waitstatus_to_exitcode(status),73,crash_at)
                self.starts=int(self.start_witness.read_text()) if self.start_witness.exists() else 0
                if tamper:
                    tamper(f)
                    with self.assertRaises((r.S12ControlError,OSError)):
                        r.followup(authorization,grant_hash,recovering=True)
                    self.assertEqual(self.starts,0)
                    self.assertEqual(r.ATTEMPT_MARKER.read_bytes(),historical)
                    with self.assertRaisesRegex(r.S12ControlError,'ALREADY_CONSUMED'):
                        r.followup(authorization,grant_hash)
                    return
                result=r.followup(authorization,grant_hash,recovering=True)
                self.assertTrue(result['ok']);self.assertEqual(result['rollback_count'],1)
                self.assertFalse(r.RELEASE_ROOT.exists())
                if crash_at in {'OBJECT_ALLOCATED','OBJECT_METADATA_SET'}:
                    # The unbound private allocation is preserved, never
                    # adopted, published, deleted or treated as historical.
                    tx=f['state']/'attempts'/r.FOLLOWUP_SLOT/'materialization/application'
                    self.assertTrue((tx/'new/0').is_dir())
                    value=json.loads((tx/'journal.json').read_bytes())
                    self.assertEqual(value['phase'],'UNDONE')
                    self.assertIsNone(value['entries'][0]['after'])
            elif attack:
                fired=False
                def interfere(name):
                    nonlocal fired
                    if name==attack_at and not fired:
                        fired=True
                        attack(f)
                with mock.patch.object(r,'_r13_boundary',side_effect=interfere):
                    with self.assertRaises(r.S12ControlError):r.followup(authorization,grant_hash)
                self.assertTrue(fired)
                with self.assertRaises(r.S12ControlError):r.followup(authorization,grant_hash,recovering=True)
                self.assertEqual(self.starts,0)
                self.assertEqual(r.ATTEMPT_MARKER.read_bytes(),historical)
                with self.assertRaisesRegex(r.S12ControlError,'ALREADY_CONSUMED'):
                    r.followup(authorization,grant_hash)
                return
            elif provider_failure:
                with self.assertRaisesRegex(r.S12ControlError,'S12_1_RUNTIME_ACCEPTANCE_RED'):
                    r.followup(authorization,grant_hash)
                result=r.followup(authorization,grant_hash,recovering=True)
                self.assertTrue(result['ok']);self.assertEqual(result['rollback_count'],1)
                self.assertFalse(r.RELEASE_ROOT.exists())
            else:
                result=r.followup(authorization,grant_hash)
                self.assertTrue(result['ok']);self.assertEqual(result['deployment_count'],1)
                self.assertEqual(result['rollback_count'],0)
            expected_starts=0 if crash_at and not provider_failure else 1
            self.assertEqual(self.starts,expected_starts)
            with self.assertRaisesRegex(r.S12ControlError,'ALREADY_CONSUMED'):
                r.followup(authorization,grant_hash)
            self.assertEqual(self.starts,expected_starts)
            self.assertEqual(r.ATTEMPT_MARKER.read_bytes(),historical)
            new_state=f['state']/'attempts'/r.FOLLOWUP_SLOT
            marker=json.loads((new_state/'deployment-attempted.json').read_bytes())
            self.assertEqual(marker['attempt_binding'],result['attempt_binding'])
            self.assertNotEqual(Path(marker['backup']),f['backup'])
            for root in (f['app'],f['control']):
                self.assertFalse((root/r.RECOVERY_GIT_DIRECTORY).exists())
            if provider_failure or crash_at:
                for key,root in [('application',f['app']),('control',f['control'])]:
                    self.assertEqual(r._identity(root),(f['index'][key]['commit'],f['index'][key]['tree']))
            else:
                self.assertNotIn('system.posix_acl_default',os.listxattr(f['app']/'created'))
                self.assertIn('system.posix_acl_default',os.listxattr(f['app']))

    def test_process_loss_at_each_materialization_boundary(self):
        for boundary in ('OBJECT_ALLOCATED','OBJECT_METADATA_SET','OBJECT_BOUND','RETIRE_INTENT','RETIRED','PUBLISH_INTENT',
                         'PUBLISHED','RECORDS_PUBLISHED','INDEX_UPDATED','REF_UPDATED'):
            with self.subTest(boundary=boundary):
                self.full_chain(crash_at=boundary)

    def test_process_loss_at_each_rollback_boundary(self):
        for boundary in ('WITHDRAW_INTENT','WITHDRAWN','RESTORE_INTENT','RESTORED'):
            with self.subTest(boundary=boundary):
                self.full_chain(provider_failure=True,crash_at=boundary)

    def test_foreign_root_mutation_and_reversion_stays_closed(self):
        def attack(f):
            # A different root TID changes and restores an unrelated tracked
            # mode. Equality after the attack must not legitimize this writer.
            path=f['app']/'.gitignore'
            mode=path.stat().st_mode&0o7777
            subprocess.run([sys.executable,'-c',
                'import os,sys; p=sys.argv[1]; m=int(sys.argv[2]); os.chmod(p,m^64); os.chmod(p,m)',
                str(path),str(mode)],check=True)
        self.full_chain(attack=attack)

    def test_same_content_root_successor_after_phase_handoff_is_rejected(self):
        def replace(f):
            path=f['app']/'kept'
            saved=f['base']/'unbound-predecessor'
            path.rename(saved)
            shutil.copy2(saved,path)
            os.chown(path,saved.stat().st_uid,saved.stat().st_gid)
        self.full_chain(attack=replace,attack_at='REPOSITORIES_MATERIALIZED')

    def test_interruption_cannot_adopt_unknown_inode_acl_or_parent(self):
        def staged(f):
            return f['state']/'attempts'/r.FOLLOWUP_SLOT/'materialization/application/new/0'
        def inode(f):
            path=staged(f);old=f['base']/'unbound-old-inode'
            path.rename(old);path.mkdir()
            shutil.copystat(old,path);os.chown(path,old.stat().st_uid,old.stat().st_gid)
        def acl(f):
            os.setxattr(staged(f),'system.posix_acl_default',os.getxattr(f['app'],'system.posix_acl_default'))
        def parent(f):
            root=f['app'];old=f['base']/'unbound-old-parent'
            root.rename(old);root.mkdir()
            for path in old.iterdir():path.rename(root/path.name)
            shutil.copystat(old,root);os.chown(root,old.stat().st_uid,old.stat().st_gid)
        def policy(f):
            journal=staged(f).parent.parent/'journal.json'
            value=json.loads(journal.read_bytes());value['entries'][0]['policy']['uid']=0
            private_json(journal,value)
        for name,tamper in (('inode',inode),('acl',acl),('parent',parent),('policy',policy)):
            with self.subTest(tamper=name):
                self.full_chain(crash_at='OBJECT_BOUND',tamper=tamper)

    def test_full_success_chain_and_replay(self):
        self.full_chain(provider_failure=False)

    def test_full_failed_activation_rollback_chain_and_replay(self):
        self.full_chain(provider_failure=True)

    def test_r12_metadata_then_actual_recovery(self):
        with fixture(complete_backup=True) as f:
            historical=r.ATTEMPT_MARKER.read_bytes()
            self.assertEqual(r.reconcile_metadata(f['contract'])['safe_code'],
                             'S12_1_R12_METADATA_SEALED')
            real_run=r._run
            def host_boundary(argv, **kwargs):
                if argv[0]=='systemctl':
                    return subprocess.CompletedProcess(argv,0,
                        'LoadState=not-found\nActiveState=inactive\nSubState=dead\n','')
                if argv[0]=='nginx':
                    return subprocess.CompletedProcess(argv,0,'','')
                return real_run(argv,**kwargs)
            with mock.patch.object(r,'_run',side_effect=host_boundary):
                result=r.recover()
            self.assertTrue(result['ok'])
            self.assertEqual(r.ATTEMPT_MARKER.read_bytes(),historical)
            for key,root in [('application',f['app']),('control',f['control'])]:
                self.assertEqual(r._identity(root),(f['index'][key]['commit'],f['index'][key]['tree']))
                self.assertFalse((root/r.RECOVERY_GIT_DIRECTORY).exists())


if __name__=='__main__':unittest.main()
