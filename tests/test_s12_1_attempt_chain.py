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
import unittest
from unittest import mock
from contextlib import ExitStack

from scripts import tu1nz_adult_commercial_s12_1_runtime as r
from tests.test_s12_1_r12_metadata_contract import fixture, private_json


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,
                     'native Linux root + kernel guards required')
class IntegratedChainTests(unittest.TestCase):
    def host_boundary(self, argv, **kwargs):
        if argv[0]=='systemctl':
            if 'start' in argv:
                self.starts += 1
                raise AssertionError('provider simulation not yet implemented')
            if 'is-enabled' in argv:
                output='enabled\n' if argv[-1]==r.S11_TIMER else 'not-found\n'
            elif '--property=LoadState,ActiveState,SubState' in argv:
                output='LoadState=not-found\nActiveState=inactive\nSubState=dead\n'
            elif '-p' in argv:
                name=argv[argv.index('-p')+1]
                output={'ActiveState':'active','NRestarts':'0','SubState':'waiting','Result':'success',
                        'ExecMainStatus':'0','NextElapseUSecRealtime':'2099-01-01 00:00:00 UTC'}.get(name,'')
            else:output=''
            return subprocess.CompletedProcess(argv,0,output,'')
        if argv[0]=='nginx':return subprocess.CompletedProcess(argv,0,'','')
        if argv[0]=='curl':return subprocess.CompletedProcess(argv,0,'308' if '.de/' in argv[-1] else '200','')
        return self.real_run(argv,**kwargs)

    def test_followup_chain_through_real_git_sync(self):
        with fixture(complete_backup=True) as f, ExitStack() as patches:
            self.real_run=r._run;self.starts=0
            patches.enter_context(mock.patch.object(r,'_run',side_effect=self.host_boundary))
            # Substitute only the fixture's interpreter/venv attestation.
            patches.enter_context(mock.patch.object(r,'_validate_source_runtime_environment'))
            trusted=f['base']/'controller.py'
            trusted.write_bytes(Path(r.__file__).read_bytes());trusted.chmod(0o500)
            controller_hash=hashlib.sha256(trusted.read_bytes()).hexdigest()
            patches.enter_context(mock.patch.object(r,'__file__',str(trusted)))
            patches.enter_context(mock.patch.object(r,'TRUSTED_CONTROLLER_PATH',trusted))
            release=json.loads(f['contract'].read_bytes())['release_commits']
            exports={}
            for key,root in [('application',f['app']),('control',f['control'])]:
                bare=f['base']/(key+'.git')
                self.real_run(['git','clone','--bare',str(root/r.RECOVERY_GIT_DIRECTORY),str(bare)])
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
            # Until the real storage chain reaches this boundary, no provider
            # simulation can hide a failed metadata/backup/Git prerequisite.
            def stage_boundary(*args):
                raise AssertionError('REACHED_IMMUTABLE_STAGE_BOUNDARY')
            patches.enter_context(mock.patch.object(r,'_create_immutable_release_stage',side_effect=stage_boundary))
            with self.assertRaisesRegex(AssertionError,'REACHED_IMMUTABLE_STAGE_BOUNDARY'):
                r.followup(authorization,grant_hash)
            self.assertEqual(r.ATTEMPT_MARKER.read_bytes(),historical)

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
