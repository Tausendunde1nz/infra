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
import signal
import struct
import unittest
from unittest import mock
from contextlib import ExitStack, contextmanager

from scripts import tu1nz_adult_commercial_s12_1_runtime as r
from tests.test_s12_1_r12_metadata_contract import fixture, private_json


class WriterEnvelopeTests(unittest.TestCase):
    def test_no_unrouted_git_subprocess_helpers_remain(self):
        import ast
        tree=ast.parse(Path(r.__file__).read_text())
        owners=[]
        for function in tree.body:
            if isinstance(function,(ast.FunctionDef,ast.AsyncFunctionDef)):
                for node in ast.walk(function):
                    if (isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
                            and isinstance(node.func.value,ast.Name) and node.func.value.id=='subprocess'
                            and node.func.attr in {'run','check_output','check_call','Popen'}):
                        owners.append(function.name)
        self.assertEqual(sorted(owners),['_git_process','_run'])

    def test_failed_epoch_rejects_direct_bundle_entry_before_spawn(self):
        guard=r._R13GitWriters.__new__(r._R13GitWriters)
        guard.failed=True;guard.fd=12345
        with mock.patch.object(r.subprocess,'Popen') as spawn,self.assertRaises(r.S12ControlError):
            guard.run((Path('/isolated'),['git','bundle','unbundle'],{}),30)
        spawn.assert_not_called()

    @staticmethod
    def event(*, tid=42, mask=0x104, kind=1, handle=b'abcd', name=b''):
        info=struct.pack('=BBH',kind,0,20+len(handle)+len(name))+b'12345678'
        info+=struct.pack('=Ii',len(handle),1)+handle+name
        return struct.pack('=IBBHQii',24+len(info),3,0,24,mask,-1,tid)+info

    def test_opaque_identity_without_names(self):
        data=self.event()+self.event(kind=2,name=b'private-name\0',mask=0x100)
        events=r._r13_fid_events(data)
        self.assertEqual(len(events),2)
        self.assertEqual(events[0][3],b'12345678'+struct.pack('=i',1)+b'abcd')
        self.assertNotIn(b'private-name',repr(events).encode())

    def test_overflow_unknown_pid_truncation_and_unknown_info_fail_closed(self):
        for data in (b'x',self.event()[:-1],self.event(mask=0x4000),
                     self.event(tid=0),self.event(kind=4),self.event(kind=2)):
            with self.subTest(data=data[:24]),self.assertRaises(r.S12ControlError):
                r._r13_fid_events(data)

    def test_child_event_before_parent_does_not_gain_retrospective_authority(self):
        for actor in (99,42):
            guard=r._R13GitWriters.__new__(r._R13GitWriters)
            guard.fd=12345;guard.failed=False;guard.controller_tid=99;guard.tasks={}
            guard.members={b'root':Path('/isolated')};guard.pending=[]
            events=[(actor,0x104,(b'new-dir',),b'new-file'),
                    (99,0x100,(b'root',),b'new-dir')]
            with mock.patch.object(r.os,'read',side_effect=[b'events',BlockingIOError]), \
                    mock.patch.object(r,'_r13_fid_events',return_value=events), \
                    mock.patch.object(guard,'fail',side_effect=r.S12ControlError(r.GIT_WRITER_RED)):
                if actor==99:
                    guard.check();self.assertIn(b'new-file',guard.members)
                else:
                    with self.assertRaises(r.S12ControlError):guard.check()


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'native Linux writer supervision required')
class AWriterTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.base=Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir='/root')))
        self.root=self.base/'repo';self.root.mkdir()
        self.state=self.base/'state';self.state.mkdir(mode=0o700)
        subprocess.run(['git','init',str(self.root)],check=True,capture_output=True)
        subprocess.run(['git','-C',str(self.root),'-c','user.name=Fixture',
            '-c','user.email=fixture@example.invalid','commit','--allow-empty','-m','fixture'],check=True,capture_output=True)
        self.sha=subprocess.check_output(['git','-C',str(self.root),'rev-parse','HEAD'],text=True).strip()
        for name,value in {'STATE_ROOT':self.state,'ACTIVE_ATTEMPT':{'isolated':'writer-test'},
                           'APPLICATION_ROOT':self.root,'CHATOPS_USER':'root'}.items():
            self.stack.enter_context(mock.patch.object(r,name,value))
        self.writer=r._R13GitWriters((self.root,))
        self.addCleanup(lambda:self.writer.close(aborted=True))

    def test_00_real_symbolic_ref_transport(self):
        command=r._recovery_git_arguments(self.root,self.root/'.git','symbolic-ref','--quiet','--short','HEAD')
        result=self.writer.run(self.writer.command(command),30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(result.stdout.strip())
        self.assertEqual(result.stderr,'')

    def test_worktree_reverted_write_during_initial_inventory_is_rejected(self):
        path=self.root/'existing';path.write_text('same contents');path.chmod(0o600)
        self.writer.close()
        fired=False
        def attack(name):
            nonlocal fired
            if name=='GIT_WRITER_INVENTORY':
                subprocess.run([sys.executable,'-c',
                    'import os,sys; p=sys.argv[1]; os.chmod(p,0o640); os.chmod(p,0o600)',
                    str(path)],check=True)
                fired=True
        with mock.patch.object(r,'_r13_boundary',side_effect=attack), \
                mock.patch.object(r.subprocess,'check_output',side_effect=AssertionError('unbound Git')), \
                self.assertRaises(r.S12ControlError):
            r._R13GitWriters((self.root,))
        self.assertTrue(fired)
        self.assertEqual(path.read_text(),'same contents')
        self.assertEqual(json.loads(self.writer.journal.read_text())['phase'],'FAILED')

    def test_read_only_text_binary_and_bundle_helpers_are_supervised(self):
        with mock.patch.object(r,'GIT_WRITER_SCOPE',self.writer):
            self.assertEqual(r._recovery_git(self.root,self.root/'.git','rev-parse','HEAD'),self.sha)
            r._recovery_git(self.root,self.root/'.git','status','--porcelain')
            r._bounded_nul_command_records(r._recovery_git_arguments(
                self.root,self.root/'.git','ls-files','-z'),r.GIT_WRITER_RED)
            result=r._git_process(r._recovery_git_arguments(
                self.root,self.root/'.git','cat-file','commit',self.sha))
            self.assertIsInstance(result.stdout,bytes)
            bundle=self.base/'fixture.bundle'
            r._create_git_bundle(self.root,bundle,self.root/'.git')
            r._verify_git_bundle(self.root,bundle,self.root/'.git')
            r._git_bundle_heads(self.root,bundle,self.root/'.git')
        history=json.loads(self.writer.journal.read_text())['history']
        self.assertGreaterEqual(len(history),7)
        self.assertTrue(all(op['access_profile']=='READ_ONLY' for op in history))
        self.assertTrue(all(task['exited'] for op in history for task in op['task_history']))

    def test_replaced_git_path_cannot_run_unrestricted_read_only_code(self):
        decoy=self.base/'approved-git';shutil.copy2('/usr/bin/git',decoy);decoy.chmod(0o500)
        self.writer.image_paths['git']=decoy
        self.writer.images['git']=self.writer.executable(decoy)
        replacement=self.base/'replacement-git';outside=self.base/'unrestricted-git-ran'
        replacement.write_text(f'#!{sys.executable}\nfrom pathlib import Path\nPath({str(outside)!r}).touch()\n')
        replacement.chmod(0o500)
        fired=False
        def replace(name):
            nonlocal fired
            if name=='GIT_WRITER_INTENT':
                subprocess.run([sys.executable,'-c','import os,sys; os.replace(sys.argv[1],sys.argv[2])',
                                str(replacement),str(decoy)],check=True)
                fired=True
        with mock.patch.object(r,'GIT_WRITER_SCOPE',self.writer), \
                mock.patch.object(r,'_r13_boundary',side_effect=replace),self.assertRaises(r.S12ControlError):
            r._recovery_git(self.root,self.root/'.git','status','--porcelain')
        self.assertTrue(fired)
        self.assertFalse(outside.exists())
        self.assertEqual(json.loads(self.writer.journal.read_text())['phase'],'FAILED')

    def test_bootstrap_path_replacement_after_intent_cannot_execute(self):
        interpreter=sys.executable
        decoy=self.base/'bootstrap-python'
        shutil.copy2(interpreter,decoy);decoy.chmod(0o500)
        replacement=self.base/'replacement-python'
        outside=self.base/'unrestricted-bootstrap-executed'
        replacement.write_text(f'#!{interpreter}\nimport os,sys\nfrom pathlib import Path\n'
            f'Path({str(outside)!r}).write_text("bad")\n'
            f'os.execv({interpreter!r},[{interpreter!r},*sys.argv[1:]])\n')
        replacement.chmod(0o500)
        fired=False
        def replace(name):
            nonlocal fired
            if name=='GIT_WRITER_INTENT':
                fired=True
                subprocess.run([interpreter,'-c','import os,sys; os.replace(sys.argv[1],sys.argv[2])',
                                str(replacement),str(decoy)],check=True)
        selected=self.writer.command(r._recovery_git_arguments(
            self.root,self.root/'.git','update-ref','refs/heads/bound-bootstrap',self.sha))
        with mock.patch.object(r.sys,'executable',str(decoy)), \
                mock.patch.object(r,'_r13_boundary',side_effect=replace):
            result=self.writer.run(selected,30)
        self.assertTrue(fired)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(outside.exists())
        self.assertEqual(json.loads(self.writer.journal.read_text())['images']['bootstrap'],
                         self.writer.executable(Path('/proc/self/exe')))

    def test_real_git_new_nested_metadata_and_foreign_reversion(self):
        command=r._recovery_git_arguments(self.root,self.root/'.git','update-ref','refs/heads/new/deep/ref',self.sha)
        result=self.writer.run(self.writer.command(command),30)
        self.assertEqual(result.returncode,0,result.stderr)
        path=self.root/'.git/refs/heads/new/deep/ref'
        self.assertIn(self.writer.handle(path),self.writer.members)
        mode=path.stat().st_mode&0o7777
        subprocess.run([sys.executable,'-c','import os,sys; p=sys.argv[1]; m=int(sys.argv[2]); os.chmod(p,m^64); os.chmod(p,m)',
                        str(path),str(mode)],check=True)
        with self.assertRaises(r.S12ControlError):self.writer.check()

    def test_controller_descendant_is_not_a_git_writer(self):
        path=self.root/'.git/HEAD'
        def attack(name):
            if name=='GIT_WRITER_BOUND':
                subprocess.run([sys.executable,'-c','import os,sys; p=sys.argv[1]; m=os.stat(p).st_mode; os.chmod(p,m^64); os.chmod(p,m)',str(path)],check=True)
        command=r._recovery_git_arguments(self.root,self.root/'.git','update-ref','refs/heads/new',self.sha)
        with mock.patch.object(r,'_r13_boundary',side_effect=attack),self.assertRaises(r.S12ControlError):
            self.writer.run(self.writer.command(command),30)
        self.assertEqual(json.loads(self.writer.journal.read_text())['phase'],'FAILED')

    def test_transient_nested_creation_cannot_escape_watch_inventory(self):
        subprocess.run([sys.executable,'-c',
            'from pathlib import Path; import sys; p=Path(sys.argv[1])/"unknown"; p.mkdir(); q=p/"deeper"; q.mkdir(); f=q/"ref"; f.write_text("x"); f.unlink(); q.rmdir(); p.rmdir()',
            str(self.root/'.git/refs')],check=True)
        with self.assertRaises(r.S12ControlError):self.writer.check()

    def test_quiet_checkpoint_cannot_adopt_reverted_offline_change(self):
        self.writer.close()
        path=self.root/'.git/HEAD';mode=path.stat().st_mode
        os.chmod(path,mode^64);os.chmod(path,mode)
        with self.assertRaises(r.S12ControlError):r._R13GitWriters((self.root,))

    def test_interrupted_running_epoch_is_not_a_quiet_resume(self):
        self.writer.close()
        pid=os.fork()
        if pid==0:
            writer=r._R13GitWriters((self.root,))
            command=r._recovery_git_arguments(self.root,self.root/'.git','update-ref','refs/heads/never',self.sha)
            with mock.patch.object(r,'_r13_boundary',side_effect=lambda name:os._exit(73)
                                   if name=='GIT_WRITER_BOUND' else None):
                writer.run(writer.command(command),30)
            os._exit(74)
        _,status=os.waitpid(pid,0)
        self.assertEqual(os.waitstatus_to_exitcode(status),73)
        self.assertFalse((self.root/'.git/refs/heads/never').exists())
        value=json.loads(self.writer.journal.read_text())
        self.assertEqual(value['phase'],'RUNNING')
        self.assertEqual(len(value['tasks']),1)
        with self.assertRaises(r.S12ControlError):r._R13GitWriters((self.root,))

    def test_landlock_prevents_git_output_outside_bound_metadata(self):
        # A real Git writer cannot create an output file in an ungranted path.
        # This helper role is exercised directly, not added to command admission.
        selected=self.writer.command(r._recovery_git_arguments(self.root,self.root/'.git','update-ref','refs/heads/new',self.sha))
        root,args,env=selected
        args=args[:-3]+['bundle','create',str(self.base/'outside.bundle'),'--all']
        result=self.writer.run((root,args,env),30)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.base/'outside.bundle').exists())

    def test_unplanned_child_executable_never_runs(self):
        selected=self.writer.command(r._recovery_git_arguments(self.root,self.root/'.git','update-ref','refs/heads/new',self.sha))
        root,args,env=selected
        forbidden=self.base/'must-not-exist'
        args=args[:-3]+['-c','alias.unplanned=!touch '+str(forbidden),'unplanned']
        with self.assertRaises(r.S12ControlError):self.writer.run((root,args,env),30)
        self.assertFalse(forbidden.exists())

    def test_failure_at_fork_stop_reaps_unadmitted_child(self):
        root,args,env=self.writer.command(r._recovery_git_arguments(
            self.root,self.root/'.git','update-ref','refs/heads/new',self.sha))
        args=args[:-3]+['-c','alias.forktest=!true','forktest']
        fired=False
        def attack(name):
            nonlocal fired
            if name=='GIT_WRITER_FORK' and not fired:
                fired=True
                subprocess.run([sys.executable,'-c',
                    'import os,sys; p=sys.argv[1]; m=os.stat(p).st_mode; os.chmod(p,m^64); os.chmod(p,m)',
                    str(self.root/'.git/HEAD')],check=True)
        with mock.patch.object(r,'_r13_boundary',side_effect=attack), \
                mock.patch.object(r.os,'kill',wraps=os.kill) as killed, \
                self.assertRaises(r.S12ControlError):
            self.writer.run((root,args,env),30)
        self.assertTrue(fired)
        tids={c.args[0] for c in killed.call_args_list if c.args[1]==signal.SIGKILL}
        self.assertGreaterEqual(len(tids),2)
        for tid in tids:
            with self.assertRaises(ChildProcessError):os.waitpid(tid,os.WNOHANG|0x40000000)
        self.assertEqual(json.loads(self.writer.journal.read_text())['phase'],'FAILED')

    def test_real_git_pack_threads_have_bound_lifetimes(self):
        files=[]
        for i in range(256):
            path=self.base/f'blob-{i}'
            path.write_bytes((b'common content '+str(i).encode()+b'\n')*4000)
            files.append(str(path))
        root,args,env=self.writer.command(r._recovery_git_arguments(
            self.root,self.root/'.git','update-ref','refs/heads/new',self.sha))
        prefix=args[:-3]
        objects=self.writer.run((root,prefix+['hash-object','-w',*files],env),30)
        self.assertEqual(objects.returncode,0,objects.stderr)
        with tempfile.TemporaryFile() as source:
            source.write(objects.stdout.encode());source.seek(0)
            packed=self.writer.run((root,prefix+['pack-objects','--threads=4','--window=10',
                str(self.root/'.git/objects/pack/bound')],env),30,stdin=source)
        self.assertEqual(packed.returncode,0,packed.stderr)
        history=json.loads(self.writer.journal.read_text())['history'][-1]['task_history']
        self.assertGreaterEqual(len(history),3)  # main plus real clone threads
        self.assertTrue(all(t['exited'] for t in history))
        self.assertTrue(all(t['parent']==history[0]['tid'] for t in history[1:]))

    def test_journal_failure_still_reaps_writers_and_keeps_unrelated_process(self):
        selected=self.writer.command(r._recovery_git_arguments(
            self.root,self.root/'.git','update-ref','refs/heads/never',self.sha))
        unavailable=False
        atomic=r._atomic_json
        def journal(*args,**kwargs):
            if unavailable:raise OSError('isolated journal unavailable')
            return atomic(*args,**kwargs)
        def interrupt(name):
            nonlocal unavailable
            if name=='GIT_WRITER_BOUND':
                unavailable=True
                raise OSError('isolated interruption')
        unrelated=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])
        try:
            with mock.patch.object(r,'_atomic_json',side_effect=journal), \
                    mock.patch.object(r,'_r13_boundary',side_effect=interrupt), \
                    mock.patch.object(r.os,'kill',wraps=os.kill) as killed, \
                    self.assertRaisesRegex(OSError,'isolated journal unavailable'):
                self.writer.run(selected,30)
            tids={c.args[0] for c in killed.call_args_list if c.args[1]==signal.SIGKILL}
            self.assertTrue(tids)
            for tid in tids:
                with self.assertRaises(ChildProcessError):os.waitpid(tid,os.WNOHANG|0x40000000)
            self.assertIsNone(unrelated.poll())
            self.assertFalse((self.root/'.git/refs/heads/never').exists())
            self.assertEqual(json.loads(self.writer.journal.read_text())['phase'],'RUNNING')
            self.writer.close(aborted=True)
            with self.assertRaises(r.S12ControlError):r._R13GitWriters((self.root,))
        finally:
            unrelated.terminate();unrelated.wait(timeout=5)


class GuardOwnerTests(unittest.TestCase):
    def test_verified_handoff_does_not_reuse_closed_callbacks(self):
        events=[]
        @contextmanager
        def guard():
            live=True
            def check():self.assertTrue(live)
            yield check
            check();live=False;events.append('closed')
        with r._R13GuardStack() as owner:
            for _ in range(2):
                owner.retain(guard());owner.paths.add(Path('/isolated-test-only'))
                owner.assert_quiet();owner.close()
                self.assertEqual(owner.checks,[]);self.assertEqual(owner.paths,set())
                owner.assert_quiet()
        self.assertEqual(events,['closed','closed'])

    def test_failed_handoff_cannot_reuse_owner(self):
        @contextmanager
        def guard():
            yield lambda:None
            raise r.S12ControlError(r.MATERIALIZATION_RED)
        with r._R13GuardStack() as owner:
            owner.retain(guard())
            with self.assertRaises(r.S12ControlError):owner.close()
            with self.assertRaises(r.S12ControlError):owner.assert_quiet()
            with self.assertRaises(r.S12ControlError):owner.retain(guard())


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,
                     'native Linux protected receipt checks required')
class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.base=Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir='/root')))
        self.state=self.base/'state';self.state.mkdir(mode=0o700)
        for name in ('app','control'):(self.base/name).mkdir(mode=0o700)
        for key,value in dict(PRIVATE_ROOT=self.base,STATE_ROOT=self.state,
                BACKUP_ROOT=self.base/'backups',DEPLOYMENT_LOCK_ROOT=self.base,
                APPLICATION_ROOT=self.base/'app',CONTROL_ROOT=self.base/'control').items():
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

    def test_cross_filesystem_rejected_before_claim_consumption(self):
        digest=self.write()
        with tempfile.TemporaryDirectory(dir='/dev/shm') as temporary:
            state=Path(temporary)
            self.assertNotEqual(state.stat().st_dev,self.base.stat().st_dev)
            with mock.patch.object(r,'STATE_ROOT',state),mock.patch.object(r,'_followup_parent_closed'), \
                    mock.patch.object(r,'read_only_preflight'),mock.patch.object(r,'_deploy_locked') as deploy:
                with self.assertRaisesRegex(r.S12ControlError,'MATERIALIZATION_FILESYSTEM_RED'):
                    r.followup(self.path,digest)
                deploy.assert_not_called()
            self.assertEqual(list(state.iterdir()),[])

    def test_empty_namespace_closure_survives_process_loss_without_adoption(self):
        digest=self.write()
        with mock.patch.object(r,'_followup_parent_closed'),mock.patch.object(r,'read_only_preflight'), \
                mock.patch.object(r,'_deploy_locked',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):r.followup(self.path,digest)
            namespace=self.state/'attempts'/r.FOLLOWUP_SLOT
            namespace.mkdir(parents=True,mode=0o700)
            original=namespace.stat()
            claim=self.state/(r.FOLLOWUP_SLOT+'.consumed.json');claim_bytes=claim.read_bytes()
            for boundary in ('FOLLOWUP_EARLY_CLOSURE_BEFORE_WRITE','FOLLOWUP_EARLY_CLOSURE_WRITTEN'):
                pid=os.fork()
                if pid==0:
                    def die(name):
                        if name==boundary:os._exit(73)
                    with mock.patch.object(r,'_r13_boundary',side_effect=die):
                        r.followup(self.path,digest,recovering=True)
                    os._exit(74)
                _,status=os.waitpid(pid,0)
                self.assertEqual(os.waitstatus_to_exitcode(status),73)
            first=r.followup(self.path,digest,recovering=True)
            self.assertEqual(first,r.followup(self.path,digest,recovering=True))
            self.assertEqual(first['deployment_count'],0)
            self.assertEqual(list(namespace.iterdir()),[])
            for field in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_mtime_ns','st_ctime_ns'):
                self.assertEqual(getattr(namespace.stat(),field),getattr(original,field))
            self.assertEqual(claim.read_bytes(),claim_bytes)
            with self.assertRaisesRegex(r.S12ControlError,'ALREADY_CONSUMED'):
                r.followup(self.path,digest)
            (namespace/'unknown').touch()
            with self.assertRaises(r.S12ControlError):
                r.followup(self.path,digest,recovering=True)


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
                    cleanup=tamper(f)
                    try:
                        with self.assertRaises((r.S12ControlError,OSError)):
                            r.followup(authorization,grant_hash,recovering=True)
                    finally:
                        if cleanup:cleanup()
                    self.assertEqual(self.starts,0)
                    self.assertEqual(r.ATTEMPT_MARKER.read_bytes(),historical)
                    for root in (f['app'],f['control']):
                        self.assertTrue(r._is_recovery_guard(root/'.git'))
                    with self.assertRaisesRegex(r.S12ControlError,'ALREADY_CONSUMED'):
                        r.followup(authorization,grant_hash)
                    return
                result=r.followup(authorization,grant_hash,recovering=True)
                self.assertTrue(result['ok'])
                if crash_at=='FOLLOWUP_NAMESPACE_CREATED':
                    self.assertEqual(result['rollback_count'],0)
                    self.assertEqual(result['deployment_count'],0)
                    self.assertEqual(list((f['state']/'attempts'/r.FOLLOWUP_SLOT).iterdir()),[])
                    self.assertEqual(r.ATTEMPT_MARKER.read_bytes(),historical)
                    self.assertEqual(self.starts,0)
                    for key,root in [('application',f['app']),('control',f['control'])]:
                        self.assertEqual(r._identity(root),(f['index'][key]['commit'],f['index'][key]['tree']))
                    self.assertEqual(r.followup(authorization,grant_hash,recovering=True),result)
                    with self.assertRaisesRegex(r.S12ControlError,'ALREADY_CONSUMED'):
                        r.followup(authorization,grant_hash)
                    return
                self.assertEqual(result['rollback_count'],1)
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
                        attack(f)
                        fired=True  # Setup failure must not masquerade as a rejected writer.
                with mock.patch.object(r,'_r13_boundary',side_effect=interfere):
                    with self.assertRaises(r.S12ControlError):r.followup(authorization,grant_hash)
                self.assertTrue(fired)
                for root in (f['app'],f['control']):
                    self.assertTrue(r._is_recovery_guard(root/'.git'))
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
        for boundary in ('FOLLOWUP_NAMESPACE_CREATED','OBJECT_ALLOCATED','OBJECT_METADATA_SET','OBJECT_BOUND','RETIRE_INTENT','RETIRED','PUBLISH_INTENT',
                         'PUBLISHED','RECORDS_PUBLISHED','INDEX_UPDATED','REF_UPDATED'):
            with self.subTest(boundary=boundary):
                self.full_chain(crash_at=boundary)

    def test_process_loss_at_each_rollback_boundary(self):
        for boundary in ('WITHDRAW_INTENT','WITHDRAWN','RESTORE_INTENT','RESTORED'):
            with self.subTest(boundary=boundary):
                self.full_chain(provider_failure=True,crash_at=boundary)

    def test_inflight_writer_loss_retains_both_barriers_without_resume(self):
        self.full_chain(crash_at='GIT_WRITER_BOUND',tamper=lambda fixture:None)

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

    def test_reverted_root_mutation_stays_visible_through_final_audit(self):
        # Both unchanged inodes and newly published successors must retain
        # event history after the local materialization contexts have returned.
        for boundary,name in (('REPOSITORIES_MATERIALIZED','.gitignore'),
                              ('REPOSITORIES_MATERIALIZED','created/new'),
                              ('MATERIALIZATION_AUDITED','created/new'),
                              ('RELEASE_BARRIERS_EXCHANGED','created/new'),
                              ('RELEASE_ATTRIBUTES_RESTORED','created/new')):
            with self.subTest(boundary=boundary,path=name):
                def attack(f):
                    path=f['app']/name
                    mode=path.stat().st_mode&0o7777
                    subprocess.run([sys.executable,'-c',
                        'import os,sys; p=sys.argv[1]; m=int(sys.argv[2]); '
                        'os.chmod(p,m^64); os.chmod(p,m)',str(path),str(mode)],check=True)
                    self.assertEqual(path.stat().st_mode&0o7777,mode)
                self.full_chain(attack=attack,attack_at=boundary)

    def test_deep_git_reverted_writer_cannot_cross_release_handoff(self):
        for boundary in ('REF_UPDATED','REPOSITORIES_MATERIALIZED',
                         'RELEASE_BARRIERS_EXCHANGED','RELEASE_ATTRIBUTES_RESTORED'):
            with self.subTest(boundary=boundary):
                def attack(f):
                    # REF_UPDATED first fires for Application. Both pre-release
                    # seams still have the real Git metadata quarantined.
                    root=f['app'] if boundary=='REF_UPDATED' else f['control']
                    branch='main' if boundary=='REF_UPDATED' else 'control-main'
                    metadata=(r.RECOVERY_GIT_DIRECTORY if boundary in
                              {'REF_UPDATED','REPOSITORIES_MATERIALIZED'} else '.git')
                    path=root/metadata/'refs/heads'/branch
                    mode=path.stat().st_mode&0o7777
                    subprocess.run([sys.executable,'-c',
                        'import os,sys; p=sys.argv[1]; m=int(sys.argv[2]); '
                        'os.chmod(p,m^64); os.chmod(p,m)',str(path),str(mode)],check=True)
                    self.assertEqual(path.stat().st_mode&0o7777,mode)
                self.full_chain(attack=attack,attack_at=boundary)

    def test_existing_worktrees_are_watched_before_fetch_and_materialization(self):
        for boundary in ('REPOSITORY_BODY_ENTERED','APPLICATION_FETCHED'):
            for key in ('app','control'):
                with self.subTest(boundary=boundary,repository=key):
                    def attack(f):
                        path=f[key]/'kept'
                        mode=path.stat().st_mode&0o7777
                        subprocess.run([sys.executable,'-c',
                            'import os,sys; p=sys.argv[1]; m=int(sys.argv[2]); '
                            'os.chmod(p,m^64); os.chmod(p,m)',str(path),str(mode)],check=True)
                        self.assertEqual(path.stat().st_mode&0o7777,mode)
                    self.full_chain(attack=attack,attack_at=boundary)

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

    def test_pending_recovery_rejects_live_git_handle_before_any_move(self):
        def hold(f):
            head=f['app']/r.RECOVERY_GIT_DIRECTORY/'HEAD'
            proc=subprocess.Popen([sys.executable,'-c',
                'import sys,time; f=open(sys.argv[1],"r+b"); print("READY",flush=True); time.sleep(60)',
                str(head)],stdout=subprocess.PIPE,text=True)
            self.assertEqual(proc.stdout.readline().strip(),'READY')
            def close():
                proc.terminate();proc.wait(timeout=5);proc.stdout.close()
            return close
        self.full_chain(crash_at='OBJECT_BOUND',tamper=hold)

    def test_pending_recovery_requires_inactive_runtime(self):
        def active(f):
            override=mock.patch.object(r,'_rollback_unit_state',return_value=('active','running'))
            override.start()
            return override.stop
        self.full_chain(crash_at='OBJECT_BOUND',tamper=active)

    def test_pending_undo_hands_event_history_to_canonical_recovery(self):
        fired=[]
        def during_recovery(f):
            def attack(name):
                if name=='PENDING_MATERIALIZATION_UNDONE':
                    fired.append(name)
                    path=f['app']/'.gitignore';mode=path.stat().st_mode&0o7777
                    subprocess.run([sys.executable,'-c',
                        'import os,sys; p=sys.argv[1]; m=int(sys.argv[2]); '
                        'os.chmod(p,m^64); os.chmod(p,m)',str(path),str(mode)],check=True)
            override=mock.patch.object(r,'_r13_boundary',side_effect=attack)
            override.start()
            return override.stop
        self.full_chain(crash_at='OBJECT_BOUND',tamper=during_recovery)
        self.assertEqual(fired,['PENDING_MATERIALIZATION_UNDONE'])

    def test_00_full_success_chain_and_replay(self):
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
