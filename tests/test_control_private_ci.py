"""Privacy/cleanup regressions: synthetic canaries, no credentials/network."""
import contextlib
import io
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_control_private_ci as p
import tu1nz_control_recovery_contract as c
import tu1nz_control_recovery_freeze as f


class PrivateCI(unittest.TestCase):
    def test_only_exact_declared_source_prs_are_eligible_not_generic_same_repo(self):
        self.assertEqual(p.APPROVED_SOURCE_PRS,frozenset((225,226,227,228)))
        with tempfile.TemporaryDirectory() as d:
            event=Path(d)/'event.json'
            env={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':p.REPOSITORY,
                 'CONTROL_PRIVATE_ENVIRONMENT':p.ENVIRONMENT,'GITHUB_EVENT_NAME':'pull_request',
                 'GITHUB_EVENT_PATH':str(event),'EXPECTED_SOURCE_SHA':'1'*40}
            for number in (225,226,227,228,229,999,'226','227','228',True):
                data={'number':number,'pull_request':{'head':{'repo':{'full_name':p.REPOSITORY},'sha':'1'*40}}}
                event.write_text(json.dumps(data))
                with patch.object(p.subprocess,'run',side_effect=lambda argv,**kw:subprocess.CompletedProcess(
                        argv,0,b'1'*40+b'\n' if 'rev-parse' in argv else b'')):
                    if type(number) is int and number in (225,226,227,228):
                        self.assertEqual(p.runtime_binding(env,Path(d)),'1'*40)
                    else:
                        with self.assertRaisesRegex(c.RecoveryError,'CI_UNTRUSTED_PR_RED'):
                            p.runtime_binding(env,Path(d))

    def test_private_location_and_finite_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d).resolve();workspace=base/'work';workspace.mkdir();parent=base/'temp';parent.mkdir()
            root=p.private_root(parent,workspace)
            self.assertEqual(root.stat().st_mode&0o777,0o700)
            (root/'SYNTHETIC_PRIVATE_CANARY').write_text('keep out of public output')
            p.remove_private(root,parent);self.assertFalse(root.exists())
            with self.assertRaises(c.RecoveryError):p.private_root(workspace,workspace)
            with self.assertRaises(c.RecoveryError):p.remove_private(workspace,base)

    def test_runtime_rejects_fork_event_wrong_sha_before_fetch(self):
        with tempfile.TemporaryDirectory() as d:
            event=Path(d)/'event.json'
            data={'number':225,'pull_request':{'head':{'repo':{'full_name':p.REPOSITORY},'sha':'1'*40}}}
            event.write_text(json.dumps(data))
            env={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':p.REPOSITORY,
                 'CONTROL_PRIVATE_ENVIRONMENT':p.ENVIRONMENT,'GITHUB_EVENT_NAME':'pull_request',
                 'GITHUB_EVENT_PATH':str(event),'EXPECTED_SOURCE_SHA':'1'*40}
            with patch.dict(os.environ,{'CONTROL_POLICY_READ_TOKEN':'SYNTHETIC_SECRET','GIT_TRACE':'1'}),\
                 patch.object(p.subprocess,'run',side_effect=lambda argv,**kw:subprocess.CompletedProcess(
                     argv,0,b'1'*40+b'\n' if 'rev-parse' in argv else b'')) as process:
                self.assertEqual(p.runtime_binding(env,Path(d)),'1'*40)
                self.assertNotIn('CONTROL_POLICY_READ_TOKEN',process.call_args.kwargs['env'])
                self.assertNotIn('GIT_TRACE',process.call_args.kwargs['env'])
                for key,value in (('CONTROL_PRIVATE_ENVIRONMENT','foreign'),('GITHUB_EVENT_NAME','pull_request_target'),
                                  ('EXPECTED_SOURCE_SHA','2'*40)):
                    with self.subTest(key=key),self.assertRaises(c.RecoveryError):
                        p.runtime_binding({**env,key:value},Path(d))
                data['pull_request']['head']['repo']['full_name']='foreign/fork';event.write_text(json.dumps(data))
                with self.assertRaises(c.RecoveryError):p.runtime_binding(env,Path(d))
                data['pull_request']['head']['repo']['full_name']=p.REPOSITORY;event.write_text(json.dumps(data))
                process.side_effect=lambda argv,**kw:subprocess.CompletedProcess(
                    argv,0,b'1'*40+b'\n' if 'rev-parse' in argv else b'changed')
                with self.assertRaisesRegex(c.RecoveryError,'CI_SOURCE_WORKING_SET_RED'):p.runtime_binding(env,Path(d))

    @unittest.skipUnless(sys.platform=='linux','required native Linux process-group semantics')
    def test_early_leader_exit_does_not_leave_live_pipe_holder(self):
        with tempfile.TemporaryDirectory() as d:
            tick=Path(d)/'synthetic-tick'
            code='import os,time,sys\nfrom pathlib import Path\npid=os.fork()\nif pid:os._exit(0)\np=Path(sys.argv[1])\nwhile True:p.write_text(str(time.monotonic()));time.sleep(0.01)\n'
            with self.assertRaisesRegex(c.RecoveryError,'CI_CHILD_TIMEOUT'):
                p.bounded([sys.executable,'-c',code,str(tick)],timeout=0.3)
            before=tick.read_bytes();time.sleep(0.1)
            self.assertEqual(tick.read_bytes(),before)

    @unittest.skipUnless(sys.platform=='linux','required native Linux interruption witness')
    def test_real_sigterm_and_sigint_cleanup_private_input_without_leak(self):
        code='''
import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import tu1nz_control_private_ci as p
base=Path(sys.argv[2]);work=base/'work';work.mkdir();temp=base/'temp';temp.mkdir()
os.environ['RUNNER_TEMP']=str(temp)
os.environ['CONTROL_POLICY_READ_TOKEN']='github_pat_SYNTHETIC_ONLY'
p.runtime_binding=lambda env,root:'1'*40
def fetch(root,token):
 file=root/'cap';file.write_bytes(b'SYNTHETIC_PRIVATE_CANARY');return file,'a'*64
p.fetch_capsule=fetch
p.native_argv=lambda *args:[sys.executable,'-c','import time;time.sleep(20)']
p.cleanup_container=lambda *args:(base/'cleanup-called').write_text('yes')
with p.interrupted():
 (base/'ready').write_text('yes')
 raise SystemExit(p.run(work,'image'))
'''
        scripts=str(Path(__file__).resolve().parents[1]/'scripts')
        for sig in (signal.SIGTERM,signal.SIGINT):
            with self.subTest(signal=sig),tempfile.TemporaryDirectory() as d:
                base=Path(d)
                child=subprocess.Popen([sys.executable,'-I','-B','-c',code,scripts,d],
                                       stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:
                    deadline=time.monotonic()+5
                    while not list((base/'temp').glob('tu1nz-control-private-*')):
                        self.assertLess(time.monotonic(),deadline);time.sleep(0.01)
                    # Wait for the captured native child, not just before run.
                    time.sleep(0.05);child.send_signal(sig)
                    out,err=child.communicate(timeout=5)
                    self.assertEqual(child.returncode,1,err)
                    self.assertNotIn(b'CANARY',out+err);self.assertNotIn(b'github_pat',out+err)
                    self.assertEqual(list((base/'temp').iterdir()),[])
                    self.assertTrue((base/'cleanup-called').is_file())
                finally:
                    if child.poll() is None:child.kill();child.wait(timeout=5)
                    child.stdout.close();child.stderr.close()

    def test_capsule_only_mount_and_no_token_in_child_environment(self):
        argv=p.native_argv(Path('/public/work'),Path('/private/temp/target-capsule.json'),'public-image','own','nonce')
        self.assertIn('type=bind,src=/public/work,dst=/work,readonly',argv)
        self.assertIn('type=bind,src=/private/temp/target-capsule.json,dst=/target-capsule.json,readonly',argv)
        self.assertEqual(sum(x=='--mount' for x in argv),2)
        self.assertNotIn('CONTROL_POLICY_READ_TOKEN',str(argv))
        with patch.dict(os.environ,{'CONTROL_POLICY_READ_TOKEN':'SYNTHETIC_CANARY','GIT_TRACE':'1'}):
            self.assertNotIn('CONTROL_POLICY_READ_TOKEN',p.tool_env());self.assertNotIn('GIT_TRACE',p.tool_env())

    def test_errors_timeout_and_interrupt_never_publish_canaries_and_cleanup(self):
        for error in (RuntimeError('SYNTHETIC_PRIVATE_CANARY github_pat_SYNTHETIC'),
                      c.RecoveryError('CONTROL_RECOVERY_CI_SYNTHETIC_PRIVATE_CANARY'),
                      InterruptedError('SYNTHETIC_PRIVATE_CANARY'),c.RecoveryError('CONTROL_RECOVERY_CI_CHILD_TIMEOUT')):
            with self.subTest(error=type(error).__name__),tempfile.TemporaryDirectory() as d:
                parent=Path(d).resolve();workspace=parent/'work';workspace.mkdir();temp=parent/'temp';temp.mkdir()
                stdout=io.StringIO()
                with patch.dict(os.environ,{'RUNNER_TEMP':str(temp),'CONTROL_POLICY_READ_TOKEN':'github_pat_SYNTHETIC_ONLY'}),\
                     patch.object(p,'runtime_binding',return_value='1'*40),\
                     patch.object(p,'fetch_capsule',side_effect=error),contextlib.redirect_stdout(stdout):
                    self.assertEqual(p.run(workspace,'image'),1)
                self.assertNotIn('SYNTHETIC_PRIVATE_CANARY',stdout.getvalue())
                self.assertNotIn('github_pat',stdout.getvalue());self.assertEqual(list(temp.iterdir()),[])

    def test_missing_credential_never_fetches_or_creates_private_root(self):
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d).resolve();workspace=parent/'work';workspace.mkdir();temp=parent/'temp';temp.mkdir()
            stdout=io.StringIO()
            with patch.dict(os.environ,{'RUNNER_TEMP':str(temp)},clear=True),\
                 patch.object(p,'runtime_binding',return_value='1'*40),patch.object(p,'fetch_capsule') as fetch,\
                 contextlib.redirect_stdout(stdout):
                self.assertEqual(p.run(workspace,'image'),1);fetch.assert_not_called()
            self.assertEqual(list(temp.iterdir()),[])

    def test_native_failure_discards_raw_output_and_removes_owned_container(self):
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d).resolve();workspace=parent/'work';workspace.mkdir();temp=parent/'temp';temp.mkdir()
            stdout=io.StringIO()
            def fake_capsule(root,token):
                file=root/'target-capsule.json';file.write_bytes(b'SYNTHETIC_PRIVATE_CANARY');return file,'a'*64
            with patch.dict(os.environ,{'RUNNER_TEMP':str(temp),'CONTROL_POLICY_READ_TOKEN':'github_pat_SYNTHETIC_ONLY'}),\
                 patch.object(p,'runtime_binding',return_value='1'*40),patch.object(p,'fetch_capsule',side_effect=fake_capsule),\
                 patch.object(p,'bounded',return_value=(1,b'SYNTHETIC_PRIVATE_CANARY stdout/stderr')),\
                 patch.object(p,'cleanup_container') as cleanup,contextlib.redirect_stdout(stdout):
                self.assertEqual(p.run(workspace,'image'),1);self.assertEqual(cleanup.call_count,1)
            self.assertNotIn('CANARY',stdout.getvalue());self.assertEqual(list(temp.iterdir()),[])

    def test_bounded_capture_timeout_output_limit_and_no_public_child_output(self):
        code,raw=p.bounded([sys.executable,'-c','print("SYNTHETIC_PRIVATE_CANARY")'],timeout=5)
        self.assertEqual(code,0);self.assertIn(b'SYNTHETIC_PRIVATE_CANARY',raw)
        with self.assertRaisesRegex(c.RecoveryError,'CI_CHILD_TIMEOUT'):
            p.bounded([sys.executable,'-c','import time;time.sleep(5)'],timeout=0.05)
        with patch.object(p,'MAX_OUTPUT',10),self.assertRaisesRegex(c.RecoveryError,'CI_OUTPUT_BOUND'):
            p.bounded([sys.executable,'-c','print("SYNTHETIC_PRIVATE_CANARY")'],timeout=5)

    def test_fetch_uses_only_temporary_askpass_environment_no_credential_argv(self):
        with tempfile.TemporaryDirectory() as d:
            private=Path(d);calls=[];raw=b'SYNTHETIC_CAPSULE'
            def record(argv,**kwargs):
                calls.append((argv,dict(kwargs['env'])))
                self.assertNotIn('github_pat_SYNTHETIC_ONLY',str(argv))
                return b''
            with patch.object(p,'require_command',side_effect=record),\
                 patch.object(p,'build_capsule',return_value=raw),patch.object(p,'CAPSULE_SHA',c.digest(raw)):
                capsule,sha=p.fetch_capsule(private,'github_pat_SYNTHETIC_ONLY')
            self.assertEqual({v.name for v in private.iterdir()},{'target-capsule.json'})
            self.assertEqual(capsule.read_bytes(),raw)
            secret_calls=[args for args,env in calls if 'CONTROL_POLICY_READ_TOKEN' in env]
            self.assertEqual(len(secret_calls),1);self.assertIn('fetch',secret_calls[0])
            self.assertEqual(sha,c.digest(raw))

    def test_cleanup_failure_cannot_report_green(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();workspace=root/'work';workspace.mkdir();temp=root/'temp';temp.mkdir()
            stdout=io.StringIO()
            def fake_capsule(private,token):
                file=private/'cap';file.write_bytes(b'private synthetic');return file,'a'*64
            with patch.dict(os.environ,{'RUNNER_TEMP':str(temp),'CONTROL_POLICY_READ_TOKEN':'github_pat_SYNTHETIC_ONLY'}),\
                 patch.object(p,'runtime_binding',return_value='1'*40),patch.object(p,'fetch_capsule',side_effect=fake_capsule),\
                 patch.object(p,'bounded',return_value=(0,b'Ran 64 tests in 1.0s\nOK\n')),\
                 patch.object(p,'cleanup_container',side_effect=OSError('SYNTHETIC_PRIVATE_CANARY')),\
                 contextlib.redirect_stdout(stdout):
                self.assertEqual(p.run(workspace,'image'),1)
            self.assertEqual(json.loads(stdout.getvalue())['code'],'CONTROL_PRIVATE_CONTAINER_CLEANUP_RED')
            self.assertNotIn('CANARY',stdout.getvalue());self.assertEqual(list(temp.iterdir()),[])

    def test_foreign_container_and_unavailable_cleanup_deny(self):
        with patch.object(p,'require_command',side_effect=[b'id\n',b'[{"Config":{"Labels":{"tu1nz.private-ci.owner":"foreign"}}}]']):
            with self.assertRaisesRegex(c.RecoveryError,'CI_FOREIGN_CONTAINER_RED'):p.cleanup_container('own','expected')
        with patch.object(p,'require_command',side_effect=c.RecoveryError('CONTROL_RECOVERY_CI_PRIVATE_COMMAND_RED')):
            with self.assertRaises(c.RecoveryError):p.cleanup_container('own','expected')

    def test_workflow_secret_boundary_and_no_private_upload_cache(self):
        raw=(Path(__file__).resolve().parents[1]/'.github/workflows/control-validation.yml').read_text()
        private,public=raw.split('  restore-contract:\n',1)
        self.assertIn('environment: control-private-ci',private)
        self.assertIn('github.event.pull_request.head.sha || github.sha',private)
        self.assertIn('persist-credentials: false',private)
        self.assertEqual(private.count('secrets.CONTROL_POLICY_READ_TOKEN'),1)
        self.assertNotIn('CONTROL_POLICY_READ_TOKEN',public)
        self.assertNotIn('pull_request_target:',raw)
        self.assertIn('needs: control-private-provenance',public)
        for forbidden in ('policy-target','upload-artifact','actions/cache','GITHUB_STEP_SUMMARY'):
            self.assertNotIn(forbidden,raw)

    def test_freeze_requires_both_successful_native_jobs_not_skipped(self):
        prefixes={'control-private-provenance':('Private CI boundary regression tests','Build fresh approved native image',
            'Control-only create-only recovery'),'restore-contract':('S8 durable anchor','R15 aborted containment',
            'S11/S12 release compatibility','R12 native Linux','Integrated S12 attempt chain')}
        jobs=[{'name':name,'conclusion':'success','steps':[{'name':x,'conclusion':'success'} for x in steps]}
              for name,steps in prefixes.items()]
        f.validate_native_jobs(jobs)
        with self.assertRaises(c.RecoveryError):f.validate_native_jobs(jobs[1:])
        for value in ('skipped','neutral','cancelled','failure'):
            changed=json.loads(json.dumps(jobs));changed[0]['conclusion']=value
            with self.assertRaises(c.RecoveryError):f.validate_native_jobs(changed)


if __name__=='__main__':unittest.main()
