"""CI transport/privacy boundaries only, NOT substituted Host observations."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator_ci as m
from tests.test_public_operator import native_trace_capable


class PublicOperatorCI(unittest.TestCase):
    def test_fixture_policy_wait_is_before_admission_and_never_retries_unknown(self):
        # Unit fixture lifecycle only, not mocked production admission.
        from types import SimpleNamespace
        from tests import public_operator_native as native
        import time
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); task=root/'2';task.mkdir();comm=task/'comm'
            comm.write_text('pool-polkitd\n')
            observer=SimpleNamespace(starttime=lambda pid:'7',process=lambda pid:{'starttime':'7'})
            class Proc:
                def __truediv__(self,part):return self if part=='2' else root
            with patch.object(native,'Path',return_value=Proc()):
                with self.assertRaisesRegex(AssertionError,'FIXTURE_POLICY_STARTUP_NOT_QUIET'):
                    native.wait_for_fixture_policy_idle(observer,2,time.monotonic()-1)
                with patch.object(native.time,'sleep',side_effect=lambda value:comm.write_text('gmain\n')):
                    native.wait_for_fixture_policy_idle(observer,2,time.monotonic()+1)
                observer.process=lambda pid:(_ for _ in ()).throw(RuntimeError('STRICT_CENSUS_UNKNOWN'))
                with self.assertRaisesRegex(RuntimeError,'STRICT_CENSUS_UNKNOWN'):
                    native.wait_for_fixture_policy_idle(observer,2,time.monotonic()+1)
                observer.process=lambda pid:{'starttime':'8'}
                with self.assertRaisesRegex(AssertionError,'FIXTURE_POLICY_LEADER_CHANGED'):
                    native.wait_for_fixture_policy_idle(observer,2,time.monotonic()+1)
                comm.unlink()
                with self.assertRaises(FileNotFoundError):
                    native.wait_for_fixture_policy_idle(observer,2,time.monotonic()+1)

    def test_legacy_unchanged_witness_follows_fixture_build_but_precedes_production(self):
        import ast
        from tests import public_operator_native as native
        tree=ast.parse(Path(native.__file__).read_bytes())
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        captures=[n for n in ast.walk(main) if isinstance(n,ast.Assign) and
                  any(isinstance(t,ast.Name) and t.id=='legacy_bytes' for t in n.targets)]
        self.assertEqual(len(captures),1)
        capture=captures[0];self.assertIsInstance(capture.value,ast.DictComp)
        fixture_calls=[n.lineno for n in ast.walk(main) if isinstance(n,ast.Call) and
            isinstance(n.func,ast.Name) and n.func.id in
            ('setup','source_read_census_fence','actual_loader_alias_fence','actual_read_census_fence',
             'actual_loader_configuration_fence','actual_policy_owner_epoch','baseline')]
        child=next(n for n in main.body if isinstance(n,ast.Assign) and
                   any(isinstance(t,ast.Name) and t.id=='child' for t in n.targets))
        self.assertTrue(fixture_calls)
        self.assertLess(max(fixture_calls),capture.lineno)
        self.assertLess(capture.lineno,child.lineno)
        # The final equality remains full inventory + hashes, not an exclusion
        # for test-created files or an overwritten post-production snapshot.
        checks=[n for n in ast.walk(main) if isinstance(n,ast.Assert) and
                isinstance(n.test,ast.Compare) and isinstance(n.test.left,ast.Name) and
                n.test.left.id=='legacy_bytes']
        self.assertEqual(len(checks),1)
        self.assertIsInstance(checks[0].test.comparators[0],ast.DictComp)
        self.assertGreater(checks[0].lineno,child.lineno)

    def test_environment_error_wrapper_follows_actual_flow_exception_context(self):
        import hashlib
        from types import SimpleNamespace
        from tests import public_operator_native as native
        code='PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_REPLACEMENT_ACTUAL_LOADER_ENVIRONMENT_CHANGED'
        class FlowFailure(Exception):primary=code
        class OriginalHold(Exception):primary=code
        actual={'component':'<authenticated-memory:replacement>','line':1,'type':'Hold'}
        host=SimpleNamespace(source_fault_location=lambda error:actual)
        modules={'host':host,'observe':SimpleNamespace(UNITS=native.UNITS)}
        scope={'s':SimpleNamespace(load=lambda key:modules[key])}
        exec(compile(native.ENV_DIAGNOSTIC_WRAPPER,'<test-wrapper>','exec'),scope)
        program='''def interpreter_binding():
 row={"pid":123,"starttime":"synthetic","initial_env_sha256":empty}
 normal="NORMAL_HASH";wms="WMS_HASH"
 raise hold
def initial_application_ready():
 unit=unit_name
 interpreter_binding()
'''
        values={'empty':hashlib.sha256(b'').hexdigest(),'hold':OriginalHold(),'unit_name':native.UNITS[0]}
        exec(compile(program,'<authenticated-memory:replacement>','exec'),values)
        try:
            try:values['initial_application_ready']()
            except OriginalHold:raise FlowFailure()
        except FlowFailure as error:wrapped=error
        stream=io.StringIO();stream.fileno=lambda:42
        with patch.object(Path,'read_bytes',side_effect=FileNotFoundError),\
             patch.object(os,'open',return_value=42),patch.object(os,'fdopen',return_value=contextlib.nullcontext(stream)),\
             patch.object(os,'fsync'):
            self.assertIs(scope['_env_source_fault'](wrapped),actual)
        found=json.loads(stream.getvalue())
        self.assertEqual((found['sample'],found['followup'],found['unit']),('EMPTY','GONE','s7'))
        self.assertNotIn('123',json.dumps(found));self.assertNotIn('synthetic',json.dumps(found))

    def test_environment_diagnostic_never_exposes_names_values_or_journal_text(self):
        from tests import public_operator_native as native
        compile(native.ENV_DIAGNOSTIC_WRAPPER,'<synthetic-diagnostic>','exec')
        replies=[b'ActiveState=failed\nResult=exit-code\nExecMainStatus=1\nNRestarts=0\nInvocationID='+b'1'*32+b'\n',
                 b'PRIVATE_CANARY: uservalue\nTypeError: PRIVATE_CANARY\n']
        with patch.object(native,'run',side_effect=replies):service=native.service_failure_diagnostic('s7')
        self.assertEqual(service['error_types'],['TypeError'])
        self.assertTrue(service['invocation_bound'])
        with patch.object(native,'run',return_value=b'ActiveState=failed\nResult=exit-code\nExecMainStatus=1\nNRestarts=0\nInvocationID=\n') as called:
            unbound=native.service_failure_diagnostic('s7')
        self.assertFalse(unbound['invocation_bound']);self.assertEqual(unbound['error_types'],[])
        self.assertEqual(called.call_count,1)
        env={'unit':'s7','sample':'EMPTY','followup':'GONE','identity':'UNKNOWN',
             'same_environment':'UNKNOWN','executable':'UNKNOWN','state':'Z','followup_expected_items':False,'service':service}
        value={'test_line':1,'test_type':'AssertionError','production_fault':None,'environment':env}
        def read(x):return m.failure_location(json.dumps({'native_failure':x}).encode())
        self.assertEqual(read(value),value);self.assertNotIn('PRIVATE_CANARY',json.dumps(read(value)))
        for bad in ({**env,'sample':'PRIVATE_CANARY'},{**env,'raw':'PRIVATE_CANARY'},
                    {**env,'service':{**service,'message':'PRIVATE_CANARY'}},
                    {**env,'service':{**service,'error_types':['PRIVATE_CANARY']}}):
            with self.subTest(bad=bad):self.assertIsNone(read({**value,'environment':bad}))

    def test_fixture_fault_retains_only_exact_public_source_location(self):
        from tests import public_operator_native as native
        target=str(Path(native.__file__).with_name('public_runtime_fixture.py'))
        try:exec(compile("raise AssertionError('PRIVATE_CANARY')",target,'exec'),{})
        except AssertionError as error:fault=native.fixture_fault_location(error)
        self.assertEqual(fault,{'component':'tests/public_runtime_fixture.py','line':1,'type':'AssertionError'})
        base={'test_line':817,'test_type':'AssertionError','production_fault':None,'fixture_fault':fault}
        def read(x):return m.failure_location(json.dumps({'native_failure':x}).encode())
        self.assertEqual(read(base),base)
        self.assertNotIn('PRIVATE_CANARY',json.dumps(read(base)))
        for bad in ({**fault,'component':'/private/CANARY'}, {**fault,'line':True},
                    {**fault,'type':'PRIVATE_CANARY'}, {**fault,'message':'PRIVATE_CANARY'}):
            with self.subTest(bad=bad):self.assertIsNone(read({**base,'fixture_fault':bad}))

    def test_primary_writer_fault_cannot_be_erased_by_later_abort_or_leak_text(self):
        first={'component':'<authenticated-memory:runtime_guard>','line':61,'type':'FileNotFoundError'}
        abort={'component':'<authenticated-memory:host>','line':535,'type':'Hold'}
        value={'test_line':1,'test_type':'AssertionError','production_fault':abort,'primary_fault':first,'errno':2}
        def read(v):return m.failure_location(json.dumps({'native_failure':v}).encode())
        self.assertEqual(read(value)['primary_fault'],first);self.assertEqual(read(value)['production_fault'],abort)
        for bad in ({**first,'component':'/private/CANARY'}, {**first,'line':True},
                    {**first,'type':'PRIVATE_CANARY'}, {**first,'message':'PRIVATE_CANARY'}):
            with self.subTest(bad=bad):self.assertIsNone(read({**value,'primary_fault':bad}))

    def test_read_cost_is_finite_source_labels_not_private_data(self):
        value = {'process': {'calls': 3, 'inclusive_ns': 1234}}
        def failure(cost):
            return json.dumps({'native_failure': {'test_line': 1, 'test_type': 'AssertionError',
                               'production_fault': None, 'read_cost': cost}}).encode()
        self.assertEqual(m.failure_location(failure(value))['read_cost'], value)
        for bad in ({'PRIVATE_CANARY': {'calls': 1, 'inclusive_ns': 2}},
                    {'process': {'calls': True, 'inclusive_ns': 2}},
                    {'process': {'calls': 1, 'inclusive_ns': 721_000_000_000}},
                    {'process': {'calls': 1, 'inclusive_ns': 2, 'path': '/private/CANARY'}}):
            with self.subTest(bad=bad): self.assertIsNone(m.failure_location(failure(bad)))

    def test_pid1_name_does_not_admit_fixture_before_actual_boot_running(self):
        replies = [(0, b'systemd\n'), (1, b'starting\n'), (0, b'systemd\n'), (0, b'running\n')]
        with patch.object(m.boundary, 'bounded', side_effect=replies) as query, patch.object(m.time, 'sleep'):
            m.ready('owned')
        self.assertEqual(query.call_count, 4)
        for call in query.call_args_list:
            self.assertLessEqual(call.kwargs['timeout'], 5)
        self.assertEqual(query.call_args_list[1].args[0][-2:], ['/usr/bin/systemctl', 'is-system-running'])

    def test_exact_private_commit_and_three_blobs_only(self):
        self.assertEqual(m.CONTROL_COMMIT, 'f2979863bbb7043261e9177842503a9b47cdb49f')
        calls = []
        def command(argv, **kw):
            calls.append((argv, dict(kw.get('env', m.boundary.tool_env()))))
            self.assertNotIn('github_pat_SYNTHETIC_CANARY', str(argv))
            if 'rev-parse' in argv: return (m.CONTROL_COMMIT+'\n').encode()
            if 'show' in argv: return ('SYNTHETIC-'+argv[-1]).encode()
            return b''
        with tempfile.TemporaryDirectory() as d, patch.object(m, 'command', command), \
             patch.dict(m.operator.io.CONTROL_PINS, {}, clear=True):
            root, hashes = m.fetch_control(Path(d), 'github_pat_SYNTHETIC_CANARY')
            self.assertEqual(set(hashes), {'entry', 'guard', 'owner'})
            self.assertEqual({str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()},
                             set(m.operator.CONTROL_FILES.values()))
            self.assertEqual({p.name for p in Path(d).iterdir()}, {'control-source'})
            private = [env for argv, env in calls if 'fetch' in argv]
            self.assertEqual(len(private), 1)
            self.assertEqual(private[0]['CONTROL_POLICY_READ_TOKEN'], 'github_pat_SYNTHETIC_CANARY')
            self.assertTrue(all('CONTROL_POLICY_READ_TOKEN' not in env for argv, env in calls if 'fetch' not in argv))

    def test_readonly_network_none_finite_guest_has_no_secret_or_host_socket(self):
        argv = m.native_argv(Path('/public/work'), Path('/private/control-source'), 'image', 'own', 'nonce')
        self.assertEqual(sum(x == '--mount' for x in argv), 2)
        self.assertIn('type=bind,src=/public/work,dst=/source,readonly', argv)
        self.assertIn('type=bind,src=/private/control-source,dst=/control-source,readonly', argv)
        self.assertEqual(argv[argv.index('--network')+1], 'none')
        self.assertIn('--cgroupns=private', argv)
        self.assertNotIn('docker.sock', str(argv)); self.assertNotIn('CONTROL_POLICY_READ_TOKEN', str(argv))

    def test_guest_inspection_rejects_extra_mount_or_rw_source(self):
        value = {'Image': 'sha256:'+'1'*64, 'Config': {'Labels': {'tu1nz.private-ci.owner': 'nonce'}},
                 'HostConfig': {'NetworkMode': 'none', 'CgroupnsMode': 'private'},
                 'Mounts': [{'Type': 'bind', 'Source': '/public', 'Destination': '/source', 'RW': False},
                            {'Type': 'bind', 'Source': '/private', 'Destination': '/control-source', 'RW': False}]}
        def check():
            with patch.object(m, 'command', return_value=json.dumps([value]).encode()):
                m.inspect_guest('own', 'nonce', Path('/public'), Path('/private'), 'sha256:'+'1'*64)
        check()
        value['Mounts'][0]['RW'] = True
        with self.assertRaises(m.CIError): check()
        value['Mounts'][0]['RW'] = False
        value['Mounts'].append({'Type': 'bind', 'Source': '/run/systemd', 'Destination': '/run/systemd', 'RW': False})
        with self.assertRaises(m.CIError): check()

    def test_exact_report_not_generic_green_and_no_source_substitution(self):
        hashes = {'owner': 'b'*64}
        value = {'scenario': 'success', 'status': 'RIGHTS_OWNER_RECEIPTED_R2_NOT_DISPATCHED', 'server_exit': 0,
                 'proof': 'a'*64, 'source_files': hashes, 'owner_confirmations': 84, 'actual_root_objects': 88,
                 'actual_faults': [], 'fixture_only_no_host_acceptance': True}
        self.assertEqual(m.validate_report(json.dumps(value).encode(), 'success', hashes)['scenario'], 'success')
        for changed in ({'owner_confirmations': 83}, {'source_files': {'owner': 'c'*64}},
                        {'fixture_only_no_host_acceptance': False}, {'server_exit': 1}, {'green': True}):
            with self.subTest(changed=changed), self.assertRaises((m.CIError, m.operator.io.Hold)):
                m.validate_report(json.dumps({**value, **changed}).encode(), 'success', hashes)

    def test_every_fault_requires_its_own_actual_marker(self):
        self.assertEqual(set(m.FAULTS), set(m.CASES))
        for case in m.CASES:
            if case in ('success','r5_success'): continue
            value = {'scenario': case, 'status': 'HOLD', 'server_exit': 0, 'proof': 'a'*64,
                     'source_files': {}, 'owner_confirmations': 0, 'actual_root_objects': 4,
                     'actual_faults': [], 'fixture_only_no_host_acceptance': True}
            with self.subTest(case=case), self.assertRaisesRegex(m.CIError, 'INTENDED_FAULT_NOT_WITNESSED'):
                m.validate_report(json.dumps(value).encode(), case, {})

    def test_native_failure_and_interrupt_never_leak_private_output_and_cleanup(self):
        for failure in (RuntimeError('PRIVATE_CANARY github_pat_SYNTHETIC'), InterruptedError('PRIVATE_CANARY')):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as d:
                base = Path(d).resolve(); work = base/'work'; work.mkdir(); temp = base/'temp'; temp.mkdir()
                output = io.StringIO()
                env = {'RUNNER_TEMP': str(temp), 'CONTROL_POLICY_READ_TOKEN': 'github_pat_SYNTHETIC',
                       'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
                with patch.dict(os.environ, env), patch.object(m.boundary, 'runtime_binding', return_value='1'*40), \
                     patch.object(m, 'command', return_value=('sha256:'+'a'*64).encode()), \
                     patch.object(m, 'fetch_control', side_effect=failure), contextlib.redirect_stdout(output):
                    self.assertEqual(m.run(work, 'tu1nz-public-operator-private:123-1'), 1)
                self.assertNotIn('CANARY', output.getvalue()); self.assertNotIn('github_pat', output.getvalue())
                self.assertFalse(list(temp.iterdir()))

    def test_missing_credential_never_fetches(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(m.boundary, 'runtime_binding', return_value='1'*40), \
             patch.object(m, 'fetch_control') as fetch, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.run(Path('/public'), 'image'), 1); fetch.assert_not_called()

    def test_failure_diagnostic_allows_only_bounded_source_locations(self):
        value = {'native_failure': {'test_line': 494, 'test_type': 'AssertionError',
                 'production_fault': {'component': '<authenticated-memory:observe>', 'line': 123, 'type': 'Hold'}}}
        self.assertEqual(m.failure_location(json.dumps(value).encode()), value['native_failure'])
        for changed in ({'test_line': True}, {'test_type': 'PRIVATE_CANARY'},
                        {'production_fault': {'component': '/private/CANARY', 'line': 123, 'type': 'Hold'}},
                        {'production_fault': {'component': '<authenticated-memory:observe>', 'line': 123,
                                              'type': 'Hold', 'message': 'PRIVATE_CANARY'}}):
            with self.subTest(changed=changed):
                self.assertIsNone(m.failure_location(json.dumps({'native_failure': {**value['native_failure'], **changed}}).encode()))
        self.assertIsNone(m.failure_location(b'PRIVATE_CANARY github_pat_SYNTHETIC'))
        value['native_failure']['cause_code'] = 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_BROKER_EFFECTIVE_DAC_ACCESS'
        self.assertEqual(m.failure_location(json.dumps(value).encode())['cause_code'], value['native_failure']['cause_code'])
        value['native_failure']['cause_code'] = 'PRIVATE_CANARY'
        self.assertNotIn('PRIVATE_CANARY', json.dumps(m.failure_location(json.dumps(value).encode())))
        value['native_failure']['test_type'] = 'PermissionError'
        self.assertEqual(m.failure_location(json.dumps(value).encode())['test_type'], 'PermissionError')
        value['native_failure'].update(test_type='NativeFSUIDFailure', cause_code='NATIVE_FSUID_CHILD_CONNECT_RED', errno=13)
        self.assertEqual(m.failure_location(json.dumps(value).encode())['errno'], 13)
        value['native_failure']['errno'] = True
        self.assertIsNone(m.failure_location(json.dumps(value).encode()))

    def test_cleanup_preserves_primary_location_and_both_independent_errors(self):
        location = {'test_line': 494, 'test_type': 'AssertionError', 'production_fault': None}
        for container_fails, input_fails in ((True, False), (False, True), (True, True)):
            with self.subTest(container=container_fails, inputs=input_fails):
                original = {'schema': m.SCHEMA, 'green': False, 'stage': 'success',
                            'code': 'NATIVE_CASE_RED', 'failure_location': location}
                with patch.object(m.boundary, 'cleanup_container', side_effect=RuntimeError('PRIVATE_CANARY') if container_fails else None) as container, \
                     patch.object(m.boundary, 'remove_private', side_effect=RuntimeError('PRIVATE_CANARY') if input_fails else None) as inputs:
                    result = m.cleanup_result(original, 'owned', 'nonce', Path('/private/inputs'), Path('/private'))
                container.assert_called_once(); inputs.assert_called_once()
                self.assertFalse(result['green']); self.assertEqual(result['code'], 'NATIVE_CASE_RED')
                self.assertEqual(result['failure_location'], location)
                self.assertEqual(result['cleanup_errors'], (['OWNED_CONTAINER_CLEANUP_RED'] if container_fails else [])+
                                 (['PRIVATE_INPUT_CLEANUP_RED'] if input_fails else []))
                self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
        original = {'schema': m.SCHEMA, 'green': True, 'code': 'PRIVATE_OPERATOR_CI_GREEN', 'cases': []}
        with patch.object(m.boundary, 'remove_private', side_effect=RuntimeError('PRIVATE_CANARY')):
            result = m.cleanup_result(original, None, 'nonce', Path('/private/inputs'), Path('/private'))
        self.assertFalse(result['green']); self.assertEqual(result['code'], 'PRIVATE_OPERATOR_CI_CLEANUP_RED')
        self.assertEqual(result['cases'], []); self.assertNotIn('PRIVATE_CANARY', json.dumps(result))

    def test_finite_failure_codes_and_counters_never_publish_unknown_values(self):
        outcome = {'status': 'HOLD', 'primary': 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_WIRE_DEADLINE',
            'abort': ['PRIVATE_CANARY'], 'cleanup': [], 'client_error_type': 'PRIVATE_CANARY',
            'server_exit': 1, 'owner_confirmations': 7, 'actual_root_objects': 11,
            'last_record_kind': 'owner_object_intent', 'last_record_sequence': 123,
            'server_terminal_code': 'PRIVATE_CANARY'}
        value = {'native_failure': {'test_line': 476, 'test_type': 'AssertionError',
                 'production_fault': None, 'outcome': outcome}}
        result = m.failure_location(json.dumps(value).encode())
        self.assertEqual(result['outcome']['primary'], outcome['primary'])
        self.assertEqual(result['outcome']['owner_confirmations'], 7)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
        for key, changed in (('owner_confirmations', True), ('actual_root_objects', 89), ('server_exit', 'PRIVATE_CANARY')):
            with self.subTest(key=key):
                value['native_failure']['outcome'] = {**outcome, key: changed}
                self.assertIsNone(m.failure_location(json.dumps(value).encode()))

    def test_terminal_stderr_cannot_export_private_or_ambiguous_exception_text(self):
        valid = b'tu1nz_public_operator_io.Hold: PUBLIC_OPERATOR_WIRE_DEADLINE'
        self.assertEqual(m.terminal_wire_code(valid), 'PUBLIC_OPERATOR_WIRE_DEADLINE')
        self.assertIsNone(m.terminal_wire_code(b'tu1nz_public_operator_io.Hold: PUBLIC_OPERATOR_PRIVATE_CANARY'))
        self.assertIsNone(m.terminal_wire_code(valid+b' PRIVATE_CANARY'))
        self.assertIsNone(m.terminal_wire_code(valid+b'\ntu1nz_public_operator_io.Hold: PUBLIC_OPERATOR_COMMAND_DEADLINE'))
        self.assertIsNone(m.terminal_wire_code(b'PRIVATE_CANARY /private/source.py github_pat_SYNTHETIC'))

    def test_actor_failure_diagnostic_is_finite_and_cannot_replace_primary(self):
        actor = {'executable_class': 'postgres', 'matching_executable_profiles': 5,
                 'different_fields': ['argv_sha256'], 'stable_followup': True,
                 'title_kind': 'POSTGRES_AUTOVACUUM_WORKER'}
        self.assertEqual(m.safe_actor_diagnostic(actor), actor)
        for change in ({'executable_class': 'PRIVATE_CANARY'}, {'matching_executable_profiles': True},
                       {'different_fields': ['PRIVATE_CANARY']}, {'different_fields': ['uid', 'uid']},
                       {'title_kind': 'PRIVATE_CANARY'}, {'argv': 'PRIVATE_CANARY'}):
            malformed = {**actor, **change}
            self.assertIsNone(m.safe_actor_diagnostic(malformed))
            failure = {'test_line': 10, 'test_type': 'AssertionError', 'production_fault': None,
                       'actor': malformed}
            result = m.failure_location(json.dumps({'native_failure': failure}).encode())
            self.assertEqual(result['test_line'], 10); self.assertIsNone(result['actor'])
            self.assertNotIn('PRIVATE_CANARY', json.dumps(result))

    def test_mixed_stream_failure_preserves_unique_proof_without_private_text(self):
        failure = {'native_failure': {'test_line': 123, 'test_type': 'AssertionError', 'production_fault': None}}
        raw = b'PRIVATE_CANARY github_pat_SYNTHETIC\n'+json.dumps(failure).encode()+b'\nPRIVATE_CANARY\n'
        self.assertEqual(m.failure_location(raw), failure['native_failure'])
        value = m.native_process_diagnostic(1, raw)
        self.assertEqual(value['exit'], 1); self.assertEqual(value['output_bytes'], len(raw))
        self.assertEqual(value['parser_status'], 'COMPLETE'); self.assertEqual(value['source_line'], 123)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(value))
        self.assertIsNone(m.failure_location(json.dumps(failure).encode()+b'\n'+json.dumps(failure).encode()))
        self.assertEqual(m.native_process_diagnostic(137, b'')['parser_status'], 'NO_STRUCTURED_LINE')
        failure['native_failure']['production_fault'] = {'message': 'PRIVATE_CANARY'}
        value = m.native_process_diagnostic(1, json.dumps(failure).encode())
        self.assertEqual(value['parser_status'], 'STRUCTURED_DATA_REDACTED')
        self.assertEqual(value['source_line'], 123); self.assertNotIn('PRIVATE_CANARY', json.dumps(value))

    def test_native_fsuid_regression_has_exact_root_non_skipped_guest_entry(self):
        argv = m.native_fsuid_argv('owned')
        self.assertEqual(argv[:6], ['/usr/bin/docker', 'exec', 'owned', '/usr/bin/python3', '-I', '-B'])
        self.assertIn('os.geteuid()==0', argv[-1]); self.assertIn('not r.skipped', argv[-1])
        self.assertIn('test_actual_fsuid_socket_owner_', argv[-1])
        self.assertIn('test_actual_child_dac_failure_', argv[-1]); self.assertIn('r.testsRun==7', argv[-1])
        self.assertIn('test_actual_nonleader_security_must_match_leader', argv[-1])
        self.assertIn('test_actual_unshared_nonleader_source_descriptor_is_rejected', argv[-1])
        self.assertIn('test_actual_single_leader_start_sample_is_bound_not_another_start', argv[-1])
        self.assertIn('test_actual_http_reader_absolute_deadline_and_reap', argv[-1])
        self.assertIn('test_actual_fsgid_not_real_saved_group_', argv[-1])
        self.assertLess(argv[-1].index('prepare_guest_kernel_view()'), argv[-1].index('r=Result()'))

    def test_zero_uid_without_ptrace_is_not_native_observer_evidence(self):
        with patch('tests.test_public_operator.sys.platform', 'linux'), \
             patch('tests.test_public_operator.os.geteuid', return_value=0), \
             patch('tests.test_public_operator.Path.read_text', return_value='CapEff:\t0000000000000000\n'):
            self.assertFalse(native_trace_capable())
        with patch('tests.test_public_operator.sys.platform', 'linux'), \
             patch('tests.test_public_operator.os.geteuid', return_value=0), \
             patch('tests.test_public_operator.Path.read_text', return_value='CapEff:\t0000000000080000\n'):
            self.assertTrue(native_trace_capable())


if __name__ == '__main__': unittest.main(verbosity=2)
