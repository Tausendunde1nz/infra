"""Pure native-fixture/CI boundary regressions; no guests or Host effects."""
import base64
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator as client
io=client.io
import tu1nz_public_maintenance_ci as m
from tests.test_public_maintenance_transport import synthetic_timing


class NativeBoundaryTests(unittest.TestCase):
    def copied_unit_program(self, unit):
        with patch.object(m.ci,'command') as command:
            m.fix_copied_unit_owner('synthetic-guest',unit)
        argv=command.call_args.args[0]
        self.assertEqual(argv[:8],['/usr/bin/docker','exec','synthetic-guest','/usr/bin/python3','-I','-B','-S','-c'])
        self.assertEqual(command.call_args.kwargs,{'timeout':15})
        self.assertEqual(argv[9:11],[str(os.geteuid()),str(os.getegid())])
        return argv[8],['-c',*argv[9:]]

    def run_copied_unit_program(self, program, argv, *, fault=None):
        # Execute the exact guest program with synthetic FD observations only.
        # No chown or access to a real systemd path occurs on the Mac.
        import builtins
        import stat
        raw=b'synthetic-unit\n';closed=[];changes=[]
        before=dict(st_mode=stat.S_IFREG|0o600,st_nlink=1,st_uid=os.geteuid(),
            st_gid=os.getegid(),st_size=len(raw),st_dev=7,st_ino=19)
        if fault=='owner':before['st_uid']+=1
        if fault=='hardlink':before['st_nlink']=2
        if fault=='mode':before['st_mode']=stat.S_IFREG|0o620
        if fault=='type':before['st_mode']=stat.S_IFDIR|0o600
        if fault=='oversize':before['st_size']=4097
        after={**before,'st_uid':0,'st_gid':0}
        if fault=='post_mode':after['st_mode']=stat.S_IFREG|0o644
        name={**after,'st_ino':20 if fault=='renamed' else 19}
        def opened(path,flags):
            self.assertEqual(path,'/etc/systemd/system/tu1nz-rev4-native-fixture.service')
            self.assertEqual(flags,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);return 91
        stats=iter((SimpleNamespace(**before),SimpleNamespace(**after)))
        fake=SimpleNamespace(O_RDONLY=os.O_RDONLY,O_NOFOLLOW=os.O_NOFOLLOW,O_CLOEXEC=os.O_CLOEXEC,
            open=opened,fstat=lambda fd:next(stats),stat=lambda p,**kw:SimpleNamespace(**name),
            pread=lambda fd,size,offset:raw,close=lambda fd:closed.append(fd),
            fchown=lambda fd,uid,gid:changes.append((fd,uid,gid)))
        real_import=builtins.__import__
        def imports(name,*args,**kwargs):
            if name=='os':return fake
            if name=='sys':return SimpleNamespace(argv=argv)
            return real_import(name,*args,**kwargs)
        try:
            exec(compile(program,'<exact-copied-unit-guest-program>','exec'),
                {'__builtins__':{**vars(builtins),'__import__':imports}})
        finally:
            self.assertEqual(closed,[91])
            if fault in ('owner','hardlink','mode','type','oversize','hash'):
                self.assertEqual(changes,[])
            else:self.assertEqual(changes,[(91,0,0)])

    def test_copied_unit_owner_uses_fixed_fd_byte_binding_and_preserves_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            unit=Path(directory)/'unit';unit.write_bytes(b'synthetic-unit\n')
            program,argv=self.copied_unit_program(unit)
            self.run_copied_unit_program(program,argv)
            for fault in ('owner','hardlink','mode','type','oversize','hash','post_mode','renamed'):
                bad=[*argv]
                if fault=='hash':bad[-1]='0'*64
                with self.subTest(fault=fault),self.assertRaises(AssertionError):
                    self.run_copied_unit_program(program,bad,fault=fault)

    def test_copied_unit_owner_failure_precedes_reload_and_cleans_owned_guest(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(m.ci,'command') as command, \
                patch.object(m.ci,'inspect_guest'),patch.object(m.ci,'ready'), \
                patch.object(m,'fix_copied_unit_owner',side_effect=RuntimeError('SYNTHETIC_OWNER_FAILURE')) as fix, \
                patch.object(m.ci.boundary,'cleanup_container') as cleanup:
            with self.assertRaisesRegex(RuntimeError,'^SYNTHETIC_OWNER_FAILURE$'):
                m.case_run(Path('/synthetic-source'),Path('/synthetic-control'),'synthetic-image','sha256:'+'a'*64,
                    'synthetic-owner',Path(directory),Path('/synthetic-inputs'),{},'original','calibration')
            name='tu1nz-rev4-synthetic-owner-calibration-original'
            fix.assert_called_once_with(name,Path(directory)/'calibration-original.service')
            self.assertEqual(command.call_args.args[0][:2],['/usr/bin/docker','cp'])
            self.assertFalse(any('daemon-reload' in call.args[0] for call in command.call_args_list))
            cleanup.assert_called_once_with(name,'synthetic-owner')

    def fixture(self):
        hashes={k:'a'*64 for k in io.MODULES|io.ASSETS};fixture={**hashes,'runtime_inputs':'b'*64}
        artifact={'objects':{str(n):{} for n in range(6260)},'archive_bytes':45560268,'expanded_file_bytes':143314310}
        proof=synthetic_timing(fixture,artifact)
        records=[]
        for case in m.CASES:
            records.append({'schema':'TU1NZ_REV4_NATIVE_CASE_V1','case':case,'phase':'calibration','green':True,
                'production_source_files':hashes,'fixture_source_files':fixture,'fixture_artifact_sha256':io.sha(io.canonical(artifact)),
                'original_failed_hold_preserved':case!='original','second_recovery_denied_before_SSH':case!='original',
                'run':proof['runs'][case],'host_acceptance':False})
        return hashes,artifact,records

    def test_complete_batch_uses_unchanged_budget_math_and_no_production_input_substitution(self):
        hashes,artifact,records=self.fixture()
        for value in records:self.assertEqual(m.validate_case(value,value['case'],'calibration',hashes),value)
        proof=m.timing(records,'f'*64)
        budget=io.maintenance_timing_binding(proof,source_hashes=records[0]['fixture_source_files'],artifact=artifact)
        self.assertTrue(all(v<600000 for v in budget['whole_budget_milliseconds'].values()))
        production=m.timing(records,'f'*64,production=True)
        self.assertEqual(production['source_sha256'],io.sha(io.canonical(hashes)))
        self.assertEqual(production['artifact_sha256'],m.PRODUCTION_ARTIFACT)
        self.assertEqual(production['runs'],proof['runs'])
        self.assertNotEqual(production['source_sha256'],proof['source_sha256'])

    def test_source_path_cleanup_clock_and_size_changes_cannot_be_passed_through(self):
        for kind in ('code','extra','cleanup','owner','whole','service','size','once','phase','private'):
            hashes,artifact,records=self.fixture();v=records[1]
            if kind=='code':v['fixture_source_files']['host']='c'*64
            elif kind=='extra':v['run']['private']='SECRET_CANARY'
            elif kind=='cleanup':v['run']['cleanup_complete']=False
            elif kind=='owner':v['run']['owner_acks']=83
            elif kind=='whole':v['run']['elapsed_milliseconds']=600000
            elif kind=='service':v['run']['largest_service_action_milliseconds']=20001
            elif kind=='size':v['run']['dimensions']['archive_bytes']-=1
            elif kind=='once':v['second_recovery_denied_before_SSH']=False
            elif kind=='phase':v['phase']='verification'
            else:v['production_source_files']['private']='SECRET_CANARY'
            with self.subTest(kind=kind),self.assertRaises(m.ci.CIError):
                m.validate_case(v,'recovery_F1','calibration',hashes if kind!='private' else {k:'a'*64 for k in io.MODULES|io.ASSETS})

    def test_error_output_only_contains_literal_owned_codes_and_no_private_strings(self):
        bad={'code':'SECRET_CANARY','error_type':'PRIVATE_CLASS','original':{'result':{'primary':'SECRET_CANARY',
            'host_abort':['SECRET_CANARY'],'host_cleanup':['PUBLIC_BOOTSTRAP_INTERRUPTED']}}}
        raw=json.dumps(m.safe_failure(bad,'original','calibration'))
        self.assertNotIn('SECRET_CANARY',raw);self.assertNotIn('PRIVATE_CLASS',raw)
        self.assertIn('PUBLIC_BOOTSTRAP_INTERRUPTED',raw)

    def counted_native_failure(self, intents=2, acks=1):
        from tests import public_maintenance_native as n
        # Actual records()/measured() reads only this temporary synthetic journal.
        # The original assertion fails before filesystem Owner inspection.
        with tempfile.TemporaryDirectory() as directory,patch.object(n.f,'CUSTODY',Path(directory)):
            journal=Path(directory)/'public-rights-20261014-1'/'recovery-once'/'operator-records'
            journal.mkdir(parents=True,mode=0o700)
            kinds=['owner_object_intent']*intents+['owner_object_ack']*acks
            for number,kind in enumerate(kinds,1):
                m.ci.save(journal/(str(number).zfill(3)+'.json'),
                    io.canonical({'kind':kind,'value':'SECRET_CANARY'}))
            with patch.object(n,'records',wraps=n.records) as reads:
                try:n.measured('recovery_F1',{}, {}, {},0,1)
                except AssertionError as error:
                    # Capturing the comparison cannot reread/reconstruct ACKs.
                    with patch.object(n,'records',side_effect=AssertionError('NO_REREAD')):
                        fields=n.failure_fields(error)
                else:self.fail('unchanged Owner comparison did not fail')
                reads.assert_called_once_with('recovery-once')
        self.assertEqual(fields['test_failure']['checkpoint'],'REV4_NATIVE_MEASURED_ASSERT_01')
        self.assertEqual(fields['owner_counts'],{'owner_intents':intents,'owner_acks':acks})
        return fields

    def retained_host_failure(self):
        import ast,time
        from tests.test_public_maintenance_result import host,r3
        from tests import public_maintenance_native as n
        # Execute the unchanged public Journal.write method with an invalid
        # synthetic dirfd. Its real OSError has no privileged or Host effect.
        tree=ast.parse(Path(r3.__file__).read_bytes())
        cls=next(x for x in tree.body if isinstance(x,ast.ClassDef) and x.name=='Journal')
        write=next(x for x in cls.body if isinstance(x,ast.FunctionDef) and x.name=='write')
        namespace=dict(vars(r3))
        exec(compile(ast.Module(body=[write],type_ignores=[]),'<authenticated-memory:r3>','exec'),namespace)
        wire=SimpleNamespace(deadline=time.monotonic()+60,send=Mock())
        state=host.MaintenanceSessionResult(wire,r3,route='recovery-once')
        journal=SimpleNamespace(check=Mock(),seq=0,fd=-1,pfd=-1,binding='a'*64)
        try:namespace['write'](journal,'probe',{'private':'SECRET_CANARY'})
        except OSError as error:state.failure(error)
        else:self.fail('real synthetic fd error did not fail')
        first=copy.deepcopy(state.location)
        state.failure(OSError('SECRET_CANARY'))  # later failure cannot replace first location
        state.paths=SimpleNamespace(rows={'synthetic':'owned'},events=None,
            close=Mock(side_effect=OSError('SECRET_CANARY')))
        result=state.close()
        self.assertEqual(result['status'],'HOLD')
        self.assertEqual(result['source_fault'],first)
        self.assertEqual(first['component'],'<authenticated-memory:r3>')
        self.assertEqual(first['type'],'OSError')
        self.assertIn('fd=os.open(',Path(r3.__file__).read_text().splitlines()[first['line']-1])
        self.assertEqual(result['cleanup'],['PUBLIC_BOOTSTRAP_RECOVERY_PATHS_CLOSE_UNKNOWN'])
        state.paths.close.assert_called_once_with();wire.send.assert_called_once_with(result)
        trace={'final':result,'private':'SECRET_CANARY'}
        before=copy.deepcopy(trace);fields=n.failure_trace_fields(trace)
        self.assertEqual(trace,before)
        self.assertEqual(fields,{'host_source_fault':first})
        return result,fields

    def test_recovery_first_host_fault_and_actual_owner_counts_survive_ci_fail_and_cleanup(self):
        import io as streams
        from contextlib import redirect_stdout
        fields=self.counted_native_failure();host_result,trace_fields=self.retained_host_failure()
        value={'schema':'TU1NZ_REV4_NATIVE_CASE_V1','green':False,'host_acceptance':False,
            'case':'recovery_F1','phase':'calibration',**fields,
            'recovery-once':{'result':{'primary':host_result['primary'],'host_primary':host_result['primary'],
                'client_primary':'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_CLIENT_NOT_CLAIMED',
                'host_abort':host_result['abort'],'host_cleanup':host_result['cleanup'],
                'client_cleanup':['PUBLIC_BOOTSTRAP_MAINTENANCE_CLOSED_CUSTODY_UNCONFIRMED']},**trace_fields}}
        expected=m.safe_failure(value,'recovery_F1','calibration')
        self.assertEqual(expected['owner_counts'],{'owner_intents':2,'owner_acks':1})
        self.assertEqual(expected['recovery-once']['host_source_fault'],host_result['source_fault'])
        self.assertEqual(expected['recovery-once']['host_cleanup'],host_result['cleanup'])
        self.assertEqual(expected['recovery-once']['client_cleanup'],
            ['PUBLIC_BOOTSTRAP_MAINTENANCE_CLOSED_CUSTODY_UNCONFIRMED'])
        self.assertNotIn('SECRET_CANARY',json.dumps(expected))
        for cleanup_fails in (False,True):
            with self.subTest(cleanup_fails=cleanup_fails),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);m.ci.save(root/'calibration-recovery_F1-result.json',io.canonical(value))
                output=streams.StringIO();failure=RuntimeError('SYNTHETIC_CLEANUP_RED') if cleanup_fails else None
                with patch.object(m.ci,'command'),patch.object(m.ci,'inspect_guest'),patch.object(m.ci,'ready'), \
                        patch.object(m.ci.boundary,'cleanup_container',side_effect=failure) as cleanup,redirect_stdout(output):
                    with self.assertRaisesRegex(RuntimeError if cleanup_fails else m.ci.CIError,
                            '^SYNTHETIC_CLEANUP_RED$' if cleanup_fails else '^REV4_NATIVE_CASE_RED$'):
                        m.case_run(Path('/synthetic-source'),Path('/synthetic-control'),'synthetic-image','sha256:'+'a'*64,
                            'synthetic-owner',root,Path('/synthetic-inputs'),{},'recovery_F1','calibration')
                emitted=json.loads(output.getvalue())
                self.assertEqual(emitted['failure'],expected)
                self.assertIs(emitted['failure']['green'],False)
                cleanup.assert_called_once_with('tu1nz-rev4-synthetic-owner-calibration-recovery-f1','synthetic-owner')

    def test_owner_counts_come_from_failed_comparison_even_for_zero_excess_and_missing_ack(self):
        for intents,acks in ((0,0),(84,83),(85,85),(0,1)):
            with self.subTest(intents=intents,acks=acks):
                fields=self.counted_native_failure(intents,acks)
                output=m.safe_failure(fields,'recovery_F1','calibration')
                self.assertEqual(output['owner_counts'],fields['owner_counts'])
                self.assertIs(output['green'],False)
        from tests import public_maintenance_native as n
        with patch.object(n,'records',return_value=(None,[{'private':'SECRET_CANARY'}])):
            try:n.measured('recovery_F1',{}, {}, {},0,1)
            except KeyError as error:fields=n.failure_fields(error)
            else:self.fail('unreadable count input did not fail')
        self.assertNotIn('owner_counts',fields)  # missing data is not zero
        try:raise AssertionError('SECRET_CANARY')
        except AssertionError as error:self.assertIsNone(m.diagnostics.capture_owner_counts(error))

    def test_host_fault_export_rejects_unapproved_components_types_lines_and_extra_data(self):
        from tests import public_maintenance_native as n
        good={'component':'<authenticated-memory:replacement>','line':123,'type':'FileNotFoundError'}
        for delta in ({'component':'SECRET_CANARY'}, {'component':'/private/SECRET_CANARY'},
                {'component':'<authenticated-memory:SECRET_CANARY>'},{'component':'<authenticated-memory:io>'},
                {'component':[]},{'line':True},{'line':0},{'line':10000},{'line':1.5},{'line':'123'},
                {'type':'SECRET_CANARY'},{'type':[]},{'locals':'SECRET_CANARY'},{'errno':2}):
            with self.subTest(delta=delta):
                bad={**good,**delta}
                self.assertEqual(n.failure_trace_fields({'final':{'source_fault':bad}}),{})
                output=m.safe_failure({'recovery-once':{'result':{},'host_source_fault':bad}},'recovery_F1','calibration')
                self.assertNotIn('host_source_fault',output['recovery-once'])
                self.assertNotIn('SECRET_CANARY',json.dumps(output))
        for missing in (None,[],{},'SECRET_CANARY'):
            self.assertEqual(n.failure_trace_fields({'final':missing}),{})
        for bad in (None,[],True,{'component':good['component']}):
            self.assertIsNone(m.diagnostics.validated_host_fault(bad))
        self.assertEqual(n.failure_trace_fields({'final':{'source_fault':good}}),{'host_source_fault':good})

    def test_owner_count_filter_rejects_invalid_values_without_changing_failure_or_cleanup(self):
        good={'owner_intents':84,'owner_acks':83}
        for bad in (None,[],True,{}, {'owner_intents':84}, {**good,'private':'SECRET_CANARY'},
                *[{**good,'owner_acks':x} for x in (-1,513,True,1.5,'83',[],None)]):
            with self.subTest(bad=bad):
                output=m.safe_failure({'owner_counts':bad,'code':'NATIVE_FULL_ENTRY_ASSERTION',
                    'recovery-once':{'result':{'host_cleanup':['PUBLIC_BOOTSTRAP_RECOVERY_PATHS_CLOSE_UNKNOWN']}}},
                    'recovery_F1','calibration')
                self.assertNotIn('owner_counts',output)
                self.assertEqual(output['code'],'NATIVE_FULL_ENTRY_ASSERTION')
                self.assertEqual(output['recovery-once']['host_cleanup'],['PUBLIC_BOOTSTRAP_RECOVERY_PATHS_CLOSE_UNKNOWN'])
                self.assertIs(output['green'],False)
                self.assertNotIn('SECRET_CANARY',json.dumps(output))
        self.assertEqual(m.diagnostics.validated_owner_counts({'owner_intents':512,'owner_acks':0}),
            {'owner_intents':512,'owner_acks':0})

    def start_limit_diagnostic(self):
        import ast,re
        from tests import public_maintenance_native as n
        from tests.test_public_maintenance import transition
        node=next(x for x in ast.parse(n.HOST_TRACE).body if isinstance(x,ast.FunctionDef)
            and x.name=='_start_limit_permission')
        seen=[]
        def actual(*args,**kwargs):
            try:return transition.start_limit_permission(*args,**kwargs)
            except io.Hold as error:seen.append(error);raise
        namespace={'_actual_start_limit_permission':actual,'_io':io,'_trace':{'start_limit_failure':None},
            '_replacement':SimpleNamespace(UNITS=transition.UNITS),'re':re,'sys':sys}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<exact-native-error-wrapper>','exec'),namespace)
        return namespace,seen

    def test_start_limit_diagnostic_uses_actual_denial_preserves_exception_and_no_extra_reads(self):
        from tests.test_public_maintenance import StartLimitStateProofTests
        seed=StartLimitStateProofTests().snapshot()
        faults=(('Type','exec','type_simple'),('NRestarts','1','restarts_zero'),
            ('ControlPID','8','control_pid_zero'),('Job','7','job_empty'),
            ('Result','start-limit-hit','result_not_limit_hit'),('InvocationID','','invocation_id_valid'),
            ('SubState','start','active_running_pid'))
        for field,value,predicate in faults:
            with self.subTest(field=field):
                ns,seen=self.start_limit_diagnostic();row=copy.deepcopy(seed);row['unit_state'][field]=value
                before=copy.deepcopy(row)
                with patch('builtins.open',side_effect=AssertionError('NO_READ')), \
                        patch.object(os,'open',side_effect=AssertionError('NO_READ')), \
                        patch('subprocess.run',side_effect=AssertionError('NO_COMMAND')):
                    try:ns['_start_limit_permission'](row,require_active=True)
                    except io.Hold as error:self.assertIs(error,seen[0])
                    else:self.fail('actual eligibility assertion did not deny')
                point=ns['_trace']['start_limit_failure'];self.assertIs(point['checks'][predicate],False)
                self.assertEqual(m.diagnostics.validated_start_limit(point),point)
                self.assertEqual(row,before)
                output=m.safe_failure({'original':{'result':{'host_primary':seen[0].primary},
                    'start_limit_failure':point}},'original','calibration')
                self.assertEqual(output['original']['start_limit_failure'],point)
                self.assertIs(output['green'],False)
                self.assertNotIn(seed['unit_state']['InvocationID'],json.dumps(output))
                self.assertEqual(len(seen),1)

    def test_start_limit_diagnostic_retains_first_failure_caller_and_other_failures(self):
        from tests.test_public_maintenance import StartLimitStateProofTests,transition
        row=StartLimitStateProofTests().snapshot();ns,seen=self.start_limit_diagnostic()
        self.assertEqual(ns['_start_limit_permission'](row,require_active=True),
            transition.start_limit_permission(row,require_active=True))
        self.assertIsNone(ns['_trace']['start_limit_failure'])
        stopped=copy.deepcopy(row);stopped['unit_state'].update(ActiveState='inactive',SubState='dead',MainPID='0')
        # Run through a named caller, just as the real fresh before-stop check.
        exec('def check_prepared_state(row):\n return _start_limit_permission(row,require_active=True)\n',ns)
        with self.assertRaises(io.Hold):ns['check_prepared_state'](stopped)
        first=copy.deepcopy(ns['_trace']['start_limit_failure'])
        self.assertEqual(first['caller'],'check_prepared_state')
        self.assertIs(first['checks']['empty_terminal_pid'],True)
        self.assertIs(first['checks']['active_running_pid'],False)
        self.assertTrue(all(first['checks'][k] for k in first['checks'] if k not in
            ('active_running_pid','empty_terminal_pid')))
        other=copy.deepcopy(row);other['unit_state']['InvocationID']='SECRET_CANARY'
        with self.assertRaises(io.Hold):ns['_start_limit_permission'](other)
        self.assertEqual(ns['_trace']['start_limit_failure'],first)
        ns,seen=self.start_limit_diagnostic()
        row['unit_state']['NRestarts']=True
        with self.assertRaises(io.Hold):ns['_start_limit_permission'](row)
        self.assertTrue(seen[0].primary.endswith('START_LIMIT_STATE_TYPES'))
        self.assertIsNone(ns['_trace']['start_limit_failure'])

    def test_start_limit_failure_export_rejects_unapproved_fields_types_and_success_claim(self):
        from tests.test_public_maintenance import StartLimitStateProofTests
        row=StartLimitStateProofTests().snapshot();row['unit_state']['InvocationID']=''
        ns,seen=self.start_limit_diagnostic()
        with self.assertRaises(io.Hold):ns['_start_limit_permission'](row,require_active=True)
        point=ns['_trace']['start_limit_failure']
        changes=({'caller':'SECRET_CANARY'},{'unit':[]},{'checkpoint':'SECRET_CANARY'},
            {'require_active':1},{'anchor_present':'false'},{'pid':5},
            {'checks':{**point['checks'],'invocation_id_valid':'SECRET_CANARY'}},
            {'checks':{**point['checks'],'invocation_id_valid':True}},
            {'checks':{**point['checks'],'private':'SECRET_CANARY'}})
        for change in changes:
            with self.subTest(change=change):
                bad={**point,**change}
                output=m.safe_failure({'original':{'result':{'host_primary':seen[0].primary},
                    'start_limit_failure':bad}},'original','calibration')
                self.assertNotIn('start_limit_failure',output['original'])
                self.assertNotIn('SECRET_CANARY',json.dumps(output))
        for wrong_code in ('PUBLIC_BOOTSTRAP_INTERRUPTED','SECRET_CANARY',None):
            output=m.safe_failure({'original':{'result':{'host_primary':wrong_code},
                'start_limit_failure':point}},'original','calibration')
            self.assertNotIn('start_limit_failure',output['original'])

    def test_actual_fixture_assertion_has_unique_public_checkpoint_and_stays_red(self):
        from tests import public_maintenance_native as n
        # Fail the first real fixture assertion before any native I/O. No
        # assertion/return value is replaced; only its synthetic UID input.
        with patch.object(n.f.f.os,'geteuid',return_value=501):
            try:n.f.f.assert_guest_isolation()
            except AssertionError as error:fields=n.failure_fields(error)
            else:self.fail('real fixture assertion did not fail')
        point=fields['test_failure']
        self.assertEqual(point['checkpoint'],'REV4_GUEST_ASSERT_GUEST_ISOLATION_ASSERT_01')
        self.assertEqual(point['file'],'tests/public_operator_native.py')
        self.assertIn('assert os.geteuid() == 0',
            (Path(__file__).resolve().parents[1]/point['file']).read_text().splitlines()[point['line']-1])
        value={'schema':'TU1NZ_REV4_NATIVE_CASE_V1','green':False,'host_acceptance':False,
            'case':'original','phase':'calibration',**fields}
        output=m.safe_failure(value,'original','calibration')
        self.assertEqual(output['test_failure'],point)
        self.assertEqual(output['code'],'NATIVE_FULL_ENTRY_ASSERTION')
        self.assertEqual(output['error_type'],'AssertionError')
        self.assertIs(output['green'],False)
        with self.assertRaisesRegex(m.ci.CIError,'^REV4_NATIVE_CASE_RED$'):
            m.validate_case(value,'original','calibration',{})
        # Exercise the actual CI failure-output/validation/finally path, with
        # all container effects mocked and a locally generated private record.
        import io as streams
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'calibration-original-result.json').write_bytes(io.canonical(value))
            output=streams.StringIO()
            with patch.object(m.ci,'command'),patch.object(m.ci,'inspect_guest'),patch.object(m.ci,'ready'), \
                    patch.object(m.ci.boundary,'cleanup_container') as cleanup,redirect_stdout(output):
                with self.assertRaisesRegex(m.ci.CIError,'^REV4_NATIVE_CASE_RED$'):
                    m.case_run(Path('/synthetic-source'),Path('/synthetic-control'),'synthetic-image','sha256:'+'a'*64,
                        'synthetic-owner',root,Path('/synthetic-inputs'),{},'original','calibration')
            emitted=json.loads(output.getvalue())
            self.assertEqual(emitted['failure']['test_failure'],point)
            self.assertIs(emitted['failure']['green'],False)
            cleanup.assert_called_once_with('tu1nz-rev4-synthetic-owner-calibration-original','synthetic-owner')

    def test_failure_locations_reject_unbound_fields_values_paths_lines_and_types(self):
        point=next(iter(m.diagnostics.checkpoints().values()))
        for change in ({'checkpoint':'SECRET_CANARY'}, {'file':'/private/SECRET_CANARY'},
                {'file':'other/'+point['file']}, {'file':'tests/../'+point['file']},
                {'line':999999}, {'line':True}, {'line':str(point['line'])},
                {'line':float(point['line'])}, {'locals':'SECRET_CANARY'},
                {'checkpoint':[]}, {'file':[]}):
            with self.subTest(change=change):
                value={'test_failure':{**point,**change},'traceback':'SECRET_CANARY'}
                result=m.safe_failure(value,'original','calibration')
                self.assertNotIn('test_failure',result)
                self.assertNotIn('SECRET_CANARY',json.dumps(result))
        # A valid source location paired with another valid ID is invalid too.
        other=next(v for v in m.diagnostics.checkpoints().values() if v['checkpoint']!=point['checkpoint'])
        self.assertIsNone(m.diagnostics.validated({**point,'checkpoint':other['checkpoint']}))
        for value in (None,[],False,{'checkpoint':'UNMAPPED_TEST_FAILURE','private':'SECRET_CANARY'}):
            self.assertIsNone(m.diagnostics.validated(value))

    def test_unmapped_innermost_frame_never_exports_exception_or_a_caller_location(self):
        from tests import public_maintenance_native as n
        try:raise AssertionError('SECRET_CANARY')
        except AssertionError as error:fields=n.failure_fields(error)
        self.assertEqual(fields['test_failure'],{'checkpoint':'UNMAPPED_TEST_FAILURE'})
        result=m.safe_failure(fields,'original','calibration')
        self.assertNotIn('SECRET_CANARY',json.dumps(result))
        self.assertEqual(result['test_failure'],fields['test_failure'])
        self.assertEqual(m.diagnostics.capture(AssertionError('SECRET_CANARY')),fields['test_failure'])

    def test_explicit_deadline_raise_and_multiline_assertion_have_distinct_bound_points(self):
        points=m.diagnostics.checkpoints()
        native=Path(__file__).resolve().parents[1]/'tests/public_maintenance_native.py'
        # Compile only the existing deadline raise, retaining its true source
        # location. No guest, worker, timer or subprocess is started locally.
        import ast
        tree=ast.parse(native.read_bytes())
        node=next(x for x in ast.walk(tree) if isinstance(x,ast.Raise) and
            isinstance(x.exc,ast.Call) and x.exc.args and isinstance(x.exc.args[0],ast.Constant)
            and x.exc.args[0].value=='FULL_ENTRY_600_PROCESS_END_EXCEEDED')
        try:exec(compile(ast.Module(body=[node],type_ignores=[]),str(native),'exec'),{})
        except AssertionError as error:point=m.diagnostics.capture(error)
        self.assertEqual(point['checkpoint'],'REV4_NATIVE_EXECUTE_WORKER_RAISE_01')
        self.assertEqual(m.diagnostics.validated(point),point)
        guest=Path(__file__).resolve().parents[1]/'tests/public_operator_native.py'
        tree=ast.parse(guest.read_bytes());fn=next(x for x in tree.body if isinstance(x,ast.FunctionDef)
            and x.name=='assert_guest_isolation')
        node=next(x for x in ast.walk(fn) if isinstance(x,ast.Assert) and x.end_lineno>x.lineno)
        rows=[points[('tests/public_operator_native.py',line)] for line in range(node.lineno,node.end_lineno+1)]
        self.assertEqual(len({v['checkpoint'] for v in rows}),1)
        self.assertTrue(all(m.diagnostics.validated(v)==v for v in rows))

    def test_native_bootstrap_parses_with_actual_dependency_order_and_without_actions(self):
        from tests import public_maintenance_native as n
        inputs={'application':{'commit':'0'*40,'tree':'1'*40,'manifest_sha256':'a'*64}}
        pins={'MAINTENANCE_MACHINE':'a'*64,'MAINTENANCE_OWNER_PLAN':'b'*64}
        with patch.object(client,'maintenance_bootstrap_original',client.maintenance_bootstrap,create=True):
            program=n.bootstrap(Path(io.__file__).read_bytes(),pins,inputs,'original','original',legacy_sha='c'*64)
        compile(program,'<compile-only-native-bootstrap>','exec')
        self.assertLess(program.index('m.ASSETS['),program.index('s=m.Source('))
        self.assertLess(program.index('s.load("artifact").APP='),program.index('_replacement=s.load("replacement")'))
        self.assertIn('os.kill(os.getpid(),signal.SIGTERM)',n.HOST_TRACE)
        self.assertNotIn('time.monotonic=',program)

    def test_current_fixture_profiles_use_fresh_batched_unit_query(self):
        from tests import public_maintenance_fixture as f
        import tu1nz_public_operator_observe as observer
        import tu1nz_public_operator_context as context
        source=SimpleNamespace(load=lambda name:{'observe':observer,'context':context}[name])
        manager={'exe':'/usr/lib/systemd/systemd','uid':[0]*4,'gid':[0]*4,'groups':[0],
            'caps':{k:0 for k in context.CAPS},'nnp':0,'cgroup':'0::/init.scope',
            'namespaces':{k:k+':[1]' for k in context.NS}}
        response='\n\n'.join('Id='+u+'\nMainPID='+str(10+i) for i,u in enumerate(f.f.UNITS)).encode()
        with patch.object(observer,'command',return_value=SimpleNamespace(returncode=0,stdout=response)) as query, \
                patch.object(f.os,'listdir',return_value=['1','10','11','12']), \
                patch.object(observer,'current_process',return_value=manager) as process, \
                patch.object(f.time,'monotonic',side_effect=[100.0,200.0]):
            for deadline in (130.0,230.0):
                profiles=f.current_profiles(source,SimpleNamespace(poll=lambda:None))
                self.assertEqual(profiles[0]['role'],'kernel_manager')
                self.assertEqual(len(profiles),1)
                query.assert_called_with(['/usr/bin/systemctl','show',*f.f.UNITS,'--no-pager',
                    '--property=Id,MainPID'],deadline)
                process.assert_called_with(1,deadline=deadline)
        self.assertEqual(query.call_count,2);self.assertEqual(process.call_count,2)

    def test_current_fixture_profiles_do_not_census_after_missing_unit_field(self):
        from tests import public_maintenance_fixture as f
        import tu1nz_public_operator_observe as observer
        import tu1nz_public_operator_context as context
        source=SimpleNamespace(load=lambda name:{'observe':observer,'context':context}[name])
        with patch.object(observer,'command',return_value=SimpleNamespace(returncode=0,
                stdout=('Id='+f.f.UNITS[0]).encode())),patch.object(f.os,'listdir') as census:
            with self.assertRaisesRegex(io.Hold,'UNIT_PROFILE_UNKNOWN'):
                f.current_profiles(source,SimpleNamespace(poll=lambda:None))
        census.assert_not_called()

    def test_legacy_fixture_coordinate_is_bound_once_and_real_guard_rejects_drift(self):
        from tests import public_maintenance_fixture as f, public_maintenance_native as n
        import tu1nz_public_operator_observe as observer
        import ast
        source=SimpleNamespace(load=lambda name:observer if name=='observe' else None)
        rows={10+i:{'uid':[1001]*4,'gid':[1001]*4,'groups':[1001,2000+i],
            'nnp':1,'caps':{k:0 for k in observer.CAPS}} for i in range(3)}
        response='\n\n'.join('Id='+u+'\nMainPID='+str(10+i) for i,u in enumerate(f.f.UNITS)).encode()
        with patch.object(observer,'command',return_value=SimpleNamespace(returncode=0,stdout=response)) as query, \
                patch.object(observer,'current_process',side_effect=lambda pid,**kw:rows[pid]) as process, \
                patch.object(f.time,'monotonic',return_value=100.0):
            digest=f.legacy_contexts_sha(source)
        query.assert_called_once_with(['/usr/bin/systemctl','show',*f.f.UNITS,'--no-pager',
            '--property=Id,MainPID'],130.0)
        self.assertEqual([c.args for c in process.call_args_list],[(10,),(11,),(12,)])
        self.assertTrue(all(c.kwargs=={'deadline':130.0} for c in process.call_args_list))
        legacy={u:{**{k:copy.deepcopy(rows[10+i][k]) for k in ('uid','gid','groups','nnp')},
            'caps':{k:'0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapAmb')}}
            for i,u in enumerate(f.f.UNITS)}
        authority=object.__new__(observer.Authority);authority.legacy_contexts=legacy
        self.assertEqual(digest,io.sha(io.canonical(legacy)))
        # Reproduce #955: the fixed production coordinate rejects the fixture.
        with self.assertRaisesRegex(io.Hold,'NOT_THE_THREE_BOUND_LEGACY_CONTEXTS'):
            authority.stop_contexts_check(stop_only=True)
        inputs={'application':{'commit':'0'*40,'tree':'1'*40,'manifest_sha256':'a'*64}}
        pins={'MAINTENANCE_MACHINE':'a'*64,'MAINTENANCE_OWNER_PLAN':'b'*64}
        for route in ('original','recovery-once'):
            with self.subTest(route=route),patch.object(client,'maintenance_bootstrap_original',
                    client.maintenance_bootstrap,create=True):
                program=n.bootstrap(Path(io.__file__).read_bytes(),pins,inputs,'original',route,legacy_sha=digest)
            # Execute the exact generated expected-coordinate assignment only;
            # no transport, Host dispatch, observation or action is substituted.
            nodes=[x for x in ast.walk(ast.parse(program)) if isinstance(x,ast.Assign) and
                any(isinstance(t,ast.Attribute) and t.attr=='LEGACY_CONTEXTS_SHA' for t in x.targets)]
            self.assertEqual(len(nodes),1)
            with patch.object(observer,'LEGACY_CONTEXTS_SHA'),patch.object(observer,'current_process') as reread:
                exec(compile(ast.Module(body=nodes,type_ignores=[]),'<fixture-pin-only>','exec'),{'s':source})
                authority.legacy_contexts=copy.deepcopy(legacy)
                authority.stop_contexts_check(stop_only=True)
                for field in ('uid','gid','groups','nnp','caps','missing_unit'):
                    changed=copy.deepcopy(legacy);row=changed[f.f.UNITS[0]]
                    if field=='missing_unit':del changed[f.f.UNITS[-1]]
                    elif field=='caps':row[field]['CapEff']='0000000000000001'
                    elif field=='nnp':row[field]=0
                    else:row[field][0]+=1
                    authority.legacy_contexts=changed
                    with self.subTest(field=field),self.assertRaisesRegex(io.Hold,'NOT_THE_THREE_BOUND_LEGACY_CONTEXTS'):
                        authority.stop_contexts_check(stop_only=True)
                reread.assert_not_called()  # frozen pin, never rebind to changed state

    def test_legacy_fixture_pin_missing_pid_collision_and_observation_failure_deny(self):
        from tests import public_maintenance_fixture as f
        import tu1nz_public_operator_observe as observer
        source=SimpleNamespace(load=lambda name:observer)
        for fault in ('missing','zero','collision','expired'):
            response='\n\n'.join('Id='+u+('' if fault=='missing' and i==2 else '\nMainPID='+
                str(0 if fault=='zero' else 10 if fault=='collision' else 10+i)) for i,u in enumerate(f.f.UNITS)).encode()
            with self.subTest(fault=fault),patch.object(observer,'command',return_value=
                    SimpleNamespace(returncode=0,stdout=response)),patch.object(observer,'current_process',
                    side_effect=io.Hold('SYNTHETIC_OBSERVATION_DEADLINE')) as process:
                with self.assertRaises((io.Hold,AssertionError)):f.legacy_contexts_sha(source)
                if fault!='expired':process.assert_not_called()

    def test_legacy_pin_reaches_local_binding_in_prepare_worker_and_main(self):
        from tests import public_maintenance_fixture as f, public_maintenance_native as n
        import ast,inspect
        calls=[]
        for module in (f,n):
            for node in ast.walk(ast.parse(Path(module.__file__).read_bytes())):
                if isinstance(node,ast.Call) and (isinstance(node.func,ast.Name) and node.func.id=='bind_expected' or
                        isinstance(node.func,ast.Attribute) and node.func.attr=='bind_expected'):
                    inspect.signature(f.bind_expected).bind(*[None for _ in node.args],
                        **{k.arg:None for k in node.keywords})
                    calls.append(node)
        self.assertEqual(len(calls),3)
        modules={name:SimpleNamespace() for name in ('io','r3','entry','artifact','observe')}
        modules['io'].ASSETS={}
        source=SimpleNamespace(load=modules.__getitem__)
        inputs={'application':{'commit':'0'*40,'tree':'1'*40,'manifest_sha256':'a'*64}}
        pins={'MAINTENANCE_MACHINE':'a'*64,'MAINTENANCE_OWNER_PLAN':'b'*64}
        with patch.dict(io.ASSETS,io.ASSETS),patch.object(io,'MAINTENANCE_MACHINE'),patch.object(io,'MAINTENANCE_OWNER_PLAN'):
            f.bind_expected(source,pins,inputs,legacy_sha='c'*64)
        self.assertEqual(modules['observe'].LEGACY_CONTEXTS_SHA,'c'*64)

    def test_native_synthetic_packet_passes_actual_local_bindings_without_io(self):
        from tests import public_maintenance_fixture as f
        from tests.test_public_maintenance_admission import CoverageTests
        import tu1nz_public_operator_admission as admission
        import tu1nz_public_operator_context as context
        import tu1nz_mainserver_restore as restore
        packet,_,bound=CoverageTests().fixture();b=packet['baseline']
        b['boot_id']='00000000-0000-0000-0000-000000000001';b['source_origin_receipts']=['a'*64]
        receipt={'application':{'commit':'0'*40},'objects':{'x':{}},'archive_bytes':100,'expanded_file_bytes':100}
        origin=io.sha(io.canonical(receipt));b['source_origin_receipts'].append(origin)
        b['source_release']={'runtime_reference':{'schema':'TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1',
            'artifact':receipt,'origin_sha256':origin},'probe_dependencies':{},'python_binary':'/usr/bin/python3',
            'operator_dependencies':{'/usr/bin/busctl':{'source':'/usr/bin/busctl','sha256':'a'*64,'origin_sha256':'a'*64,
                'uid':0,'gid':0,'mode':0o555,'attrs':{},'flags':0}}}
        s=SimpleNamespace(bytes={k:k.encode() for k in io.MODULES|io.ASSETS},load=lambda name:{
            'admission':admission,'context':context,'restore':restore}[name])
        cover=bound['documents']['current_observation']['coverage'];plan=io.parse(bound['plan']);plan['host']=b['machine_sha256']
        receipts={'protection':io.canonical(bound['restore_receipts']['protection']),
            'database':b'{"synthetic":"database"}','cleanup':b'{"synthetic":"cleanup"}'}
        with patch.object(os,'open',side_effect=AssertionError('PURE_PACKET_ONLY')):
            built,pins=f.package(s,b,io.canonical(plan),receipt,cover,receipts)
            with ExitStack() as stack:
                for k,v in pins.items():stack.enter_context(patch.object(io,k,v))
                checked=io.maintenance_packet_binding(built,s,remaining_seconds=600)
                admission.validate(built,s,checked,remaining_seconds=600)

    def test_create_effect_then_lost_ack_still_cleans_only_fixed_owned_container(self):
        with patch.object(m.ci,'command',side_effect=TimeoutError('SYNTHETIC_LOST_CREATE_ACK')), \
                patch.object(m.ci.boundary,'cleanup_container') as cleanup:
            with self.assertRaises(TimeoutError):
                m.case_run(Path('/synthetic-source'),Path('/synthetic-control'),'synthetic-image','sha256:'+'a'*64,
                    'synthetic-owner',Path('/synthetic-private'),Path('/synthetic-inputs'),{},'original','calibration')
        cleanup.assert_called_once_with('tu1nz-rev4-synthetic-owner-calibration-original','synthetic-owner')

    def test_calibration_between_jobs_is_exact_source_and_measurement_bound(self):
        hashes,artifact,records=self.fixture();receipt=m.calibration_record(records,'f'*64,'c'*40)
        raw=json.dumps(receipt)
        self.assertEqual(m.calibration_input(raw,hashes,'f'*64,'c'*40),receipt['timing'])
        for key,value in (('source_sha','d'*40),('measurement_source_sha256','e'*64),('host_acceptance',True)):
            changed={**receipt,key:value}
            with self.subTest(key=key),self.assertRaises(m.ci.CIError):
                m.calibration_input(json.dumps(changed),hashes,'f'*64,'c'*40)
        with self.assertRaises(m.ci.CIError):m.calibration_input(' '*32769,hashes,'f'*64,'c'*40)

    def test_job_output_appends_one_bounded_canonical_calibration_only(self):
        _,_,records=self.fixture();receipt=m.calibration_record(records,'f'*64,'c'*40)
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'job-output';target.write_bytes(b'existing=value\n')
            with patch.dict(os.environ,{'GITHUB_OUTPUT':str(target)}):m.publish_calibration(receipt)
            self.assertEqual(target.read_bytes(),b'existing=value\nrev4_calibration='+io.canonical(receipt)+b'\n')

    def test_job_output_rejects_symlinks_hardlinks_and_oversized_values_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);target=root/'output';target.write_bytes(b'UNCHANGED')
            link=root/'link';link.symlink_to(target)
            with patch.dict(os.environ,{'GITHUB_OUTPUT':str(link)}),self.assertRaises(OSError):
                m.publish_calibration({'synthetic':True})
            link.unlink();os.link(target,link)
            with patch.dict(os.environ,{'GITHUB_OUTPUT':str(link)}),self.assertRaises(m.ci.CIError):
                m.publish_calibration({'synthetic':True})
            with patch.dict(os.environ,{'GITHUB_OUTPUT':str(target)}),self.assertRaises(m.ci.CIError):
                m.publish_calibration({'synthetic':'x'*32769})
            self.assertEqual(target.read_bytes(),b'UNCHANGED')

    def test_fixture_references_require_isolation_and_actual_loaded_target_before_ageing(self):
        from tests import public_maintenance_fixture as f
        active=('ActiveState=active\nWants='+' '.join(f.f.UNITS)+'\n').encode()
        with patch.object(f.f,'assert_guest_isolation') as isolated,patch.object(f.f,'run',return_value=active) as run:
            f.retain_fixture_unit_references()
        isolated.assert_called_once_with()
        self.assertEqual([c.args for c in run.call_args_list],
            [('/usr/bin/systemctl','enable',unit) for unit in f.f.UNITS]+
            [('/usr/bin/systemctl','daemon-reload'),
             ('/usr/bin/systemctl','show','multi-user.target','--property=ActiveState,Wants')])
        for value in (active.replace(b'active',b'inactive'),b'ActiveState=active\nWants=\n',
                      active.replace(f.f.UNITS[0].encode(),b'')):
            with self.subTest(value=value),patch.object(f.f,'assert_guest_isolation'), \
                    patch.object(f.f,'run',return_value=value), \
                    self.assertRaisesRegex(AssertionError,'NATIVE_FIXTURE_UNIT_REFERENCES_MISSING'):
                f.retain_fixture_unit_references()
        with patch.object(f.f,'assert_guest_isolation',side_effect=AssertionError('NOT_A_GUEST')), \
                patch.object(f.f,'run') as run,self.assertRaisesRegex(AssertionError,'NOT_A_GUEST'):
            f.retain_fixture_unit_references()
        run.assert_not_called()
        # A failed reference setup must not reach ageing, baseline or a packet.
        with patch.object(f.f,'assert_guest'),patch.object(f.f,'source',return_value=(object(),None,{})), \
                patch.object(f.f,'setup'),patch.object(f,'ssh_setup'), \
                patch.object(f,'retain_fixture_unit_references',side_effect=AssertionError('REFERENCES_MISSING')), \
                patch.object(f,'runtime') as runtime,patch.object(f,'age_start_anchors') as age, \
                patch.object(f.f,'baseline') as baseline,self.assertRaisesRegex(AssertionError,'REFERENCES_MISSING'):
            f.prepare()
        runtime.assert_not_called();age.assert_not_called();baseline.assert_not_called()

    def test_missing_stopped_invocation_still_denies_even_with_valid_active_anchor(self):
        from tests.test_public_maintenance import StartLimitStateProofTests,transition
        fixture=StartLimitStateProofTests();anchor=fixture.snapshot();stopped=fixture.snapshot(active=False)
        self.assertEqual(transition.start_limit_permission(stopped,anchor=anchor),
            'SAME_AGED_INVOCATION_NOW_SUCCESSFULLY_EMPTY')
        stopped['unit_state']['InvocationID']=''
        with self.assertRaisesRegex(io.Hold,'START_LIMIT_STATE_NOT_ELIGIBLE'):
            transition.start_limit_permission(stopped,anchor=anchor)

    def test_start_anchor_age_uses_real_wait_before_fresh_read_and_closes_provider(self):
        from tests import public_maintenance_fixture as f
        clock=[0.0];events=[];bus=SimpleNamespace(close=lambda:events.append('bus_closed'))
        def read(reader,unit_reader,unit):
            events.append(('read',unit,clock[0]));self.assertIs(reader,bus)
            return {'unit':unit,'manager_owner':':1.1','properties':{'StartLimitIntervalUSec':900000000,
                'ActiveEnterTimestampMonotonic':0},'unit_state':{'ActiveState':'active','NRestarts':'0'},
                'observed_monotonic_us':int(clock[0]*1e6)}
        def permission(value,require_active):
            self.assertTrue(require_active);self.assertGreater(value['observed_monotonic_us'],900001000)
            events.append('fresh_predicate');return 'AGED_SUCCESSFUL_ACTIVE_INVOCATION'
        replacement=SimpleNamespace(ReadOnlyBus=Mock(return_value=bus),start_limit_state_read=read,
            start_limit_permission=permission)
        source=SimpleNamespace(load=lambda n:replacement if n=='replacement' else None)
        provider=Path('/synthetic/libsystemd-shared-255.so')
        with patch.object(f.f,'operator_dependency_names',return_value=[str(provider)]), \
                patch.object(f.Path,'resolve',return_value=provider),patch.object(f.os,'open',return_value=7), \
                patch.object(f.os,'close') as close,patch.object(f.time,'monotonic',side_effect=lambda:clock[0]), \
                patch.object(f.time,'sleep',side_effect=lambda seconds:clock.__setitem__(0,clock[0]+seconds)):
            f.age_start_anchors(source)
        self.assertGreater(clock[0],900.001);self.assertEqual(events.count('fresh_predicate'),3)
        self.assertEqual(events[-1],'bus_closed');close.assert_called_once_with(7)
        replacement.ReadOnlyBus.assert_called_once_with(7,925)


if __name__=='__main__':unittest.main()
