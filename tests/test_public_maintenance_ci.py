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

    def test_native_bootstrap_parses_with_actual_dependency_order_and_without_actions(self):
        from tests import public_maintenance_native as n
        inputs={'application':{'commit':'0'*40,'tree':'1'*40,'manifest_sha256':'a'*64}}
        pins={'MAINTENANCE_MACHINE':'a'*64,'MAINTENANCE_OWNER_PLAN':'b'*64}
        with patch.object(client,'maintenance_bootstrap_original',client.maintenance_bootstrap,create=True):
            program=n.bootstrap(Path(io.__file__).read_bytes(),pins,inputs,'original','original')
        compile(program,'<compile-only-native-bootstrap>','exec')
        self.assertLess(program.index('m.ASSETS['),program.index('s=m.Source('))
        self.assertLess(program.index('s.load("artifact").APP='),program.index('_replacement=s.load("replacement")'))
        self.assertIn('os.kill(os.getpid(),signal.SIGTERM)',n.HOST_TRACE)
        self.assertNotIn('time.monotonic=',program)

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
