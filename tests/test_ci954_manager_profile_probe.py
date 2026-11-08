import ast
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from tests import ci954_manager_profile_probe as p


class ProbeTests(unittest.TestCase):
    def result(self):
        return {'schema':p.SCHEMA,'conditions':dict.fromkeys(p.BOOLS,True),'guard_passed':True,
            'error_type':None,'test_failure':None,'source_files':p.source_hashes(),'host_acceptance':False,
            'manager_profile':{'objects_examined':12,'offenders':[{'object':'FIXTURE_UNIT',
                'path_sha256':hashlib.sha256(p.UNIT_PATH.encode()).hexdigest(),'uid':os.geteuid(),
                'gid':os.getegid(),'mode':0o600,'nlink':1,'regular_file':True}]}}

    def test_unit_bytes_only_change_entry_not_unit_configuration(self):
        expected=('[Unit]\nAfter=multi-user.target\n[Service]\nType=simple\nEnvironment=container=docker\n'
            'ExecStart=/usr/bin/python3 -I -B -S /source/tests/ci954_manager_profile_probe.py --case original --phase calibration\n'
            'StandardOutput=null\nStandardError=append:/native-private-stderr\nTimeoutStartSec=infinity\n').encode()
        self.assertEqual(p.unit_bytes(False),expected);self.assertEqual(p.unit_bytes(True),expected)

    def test_exact_failed_source_predicate_keeps_owner_and_mode_guards(self):
        expr,roots=p.source_expressions();code=compile(ast.Expression(expr),'<predicate>','eval')
        self.assertEqual(len(roots),12)
        for uid,kind,mode,expected in ((0,stat.S_IFREG,0o600,True),(1001,stat.S_IFREG,0o600,False),
                (0,stat.S_IFREG,0o664,False),(0,stat.S_IFDIR,0o775,False),(0,stat.S_IFLNK,0o777,True),
                (1001,stat.S_IFLNK,0o777,False)):
            with self.subTest(uid=uid,kind=kind,mode=mode):
                self.assertIs(eval(code,{'stat':stat},{'s':SimpleNamespace(st_uid=uid,st_mode=kind|mode)}),expected)

    def test_only_one_exact_runner_owned_unit_allows_comparison(self):
        self.assertTrue(p.only_copied_unit_owner(self.result()))
        for change in ({'uid':0},{'uid':os.geteuid()+1},{'gid':os.getegid()+1},
                {'mode':0o660},{'nlink':2},{'regular_file':False},{'object':'OTHER_SEARCH_OBJECT'}):
            v=self.result();v['manager_profile']['offenders'][0].update(change)
            self.assertFalse(p.only_copied_unit_owner(v))
        for rows in ([],self.result()['manager_profile']['offenders']*2):
            v=self.result();v['manager_profile']['offenders']=rows
            self.assertFalse(p.only_copied_unit_owner(v))

    def test_reject_private_unknown_or_ill_typed_report_fields(self):
        for change in ({'private':'SECRET'},{'uid':True},{'mode':0o10000},{'nlink':0},
                {'path_sha256':'SECRET'},{'object':'SECRET'}):
            v=self.result();v['manager_profile']['offenders'][0].update(change)
            with self.subTest(change=change),self.assertRaises(p.ProbeError):p.validate(v)
        v=self.result();v['source_files'][p.BOUND[0]]='a'*64
        with self.assertRaises(p.ProbeError):p.validate(v)
        v=self.result();v['conditions']['euid_is_zero']=False
        with self.assertRaises(p.ProbeError):p.validate(v)

    def test_actual_local_synthetic_metadata_scan_no_contents_or_symlink_follow(self):
        expression,_=p.source_expressions()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();(root/'file').write_text('SECRET_NOT_EMITTED');(root/'link').symlink_to('/nonexistent')
            with mock.patch.object(p,'source_expressions',return_value=(expression,{str(root)})), \
                    mock.patch.object(p.ci,'command',return_value=str(root).encode()):
                result=p.manager_profile()
            self.assertEqual(result['objects_examined'],2)
            self.assertEqual(len(result['offenders']),2 if os.geteuid()!=0 else 0)
            self.assertNotIn('SECRET',json.dumps(result));p.validate_profile(result)

    def test_owner_correction_command_is_fixed_and_program_parses_only(self):
        with tempfile.TemporaryDirectory() as directory:
            unit=Path(directory)/'unit';unit.write_bytes(b'SYNTHETIC')
            with mock.patch.object(p.ci,'command') as command:p.fix_copied_unit_owner('synthetic-guest',unit)
            argv=command.call_args.args[0]
            self.assertEqual(argv[:8],['/usr/bin/docker','exec','synthetic-guest','/usr/bin/python3','-I','-B','-S','-c'])
            compile(argv[8],'<parse-only>','exec')
            self.assertIn('os.fchown(fd,0,0)',argv[8]);self.assertIn(p.UNIT_PATH,argv[8])
            self.assertEqual(argv[9:],[str(os.geteuid()),str(os.getegid()),hashlib.sha256(b'SYNTHETIC').hexdigest()])

    def test_exit_one_still_requires_valid_report_and_separate_transport_status(self):
        with tempfile.TemporaryDirectory() as directory:
            dest=Path(directory)/'result';dest.write_text(json.dumps(self.result()));report={'transports':[]}
            with mock.patch.object(p.ci.boundary,'bounded',side_effect=[(0,b'1\n'),(0,b'')]):
                self.assertEqual(p.receive_report('synthetic',dest,'original-unit',report),self.result())
            self.assertEqual(report['transports'],[{'variant':'original-unit','wait_command_exit':0,
                'guest_exit_status':1,'report_copy_exit':0,'report_valid':True}])

    def test_transport_and_invalid_reports_fail_without_exporting_error_bytes(self):
        cases=[([(1,b'SECRET')],None,'PROBE_WAIT_COMMAND_RED'),
            ([(0,b'SECRET')],None,'PROBE_WAIT_PAYLOAD_RED'),
            ([(0,b'256')],None,'PROBE_WAIT_PAYLOAD_RED'),
            ([(0,b'1'),(1,b'SECRET')],None,'PROBE_REPORT_COPY_RED'),
            ([(0,b'1'),(0,b'')],None,'PROBE_REPORT_READ_RED'),
            ([(0,b'1'),(0,b'')],b'SECRET','PROBE_REPORT_JSON_RED'),
            ([(0,b'1'),(0,b'')],b'{}','PROBE_REPORT_RED')]
        for outputs,content,code in cases:
            with self.subTest(code=code),tempfile.TemporaryDirectory() as directory:
                dest=Path(directory)/'result';report={'transports':[]}
                if content is not None:dest.write_bytes(content)
                with mock.patch.object(p.ci.boundary,'bounded',side_effect=outputs),self.assertRaisesRegex(p.ProbeError,code):
                    p.receive_report('synthetic',dest,'original-unit',report)
                self.assertNotIn('SECRET',json.dumps(report));self.assertFalse(report['transports'][0]['report_valid'])

    def test_unclear_create_ack_retains_owned_cleanup_and_primary_failure(self):
        for cleanup_fails in (False,True):
            with self.subTest(cleanup_fails=cleanup_fails),tempfile.TemporaryDirectory() as directory:
                parent=Path(directory).resolve();out=io.StringIO()
                def command(argv,**kwargs):
                    if argv[1:3]==['image','inspect']:return b'sha256:'+b'1'*64+b'\n'
                    self.assertEqual(argv[1],'create');raise TimeoutError('SECRET')
                with mock.patch.dict(os.environ,{'RUNNER_TEMP':str(parent),'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1'}), \
                        mock.patch.object(p,'binding',return_value='a'*40),mock.patch.object(p.ci,'command',side_effect=command), \
                        mock.patch.object(p.ci.boundary,'cleanup_container',side_effect=RuntimeError() if cleanup_fails else None) as cleanup, \
                        contextlib.redirect_stdout(out):
                    self.assertEqual(p.driver('tu1nz-ci954-probe:1-1'),1)
                row=json.loads(out.getvalue());self.assertEqual(row['code'],'PROBE_COMMAND_RED')
                self.assertEqual(row['phase'],'original-unit-create');self.assertTrue(row['temporary_inputs_removed'])
                self.assertEqual(row['cleanup_errors'],['GUEST_CLEANUP_RED'] if cleanup_fails else [])
                self.assertNotIn('SECRET',out.getvalue());cleanup.assert_called_once();self.assertEqual(list(parent.iterdir()),[])


if __name__=='__main__':unittest.main()
