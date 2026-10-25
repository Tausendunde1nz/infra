"""Synthetic material/schema regressions; NOT Host capture or annex acceptance."""
import base64
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator as client
io=client.io


class ProspectiveAdmission(unittest.TestCase):
    def fixture(self, change=None):
        actual={}
        def put(value):
            raw=io.canonical(value);h=io.sha(raw);actual[h]=raw;return h
        evidence=[put({'synthetic_evidence':k}) for k in range(7)]
        def origin(basis,objects):
            return put({'schema':io.BYTE_ORIGIN,'basis':basis,'objects':objects,
                        'source_evidence_sha256':[evidence[5]]})
        def meta(mode=0o644):return dict(uid=0,gid=0,mode=mode,attrs={},flags=0)
        files={p:dict(sha256=io.sha(p.encode()),**meta()) for p in io.PROSPECTIVE_NSS}
        # One explicit policy leaf exercises complete directory membership.
        policy={p:[] for p in io.PROSPECTIVE_POLICY_ROOTS}
        policy['/etc/sudoers.d']=['synthetic'];files['/etc/sudoers.d/synthetic']=dict(sha256='d'*64,**meta(0o440))
        units={p:dict(sha256=h,**meta()) for p,h in io.PROSPECTIVE_UNITS.items()}
        unit_origin=origin('GIT',dict(io.PROSPECTIVE_UNITS))
        execution={'/usr/bin/busctl':'a'*64,'/usr/bin/python3.12':'b'*64,
            '/usr/lib/systemd/systemd':'c'*64,'/usr/sbin/nginx':'e'*64}
        exec_origin=origin('PUBLISHER',execution)
        cache_hash='f'*64;cache_origin=origin('CACHE_DERIVATION',{'/etc/ld.so.cache':cache_hash})
        actors=[]
        for role,exe in [('kernel_manager','/usr/lib/systemd/systemd'),
            ('authenticated_maintenance','/usr/bin/python3.12'),
            ('administrative_service','/usr/bin/busctl'),('nginx_reader','/usr/sbin/nginx')]:
            uid=33 if role=='nginx_reader' else 0
            row=dict(role=role,exe=exe,exe_sha256=execution[exe],uid=[uid]*4,gid=[uid]*4,
                groups=[uid],caps={k:0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')},nnp=1,
                argv_sha256='1'*64,cgroup='/system.slice/synthetic.service',initial_env_sha256='2'*64,
                lsm_sha256='3'*64,namespaces={k:k+':[1]' for k in ('pid','mnt','user','net')},max_instances=1)
            actors.append(dict(profile=row,justification='Synthetic regression fixture, never a production role approval.'))
        b=dict(machine_sha256='4'*64,boot_id='synthetic-boot',policy_roots=policy,
            source_release=dict(operator_dependencies={'/usr/bin/busctl':dict(source='/usr/bin/busctl',
                sha256='a'*64,origin_sha256=exec_origin,**meta(0o755))},
                probe_dependencies={'/usr/bin/python3.12':dict(source='/usr/bin/python3.12',sha256='b'*64)}),
            unit_files={str(n):dict(fragment=p,dropins=[]) for n,p in enumerate(units)},files={},actors=[])
        names={}
        for path in set(files)|set(units)|set(execution)|set(policy):
            parent=Path(path) if path in policy else Path(path).parent
            while True:
                names[str(parent)]=dict(kind='directory',**meta(0o755))
                if str(parent)=='/':break
                parent=parent.parent
        binding=dict(schema=io.PROSPECTIVE_BINDING,machine_sha256=b['machine_sha256'],boot_id=b['boot_id'],
            transaction='public-rights-20261014-1',capture=dict(read_scope_sha256=evidence[0],
            reader_source_sha256=evidence[1],read_receipt_sha256=evidence[2],
            started_at='2026-10-25T10:00:00Z',finished_at='2026-10-25T10:01:00Z'),
            host_files=files,unit_files=units,policy_roots=policy,actors=actors,
            metadata={p:{k:v for k,v in r.items() if k!='sha256'} for p,r in {**files,**units}.items()},
            execution_origins={p:exec_origin for p in execution},names=names)
        binding['metadata']['/usr/bin/busctl']=meta(0o755)
        binding['metadata'].update({p:meta(0o755) for p in execution})
        binding['metadata']['/etc/ld.so.cache']=meta()
        scope=dict(schema=io.PROSPECTIVE_SCOPE,machine_sha256=b['machine_sha256'],transaction=binding['transaction'],
                   release_sha256='5'*64,owner_plan_sha256='6'*64)
        acceptance=dict(schema=io.PROSPECTIVE_ACCEPTANCE,binding_sha256='',machine_sha256=b['machine_sha256'],
            boot_id=b['boot_id'],transaction=binding['transaction'],release_sha256=scope['release_sha256'],
            owner_plan_sha256=scope['owner_plan_sha256'],review_sha256=evidence[3],human_decision_sha256=evidence[4],
            accepted_at='2026-10-25T10:02:00Z',expires_at='2026-10-26T10:01:00Z',risk=io.PROSPECTIVE_RISK)
        if change:change(binding,acceptance,b,actual)
        bh=put(binding);acceptance['binding_sha256']=bh;ah=put(acceptance)
        scope.update(prospective_binding_sha256=bh,prospective_acceptance_sha256=ah)
        b['files']={p:dict(r,origin_sha256=bh) for p,r in files.items()}
        b['files'].update({p:dict(r,origin_sha256=unit_origin) for p,r in units.items()})
        b['files']['/etc/ld.so.cache']=dict(sha256=cache_hash,origin_sha256=cache_origin,**meta())
        b['actors']=[dict(a['profile'],origin_sha256=bh) for a in actors]
        b['source_origin_receipts']=sorted(actual)
        return scope,b,actual

    def check(self,fixture):
        with patch.object(io.time,'time',return_value=1792923000): # 25 Oct 2026 10:10 UTC
            return io.prospective_binding(*fixture)

    def test_complete_synthetic_material_and_exact_packet_roundtrip(self):
        s,b,a=self.fixture();used=self.check((s,b,a))
        self.assertGreater(len(used),7)
        p=dict(scope=s,baseline=b,prospective_material={h:base64.b64encode(v).decode() for h,v in used.items()})
        with patch.object(io.time,'time',return_value=1792923000):
            self.assertEqual(io.prospective_packet_material(p)['schema'],io.PROSPECTIVE_BINDING)

    def test_no_annex_template_boolean_empty_or_missing_evidence_admits(self):
        cases=[lambda x,y,b,a:x['host_files'].clear(),lambda x,y,b,a:x['actors'].clear(),
            lambda x,y,b,a:x.update(trusted=True),lambda x,y,b,a:y.update(accepted=True),
            lambda x,y,b,a:a.pop(y['review_sha256']),lambda x,y,b,a:a.pop(y['human_decision_sha256']),
            lambda x,y,b,a:y.update(risk='ACCEPT_ALL_ROOT'),lambda x,y,b,a:y.update(release_sha256='7'*64)]
        for n,change in enumerate(cases):
            with self.subTest(case=n),self.assertRaises(io.Hold):self.check(self.fixture(change))

    def test_policy_file_unit_and_metadata_sets_cannot_be_partial_or_broader(self):
        cases=[lambda x,y,b,a:x['host_files'].pop('/etc/hosts'),
            lambda x,y,b,a:x['policy_roots'].pop('/etc/sudoers.d'),
            lambda x,y,b,a:x['policy_roots']['/etc/sudoers.d'].append('../foreign'),
            lambda x,y,b,a:x['unit_files'].pop(next(iter(x['unit_files']))),
            lambda x,y,b,a:x['unit_files'][next(iter(x['unit_files']))].update(sha256='8'*64),
            lambda x,y,b,a:x['metadata'].pop('/etc/passwd'),
            lambda x,y,b,a:x['metadata']['/etc/passwd'].update(mode=0o666),
            lambda x,y,b,a:x['metadata']['/etc/passwd'].update(attrs={'security.capability':'x'}),
            lambda x,y,b,a:x['metadata']['/etc/passwd'].update(uid=False)]
        for n,change in enumerate(cases):
            with self.subTest(case=n),self.assertRaises(io.Hold):self.check(self.fixture(change))

    def test_roles_are_exact_bounded_justified_and_not_uid_exceptions(self):
        cases=[lambda x,y,b,a:x['actors'][0]['profile'].update(role='root_any'),
            lambda x,y,b,a:x['actors'][0]['profile'].update(max_instances=2),
            lambda x,y,b,a:x['actors'][0]['profile'].update(uid=[1001]*4),
            lambda x,y,b,a:x['actors'][1].update(justification='UID0'),
            lambda x,y,b,a:x['actors'][1]['profile'].update(nnp=True),
            lambda x,y,b,a:x['actors'][1]['profile'].update(namespaces={}),
            lambda x,y,b,a:x['actors'][2]['profile'].update(cgroup='/unknown'),
            lambda x,y,b,a:x['actors'][3]['profile']['caps'].update(CapEff=1),
            lambda x,y,b,a:x['execution_origins'].pop('/usr/sbin/nginx')]
        for n,change in enumerate(cases):
            with self.subTest(case=n),self.assertRaises(io.Hold):self.check(self.fixture(change))

    def test_prospective_receipts_never_authenticate_executable_bytes(self):
        s,b,a=self.fixture();b['source_release']['operator_dependencies']['/usr/bin/busctl']['origin_sha256']=s['prospective_binding_sha256']
        with self.assertRaises(io.Hold):self.check((s,b,a))
        def fake(x,y,b,a):
            h=x['execution_origins']['/usr/bin/busctl'];v=io.parse(a.pop(h));v['basis']='PROSPECTIVE'
            raw=io.canonical(v);new=io.sha(raw);a[new]=raw
            x['execution_origins']={k:new for k in x['execution_origins']}
        with self.assertRaises(io.Hold):self.check(self.fixture(fake))

    def test_expired_future_capture_and_old_scope_downgrade_deny(self):
        for change in [lambda x,y,b,a:y.update(expires_at='2026-10-25T10:03:00Z'),
            lambda x,y,b,a:x['capture'].update(finished_at='2026-10-25T10:06:00Z'),
            lambda x,y,b,a:y.update(accepted_at='2026-10-25T11:00:00Z')]:
            with self.assertRaises(io.Hold):self.check(self.fixture(change))
        s,b,a=self.fixture();s['schema']=io.R5_SCOPE
        with self.assertRaisesRegex(io.Hold,'DOWNGRADE'):self.check((s,b,a))

    def test_names_exact_parents_alias_targets_cycles_and_secure_profiles(self):
        cases=[lambda x,y,b,a:x['names'].pop('/usr'),
            lambda x,y,b,a:x['names'].update({'/unselected':dict(x['names']['/'])}),
            lambda x,y,b,a:x['names']['/usr'].update(mode=0o777),
            lambda x,y,b,a:x['names'].update({'/usr':dict(kind='link',uid=0,gid=0,mode=0o777,attrs={},target='/usr')})]
        for n,change in enumerate(cases):
            with self.subTest(case=n),self.assertRaises(io.Hold):self.check(self.fixture(change))

    def test_packet_missing_extra_or_changed_private_material_denies(self):
        s,b,a=self.fixture();used=self.check((s,b,a))
        for change in [lambda p:p.pop('prospective_material'),
            lambda p:p['prospective_material'].update({'a'*64:base64.b64encode(b'EXTRA').decode()}),
            lambda p:p['prospective_material'].pop(s['prospective_acceptance_sha256']),
            lambda p:p['prospective_material'].update({s['prospective_binding_sha256']:'INVALID'})]:
            p=dict(scope=s,baseline=b,prospective_material={h:base64.b64encode(v).decode() for h,v in used.items()});change(p)
            with self.subTest(change=change),patch.object(io.time,'time',return_value=1792923000),self.assertRaises(io.Hold):
                io.prospective_packet_material(p)

    def test_selected_alias_target_must_match_authenticated_canonical_source(self):
        def alias(x,y,b,a):
            b['source_release']['operator_dependencies']['/bin/busctl']=dict(
                b['source_release']['operator_dependencies']['/usr/bin/busctl'])
            x['metadata']['/bin/busctl']=dict(x['metadata']['/usr/bin/busctl'])
            x['names']['/bin']=dict(kind='link',uid=0,gid=0,mode=0o777,attrs={},target='usr/bin')
        self.check(self.fixture(alias))
        def wrong(x,y,b,a):
            alias(x,y,b,a);x['names']['/bin']['target']='usr/sbin'
        with self.assertRaisesRegex(io.Hold,'ALIAS_SOURCE'):self.check(self.fixture(wrong))
        def probe_conflict(x,y,b,a):
            b['source_release']['probe_dependencies']['/bin/python3.12']=dict(
                b['source_release']['probe_dependencies']['/usr/bin/python3.12'])
            x['metadata']['/bin/python3.12']=dict(x['metadata']['/usr/bin/python3.12'],mode=0o700)
            x['names']['/bin']=dict(kind='link',uid=0,gid=0,mode=0o777,attrs={},target='usr/bin')
        with self.assertRaisesRegex(io.Hold,'METADATA_ALIAS_CONFLICT'):self.check(self.fixture(probe_conflict))

    def test_actual_name_comparison_is_additional_and_fail_closed(self):
        # Method contract with synthetic Paths only; not actual Linux/Host admission.
        with patch.object(os,'O_NOATIME',getattr(os,'O_NOATIME',0),create=True):
            import tu1nz_public_runtime_transition as transition
        s,b,a=self.fixture();binding=io.parse(a[s['prospective_binding_sha256']])
        subject=transition.ReplacementAuthority.__new__(transition.ReplacementAuthority)
        subject.b=b;subject.paths=Mock();subject.bind_loader_path=Mock(side_effect=lambda p:p);subject.check_loader_paths=Mock()
        subject.paths.rows={p:(None,dict(r)) for p,r in binding['names'].items()}
        subject.admit_prospective_names(binding)
        self.assertEqual(subject.bind_loader_path.call_count,len(io.prospective_names(binding,b))+len(binding['metadata']))
        subject.paths.rows['/usr'][1]['mode']=0o777
        with self.assertRaisesRegex(io.Hold,'DIRECTORY_DRIFT'):subject.admit_prospective_names(binding)

    def test_cache_actor_probe_metadata_coverage_and_fresh_flags(self):
        s,b,a=self.fixture();b['files'].pop('/etc/ld.so.cache')
        with self.assertRaisesRegex(io.Hold,'CACHE_BASELINE_REQUIRED'):self.check((s,b,a))
        for path in ('/etc/ld.so.cache','/usr/sbin/nginx','/usr/bin/python3.12'):
            def omit(x,y,b,a):x['metadata'].pop(path)
            with self.subTest(path=path),self.assertRaisesRegex(io.Hold,'METADATA_SET'):self.check(self.fixture(omit))
        with patch.object(os,'O_NOATIME',getattr(os,'O_NOATIME',0),create=True):
            import tu1nz_public_runtime_transition as transition
        subject=transition.ReplacementAuthority.__new__(transition.ReplacementAuthority)
        expected=dict(uid=0,gid=0,mode=0o755,attrs={},flags=0)
        subject.paths=Mock();subject.paths.get.return_value=7;subject.loader_aliases={}
        subject.prospective_metadata={'/usr/sbin/nginx':expected};subject.paths.d.metadata.return_value=expected
        with patch.object(transition.os,'open',return_value=8),patch.object(transition.os,'close') as close:
            subject.check_loader_paths();close.assert_called_once_with(8)
        subject.paths.d.metadata.return_value=dict(expected,flags=16)
        with patch.object(transition.os,'open',return_value=8),patch.object(transition.os,'close') as close:
            with self.assertRaisesRegex(io.Hold,'FILE_METADATA_DRIFT'):subject.check_loader_paths()
            close.assert_called_once_with(8)

    def test_client_requires_private_material_before_success(self):
        s,b,a=self.fixture();artifact={'synthetic':'NOT_HOST_ADMISSION'};raw=io.canonical(artifact);h=io.sha(raw)
        a[h]=raw;b['source_origin_receipts'].append(h)
        b['source_release']['runtime_reference']=dict(schema='TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1',
            artifact=artifact,origin_sha256=h)
        with tempfile.TemporaryDirectory() as folder:
            paths=[]
            for digest,raw in a.items():
                p=Path(folder)/digest;p.write_bytes(raw);p.chmod(0o600);paths.append(p)
            with patch.object(io.time,'time',return_value=1792923000):
                selected=client.reference_origins(paths,b,s)
                self.assertNotIn(h,selected) # full runtime receipt is NOT sent twice
            with self.assertRaisesRegex(io.Hold,'DOWNGRADE'):client.reference_origins(paths,b)

    def test_host_checks_material_before_adapter_or_claim(self):
        # Source-order assertion plus direct missing-packet refusal; not a native Host acceptance.
        import inspect
        with patch.object(os,'O_NOATIME',getattr(os,'O_NOATIME',0),create=True):
            import tu1nz_public_operator_host as host
        body=inspect.getsource(host.session)
        self.assertLess(body.index('io.prospective_packet_material(packet)'),body.index('adapter.__init__'))
        self.assertLess(body.index('admit_prospective_names'),body.index("wire.send({'type': 'prepared'"))
        self.assertIn('io.prospective_packet_material(packet)',body[body.index('admit_prospective_names'):body.index("wire.send({'type': 'prepared'")])

    def test_expiry_during_preparation_denies_before_client_custody_and_claim(self):
        s,b,a=self.fixture();used=self.check((s,b,a))
        packet=dict(scope=s,baseline=b,prospective_material={h:base64.b64encode(v).decode() for h,v in used.items()})
        wire=Mock();wire.receive.return_value={'type':'prepared','binding':'synthetic'}
        subject=client.Client(wire,Mock(),'synthetic',http_expectations=[],admission_packet=packet)
        subject.initialize=Mock()
        with patch.object(io.time,'time',return_value=1792923000):subject.admission_current()
        with patch.object(io.time,'time',return_value=1793012400),self.assertRaisesRegex(io.Hold,'TIME_OR_EXPIRY'):
            subject.serve()
        subject.initialize.assert_not_called();wire.send.assert_not_called()


if __name__=='__main__':unittest.main()
