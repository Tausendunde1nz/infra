"""Portable byte/protocol regressions, NOT native/Host acceptance.

No upstream code, server, credential, systemd or production transaction runs.
Native filesystem/rights/full-entry tests are separate mandatory gates.
"""
import base64
import copy
import gzip
import io
import json
import subprocess
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import zlib
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_runtime_artifact as a
import tu1nz_public_operator as client
import tu1nz_public_operator_io as wire
import tu1nz_public_runtime_ci as native


class ArtifactBytes(unittest.TestCase):
    def test_ci_checks_actual_infra_root_not_application_workflow_carrier(self):
        with tempfile.TemporaryDirectory() as d:
            workflow=Path(d).resolve();infra=workflow/'infra';application=workflow/'canonical-runtime-r5'
            expected='a'*40;carrier='b'*40
            def read(root,*argv):
                if root==infra:return '' if argv[0] in ('status','ls-files') else expected
                if root==application:return a.APP[1] if argv[-1]=='HEAD^{tree}' else a.APP[0]
                self.assertEqual(root,workflow);return carrier
            with patch.object(native,'git_read',side_effect=read) as queried:
                actual,roles=native.checkout_roles(infra,application,workflow,expected,carrier)
                self.assertEqual(actual,expected);self.assertEqual(roles['application_workflow_head'],carrier)
                queried.assert_any_call(infra,'rev-parse','HEAD')
            for bad in ('wrong_infra','dirty_infra','ignored_infra','wrong_carrier'):
                def altered(root,*argv):
                    if bad=='wrong_infra' and root==infra and argv[0]=='rev-parse':return carrier
                    if bad=='dirty_infra' and root==infra and argv[0]=='status':return 'M SYNTHETIC'
                    if bad=='ignored_infra' and root==infra and argv[0]=='ls-files':return 'SYNTHETIC.so'
                    if bad=='wrong_carrier' and root==workflow:return 'c'*40
                    return read(root,*argv)
                with self.subTest(bad=bad),patch.object(native,'git_read',side_effect=altered),self.assertRaises(a.Denied):
                    native.checkout_roles(infra,application,workflow,expected,carrier)

    def test_preimport_gate_rejects_ignored_shadow_before_any_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()
            def git(*argv):return subprocess.check_output(['/usr/bin/git','-C',str(root),*argv],stderr=subprocess.DEVNULL)
            git('init','-q');(root/'.gitignore').write_text('*\n');(root/'tracked').write_bytes(b'SYNTHETIC')
            git('add','-f','.gitignore','tracked')
            git('-c','user.name=Synthetic','-c','user.email=synthetic@example.invalid','commit','-qm','fixture')
            head=git('rev-parse','HEAD').decode().strip()
            self.assertEqual(native.preimport_source(root,head),head)
            (root/'scripts').mkdir();(root/'scripts/tu1nz_public_runtime_artifact.so').write_bytes(b'NOT_EXECUTABLE')
            with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_WORKING_SET'):
                native.preimport_source(root,head)
            with self.assertRaisesRegex(RuntimeError,'SOURCE_SHA'):
                native.preimport_source(root,'0'*40)

    def test_native_manifest_includes_retained_legacy_writer_failure(self):
        from tests import public_operator_native as fixture
        self.assertEqual(tuple(fixture.SCENARIOS),tuple(native.native.CASES))
        self.assertEqual(len(fixture.SCENARIOS),28)
        self.assertEqual(native.native.FAULTS['r5_legacy_tamper'],
                         ['REAL_R5_LEGACY_WRITE_AFTER_REPLACEMENT'])

    def test_ci_workflow_carrier_cannot_be_reported_as_runtime_source(self):
        carrier='7'*40
        self.assertEqual(native.source_roles(*a.APP,carrier,carrier),dict(
            application_commit=a.APP[0],application_tree=a.APP[1],application_workflow_head=carrier))
        for head,tree,workflow,event in ((carrier,a.APP[1],carrier,carrier),
            (a.APP[0],'8'*40,carrier,carrier),(*a.APP,carrier,'9'*40)):
            with self.subTest(head=head,tree=tree,workflow=workflow),self.assertRaises(a.Denied):
                native.source_roles(head,tree,workflow,event)

    def test_native_tamper_fault_waits_for_actual_artifact_verified_record(self):
        from tests.public_operator_native import FaultWire
        class Peer:
            message=None
            def receive(self):return self.message
        peer=Peer();fault=FaultWire(peer,'r5_artifact_tamper',SimpleNamespace(pid=0))
        with tempfile.TemporaryDirectory() as d,patch.object(a,'ROOT',d+'/not-created'):
            peer.message={'type':'durable_record','record':{'kind':'host_action_intent',
                'value':{'action':'install_four_artifacts'}}}
            fault.receive();self.assertEqual(fault.injected,[])
            self.assertFalse(Path(a.ROOT).exists())
            binary=Path(a.ROOT)/'python/bin/python3.12';binary.parent.mkdir(parents=True)
            binary.write_bytes(b'SYNTHETIC_PINNED_INPUT')
            peer.message={'type':'durable_record','record':{'kind':'replacement_artifact_verified','value':{}}}
            fault.receive()
            self.assertEqual(fault.injected,['REAL_R5_ARTIFACT_WRITE_AFTER_FENCE'])
            self.assertEqual(binary.read_bytes(),b'SYNTHETIC_TAMPER')

    def test_read_witness_coordinates_do_not_adopt_legacy_origin(self):
        coordinates={'commit':'1'*40,'tree':'2'*40,'origin_sha256':'3'*64}
        old={'schema':'TU1NZ_PUBLIC_RUNTIME_REFERENCE_V1','objects':{},**coordinates}
        self.assertEqual(wire.application_coordinates(old),coordinates)
        new={'schema':'TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1',
            'origin_sha256':'4'*64,'artifact':{'application':{'commit':'5'*40,'tree':'6'*40}}}
        self.assertEqual(wire.application_coordinates(new),dict(commit='5'*40,tree='6'*40,
            origin_sha256='4'*64,binding_kind='PROSPECTIVE_REPLACEMENT_NOT_LEGACY_ORIGIN'))
        with self.assertRaises((wire.Hold,KeyError)):
            wire.application_coordinates({**new,'artifact':{'application':{'commit':'5'*40}}})

    def test_native_summary_cannot_substitute_wrong_artifact_or_host_acceptance(self):
        receipt={'archive_sha256':'1'*64,'objects':{'synthetic':{}}}
        proof=dict(schema='TU1NZ_PUBLIC_RUNTIME_ACTUAL_NATIVE_R5_V1',artifact_sha256='1'*64,
            receipt_sha256=a.sha(a.canonical(receipt)),source_manifest_sha256=a.SOURCE_MANIFEST,objects=1,
            units=[dict(unit_index=i,http_sha256='2'*64,same_first_invocation=True,
                kernel_groups_empty_caps_zero=True,actual_readonly_artifact_view=True) for i in range(3)],
            historical_sentinel_unchanged=True,host_acceptance=False,provider_actions=False,
            operator_owner_acceptance='SEPARATE_MANDATORY_NATIVE_GATE')
        self.assertEqual(native.validate_proof(a.canonical(proof),receipt),proof)
        for key,bad in [('artifact_sha256','3'*64),('host_acceptance',True),('provider_actions',True),
                        ('units',proof['units'][:2]),('source_manifest_sha256','4'*64)]:
            with self.subTest(key=key),self.assertRaises(a.Denied):
                native.validate_proof(a.canonical({**proof,key:bad}),receipt)

    def example(self):
        assembly=a.Assembly()
        assembly.add('python/bin/python3.12',raw=b'SYNTHETIC-NOT-EXECUTED',executable=True)
        assembly.add('python/bin/python3',target='python3.12')
        assembly.add('app/.venv/bin/python',target=a.ROOT+'/python/bin/python3.12')
        assembly.add('app/'+('long-name-'*14)+'/empty',raw=b'')
        raw=assembly.archive()
        return raw,{'archive_bytes':len(raw),'archive_sha256':a.sha(raw),
            'objects':assembly.manifest(),'expanded_file_bytes':assembly.total}

    def mutated(self, change):
        raw,receipt=self.example();out=io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw)),mode='r:') as old:
            with tarfile.open(fileobj=out,mode='w',format=tarfile.PAX_FORMAT) as new:
                for index,member in enumerate(old):
                    data=old.extractfile(member).read() if member.isfile() else None
                    change(index,member)
                    new.addfile(member,io.BytesIO(data) if data is not None else None)
        raw=gzip.compress(out.getvalue(),mtime=0)
        receipt.update(archive_bytes=len(raw),archive_sha256=a.sha(raw))
        return raw,receipt

    def test_offline_assembly_is_byte_reproducible(self):
        first,ref=self.example();second,other=self.example()
        self.assertEqual((first,ref),(second,other));a.inspect_archive(first,ref)

    def test_generated_long_path_and_exact_absolute_venv_link_pax_are_accepted(self):
        raw,ref=self.example();a.inspect_archive(raw,ref)
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:
            fields={k for m in t for k in m.pax_headers}
        self.assertEqual(fields,{'path','linkpath'})

    def test_no_path_escape_or_noncanonical_path(self):
        for name in ('/escape','a/../escape','a//b','a/./b','a\\b',''):
            with self.subTest(name=name),self.assertRaises(a.Denied):a.Assembly().add(name,raw=b'X')

    def test_only_exact_generated_absolute_links_are_allowed(self):
        for name,target in [('python/bin/python','/usr/bin/python3'),
                            ('app/.venv/bin/python','/usr/bin/python3'),
                            ('python/bin/python','../../../escape')]:
            with self.subTest(name=name),self.assertRaises(a.Denied):a.Assembly().add(name,target=target)

    def test_duplicate_file_is_not_overwritten(self):
        x=a.Assembly();x.add('app/test',raw=b'one')
        with self.assertRaises(a.Denied):x.add('app/test',raw=b'two')

    def test_parent_file_cannot_be_reused_as_a_directory(self):
        x=a.Assembly();x.add('app',raw=b'file')
        with self.assertRaises(a.Denied):x.add('app/child',raw=b'X')

    def test_archive_hash_and_size_must_match(self):
        raw,ref=self.example()
        for bad in (raw+b'X',raw[:-1],bytes([raw[0]^1])+raw[1:]):
            with self.subTest(size=len(bad)),self.assertRaises(a.Denied):a.inspect_archive(bad,ref)

    def test_current_hash_does_not_admit_different_member_bytes(self):
        raw,ref=self.example();bad=copy.deepcopy(ref)
        bad['objects']['python/bin/python3.12']['sha256']='0'*64
        with self.assertRaises(a.Denied):a.inspect_archive(raw,bad)

    def test_privileged_or_wrong_owner_mode_and_epoch_headers_deny(self):
        for field,value in [('uid',1001),('gid',33),('mode',0o6777),('mtime',a.EPOCH+1)]:
            def change(index,m):
                if index==0:setattr(m,field,value)
            raw,ref=self.mutated(change)
            with self.subTest(field=field),self.assertRaises(a.Denied):a.inspect_archive(raw,ref)

    def test_security_pax_metadata_is_not_ignored(self):
        def change(index,m):
            if index==0:m.pax_headers['SCHILY.xattr.security.capability']='FOREIGN'
        raw,ref=self.mutated(change)
        with self.assertRaises(a.Denied):a.inspect_archive(raw,ref)

    def test_foreign_members_and_link_retargeting_deny(self):
        for field,value in [('name','foreign'),('linkname','/etc/passwd')]:
            def change(index,m):
                if (field=='name' and index==0) or (field=='linkname' and m.issym()):setattr(m,field,value);m.pax_headers={}
            raw,ref=self.mutated(change)
            with self.subTest(field=field),self.assertRaises(a.Denied):a.inspect_archive(raw,ref)

    def test_archive_requires_every_bound_member(self):
        raw,ref=self.example();ref['objects']['app/not-present']={'kind':'file','mode':0o444,'sha256':'a'*64,'size':0}
        with self.assertRaises(a.Denied):a.inspect_archive(raw,ref)

    def test_duplicate_json_and_nonfinite_values_deny(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}'):
            with self.subTest(raw=raw),self.assertRaises(a.Denied):a.parse(raw)

    def test_input_lock_rejects_same_named_unapproved_source(self):
        inputs=json.loads((Path(__file__).resolve().parents[1]/'manifests/public-web-runtime-r5-inputs.json').read_bytes())
        self.assertEqual(a.sha(a.canonical(inputs)),a.INPUTS_SHA)
        inputs['python']['sha256']='0'*64
        with self.assertRaises(a.Denied):a.assemble({},b'',{},inputs)

    def test_canonical_source_cannot_be_replaced_by_a_new_scan(self):
        inputs=json.loads((Path(__file__).resolve().parents[1]/'manifests/public-web-runtime-r5-inputs.json').read_bytes())
        with self.assertRaises(a.Denied):a.assemble({'UNTRUSTED_CURRENT_COPY':b'X'},b'',{},inputs)


class BoundTransport(unittest.TestCase):
    def scope(self):
        artifact={'schema':'SYNTHETIC_UNIT_INPUT_NOT_HOST_ADMISSION'};digest=wire.sha(wire.canonical(artifact))
        baseline={'source_release':{'runtime_reference':{
            'schema':'TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1','artifact':artifact,'origin_sha256':digest}},
            'source_origin_receipts':[digest],'files':{}}
        fields={'schema','release_sha256','baseline_sha256','administrative_roles_sha256','baseline_origins_sha256',
                'r3_approval_sha256','machine_sha256','transaction','owner_plan_sha256'}
        scope={k:'UNIT' for k in fields};scope.update(schema='TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_R5_V1',
            runtime_artifact_sha256=digest,legacy_return=False)
        return scope,baseline

    def test_new_scope_binds_exact_artifact_and_prohibits_old_return(self):
        scope,b=self.scope();self.assertTrue(wire.replacement_scope(scope,b))
        for field,value in [('legacy_return',True),('runtime_artifact_sha256','b'*64),('extra','GREEN')]:
            bad={**scope,field:value}
            with self.subTest(field=field),self.assertRaises(wire.Hold):wire.replacement_scope(bad,b)

    def test_old_scope_never_authorizes_replacement(self):
        scope,b=self.scope();scope['schema']='TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_V1'
        del scope['runtime_artifact_sha256'];del scope['legacy_return']
        with self.assertRaises(wire.Hold):wire.replacement_scope(scope,b)

    def test_unknown_legacy_scan_cannot_become_a_baseline_origin(self):
        scope,b=self.scope()
        b['files']['/opt/tu1nz_repos/adult-publishing-core/.venv/bin/python']={'sha256':'CURRENT_IS_NOT_ORIGIN'}
        with self.assertRaises(wire.Hold):wire.replacement_scope(scope,b)

    def test_missing_or_changed_artifact_origin_denies(self):
        scope,b=self.scope();b['source_origin_receipts']=[]
        with self.assertRaises(wire.Hold):wire.replacement_scope(scope,b)
        scope,b=self.scope();b['source_release']['runtime_reference']['artifact']['changed']=True
        with self.assertRaises(wire.Hold):wire.replacement_scope(scope,b)

    def test_compression_preserves_exact_original_scope_bound_bytes(self):
        raw=b'{"exact-byte-layout": 1}\n'
        p={'scope':{'schema':'TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_R5_V1'},'baseline_encoding':'zlib_R5',
           'baseline_raw':base64.b64encode(zlib.compress(raw)).decode()}
        self.assertEqual(wire.baseline_bytes(p),raw)
        p['scope']['schema']='TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_V1'
        with self.assertRaises(wire.Hold):wire.baseline_bytes(p)

    def test_compressed_truncation_extra_stream_and_expansion_are_rejected(self):
        for raw in (zlib.compress(b'X')[:-1],zlib.compress(b'X')+b'EXTRA',zlib.compress(b'X'*(wire.MAX_FRAME+1))):
            p={'scope':{'schema':'TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_R5_V1'},'baseline_encoding':'zlib_R5',
               'baseline_raw':base64.b64encode(raw).decode()}
            with self.subTest(bytes=len(raw)),self.assertRaises(wire.Hold):wire.baseline_bytes(p)

    def test_unknown_encoding_and_duplicate_stream_do_not_fallback(self):
        for value in ('plain','gzip','zlib_R5_EXTRA'):
            with self.subTest(value=value),self.assertRaises(wire.Hold):wire.baseline_bytes({
                'baseline_raw':base64.b64encode(b'{}').decode(),'baseline_encoding':value})

    def test_chunk_sequence_size_and_exact_payload_are_bound(self):
        class Transport:
            def __init__(self):self.sent=[]
            def send(self,value):self.sent.append(value)
        transport=Transport();payload=b'X'*(512*1024)+b'LAST'
        sender=client.Client(transport,None,'UNIT',http_expectations=[],runtime_payload=payload)
        for index in (0,1):sender.send_runtime_chunk({'type':'runtime_chunk_request','index':index,'archive_sha256':wire.sha(payload)})
        self.assertEqual([len(base64.b64decode(v['data'])) for v in transport.sent],[512*1024,4])
        self.assertEqual(b''.join(base64.b64decode(v['data']) for v in transport.sent),payload)
        with self.assertRaises(wire.Hold):sender.send_runtime_chunk({'type':'runtime_chunk_request','index':2,'archive_sha256':wire.sha(payload)})
        with self.assertRaises(wire.Hold):sender.send_runtime_chunk({'type':'runtime_chunk_request','index':0,'archive_sha256':wire.sha(payload)})

    def test_lost_chunk_output_consumes_position_without_retry(self):
        class BrokenTransport:
            def send(self,value):raise BrokenPipeError()
        sender=client.Client(BrokenTransport(),None,'UNIT',http_expectations=[],runtime_payload=b'X')
        message={'type':'runtime_chunk_request','index':0,'archive_sha256':wire.sha(b'X')}
        with self.assertRaises(BrokenPipeError):sender.send_runtime_chunk(message)
        self.assertEqual(sender.runtime_next,1)
        with self.assertRaises(wire.Hold):sender.send_runtime_chunk(message)

    def test_wrong_or_boolean_chunk_number_and_no_payload_deny(self):
        sender=client.Client(None,None,'UNIT',http_expectations=[],runtime_payload=b'X')
        for message in ({'type':'runtime_chunk_request','index':True,'archive_sha256':wire.sha(b'X')},
                        {'type':'runtime_chunk_request','index':0,'archive_sha256':'f'*64},
                        {'type':'runtime_chunk_request','index':1,'archive_sha256':wire.sha(b'X')}):
            with self.subTest(message=message),self.assertRaises(wire.Hold):sender.send_runtime_chunk(message)
        sender=client.Client(None,None,'UNIT',http_expectations=[])
        with self.assertRaises(wire.Hold):sender.send_runtime_chunk({'type':'runtime_chunk_request','index':0,'archive_sha256':wire.sha(b'X')})


if __name__=='__main__':unittest.main()
