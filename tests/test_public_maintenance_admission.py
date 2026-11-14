"""Synthetic coverage-input and fresh-read tests; no real backup/Host access."""
import base64
import copy
from datetime import datetime,timezone
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator as client
io=client.io
import tu1nz_public_operator_admission as a
import tu1nz_mainserver_restore as model
import tu1nz_public_operator_observe as observe


def metadata():return {'uid':0,'gid':0,'mode':0o600,'attrs':{},'flags':0}
def encoded(value):return base64.b64encode(io.canonical(value)).decode()
def catalog():
    rows=[{'kind':'relation','table':n,'owner':'synthetic','relation_kind':'r','persistence':'p',
        'partition':False,'rls':False,'force_rls':False,'options':None,'tablespace_default':True} for n in a.TABLES]
    rows += [{'kind':'function','name':n,'owner':'synthetic','schema':'public','arguments':'','language':'plpgsql',
        'security_definer':False,'settings':None} for n in model.FUNCTIONS]
    return b'\n'.join(io.canonical(v) for v in rows)+b'\n'


class CoverageTests(unittest.TestCase):
    def fixture(self):
        now=time.time();files={};objects={}
        for index in range(88):
            name='.' if index==0 else 'synthetic-'+str(index)
            row={'sha256':'f'*64,'metadata':metadata()};objects[name]=row
            files[a.LIGHTING if name=='.' else a.LIGHTING+'/'+name]=copy.deepcopy(row)
        units={u:{'fragment':'/etc/systemd/system/'+u,'dropins':[]} for u in a.UNITS}
        units[a.UNITS[1]]['dropins']=['/etc/systemd/system/'+a.UNITS[1]+'.d/s9-growth.conf']
        immutable={p for row in units.values() for p in (row['fragment'],*row['dropins'])}|set(a.CONFIGS)
        for path in immutable|set(a.STATE):files[path]={'sha256':'e'*64,'metadata':metadata()}
        b={k:{} for k in ('policy_roots','source_release','http','database')}
        b.update(machine_sha256='a'*64,boot_id='SYNTHETIC_BOOT',unit_files=units,actors=[],broker_sockets=[],broker_tcp=[],
            nginx_groups=[33],source_origin_receipts=[],unit_search_sha256='a'*64,
            files={p:{'sha256':row['sha256'],**row['metadata'],'current_observation_sha256':'a'*64}
                   for p,row in files.items() if p in immutable})
        b['database']={'database':'synthetic'}
        b['source_release']={'runtime_reference':{'artifact':{'application':{'commit':'0'*40}}}}
        manifest=io.canonical(files);rights=b'{"kind":"runtime_role","inherit":false}\n';cat=catalog()
        db={'cleanup':[],'snapshot':{'snapshot_started_unix':now-50,'fingerprints':{n:{'rows':0} for n in a.TABLES}},
            'admission':model.compare_restore_catalog(cat,cat,rights,rights)}
        completion={'status':'PASS_REAL_DB_AND_FILE_RESTORES','db_result_sha256':io.sha(io.canonical(db)),
            'file_result_sha256':'d'*64,'actual_local_cleanup':[],'file_manifest_sha256':io.sha(manifest),
            'db_snapshot_started_unix':now-50}
        protection={'private_completion_sha256':io.sha(io.canonical(completion)),
            'private_DB_result_sha256':io.sha(io.canonical(db)),'private_file_result_sha256':'d'*64,
            'file_capture_finished_utc':datetime.fromtimestamp(now-100,timezone.utc).isoformat()}
        covered={'schema':'TU1NZ_REV4_CURRENT_PROTECTION_COVERAGE_V1','completion':encoded(completion),
            'database_result':encoded(db),'file_manifest':encoded(files),'source_catalog':base64.b64encode(cat).decode(),
            'source_rights':base64.b64encode(rights).decode()}
        assess={'schema':'TU1NZ_REV4_MUTABLE_COVERAGE_ASSESSMENT_V1','risk':a.RISK,
            'file_snapshot_unix':datetime.fromisoformat(protection['file_capture_finished_utc']).timestamp(),
            'db_snapshot_unix':now-50,'assessed_at_unix':now-1,'valid_until_unix':now+3600,
            'maximum_snapshot_age_seconds':4000,'changes':{},'evidence':{}}
        for name in (*a.TABLES,*a.STATE):
            row={'classification':'ASSESSED_MUTABLE_DATA_GAP','maximum_current_rows':100,
                'maximum_current_bytes':1024*1024}
            row['observed_at_unix']=now-2
            row['observed']={'rows':1,'json_bytes':50} if name in a.TABLES else {'bytes':20,'sha256':'e'*64}
            row['gap_assessment']=({'snapshot_unix':now-50,'observed_unix':now-2,'backup_rows':0,'additional_rows':1,
                'content_equality_proved':False} if name in a.TABLES else
                {'snapshot_unix':assess['file_snapshot_unix'],'observed_unix':now-2,'backup_sha256':'e'*64,'content_changed':False})
            row['gap_assessment'].update(remaining_exposure='Synthetic local validator test only; this is not an assessment of real data loss.',
                adequacy_reason='Synthetic local validator test only; this is not permission to stop any real service.')
            evidence={'schema':'TU1NZ_REV4_FINITE_CURRENT_WRITE_ASSESSMENT_V1','object':name,
                'classification':row['classification'],'writer_unit':a.UNITS[0] if name in a.TABLES else a.UNITS[1 if name==a.STATE[0] else 2],
                'target_application_commit':'0'*40,'immutable_inputs_sha256':io.sha(io.canonical({p:a.projection(b)['files'][p] for p in sorted(immutable)})),
                'backup_reference_sha256':protection['private_DB_result_sha256'] if name in a.TABLES else completion['file_manifest_sha256'],
                'observed_at_unix':row['observed_at_unix'],'observed':row['observed'],
                'gap_assessment_sha256':io.sha(io.canonical(row['gap_assessment'])),'historical_or_lossless_restore_claim':False}
            digest=io.sha(io.canonical(evidence));assess['evidence'][digest]=encoded(evidence)
            row['evidence_sha256']=digest;assess['changes'][name]=row
        covered['assessment']=assess
        packet={'baseline':b,'hashes':{'synthetic':'b'*64},'scope':{'runtime_artifact_sha256':'c'*64}}
        observation={'schema':'TU1NZ_REV4_CURRENT_OBSERVATION_V1','host_id':109772243,'boot_id':b['boot_id'],
            'source_sha256':io.sha(io.canonical(packet['hashes'])),'baseline_projection_sha256':io.sha(io.canonical(a.projection(b))),'coverage':covered}
        reads={'schema':'TU1NZ_REV4_FINITE_EXECUTION_READ_SCOPE_V1','host_id':109772243,'transaction':'public-rights-20261014-1',
            'units':list(a.UNITS),'files':sorted(b['files']),'state':list(a.STATE),'lighting_root':a.LIGHTING,'lighting_objects':88,
            'database':'synthetic','tables':list(a.TABLES),'runtime_artifact_sha256':'c'*64,'source_sha256':observation['source_sha256'],
            'functions':['existing_current_authority','existing_writer_and_platform_checks','existing_bound_runtime_and_file_reads',
                         's7_catalog_rights_and_counts','current_two_json_states','same_transaction_recovery_custody'],
            'historical_reader_or_claim_reuse':False,'production_data_restore':False}
        bound={'documents':{'current_observation':observation,'read_scope':reads},
            'restore_receipts':{'protection':protection},'plan':io.canonical({'capture':{'objects':objects}})}
        source=SimpleNamespace(load=lambda name:model if name=='restore' else None)
        return packet,source,bound

    def test_exact_closed_restore_links_admit_only_finite_current_coverage_not_a_host(self):
        packet,source,bound=self.fixture()
        with patch.object(os,'open') as opening:
            proof=a.validate(packet,source,bound,remaining_seconds=600)
        opening.assert_not_called();self.assertNotIn('host_admitted',proof)
        self.assertEqual(set(proof['assessment']['changes']),set(a.TABLES)|set(a.STATE))

    def test_changed_receipt_missing_dependency_or_circular_observation_is_not_admitted(self):
        for kind in ('receipt','lighting','config','readscope','source','closed_time','expiry','unexplained','lossless'):
            p,s,b=self.fixture();cover=b['documents']['current_observation']['coverage']
            if kind=='receipt':cover['completion']=encoded({'status':'PASS'})
            elif kind=='lighting':b['plan']=io.canonical({'capture':{'objects':{}}})
            elif kind=='config':p['baseline']['files'][a.CONFIGS[0]]['sha256']='0'*64
            elif kind=='readscope':b['documents']['read_scope']['production_data_restore']=True
            elif kind=='source':p['hashes']['synthetic']='0'*64
            elif kind=='closed_time':cover['assessment']['file_snapshot_unix']+=1
            elif kind=='expiry':cover['assessment']['valid_until_unix']=time.time()+599
            elif kind=='unexplained':cover['assessment']['changes'][a.TABLES[0]]['classification']='UNKNOWN'
            else:
                digest=next(iter(cover['assessment']['evidence']))
                cover['assessment']['evidence'][digest]=encoded({'historical_or_lossless_restore_claim':True})
            with self.subTest(kind=kind),self.assertRaises((io.Hold,model.Denied)):
                a.validate(p,s,b,remaining_seconds=600)

    def test_actual_database_metadata_types_rights_and_extent_are_checked(self):
        p,s,b=self.fixture();coverage=a.validate(p,s,b,remaining_seconds=600)
        lines=coverage['catalog'].decode().splitlines()+[a.CATALOG_END]+coverage['rights'].decode().splitlines()+[a.RIGHTS_END]
        stats=[io.canonical({'table':name,'rows':1,'json_bytes':50}).decode() for name in a.TABLES]
        proof=a.compare_database(coverage,lines+stats+[a.STATS_END])
        self.assertFalse(proof['data_equality_or_lossless_restore_claim'])
        for change in ('type','count','bytes','missing','rights'):
            changed=lines+stats+[a.STATS_END]
            if change=='type':changed[-3]=io.canonical({'table':a.TABLES[0],'rows':True,'json_bytes':50}).decode()
            elif change=='count':changed[-3]=io.canonical({'table':a.TABLES[0],'rows':101,'json_bytes':50}).decode()
            elif change=='bytes':changed[-3]=io.canonical({'table':a.TABLES[0],'rows':1,'json_bytes':2**30}).decode()
            elif change=='missing':changed.pop()
            else:changed[len(coverage['catalog'].splitlines())+1]='{"kind":"runtime_role","inherit":true}'
            with self.subTest(change=change),self.assertRaises((io.Hold,model.Denied)):
                a.compare_database(coverage,changed)

    def test_database_command_remains_same_readonly_identity_and_explicit_scope(self):
        p,s,b=self.fixture();coverage=a.validate(p,s,b,remaining_seconds=600)
        observer=observe.CurrentAuthority.__new__(observe.CurrentAuthority)
        observer.b={'database':{'database':'synthetic','role':'chatops'}};observer.deadline=time.monotonic()+20
        lines=coverage['catalog'].decode().splitlines()+[a.CATALOG_END]+coverage['rights'].decode().splitlines()+[a.RIGHTS_END]
        lines += [io.canonical({'table':n,'rows':1,'json_bytes':50}).decode() for n in a.TABLES]+[a.STATS_END]
        raw=b'chatops|synthetic|on|t|t\nf|f|f|f|f\nf|f\n0\n'+('\n'.join(lines)+'\n').encode()
        with patch.object(observe,'command',return_value=SimpleNamespace(returncode=0,stderr=b'',stdout=raw)) as command:
            proof=observer.database_readonly('postgresql://chatops:synthetic-secret@localhost/synthetic',
                require_other_connections_absent=True,coverage=coverage)
        self.assertIn('current_coverage',proof);self.assertNotIn('synthetic-secret',repr(proof))
        args,kwargs=command.call_args
        self.assertNotIn('synthetic-secret',repr(args));self.assertEqual(command.call_count,1)
        self.assertIn(b'BEGIN READ ONLY;',kwargs['data']);self.assertTrue(kwargs['data'].endswith(b'ROLLBACK;'))
        self.assertNotIn(b'COPY ',kwargs['data']);self.assertNotIn(b'pg_terminate_backend',kwargs['data'])
        self.assertNotIn(b'FROM pg_authid',kwargs['data'])

    def test_fresh_current_data_and_deadline_required_even_after_closed_restore(self):
        p,s,b=self.fixture();coverage=a.validate(p,s,b,remaining_seconds=600)
        authority=SimpleNamespace(deadline=time.monotonic()+20,check_files=Mock(),current_data_readonly=Mock(return_value={
            'database':{},'state':{name.rsplit('/',1)[1]:{'sha256':'e'*64,'metadata':{'st_size':20}} for name in a.STATE}}))
        proof=a.check_current(authority,coverage)
        self.assertTrue(proof['no_atomic_or_zero_rpo_claim']);authority.current_data_readonly.assert_called_once_with(coverage=coverage)
        coverage['assessment']['valid_until_unix']=time.time()+19
        with self.assertRaises(io.Hold):a.check_current(authority,coverage)
        self.assertEqual(authority.current_data_readonly.call_count,1)

if __name__=='__main__':unittest.main()
