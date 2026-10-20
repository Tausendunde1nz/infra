"""One fixed capture engine with 34 SYNTHETIC tables, owned Unix-only PG.
No real DSN, transport, production rows or approval; retain evidence No-Delete.
"""
from copy import deepcopy
import json,os
from pathlib import Path
import subprocess,sys,tempfile,time,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_b_precopy_once as c

class Native(unittest.TestCase):
    def test_full_same_snapshot_capture_two_copies_and_fresh_verification(self):
        self.assertNotEqual(os.geteuid(),0,'unprivileged fixture required')
        root=Path(tempfile.mkdtemp(prefix='b-once-pg-',dir='/tmp')).resolve()
        bindir=Path(os.environ['TU1NZ_B_PG_BIN']);base=bindir.parent
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','PGHOST':str(root),'PGPORT':'6545','PGUSER':'b_admin','PGDATABASE':'postgres'}
        def run(tool,*argv,sql=None):
            p=subprocess.run([str(bindir/tool),*argv],input=sql,capture_output=True,env=env,timeout=30)
            self.assertEqual(p.returncode,0,'synthetic '+tool+' failed: '+p.stderr.decode());return p.stdout
        def sql(text,db='postgres'):return run('psql','-X','-qAt','-v','ON_ERROR_STOP=1','-d',db,sql=text.encode())
        run('initdb','-D',str(root/'cluster'),'--username=b_admin','--auth-local=trust','--auth-host=reject','--no-locale','--encoding=UTF8')
        run('pg_ctl','-D',str(root/'cluster'),'-l',str(root/'server.log'),'-o',"-k "+str(root)+" -p 6545 -c listen_addresses=''",'-w','start')
        try:
            sql('CREATE ROLE '+c.m.ROLE+' LOGIN;')
            sql('CREATE DATABASE '+c.m.DATABASE+';')
            names=sorted(json.loads(c.b.CATALOG.read_bytes())['tables'])
            sql(''.join('CREATE TABLE '+n+'(id int PRIMARY KEY,value text); INSERT INTO '+n+" VALUES(1,'SYNTHETIC'); GRANT SELECT ON "+n+' TO '+c.m.ROLE+';' for n in names),c.m.DATABASE)
            service=root/'service.conf';service.write_text('[tu1nz_b_export]\nhost='+str(root)+'\nport=6545\nuser='+c.m.ROLE+'\ndbname='+c.m.DATABASE+'\n');service.chmod(0o600)
            env.update(PGSERVICEFILE=str(service),PGOPTIONS='-c default_transaction_read_only=on -c search_path=pg_catalog')
            targets=(root/'a',root/'b')
            for t in targets:t.mkdir(mode=0o700)
            at=c.Attempt(root/'attempt',time.monotonic()+60,targets)
            try:
                query=c.m.metadata_sql(c.b.CATALOG.read_bytes()).decode().replace('COMMIT;\n',c.catalog_sql().decode()+'COMMIT;\n')
                reference=[json.loads(l) for l in run('psql','-X','-qAt','-v','ON_ERROR_STOP=1','-d','service=tu1nz_b_export',sql=query.encode()).splitlines()]
                def fixture_validator(rows,catalog):
                    # Substitute only synthetic Unix connection identity, never CLI.
                    ident=next(r for r in rows if r['kind']=='identity')
                    self.assertEqual((ident['database'],ident['role'],ident['address'],ident['port'],ident['ssl']),(c.m.DATABASE,c.m.ROLE,None,None,False))
                    fixed=deepcopy(rows);i=next(r for r in fixed if r['kind']=='identity')
                    i.update(version='170011',address='127.0.0.1',port=5432,ssl=True,postmaster_start='2026-08-27T19:59:20.500309+00:00')
                    c.m.validate_observation(fixed,catalog)
                cat=json.loads(c.b.CATALOG.read_bytes())
                selection=dict(schema='TU1NZ_B_DATA_SELECTION_V2',source_app=cat['source_app'],database=c.m.DATABASE,host_inventory_sha256='1'*64,relations=[dict(name=n,disposition='export') for n in names],retained_dependencies={n:'retain_old' for n in cat['retained_dependency_relations']},file_dispositions={n:'retain_old' for n in cat['fixed_files']},files=[])
                sr=(json.dumps(selection)+'\n').encode();selected=c.b.selection(sr,cat)
                artifacts,observed=c.capture(at,base,env,names,reference,selected,c.m.sha(sr),validate=fixture_validator)
                self.assertEqual(len(observed['fingerprints']),34)
                self.assertTrue(all(r['count']==1 for r in observed['fingerprints'].values()))
                c.duplicate(at,artifacts)
                manifest=dict(schema='TU1NZ_B_DATA_PACKAGE_V1',phase='precopy',selection_sha256=c.m.sha(sr),capture_receipt_sha256='1'*64,artifacts=artifacts)
                mr=json.dumps(manifest).encode()
                for target in targets:
                    self.assertEqual(c.b.verify_package(target,mr,c.m.sha(mr),selected,c.m.sha(sr))['status'],'BYTES_CHECKED_NOT_ADMITTED')
                # No second capture: negative validation before data, same engine only.
                with self.assertRaisesRegex(c.m.Denied,'PREFLIGHT_SCHEMA_OR_RIGHTS_DRIFT'):
                    c.capture(at,base,env,names,reference+[{"kind":"function_meta","definition_sha256":"changed"}],selected,c.m.sha(sr),validate=fixture_validator)
            finally:at.close()
        finally:run('pg_ctl','-D',str(root/'cluster'),'-m','fast','-w','stop')
        print('SYNTHETIC_EVIDENCE_RETAINED='+str(root))
if __name__=='__main__':unittest.main()
