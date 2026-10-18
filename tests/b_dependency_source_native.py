"""Explicit local private-source PostgreSQL17 proof; not public test discovery.

Uses an EXISTING isolated local PostgreSQL container created by the operator,
no production endpoint/credentials or network. Private pinned SQL enters stdin
only, never logs or public CI. Container and Source closure are bound in the
private handoff; successful tests are not real Host/restore admission.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest

SPEC=importlib.util.spec_from_file_location('b_dependency_recipe',Path(__file__).resolve().parents[1]/
                                         'scripts/tu1nz_b_dependency_schema.py')
d=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d)


class AuthenticDependencyRestore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.container=os.environ['TU1NZ_B_PG_CONTAINER']
        cls.source=Path(os.environ['TU1NZ_B_APP_SOURCE'])
        cls.docker=os.environ.get('TU1NZ_B_DOCKER','/usr/local/bin/docker')
        meta=json.loads(subprocess.check_output([cls.docker,'inspect',cls.container]))[0]
        assert meta['HostConfig']['NetworkMode']=='none' and meta['HostConfig']['ReadonlyRootfs']
        assert all(m['Type']=='tmpfs' and m['Destination'] in
                   ('/tmp','/var/run/postgresql','/var/lib/postgresql/data')
                   for m in meta.get('Mounts',[])), 'NO_BINDS_OR_HOST_DATA'
        assert meta['Config']['Labels'].get('tu1nz.test')=='b-s11-dependency-source-20261018'
        assert cls.sql('SHOW server_version_num;').stdout.strip()==b'170011'

    @classmethod
    def command(cls,tool,*args,input=None,check=True):
        p=subprocess.run([cls.docker,'exec','-i','--user','999:999',cls.container,tool,*args],
                         input=input,capture_output=True,timeout=40)
        if check and p.returncode:
            # No private SQL/error text in the test transcript.
            raise AssertionError(tool+' failed: '+d.b.sha(p.stderr))
        return p

    @classmethod
    def sql(cls,text,db='postgres',check=True):
        return cls.command('psql','-X','-qAt','--set=ON_ERROR_STOP=1','--username=b_admin',
                           '--dbname='+db,'--file=-',input=text.encode() if isinstance(text,str) else text,check=check)

    def setUp(self):
        for db in ('builder','restored','old_authority'):
            self.sql('DROP DATABASE IF EXISTS '+db+'; CREATE DATABASE '+db+';')
        sql,self.recipe=d.recipe(self.source,empty_builder=True)
        self.sql(sql,'builder')
        # Source-defined default is synthetic fixture data, not a reset on target.
        name=next(n for n in d.SOURCES if n.startswith('0031'))
        seed=b''.join(d.b.read_small(self.source/'migrations'/name).splitlines(keepends=True)[23:33])
        self.sql(seed,'builder')
        self.pre=self.command('pg_dump','-U','b_admin','-d','builder','--schema-only','--section=pre-data',
                              '--no-owner','--no-privileges').stdout
        self.post=self.command('pg_dump','-U','b_admin','-d','builder','--schema-only','--section=post-data',
                               '--no-owner','--no-privileges').stdout

    def dump(self):
        return self.command('pg_dump','-U','b_admin','-d','builder','--data-only','--format=custom',
                            '--no-owner','--no-privileges').stdout

    def restore(self):
        self.sql(self.pre,'restored')
        self.command('pg_restore','-U','b_admin','-d','restored','--data-only','--single-transaction',
                     '--exit-on-error','--no-owner','--no-privileges',input=self.dump())
        self.sql(self.post,'restored')

    def test_authentic_minimal_schema_roundtrip_and_no_activation_entry(self):
        self.restore()
        self.assertEqual(self.sql("SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace "
                                  "AND relkind='r';",'restored').stdout.strip(),b'34')
        self.assertEqual(self.sql('SELECT enabled,release_state FROM commercial_s11_runtime_control;',
                                  'restored').stdout.strip(),b'f|S11_DISABLED')
        self.assertEqual(self.sql("SELECT count(*) FROM pg_proc WHERE proname IN "
            "('tu1nz_s11_2_transition_runtime_control','tu1nz_s11_2_rearm_runtime_control');",'restored').stdout.strip(),b'0')
        self.assertEqual(self.sql("SELECT count(*) FROM pg_class WHERE relname IN "
            "('commercial_s11_experience_sessions','commercial_s11_product_events',"
            "'commercial_s11_canary_admission_counters','commercial_s11_canary_epoch_history');",'restored').stdout.strip(),b'0')
        denied=self.sql("UPDATE commercial_s11_runtime_control SET release_state='S11_CANARY';",'restored',check=False)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn(b'serialized transition entrypoint',denied.stderr)

    def test_runtime_cannot_write_dependency_or_bypass_security_definer_owner(self):
        self.restore()
        self.sql("DO $$BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='b_dep_guard') THEN "
                 "CREATE ROLE b_dep_guard NOLOGIN; END IF; "
                 "IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='b_dep_runtime') THEN "
                 "CREATE ROLE b_dep_runtime NOLOGIN; END IF; END$$;")
        self.sql('GRANT USAGE ON SCHEMA public TO b_dep_guard;'
                 'GRANT SELECT ON commercial_s11_runtime_control,commercial_s10_2d_runtime_control TO b_dep_guard;'
                 'GRANT UPDATE(singleton) ON commercial_s11_runtime_control,commercial_s10_2d_runtime_control TO b_dep_guard;'
                 'GRANT USAGE ON SCHEMA public TO b_dep_runtime;'
                 'REVOKE CREATE ON SCHEMA public FROM PUBLIC;'
                 'GRANT SELECT ON commercial_s11_runtime_control TO b_dep_runtime;'
                 'GRANT UPDATE ON commercial_s10_2d_runtime_control TO b_dep_runtime;'
                 'ALTER FUNCTION tu1nz_s11_2_guard_runtime_release_binding() OWNER TO b_dep_guard;'
                 'ALTER FUNCTION tu1nz_s11_2_guard_canary_latency_insert() OWNER TO b_dep_guard;'
                 'REVOKE ALL ON commercial_s11_runtime_control FROM PUBLIC;', 'restored')
        self.assertEqual(self.sql("SELECT count(*) FROM pg_proc p JOIN pg_roles r ON p.proowner=r.oid "
            "WHERE p.proname IN('tu1nz_s11_2_guard_runtime_release_binding','tu1nz_s11_2_guard_canary_latency_insert') "
            "AND p.prosecdef AND NOT r.rolsuper AND NOT r.rolcanlogin "
            "AND p.proconfig=ARRAY['search_path=pg_catalog'];",'restored').stdout.strip(),b'2')
        denied=self.sql('SET ROLE b_dep_guard; UPDATE commercial_s11_runtime_control SET updated_at=clock_timestamp();',
                        'restored',check=False)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn(b'permission denied',denied.stderr)
        denied=self.sql('SET ROLE b_dep_runtime; UPDATE commercial_s11_runtime_control SET enabled=true;',
                        'restored',check=False)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn(b'permission denied',denied.stderr)
        # FOR KEY SHARE needs an UPDATE privilege even though the bound guard
        # only reads. Dedicated NOLOGIN owner gets singleton-column permission,
        # not UPDATE of enablement/release fields and no membership for runtime.
        self.sql("SET ROLE b_dep_runtime; UPDATE commercial_s10_2d_runtime_control SET target_release_id='s10-2d-r999';",
                 'restored')

    def test_missing_dependency_is_detected_not_empty_success(self):
        self.restore()
        # Rename only our synthetic restored object, preserving trigger bodies.
        self.sql('ALTER TABLE commercial_s11_runtime_control RENAME TO missing_dependency;','restored')
        denied=self.sql("UPDATE commercial_s10_2d_runtime_control SET target_release_id='s10-2d-r999';",
                        'restored',check=False)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn(b'does not exist',denied.stderr)

    def test_both_actual_s10_guards_preserve_canary_binding(self):
        # Synthetic source state only, no S11 process/provider/start entrypoint.
        release=self.sql('SELECT target_release_id FROM commercial_s10_2d_runtime_control;',
                         'builder').stdout.decode().strip()
        self.assertRegex(release,r'^s10-2d-r[0-9]+(-[0-9]+)?$')
        self.sql("SELECT set_config('tu1nz.s11_transition_barrier','held',false);"
                 "UPDATE commercial_s11_runtime_control SET enabled=true,"
                 "release_state='S11_CANARY',promotion_state='CANARY_COLLECTING_EVIDENCE',"
                 "canary_release_id='"+release+"',canary_evidence_start='2026-10-01T00:00:00Z',"
                 "canary_live_start='2026-10-01T00:00:00Z',live_start='2026-10-01T00:00:00Z',"
                 "canary_horizon_at='2026-10-02T00:00:00Z';",'builder')
        self.restore()
        denied=self.sql("UPDATE commercial_s10_2d_runtime_control SET target_release_id='s10-2d-r999';",
                        'restored',check=False)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn(b'active canary release binding is immutable',denied.stderr)
        insert=("INSERT INTO commercial_s10_2d_latency_samples "
                "(sample_id,source,bot_response_latency_ms,poll_lag_ms,handler_duration_ms,send_ack_ms,"
                "occurred_at,release_id,run_id,evidence_class,cutover_started_at,sample_type,interaction_path) "
                "VALUES('00000000-0000-0000-0000-000000000001','DIRECT',1,1,1,1,"
                "'2026-10-01T01:00:00Z','"+release+"','00000000-0000-0000-0000-000000000002',"
                "'REAL','2026-10-01T00:00:00Z','S11_CANARY_RESPONSE','TELEGRAM_DIRECT');")
        self.sql(insert,'restored')
        denied=self.sql(insert.replace('2026-10-01T01:00:00Z','2026-10-03T01:00:00Z').replace(
            '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003'),
            'restored',check=False)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn(b'canary latency insert is not bound',denied.stderr)

    def test_retained_incoming_fk_remains_at_old_authority(self):
        # Synthetic FK boundary, not copied private session/business data.
        self.sql('CREATE TABLE commercial_s8_users(subject_id uuid PRIMARY KEY);'
                 'CREATE TABLE commercial_s11_experience_sessions(subject_id uuid PRIMARY KEY '
                 'REFERENCES commercial_s8_users(subject_id) ON DELETE CASCADE);','old_authority')
        denied=self.sql("INSERT INTO commercial_s11_experience_sessions VALUES('00000000-0000-0000-0000-000000000001');",
                        'old_authority',check=False)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn(b'foreign key constraint',denied.stderr)
        self.restore()
        self.assertEqual(self.sql("SELECT to_regclass('public.commercial_s11_experience_sessions') IS NULL;",
                                  'restored').stdout.strip(),b't')


if __name__=='__main__':unittest.main()
