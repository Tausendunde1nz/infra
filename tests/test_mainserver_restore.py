"""Bounded two-table restore tests; no production credentials or Host access."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('mainserver_restore',ROOT/'scripts/tu1nz_mainserver_restore.py')
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class DumpBoundary(unittest.TestCase):
    def setUp(self):
        self.layout = {n:('id','payload') for n in m.TABLES}

    def render(self, data=b'1\tSYNTHETIC\n', extra=b''):
        return (b'-- PostgreSQL database dump\n\n\\restrict SYNTHETIC123\n'
                b"SET client_encoding = 'UTF8';\nSET row_security = off;\n"+extra+
                b'COPY public.commercial_s7_analytics_events (id, payload) FROM stdin;\n'+data+b'\\.\n\n'+
                b'COPY public.commercial_s7_waitlist (id, payload) FROM stdin;\n'+data+b'\\.\n'+
                b'\\unrestrict SYNTHETIC123\n-- PostgreSQL database dump complete\n')

    def test_exact_data_only_blocks_order_does_not_grant_sql(self):
        data = b'1\t\\N\n2\t\\\\!not-a-command\\nnext\n'
        result = m.extract_copy_data(self.render(data),self.layout)
        self.assertEqual(set(result),set(m.TABLES))
        for row in result.values():self.assertEqual(row,{'data':data,'rows':2})

    def test_real_empty_table_block_is_retained(self):
        result = m.extract_copy_data(self.render(b''),self.layout)
        self.assertTrue(all(row == {'data':b'','rows':0} for row in result.values()))

    def test_any_executable_archive_sql_is_rejected(self):
        for sql in (b'COPY public.commercial_s7_waitlist TO PROGRAM \'evil\';\n',
                    b"SELECT pg_catalog.set_config('session_preload_libraries','evil',false);\n",
                    b'CREATE FUNCTION x() RETURNS void LANGUAGE c AS \'evil\';\n',
                    b'\\! evil\n',b'SET session_replication_role = replica;\n',
                    b"SET search_path = untrusted;\n",b'ALTER TABLE x DISABLE TRIGGER ALL;\n'):
            with self.subTest(sql=sql),self.assertRaises(m.Denied):
                m.extract_copy_data(self.render(extra=sql),self.layout)

    def test_host_cannot_select_a_different_table_columns_or_source(self):
        good = self.render()
        for old,new in ((b'public.commercial_s7_waitlist',b'other.commercial_s7_waitlist'),
                        (b'(id, payload)',b'(id, payload, extra)'),(b'FROM stdin;',b"FROM '/etc/passwd';")):
            with self.assertRaises(m.Denied):m.extract_copy_data(good.replace(old,new),self.layout)

    def test_partial_duplicate_or_out_of_order_wrappers_deny(self):
        good = self.render()
        bad = (good[:-10],good.replace(b'\\.\n',b'',1),good.replace(b'\\unrestrict SYNTHETIC123',b'\\unrestrict wrong'),
               good+b'\\unrestrict SYNTHETIC123\n',good.replace(b'commercial_s7_analytics_events',b'commercial_s7_waitlist'),
               good+b'COPY public.commercial_s7_waitlist (id, payload) FROM stdin;\n\\.\n')
        for raw in bad:
            with self.subTest(raw=raw[-80:]),self.assertRaises(m.Denied):m.extract_copy_data(raw,self.layout)

    def test_early_copy_terminator_does_not_execute_following_payload(self):
        with self.assertRaises(m.Denied):m.extract_copy_data(self.render(b'\\.\n\\! malicious\n'),self.layout)

    def test_unrestricted_old_pg_output_allowed_without_adding_commands(self):
        raw = self.render().replace(b'\\restrict SYNTHETIC123\n',b'').replace(b'\\unrestrict SYNTHETIC123\n',b'')
        self.assertEqual(len(m.extract_copy_data(raw,self.layout)),2)


class CatalogBoundary(unittest.TestCase):
    def rows(self):
        rows = [dict(kind='relation',table=n,relation_kind='r',persistence='p',partition=False,rls=False,
                     force_rls=False,replica_identity='d',options=None,tablespace_default=True,owner='postgres',acl=None)
                for n in m.TABLES]
        rows += [dict(kind='function',name=n,schema='public',arguments='',language='plpgsql',security_definer=False,
                      settings=None,owner='postgres',acl=None,definition_sha256='1'*64) for n in m.FUNCTIONS]
        rows += [dict(kind='column',table=n,position=1,name='id',type='uuid',type_schema='pg_catalog',type_kind='b',
                      not_null=True,generated='',identity='',collation=None,acl=None,default_sha256=None) for n in m.TABLES]
        return rows

    def raw(self,rows):return b'\n'.join(m.canonical(r) for r in rows)+b'\n'

    def test_finite_catalog_query_has_no_business_row_or_ddl_statement(self):
        sql = m.catalog_transaction().decode()
        self.assertIn('REPEATABLE READ READ ONLY',sql)
        self.assertIn('SET LOCAL search_path=pg_catalog',sql)
        self.assertIn("d.deptype IN('a','i')",sql)
        self.assertNotIn('FROM public.',sql)
        self.assertNotIn('CREATE ',sql)
        self.assertNotIn('pg_authid',sql)

    def test_current_authority_is_preserved_outside_structural_comparison(self):
        rows = self.rows();original = copy.deepcopy(rows)
        normalized = m.structural_catalog(self.raw(rows))
        self.assertEqual(rows,original)
        self.assertTrue(all('acl' not in r and 'owner' not in r for r in normalized))
        rows[0]['owner'] = 'UNTRUSTED_NEW_OWNER'
        self.assertEqual(normalized,m.structural_catalog(self.raw(rows)))
        # This equality deliberately is NOT a rights/Owner/V3 acceptance.

    def test_missing_duplicate_unsupported_relations_are_not_silently_ignored(self):
        for rows in (self.rows()[1:],self.rows()+[self.rows()[0]],self.rows()+[dict(kind='sequence',table=m.TABLES[0])]):
            with self.assertRaises(m.Denied):m.structural_catalog(self.raw(rows))

    def test_rls_custom_types_defaults_definer_and_unvalidated_constraints_deny(self):
        for index,key,value in ((0,'rls',True),(0,'partition',True),(0,'options',['user_catalog_table=true']),
                                (2,'security_definer',True),(2,'settings',['search_path=evil']),
                                (4,'type_schema','untrusted'),(4,'default_sha256','f'*64),(4,'identity','a')):
            rows = self.rows();rows[index][key] = value
            with self.subTest(key=key),self.assertRaises(m.Denied):m.structural_catalog(self.raw(rows))
        rows = self.rows()+[dict(kind='constraint',validated=False)]
        with self.assertRaises(m.Denied):m.structural_catalog(self.raw(rows))

    def test_layout_comes_from_trusted_catalog_and_cannot_inject_identifier(self):
        rows = m.structural_catalog(self.raw(self.rows()))
        self.assertEqual(m.copy_layout(rows),{n:('id',) for n in m.TABLES})
        next(r for r in rows if r['kind'] == 'column')['name'] = 'id); evil'
        with self.assertRaises(m.Denied):m.copy_layout(rows)

    def test_structural_match_cannot_hide_changed_owner_or_effective_rights(self):
        original = self.raw(self.rows())
        rights = b'{"kind":"table_rights","table":"synthetic","select":true}\n'
        proof = m.compare_restore_catalog(original,original,rights,rights)
        self.assertTrue(proof['not_production_restore_permission'])
        changed = self.rows();changed[0]['owner'] = 'foreign'
        with self.assertRaises(m.Denied):m.compare_restore_catalog(self.raw(changed),original,rights,rights)
        with self.assertRaises(m.Denied):m.compare_restore_catalog(original,original,rights.replace(b'true',b'false'),rights)
        with self.assertRaises(m.Denied):m.compare_restore_catalog(original,original,rights+rights,rights)

    def test_readonly_rights_catalog_includes_schema_and_actual_effective_privileges(self):
        sql = m.rights_transaction().decode()
        for term in ('BEGIN READ ONLY','has_schema_privilege','has_table_privilege','has_column_privilege',
                     'aclexplode','pg_has_role','rolsuper','rolbypassrls'):
            self.assertIn(term,sql)
        self.assertNotIn('rolpassword',sql)
        self.assertNotIn('pg_authid',sql)

    def test_constraint_negative_requires_exact_sqlstate_not_connection_failure(self):
        pg = m.PrivatePostgres.__new__(m.PrivatePostgres)
        pg.call = Mock(return_value=(3,b'',b'psql:<stdin>:1: ERROR:  23503\n'))
        self.assertEqual(pg.query(b'SYNTHETIC',expect_error='23503'),b'')
        for result in ((2,b'',b'connection failed\n'),(3,b'',b'psql:<stdin>:1: ERROR:  42501\n'),
                       (0,b'',b''),(3,b'',b'psql:<stdin>:1: ERROR:  23503\nextra\n')):
            pg.call.return_value = result
            with self.assertRaises(m.Denied):pg.query(b'SYNTHETIC',expect_error='23503')
        with self.assertRaises(m.Denied):pg.query(b'SYNTHETIC',expect_error=True)


class PrivateCustody(unittest.TestCase):
    def test_create_readback_and_no_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve()/'proof.json';m.private_create(path,b'{"synthetic":true}\n')
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):m.private_create(path,b'changed\n')
            alias = path.parent/'alias';alias.symlink_to(path)
            with self.assertRaises(m.Denied):m.private_read(alias,1024)
            os.chmod(path,0o644)
            with self.assertRaises(m.Denied):m.private_read(path,1024)

    def test_hardlink_or_too_large_input_not_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve()/'input';m.private_create(path,b'x'*100)
            with self.assertRaises(m.Denied):m.private_read(path,99)
            os.link(path,path.parent/'alias')
            with self.assertRaises(m.Denied):m.private_read(path,100)

    def test_process_output_is_bounded_without_emitting_child_data(self):
        with self.assertRaisesRegex(m.Denied,'PROCESS_OUTPUT_BOUND'):
            m.bounded_process([sys.executable,'-I','-c','print("SYNTHETIC"*1024)'],env={},
                              deadline=time.monotonic()+5,limit=32)

    def test_full_duplex_input_and_output_do_not_deadlock(self):
        data = b'x'*131072
        code,out,err = m.bounded_process([sys.executable,'-I','-c',
            'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.stderr.write("test")'],
            env={},deadline=time.monotonic()+5,data=data,limit=len(data))
        self.assertEqual((code,out,err),(0,data,b'test'))


import sys
if __name__ == '__main__':unittest.main()
