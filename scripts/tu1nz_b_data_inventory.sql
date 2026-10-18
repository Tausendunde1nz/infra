-- B bounded metadata intake; no business rows, passwords, query text or hba options.
-- psql -X --set=ON_ERROR_STOP=1 --dbname=service=tu1nz_b_export -f THIS_FILE
-- Current observation only. No origin, export, writer fence or Host admission.
\set ON_ERROR_STOP on
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '3s';
SELECT current_database() AS database, current_user AS reader,
       current_setting('server_version_num') AS server_version_num,
       current_setting('server_encoding') AS server_encoding,
       (SELECT datcollate FROM pg_database WHERE datname=current_database()) AS lc_collate,
       (SELECT datctype FROM pg_database WHERE datname=current_database()) AS lc_ctype;

-- Exact names are classified against the Source catalogue locally. Unknown
-- family relations/partitions/sequences are HOLD, not implicit export scope.
SELECT n.nspname, c.relname, c.relkind, c.relowner::regrole AS owner,
       c.relpersistence, c.relrowsecurity, c.relforcerowsecurity, c.relispartition,
       c.relacl, pg_total_relation_size(c.oid) AS bytes
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relname ~ '^commercial_s(7_|8_|9_|10_)'
  AND c.relkind IN ('r','p','S','v','m','f') ORDER BY 1,2;

SELECT c.conname, c.contype, c.conrelid::regclass AS relation,
       c.confrelid::regclass AS referenced_relation, c.convalidated,
       pg_get_constraintdef(c.oid, true) AS definition
FROM pg_constraint c
WHERE c.conrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace
                    AND relname ~ '^commercial_s(7_|8_|9_|10_)')
   OR c.confrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace
                     AND relname ~ '^commercial_s(7_|8_|9_|10_)') ORDER BY 3,1;

SELECT i.inhrelid::regclass AS child, i.inhparent::regclass AS parent
FROM pg_inherits i
WHERE i.inhrelid IN (SELECT oid FROM pg_class WHERE relname ~ '^commercial_s(7_|8_|9_|10_)')
   OR i.inhparent IN (SELECT oid FROM pg_class WHERE relname ~ '^commercial_s(7_|8_|9_|10_)');

SELECT t.tgrelid::regclass AS relation, t.tgname, t.tgenabled, p.oid::regprocedure AS function,
       p.proowner::regrole AS function_owner, p.prosecdef AS security_definer
FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
WHERE t.tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace
                   AND relname ~ '^commercial_s(7_|8_|9_|10_)') ORDER BY 1,2;

SELECT r.rolname, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication,
       r.rolbypassrls, r.rolcanlogin, c.oid::regclass AS relation,
       has_table_privilege(r.oid,c.oid,'SELECT') AS can_read,
       (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
        OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')) AS can_change
FROM pg_roles r CROSS JOIN pg_class c
WHERE c.relnamespace='public'::regnamespace AND c.relname ~ '^commercial_s(7_|8_|9_|10_)'
  AND c.relkind IN ('r','p')
  AND (r.rolsuper OR r.rolcreaterole OR r.oid=c.relowner
       OR has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES'))
ORDER BY 1,8;

SELECT member::regrole AS member, roleid::regrole AS role, admin_option
FROM pg_auth_members ORDER BY roleid, member;
-- The bounded role-membership graph is necessary to trace indirect SET ROLE /
-- administrative authority. No passwords and no data from other databases.
SELECT nspname, nspowner::regrole AS owner, nspacl FROM pg_namespace WHERE nspname='public';
SELECT defaclrole::regrole AS role, defaclnamespace::regnamespace AS namespace,
       defaclobjtype, defaclacl FROM pg_default_acl
WHERE defaclnamespace=0 OR defaclnamespace='public'::regnamespace;

-- No app/client address or query bodies: this is not an activity audit.
SELECT pid, usename, backend_type, state, xact_start, backend_xid IS NOT NULL AS has_xid
FROM pg_stat_activity WHERE datname=current_database() ORDER BY pid;
SELECT count(*) AS prepared_transactions FROM pg_prepared_xacts WHERE database=current_database();
COMMIT;
