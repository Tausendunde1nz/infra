"""Finite Rev4 current-coverage admission; no acquisition or effects at import.

Closed real restores remain immutable. This does not attest a historical gap
or promise zero RPO: current mutable-data exposure needs a concrete separately
reviewed bounded assessment, while live Authority/Writer gates remain required.
"""
import base64
import math
import time
from datetime import datetime
import tu1nz_public_operator_io as io

UNITS = ('tu1nz-adult-public-s7.service', 'tu1nz-adult-public-s8-landing.service',
         'tu1nz-adult-public-s10-wms.service')
CONFIGS = tuple('/etc/tu1nz/'+n for n in (
    'adult-commercial-s7-public.json','adult-commercial-s7-form.secret','adult-commercial-s7-database.dsn',
    'adult-commercial-s8-landing.json','adult-commercial-s10-wms.json','adult-commercial-s10-wms-copy.json',
    'adult-commercial-s10-wms-bot-identity.json','adult-commercial-s10-2d-community.json'))
STATE = ('/var/lib/tu1nz-adult-public-s9/landing-aggregates.json',
         '/var/lib/tu1nz-adult-public-s9/wms-traffic-quality.json')
TABLES = ('commercial_s7_waitlist','commercial_s7_analytics_events')
LIGHTING = '/var/www/lighting.tu1nz.com'
RISK = 'REV4_BOUNDED_CURRENT_COVERAGE_NOT_ATOMIC_ZERO_RPO_OR_HISTORICAL_INTEGRITY'


def projection(baseline):
    # Exclude ONLY the observation's own digest to avoid a self-hash cycle.
    fields = ('machine_sha256','boot_id','unit_files','actors','policy_roots','broker_sockets',
              'broker_tcp','source_release','http','database','nginx_groups','source_origin_receipts',
              'unit_search_sha256')
    return {**{k:baseline[k] for k in fields}, 'files':{
        p:{k:v for k,v in row.items() if k != 'current_observation_sha256'}
        for p,row in baseline['files'].items()}}


def decoded(value, expected, code):
    io.require(type(value) is str and 0 < len(value) <= 768*1024, code)
    raw = base64.b64decode(value,validate=True)
    io.require(io.sha(raw) == expected, code)
    return io.parse(raw),raw


def validate(packet, source, bound, *, remaining_seconds):
    b = packet['baseline']; docs = bound['documents']; o = docs['current_observation']; r = docs['read_scope']
    io.require(type(o) is dict and set(o) == {'schema','host_id','boot_id','source_sha256','baseline_projection_sha256','coverage'} and
        o['schema'] == 'TU1NZ_REV4_CURRENT_OBSERVATION_V1' and o['host_id'] == 109772243 and
        o['boot_id'] == b['boot_id'] and o['source_sha256'] == io.sha(io.canonical(packet['hashes'])) and
        o['baseline_projection_sha256'] == io.sha(io.canonical(projection(b))), 'MAINTENANCE_CURRENT_OBSERVATION_CONTENT')
    paths = sorted(b['files'])
    expected_scope = {'schema':'TU1NZ_REV4_FINITE_EXECUTION_READ_SCOPE_V1',
        'host_id':109772243,'transaction':'public-rights-20261014-1','units':list(UNITS),
        'files':paths,'state':list(STATE),'lighting_root':LIGHTING,'lighting_objects':88,
        'database':b['database']['database'],'tables':list(TABLES),
        'runtime_artifact_sha256':packet['scope']['runtime_artifact_sha256'],
        'source_sha256':o['source_sha256'],
        'functions':['existing_current_authority','existing_writer_and_platform_checks',
                     'existing_bound_runtime_and_file_reads','s7_catalog_rights_and_counts',
                     'current_two_json_states','same_transaction_recovery_custody'],
        'historical_reader_or_claim_reuse':False,'production_data_restore':False}
    io.require(r == expected_scope and set(b['unit_files']) == set(UNITS), 'MAINTENANCE_READ_SCOPE_CONTENT')
    coverage = o['coverage']
    io.require(type(coverage) is dict and set(coverage) == {'schema','completion','database_result',
        'file_manifest','source_catalog','source_rights','assessment'} and
        coverage['schema'] == 'TU1NZ_REV4_CURRENT_PROTECTION_COVERAGE_V1', 'MAINTENANCE_COVERAGE_SCHEMA')
    closed = bound['restore_receipts']; protection = closed['protection']
    completion,_ = decoded(coverage['completion'],protection['private_completion_sha256'],'MAINTENANCE_CLOSED_COMPLETION')
    db,_ = decoded(coverage['database_result'],protection['private_DB_result_sha256'],'MAINTENANCE_CLOSED_DATABASE')
    files,_ = decoded(coverage['file_manifest'],completion['file_manifest_sha256'],'MAINTENANCE_CLOSED_FILE_MANIFEST')
    io.require(completion['status'] == 'PASS_REAL_DB_AND_FILE_RESTORES' and
        completion['db_result_sha256'] == protection['private_DB_result_sha256'] and
        completion['file_result_sha256'] == protection['private_file_result_sha256'] and
        completion['actual_local_cleanup'] == [] and db['cleanup'] == [], 'MAINTENANCE_CLOSED_PROTECTION_LINKS')
    # The catalog/rights are JSONL technical metadata, not a data dump or SQL.
    catalog_raw = base64.b64decode(coverage['source_catalog'],validate=True)
    rights_raw = base64.b64decode(coverage['source_rights'],validate=True)
    model = source.load('restore')
    io.require(0 < len(catalog_raw) <= model.MAX_CATALOG and 0 < len(rights_raw) <= model.MAX_CATALOG and
        io.sha(catalog_raw) == db['admission']['source_catalog_sha256'], 'MAINTENANCE_S7_METADATA_BOUND')
    profile = model.compare_restore_catalog(catalog_raw,catalog_raw,rights_raw,rights_raw)
    io.require(profile['rights_sha256'] == db['admission']['rights_sha256'], 'MAINTENANCE_S7_RIGHTS_REFERENCE')
    plan = io.parse(bound['plan']); objects = plan['capture']['objects']
    lighting = {LIGHTING if k == '.' else LIGHTING+'/'+k:v for k,v in objects.items()}
    unit_paths = {p for u in b['unit_files'].values() for p in (u['fragment'],*u['dropins'])}
    io.require(len(lighting) == 88 and len(files) == 102 and
        set(files) == set(lighting)|unit_paths|set(CONFIGS)|set(STATE), 'MAINTENANCE_CURRENT_BACKUP_EXTENT')
    for path,row in lighting.items():
        saved = files[path]
        io.require(saved['sha256'] == row['sha256'] and all(saved['metadata'][k] == v
                   for k,v in row['metadata'].items()), 'MAINTENANCE_LIGHTING_RESTORE_PLAN_CHANGED')
    for path in unit_paths|set(CONFIGS):
        saved = files[path]; expected = b['files'][path]
        io.require(saved['sha256'] == expected['sha256'] and all(saved['metadata'][k] == expected[k]
            for k in ('uid','gid','mode','attrs','flags')), 'MAINTENANCE_UNBACKED_IMMUTABLE_INPUT_CHANGE')
    # No inference from a changed content hash to illegitimate data, and no
    # assertion that the separate snapshots cover intervening business writes.
    # The independent input review binds this explicit finite risk/age budget.
    a = coverage['assessment']; now = time.time()
    io.require(type(a) is dict and set(a) == {'schema','risk','file_snapshot_unix','db_snapshot_unix',
        'assessed_at_unix','valid_until_unix','maximum_snapshot_age_seconds','changes','evidence'} and
        a['schema'] == 'TU1NZ_REV4_MUTABLE_COVERAGE_ASSESSMENT_V1' and a['risk'] == RISK and
        all(type(a[k]) in (int,float) and math.isfinite(a[k]) for k in
            ('file_snapshot_unix','db_snapshot_unix','assessed_at_unix','valid_until_unix')) and
        a['file_snapshot_unix'] == datetime.fromisoformat(protection['file_capture_finished_utc'].replace('Z','+00:00')).timestamp() and
        a['db_snapshot_unix'] == db['snapshot']['snapshot_started_unix'] == completion['db_snapshot_started_unix'] and
        a['file_snapshot_unix'] < a['db_snapshot_unix'] <= a['assessed_at_unix'] <= now and
        now+remaining_seconds <= a['valid_until_unix'] and
        type(a['maximum_snapshot_age_seconds']) is int and 0 < a['maximum_snapshot_age_seconds'] < 2**31 and
        a['valid_until_unix']-a['file_snapshot_unix'] <= a['maximum_snapshot_age_seconds'],
        'MAINTENANCE_COVERAGE_AGE_OR_WINDOW')
    io.require(type(a['changes']) is dict and set(a['changes']) == set(TABLES)|set(STATE) and
        type(a['evidence']) is dict and 1 <= len(a['evidence']) <= 16, 'MAINTENANCE_MUTABLE_ASSESSMENT_EXTENT')
    evidence = {}
    for digest,encoded in a['evidence'].items():
        value,raw = decoded(encoded,digest,'MAINTENANCE_CHANGE_ASSESSMENT_EVIDENCE')
        io.require(type(value) is dict and 0 < len(raw) <= 65536, 'MAINTENANCE_CHANGE_EVIDENCE_BOUND')
        evidence[digest] = value
    for name,row in a['changes'].items():
        io.require(type(row) is dict and set(row) == {'classification','evidence_sha256','maximum_current_bytes',
                   'maximum_current_rows','observed_at_unix','observed','gap_assessment'} and row['classification'] in ('UNCHANGED','ASSESSED_MUTABLE_DATA_GAP') and
            row['evidence_sha256'] in evidence and type(row['maximum_current_bytes']) is int and
            0 <= row['maximum_current_bytes'] <= 128*1024*1024 and
            type(row['maximum_current_rows']) is int and 0 <= row['maximum_current_rows'] <= 1000000,
            'MAINTENANCE_UNEXPLAINED_DATA_CHANGE_OR_BOUND')
        io.require(type(row['observed_at_unix']) in (int,float) and math.isfinite(row['observed_at_unix']) and
            a['db_snapshot_unix'] <= row['observed_at_unix'] <= a['assessed_at_unix'] and
            a['assessed_at_unix']-row['observed_at_unix'] <= 300 and type(row['observed']) is dict,
            'MAINTENANCE_CHANGE_OBSERVATION_TIME')
        observed = row['observed']; gap = row['gap_assessment']
        if name in TABLES:
            io.require(set(observed) == {'rows','json_bytes'} and all(type(v) is int and v >= 0 for v in observed.values()),
                       'MAINTENANCE_CHANGE_DATABASE_OBSERVATION')
            backup_rows = db['snapshot']['fingerprints'][name]['rows']
            expected_gap = {'snapshot_unix':a['db_snapshot_unix'],'observed_unix':row['observed_at_unix'],
                'backup_rows':backup_rows,'additional_rows':observed['rows']-backup_rows,
                'content_equality_proved':False}
        else:
            io.require(set(observed) == {'bytes','sha256'} and type(observed['bytes']) is int and observed['bytes'] >= 0 and
                type(observed['sha256']) is str and len(observed['sha256']) == 64,
                'MAINTENANCE_CHANGE_FILE_OBSERVATION')
            expected_gap = {'snapshot_unix':a['file_snapshot_unix'],'observed_unix':row['observed_at_unix'],
                'backup_sha256':files[name]['sha256'],'content_changed':observed['sha256'] != files[name]['sha256']}
        io.require(type(gap) is dict and set(gap) == set(expected_gap)|{'remaining_exposure','adequacy_reason'} and
            all(gap[k] == v for k,v in expected_gap.items()) and all(type(gap[k]) is str and
                40 <= len(gap[k]) <= 2048 and all(c.isprintable() or c == '\n' for c in gap[k])
                for k in ('remaining_exposure','adequacy_reason')), 'MAINTENANCE_CHANGE_GAP_NOT_REVIEWABLE')
        # These prose judgments are NOT facts inferred by code. The separate
        # independent input review covers their adequacy. Actual observed
        # counts/bytes or JSON hash must still match the fresh read below;
        # an unassessed new change remains HOLD. No old-runtime origin claim.
        if name in TABLES:
            io.require(row['classification'] == 'ASSESSED_MUTABLE_DATA_GAP',
                       'MAINTENANCE_DATABASE_UNCHANGED_NOT_PROVED_BY_COUNTS')
        unit = UNITS[0] if name in TABLES else UNITS[1 if name == STATE[0] else 2]
        reference = protection['private_DB_result_sha256'] if name in TABLES else completion['file_manifest_sha256']
        io.require(evidence[row['evidence_sha256']] == {
            'schema':'TU1NZ_REV4_FINITE_CURRENT_WRITE_ASSESSMENT_V1', 'object':name,
            'classification':row['classification'], 'writer_unit':unit,
            'target_application_commit':b['source_release']['runtime_reference']['artifact']['application']['commit'],
            'immutable_inputs_sha256':io.sha(io.canonical({p:projection(b)['files'][p] for p in sorted(unit_paths|set(CONFIGS))})),
            'backup_reference_sha256':reference, 'observed_at_unix':row['observed_at_unix'],
            'observed':row['observed'], 'gap_assessment_sha256':io.sha(io.canonical(row['gap_assessment'])),
            'historical_or_lossless_restore_claim':False},
            'MAINTENANCE_WRITE_ASSESSMENT_REFERENCE')
    return {'assessment':a,'catalog':catalog_raw,'rights':rights_raw,'model':model,
            'backup_manifest':files,'snapshot':db['snapshot'], 'coverage_sha256':io.sha(io.canonical(coverage))}


# Distinct fixed text tokens cannot occur as a raw line in JSONL metadata.
CATALOG_END = 'TU1NZ_REV4_CATALOG_END'
RIGHTS_END = 'TU1NZ_REV4_RIGHTS_END'
STATS_END = 'TU1NZ_REV4_STATS_END'


def query(model):
    """Only metadata and aggregate counts/bytes of the two already bound tables.

    Invoked inside the existing local read-only identity transaction. No raw
    business row leaves PostgreSQL; counts do not prove equality to the dump.
    """
    stats = []
    for table in TABLES:
        stats.append("SELECT json_build_object('table','"+table+"','rows',count(*),"
            "'json_bytes',coalesce(sum(octet_length(to_jsonb(t)::text)),0)) FROM public."+table+" t;")
    return (b"SET LOCAL search_path=pg_catalog;\n"+model.catalog_sql()+
        ("SELECT '"+CATALOG_END+"';\n").encode()+model.rights_sql()+
        ("SELECT '"+RIGHTS_END+"';\n"+'\n'.join(stats)+"\nSELECT '"+STATS_END+"';\n").encode())


def compare_database(coverage, lines):
    io.require(type(lines) is list and 3 < len(lines) < 1024 and
        all(type(v) is str for v in lines) and lines[-1] == STATS_END and
        lines.count(CATALOG_END) == lines.count(RIGHTS_END) == lines.count(STATS_END) == 1,
        'MAINTENANCE_DATABASE_COVERAGE_FRAME')
    c = lines.index(CATALOG_END); r = lines.index(RIGHTS_END)
    io.require(0 < c < r-1 and len(lines)-r == 4, 'MAINTENANCE_DATABASE_COVERAGE_FIELDS')
    catalog = ('\n'.join(lines[:c])+'\n').encode()
    rights = ('\n'.join(lines[c+1:r])+'\n').encode()
    profile = coverage['model'].compare_restore_catalog(coverage['catalog'],catalog,coverage['rights'],rights)
    stats = [io.parse(v) for v in lines[r+1:-1]]
    io.require([v.get('table') for v in stats] == list(TABLES), 'MAINTENANCE_DATABASE_COVERAGE_TABLES')
    for row in stats:
        io.require(set(row) == {'table','rows','json_bytes'} and
            all(type(row[k]) is int and row[k] >= 0 for k in ('rows','json_bytes')),
            'MAINTENANCE_DATABASE_COVERAGE_TYPES')
        bounds = coverage['assessment']['changes'][row['table']]
        io.require(bounds['observed'] == {k:row[k] for k in ('rows','json_bytes')},
                   'MAINTENANCE_DATABASE_CHANGED_SINCE_ASSESSMENT')
        io.require(coverage['snapshot']['fingerprints'][row['table']]['rows'] <= row['rows'] <=
                   bounds['maximum_current_rows'] and row['json_bytes'] <= bounds['maximum_current_bytes'],
                   'MAINTENANCE_DATABASE_CURRENT_EXTENT_OUTSIDE_ASSESSMENT')
    return {'schema_rights_sha256':io.sha(io.canonical(profile)), 'counts':stats,
            'data_equality_or_lossless_restore_claim':False}


def check_current(authority, coverage):
    """Fresh actual current data/Writer checks, before admission and first stop.

    Existing Authority supplies relevant actor isolation and actual Writer
    fences. No saved receipt replaces those checks; mutable data remain live.
    """
    a = coverage['assessment']; now = time.time()
    io.require(now+max(1,math.ceil(authority.deadline-time.monotonic())) <= a['valid_until_unix'],
               'MAINTENANCE_CURRENT_COVERAGE_EXPIRED')
    proof = authority.current_data_readonly(coverage=coverage)
    for path in STATE:
        row = proof['state'][path.rsplit('/',1)[1]]; allowed = a['changes'][path]
        io.require(allowed['observed'] == {'bytes':row['metadata']['st_size'],'sha256':row['sha256']},
                   'MAINTENANCE_JSON_CHANGED_SINCE_ASSESSMENT')
        io.require(row['metadata']['st_size'] <= allowed['maximum_current_bytes'],
                   'MAINTENANCE_CURRENT_JSON_EXTENT_OUTSIDE_ASSESSMENT')
        if allowed['classification'] == 'UNCHANGED':
            io.require(row['sha256'] == coverage['backup_manifest'][path]['sha256'],
                       'MAINTENANCE_CURRENT_JSON_CHANGED_AFTER_ASSESSMENT')
    authority.check_files()
    return {'coverage_sha256':coverage['coverage_sha256'], 'checked_unix':now,
            'file_capture_age_seconds':now-a['file_snapshot_unix'],
            'database_snapshot_age_seconds':now-a['db_snapshot_unix'],
            'data':proof, 'no_atomic_or_zero_rpo_claim':True}
