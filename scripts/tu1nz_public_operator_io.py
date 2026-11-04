"""Bounded private framing, durable receipts and authenticated source loading.

Only standard-library code. No socket/SSH launch or Host mutation at import.
The caller supplies authenticated code bytes, not executable paths from a Host.
"""
from __future__ import annotations

import ast
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import select
import stat
import subprocess
import sys
import time
import types
import zlib
from contextlib import contextmanager
import urllib.error
import urllib.parse
import urllib.request

MAX_FRAME = 4*1024*1024
R5_SCOPE = 'TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_R5_V1'
PROSPECTIVE_SCOPE = 'TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_R5P_V1'
PROSPECTIVE_BINDING = 'TU1NZ_PUBLIC_PROSPECTIVE_BINDING_V1'
PROSPECTIVE_ACCEPTANCE = 'TU1NZ_PUBLIC_PROSPECTIVE_ACCEPTANCE_V1'
CONTEXT_SCOPE = 'TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_R5P_CONTEXT_V1'
CONTEXT_BINDING = 'TU1NZ_PUBLIC_PROSPECTIVE_BINDING_CONTEXT_V1'
CONTEXT_ACCEPTANCE = 'TU1NZ_PUBLIC_PROSPECTIVE_ACCEPTANCE_CONTEXT_V1'
BYTE_ORIGIN = 'TU1NZ_PUBLIC_BYTE_ORIGIN_V1'
PROSPECTIVE_SCOPES = (PROSPECTIVE_SCOPE, CONTEXT_SCOPE)
R5_SCOPES = (R5_SCOPE, *PROSPECTIVE_SCOPES)
PROSPECTIVE_POLICY_ROOTS = ('/etc/polkit-1/rules.d', '/usr/share/polkit-1/rules.d',
    '/etc/sudoers.d', '/etc/dbus-1/system.d', '/usr/share/dbus-1/system.d')
PROSPECTIVE_NSS = frozenset(('/etc/passwd', '/etc/group', '/etc/nsswitch.conf', '/etc/sudoers', '/etc/hosts'))
PROSPECTIVE_UNITS = {
    '/etc/systemd/system/tu1nz-adult-public-s7.service': 'ad098f7533716f2e26f9aff500bc82a7b98c939b5b021a442f37d778edc7b692',
    '/etc/systemd/system/tu1nz-adult-public-s8-landing.service': 'f2663c4f1e57e91aa938d67bc5533fa5324dd355282bdf6e52fe40102b7b994d',
    '/etc/systemd/system/tu1nz-adult-public-s10-wms.service': '53237fc837a28cabbab7e34693db67bfaa2736b5153818f6b218c7dbcd65b89a',
    '/etc/systemd/system/tu1nz-adult-public-s8-landing.service.d/s9-growth.conf': '2e10d790f1ed2dd736c9b0c7ec1dda5b58c6cc767e5d5cb2574fe76eb99ceb4b'}
PROSPECTIVE_RISK = 'CURRENT_HOST_TCB_MAY_FALSIFY_CAPTURE_NOT_HISTORICAL_INTEGRITY'
CONTROL_PINS = {
    'entry': '538e157629414f717039de1f4b3d0b388fde16718df74dc54c16dde1ac3826c7',
    'guard': 'eb01c7d260f7ad83b7d3437fe78768549a091289ecff99cae68f05689c224b58'}
MODULES = {'io': 'tu1nz_public_operator_io', 'fs': 'tu1nz_public_operator_fs',
           'context': 'tu1nz_public_operator_context',
           'client': 'tu1nz_public_operator',
           'observe': 'tu1nz_public_operator_observe', 'probes': 'tu1nz_public_operator_probes',
           'runtime_guard': 'tu1nz_public_operator_runtime_guard',
           'artifact': 'tu1nz_public_runtime_artifact', 'replacement': 'tu1nz_public_runtime_transition',
           'host': 'tu1nz_public_operator_host', 'r3': 'tu1nz_public_bootstrap_r3',
           'owner': 'tu1nz_bound_owner_supervisor', 'entry': 'tu1nz_bound_lighting_entry',
           'guard': 'tu1nz_bound_writer_guard'}
ASSETS = {'runtime': '2884c2531e73480513d533844cab9ac1a906e13fd4fdb104ab1d49759f3e9b01',
          'dropin_s7': 'df605ffec37e59d1c3c535a93879e7e155447967c6cd97a2f83ca866f841c16b',
          'dropin_s8_landing': '1e84f8904b4ce292e8b002ad373b27ea5d6592ddaaca4c07c68e990452133213',
    'dropin_wms': 'ce23c6382e50b740fb22f5a085d15fb0f96cd7fc15afcc1deaf23e04aff8bcf3',
    'runtime_inputs': 'dc60ead4d72111f5d748b4cbc34f724c03e78435fd3a32ac8b323b8a5b2e4b9a',
    'runtime_overlay': '0fb502c4f6b164e7e5fb9b1209c11c5f8f221f8191a658d6704bf00c41949b83'}
PUBLIC_HOSTS = frozenset(('tu1nz.com', 'www.tu1nz.com', 'wantmeseen.com', 'www.wantmeseen.com',
                          'lighting.tu1nz.com'))


class Hold(RuntimeError):
    def __init__(self, code):
        if not re.fullmatch('PUBLIC_OPERATOR_[A-Z0-9_]{1,96}', code):
            code = 'PUBLIC_OPERATOR_ERROR_SCHEMA_RED'
        self.primary = 'PUBLIC_BOOTSTRAP_'+code
        super().__init__(code)


def require(value, code):
    if not value:
        raise Hold('PUBLIC_OPERATOR_'+code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def cgroup_records(value):
    """Full proc cgroup records, NOT a path or a normalized authorization.

    Keep every hierarchy/controller/path and its order for exact comparison.
    The proc reader removes exactly its final LF, never whitespace/path data.
    This grammar does not grant a role or add v1/hybrid runtime support.
    """
    require(type(value) is str and 0 < len(value) <= 256*1024, 'CGROUP_PROFILE_BOUND')
    lines = value.split('\n')
    require(1 <= len(lines) <= 64, 'CGROUP_PROFILE_BOUND')
    records = []; hierarchies = set(); controllers = set()
    for line in lines:
        fields = line.split(':', 2)
        require(len(fields) == 3, 'CGROUP_PROFILE_STRUCTURE')
        hierarchy, control, path = fields
        require(re.fullmatch(r'0|[1-9][0-9]{0,9}', hierarchy) and
                int(hierarchy) <= 0x7fffffff and hierarchy not in hierarchies,
                'CGROUP_PROFILE_HIERARCHY')
        names = control.split(',') if control else []
        require((hierarchy == '0' and not names) or (hierarchy != '0' and names and
                all(re.fullmatch(r'[A-Za-z0-9_]+|name=[A-Za-z0-9_.-]+', n) for n in names)),
                'CGROUP_PROFILE_CONTROLLERS')
        require(len(names) == len(set(names)) and not controllers.intersection(names),
                'CGROUP_PROFILE_CONTROLLERS')
        require(0 < len(path) <= 4096 and path.startswith('/') and
                all(c.isprintable() for c in path) and
                (path == '/' or all(p not in ('', '.', '..') for p in path[1:].split('/'))),
                'CGROUP_PROFILE_PATH')
        hierarchies.add(hierarchy); controllers.update(names)
        records.append((int(hierarchy), tuple(names), path))
    return tuple(records)


def system_slice_cgroup(value):
    # Every recorded hierarchy must have this context; one matching substring
    # or one selected controller must never mask a different membership.
    return all(path.startswith('/system.slice/') for _, _, path in cgroup_records(value))


def operator_dependency_reference(release, origins):
    """R5 observer TCB inputs, NEVER copied into synthetic execution roots."""
    require(type(release) is dict and set(release)=={'probe_dependencies','python_binary',
        'runtime_reference','operator_dependencies'},'REPLACEMENT_OPERATOR_RELEASE_SCHEMA')
    rows=release['operator_dependencies']
    require(type(rows) is dict and 0<len(rows)<=128 and '/usr/bin/busctl' in rows,
            'REPLACEMENT_READER_DEPENDENCY_SET')
    fields={'source','sha256','uid','gid','mode','attrs','flags','origin_sha256'}
    for path,row in rows.items():
        require(type(path) is str and path.startswith(('/usr/bin/','/usr/lib/','/lib/','/lib64/')) and
                '\x00' not in path and '..' not in Path(path).parts and str(Path(path))==path and type(row) is dict and set(row)==fields,
                'REPLACEMENT_OPERATOR_DEPENDENCY_SCHEMA')
        require(type(row['source']) is str and row['source'].startswith(('/usr/bin/','/usr/lib/')) and
                '\x00' not in row['source'] and '..' not in Path(row['source']).parts and str(Path(row['source']))==row['source'] and
                type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}',row['sha256']) and
                row['origin_sha256'] in origins,'REPLACEMENT_READER_LIBRARY_ORIGIN_UNBOUND')
        require(type(row['uid']) is type(row['gid']) is int and row['uid']==row['gid']==0 and
                type(row['mode']) is int and 0<=row['mode']<=0o777 and not row['mode']&0o022 and
                type(row['flags']) is int and 0<=row['flags']<2**32 and type(row['attrs']) is dict and
                all(type(k) is type(v) is str for k,v in row['attrs'].items()),
                'REPLACEMENT_OPERATOR_DEPENDENCY_PROFILE')
    return rows


def replacement_scope(scope, baseline):
    fields={'schema','release_sha256','baseline_sha256','administrative_roles_sha256',
            'baseline_origins_sha256','r3_approval_sha256','machine_sha256','transaction','owner_plan_sha256'}
    replacement=scope.get('schema') in R5_SCOPES
    prospective=scope.get('schema') in PROSPECTIVE_SCOPES
    extra={'prospective_binding_sha256','prospective_acceptance_sha256'} if prospective else set()
    require(set(scope)==fields | ({'runtime_artifact_sha256','legacy_return'} if replacement else set()) | extra and
            scope['schema'] in ('TU1NZ_PUBLIC_OPERATOR_APPROVED_SCOPE_V1', *R5_SCOPES),
            'APPROVED_SCOPE_SCHEMA')
    require(not prospective or all(type(scope[k]) is str and re.fullmatch('[a-f0-9]{64}',scope[k])
            for k in extra),'PROSPECTIVE_SCOPE_HASHES')
    contextual = scope.get('schema') == CONTEXT_SCOPE
    require((baseline.get('schema') == 'TU1NZ_PUBLIC_HOST_BASELINE_CONTEXT_V1') == contextual and
            ('contexts' in baseline) == contextual, 'CONTEXT_SCOPE_BASELINE_DOWNGRADE')
    reference=baseline['source_release']['runtime_reference']
    if replacement:
        operator_dependency_reference(baseline['source_release'],baseline['source_origin_receipts'])
        require(set(reference)=={'schema','artifact','origin_sha256'} and
                reference['schema']=='TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1' and
                scope['legacy_return'] is False and
                sha(canonical(reference['artifact']))==scope['runtime_artifact_sha256']==reference['origin_sha256'] and
                reference['origin_sha256'] in baseline['source_origin_receipts'],
                'INDEPENDENT_REPLACEMENT_SCOPE_BINDING')
        require(not any(p=='/opt/tu1nz_repos/adult-publishing-core' or
            p.startswith('/opt/tu1nz_repos/adult-publishing-core/') for p in baseline['files']),
            'REPLACEMENT_BASELINE_CANNOT_ADOPT_UNPROVEN_LEGACY_BYTES')
    else:
        require(set(baseline['source_release'])=={'probe_dependencies','python_binary','runtime_reference'},
                'LEGACY_SOURCE_RELEASE_SCHEMA')
        require(reference.get('schema')=='TU1NZ_PUBLIC_RUNTIME_REFERENCE_V1',
                'LEGACY_SCOPE_CANNOT_AUTHORIZE_RUNTIME_REPLACEMENT')
    return replacement


def baseline_bytes(packet):
    raw=base64.b64decode(packet['baseline_raw'],validate=True)
    if packet.get('baseline_encoding')=='zlib_R5':
        require(packet['scope']['schema'] in R5_SCOPES,
                'COMPRESSED_BASELINE_NOT_LEGACY_SCOPE')
        decoder=zlib.decompressobj();raw=decoder.decompress(raw,MAX_FRAME+1)
        require(len(raw)<=MAX_FRAME and decoder.eof and not decoder.unconsumed_tail and
                not decoder.unused_data,'BASELINE_DECOMPRESSION_BOUND')
    else:
        require('baseline_encoding' not in packet,'UNKNOWN_BASELINE_ENCODING')
    require(len(raw)<=MAX_FRAME,'BASELINE_SIZE_BOUND')
    return raw


def prospective_binding(scope, baseline, actual):
    """Pure, fail-closed admission of MATERIAL, not a Host read or approval.

    Actual review/human provenance is selected by the OUT-OF-BAND independently
    approved scope hash. Names, booleans and this function cannot create it.
    Return only the exact required material for repeated pre-claim validation.
    """
    prospective = scope.get('schema') in PROSPECTIVE_SCOPES
    contextual = scope.get('schema') == CONTEXT_SCOPE
    special = set()
    for h, raw in actual.items():
        try: value = json.loads(raw)
        except (ValueError, UnicodeError): continue
        if type(value) is dict and value.get('schema') in (PROSPECTIVE_BINDING, PROSPECTIVE_ACCEPTANCE,
                                                         CONTEXT_BINDING, CONTEXT_ACCEPTANCE):
            special.add(h)
    if not prospective:
        require(not special, 'PROSPECTIVE_DOWNGRADE')
        return {}
    origins = set(baseline['source_origin_receipts']); used = set()
    def material(h):
        require(type(h) is str and re.fullmatch('[a-f0-9]{64}', h) and h in origins and
                h in actual and actual[h] and sha(actual[h]) == h, 'PROSPECTIVE_MATERIAL_MISSING')
        used.add(h)
        return actual[h]
    binding_hash, acceptance_hash = (scope[k] for k in ('prospective_binding_sha256', 'prospective_acceptance_sha256'))
    binding, acceptance = parse(material(binding_hash)), parse(material(acceptance_hash))
    require(special == {binding_hash, acceptance_hash}, 'PROSPECTIVE_EXACT_RECEIPTS')
    require(type(binding) is dict and set(binding) == {'schema','machine_sha256','boot_id','transaction',
        'capture','host_files','unit_files','policy_roots','actors','metadata','execution_origins','names'} |
        ({'contexts'} if contextual else set()),
        'PROSPECTIVE_BINDING_SCHEMA')
    require(binding['schema'] == (CONTEXT_BINDING if contextual else PROSPECTIVE_BINDING) and
        binding['machine_sha256'] == scope['machine_sha256'] ==
        baseline['machine_sha256'] and binding['boot_id'] == baseline['boot_id'] and
        binding['transaction'] == scope['transaction'] == 'public-rights-20261014-1', 'PROSPECTIVE_HOST_BINDING')
    require(type(acceptance) is dict and set(acceptance) == {'schema','binding_sha256','machine_sha256','boot_id',
        'transaction','release_sha256','owner_plan_sha256','review_sha256','human_decision_sha256',
        'accepted_at','expires_at','risk'}, 'PROSPECTIVE_ACCEPTANCE_SCHEMA')
    require(acceptance['schema'] == (CONTEXT_ACCEPTANCE if contextual else PROSPECTIVE_ACCEPTANCE) and
        acceptance['binding_sha256'] == binding_hash and
        all(acceptance[k] == scope[k] for k in ('machine_sha256','transaction','release_sha256','owner_plan_sha256')) and
        acceptance['boot_id'] == baseline['boot_id'] and
        acceptance['risk'] == ([PROSPECTIVE_RISK, 'SELECTED_COEXISTENCE_TCB_CAN_INFLUENCE_R5_NOT_ISOLATED']
                               if contextual else PROSPECTIVE_RISK),
        'PROSPECTIVE_ACCEPTANCE_BINDING')
    require(type(binding['capture']) is dict and set(binding['capture']) ==
        {'read_scope_sha256','reader_source_sha256','read_receipt_sha256','started_at','finished_at'},
        'PROSPECTIVE_CAPTURE_SCHEMA')
    evidence = [binding['capture'][k] for k in ('read_scope_sha256','reader_source_sha256','read_receipt_sha256')]
    evidence += [acceptance['review_sha256'], acceptance['human_decision_sha256']]
    require(all(type(h) is str and re.fullmatch('[a-f0-9]{64}',h) for h in evidence) and
            len(set(evidence + [binding_hash, acceptance_hash])) == 7, 'PROSPECTIVE_DISTINCT_EVIDENCE')
    for h in evidence:
        require(len(material(h)) <= 256*1024, 'PROSPECTIVE_EVIDENCE_BOUND')
    def timestamp(v):
        require(type(v) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', v), 'PROSPECTIVE_TIME_SCHEMA')
        try: return datetime.strptime(v, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
        except ValueError: raise Hold('PUBLIC_OPERATOR_PROSPECTIVE_TIME_SCHEMA') from None
    start, end = (timestamp(binding['capture'][k]) for k in ('started_at','finished_at'))
    accepted, expires = (timestamp(acceptance[k]) for k in ('accepted_at','expires_at'))
    require(0 <= end-start <= 300 and end <= accepted <= time.time() <= expires <= end+86400,
            'PROSPECTIVE_TIME_OR_EXPIRY')
    roots = binding['policy_roots']
    require(type(roots) is dict and set(roots) == set(PROSPECTIVE_POLICY_ROOTS) and roots == baseline['policy_roots'],
            'PROSPECTIVE_POLICY_ROOTS')
    host_paths = set(PROSPECTIVE_NSS)
    for root, names in roots.items():
        require(type(names) is list and len(names) <= 64 and
                all(type(n) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', n) and n not in ('.','..') for n in names) and
                names == sorted(set(names)),
                'PROSPECTIVE_POLICY_NAMES')
        host_paths.update(root+'/'+n for n in names)
    require(type(binding['host_files']) is dict and set(binding['host_files']) == host_paths and
        type(binding['unit_files']) is dict and set(binding['unit_files']) == set(PROSPECTIVE_UNITS),
        'PROSPECTIVE_EXACT_FILE_SET')
    file_fields = {'sha256','uid','gid','mode','attrs','flags'}
    def secure_metadata(row):
        require(type(row) is dict and set(row) == {'uid','gid','mode','attrs','flags'} and
            type(row['uid']) is type(row['gid']) is int and row['uid'] == row['gid'] == 0 and
            type(row['mode']) is int and 0 <= row['mode'] <= 0o777 and not row['mode'] & 0o022 and
            row['attrs'] == {} and type(row['flags']) is int and row['flags'] in (0, 0x80000),
            'PROSPECTIVE_METADATA_PROFILE')
    def byte_origin(h, path, digest, allowed):
        require(h not in {binding_hash, acceptance_hash, *evidence}, 'PROSPECTIVE_NOT_BYTE_ORIGIN')
        origin = parse(material(h))
        require(type(origin) is dict and set(origin) == {'schema','basis','source_evidence_sha256','objects'} and
                origin['schema'] == BYTE_ORIGIN and origin['basis'] in allowed and
                type(origin['objects']) is dict and 0<len(origin['objects'])<=512 and
                origin['objects'].get(path) == digest,
                'PROSPECTIVE_TYPED_BYTE_ORIGIN')
        refs = origin['source_evidence_sha256']
        require(type(refs) is list and 0 < len(refs) <= 8 and all(type(h) is str for h in refs) and len(set(refs)) == len(refs) and
                not set(refs) & {binding_hash,acceptance_hash,h,*evidence}, 'PROSPECTIVE_BYTE_EVIDENCE')
        for ref in refs:
            raw = material(ref)
            try: obj = json.loads(raw)
            except (ValueError, UnicodeError): obj = None
            require(not (type(obj) is dict and obj.get('schema') in
                (BYTE_ORIGIN, PROSPECTIVE_BINDING, PROSPECTIVE_ACCEPTANCE,
                 CONTEXT_BINDING, CONTEXT_ACCEPTANCE)), 'PROSPECTIVE_ORIGIN_CYCLE')
    for table in ('host_files','unit_files'):
        for path, row in binding[table].items():
            require(type(row) is dict and set(row) == file_fields and
                type(row.get('sha256')) is str and re.fullmatch('[a-f0-9]{64}', row['sha256']), 'PROSPECTIVE_FILE_SCHEMA')
            secure_metadata({k:row[k] for k in file_fields-{'sha256'}})
            require(not row['mode'] & 0o111 and path in baseline['files'] and
                    row == {k:v for k,v in baseline['files'][path].items() if k != 'origin_sha256'},
                    'PROSPECTIVE_FILE_DRIFT')
            h = baseline['files'][path]['origin_sha256']
            if table == 'host_files': require(h == binding_hash, 'PROSPECTIVE_POLICY_ORIGIN')
            else:
                require(row['sha256'] == PROSPECTIVE_UNITS[path], 'PROSPECTIVE_UNIT_SOURCE_BYTES')
                byte_origin(h, path, row['sha256'], ('GIT',))
    actual_units = {p for v in baseline['unit_files'].values() for p in [v['fragment'], *v['dropins']]}
    require(actual_units == set(PROSPECTIVE_UNITS), 'PROSPECTIVE_UNIT_SET')
    # EVERY baseline actor is represented, never a subset or an origin wildcard.
    actors = binding['actors']
    require(type(actors) is list and 4 <= len(actors) <= 256 and len(actors) == len(baseline['actors']),
            'PROSPECTIVE_ACTOR_SET')
    actor_fields = {'role','exe','exe_sha256','uid','gid','groups','caps','nnp','argv_sha256','cgroup',
                    'initial_env_sha256','lsm_sha256','namespaces','max_instances'}
    roles = {'kernel_manager':1,'authenticated_maintenance':8,'administrative_service':16,'nginx_reader':16}
    counts = {k:0 for k in roles}; execution = {}; actor_identities=set()
    for item, expected in zip(actors, baseline['actors']):
        require(type(item) is dict and set(item) == {'profile','justification'} and
                type(item['justification']) is str and 32 <= len(item['justification']) <= 2048,
                'PROSPECTIVE_ROLE_JUSTIFICATION')
        row = item['profile']
        require(type(row) is dict and set(row) == actor_fields | ({'context_id'} if contextual else set()) and row ==
                {k:v for k,v in expected.items() if k != 'origin_sha256'} and expected['origin_sha256'] == binding_hash,
                'PROSPECTIVE_ROLE_BINDING')
        if contextual:
            require(type(row['context_id']) is str, 'CONTEXT_ROLE_DOMAIN')
            if row['context_id'] != 'HOST':
                continue  # Every such row is validated and consumed below, never omitted.
            row = {k:v for k,v in row.items() if k != 'context_id'}
        role = row['role']; require(type(role) is str and role in roles and type(row['max_instances']) is int and
                1 <= row['max_instances'] <= roles[role], 'PROSPECTIVE_ROLE_LIMIT')
        counts[role] += row['max_instances']
        require(type(row['nnp']) is int and row['nnp'] in (0,1) and
            type(row['caps']) is dict and set(row['caps'])=={'CapInh','CapPrm','CapEff','CapBnd','CapAmb'} and
            all(type(n) is int and 0<=n<2**64 for n in row['caps'].values()) and
            all(type(row[k]) is list and len(row[k])==4 and all(type(n) is int and 0<=n<2**32
                for n in row[k]) for k in ('uid','gid')) and type(row['groups']) is list and
            all(type(n) is int and 0<=n<2**32 for n in row['groups']) and
            row['groups']==sorted(row['groups']) and len(row['groups']) <= 65536 and
            all(type(row[k]) is str and re.fullmatch('[a-f0-9]{64}',row[k])
                for k in ('exe_sha256','argv_sha256','initial_env_sha256','lsm_sha256')) and
            type(row['cgroup']) is str and
            type(row['namespaces']) is dict and set(row['namespaces'])=={'pid','mnt','user','net'} and
            all(type(v) is str and re.fullmatch(k+r':\[[0-9]+\]',v) for k,v in row['namespaces'].items()),
            'PROSPECTIVE_ROLE_PROFILE')
        cgroup_records(row['cgroup'])
        identity=sha(canonical({k:v for k,v in row.items() if k not in ('role','max_instances')}))
        require(identity not in actor_identities,'PROSPECTIVE_AMBIGUOUS_ROLE');actor_identities.add(identity)
        require(type(row['exe']) is str and row['exe'].startswith(('/usr/bin/','/usr/sbin/','/usr/lib/','/sbin/','/bin/')) and
                '\x00' not in row['exe'] and '..' not in Path(row['exe']).parts and str(Path(row['exe']))==row['exe'],
                'PROSPECTIVE_ACTOR_EXECUTABLE')
        require(row['exe'] not in execution or execution[row['exe']]==row['exe_sha256'], 'PROSPECTIVE_EXEC_COLLISION')
        execution[row['exe']] = row['exe_sha256']
        if role == 'kernel_manager': require(row['uid'] == row['gid'] == [0]*4, 'PROSPECTIVE_MANAGER_PROFILE')
        if role == 'administrative_service': require(system_slice_cgroup(row['cgroup']), 'PROSPECTIVE_SERVICE_CONTEXT')
        if role == 'nginx_reader': require(row['uid'] == row['gid'] == [33]*4 and row['groups'] == [33] and
            not any(v for k,v in row['caps'].items() if k != 'CapBnd'), 'PROSPECTIVE_NGINX_PROFILE')
    require(counts['kernel_manager'] == 1 and all(counts.values()) and sum(counts.values()) <= 256,
            'PROSPECTIVE_COMPLETE_ROLES')
    for rows in (baseline['source_release']['operator_dependencies'], baseline['source_release']['probe_dependencies']):
        for path, row in rows.items():
            require(row['source'] not in execution or execution[row['source']] == row['sha256'], 'PROSPECTIVE_EXEC_COLLISION')
            execution[row['source']] = row['sha256']
    require(type(binding['execution_origins']) is dict and set(binding['execution_origins']) == set(execution),
            'PROSPECTIVE_EXECUTION_COVERAGE')
    for path,digest in execution.items():
        byte_origin(binding['execution_origins'][path],path,digest,('PUBLISHER','GIT'))
    for row in baseline['source_release']['operator_dependencies'].values():
        require(row['origin_sha256'] == binding['execution_origins'][row['source']], 'PROSPECTIVE_OPERATOR_ORIGIN')
    cache=baseline['files'].get('/etc/ld.so.cache')
    require(type(cache) is dict and set(cache)==file_fields|{'origin_sha256'} and
        type(cache['sha256']) is str and re.fullmatch('[a-f0-9]{64}',cache['sha256']),
        'PROSPECTIVE_CACHE_BASELINE_REQUIRED')
    for path, row in baseline['files'].items():
        if path in host_paths or path in PROSPECTIVE_UNITS: continue
        allowed=(('CACHE_DERIVATION',) if path == '/etc/ld.so.cache' else
                 ('PUBLISHER','GIT','PRIOR_RECORD') if path.startswith('/etc/') and not row['mode']&0o111
                 else ('PUBLISHER','GIT'))
        byte_origin(row['origin_sha256'],path,row['sha256'],allowed)
    metadata = binding['metadata']
    required_meta = set(host_paths) | set(PROSPECTIVE_UNITS) | set(execution) | {'/etc/ld.so.cache'}
    for rows in (baseline['source_release']['operator_dependencies'],baseline['source_release']['probe_dependencies']):
        required_meta.update(rows)
    require(type(metadata) is dict and set(metadata) == required_meta, 'PROSPECTIVE_METADATA_SET')
    for path, row in metadata.items():
        secure_metadata(row)
        expected = baseline['files'].get(path, baseline['source_release']['operator_dependencies'].get(path))
        if expected is not None:
            require(row == {k:expected[k] for k in row}, 'PROSPECTIVE_METADATA_DRIFT')
        if path=='/etc/ld.so.cache':require(not row['mode']&0o111,'PROSPECTIVE_CACHE_METADATA')
    resolved=prospective_names(binding, baseline);canonical_metadata={}
    for path,row in metadata.items():
        name=resolved[path]
        require(name not in canonical_metadata or canonical_metadata[name]==row,
                'PROSPECTIVE_METADATA_ALIAS_CONFLICT')
        canonical_metadata[name]=row
    if contextual:
        from tu1nz_public_operator_context import validate_material
        require(baseline.get('schema') == 'TU1NZ_PUBLIC_HOST_BASELINE_CONTEXT_V1' and
                baseline.get('contexts') == binding['contexts'], 'CONTEXT_BASELINE_BINDING')
        additional = validate_material(binding, baseline, material, byte_origin)
        require(sum(counts.values()) + additional <= 256, 'CONTEXT_TOTAL_INSTANCES')
    require(sum(len(actual[h]) for h in used) <= 1024*1024, 'PROSPECTIVE_MATERIAL_BOUND')
    return {h:actual[h] for h in used}


def prospective_names(binding, baseline):
    """Exact no-follow directory/link graph, derived ONLY from selected inputs.

    No Host I/O here. Existing R5 Paths/loader fences compare these profiles
    before claim and retain their ordinary event/identity protection thereafter.
    """
    names=binding['names']; require(type(names) is dict and 0<len(names)<=1024,'PROSPECTIVE_NAMES_BOUND')
    required=set();files=set(baseline['files'])|set(binding['execution_origins'])
    for key in ('operator_dependencies','probe_dependencies'):
        files.update(baseline['source_release'][key])
    def resolve(path, directory=False):
        require(type(path) is str and path.startswith('/') and '\x00' not in path and
            '..' not in Path(path).parts and str(Path(path))==path,'PROSPECTIVE_NAME_PATH')
        pending=path.split('/')[1:];current=Path('/');links=steps=0
        required.add('/')
        while pending:
            steps+=1;require(steps<=512,'PROSPECTIVE_NAME_CYCLE')
            leaf=pending.pop(0)
            if leaf in ('','.'):continue
            if leaf=='..':current=current.parent;continue
            name=str(current/leaf);row=names.get(name)
            if not pending and not directory and row is None:return name
            require(type(row) is dict,'PROSPECTIVE_NAME_MISSING');required.add(name)
            if row.get('kind')=='link':
                links+=1;require(links<=40 and set(row)=={'kind','uid','gid','mode','attrs','target'} and
                    type(row['uid']) is type(row['gid']) is int and row['uid']==row['gid']==0 and
                    row['mode']==0o777 and row['attrs']=={} and type(row['target']) is str and
                    0<len(row['target'])<=4096 and '\x00' not in row['target'],'PROSPECTIVE_LINK_PROFILE')
                if row['target'].startswith('/'):current=Path('/')
                pending=row['target'].split('/')+pending
            else:
                require(row.get('kind')=='directory','PROSPECTIVE_NAME_TYPE');current=current/leaf
        return str(current)
    resolved={path:resolve(path) for path in files}
    for key in ('operator_dependencies','probe_dependencies'):
        require(all(resolved[path]==row['source'] for path,row in baseline['source_release'][key].items()),
                'PROSPECTIVE_ALIAS_SOURCE')
    require(all(resolved[path]==path for path in binding['execution_origins']),
            'PROSPECTIVE_EXECUTABLE_CANONICAL_NAME')
    for path in PROSPECTIVE_POLICY_ROOTS:resolve(path,True)
    require(set(names)==required,'PROSPECTIVE_EXACT_NAMES')
    for path,row in names.items():
        if row.get('kind')=='link':continue
        require(set(row)=={'kind','uid','gid','mode','attrs','flags'} and row['kind']=='directory' and
            type(row['uid']) is type(row['gid']) is int and row['uid']==row['gid']==0 and
            type(row['mode']) is int and 0<=row['mode']<=0o777 and not row['mode']&0o022 and
            row['attrs']=={} and type(row['flags']) is int and row['flags'] in (0,0x1000,0x80000,0x81000),
            'PROSPECTIVE_DIRECTORY_PROFILE')
    return resolved


def prospective_packet_material(packet):
    prospective=packet['scope'].get('schema') in PROSPECTIVE_SCOPES
    require(('prospective_material' in packet)==prospective,'PROSPECTIVE_PACKET_SCHEMA')
    if not prospective:return {}
    data=packet['prospective_material']
    require(type(data) is dict and 0<len(data)<=256 and all(type(v) is str for v in data.values()),
            'PROSPECTIVE_PACKET_MATERIAL')
    try:actual={h:base64.b64decode(v,validate=True) for h,v in data.items()}
    except ValueError:raise Hold('PUBLIC_OPERATOR_PROSPECTIVE_PACKET_MATERIAL') from None
    required=prospective_binding(packet['scope'],packet['baseline'],actual)
    require(set(required)==set(actual),'PROSPECTIVE_PACKET_EXACT_MATERIAL')
    return parse(actual[packet['scope']['prospective_binding_sha256']])


def application_coordinates(reference):
    """Source coordinates, never a claim that the legacy install has this origin."""
    replacement=reference.get('schema')=='TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1'
    row=reference['artifact']['application'] if replacement else reference
    require(all(type(row.get(k)) is str and re.fullmatch('[a-f0-9]{40}',row[k])
                for k in ('commit','tree')) and
            re.fullmatch('[a-f0-9]{64}',reference.get('origin_sha256','')),'APPLICATION_COORDINATE_BINDING')
    result={k:row[k] for k in ('commit','tree')}
    result['origin_sha256']=reference['origin_sha256']
    if replacement:result['binding_kind']='PROSPECTIVE_REPLACEMENT_NOT_LEGACY_ORIGIN'
    return result


def parse(raw):
    def pairs(items):
        value = {}
        for k, v in items:
            require(k not in value, 'DUPLICATE_KEY')
            value[k] = v
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Hold('PUBLIC_OPERATOR_JSON_CONSTANT')))


HTTP_READER = r'''import hashlib,json,sys,time,urllib.error,urllib.request
class RedirectDenied(Exception):pass
class OutputLimit(Exception):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise RedirectDenied()
try:
 value=json.load(sys.stdin);endpoint=value['endpoint'];deadline=value['deadline']
 if time.monotonic()>=deadline:raise TimeoutError()
 request=urllib.request.Request(endpoint['url'],method=endpoint['method'],headers={
  'User-Agent':'TU1NZ-bound-readonly-admission/1',
  **({'Host':endpoint['host_header']} if endpoint['host_header'] else {})})
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 try:response=opener.open(request,timeout=min(2,max(.001,deadline-time.monotonic())))
 except urllib.error.HTTPError as error:response=error
 with response:
  raw=response.read(1024*1024+1)
  if len(raw)>1024*1024:raise OutputLimit()
  result={'status':response.status,'body_sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
 print(json.dumps(result,sort_keys=True))
except BaseException as error:
 code=('HTTP_REDIRECT_NOT_ADMITTED' if isinstance(error,RedirectDenied) else
       'HTTP_OUTPUT_LIMIT' if isinstance(error,OutputLimit) else 'HTTP_READ_UNKNOWN')
 print(json.dumps({'error':code}));sys.exit(3)
'''
HTTP_CLEANUP = frozenset(('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_HTTP_CHILD_KILL_UNKNOWN',
                         'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_HTTP_CHILD_END_UNKNOWN',
                         'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_HTTP_CHILD_PIPE_CLOSE_UNKNOWN'))


def http_cleanup(error):
    """Keep HTTP cleanup separate even through an owner/adapter exception."""
    found = []; seen = set(); current = error
    while current is not None and id(current) not in seen and len(seen) < 32:
        seen.add(id(current))
        for code in getattr(current, '_http_cleanup', ()):
            if code in HTTP_CLEANUP and code not in found: found.append(code)
        current = current.__cause__ or current.__context__
    return found


def http_child(endpoint, deadline):
    # Covers DNS/connect/TLS/headers/slow body, not merely socket inactivity.
    # Only this owned fixed-code child; no shell, credential/proxy environment,
    # imported Host script, daemon, reconnect or reader retry. Reserve cleanup
    # time INSIDE the original absolute budget, never a deadline extension.
    require(time.monotonic() < deadline, 'HTTP_DEADLINE')
    child = None; primary = None; cleanup = []; measured = None
    try:
        child = subprocess.Popen([sys.executable, '-I', '-B', '-S', '-c', HTTP_READER],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd='/', env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, start_new_session=True)
        remaining = deadline-time.monotonic()
        require(remaining > 0, 'HTTP_DEADLINE')
        reserve = min(.25, remaining/4)
        raw, _stderr = child.communicate(canonical({'endpoint': endpoint, 'deadline': deadline}),
                                         timeout=remaining-reserve)
        require(len(raw) <= 4096 and time.monotonic() < deadline, 'HTTP_OUTPUT_OR_DEADLINE')
        measured = parse(raw)
        if type(measured) is dict and set(measured) == {'error'}:
            require(measured['error'] in ('HTTP_REDIRECT_NOT_ADMITTED', 'HTTP_OUTPUT_LIMIT', 'HTTP_READ_UNKNOWN'),
                    'HTTP_CHILD_PROTOCOL')
            raise Hold('PUBLIC_OPERATOR_'+measured['error'])
        require(child.returncode == 0 and type(measured) is dict and
                set(measured) == {'status', 'body_sha256', 'bytes'} and
                type(measured['status']) is int and 100 <= measured['status'] <= 599 and
                type(measured['bytes']) is int and 0 <= measured['bytes'] <= 1024*1024 and
                type(measured['body_sha256']) is str and re.fullmatch('[a-f0-9]{64}', measured['body_sha256']),
                'HTTP_CHILD_PROTOCOL')
    except subprocess.TimeoutExpired:
        primary = Hold('PUBLIC_OPERATOR_HTTP_ABSOLUTE_DEADLINE')
    except BaseException as error: primary = error
    finally:
        if child is not None:
            if child.poll() is None:
                try: child.kill()
                except ProcessLookupError: pass
                except BaseException: cleanup.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_HTTP_CHILD_KILL_UNKNOWN')
            try: child.wait(timeout=max(0, deadline-time.monotonic()))
            except BaseException: cleanup.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_HTTP_CHILD_END_UNKNOWN')
            for stream in (child.stdin, child.stdout, child.stderr):
                try:
                    if not stream.closed: stream.close()
                except BaseException:
                    if not stream.closed: cleanup.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_HTTP_CHILD_PIPE_CLOSE_UNKNOWN')
    if cleanup and primary is None: primary = Hold('PUBLIC_OPERATOR_HTTP_CHILD_CLEANUP_UNCONFIRMED')
    if primary is not None:
        primary._http_cleanup = tuple(cleanup)
        primary.client_cleanup = list(getattr(primary, 'client_cleanup', ())) + cleanup
        raise primary
    require(time.monotonic() < deadline, 'HTTP_DEADLINE')
    return measured


def measured_http(endpoint, *, deadline, location):
    require(set(endpoint) == {'stage', 'location', 'url', 'method', 'host_header', 'status', 'body_sha256'}
            and endpoint['location'] == location, 'HTTP_EXPECTED_SCHEMA')
    u = urllib.parse.urlsplit(endpoint['url'])
    require(not u.username and not u.password and not u.query and not u.fragment and
            u.path in ('', '/', '/adult', '/adult/', '/health', '/adult/health', '/privacy', '/terms',
                       '/imprint', '/adult/privacy', '/adult/terms', '/adult/imprint'), 'HTTP_SCOPE')
    require(endpoint['method'] in ('GET', 'HEAD') and
            (u.path not in ('', '/', '/adult', '/adult/') or endpoint['method'] == 'HEAD'
             or u.hostname == 'lighting.tu1nz.com'), 'NO_ANALYTICS_OR_PROVIDER_TEST')
    if location == 'host':
        require(u.scheme == 'http' and u.hostname in ('127.0.0.1', 'localhost', '::1') and
                endpoint['host_header'] in PUBLIC_HOSTS | {None}, 'HOST_HTTP_LOOPBACK_ONLY')
    else:
        require(location == 'client' and u.scheme == 'https' and u.hostname in PUBLIC_HOSTS and
                u.port in (None, 443) and endpoint['host_header'] is None, 'CLIENT_HTTP_SCOPE')
    measured = http_child(endpoint, deadline)
    require(measured['status'] == endpoint['status'] and measured['body_sha256'] == endpoint['body_sha256'],
            'ACTUAL_HTTP_DIFFERENT_OR_UNKNOWN')
    return measured


def private_read(path, limit=MAX_FRAME):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        a = os.fstat(fd)
        require(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_uid == os.geteuid()
                and stat.S_IMODE(a.st_mode) == 0o600 and a.st_size <= limit, 'PRIVATE_INPUT')
        raw = os.pread(fd, a.st_size+1, 0); b = os.fstat(fd); c = os.lstat(path)
        require(len(raw) == a.st_size and (a.st_dev, a.st_ino, a.st_mtime_ns, a.st_ctime_ns, a.st_size) ==
                (b.st_dev, b.st_ino, b.st_mtime_ns, b.st_ctime_ns, b.st_size) and
                (a.st_dev, a.st_ino) == (c.st_dev, c.st_ino), 'PRIVATE_INPUT_CHANGED')
        return raw
    finally:
        os.close(fd)


class Wire:
    def __init__(self, incoming, outgoing, *, deadline):
        self.incoming, self.outgoing, self.deadline = incoming, outgoing, deadline
        self.sequence = 0

    def _read(self, count):
        out = bytearray()
        while len(out) < count:
            remaining = self.deadline-time.monotonic()
            require(remaining > 0 and select.select([self.incoming], [], [], remaining)[0], 'WIRE_DEADLINE')
            chunk = os.read(self.incoming, count-len(out))
            require(chunk, 'WIRE_LOST_NO_RETRY')
            out.extend(chunk)
        return bytes(out)

    def receive(self):
        length = int.from_bytes(self._read(4), 'big')
        require(0 < length <= MAX_FRAME, 'FRAME_SIZE')
        return parse(self._read(length))

    def send(self, value):
        raw = canonical(value)
        require(0 < len(raw) <= MAX_FRAME, 'FRAME_SIZE')
        packet = memoryview(len(raw).to_bytes(4, 'big')+raw)
        while packet:
            remaining = self.deadline-time.monotonic()
            require(remaining > 0 and select.select([], [self.outgoing], [], remaining)[1], 'WIRE_DEADLINE')
            size = os.write(self.outgoing, packet)
            require(size > 0, 'WIRE_LOST_NO_RETRY')
            packet = packet[size:]


def exclusive(parent, name, raw):
    require('/' not in name and name not in ('.', '..') and len(raw) <= MAX_FRAME, 'RECORD_BOUND')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            size = os.write(fd, view); require(size > 0, 'SHORT_WRITE'); view = view[size:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        require(os.read(fd, len(raw)+1) == raw, 'RECORD_READBACK')
    finally:
        os.close(fd)


def read_original_chain(parent, binding, *, owner, deadline, client_supplements=False):
    """Bounded, strictly read-only original custody census for one recovery.

    The caller obtains this FD through the fixed compiled custody path and
    proves the old operator/helpers absent plus lock ownership separately.
    This reader neither repairs a tail nor grants any action from a record.
    """
    require(type(binding) is str and re.fullmatch('[0-9a-f]{64}', binding) and
            type(owner) is int and owner >= 0, 'ORIGINAL_CHAIN_ARGUMENTS')
    before = os.fstat(parent)
    require(stat.S_ISDIR(before.st_mode) and before.st_uid == owner and
            stat.S_IMODE(before.st_mode) == 0o700, 'ORIGINAL_CHAIN_DIRECTORY_PROFILE')
    names = sorted(os.listdir(parent))
    extras = {'held.json', 'final.json'} if client_supplements else set()
    require(0 < len(names) <= 512+len(extras) and all(n in extras or
            re.fullmatch('[0-9]{3}-[A-Za-z0-9_]+[.]json', n) for n in names), 'ORIGINAL_CHAIN_NAMES')
    rows = []; supplements = {}; previous = binding; total = 0
    for name in names:
        require(time.monotonic() < deadline, 'ORIGINAL_CHAIN_READ_DEADLINE')
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        if sys.platform == 'linux':flags |= os.O_NOATIME
        fd = os.open(name, flags, dir_fd=parent)
        try:
            first = os.fstat(fd)
            require(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_uid == owner and
                    stat.S_IMODE(first.st_mode) == 0o600 and 0 < first.st_size <= 65536,
                    'ORIGINAL_CHAIN_RECORD_PROFILE')
            raw = os.pread(fd, first.st_size+1, 0); total += len(raw)
            require(len(raw) == first.st_size and total <= (512+len(extras))*65536,
                    'ORIGINAL_CHAIN_BYTES_BOUND')
            after = os.fstat(fd); named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
                      'st_size', 'st_mtime_ns', 'st_ctime_ns')
            identity = {k: getattr(first, k) for k in fields}
            require(all(identity == {k: getattr(s, k) for k in fields} for s in (after, named)),
                    'ORIGINAL_CHAIN_RECORD_CHANGED')
            value = parse(raw)
            require(type(value) is dict and canonical(value) == raw, 'ORIGINAL_CHAIN_RECORD_CANONICAL')
            proof = {'name': name, 'sha256': sha(raw), 'metadata': identity, 'record': value}
            if name in extras:
                require(value.get('type') == name[:-5], 'ORIGINAL_CHAIN_SUPPLEMENT_TYPE')
                supplements[name] = proof
                continue
            sequence = len(rows)+1
            require(sequence <= 512 and set(value) == {'sequence', 'binding', 'previous', 'kind', 'value'} and
                    type(value['sequence']) is int and value['sequence'] == sequence and
                    value['binding'] == binding and value['previous'] == previous and
                    type(value['kind']) is str and re.fullmatch('[A-Za-z0-9_]+', value['kind']) and
                    name == str(sequence).zfill(3)+'-'+value['kind']+'.json',
                    'ORIGINAL_CHAIN_LINK_OR_SEQUENCE')
            previous = proof['sha256']; rows.append(proof)
        finally:
            os.close(fd)
    current = os.fstat(parent)
    fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
    require(rows and sorted(os.listdir(parent)) == names and
            all(getattr(before, k) == getattr(current, k) for k in fields) and
            time.monotonic() < deadline, 'ORIGINAL_CHAIN_DIRECTORY_CHANGED')
    return {'binding': binding, 'tail': previous, 'count': len(rows), 'records': rows,
            'supplements': supplements, 'directory': {k: getattr(current, k) for k in fields}}


def original_chain_pair(mac, host, *, binding, ready_sha256):
    """Validate prefix/tails, never reconstruct original acknowledgements.

    The sole possible mismatch is ONE valid Mac-only tail: LinkedRecords waits
    for that durable Mac ACK before writing its Host mirror. Divergence, a Host
    lead, a larger gap, and missing beidseitiges READY all remain HOLD.
    Fresh process/data/files/probe admission and a bound original failure are
    still required elsewhere; these two hashes are not recovery permission.
    """
    require(type(ready_sha256) is str and re.fullmatch('[0-9a-f]{64}', ready_sha256),
            'ORIGINAL_READY_HASH')
    for snapshot in (mac, host):
        require(type(snapshot) is dict and snapshot.get('binding') == binding and
                type(snapshot.get('records')) is list and type(snapshot.get('count')) is int and
                snapshot['count'] == len(snapshot['records']) and 0 < snapshot['count'] <= 512,
                'ORIGINAL_CHAIN_SNAPSHOT')
        previous = binding
        for number, proof in enumerate(snapshot['records'], 1):
            row = proof.get('record'); raw = canonical(row)
            require(type(row) is dict and set(row) == {'sequence', 'binding', 'previous', 'kind', 'value'} and
                    type(row['sequence']) is int and row['sequence'] == number and row['binding'] == binding and
                    row['previous'] == previous and type(row['kind']) is str and
                    re.fullmatch('[A-Za-z0-9_]+', row['kind']) and len(raw) <= 65536 and
                    sha(raw) == proof.get('sha256'), 'ORIGINAL_CHAIN_SNAPSHOT_INVALID')
            previous = proof['sha256']
        require(snapshot.get('tail') == previous, 'ORIGINAL_CHAIN_TAIL_INVALID')
    require(host['count'] <= mac['count'] <= host['count']+1, 'ORIGINAL_CHAIN_UNEXPLAINED_GAP')
    require(all(m['sha256'] == h['sha256'] for m, h in zip(mac['records'], host['records'])),
            'ORIGINAL_CHAIN_DIVERGENCE')
    common = [v['record'] for v in host['records']]
    ready = [v for v in common if v['kind'] == 'maintenance_ready']
    require(len(ready) == 1 and type(ready[0]['value']) is dict and
            ready[0]['value'].get('sha256') == ready_sha256 and
            sha(canonical(ready[0]['value'].get('ready'))) == ready_sha256,
            'ORIGINAL_READY_NOT_IN_BOTH_CUSTODIES')
    claims = [v for v in common if v['kind'] == 'flow_claim']
    require(len(claims) == 1 and claims[0]['value'] == {'transaction': 'public-rights-20261014-1'} and
            claims[0]['sequence'] < ready[0]['sequence'],
            'ORIGINAL_TRANSACTION_CLAIM')
    for proof in mac['records']:
        row = proof['record']; value = row['value']
        require(not row['kind'].startswith(('owner_', 'recovery_')) and row['kind'] != 'flow_complete' and
                not (type(value) is dict and
                     (value.get('phase') in ('owner_ready', 'owner_done') or
                      value.get('action') == 'supervised_owner_transaction')),
                'ORIGINAL_OWNER_OR_COMPLETION_EXCLUDES_RECOVERY')
    return {'original_binding': binding, 'mac_tail_sha256': mac['tail'], 'host_tail_sha256': host['tail'],
            'common_records': host['count'], 'ready_sha256': ready_sha256,
            'unconfirmed_mac_tail': mac['records'][-1]['sha256'] if mac['count'] > host['count'] else None,
            'original_ack_reconstructed': False}


def original_chain_manifest(snapshot):
    """Bound the actual Mac read without transferring up to32MiB of history.

    Called only after read_original_chain on the held fixed Mac directory.
    The sole final record is included because it may be the unexplained ACK
    tail. Common bytes are read independently on the Host and compared by
    hash. No original record is created, appended, or called successful.
    """
    rows = snapshot['records']
    require(type(rows) is list and 0 < len(rows) <= 512 and
            snapshot['count'] == len(rows), 'ORIGINAL_MANIFEST_RECORD_BOUND')
    previous = snapshot['binding']; hashes = []
    for index, proof in enumerate(rows, 1):
        row = proof['record']; raw = canonical(row)
        require(type(row) is dict and set(row) == {'sequence', 'binding', 'previous', 'kind', 'value'} and
                type(row['sequence']) is int and row['sequence'] == index and
                row['binding'] == snapshot['binding'] and row['previous'] == previous and
                type(row['kind']) is str and re.fullmatch('[A-Za-z0-9_]+', row['kind']) and
                len(raw) <= 65536 and sha(raw) == proof['sha256'], 'ORIGINAL_MANIFEST_CHAIN_INVALID')
        previous = proof['sha256']; hashes.append(previous)
    require(previous == snapshot['tail'], 'ORIGINAL_MANIFEST_TAIL_INVALID')
    supplements = snapshot['supplements']
    require(type(supplements) is dict and set(supplements) <= {'held.json', 'final.json'},
            'ORIGINAL_MANIFEST_SUPPLEMENTS')
    values = {}
    for name, proof in supplements.items():
        raw = canonical(proof['record'])
        require(type(proof['record']) is dict and proof['record'].get('type') == name[:-5] and
                len(raw) <= 65536 and sha(raw) == proof['sha256'], 'ORIGINAL_MANIFEST_SUPPLEMENT_INVALID')
        values[name] = {'sha256': proof['sha256'], 'record': proof['record']}
    return {'schema': 'TU1NZ_REV4_ORIGINAL_CHAIN_MANIFEST', 'binding': snapshot['binding'],
            'hashes': hashes, 'last_record': rows[-1]['record'], 'supplements': values,
            'snapshot_sha256': sha(canonical(snapshot))}


def original_manifest_pair(manifest, host, *, binding, ready_sha256):
    """Compare independently read custody bytes; this is not an ACK repair.

    The authenticated recovery transport supplies a manifest made from the
    actual fixed Mac custody. Host records supply the matching common bytes.
    The original_chain_pair rules still apply to EVERY common/orphan record.
    Neither a scope document nor a user-provided manifest is an executable
    input to this helper. The actual directory snapshots remain held by their
    respective readers and must be unchanged at subsequent action boundaries.
    """
    require(type(manifest) is dict and set(manifest) ==
            {'schema', 'binding', 'hashes', 'last_record', 'supplements', 'snapshot_sha256'} and
            manifest['schema'] == 'TU1NZ_REV4_ORIGINAL_CHAIN_MANIFEST' and
            manifest['binding'] == binding and type(manifest['hashes']) is list and
            type(host.get('count')) is int and host['count'] <= len(manifest['hashes']) <= host['count']+1 and
            0 < len(manifest['hashes']) <= 512 and
            all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in
                [manifest['snapshot_sha256'], *manifest['hashes']]), 'ORIGINAL_MANIFEST_SCHEMA_OR_GAP')
    hashes = manifest['hashes']
    require(len(host['records']) == host['count'] and all(
            row['sha256'] == hashes[index] for index, row in enumerate(host['records'])),
            'ORIGINAL_MANIFEST_COMMON_BYTES_DIFFER')
    last_raw = canonical(manifest['last_record'])
    require(len(last_raw) <= 65536 and sha(last_raw) == hashes[-1], 'ORIGINAL_MANIFEST_LAST_BYTES')
    # A temporary comparison view ONLY. These entries are never persisted or
    # returned as acknowledgements. The common Host bytes have matching Mac
    # digests; the Mac-only tail, if any, keeps its UNKNOWN outcome.
    rows = list(host['records'])
    if len(hashes) > host['count']:
        rows.append({'sha256': hashes[-1], 'record': manifest['last_record']})
    else:
        require(rows[-1]['record'] == manifest['last_record'], 'ORIGINAL_MANIFEST_FINAL_DIVERGENCE')
    comparison = {'binding': binding, 'count': len(rows), 'tail': hashes[-1], 'records': rows}
    result = original_chain_pair(comparison, host, binding=binding, ready_sha256=ready_sha256)
    # Validate supplement shape and digest independently of an optional value.
    checked = original_chain_manifest({**comparison, 'supplements': manifest['supplements']})
    require(checked['hashes'] == hashes, 'ORIGINAL_MANIFEST_LINKS_DIFFER')
    result['mac_snapshot_sha256'] = manifest['snapshot_sha256']
    result['mac_supplements'] = checked['supplements']
    result['unconfirmed_mac_record'] = manifest['last_record'] if len(hashes) > host['count'] else None
    return result


class Source:
    """In-memory exact old components plus new reviewed operator modules.

    The old guard's unchanged function bodies are loaded without its historical
    filesystem import bootstrap. Its sole dependency is the exact pinned entry
    module. No historical/locked repository import, sys.path or HOME fallback.
    """
    def __init__(self, encoded, hashes):
        require(set(encoded) == set(hashes) == set(MODULES) | set(ASSETS), 'SOURCE_MEMBERS')
        self.bytes = {n: base64.b64decode(v, validate=True) for n, v in encoded.items()}
        require(sum(map(len, self.bytes.values())) <= 3*1024*1024 and
                all(sha(raw) == hashes[n] for n, raw in self.bytes.items()), 'SOURCE_HASH')
        require(all(hashes[k] == h for k, h in CONTROL_PINS.items()), 'UNCHANGED_CONTROL_COMPONENT')
        require(all(hashes[k] == h for k, h in ASSETS.items()), 'UNCHANGED_RUNTIME_COMPONENT')
        require(hashes['r3'] == '101aa8cb37277148d3166059c44e34edf45d5fcfa3e2c93204af44a825df559f',
                'REV4_ORDERING_COMPONENT')
        self.modules = {}

    def load(self, name):
        if name in self.modules:
            return self.modules[name]
        require(name in MODULES, 'MODULE_NAME')
        if name in ('host', 'observe', 'replacement'):
            self.load('context')
        module = types.ModuleType('public_operator_bound_'+name)
        module.__file__ = '<authenticated-memory:'+name+'>'
        self.modules[name] = module
        sys.modules[module.__name__] = module  # dataclass resolves this exact module.
        sys.modules[MODULES[name]] = module
        if name == 'guard':
            entry = self.load('entry'); tree = ast.parse(self.bytes[name])
            nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
            module.__dict__['d'] = entry
            module.__dict__['WEB'] = str(entry.HOST_ROOT)
            module.__dict__['BACKUP'] = str(entry.HOST_STAGING_ROOT)
            module.__dict__['FIELDS'] = frozenset(('device', 'inode', 'uid', 'gid', 'mode', 'type',
                'nlink', 'size', 'mtime_ns', 'ctime_ns', 'attrs', 'flags'))
            code = compile(ast.Module(body=nodes, type_ignores=[]), module.__file__, 'exec')
        else:
            code = compile(self.bytes[name], module.__file__, 'exec')
        exec(code, module.__dict__)
        return module


class LinkedRecords:
    """Client write+fsync+readback precedes every confirmed Host record/effect.

    Server output is trusted only through the authenticated code/SSH session;
    a JSON file cannot be substituted for this live bidirectional exchange.
    """
    def __init__(self, wire, binding):
        self.wire, self.binding = wire, binding
        self.sequence = 0; self.previous = binding; self.host_fd = None; self.prior = []
        self.ceiling = wire.deadline
        self.return_confirmed = False; self.approval_bound = False

    @contextmanager
    def limit(self, deadline):
        prior = self.wire.deadline
        self.wire.deadline = min(prior, deadline)
        try:
            require(time.monotonic() < self.wire.deadline, 'LINKED_CUSTODY_DEADLINE')
            yield
            require(time.monotonic() < self.wire.deadline, 'LINKED_CUSTODY_DEADLINE')
        finally:
            self.wire.deadline = min(prior, self.ceiling)

    def cap(self, deadline):
        self.ceiling = min(self.ceiling, deadline)
        self.wire.deadline = min(self.wire.deadline, self.ceiling)

    def bounded(self, deadline):
        parent = self
        class Bound:
            def record(self, kind, value):
                with parent.limit(deadline): return parent.record(kind, value)
        return Bound()

    def record(self, kind, value):
        require(self.sequence < 512 and kind.replace('_', '').isalnum(), 'LINKED_RECORD_BOUND')
        self.sequence += 1
        payload = {'sequence': self.sequence, 'binding': self.binding, 'previous': self.previous,
                   'kind': kind, 'value': value}
        raw = canonical(payload); require(len(raw) <= 65536, 'LINKED_RECORD_SIZE')
        digest = sha(raw)
        self.wire.send({'type': 'durable_record', 'record': payload, 'sha256': digest})
        ack = self.wire.receive()
        expected = {'type': 'persisted', 'sequence': self.sequence, 'sha256': digest}
        held = ack == {**expected, 'control': 'HOLD_BEFORE_OWNER_EFFECT'} and kind == 'owner_object_intent'
        require(ack == expected or held,
                'CLIENT_CUSTODY_ACK_LOST')
        if self.host_fd is not None:
            exclusive(self.host_fd, str(self.sequence).zfill(3)+'-'+kind+'.json', raw)
        else:
            self.prior.append((str(self.sequence).zfill(3)+'-'+kind+'.json', raw))
        self.previous = digest
        # A durable, chain-preserving DENIAL cannot grant an effect. It is a
        # classified operator interruption BEFORE owner_transition can fchown;
        # no fake ACK/lost confirmation is repaired into another permission.
        if held: raise Hold('PUBLIC_OPERATOR_REQUESTED_OWNER_BOUNDARY_HOLD')
        return digest

    def attach(self, fd):
        require(self.host_fd is None, 'HOST_MIRROR_ALREADY_ATTACHED')
        self.host_fd = os.dup(fd)
        for name, raw in self.prior:
            exclusive(self.host_fd, name, raw)
        self.prior.clear()
        self.check()

    def check(self):
        self.wire.send({'type': 'custody_check', 'sequence': self.sequence, 'sha256': self.previous})
        require(self.wire.receive() == {'type': 'custody_current', 'sequence': self.sequence,
                                      'sha256': self.previous}, 'CUSTODY_LOST')

    def http(self, endpoint):
        if endpoint['location'] == 'host':
            measured = measured_http(endpoint, deadline=self.wire.deadline, location='host')
        else:
            self.wire.send({'type': 'http_read', 'endpoint': endpoint})
            measured = self.wire.receive()
            require(set(measured) == {'status', 'body_sha256', 'bytes'} and
                    measured['status'] == endpoint['status'] and
                    measured['body_sha256'] == endpoint['body_sha256'] and
                    type(measured['bytes']) is int and 0 <= measured['bytes'] <= 1024*1024,
                    'CLIENT_HTTP_MEASUREMENT_RED')
        return measured


def owner_entry_marker(*, original_binding, execution_binding, ready_sha256, boot_id, route):
    require(route in ('original', 'recovery-once') and
            all(type(h) is str and re.fullmatch('[0-9a-f]{64}', h)
                for h in (original_binding, execution_binding, ready_sha256)) and
            type(boot_id) is str and
            re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', boot_id) and
            (route != 'original' or original_binding == execution_binding), 'OWNER_ENTRY_BINDING')
    return {'schema': 'TU1NZ_REV4_FIRST_OWNER_ADMISSION', 'transaction': 'public-rights-20261014-1',
            'machine': 'a2166d9d5e0815dc5e452be3d01a1356f4d39e2164446274a43cde5afa7d8aae',
            'owner_plan_sha256': 'e9ac7f6056c42c5bcc67b9823d4cd65740a5037bae816a10431b0c8635dd6b36',
            'original_binding': original_binding, 'execution_binding': execution_binding,
            'ready_sha256': ready_sha256, 'boot_id': boot_id, 'route': route, 'owner_window_seconds': 120}


class MaintenanceLinkedRecords(LinkedRecords):
    """R4 original/recovery marker protocol; legacy channels cannot emit it."""
    def __init__(self, wire, binding, *, original_binding, boot_id, route='original'):
        # Validate the fixed contextual fields without claiming READY exists.
        owner_entry_marker(original_binding=original_binding, execution_binding=binding,
                           ready_sha256='0'*64, boot_id=boot_id, route=route)
        super().__init__(wire, binding)
        self.original_binding, self.boot_id, self.route = original_binding, boot_id, route
        self.owner_entry_started = False

    def begin_owner_admission(self, paths, *, ready_sha256):
        require(self.approval_bound and not self.owner_entry_started and self.host_fd is not None,
                'OWNER_ENTRY_NOT_ADMITTED_OR_REPLAY')
        self.owner_entry_started = True  # includes unknown/one-sided marker
        marker = owner_entry_marker(original_binding=self.original_binding, execution_binding=self.binding,
                                   ready_sha256=ready_sha256, boot_id=self.boot_id, route=self.route)
        path = '/etc/tu1nz/public-web-bootstrap-r3/20261014-1/owner-admission-intent'
        paths.absent(path)
        paths.absent('/opt/tu1nz_repos/lighting-halloween-r1/20261014-1/writer-preparation-r2')
        # The R4 client persists its fixed TX-root marker BEFORE this ACK.
        # Either side's partial outcome consumes admission permanently.
        self.record('owner_admission_intent', marker)
        raw = canonical(marker); metadata = paths.create_file(path, raw)
        actual, row = paths.read(path)
        require(actual == raw and all(row[k] == metadata[k] for k in row if k != 'atime_ns'),
                'OWNER_ENTRY_HOST_READBACK')
        self.record('owner_admission_markers_confirmed', {'sha256': sha(raw), 'host_metadata': row})
        return marker


def recovery_binding(seed):
    """Technical binding of the sole recovery context, not a new approval."""
    hashes = {'original_binding', 'ready_sha256', 'source_sha256', 'artifact_sha256',
              'mac_tail_sha256', 'host_tail_sha256', 'original_failure_sha256', 'fresh_state_sha256'}
    require(type(seed) is dict and set(seed) == hashes | {'schema', 'transaction', 'machine',
            'boot_id', 'owner_plan_sha256', 'original_status', 'unconfirmed_mac_tail'},
            'RECOVERY_BINDING_SCHEMA')
    require(seed['schema'] == 'TU1NZ_MAIN_SERVER_REV4_RECOVERY_ONCE' and
            seed['transaction'] == 'public-rights-20261014-1' and
            seed['machine'] == 'a2166d9d5e0815dc5e452be3d01a1356f4d39e2164446274a43cde5afa7d8aae' and
            seed['owner_plan_sha256'] == 'e9ac7f6056c42c5bcc67b9823d4cd65740a5037bae816a10431b0c8635dd6b36' and
            seed['original_status'] == 'FAILED_HOLD' and type(seed['boot_id']) is str and
            re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', seed['boot_id']) and
            all(type(seed[k]) is str and re.fullmatch('[0-9a-f]{64}', seed[k]) for k in hashes) and
            (seed['unconfirmed_mac_tail'] is None or seed['unconfirmed_mac_tail'] == seed['mac_tail_sha256']),
            'RECOVERY_FIXED_BINDING')
    return sha(canonical(seed))


class RecoveryLinkedRecords(MaintenanceLinkedRecords):
    """An additive chain only; no handle to the original journal is accepted.

    Host and Mac recovery-entry markers must already exist and be matched by
    the admitted session. Failure at any point spends the one recovery entry.
    This class does not reconnect, repair prior ACKs, or remove original HOLD.
    """
    def __init__(self, wire, seed):
        self.seed = parse(canonical(seed))
        super().__init__(wire, recovery_binding(self.seed), original_binding=self.seed['original_binding'],
                         boot_id=self.seed['boot_id'], route='recovery-once')

    def attach(self, fd):
        require(self.sequence == 0 and not self.prior and self.host_fd is None,
                'RECOVERY_CHAIN_ATTACH_ONCE')
        expected = '/etc/tu1nz/public-web-bootstrap-r3/20261014-1/recovery-once/intents'
        current = os.fstat(fd)
        require(stat.S_ISDIR(current.st_mode) and current.st_uid == current.st_gid == 0 and
                stat.S_IMODE(current.st_mode) == 0o700 and not os.listdir(fd) and
                os.readlink('/proc/self/fd/'+str(fd)) == expected, 'RECOVERY_CHAIN_FIXED_NEW_DIRECTORY')
        named = os.stat(expected, follow_symlinks=False)
        require((current.st_dev, current.st_ino) == (named.st_dev, named.st_ino),
                'RECOVERY_CHAIN_DIRECTORY_BINDING')
        super().attach(fd)

    def record(self, kind, value):
        require(self.host_fd is not None and kind not in
                ('maintenance_ready', 'flow_claim', 'flow_complete', 'prestate_read_witness'),
                'RECOVERY_CANNOT_REWRITE_ORIGINAL_HISTORY')
        if self.sequence == 0:
            require(kind == 'recovery_context' and value == self.seed, 'RECOVERY_FIRST_CONTEXT_REQUIRED')
        else:
            require(kind != 'recovery_context', 'RECOVERY_CONTEXT_NO_REPLAY')
        return super().record(kind, value)
