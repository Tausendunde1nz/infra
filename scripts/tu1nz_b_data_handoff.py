#!/usr/bin/env python3
"""B data selection/byte verifier, NOT a Host admission or execution tool.

No subprocess, network, archive extraction, export, restore or writer action.
An externally held hash detects changes to a selection/manifest; it is not an
origin, approval, writer-freedom, cross-store-consistency or restore attestation.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import date
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

CATALOG = Path(__file__).resolve().parent.parent / 'manifests/b-data-writer-handoff-r1.json'
MAX_JSON = 8 * 1024 * 1024
MAX_FILES = 256
MAX_BYTES = 16 * 1024 * 1024 * 1024


class Denied(ValueError):
    """Only fixed non-sensitive codes may leave the CLI."""


def need(condition, code):
    if not condition:
        raise Denied(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    obj = {}
    for key, value in pairs:
        need(key not in obj, 'DUPLICATE_JSON_KEY')
        obj[key] = value
    return obj


def parse(raw):
    need(len(raw) <= MAX_JSON, 'JSON_LIMIT')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Denied('NONFINITE_JSON')))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise Denied('INVALID_JSON') from None


def digest(value):
    need(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None
         and value != '0' * 64, 'HASH_REQUIRED')
    return value


def relative(value):
    need(isinstance(value, str) and 0 < len(value) < 256, 'PATH_INVALID')
    p = PurePosixPath(value)
    need(not p.is_absolute() and str(p) == value and
         all(re.fullmatch('[A-Za-z0-9_-][A-Za-z0-9_.-]*', c) and c not in ('.', '..')
             for c in p.parts), 'PATH_INVALID')
    return p


def fields(value, expected):
    need(isinstance(value, dict) and set(value) == set(expected), 'FIELDS_INVALID')


def selection(raw, catalog):
    value = parse(raw)
    fields(value, ('schema', 'source_app', 'database', 'host_inventory_sha256',
                   'relations', 'retained_dependencies', 'file_dispositions', 'files'))
    need(value['schema'] == 'TU1NZ_B_DATA_SELECTION_V2' and
         value['source_app'] == catalog['source_app'] and
         value['database'] == catalog['database_source_default_not_live_attestation'], 'SOURCE_BINDING')
    digest(value['host_inventory_sha256'])
    rows = value['relations']
    need(isinstance(rows, list) and len(rows) == len(catalog['tables']), 'RELATION_COVERAGE')
    seen = {}
    for row in rows:
        fields(row, ('name', 'disposition'))
        name, disposition = row['name'], row['disposition']
        need(isinstance(name, str) and name in catalog['tables'] and name not in seen,
             'RELATION_SELECTION')
        need(disposition in ('export', 'retain_old', 'absent'), 'RELATION_DISPOSITION')
        seen[name] = disposition
    need(all(seen[n] == 'export' for n in catalog['required_tables']), 'REQUIRED_TABLE')
    for child, parents in catalog['foreign_keys'].items():
        need(seen[child] != 'export' or all(seen[p] == 'export' for p in parents), 'FOREIGN_KEY_CLOSURE')
    for child, parents in catalog['guard_dependencies'].items():
        need(seen[child] != 'export' or all(seen[p] == 'export' for p in parents),
             'GUARD_DEPENDENCY_CLOSURE')
    retained = value['retained_dependencies']
    fields(retained, catalog['retained_dependency_relations'])
    # Explicit custody boundary, NOT a claim of absence, writer freedom or
    # permission to create empty admission/audit histories on the new basis.
    need(all(v == 'retain_old' for v in retained.values()), 'RETAINED_DEPENDENCY_BOUNDARY')
    files = value['files']
    need(isinstance(files, list) and len(files) <= MAX_FILES - 3, 'FILE_LIMIT')
    sources, names = set(), set()
    dispositions = value['file_dispositions']
    fields(dispositions, catalog['fixed_files'])
    need(all(v in ('export', 'retain_old', 'absent') for v in dispositions.values()),
         'FILE_DISPOSITION')
    for row in files:
        fields(row, ('source', 'name', 'kind'))
        source, name, kind = row['source'], row['name'], row['kind']
        relative(name)
        need(name.startswith('files/') and name not in names, 'FILE_SELECTION')
        need(isinstance(source, str) and source not in sources, 'FILE_SELECTION')
        if source in catalog['fixed_files']:
            need(kind == catalog['fixed_files'][source], 'FILE_KIND')
        else:
            prefix = catalog['lighting_root'] + '/'
            need(source.startswith(prefix) and kind == 'bytes', 'FILE_SOURCE')
            suffix = source[len(prefix):]
            relative(suffix)
            need(not any(part.lower() in ('.git', '.venv', 'venv', 'secrets')
                         for part in PurePosixPath(suffix).parts) and
                 not suffix.lower().endswith(('.key', '.pem', '.secret', '.dsn', '.env')),
                 'SECRET_OR_RUNTIME_PATH')
        sources.add(source)
        names.add(name)
    need(all((dispositions[p] == 'export') == (p in sources) for p in catalog['fixed_files']),
         'FIXED_FILE_COVERAGE')
    return value


def dump_argv(value, snapshot):
    # An exported snapshot token, never a connection string or caller option.
    need(isinstance(snapshot, str) and re.fullmatch('[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9]+', snapshot),
         'SNAPSHOT_TOKEN')
    args = ['pg_dump', '--dbname=service=tu1nz_b_export', '--format=custom',
            '--data-only', '--no-owner', '--no-privileges', '--strict-names',
            '--lock-wait-timeout=5000', '--snapshot=' + snapshot]
    args.extend('--table=public.' + row['name'] for row in value['relations']
                if row['disposition'] == 'export')
    return args


def counts_sql(value):
    names = sorted(row['name'] for row in value['relations'] if row['disposition'] == 'export')
    # Catalog identifiers only. The snapshot lives in the separately held
    # REPEATABLE READ READ ONLY source connection described by the contract.
    return '\n'.join("SELECT '" + name + "', count(*) FROM ONLY public.\"" + name + '\";'
                     for name in names)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def directory(path, stack):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'ABSOLUTE_DIRECTORY_REQUIRED')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    stack.callback(os.close, fd)
    for part in path.parts[1:]:
        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        stack.callback(os.close, fd)
    return fd


def opened(root, name, stack):
    parts = relative(name).parts
    parent = root
    guards = []
    for part in parts[:-1]:
        parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        stack.callback(os.close, parent)
        guards.append((parent, identity(os.fstat(parent))))
    fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    stack.callback(os.close, fd)
    s = os.fstat(fd)
    need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'REGULAR_SINGLE_LINK_REQUIRED')
    return fd, parent, parts[-1], identity(s), guards


def hash_fd(fd, limit):
    before = identity(os.fstat(fd))
    need(before[6] <= limit, 'BYTE_LIMIT')
    h, count = hashlib.sha256(), 0
    while block := os.read(fd, 1024 * 1024):
        count += len(block)
        need(count <= limit, 'BYTE_LIMIT')
        h.update(block)
    need(identity(os.fstat(fd)) == before and count == before[6], 'READ_CHANGED')
    return h.hexdigest(), count


def read_small(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'REGULAR_SINGLE_LINK_REQUIRED')
        before = identity(info)
        need(info.st_size <= MAX_JSON, 'JSON_LIMIT')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(MAX_JSON + 1)
        need(len(raw) <= MAX_JSON and identity(os.fstat(fd)) == before, 'READ_CHANGED')
        return raw
    finally:
        os.close(fd)


def tree_names(fd, expected, prefix='', found=None):
    """Metadata-only census. Never reads unexpected bytes or follows links."""
    found = set() if found is None else found
    need(prefix.count('/') <= 8, 'PATH_DEPTH')
    for name in os.listdir(fd):
        full = prefix + name
        relative(full)
        s = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(s.st_mode):
            need(any(p.startswith(full + '/') for p in expected), 'UNEXPECTED_DIRECTORY')
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                tree_names(child, expected, full + '/', found)
            finally:
                os.close(child)
        else:
            need(stat.S_ISREG(s.st_mode), 'UNEXPECTED_OBJECT')
            found.add(full)
            need(len(found) <= MAX_FILES, 'FILE_LIMIT')
    return found


def counter(raw, kind):
    value = parse(raw)
    need(isinstance(value, dict), 'COUNTER_SHAPE')
    for key, count in value.items():
        need(isinstance(key, str) and type(count) is int and count >= 0, 'COUNTER_VALUE')
        parts = key.split('|')
        need(len(parts) == (4 if kind == 'aggregate' else 3), 'COUNTER_KEY')
        try:
            date.fromisoformat(parts[0])
        except ValueError:
            raise Denied('COUNTER_DATE') from None
        if kind == 'aggregate':
            need(parts[1] in ('LANDING_VIEW', 'TELEGRAM_CTA', 'COMMUNITY_CTA') and
                 all(0 < len(p) <= 64 for p in parts[2:]), 'COUNTER_EVENT')
        else:
            need(parts[1] in ('LANDING', 'TELEGRAM_CTA', 'COMMUNITY_CTA') and
                 parts[2] in ('HUMAN_LIKE', 'KNOWN_AUTOMATION', 'KNOWN_HEALTH',
                              'BOT_OR_CRAWLER', 'PREFETCH_OR_PREVIEW', 'UNKNOWN'), 'COUNTER_EVENT')


def verify_package(root, manifest_raw, expected_manifest, selected, selection_hash):
    need(sha(manifest_raw) == digest(expected_manifest), 'MANIFEST_HASH')
    manifest = parse(manifest_raw)
    fields(manifest, ('schema', 'phase', 'selection_sha256', 'capture_receipt_sha256', 'artifacts'))
    need(manifest['schema'] == 'TU1NZ_B_DATA_PACKAGE_V1' and
         manifest['phase'] in ('precopy', 'final') and
         manifest['selection_sha256'] == selection_hash, 'PACKAGE_BINDING')
    digest(manifest['capture_receipt_sha256'])
    rows = manifest['artifacts']
    kinds = {row['name']: row['kind'] for row in selected['files']}
    expected = set(kinds) | {'postgres.data.dump', 'postgres.capture.json', 'schema.observed.sql'}
    need(isinstance(rows, list) and len(rows) == len(expected), 'ARTIFACT_COVERAGE')
    seen, opened_files = set(), []
    with ExitStack() as stack:
        root_fd = directory(root, stack)
        root_before = identity(os.fstat(root_fd))
        need(tree_names(root_fd, expected) == expected, 'UNLISTED_OR_MISSING_ARTIFACT')
        total = 0
        for row in rows:
            fields(row, ('name', 'sha256', 'size'))
            name = row['name']
            need(isinstance(name, str) and name in expected and name not in seen, 'ARTIFACT_SELECTION')
            need(type(row['size']) is int and 0 <= row['size'] <= MAX_BYTES, 'BYTE_LIMIT')
            total += row['size']
            need(total <= MAX_BYTES, 'BYTE_LIMIT')
            fd, parent, leaf, before, guards = opened(root_fd, name, stack)
            actual, count = hash_fd(fd, MAX_BYTES)
            need(actual == digest(row['sha256']) and count == row['size'], 'ARTIFACT_HASH')
            kind = kinds.get(name)
            if kind in ('json', 'aggregate', 'traffic') or name == 'postgres.capture.json':
                need(count <= MAX_JSON, 'JSON_LIMIT')
                os.lseek(fd, 0, os.SEEK_SET)
                raw = os.read(fd, count + 1)
                if kind in ('aggregate', 'traffic'):
                    counter(raw, kind)
                else:
                    parse(raw)
            opened_files.append((fd, parent, leaf, before, guards))
            seen.add(name)
        need(seen == expected, 'ARTIFACT_COVERAGE')
        for fd, parent, leaf, before, guards in opened_files:
            need(identity(os.fstat(fd)) == before and
                 identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == before,
                 'PACKAGE_CHANGED')
            need(all(identity(os.fstat(d)) == old for d, old in guards), 'PACKAGE_CHANGED')
        need(identity(os.fstat(root_fd)) == root_before, 'PACKAGE_CHANGED')
        need(tree_names(root_fd, expected) == expected, 'PACKAGE_CHANGED')
    return {'status': 'BYTES_CHECKED_NOT_ADMITTED', 'phase_label': manifest['phase'],
            'artifacts': len(seen), 'host_admission': False, 'writer_freedom': 'UNPROVEN',
            'cross_store_consistency': 'UNPROVEN', 'restore': 'UNPROVEN'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--selection-sha256', required=True)
    sub = parser.add_subparsers(dest='action', required=True)
    render = sub.add_parser('render')
    render.add_argument('--snapshot', required=True)
    verify = sub.add_parser('verify')
    verify.add_argument('--directory', type=Path, required=True)
    verify.add_argument('--manifest', type=Path, required=True)
    verify.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        raw = read_small(args.selection)
        need(sha(raw) == digest(args.selection_sha256), 'SELECTION_HASH')
        selected = selection(raw, parse(read_small(CATALOG)))
        if args.action == 'render':
            result = {'status': 'PLAN_ONLY_NOT_AUTHORIZED', 'host_admission': False,
                      'pg_dump_argv': dump_argv(selected, args.snapshot),
                      'counts_sql_in_same_snapshot': counts_sql(selected)}
        else:
            result = verify_package(args.directory, read_small(args.manifest), args.manifest_sha256,
                                    selected, args.selection_sha256)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        code = str(error) if isinstance(error, Denied) else 'INPUT_OR_IO_INVALID'
        print(json.dumps({'status': 'HOLD', 'code': code, 'host_admission': False}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
