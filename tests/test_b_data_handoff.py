"""Synthetic local data only; no Host, providers, production dump or secret."""
from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('b_handoff', Path(__file__).resolve().parents[1] /
                                             'scripts/tu1nz_b_data_handoff.py')
b = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(b)
CATALOG = b.parse(b.CATALOG.read_bytes())


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def chosen():
    return {'schema': 'TU1NZ_B_DATA_SELECTION_V2', 'source_app': CATALOG['source_app'],
            'database': 'tu1nz_adult_commercial_s3', 'host_inventory_sha256': '1' * 64,
            'relations': [{'name': n, 'disposition': 'export'} for n in CATALOG['tables']],
            'retained_dependencies': {n: 'retain_old' for n in CATALOG['retained_dependency_relations']},
            'file_dispositions': {p: ('export' if kind in ('aggregate', 'traffic') else 'retain_old')
                                  for p, kind in CATALOG['fixed_files'].items()},
            'files': [{'source': '/var/lib/tu1nz-adult-public-s9/landing-aggregates.json',
                       'name': 'files/aggregate.json', 'kind': 'aggregate'},
                      {'source': '/var/lib/tu1nz-adult-public-s9/wms-traffic-quality.json',
                       'name': 'files/traffic.json', 'kind': 'traffic'}]}


class Selection(unittest.TestCase):
    def test_explicit_source_relations(self):
        value = b.selection(encoded(chosen()), CATALOG)
        self.assertEqual(len(value['relations']), 34)

    def test_unknown_missing_duplicate_and_injection(self):
        for change in ('unknown', 'missing', 'duplicate', 'injection'):
            v = chosen()
            if change == 'missing': v['relations'].pop()
            elif change == 'duplicate': v['relations'][-1] = v['relations'][0]
            else: v['relations'][0]['name'] = 'unrelated_table' if change == 'unknown' else 't; DROP DATABASE x'
            with self.subTest(change=change), self.assertRaises(b.Denied):
                b.selection(encoded(v), CATALOG)

    def test_required_and_dependent_relations(self):
        for name in ('commercial_s7_waitlist', 'commercial_s8_users'):
            v = chosen()
            next(r for r in v['relations'] if r['name'] == name)['disposition'] = 'retain_old'
            with self.subTest(name=name), self.assertRaises(b.Denied):
                b.selection(encoded(v), CATALOG)

    def test_optional_absence_never_defaulted(self):
        v = chosen()
        for r in v['relations']:
            if r['name'] not in CATALOG['required_tables']: r['disposition'] = 'absent'
        self.assertEqual(len(b.selection(encoded(v), CATALOG)['relations']), 34)
        # This records an externally evidenced disposition, NOT proof of absence.

    def test_s11_guard_dependencies_cannot_be_omitted(self):
        for name in CATALOG['guard_dependencies']:
            v = chosen()
            next(r for r in v['relations'] if r['name'] == name)['disposition'] = 'retain_old'
            with self.subTest(name=name), self.assertRaisesRegex(b.Denied, 'GUARD_DEPENDENCY_CLOSURE'):
                b.selection(encoded(v), CATALOG)

    def test_incoming_fk_and_admission_history_remain_at_old_authority(self):
        for name in CATALOG['retained_dependency_relations']:
            for disposition in ('export', 'absent'):
                v = chosen(); v['retained_dependencies'][name] = disposition
                with self.subTest(name=name, disposition=disposition), self.assertRaises(b.Denied):
                    b.selection(encoded(v), CATALOG)
        v = chosen(); del v['retained_dependencies']['commercial_s11_experience_sessions']
        with self.assertRaises(b.Denied): b.selection(encoded(v), CATALOG)

    def test_legacy_selection_cannot_silently_omit_new_boundary(self):
        v = chosen(); v['schema'] = 'TU1NZ_B_DATA_SELECTION_V1'
        with self.assertRaises(b.Denied): b.selection(encoded(v), CATALOG)

    def test_no_secret_git_runtime_or_traversal_selection(self):
        for source in ('/etc/tu1nz/adult-commercial-s7-form.secret',
                       '/etc/tu1nz/adult-commercial-s7-database.dsn',
                       '/opt/tu1nz_repos/control/.git/index',
                       '/var/www/lighting.tu1nz.com/.git/config',
                       '/var/www/lighting.tu1nz.com/.venv/bin/python',
                       '/var/www/lighting.tu1nz.com/assets/key.pem',
                       '/var/www/lighting.tu1nz.com/../other/index.html'):
            v = chosen(); v['files'] = [{'source': source, 'name': 'files/item', 'kind': 'bytes'}]
            with self.subTest(source=source), self.assertRaises(b.Denied):
                b.selection(encoded(v), CATALOG)

    def test_exact_config_and_individual_lighting(self):
        v = chosen()
        v['files'] += [{'source': '/var/www/lighting.tu1nz.com/assets/products/a.webp',
                        'name': 'files/product.webp', 'kind': 'bytes'},
                       {'source': '/etc/tu1nz/adult-commercial-s7-public.json',
                        'name': 'files/s7.json', 'kind': 'json'}]
        v['file_dispositions']['/etc/tu1nz/adult-commercial-s7-public.json'] = 'export'
        b.selection(encoded(v), CATALOG)

    def test_fixed_file_omission_requires_explicit_disposition(self):
        v = chosen(); v['files'].pop()
        with self.assertRaises(b.Denied): b.selection(encoded(v), CATALOG)
        v['file_dispositions'].pop('/var/lib/tausendunde1nz/mychatbuddy/mychatbuddy.db')
        with self.assertRaises(b.Denied): b.selection(encoded(v), CATALOG)

    def test_reject_claims_and_bad_bindings(self):
        for key, value in (('host_green', True), ('source_app', '0' * 40),
                           ('database', 'unrelated'), ('host_inventory_sha256', None)):
            v = chosen(); v[key] = value
            with self.subTest(key=key), self.assertRaises(b.Denied): b.selection(encoded(v), CATALOG)

    def test_render_no_exec_or_credential(self):
        v = b.selection(encoded(chosen()), CATALOG)
        argv = b.dump_argv(v, '00000003-0000001B-1')
        self.assertIn('--data-only', argv)
        self.assertIn('--strict-names', argv)
        self.assertEqual(sum(a.startswith('--table=public.') for a in argv), 34)
        self.assertFalse(any('*' in a or 'password' in a for a in argv))
        for bad in ('service=evil', '1;DELETE', '000-0-1 --schema=x', '', None):
            with self.assertRaises(b.Denied): b.dump_argv(v, bad)

    def test_duplicate_json_and_nonfinite(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff', b'not json'):
            with self.assertRaises(b.Denied): b.parse(raw)


class Package(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='tu1nz-b-synthetic-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / 'package'
        self.root.mkdir(mode=0o700)
        (self.root / 'files').mkdir(mode=0o700)
        self.selected = b.selection(encoded(chosen()), CATALOG)
        self.selected_hash = b.sha(encoded(chosen()))
        self.data = {'postgres.data.dump': b'SYNTHETIC_NOT_A_VALID_PG_DUMP',
                     'postgres.capture.json': b'{"synthetic":true}',
                     'schema.observed.sql': b'-- SYNTHETIC DO NOT EXECUTE',
                     'files/aggregate.json': b'{"2026-10-18|LANDING_VIEW|direct|none":2}',
                     'files/traffic.json': b'{"2026-10-18|LANDING|HUMAN_LIKE":2}'}
        for name, raw in self.data.items(): (self.root / name).write_bytes(raw)
        self.manifest = {'schema': 'TU1NZ_B_DATA_PACKAGE_V1', 'phase': 'precopy',
                         'selection_sha256': self.selected_hash, 'capture_receipt_sha256': '2' * 64,
                         'artifacts': [{'name': n, 'sha256': b.sha(raw), 'size': len(raw)}
                                       for n, raw in self.data.items()]}

    def check(self):
        raw = encoded(self.manifest)
        return b.verify_package(self.root, raw, b.sha(raw), self.selected, self.selected_hash)

    def test_bytes_not_dump_or_restore_admission(self):
        result = self.check()
        self.assertFalse(result['host_admission'])
        self.assertEqual(result['restore'], 'UNPROVEN')
        self.assertEqual(result['writer_freedom'], 'UNPROVEN')

    def test_final_label_does_not_create_final_consistency(self):
        self.manifest['phase'] = 'final'
        self.assertEqual(self.check()['cross_store_consistency'], 'UNPROVEN')
        self.manifest['writers_closed'] = True
        with self.assertRaises(b.Denied): self.check()

    def test_missing_extra_file_and_hardlink_symlink(self):
        path = self.root / 'postgres.data.dump'
        path.unlink()
        with self.assertRaises(b.Denied): self.check()
        path.write_bytes(self.data[path.name])
        extra = self.root / 'not-selected.secret'; extra.write_bytes(b'SYNTHETIC')
        with self.assertRaises(b.Denied): self.check()
        extra.unlink()
        link = self.root / 'another-link'; os.link(path, link)
        with self.assertRaises(b.Denied): self.check()
        link.unlink()
        path.unlink(); path.symlink_to('/dev/null')
        with self.assertRaises(b.Denied): self.check()

    def test_bad_hash_incomplete_export(self):
        (self.root / 'postgres.data.dump').write_bytes(b'partial')
        with self.assertRaises(b.Denied): self.check()

    def test_extra_empty_directory_and_linked_parent_are_rejected(self):
        extra = self.root / 'foreign'; extra.mkdir()
        with self.assertRaises(b.Denied): self.check()
        extra.rmdir()
        actual = self.root / 'files'; moved = self.root.parent / 'other-files'
        actual.rename(moved); actual.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(b.Denied): self.check()

    def test_small_input_reader_does_not_follow_link_or_open_fifo(self):
        path = Path(self.tmp.name) / 'linked'; path.symlink_to(self.root / 'postgres.capture.json')
        with self.assertRaises(OSError): b.read_small(path)
        if hasattr(os, 'mkfifo'):
            fifo = Path(self.tmp.name) / 'fifo'; os.mkfifo(fifo)
            with self.assertRaises(b.Denied): b.read_small(fifo)

    def test_unlisted_path_and_wrong_manifest(self):
        self.manifest['artifacts'][0]['name'] = '../../not-allowed'
        with self.assertRaises(b.Denied): self.check()
        with self.assertRaises(b.Denied):
            b.verify_package(self.root, encoded(self.manifest), '3' * 64,
                             self.selected, self.selected_hash)

    def test_changed_after_read(self):
        original = b.hash_fd
        def change(fd, limit):
            result = original(fd, limit)
            path = self.root / 'postgres.data.dump'
            if os.fstat(fd).st_ino == path.stat().st_ino:
                path.rename(self.root / 'replaced')
                path.write_bytes(self.data['postgres.data.dump'])
            return result
        with patch.object(b, 'hash_fd', change), self.assertRaises(b.Denied): self.check()

    def test_invalid_counter_types_and_unknown_events(self):
        for raw in (b'{"2026-10-18|LANDING_VIEW|d|n":true}',
                    b'{"2026-10-18|UNKNOWN|d|n":1}', b'{"x":-1}'):
            with self.assertRaises(b.Denied): b.counter(raw, 'aggregate')
        with self.assertRaises(b.Denied): b.counter(b'{"2026-10-18|LANDING|BAD":1}', 'traffic')

    def test_cli_errors_do_not_echo_private_inputs(self):
        select = Path(self.tmp.name) / 'selection.json'; select.write_text('SYNTHETIC_PRIVATE_ERROR')
        output = io.StringIO()
        with redirect_stdout(output):
            result = b.main(['--selection', str(select), '--selection-sha256', '4' * 64,
                             'render', '--snapshot', '0-0-1'])
        self.assertEqual(result, 2)
        self.assertNotIn('SYNTHETIC_PRIVATE_ERROR', output.getvalue())

    def test_actual_cli_render_and_verify_remain_non_admitting(self):
        select = Path(self.tmp.name) / 'selection.json'; select.write_bytes(encoded(chosen()))
        manifest = Path(self.tmp.name) / 'manifest.json'; manifest.write_bytes(encoded(self.manifest))
        common = ['--selection', str(select), '--selection-sha256', self.selected_hash]
        for extra in (['render', '--snapshot', '0-0-1'],
                      ['verify', '--directory', str(self.root), '--manifest', str(manifest),
                       '--manifest-sha256', b.sha(manifest.read_bytes())]):
            output = io.StringIO()
            with redirect_stdout(output): result = b.main(common + extra)
            self.assertEqual(result, 0)
            self.assertFalse(json.loads(output.getvalue())['host_admission'])


class SQLiteSnapshot(unittest.TestCase):
    def test_online_backup_includes_committed_wal_without_running_application(self):
        with tempfile.TemporaryDirectory(prefix='tu1nz-b-sqlite-synthetic-') as tmp:
            src = sqlite3.connect(str(Path(tmp) / 'source.db'))
            dst = sqlite3.connect(str(Path(tmp) / 'snapshot.db'))
            try:
                src.execute('PRAGMA journal_mode=WAL')
                src.execute('CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT)')
                src.execute("INSERT INTO items VALUES(1,'SYNTHETIC')"); src.commit()
                src.backup(dst)
                self.assertEqual(dst.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                self.assertEqual(dst.execute('SELECT count(*) FROM items').fetchone()[0], 1)
                dst.execute('INSERT INTO items VALUES(2,\'SYNTHETIC\')'); dst.commit()
                self.assertEqual(src.execute('SELECT count(*) FROM items').fetchone()[0], 1)
            finally:
                dst.close(); src.close()


if __name__ == '__main__': unittest.main()
