"""R4 maintenance boundary tests; local proofs are not native admission.

The native production-adapter suite must separately exercise actual Linux
renameat2, systemd, fences, failures, real restore and complete time budgets.
"""
import copy
import base64
from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
import zlib
from unittest.mock import Mock, patch
from types import SimpleNamespace
from contextlib import nullcontext

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import tu1nz_public_operator as client  # owns the existing authenticated io loader
import tu1nz_public_operator_io as io
if hasattr(os, 'O_NOATIME'):
    import tu1nz_public_operator_fs as fs
    import tu1nz_public_runtime_transition as transition
else:
    # Pure validator import only, exactly as the existing R5 boundary tests.
    # No claim of Mac support for native Paths or an O_NOATIME fallback.
    with patch.object(os, 'O_NOATIME', 0, create=True):
        import tu1nz_public_operator_fs as fs
        import tu1nz_public_runtime_transition as transition
import tu1nz_public_bootstrap_r3 as r3
import tu1nz_public_operator_context as contexts
import tu1nz_public_operator_observe as observe
import tu1nz_public_operator_runtime_guard as runtime_guard


class OwnedCandidateTests(unittest.TestCase):
    def setUp(self):
        self.raw = b'synthetic complete candidate\n'
        self.row = {'device': 1, 'inode': 123, 'uid': 0, 'gid': 0, 'mode': 0o644,
                    'type': stat.S_IFREG, 'nlink': 1, 'size': len(self.raw),
                    'mtime_ns': 1000, 'ctime_ns': 2000, 'atime_ns': 900,
                    'attrs': {}, 'flags': 0x80000}
        self.expected = {'sha256': io.sha(self.raw), 'metadata': copy.deepcopy(self.row)}

    def test_ready_candidate_requires_exact_ctime(self):
        proof = fs.owned_file_matches(self.raw, self.row, self.expected, moved=False)
        self.assertEqual(proof['ctime_basis'], 'EXACT_READY_CANDIDATE')
        self.row['ctime_ns'] += 1
        with self.assertRaises(io.Hold):
            fs.owned_file_matches(self.raw, self.row, self.expected, moved=False)

    def test_rename_reports_real_ctime_without_mutating_ready_or_inventing_ack(self):
        self.row['ctime_ns'] = 3000
        proof = fs.owned_file_matches(self.raw, self.row, self.expected, moved=True)
        self.assertEqual(proof['metadata']['ctime_ns'], 3000)
        self.assertEqual(self.expected['metadata']['ctime_ns'], 2000)
        self.assertEqual(proof['ctime_basis'], 'CURRENT_RENAME_OBSERVATION')
        self.assertNotIn('ack', proof)

    def test_rename_never_allows_changed_bytes_or_other_metadata(self):
        for key, changed in (('inode', 124), ('device', 2), ('uid', 1001), ('gid', 1001),
                             ('mode', 0o666), ('mtime_ns', 1001), ('nlink', 2),
                             ('type', stat.S_IFLNK), ('flags', 0), ('attrs', {'user.x': 'eA=='})):
            with self.subTest(field=key):
                row = dict(self.row); row[key] = changed
                with self.assertRaises(io.Hold):
                    fs.owned_file_matches(self.raw, row, self.expected, moved=True)
        for changed in (self.raw[:-1], b'x'*len(self.raw)):
            with self.assertRaises(io.Hold):
                fs.owned_file_matches(changed, self.row, self.expected, moved=True)

    def test_missing_extra_or_unsafe_ready_metadata_is_not_adopted(self):
        for key, value in (('nlink', 2), ('attrs', {'user.unbound': 'eA=='}), ('mode', 0o755)):
            expected = copy.deepcopy(self.expected); expected['metadata'][key] = value
            with self.assertRaises(io.Hold):
                fs.owned_file_matches(self.raw, self.row, expected, moved=True)
        missing = copy.deepcopy(self.expected); del missing['metadata']['ctime_ns']
        with self.assertRaises(io.Hold):
            fs.owned_file_matches(self.raw, self.row, missing, moved=True)

    def test_moved_ctime_cannot_predate_ready(self):
        self.row['ctime_ns'] = 1999
        with self.assertRaises(io.Hold):
            fs.owned_file_matches(self.raw, self.row, self.expected, moved=True)


class MaintenanceOrderTests(unittest.TestCase):
    """Fault-injected ordering only; these mocks do not claim native safety."""
    def flow(self, *, fail=None, missing_ready=False, unconfirmed=False):
        tmp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(tmp.cleanup)
        parent = patch.object(r3, 'CUSTODY_PARENT', Path(tmp.name))
        parent.start(); self.addCleanup(parent.stop)
        journal = r3.Journal(tmp.name, 'a'*64); self.addCleanup(journal.close)
        adapter = Mock(); adapter.deadline = time.monotonic()+300
        effects = []
        def observe(phase, *, deadline):
            facts = r3.MaintenanceFlow.required[phase]
            if phase == 'prepared' and missing_ready:facts = frozenset()
            return r3.Observation(r3.TX, journal.binding, phase, frozenset(facts), time.monotonic())
        def perform(action, unit, *, deadline):
            effects.append((action, unit))
            if action == fail:
                if unconfirmed:return None
                raise OSError('synthetic interruption')
            return {'action': action, 'unit': unit, 'outcome': 'CONFIRMED',
                    'cgroup_empty': True, 'no_job': True}
        adapter.observe.side_effect = observe; adapter.perform.side_effect = perform
        return r3.MaintenanceFlow(adapter, journal), effects, adapter

    def test_complete_preparation_precedes_any_barrier_or_stop(self):
        flow, effects, adapter = self.flow()
        flow.forward()
        self.assertLessEqual(flow.deadline, adapter.deadline)
        names = [a for a, _ in effects]
        self.assertEqual(names[:2], ['prepare_runtime_bundle', 'create_persistent_barriers'])
        self.assertNotIn('create_sealed_staging', names)
        self.assertEqual([u for a, u in effects if a == 'stop'], list(r3.STOP))
        self.assertEqual([u for a, u in effects if a == 'start'], list(r3.UNITS))
        self.assertLess(max(i for i, a in enumerate(names) if a == 'stop'),
                        names.index('protected_rights_backup'))
        self.assertLess(names.index('isolated_restore_rehearsal'), names.index('install_four_artifacts'))
        self.assertLess(names.index('bounded_synthetic_probes'), names.index('install_four_artifacts'))

    def test_partial_or_unconfirmed_preparation_permanently_denies_stop(self):
        for unknown in (False, True):
            with self.subTest(unknown=unknown):
                flow, effects, _ = self.flow(fail='prepare_runtime_bundle', unconfirmed=unknown)
                with self.assertRaises(r3.FlowFailure):flow.forward()
                self.assertEqual(effects, [('prepare_runtime_bundle', None)])
                self.assertTrue(flow.hold)
                with self.assertRaises(r3.Denied):flow.forward()
                with self.assertRaises(r3.Denied):flow.return_old()

    def test_ready_gate_not_inferred_from_successful_preparation_action(self):
        flow, effects, _ = self.flow(missing_ready=True)
        with self.assertRaises(r3.FlowFailure):flow.forward()
        self.assertEqual(effects, [('prepare_runtime_bundle', None)])
        self.assertTrue(flow.hold)

    def test_barrier_error_does_not_start_stop_or_recover(self):
        flow, effects, _ = self.flow(fail='create_persistent_barriers')
        with self.assertRaises(r3.FlowFailure):flow.forward()
        self.assertEqual([a for a, _ in effects], ['prepare_runtime_bundle', 'create_persistent_barriers'])
        with self.assertRaises(r3.Denied):flow.return_old()

    def test_compiled_map_contains_only_exact_seven_assets_and_three_barriers(self):
        mapping = transition.prepared_asset_map(r3)
        self.assertEqual(len(mapping), 10)
        self.assertEqual(len({v['candidate'] for v in mapping.values()}), 10)
        self.assertEqual(len({v['target'] for v in mapping.values()}), 10)
        barriers = [v for v in mapping.values() if v['source'] is None]
        self.assertEqual({v['unit'] for v in barriers}, set(r3.UNITS))
        self.assertTrue(all(v['quarantine'] == r3.BOOT+'/quarantine/forward-'+v['unit'] for v in barriers))
        self.assertEqual(sum(v['mode'] == 0o555 for v in mapping.values()), 1)
        self.assertTrue(all(v['candidate'].startswith(r3.BOOT+'/prepared/assets/') for v in mapping.values()))
        self.assertFalse(any('173954685' in str(v) for v in mapping.values()))


class PreparedRuntimeTests(unittest.TestCase):
    def test_lost_ready_ack_cannot_set_ready_or_authorize_stop(self):
        adapter = transition.MaintenanceAdapter.__new__(transition.MaintenanceAdapter)
        adapter.prepared_ready = None; adapter.ready_raw = None; adapter.transaction_lock = None
        adapter.a = SimpleNamespace(prepared_runtime=None, b={'boot_id': 'synthetic'})
        adapter.r = r3; adapter.maintenance_inputs = {'test': 'bound elsewhere'}
        adapter.replacement_receipt = {'archive_sha256': 'a'*64}
        adapter.asset_map = transition.prepared_asset_map(r3)
        adapter.prepared_assets = {}; adapter.created = set()
        adapter.p = Mock(); adapter.p.create_file.return_value = {'synthetic': 'metadata'}
        adapter.prepare_private_roots = Mock(); adapter.receive_artifact = Mock(return_value=b'fixture')
        fence = Mock(); fence.identity_digest.return_value = {'sha256': 'b'*64, 'objects': 1, 'file_bytes': 0}
        adapter.a.legacy_runtime = fence; adapter.read_witness = {'synthetic': 'read witness only'}
        adapter.operator_session = dict(pid=123, starttime='10', session=123, process_group=123)
        adapter.construct_runtime = Mock(return_value=fence)
        adapter.check_prepared_dependencies = Mock(); adapter.prepare_asset_candidates = Mock()
        adapter.preparation_check = Mock(); adapter.check_transaction_lock = Mock()
        adapter.check_prepared_state = Mock()
        adapter.channel = Mock(); adapter.channel.record.side_effect = io.Hold('PUBLIC_OPERATOR_CLIENT_CUSTODY_ACK_LOST')
        with self.assertRaises(io.Hold):adapter.prepare_runtime_bundle(deadline=100)
        self.assertIs(adapter.a.prepared_runtime, fence)
        self.assertIsNone(adapter.prepared_ready)
        self.assertIsNone(adapter.ready_raw)
        adapter.check_prepared_state.assert_not_called()

    def test_probe_reuse_receipt_requires_completed_cleanup_and_same_actual_platform(self):
        adapter = transition.MaintenanceAdapter.__new__(transition.MaintenanceAdapter)
        adapter.quiet = Mock(); adapter.channel = Mock(); adapter.probe_hash = 'a'*64
        adapter.p = Mock()
        adapter.arm_start_limit_observation = Mock()
        platform = {'synthetic': 'measured platform'}
        adapter.a = SimpleNamespace(platform_identity=Mock(return_value=platform))
        adapter.probes = SimpleNamespace(cleanup_complete=True, unconfirmed=set(), reports=[],
                                        owned={}, retained={}, private='synthetic')
        with patch.object(transition.ReplacementAdapter, '_perform', return_value={'outcome': 'CONFIRMED'}) as run:
            adapter._perform('bounded_synthetic_probes', deadline=100)
        run.assert_called_once()
        self.assertEqual([c.args[0] for c in adapter.channel.record.call_args_list],
                         ['maintenance_probe_platform', 'maintenance_probes_complete'])
        adapter.channel.reset_mock(); adapter.probes.cleanup_complete = False
        with patch.object(transition.ReplacementAdapter, '_perform', return_value={'outcome': 'CONFIRMED'}):
            with self.assertRaises(io.Hold):adapter._perform('bounded_synthetic_probes', deadline=100)
        self.assertEqual([c.args[0] for c in adapter.channel.record.call_args_list], ['maintenance_probe_platform'])
        adapter.probes.cleanup_complete = True
        adapter.a.platform_identity.side_effect = [platform, {'synthetic': 'changed platform'}]
        with patch.object(transition.ReplacementAdapter, '_perform', return_value={'outcome': 'CONFIRMED'}):
            with self.assertRaises(io.Hold):adapter._perform('bounded_synthetic_probes', deadline=100)
    def test_prepared_dependency_failure_never_switches_old_active_runtime(self):
        adapter = transition.MaintenanceAdapter.__new__(transition.MaintenanceAdapter)
        old = Mock(); old.files = {(1, 1)}
        new = Mock(); new.files = {(1, 2)}
        adapter.a = SimpleNamespace(replacement_active=False, runtime=old, legacy_runtime=old,
                                    prepared_runtime=new)
        adapter.artifacts = {'fixed': 'expected'}; adapter.installed = {'fixed': 'observed'}
        adapter.replacement_ready = False
        adapter.quiet = Mock(); adapter.check_prepared_state = Mock()
        adapter.check_prepared_dependencies = Mock(side_effect=io.Hold('PUBLIC_OPERATOR_PREPARED_DEPENDENCY_DRIFT'))
        adapter.channel = Mock()
        with self.assertRaises(io.Hold):adapter.activate_prepared_runtime()
        self.assertIs(adapter.a.runtime, old)
        self.assertFalse(adapter.a.replacement_active)
        self.assertFalse(adapter.replacement_ready)
        adapter.channel.record.assert_not_called()

    def test_active_or_wrong_prepared_fence_is_not_an_ELF_census_permission(self):
        authority = transition.ReplacementAuthority.__new__(transition.ReplacementAuthority)
        authority.runtime = Mock(); authority.legacy_runtime = authority.runtime
        authority.prepared_runtime = transition.ReplacementFence.__new__(transition.ReplacementFence)
        authority.replacement_active = True
        authority.check_loader_configuration = Mock()
        for proposed in (authority.prepared_runtime, Mock()):
            with self.subTest(proposed=type(proposed).__name__), self.assertRaises(io.Hold):
                authority.bind_external_libraries(prepared=proposed)


class RecoveryCustodyTests(unittest.TestCase):
    def setUp(self):
        self.binding = 'a'*64
        self.ready = {'schema': transition.MAINTENANCE_CONTRACT, 'fixture': True}
        self.ready_sha = io.sha(io.canonical(self.ready))

    def rows(self, extra=()):
        values = [('flow_claim', {'transaction': r3.TX}),
                  ('maintenance_ready', {'ready': self.ready, 'sha256': self.ready_sha}), *extra]
        previous = self.binding; out = []
        for index, (kind, value) in enumerate(values, 1):
            record = {'sequence': index, 'binding': self.binding, 'previous': previous,
                      'kind': kind, 'value': value}
            raw = io.canonical(record); previous = io.sha(raw)
            out.append((str(index).zfill(3)+'-'+kind+'.json', raw))
        return out

    def snapshot(self, rows, *, extra=None):
        tmp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(tmp.cleanup)
        fd = os.open(tmp.name, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        for name, raw in rows:io.exclusive(fd, name, raw)
        if extra:
            for name, raw in extra.items():io.exclusive(fd, name, raw)
        before = {p.name: p.read_bytes() for p in Path(tmp.name).iterdir()}
        snapshot = io.read_original_chain(fd, self.binding, owner=os.geteuid(), deadline=time.monotonic()+10,
                                          client_supplements=bool(extra))
        self.assertEqual(before, {p.name: p.read_bytes() for p in Path(tmp.name).iterdir()})
        return snapshot, fd, Path(tmp.name)

    def pair(self, mac, host):
        return io.original_chain_pair(mac, host, binding=self.binding, ready_sha256=self.ready_sha)

    def test_identical_chains_and_one_explainable_mac_tail_remain_original_unknown(self):
        base = self.rows(); host, _, _ = self.snapshot(base)
        mac, _, _ = self.snapshot(base)
        self.assertIsNone(self.pair(mac, host)['unconfirmed_mac_tail'])
        extended = self.rows([('host_action_intent', {'action': 'stop', 'unit': r3.STOP[0]})])
        mac, _, _ = self.snapshot(extended)
        proof = self.pair(mac, host)
        self.assertEqual(proof['unconfirmed_mac_tail'], mac['tail'])
        self.assertFalse(proof['original_ack_reconstructed'])
        self.assertEqual(host['count'], 2)

    def test_host_lead_gap_and_divergence_are_not_repaired(self):
        base, _, _ = self.snapshot(self.rows())
        once, _, _ = self.snapshot(self.rows([('host_action_intent', {'action': 'stop'})]))
        twice, _, _ = self.snapshot(self.rows([('host_action_intent', {'action': 'stop'}),
                                               ('host_action_ack', {'action': 'stop'})]))
        other, _, _ = self.snapshot(self.rows([('host_action_intent', {'action': 'start'})]))
        for mac, host in ((base, once), (twice, base), (once, other)):
            with self.subTest(mac=mac['tail'], host=host['tail']), self.assertRaises(io.Hold):self.pair(mac, host)

    def test_ready_only_on_mac_and_owner_entry_or_completion_exclude_recovery(self):
        mac, _, _ = self.snapshot(self.rows())
        host, _, _ = self.snapshot(self.rows()[:1])
        with self.assertRaises(io.Hold):self.pair(mac, host)
        for extra in (('owner_admission_intent', {}), ('owner_object_intent', {}),
                      ('flow_observation', {'phase': 'owner_ready'}),
                      ('host_action_intent', {'action': 'supervised_owner_transaction'}),
                      ('flow_complete', {}), ('recovery_flow_claim', {})):
            with self.subTest(extra=extra):
                one, _, _ = self.snapshot(self.rows([extra]))
                with self.assertRaises(io.Hold):self.pair(one, one)

    def test_pre_marker_owner_gate_failure_is_not_evidence_of_owner_entry(self):
        # Actual marker/claim absence is an additional mandatory native gate.
        row, _, _ = self.snapshot(self.rows([('flow_hold', {'gate': 'owner_ready'})]))
        self.assertFalse(self.pair(row, row)['original_ack_reconstructed'])

    def test_original_supplements_are_read_and_preserved_but_not_acknowledgements(self):
        chain, _, _ = self.snapshot(self.rows(), extra={
            'held.json': io.canonical({'type': 'held', 'primary': 'synthetic'}),
            'final.json': io.canonical({'type': 'final', 'status': 'HOLD'})})
        self.assertEqual(set(chain['supplements']), {'held.json', 'final.json'})
        self.assertEqual(chain['count'], 2)

    def test_compact_manifest_requires_matching_independently_read_bytes(self):
        host, _, _ = self.snapshot(self.rows())
        mac, _, _ = self.snapshot(self.rows([('host_action_intent', {'action': 'stop'})]),
            extra={'final.json': io.canonical({'type': 'final', 'status': 'HOLD'})})
        manifest = io.original_chain_manifest(mac)
        proof = io.original_manifest_pair(manifest, host, binding=self.binding, ready_sha256=self.ready_sha)
        self.assertEqual(proof['unconfirmed_mac_record'], mac['records'][-1]['record'])
        self.assertEqual(proof['mac_snapshot_sha256'], io.sha(io.canonical(mac)))
        self.assertFalse(proof['original_ack_reconstructed'])
        for field, value in (('hashes', ['b'*64, *manifest['hashes'][1:]]),
                             ('last_record', {'kind': 'invented'}), ('snapshot_sha256', 'not-a-hash')):
            with self.subTest(field=field), self.assertRaises(io.Hold):
                io.original_manifest_pair({**manifest, field: value}, host,
                                         binding=self.binding, ready_sha256=self.ready_sha)
        bad = copy.deepcopy(manifest); bad['supplements']['final.json']['record']['status'] = 'SUCCESS'
        with self.assertRaises(io.Hold):
            io.original_manifest_pair(bad, host, binding=self.binding, ready_sha256=self.ready_sha)

    def test_compact_manifest_cannot_hide_owner_tail_or_replace_the_512_record_bound(self):
        host, _, _ = self.snapshot(self.rows())
        owner, _, _ = self.snapshot(self.rows([('owner_admission_intent', {})]))
        with self.assertRaises(io.Hold):
            io.original_manifest_pair(io.original_chain_manifest(owner), host,
                                     binding=self.binding, ready_sha256=self.ready_sha)
        large = self.rows([('bounded_fixture', {'padding': 'x'*60000}) for _ in range(510)])
        snapshot = {'binding': self.binding, 'tail': io.sha(large[-1][1]), 'count': len(large),
                    'records': [{'sha256': io.sha(raw), 'record': io.parse(raw)} for _, raw in large],
                    'supplements': {}}
        manifest = io.original_chain_manifest(snapshot)
        self.assertLess(len(io.canonical(manifest)), 128*1024)
        snapshot['records'].append(snapshot['records'][-1]); snapshot['count'] += 1
        with self.assertRaises(io.Hold):io.original_chain_manifest(snapshot)

    def test_bad_record_names_permissions_links_or_bytes_deny_read(self):
        for fault in ('partial', 'extra', 'symlink', 'hardlink', 'mode', 'noncanonical', 'sequence'):
            with self.subTest(fault=fault):
                _, fd, root = self.snapshot(self.rows())
                name = self.rows()[0][0]; path = root/name
                if fault == 'partial':path.write_bytes(b'{')
                elif fault == 'extra':io.exclusive(fd, 'unknown.json', b'{}')
                elif fault == 'symlink':path.unlink();path.symlink_to(root/self.rows()[1][0])
                elif fault == 'hardlink':os.link(path, root/'unrelated')
                elif fault == 'mode':path.chmod(0o644)
                elif fault == 'noncanonical':path.write_bytes(path.read_bytes()+b'\n')
                elif fault == 'sequence':path.rename(root/'003-flow_claim.json')
                with self.assertRaises((io.Hold, OSError, ValueError)):
                    io.read_original_chain(fd, self.binding, owner=os.geteuid(), deadline=time.monotonic()+10)

    def test_recovery_seed_binds_both_tails_and_cannot_claim_original_success(self):
        fields = ('original_binding', 'ready_sha256', 'source_sha256', 'artifact_sha256',
                  'mac_tail_sha256', 'host_tail_sha256', 'original_failure_sha256', 'fresh_state_sha256')
        seed = {k: 'a'*64 for k in fields}
        seed.update(schema='TU1NZ_MAIN_SERVER_REV4_RECOVERY_ONCE', transaction=r3.TX,
                    machine=r3.MACHINE, boot_id='00000000-0000-0000-0000-000000000001',
                    owner_plan_sha256=r3.OWNER_PLAN, original_status='FAILED_HOLD', unconfirmed_mac_tail=None)
        digest = io.recovery_binding(seed)
        for key in fields:
            self.assertNotEqual(io.recovery_binding({**seed, key: 'b'*64}), digest)
        for key, value in (('transaction', 'new-name'), ('original_status', 'SUCCESS'),
                           ('owner_plan_sha256', 'b'*64), ('unconfirmed_mac_tail', 'b'*64)):
            with self.subTest(key=key), self.assertRaises(io.Hold):io.recovery_binding({**seed, key: value})


class RecoveryObjectHistoryTests(unittest.TestCase):
    def setUp(self):
        OwnedCandidateTests.setUp(self)
        self.expected['metadata']['ctime_ns'] = 100

    def history(self, place, records, *, ctime=110):
        spec = transition.prepared_asset_map(r3)['0-barrier']
        observed = {'place': place, 'metadata': {**self.expected['metadata'], 'ctime_ns': ctime}}
        return transition.recovery_asset_history('0-barrier', spec, self.expected, observed, records)

    def intent(self):
        return {'kind': 'prepared_publication_intent', 'value': {
            'key': '0-barrier', 'mapping': transition.prepared_asset_map(r3)['0-barrier']}}

    def publication(self):
        return {'kind': 'prepared_publication_observed', 'value': {'key': '0-barrier',
            'actual': {'place': 'target', 'metadata': {**self.expected['metadata'], 'ctime_ns': 110}}}}

    def test_unknown_ack_does_not_authorize_an_unrequested_move_or_reverse_a_confirmed_move(self):
        initial = self.expected['metadata']['ctime_ns']
        self.history('candidate', [], ctime=initial)
        with self.assertRaises(io.Hold):self.history('target', [])
        proof = self.history('target', [self.intent()])
        self.assertEqual(proof['basis'], 'CURRENT_OBJECT_OBSERVATION_NOT_ORIGINAL_ACK')
        self.assertEqual(proof['original_last_confirmed_place'], 'candidate')
        self.history('candidate', [self.intent()], ctime=initial)
        confirmed = [self.intent(), self.publication()]
        self.history('target', confirmed)
        for place, ctime in (('candidate', initial), ('target', 111), ('quarantine', 120)):
            with self.subTest(place=place, ctime=ctime), self.assertRaises(io.Hold):
                self.history(place, confirmed, ctime=ctime)

    def test_barrier_release_requires_original_intent_and_preserves_real_post_ctime(self):
        records = [self.intent(), self.publication(), {'kind': 'host_action_intent', 'value': {
            'action': 'quarantine_own_barrier', 'unit': r3.UNITS[0]}}]
        self.history('target', records)
        self.history('quarantine', records, ctime=120)
        records.append({'kind': 'barrier_quarantined', 'value': {'unit': r3.UNITS[0],
            'path': transition.prepared_asset_map(r3)['0-barrier']['quarantine'],
            'actual': {**self.expected['metadata'], 'ctime_ns': 120}}})
        self.history('quarantine', records, ctime=120)
        with self.assertRaises(io.Hold):self.history('target', records)
        with self.assertRaises(io.Hold):self.history('quarantine', records, ctime=121)


class RecoveryOriginalEvidenceTests(unittest.TestCase):
    def fixture(self):
        self.binding = 'a'*64; self.boot = '00000000-0000-0000-0000-000000000001'
        self.source = SimpleNamespace(bytes={'runtime': b'synthetic'}, load=lambda name:r3)
        self.inputs = {k:'c'*64 for k in ('baseline_sha256', 'pre_stop_protection_sha256', 'native_timing_sha256')}
        self.inputs.update(scope_sha256=self.binding, source_sha256=io.sha(io.canonical(
            {k:io.sha(v) for k,v in self.source.bytes.items()})))
        self.session = {'pid': 42, 'starttime': '1000', 'session': 42, 'process_group': 42}
        self.witness = {'boot': self.boot, 'operator_session': self.session}
        self.meta = {'device': 1, 'inode': 2, 'uid': 0, 'gid': 0, 'mode': 0o600,
                     'type': stat.S_IFREG, 'nlink': 1, 'size': 0, 'mtime_ns': 100,
                     'ctime_ns': 100, 'atime_ns': 100, 'attrs': {}, 'flags': 0}
        mapping = transition.prepared_asset_map(r3)
        self.ready = {'schema': transition.MAINTENANCE_CONTRACT, 'transaction': r3.TX,
            'machine': r3.MACHINE, 'boot_id': self.boot, 'inputs': self.inputs,
            'owner_plan_sha256': r3.OWNER_PLAN, 'artifact_sha256': 'b'*64, 'archive_sha256': 'd'*64,
            'read_witness_sha256': io.sha(io.canonical(self.witness)), 'legacy_runtime_identity': {},
            'operator_session': self.session, 'runtime': {}, 'mapping': mapping,
            'assets': {k:{} for k in mapping}, 'directories': {}, 'checks': ['complete_runtime',
            'prepared_dependencies', 'complete_candidates', 'current_old_stop_authority',
            'current_writers', 'exclusive_lock'], 'activation': 'NOT_ACTIVATED', 'old_return': False}
        ready_record = {'ready': self.ready, 'sha256': io.sha(io.canonical(self.ready)),
                        'file_metadata': self.meta, 'actual_prepared_directories': {}}
        lock_record = {'path': r3.BOOT+'/transaction.lock', 'metadata': self.meta,
                       'operator_session': self.session, 'operator': {'pid': 42, 'starttime': '1000'}}
        values = [('prestate_read_witness', self.witness), ('flow_claim', {'transaction': r3.TX}),
                  ('maintenance_lock_held', lock_record), ('maintenance_ready', ready_record)]
        previous = self.binding; rows = []
        for index, (kind, value) in enumerate(values, 1):
            record = {'sequence': index, 'binding': self.binding, 'previous': previous,
                      'kind': kind, 'value': value}
            previous = io.sha(io.canonical(record)); rows.append({'record': record, 'sha256': previous})
        self.snapshot = {'binding': self.binding, 'tail': previous, 'count': len(rows),
                         'records': rows, 'supplements': {}}
        self.manifest = io.original_chain_manifest(self.snapshot)
        self.files = {r3.BOOT+'/prepared/READY.json': (io.canonical(self.ready), self.meta),
                      r3.BOOT+'/read-witness/witness.json': (io.canonical(self.witness), self.meta),
                      r3.BOOT+'/transaction.lock': (b'', self.meta)}
        self.paths = Mock(); self.paths.get.return_value = 99
        self.paths.read.side_effect = lambda path:self.files[path]
        self.object = transition.RecoveryOriginalEvidence.__new__(transition.RecoveryOriginalEvidence)

    def initialize(self):
        self.object.__init__(self.paths, self.source, self.manifest, original_binding=self.binding,
                            maintenance_inputs=self.inputs, boot_id=self.boot, deadline=time.monotonic()+10)

    def native_mocks(self, *, members=()):
        from contextlib import ExitStack
        stack = ExitStack(); self.addCleanup(stack.close)
        stack.enter_context(patch.object(io, 'read_original_chain', return_value=self.snapshot))
        stack.enter_context(patch.object(transition, 'operator_session_members', return_value=list(members)))
        for name, value in (('dup', 90), ('open', 91), ('fstat', SimpleNamespace(st_dev=1, st_ino=2))):
            stack.enter_context(patch.object(transition.os, name, return_value=value))
        self.lock = stack.enter_context(patch.object(transition.fcntl, 'flock'))

    def test_original_custody_is_read_only_and_existing_lock_is_acquired_without_reset(self):
        self.fixture(); self.native_mocks(); self.initialize()
        self.lock.assert_called_once_with(91, transition.fcntl.LOCK_EX | transition.fcntl.LOCK_NB)
        self.paths.create_file.assert_not_called(); self.paths.create_directory.assert_not_called()
        self.assertEqual(self.object.binding, self.binding)
        self.assertEqual(self.object.ready_raw, io.canonical(self.ready))
        self.files[r3.BOOT+'/transaction.lock'] = (b'', {**self.meta, 'inode': 3})
        with self.assertRaises(io.Hold):self.object.check_original()

    def test_live_original_or_orphan_helper_prevents_lock_and_recovery_admission(self):
        self.fixture(); self.native_mocks(members=[{'pid': 43, 'starttime': '1001'}])
        with self.assertRaisesRegex(io.Hold, 'HELPER_STILL_PRESENT'):self.initialize()
        self.lock.assert_not_called()

    def test_changed_ready_witness_or_source_never_becomes_current_authority(self):
        for fault in ('ready', 'witness', 'source'):
            with self.subTest(fault=fault):
                self.fixture()
                with patch.object(io, 'read_original_chain', return_value=self.snapshot), \
                     patch.object(transition.os, 'dup', return_value=90):
                    if fault == 'ready':
                        self.files[r3.BOOT+'/prepared/READY.json'] = (io.canonical({**self.ready, 'old_return': True}), self.meta)
                    elif fault == 'witness':
                        self.files[r3.BOOT+'/read-witness/witness.json'] = (io.canonical({**self.witness, 'boot': 'other'}), self.meta)
                    else:self.source.bytes['runtime'] = b'changed'
                    with self.assertRaises(io.Hold):self.initialize()


class RecoveryPhaseTests(unittest.TestCase):
    def fixture(self, installed=0, *, barriers='target', units='empty_inactive'):
        mapping = transition.prepared_asset_map(r3)
        assets = {}; count = 0
        for key, spec in mapping.items():
            if spec['source'] is None:assets[key] = {'place': barriers}
            else:
                assets[key] = {'place': 'target' if count < installed else 'candidate'}; count += 1
        return mapping, assets, {u: units for u in r3.UNITS}

    def test_finite_f1_f2_f3_f4_with_no_second_runtime_construction(self):
        for installed, barriers, units, expected in (
                (0, 'candidate', 'known_old_active', 'F1'),
                (0, 'target', 'known_old_active', 'F1'),
                (0, 'target', 'empty_inactive', 'F2'),
                (0, 'target', 'empty_terminal_failed', 'F2'),
                (1, 'target', 'empty_inactive', 'F3'),
                (6, 'target', 'empty_inactive', 'F3'),
                (7, 'target', 'empty_terminal_failed', 'F4'),
                (7, 'quarantine', 'known_new_active', 'F4')):
            with self.subTest(expected=expected, installed=installed):
                args = self.fixture(installed, barriers=barriers, units=units)
                self.assertEqual(transition.recovery_phase(*args), expected)

    def test_unknown_runtime_mixed_old_new_or_premature_downstream_release_denied(self):
        cases = [self.fixture(1, units='known_old_active'),
                 self.fixture(6, units='known_new_active'), self.fixture(3, barriers='quarantine')]
        mapping, assets, units = self.fixture(7)
        units[r3.UNITS[1]] = 'known_new_active'; assets['1-barrier']['place'] = 'quarantine'
        cases.append((mapping, assets, units))
        mapping, assets, units = self.fixture(7); assets['2-barrier']['place'] = 'quarantine'
        cases.append((mapping, assets, units))
        for args in cases:
            with self.subTest(args=args), self.assertRaises(io.Hold):transition.recovery_phase(*args)

    def test_only_active_prefix_and_one_next_released_empty_unit_is_admitted(self):
        mapping, assets, units = self.fixture(7)
        units[r3.UNITS[0]] = 'known_new_active'; assets['0-barrier']['place'] = 'quarantine'
        assets['1-barrier']['place'] = 'quarantine'
        self.assertEqual(transition.recovery_phase(mapping, assets, units), 'F4')
        assets['2-barrier']['place'] = 'quarantine'
        with self.assertRaises(io.Hold):transition.recovery_phase(mapping, assets, units)


class RecoveryCurrentUnitTests(unittest.TestCase):
    def fixture(self):
        a = transition.RecoveryAuthority.__new__(transition.RecoveryAuthority)
        a.replacement_active = False; a.empty = Mock(return_value=True)
        a.interpreter_binding = Mock(); a.delegation_check = Mock(); a.rights_check = Mock()
        a.initial_application_ready = Mock(return_value=True)
        old = {'InvocationID': 'a'*32, 'NRestarts': '0'}
        row = {'pid': 42, 'starttime': '99', 'uid': [1001]*4, 'gid': [1001]*4,
               'cgroup': '0::/system.slice/'+r3.UNITS[0]}
        a.evidence = SimpleNamespace(witness={'units': {r3.UNITS[0]: old},
                                              'targets': {r3.UNITS[0]: [42, '99']}})
        a.original_profiles = {r3.UNITS[0]: {'uid': [1001]*4, 'gid': [1001]*4}}
        value = {**old, 'Job': '', 'ControlPID': '0', 'MainPID': '42', 'ActiveState': 'active',
                 'SubState': 'running', 'Result': 'success', 'ControlGroup': '/system.slice/'+r3.UNITS[0]}
        return a, value, row

    def test_old_target_requires_same_actual_lifetime_invocation_and_counter(self):
        a, value, row = self.fixture()
        self.assertEqual(a.classify_current_unit(r3.UNITS[0], value, row), 'known_old_active')
        for v, r in (({**value, 'InvocationID': 'b'*32}, row),
                     ({**value, 'NRestarts': '1'}, row), (value, {**row, 'starttime': '100'}),
                     ({**value, 'Job': '1'}, row)):
            with self.assertRaises(io.Hold):a.classify_current_unit(r3.UNITS[0], v, r)

    def test_new_active_runtime_and_isolation_are_measured_not_inferred_from_zero_counter(self):
        a, value, row = self.fixture(); a.replacement_active = True
        a.interpreter_binding.side_effect = io.Hold('PUBLIC_OPERATOR_SYNTHETIC_WRONG_RUNTIME')
        with self.assertRaises(io.Hold):a.classify_current_unit(r3.UNITS[0], value, row)
        a.rights_check.assert_not_called()
        a.interpreter_binding.side_effect = None
        a.rights_check.side_effect = io.Hold('PUBLIC_OPERATOR_SYNTHETIC_RIGHTS_RED')
        with self.assertRaises(io.Hold):a.classify_current_unit(r3.UNITS[0], value, row)
        a.rights_check.side_effect = None
        self.assertEqual(a.classify_current_unit(r3.UNITS[0], value, row), 'known_new_active')

    def test_empty_terminal_failed_is_distinct_from_restart_startlimit_or_nonempty(self):
        a, value, _ = self.fixture(); value.update(MainPID='0', ActiveState='failed', SubState='failed', Result='exit-code')
        self.assertEqual(a.classify_current_unit(r3.UNITS[0], value, None), 'empty_terminal_failed')
        for change in ({'Result': 'start-limit-hit'}, {'NRestarts': '1'}, {'ControlPID': '1'},
                       {'SubState': 'auto-restart'}, {'ActiveState': 'deactivating'}):
            with self.subTest(change=change), self.assertRaises(io.Hold):
                a.classify_current_unit(r3.UNITS[0], {**value, **change}, None)
        a.empty.return_value = False
        with self.assertRaises(io.Hold):a.classify_current_unit(r3.UNITS[0], value, None)


class RecoveryProbeAdmissionTests(unittest.TestCase):
    def test_partial_unknown_or_failed_probe_cannot_become_unused_even_when_currently_empty(self):
        for record in ({'kind': 'probe_start_intent', 'value': {}},
                       {'kind': 'probe_completed', 'value': {}},
                       {'kind': 'maintenance_probes_complete', 'value': {}},
                       {'kind': 'host_action_intent', 'value': {'action': 'bounded_synthetic_probes'}}):
            e = SimpleNamespace(snapshot={'records': []}, records=[record], source=Mock())
            with self.subTest(record=record), patch.object(transition.RecoveryProbeEvidence, 'unused_current') as unused:
                with self.assertRaisesRegex(io.Hold, 'PARTIAL_OR_UNKNOWN_PROBE'):
                    transition.RecoveryProbeEvidence(Mock(), e)
                unused.assert_not_called()

    def test_unused_requires_current_fixed_probe_names_and_objects_absent(self):
        e = SimpleNamespace(snapshot={'records': []}, records=[], source=Mock())
        with patch.object(transition.RecoveryProbeEvidence, 'unused_current',
                          side_effect=io.Hold('PUBLIC_OPERATOR_SYNTHETIC_OCCUPIED')) as unused:
            with self.assertRaises(io.Hold):transition.RecoveryProbeEvidence(Mock(), e)
            unused.assert_called_once()


class RecoveryFailureTests(unittest.TestCase):
    def test_lost_ack_is_unknown_and_known_negative_cannot_be_overruled(self):
        code = 'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_CLIENT_CUSTODY_ACK_LOST'
        records = [{'kind': 'flow_hold', 'value': {'primary': code, 'abort': [], 'cleanup': []}}]
        proof = transition.recovery_failure_assessment(records, {})
        self.assertEqual(proof['original_status'], 'FAILED_HOLD')
        self.assertEqual(proof['original_effects'], 'UNKNOWN_UNTIL_FRESH_CLASSIFICATION')
        for primary in ('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_ACTUAL_RUNTIME_RIGHTS_RED',
                        'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_RESTORE_CONTENT_OR_METADATA',
                        'PUBLIC_BOOTSTRAP_REQUIREMENT_OR_OPERATION_UNCONFIRMED'):
            with self.subTest(primary=primary), self.assertRaises(io.Hold):
                transition.recovery_failure_assessment(records+[{'kind': 'flow_hold',
                    'value': {'primary': primary}}], {})

    def test_missing_diagnostic_does_not_claim_mechanical_cause_or_original_success(self):
        proof = transition.recovery_failure_assessment([], {})
        self.assertEqual(proof['cause'], 'INCOMPLETE_ORIGINAL_NO_CAUSE_CLAIM')
        self.assertTrue(proof['fresh_admission_still_required'])
        with self.assertRaises(io.Hold):
            transition.recovery_failure_assessment([], {'final.json': {
                'record': {'type': 'final', 'status': 'COMPLETE'}}})


class MaintenanceMaterialBoundaryTests(unittest.TestCase):
    def fixture(self):
        source = {n:'a'*64 for n in set(io.MODULES)|set(io.ASSETS)}
        artifact = {'synthetic_archive_receipt': 'not production evidence'}
        artifact_hash = io.sha(io.canonical(artifact)); origin = 'b'*64
        boot = '00000000-0000-0000-0000-000000000001'
        material = {'contract': b'synthetic decision', 'approval': io.canonical({'synthetic_approval': True}),
                    'current_observation': io.canonical({'synthetic_observation': True}),
                    'read_scope': io.canonical({'synthetic_reader_scope': True}),
                    'pre_stop_protection': io.canonical({'synthetic_protection': True}),
                    'native_timing': io.canonical({'synthetic_timing': True})}
        self.enterContext(patch.object(io, 'MAINTENANCE_DECISION_SHA', io.sha(material['contract'])))
        self.enterContext(patch.object(io, 'MAINTENANCE_APPROVAL_SHA', io.sha(material['approval'])))
        baseline = {'schema': 'TU1NZ_PUBLIC_HOST_BASELINE_CURRENT_REV4_V1', 'machine_sha256': r3.MACHINE,
                    'boot_id': boot, 'actors': [], 'files': {}, 'source_origin_receipts': [origin, artifact_hash],
                    'current_authority': {'schema': contexts.CURRENT_AUTHORITY, 'risk': contexts.CURRENT_RISK,
                                          'observation_sha256': io.sha(material['current_observation'])},
                    'source_release': {'probe_dependencies': {}, 'python_binary': '/usr/bin/python3',
                        'operator_dependencies': {'/usr/bin/busctl': {'source': '/usr/bin/busctl', 'sha256': 'c'*64,
                            'uid': 0, 'gid': 0, 'mode': 0o755, 'attrs': {}, 'flags': 0, 'origin_sha256': origin}},
                        'runtime_reference': {'schema': 'TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1',
                                              'artifact': artifact, 'origin_sha256': artifact_hash}}}
        now = 1804348800
        def stamp(seconds):return datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        acceptance = {'schema': 'TU1NZ_REV4_CURRENT_ACCEPTANCE',
            'observation_sha256': io.sha(material['current_observation']), 'read_scope_sha256': io.sha(material['read_scope']),
            'machine_sha256': r3.MACHINE, 'boot_id': boot, 'transaction': r3.TX,
            'source_sha256': io.sha(io.canonical(source)), 'capture_started_at': stamp(now-120),
            'capture_finished_at': stamp(now-60), 'accepted_at': stamp(now-30), 'expires_at': stamp(now+3600),
            'risk': contexts.CURRENT_RISK}
        material['current_acceptance'] = io.canonical(acceptance)
        scope = {'schema': io.MAINTENANCE_SCOPE, 'release_sha256': 'd'*64,
            'baseline_sha256': io.sha(io.canonical(baseline)), 'administrative_roles_sha256': io.sha(io.canonical([])),
            'baseline_origins_sha256': io.sha(io.canonical(baseline['source_origin_receipts'])),
            'r3_approval_sha256': client.APPROVAL, 'machine_sha256': r3.MACHINE, 'transaction': r3.TX,
            'owner_plan_sha256': r3.OWNER_PLAN, 'runtime_artifact_sha256': artifact_hash, 'legacy_return': False,
            **{n+'_sha256':io.sha(v) for n,v in material.items()}}
        review = {'schema': 'TU1NZ_REV4_INDEPENDENT_EXECUTION_INPUT_REVIEW', 'reviewer': 'synthetic reviewer',
            'inputs': {}, 'findings': [], 'evidence_sha256': 'e'*64, 'reviewed_at': stamp(now-10)}
        def bind_review():
            review['inputs'] = {k:scope[k+'_sha256'] for k in ('release', 'baseline', 'current_observation',
                'current_acceptance', 'read_scope', 'pre_stop_protection', 'native_timing', 'contract', 'approval')}
            review['inputs'].update(scope_sha256=io.sha(io.canonical(scope)), source_sha256=io.sha(io.canonical(source)))
            material['review'] = io.canonical(review)
        bind_review()
        self.enterContext(patch.object(io.time, 'time', return_value=now))
        return scope,baseline,material,source,acceptance,review,bind_review,stamp,now

    def check(self, fixture):
        scope,baseline,material,source,*_ = fixture
        return io.maintenance_material_binding(scope,baseline,material,source_hashes=source,
                                               review_sha256=io.sha(material['review']))

    def test_exact_material_binding_is_explicitly_not_restore_or_native_admission(self):
        f = self.fixture(); docs = self.check(f)
        # Intentionally incomplete synthetic gate documents pass ONLY byte
        # binding. They must not enter any session/claim without V1–V6 checks.
        self.assertEqual(docs['native_timing'], {'synthetic_timing': True})
        self.assertNotIn('host_admitted', docs)
        with self.assertRaises(io.Hold):io.replacement_scope(f[0], f[1])

    def test_old_context_baseline_old_return_and_new_transaction_are_rejected(self):
        f = self.fixture(); scope,baseline = f[:2]
        for delta in ({'legacy_return': True}, {'transaction': 'new-transaction'}, {'approval_sha256': 'f'*64}):
            with self.subTest(delta=delta), self.assertRaises(io.Hold):io.maintenance_scope({**scope,**delta},baseline)
        with self.assertRaises(io.Hold):io.maintenance_scope(scope,{**baseline,'contexts':{}})

    def test_capture_lifetime_and_full_remaining_window_are_not_extended(self):
        f = self.fixture(); scope,baseline,material,source,acceptance,review,bind,stamp,now = f
        original = dict(acceptance)
        for delta in ({'expires_at': stamp(now+599)}, {'expires_at': stamp(now+86401)},
                      {'capture_started_at': stamp(now-361)}, {'accepted_at': stamp(now+1)}):
            acceptance.clear(); acceptance.update(original); acceptance.update(delta)
            material['current_acceptance'] = io.canonical(acceptance)
            scope['current_acceptance_sha256'] = io.sha(material['current_acceptance']); bind()
            with self.subTest(delta=delta), self.assertRaises(io.Hold):self.check(f)

    def test_changed_receipts_or_optimistic_review_flags_do_not_match_reviewed_inputs(self):
        f = self.fixture(); scope,baseline,material,source,acceptance,review,bind,*_ = f
        old = material['native_timing']; material['native_timing'] = io.canonical({'passed': True})
        with self.assertRaises(io.Hold):self.check(f)
        material['native_timing'] = old
        review['inputs']['scope_sha256'] = 'f'*64; material['review'] = io.canonical(review)
        with self.assertRaises(io.Hold):self.check(f)
        bind(); review['findings'] = ['unresolved']; material['review'] = io.canonical(review)
        with self.assertRaises(io.Hold):self.check(f)

    def packet(self):
        f = self.fixture(); scope,baseline,material,hashes,acceptance,review,bind,*_ = f
        source = SimpleNamespace(bytes={n:('SYNTHETIC_SOURCE_'+n).encode() for n in hashes})
        hashes.clear(); hashes.update({n:io.sha(raw) for n,raw in source.bytes.items()})
        acceptance['source_sha256'] = io.sha(io.canonical(hashes))
        material['current_acceptance'] = io.canonical(acceptance)
        scope['current_acceptance_sha256'] = io.sha(material['current_acceptance'])
        plan = io.canonical({'host': r3.MACHINE, 'fixture': 'not actual owner evidence'})
        self.enterContext(patch.object(io, 'MAINTENANCE_OWNER_PLAN', io.sha(plan)))
        scope['owner_plan_sha256'] = io.sha(plan)
        release = {'schema': 'TU1NZ_PUBLIC_OPERATOR_RELEASE_V1', 'files': hashes}
        scope['release_sha256'] = io.sha(io.canonical(release)); bind()
        encoded = lambda raw:base64.b64encode(raw).decode()
        raw_scope = io.canonical(scope)
        return {'source': {n:encoded(raw) for n,raw in source.bytes.items()}, 'hashes': hashes,
            'baseline': baseline, 'baseline_raw': encoded(zlib.compress(io.canonical(baseline))),
            'baseline_encoding': 'zlib_REV4', 'scope': scope, 'scope_raw': encoded(raw_scope),
            'scope_sha256': io.sha(raw_scope), 'binding': io.sha(raw_scope), 'owner_plan': encoded(plan),
            'release': release, 'maintenance_material': {n:encoded(raw) for n,raw in material.items()},
            'review_sha256': io.sha(material['review']), 'route': 'original', 'remaining_milliseconds': 590000}, source

    def test_packet_requires_exact_current_source_and_canonical_reviewed_bytes(self):
        packet, source = self.packet()
        result = io.maintenance_packet_binding(packet, source, remaining_seconds=590)
        self.assertEqual(result['inputs']['scope_sha256'], packet['binding'])
        self.assertNotIn('approval_bound', result)
        for field,value in (('binding','f'*64), ('remaining_milliseconds',True), ('baseline_encoding','zlib_R5'),
                            ('scope_raw',base64.b64encode(io.canonical(packet['scope'])+b'\n').decode())):
            with self.subTest(field=field), self.assertRaises(io.Hold):
                io.maintenance_packet_binding({**packet,field:value}, source, remaining_seconds=590)
        changed = copy.deepcopy(packet); changed['source']['host'] = base64.b64encode(b'changed').decode()
        with self.assertRaises(io.Hold):io.maintenance_packet_binding(changed, source, remaining_seconds=590)
        changed = copy.deepcopy(packet)
        changed['baseline_raw'] = base64.b64encode(base64.b64decode(packet['baseline_raw'])+b'trailing').decode()
        with self.assertRaises(io.Hold):io.maintenance_packet_binding(changed, source, remaining_seconds=590)

    def test_recovery_envelope_cannot_change_source_original_binding_or_route(self):
        packet, source = self.packet()
        entry = io.recovery_entry(packet['binding'], packet['baseline']['boot_id'],
                                 io.sha(io.canonical(packet['hashes'])), 'a'*64, 'b'*64)
        recovery = {'entry': entry, 'manifest': {'binding': packet['binding'], 'snapshot_sha256': 'a'*64}}
        packet.update(route='recovery-once', recovery=recovery)
        result = io.maintenance_packet_binding(packet, source, remaining_seconds=590)
        self.assertEqual(result['inputs']['scope_sha256'], entry['original_binding'])
        # Only envelope binding is established here; the actual host chain
        # reader must still reject this intentionally incomplete manifest.
        recovery['entry'] = {**entry, 'original_binding': 'f'*64}
        with self.assertRaises(io.Hold):io.maintenance_packet_binding(packet, source, remaining_seconds=590)


class RecoveryAdmissionChannelTests(unittest.TestCase):
    def test_current_custody_read_cannot_emit_an_action_claim_or_original_ack(self):
        wire = Mock(); wire.deadline = time.monotonic()+10
        channel = io.RecoveryAdmissionChannel(wire, original_binding='a'*64,
            entry_sha256='b'*64, mac_snapshot_sha256='c'*64)
        wire.receive.return_value = {'type': 'recovery_admission_current', **channel.context}
        channel.check()
        for kind in ('flow_claim', 'host_action_intent', 'recovery_context', 'owner_admission_intent'):
            with self.subTest(kind=kind), self.assertRaises(io.Hold):channel.record(kind, {})
        with self.assertRaises(io.Hold):channel.attach(5)
        self.assertEqual(channel.sequence, 0); self.assertIsNone(channel.host_fd)
        self.assertFalse(channel.approval_bound)
        channel.finish()
        with self.assertRaises(io.Hold):channel.check()

    def test_changed_original_or_entry_custody_does_not_form_a_fresh_binding(self):
        wire = Mock(); wire.deadline = time.monotonic()+10
        channel = io.RecoveryAdmissionChannel(wire, original_binding='a'*64,
            entry_sha256='b'*64, mac_snapshot_sha256='c'*64)
        wire.receive.return_value = {'type': 'recovery_admission_current', **channel.context,
                                    'mac_snapshot_sha256': 'd'*64}
        with self.assertRaises(io.Hold):channel.finish()
        self.assertEqual(channel.sequence, 0); self.assertFalse(channel.approval_bound)


class RecoveryMacCustodyTests(unittest.TestCase):
    def fixture(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()))
        root = Path(tmp)
        self.enterContext(patch.object(r3, 'CUSTODY_PARENT', root))
        fixed = '/Users/daniel/Developer/tu1nz/service-isolation-lighting-night-20261013/host-operator-intents'
        self.enterContext(patch.object(client, 'Path', side_effect=lambda value:root if value == fixed else Path(value)))
        binding = 'a'*64; source = 'b'*64; boot = '00000000-0000-0000-0000-000000000001'
        ready = {'boot_id': boot, 'inputs': {'scope_sha256': binding, 'source_sha256': source},
                 'artifact_sha256': 'c'*64}
        journal = r3.Journal(root, binding); journal.claim()
        os.mkdir('operator-records', 0o700, dir_fd=journal.fd)
        fd = os.open('operator-records', os.O_RDONLY | os.O_DIRECTORY, dir_fd=journal.fd)
        previous = binding
        try:
            for seq,(kind,value) in enumerate((('flow_claim', {'transaction': r3.TX}),
                    ('maintenance_ready', {'ready': ready, 'sha256': io.sha(io.canonical(ready))}),
                    ('flow_hold', {'phase': 'quiet'})), 1):
                row = {'sequence': seq, 'binding': binding, 'previous': previous, 'kind': kind, 'value': value}
                raw = io.canonical(row); io.exclusive(fd, str(seq).zfill(3)+'-'+kind+'.json', raw)
                previous = io.sha(raw)
        finally:os.close(fd); journal.close()
        return root, binding, source, boot

    def make(self, args):
        root, binding, source, boot = args
        c = client.RecoveryCustody(r3, binding, boot_id=boot, source_sha256=source, deadline=time.monotonic()+600)
        self.addCleanup(c.close)
        return c

    def seed(self, c, state=None, failure=None):
        return {'schema': 'TU1NZ_MAIN_SERVER_REV4_RECOVERY_ONCE', 'transaction': r3.TX, 'machine': r3.MACHINE,
                'boot_id': c.entry['boot_id'], 'owner_plan_sha256': r3.OWNER_PLAN, 'original_status': 'FAILED_HOLD',
                'unconfirmed_mac_tail': None, 'original_binding': c.original_binding,
                'ready_sha256': c.ready_sha256, 'source_sha256': c.entry['source_sha256'],
                'artifact_sha256': c.ready['artifact_sha256'], 'mac_tail_sha256': c.snapshot['tail'],
                'host_tail_sha256': c.snapshot['tail'], 'original_failure_sha256': io.sha(io.canonical(failure or {})),
                'fresh_state_sha256': io.sha(io.canonical(state or {}))}

    def test_one_additive_entry_keeps_original_bytes_and_cannot_be_reopened(self):
        args = self.fixture(); root = args[0]/r3.TX
        before = {p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
        c = self.make(args); c.bind(self.seed(c)); c.claim(); c.write('hold', {'original_status': 'FAILED_HOLD'})
        c.check(); c.close()
        self.assertTrue((root/'recovery-once/entry.json').is_file())
        self.assertTrue(all((root/p).read_bytes() == raw for p,raw in before.items()))
        with self.assertRaises(io.Hold):self.make(args)
        self.assertTrue(all((root/p).read_bytes() == raw for p,raw in before.items()))

    def test_partial_entry_write_consumes_entry_without_deleting_or_repairing_it(self):
        args = self.fixture(); original = io.exclusive
        def fail(parent, name, raw):
            if name == 'entry.json':raise OSError('synthetic interrupted durable entry')
            return original(parent, name, raw)
        with patch.object(io, 'exclusive', side_effect=fail), self.assertRaises(OSError):self.make(args)
        self.assertTrue((args[0]/r3.TX/'recovery-once').is_dir())
        with self.assertRaises(io.Hold):self.make(args)
        self.assertEqual(list((args[0]/r3.TX/'recovery-once').iterdir()), [])

    def test_original_or_entry_byte_change_is_not_adopted(self):
        args = self.fixture(); c = self.make(args)
        path = args[0]/r3.TX/'operator-records/003-flow_hold.json'
        raw = path.read_bytes(); path.write_bytes(raw+b' ')
        with self.assertRaises(io.Hold):c.check()
        self.assertEqual(path.read_bytes(), raw+b' ')

    def test_recovery_binding_rejects_different_runtime_and_unknown_host_tail(self):
        args = self.fixture(); c = self.make(args); seed = self.seed(c)
        for delta in ({'artifact_sha256': 'd'*64}, {'host_tail_sha256': 'e'*64}):
            with self.subTest(delta=delta), self.assertRaises(io.Hold):c.bind({**seed, **delta})
        self.assertIsNone(c.binding)
        self.assertFalse((args[0]/r3.TX/'recovery-once/operator-records').exists())

    def test_draft_checks_survive_binding_but_end_before_effects_and_owner_is_additive(self):
        args = self.fixture(); custody = self.make(args)
        wire = Mock(); wire.deadline = custody.deadline
        c = client.RecoveryClient(wire, r3, custody, http_expectations=[]); self.addCleanup(c.close)
        check = {'type': 'recovery_admission_check', 'original_binding': custody.original_binding,
                 'entry_sha256': io.sha(custody.entry_raw), 'mac_snapshot_sha256': custody.manifest['snapshot_sha256']}
        state = {'phase': 'F4'}; failure = {'original_status': 'FAILED_HOLD'}
        seed = self.seed(custody, state, failure)
        self.assertTrue(c.extension_message(check))
        self.assertTrue(c.extension_message({'type': 'recovery_prepared', 'seed': seed,
                                           'fresh_state': state, 'original_failure': failure}))
        def record(kind, value):
            row = {'sequence': c.sequence+1, 'binding': c.binding, 'previous': c.last, 'kind': kind, 'value': value}
            raw = io.canonical(row); name = str(row['sequence']).zfill(3)+'-'+kind+'.json'
            io.exclusive(c.fd, name, raw); c.records[name] = raw; c.project_record(row)
            c.sequence += 1; c.last = io.sha(raw); c.check()
        record('recovery_context', seed)
        self.assertTrue(c.extension_message(check))  # Host draft.finish before fresh-state record
        record('recovery_state_observation', state)
        with self.assertRaises(io.Hold):c.extension_message(check)
        record('recovery_flow_claim', {'transaction': r3.TX, 'original_claim_reset': False, 'recovery_of_recovery': False})
        marker = io.owner_entry_marker(original_binding=c.original_binding, execution_binding=c.binding,
            ready_sha256=c.ready_sha256, boot_id=c.boot_id, route='recovery-once')
        record('owner_admission_intent', marker)
        self.assertEqual((args[0]/r3.TX/'owner-admission-intent').read_bytes(), io.canonical(marker))
        self.assertEqual(custody.read_original_root(), custody.original_files)
        for kind in ('prepared', 'runtime_chunk_request'):
            with self.assertRaises(io.Hold):c.extension_message({'type': kind})


class RecoveryActionBoundaryTests(unittest.TestCase):
    def adapter(self):
        a = transition.RecoveryAdapter.__new__(transition.RecoveryAdapter)
        a.deadline = time.monotonic()+600; a.recovery_bound = True; a.recovery_terminal = False
        a.pending = None; a.recovery_once_actions = set(); a.start_limit_observation = None
        a.protected_state = Mock(); a.check_prepared_state = Mock(); a.check_unspent_owner = Mock()
        a.quiet = Mock(); a.space = Mock(); a.channel = Mock(); a.p = Mock()
        a.a = SimpleNamespace(current_data_readonly=Mock(), b={'files': {'/etc/tu1nz/example': {'sha256': 'a'*64}}})
        a.arm_start_limit_observation = Mock(); a.current_backup_verified = Mock()
        a.backup_mode = 'NEW_RECOVERY_REQUIRED'; a.recovery_backup_used = False
        a.backup = None; a.backup_hash = a.restore_hash = None
        return a

    def test_new_private_copy_uses_only_one_fixed_child_and_failure_does_not_reenter(self):
        a = self.adapter(); fake = Mock(); fake.create.side_effect = OSError('synthetic interrupted copy')
        with patch.object(transition, 'Backup', return_value=fake) as constructor:
            with self.assertRaises(OSError):a._perform('recovery_private_backup', deadline=time.monotonic()+120)
        self.assertTrue(a.recovery_backup_used)
        self.assertEqual(constructor.call_args.args[2], transition.STAGING+'/recovery-once')
        a.p.create_directory.assert_called_once_with(transition.STAGING+'/recovery-once')
        with self.assertRaises(io.Hold):a._perform('recovery_private_backup', deadline=time.monotonic()+120)
        self.assertEqual(fake.create.call_count, 1)
        fake.restore_test.assert_not_called()

    def test_current_original_copy_and_restore_are_read_only_reused(self):
        a = self.adapter(); a.backup_mode = 'ORIGINAL_CURRENT'; a.backup_hash = a.restore_hash = 'a'*64
        with patch.object(transition, 'Backup') as constructor:
            for action in ('recovery_private_backup', 'recovery_private_restore'):
                result = a._perform(action, deadline=time.monotonic()+120)
                self.assertEqual(result['proof_sha256'], 'a'*64)
            constructor.assert_not_called()
        a.p.create_directory.assert_not_called()
        self.assertEqual(a.current_backup_verified.call_count, 2)

    def test_old_start_rebuild_second_entry_and_terminal_forward_are_denied(self):
        for action in ('start_old', 'return_old_configuration', 'prepare_runtime_bundle', 'create_sealed_staging'):
            a = self.adapter()
            with self.subTest(action=action), self.assertRaises(io.Hold):
                a._perform(action, deadline=time.monotonic()+120)
            a.channel.record.assert_not_called()
        a = self.adapter(); a.recovery_terminal = True
        with self.assertRaises(io.Hold):a._perform('recovery_start', r3.UNITS[0], deadline=time.monotonic()+20)
        a.channel.record.assert_not_called()

    def test_reconcile_skips_reload_for_current_configuration(self):
        a = self.adapter(); a.a.check = Mock(); a.a.deadline = a.deadline
        a.a.recovery_reload_units = set(); a.a.recovery_allow_load_delta = True
        a.a.b['unit_files'] = {u: {'dropins': []} for u in r3.UNITS}
        a.a.own_dropins = {u: set() for u in r3.UNITS}; a.reload = Mock()
        current = {u: {'NeedDaemonReload': 'no', 'DropInPaths': ''} for u in r3.UNITS}
        with patch.object(transition, 'unit_rows', return_value=current):a.reconcile_config()
        a.reload.assert_not_called(); self.assertFalse(a.a.recovery_allow_load_delta)
        a.channel.record.assert_not_called()


class RecoveryTerminalBoundaryTests(unittest.TestCase):
    def fixture(self, *, active=True):
        x = transition.RecoveryAdapter.__new__(transition.RecoveryAdapter)
        x.recovery_bound = True; x.recovery_terminal = False; x.owner_admission_started = False
        x.owner = None; x.replacement_ready = True; x.deadline = time.monotonic()+600
        x.terminal_prepare_seconds = 30; x.terminal_cleanup_seconds = 10; x.terminal_reserve_seconds = 100
        x.channel = Mock(); x.channel.ceiling = x.deadline; x.evidence = Mock()
        x.check_unspent_owner = Mock(); x.check_transaction_lock = Mock(); x.check_prepared_state = Mock()
        x.condition = Mock(); x.reconcile_config = Mock(); x.p = Mock()
        x.terminal_stop_invocations = set(); x.recovery_new_seen = {}
        x.asset_map = transition.prepared_asset_map(r3)
        x.asset_states = {k: {'place': 'target', 'metadata': {}} for k in x.asset_map}
        x.barriers = {}; x.barrier_places = {}
        a = x.a = Mock(); a.replacement_active = True; a.b = {'unit_search_sha256': 'a'*64}
        a.unit_search.return_value = 'a'*64; a.deadline = x.deadline
        a.limit.side_effect = lambda deadline:nullcontext(); a.empty.return_value = True
        a.runtime_invocations = {}; a.own_dropins = {u:set() for u in r3.UNITS}; a.own_config_paths = set()
        fields = (*contexts.CURRENT_SECURITY, 'uid_map', 'gid_map', 'setgroups', 'exe_sha256',
                  'initial_env_sha256', 'lsm_sha256')
        rows = {}; processes = {}
        for n,u in enumerate(r3.UNITS):
            pid = 100+n
            rows[u] = {'MainPID': str(pid) if active else '0', 'ControlPID': '0', 'Job': '',
                       'ActiveState': 'active' if active else 'inactive', 'SubState': 'running' if active else 'dead',
                       'NRestarts': '0', 'Result': 'success', 'InvocationID': str(n+1)*32,
                       'ControlGroup': '/system.slice/'+u}
            processes[pid] = {**dict.fromkeys(fields, 'synthetic'), 'pid': pid, 'starttime': 1000+n,
                              'cgroup': '0::/system.slice/'+u}
            a.runtime_invocations[u] = (rows[u]['InvocationID'], pid, 1000+n)
        a.unit.side_effect = lambda unit:rows[unit]
        def stop(action, unit, *, deadline):
            self.assertEqual(action, 'stop')
            rows[unit].update(MainPID='0', ActiveState='inactive', SubState='dead')
            return SimpleNamespace(returncode=0)
        x.service_action = Mock(side_effect=stop)
        return x, rows, processes

    def run_terminal(self, x, rows, processes):
        with patch.object(transition, 'unit_rows', return_value=rows), \
             patch.object(transition, 'process', side_effect=lambda pid:processes[pid]):
            x.hold_known_new_units(deadline=x.deadline)

    def test_known_new_reverse_stop_is_terminal_and_never_claims_completion(self):
        x, rows, processes = self.fixture()
        self.run_terminal(x, rows, processes)
        self.assertEqual([c.args for c in x.service_action.call_args_list],
                         [('stop',u) for u in reversed(r3.UNITS)])
        self.assertEqual(x.a.stopped, set(r3.UNITS)); self.assertTrue(x.recovery_terminal)
        final = x.channel.record.call_args.args
        self.assertEqual(final[0], 'recovery_terminal_hold_current')
        self.assertFalse(final[1]['host_complete']); self.assertFalse(final[1]['owner_entered'])
        self.assertEqual(final[1]['original_status'], 'FAILED_HOLD')
        x.p.quarantine.assert_not_called()
        with self.assertRaises(io.Hold):self.run_terminal(x, rows, processes)
        self.assertEqual(x.service_action.call_count, 3)

    def test_unknown_invocation_job_or_source_delta_denies_every_service_action(self):
        for failure in ('identity', 'job', 'source'):
            x, rows, processes = self.fixture()
            if failure == 'identity':rows[r3.UNITS[0]]['InvocationID'] = 'f'*32
            if failure == 'job':rows[r3.UNITS[0]]['Job'] = 'unresolved'
            if failure == 'source':x.a.unit_search.return_value = 'b'*64
            with self.subTest(failure=failure), self.assertRaises(io.Hold):self.run_terminal(x, rows, processes)
            x.service_action.assert_not_called(); x.p.quarantine.assert_not_called()
            self.assertTrue(x.recovery_terminal)

    def test_insufficient_reserve_spends_terminal_entry_and_does_not_reset_deadline(self):
        x, rows, processes = self.fixture(); original = x.deadline = time.monotonic()+50
        with self.assertRaises(io.Hold):self.run_terminal(x, rows, processes)
        self.assertEqual(x.deadline, original); self.assertTrue(x.recovery_terminal)
        x.channel.record.assert_not_called(); x.service_action.assert_not_called()

    def test_owner_entry_excludes_even_stop_only_branch(self):
        x, rows, processes = self.fixture(); x.owner_admission_started = True
        with self.assertRaises(io.Hold):self.run_terminal(x, rows, processes)
        x.channel.record.assert_not_called(); x.service_action.assert_not_called()

    def test_unknown_stop_ack_is_not_replayed_or_followed_by_other_stops(self):
        x, rows, processes = self.fixture()
        x.service_action.side_effect = TimeoutError('synthetic missing stop response')
        with self.assertRaises(TimeoutError):self.run_terminal(x, rows, processes)
        self.assertTrue(x.recovery_terminal); self.assertEqual(x.service_action.call_count, 1)
        with self.assertRaises(io.Hold):self.run_terminal(x, rows, processes)
        self.assertEqual(x.service_action.call_count, 1)
        self.assertFalse(any(c.args[0] == 'recovery_terminal_hold_current' for c in x.channel.record.call_args_list))

    def test_stop_only_snapshot_cannot_accept_a_changed_kernel_profile(self):
        x, rows, processes = self.fixture(); self.run_terminal(x, rows, processes)
        # Records are serialized in production; retain the initial live view
        # separately because the adapter subsequently marks stopped units empty.
        u = r3.UNITS[0]; row = processes[100]
        fields = (*contexts.CURRENT_SECURITY, 'uid_map', 'gid_map', 'setgroups', 'exe_sha256',
                  'initial_env_sha256', 'lsm_sha256')
        auth = transition.RecoveryAuthority.__new__(transition.RecoveryAuthority)
        auth.terminal_profiles = {u: {'kind': 'known_new_stop_only',
            'identity': (rows[u]['InvocationID'], row['pid'], row['starttime']),
            'kernel': {k:row[k] for k in fields}}}
        auth.interpreter_binding = Mock(); auth.rights_check = Mock()
        auth.accepted_runtime_actor(u, row)
        auth.rights_check.assert_not_called()
        with self.assertRaises(io.Hold):auth.accepted_runtime_actor(u, {**row, 'exe_sha256': 'changed'})
        self.assertEqual(auth.interpreter_binding.call_count, 1)


class RecoveryLoadedConfigTests(unittest.TestCase):
    def fixture(self):
        a = transition.RecoveryAuthority.__new__(transition.RecoveryAuthority)
        a.evidence = SimpleNamespace(r=r3); a.recovery_allow_load_delta = True; a.recovery_reload_units = set()
        mapping = transition.prepared_asset_map(r3); a.recovery_assets = {k: {'place': 'target'} for k in mapping}
        a.own_dropins = {u: {s['target'] for s in mapping.values() if s['unit'] == u} for u in r3.UNITS}
        expected = {'fragment': '/etc/systemd/system/'+r3.UNITS[0], 'dropins': []}
        value = {'FragmentPath': expected['fragment'], 'Job': '', 'KillMode': 'control-group',
                 'NeedDaemonReload': 'yes', 'DropInPaths': ''}
        return a, value, expected

    def test_only_known_own_missing_load_delta_is_admitted_before_exact_reload(self):
        a, value, expected = self.fixture()
        a.unit_configuration_check(r3.UNITS[0], value, expected)
        self.assertEqual(a.recovery_reload_units, {r3.UNITS[0]})
        for change in ({'DropInPaths': '/etc/systemd/system/foreign.conf'}, {'Job': '1'},
                       {'FragmentPath': '/run/unknown.service'}, {'NeedDaemonReload': 'unknown'}):
            with self.subTest(change=change), self.assertRaises(io.Hold):
                a.unit_configuration_check(r3.UNITS[0], {**value, **change}, expected)
        a.recovery_allow_load_delta = False
        with self.assertRaises(io.Hold):a.unit_configuration_check(r3.UNITS[0], value, expected)
        a.unit_configuration_check(r3.UNITS[0], {**value, 'NeedDaemonReload': 'no',
                                   'DropInPaths': ' '.join(a.own_dropins[r3.UNITS[0]])}, expected)


class CurrentDatabaseReadTests(unittest.TestCase):
    def authority(self):
        a = observe.CurrentAuthority.__new__(observe.CurrentAuthority)
        a.b = {'database': {'role': 'chatops', 'database': 'synthetic'}}; a.deadline = 120
        return a

    def test_quiet_read_is_readonly_with_actual_connection_count_and_no_secret_in_arguments(self):
        a = self.authority()
        result = SimpleNamespace(returncode=0, stderr=b'', stdout=b'chatops|synthetic|on|t|t\nf|f|f|f|f\nt|f\n0\n')
        with patch.object(observe, 'command', return_value=result) as command:
            proof = a.database_readonly('postgresql://chatops:synthetic-secret@127.0.0.1/synthetic',
                                         require_other_connections_absent=True)
        args, kwargs = command.call_args
        self.assertNotIn('synthetic-secret', repr(args))
        self.assertEqual(kwargs['extra_env']['PGOPTIONS'], '-c default_transaction_read_only=on')
        self.assertIn(b'BEGIN READ ONLY;', kwargs['data'])
        self.assertIn(b'FROM pg_stat_activity WHERE datname=current_database()', kwargs['data'])
        self.assertTrue(kwargs['data'].endswith(b'ROLLBACK;'))
        self.assertFalse(proof['provider_data_emitted'])
        self.assertNotIn('synthetic-secret', repr(proof))

    def test_other_connection_or_unknown_result_refuses_quiet_admission_without_terminating_it(self):
        a = self.authority()
        for suffix in (b'1\n', b'\n', b'unknown\n'):
            result = SimpleNamespace(returncode=0, stderr=b'', stdout=b'chatops|synthetic|on|t|t\nf|f|f|f|f\nt|f\n'+suffix)
            with patch.object(observe, 'command', return_value=result) as command, self.assertRaises(io.Hold):
                a.database_readonly('postgresql://chatops@127.0.0.1/synthetic', require_other_connections_absent=True)
            self.assertEqual(command.call_count, 1)
            self.assertNotIn(b'pg_terminate_backend', command.call_args.kwargs['data'])


class RecoveryOrderTests(unittest.TestCase):
    def flow(self, state='F1', *, active_new=(), fail=None, partial_owner=False):
        journal = Mock(); journal.binding = 'b'*64
        adapter = Mock(); adapter.deadline = time.monotonic()+600; adapter.owner_admission_started = False
        effects = []; limits = []; stops_finished = state != 'F1'
        def observe(phase, *, deadline):
            nonlocal stops_finished
            facts = set(r3.RecoveryFlow.required[phase])
            if phase == 'recovery_admitted':facts.add(state)
            if phase.startswith('recovery_state:'):
                unit = phase.split(':', 1)[1]
                facts.add('known_new_active' if stops_finished and unit in active_new else
                          'empty_inactive' if stops_finished else 'known_old_active')
            if phase == 'quiet':stops_finished = True
            if phase == 'owner_ready' and partial_owner:
                adapter.owner_admission_started = True
                raise OSError('synthetic lost owner marker acknowledgement')
            return r3.Observation(r3.TX, journal.binding, phase, frozenset(facts), time.monotonic())
        def perform(action, unit, *, deadline):
            effects.append((action, unit)); limits.append((action, deadline-time.monotonic()))
            if action == fail:return None
            return {'action': action, 'unit': unit, 'outcome': 'CONFIRMED',
                    'cgroup_empty': True, 'no_job': True}
        adapter.observe.side_effect = observe; adapter.perform.side_effect = perform
        return r3.RecoveryFlow(adapter, journal), adapter, journal, effects, limits

    def test_f1_serial_stops_then_backup_restore_probes_assets_and_first_owner(self):
        flow, adapter, journal, effects, limits = self.flow()
        self.assertEqual(flow.recover(), 'RECOVERY_RIGHTS_OWNER_RECEIPTED_PENDING_OPERATOR_CLEANUP')
        self.assertEqual([u for a, u in effects if a == 'recovery_stop'], list(r3.STOP))
        self.assertEqual([u for a, u in effects if a == 'recovery_start'], list(r3.UNITS))
        names = [a for a, _ in effects]
        for earlier, later in zip(('recovery_private_backup', 'recovery_private_restore',
                                  'recovery_unused_or_verified_probes', 'recovery_publish_assets'),
                                 ('recovery_private_restore', 'recovery_unused_or_verified_probes',
                                  'recovery_publish_assets', 'supervised_owner_transaction')):
            self.assertLess(names.index(earlier), names.index(later))
        for action, remaining in limits:
            self.assertGreater(remaining, 0)
            self.assertLessEqual(remaining, 20 if action in ('recovery_stop', 'recovery_start') else 120)
        self.assertEqual(names.count('supervised_owner_transaction'), 1)
        self.assertFalse(journal.write.call_args.args[1]['final_host_acceptance'])
        adapter.hold_known_new_units.assert_not_called()


    def test_direct_f4_fresh_acceptance_of_active_new_units_never_restarts(self):
        flow, adapter, _, effects, _ = self.flow('F4', active_new=r3.UNITS)
        flow.recover()
        self.assertEqual(effects, [('recovery_reconcile_config', None), ('supervised_owner_transaction', None)])
        observed = [call.args[0] for call in adapter.observe.call_args_list]
        self.assertTrue(all('recovery_active:'+u in observed for u in r3.UNITS))
        self.assertNotIn('install', observed)

    def test_unconfirmed_recovery_stop_ends_without_replay_or_terminal_f4_action(self):
        flow, adapter, _, effects, _ = self.flow(fail='recovery_stop')
        with self.assertRaises(r3.FlowFailure):flow.recover()
        self.assertEqual(effects[-1], ('recovery_stop', r3.STOP[0]))
        self.assertTrue(flow.hold)
        with self.assertRaises(r3.Denied):flow.recover()
        with self.assertRaises(r3.Denied):flow.forward()
        with self.assertRaises(r3.Denied):flow.return_old()
        adapter.hold_known_new_units.assert_not_called()

    def test_f4_failure_allows_only_terminal_adapter_admission_no_further_start(self):
        flow, adapter, _, effects, _ = self.flow('F4', fail='recovery_start')
        with self.assertRaises(r3.FlowFailure):flow.recover()
        self.assertEqual([u for a, u in effects if a == 'recovery_start'], [r3.UNITS[0]])
        self.assertNotIn(('supervised_owner_transaction', None), effects)
        adapter.hold_known_new_units.assert_called_once_with(deadline=flow.deadline)
        with self.assertRaises(r3.Denied):flow.recover()

    def test_partial_owner_admission_blocks_terminal_service_actions(self):
        flow, adapter, _, effects, _ = self.flow('F4', active_new=r3.UNITS, partial_owner=True)
        with self.assertRaises(r3.FlowFailure):flow.recover()
        self.assertEqual(effects, [('recovery_reconcile_config', None)])
        adapter.hold_known_new_units.assert_not_called()
        with self.assertRaises(r3.Denied):flow.recover()

    def test_fresh_state_unknown_spends_recovery_without_effect(self):
        flow, adapter, journal, effects, _ = self.flow('UNCLASSIFIED')
        with self.assertRaises(r3.FlowFailure):flow.recover()
        journal.claim.assert_called_once()
        self.assertEqual(effects, [])
        adapter.hold_known_new_units.assert_not_called()


class ExistingBackupTests(unittest.TestCase):
    def fixture(self):
        root = '/opt/tu1nz_repos/public-web-isolation-r1/20261014-1'
        source = '/etc/tu1nz/example.json'; raw = b'{"fixture":true}'
        meta = {'device': 1, 'inode': 17, 'uid': 0, 'gid': 0, 'mode': 0o644,
                'type': stat.S_IFREG, 'nlink': 1, 'size': len(raw), 'mtime_ns': 10,
                'ctime_ns': 20, 'atime_ns': 10, 'attrs': {}, 'flags': 0}
        manifest = {source: {'copy': '000', 'sha256': io.sha(raw), 'original': dict(meta)}}
        manifest_raw = io.canonical(manifest)
        copy_meta = {**meta, 'mode': 0o600, 'inode': 18}
        manifest_meta = {**copy_meta, 'size': len(manifest_raw), 'inode': 19}
        restored_meta = {**meta, 'inode': 20, 'ctime_ns': 21}
        paths = Mock(); paths.get.side_effect = lambda path: path
        paths.d.PHYSICAL_FLAGS = 0x80000
        paths.d.metadata.return_value = {**meta, 'type': stat.S_IFDIR, 'mode': 0o700}
        values = {source: (raw, dict(meta)), root+'/restore-test/tree'+source: (raw, restored_meta)}
        private = {(root+'/before', 'manifest.json'): (manifest_raw, manifest_meta),
                   (root+'/before', '000'): (raw, copy_meta)}
        paths.read.side_effect = lambda path: values[path]
        paths.d.stable_file.side_effect = lambda parent, name: private[(parent, name)]
        names = {root+'/before': ['000', 'manifest.json'], root+'/restore-test': ['tree'],
                 root+'/restore-test/tree': ['etc'], root+'/restore-test/tree/etc': ['tu1nz'],
                 root+'/restore-test/tree/etc/tu1nz': ['example.json']}
        backup = fs.Backup(paths, {source: io.sha(raw)}, root, Mock())
        return backup, values, private, names, manifest_raw

    def classify(self, backup, values, private, names):
        def info(name, *, dir_fd, follow_symlinks):
            if dir_fd+'/'+name not in names:raise FileNotFoundError()
            return SimpleNamespace()
        backup.paths.d.stable_file.side_effect = lambda parent, name: (
            private[(parent, name)] if (parent, name) in private else values[parent+'/'+name])
        with patch.object(fs.os, 'stat', side_effect=info), patch.object(fs.os, 'listdir', side_effect=lambda p:names[p]):
            return backup.classify_original_for_recovery()

    def test_partial_private_copy_is_classified_without_finishing_repairing_or_claiming_restore(self):
        backup, values, private, names, _ = self.fixture(); before = backup.root+'/before'
        names[before] = ['000']; names[backup.root+'/restore-test'] = []
        raw, row = private[(before, '000')]; private[(before, '000')] = (raw[:5], row)
        proof = self.classify(backup, values, private, names)
        self.assertEqual(proof['state'], 'INCOMPLETE_PRIVATE_COPY_REQUIRES_NEW_FIXED_TEST')
        self.assertFalse(proof['old_objects_changed']); self.assertFalse(proof['old_restore_claimed_successful'])
        backup.paths.create_file.assert_not_called(); backup.paths.create_directory.assert_not_called()
        self.assertIsNone(backup.manifest)

    def test_complete_private_copy_and_restore_are_reused_by_current_readback(self):
        backup, values, private, names, _ = self.fixture()
        proof = self.classify(backup, values, private, names)
        self.assertEqual(proof['state'], 'COMPLETE_CURRENT_COPY_AND_RESTORE')
        self.assertFalse(proof['historical_ack_reconstructed'])
        backup.paths.create_file.assert_not_called(); backup.paths.create_directory.assert_not_called()

    def test_partial_restore_prefix_may_be_left_for_new_test_but_wrong_content_is_negative(self):
        for replacement in (b'{"fix', b'{"wrong'):
            backup, values, private, names, _ = self.fixture()
            key = next(k for k in values if '/restore-test/' in k); raw, row = values[key]
            values[key] = (replacement, {**row, 'mode': 0o600, 'mtime_ns': 99})
            if replacement == b'{"fix':
                self.assertEqual(self.classify(backup, values, private, names)['state'],
                                 'INCOMPLETE_PRIVATE_COPY_REQUIRES_NEW_FIXED_TEST')
            else:
                with self.assertRaisesRegex(io.Hold, 'NEGATIVE_CONTENT'):
                    self.classify(backup, values, private, names)

    def test_manifest_contradiction_foreign_name_or_malformed_manifest_cannot_trigger_fresh_copy(self):
        for fault in ('copy_lost_after_manifest', 'foreign', 'manifest'):
            backup, values, private, names, _ = self.fixture(); before = backup.root+'/before'
            if fault == 'copy_lost_after_manifest':names[before] = ['manifest.json']
            elif fault == 'foreign':names[before].append('not-owned')
            else:
                raw, row = private[(before, 'manifest.json')]; private[(before, 'manifest.json')] = (b'{', row)
            with self.subTest(fault=fault), self.assertRaises((io.Hold, ValueError)):
                self.classify(backup, values, private, names)
            backup.paths.create_file.assert_not_called(); backup.paths.create_directory.assert_not_called()

    def test_complete_current_backup_and_actual_restored_bytes_can_be_observed_without_ack_repair(self):
        backup, values, private, names, raw = self.fixture()
        with patch.object(fs.os, 'listdir', side_effect=lambda p: names[p]):
            proof = backup.load_verified_existing(expected_sha256=io.sha(raw))
        self.assertEqual(proof['manifest_sha256'], io.sha(raw))
        self.assertTrue(proof['current_copies_and_restored_metadata_verified'])
        self.assertFalse(proof['historical_ack_reconstructed'])
        self.assertFalse(proof['live_or_database_restore'])
        backup.paths.create_file.assert_not_called()
        backup.paths.create_directory.assert_not_called()
        backup.paths.d.new_file.assert_not_called()
        backup.paths.d.restore_metadata.assert_not_called()

    def test_interrupted_manifest_exact_prefix_needs_all_copies_and_no_restore_objects(self):
        for size in (0, 1, 70):
            backup, values, private, names, raw = self.fixture(); before = backup.root+'/before'
            names[backup.root+'/restore-test'] = []
            _, row = private[(before, 'manifest.json')]
            private[(before, 'manifest.json')] = (raw[:size], {**row, 'size': size})
            proof = self.classify(backup, values, private, names)
            self.assertEqual(proof['state'], 'INCOMPLETE_PRIVATE_COPY_REQUIRES_NEW_FIXED_TEST')
            self.assertIsNone(backup.manifest)
            self.assertEqual(private[(before, 'manifest.json')][0], raw[:size])
            backup.paths.create_directory.assert_not_called()
            backup.paths.d.new_file.assert_not_called()
            backup.paths.d.restore_metadata.assert_not_called()
            names[before] = ['manifest.json']
            with self.assertRaises(io.Hold):self.classify(backup, values, private, names)

    def test_changed_source_copy_restore_or_extra_object_cannot_be_adopted(self):
        for fault in ('source_metadata', 'copy', 'restore', 'restore_metadata', 'extra', 'wrong_manifest_hash'):
            with self.subTest(fault=fault):
                backup, values, private, names, raw = self.fixture()
                source = '/etc/tu1nz/example.json'; restored = backup.root+'/restore-test/tree'+source
                if fault == 'source_metadata':values[source][1]['ctime_ns'] += 1
                elif fault == 'copy':
                    key = (backup.root+'/before', '000'); private[key] = (b'wrong', private[key][1])
                elif fault == 'restore':values[restored] = (b'wrong', values[restored][1])
                elif fault == 'restore_metadata':values[restored][1]['gid'] = 1001
                elif fault == 'extra':names[backup.root+'/restore-test/tree/etc'].append('extra')
                with patch.object(fs.os, 'listdir', side_effect=lambda p: names[p]), self.assertRaises(io.Hold):
                    backup.load_verified_existing(expected_sha256='f'*64 if fault == 'wrong_manifest_hash' else io.sha(raw))
                self.assertIsNone(backup.manifest)
                backup.paths.d.new_file.assert_not_called()


class FirstOwnerEntryTests(unittest.TestCase):
    def adapter(self, *, ceiling=500, marker_error=False):
        a = transition.MaintenanceAdapter.__new__(transition.MaintenanceAdapter)
        a.owner_admission_started = False; a.owner = None; a.deadline = 500
        a.channel = Mock(spec=io.MaintenanceLinkedRecords); a.channel.ceiling = ceiling
        a.a = Mock(); a.a.limit.side_effect = lambda deadline: nullcontext()
        a.p = Mock(); a.r = r3; a.binding = 'a'*64; a.ready_raw = b'fixture'; a.plan_raw = b'bound plan'
        a.now = Mock(); a.function_all = Mock()
        supervisor = Mock(); owner_module = SimpleNamespace(Supervisor=supervisor)
        a.source = Mock(); a.source.load.side_effect = lambda name: owner_module if name == 'owner' else object()
        if marker_error:a.channel.begin_owner_admission.side_effect = io.Hold('PUBLIC_OPERATOR_MARKER_ACK_UNKNOWN')
        return a, supervisor

    def test_full_owner_window_is_required_before_marker_or_supervisor(self):
        a, supervisor = self.adapter(ceiling=220)
        with patch.object(transition.time, 'monotonic', return_value=100), self.assertRaises(io.Hold):
            a._observe('owner_ready', deadline=500)
        self.assertFalse(a.owner_admission_started)
        a.channel.cap.assert_not_called(); a.channel.begin_owner_admission.assert_not_called()
        supervisor.assert_not_called()

    def test_marker_failure_spends_admission_without_initializing_owner(self):
        a, supervisor = self.adapter(marker_error=True)
        with patch.object(transition.time, 'monotonic', return_value=100), self.assertRaises(io.Hold):
            a._observe('owner_ready', deadline=500)
        self.assertTrue(a.owner_admission_started)
        a.channel.cap.assert_called_once_with(220)
        supervisor.assert_not_called()
        with self.assertRaises(io.Hold):a._observe('owner_ready', deadline=500)
        a.channel.begin_owner_admission.assert_called_once()

    def test_marker_authority_and_supervisor_share_exactly_the_original_owner_deadline(self):
        a, supervisor = self.adapter(); order = []
        a.channel.begin_owner_admission.side_effect = lambda *_args, **_kwargs: order.append('marker')
        a.a.check.side_effect = lambda: order.append('authority')
        def construct(*args, **kwargs):
            order.append('supervisor'); return Mock()
        supervisor.side_effect = construct
        with patch.object(transition.time, 'monotonic', return_value=100):
            observed = a._observe('owner_ready', deadline=500)
        self.assertEqual(order, ['marker', 'authority', 'supervisor'])
        self.assertEqual(supervisor.call_args.kwargs['deadline'], 220)
        a.a.bounded.assert_called_once_with(220); a.channel.bounded.assert_called_once_with(220)
        self.assertIn('first_owner_marker_two_custodies_same_window', observed.facts)

    def test_actual_local_marker_is_create_only_and_change_is_detected(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as parent,\
             patch.object(r3, 'CUSTODY_PARENT', Path(parent)):
            wire = Mock(); wire.deadline = time.monotonic()+120
            c = client.MaintenanceClient(wire, r3, 'a'*64,
                boot_id='00000000-0000-0000-0000-000000000001', http_expectations=[])
            try:
                c.initialize(); c.journal.claim(); c.ready_sha256 = 'b'*64
                claim = {'kind': 'flow_claim', 'sequence': 1, 'value': {'transaction': r3.TX}}
                raw = io.canonical(claim); io.exclusive(c.fd, '001-flow_claim.json', raw)
                c.records['001-flow_claim.json'] = raw
                marker = io.owner_entry_marker(original_binding=c.binding, execution_binding=c.binding,
                    ready_sha256=c.ready_sha256, boot_id=c.boot_id, route='original')
                row = {'kind': 'owner_admission_intent', 'sequence': 2, 'value': marker}
                c.project_record(row); c.check()
                path = Path(parent)/r3.TX/'owner-admission-intent'
                before = path.read_bytes()
                self.assertEqual(before, io.canonical(marker))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                with self.assertRaises(io.Hold):c.project_record(row)
                self.assertEqual(path.read_bytes(), before)
                path.write_bytes(before+b' ')
                with self.assertRaises(io.Hold):c.check()
            finally:c.close()

    def test_main_transport_refuses_password_echo_fallback_before_ssh(self):
        import base64
        import getpass
        from contextlib import redirect_stdout
        from io import StringIO
        packet = {'binding': 'a'*64}
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as parent:
            roots = [Path(parent)/name for name in ('one', 'two')]
            for root in roots:root.mkdir(mode=0o700)
            fds = [os.open(root, os.O_RDONLY | os.O_DIRECTORY) for root in roots]
            with patch.object(client, 'preparation_records', return_value=(roots, fds)),\
                 patch.object(client.getpass, 'getpass', side_effect=getpass.fallback_getpass),\
                 patch.object(getpass, '_raw_input') as read_password,\
                 patch.object(client.subprocess, 'Popen') as ssh,\
                 patch.object(client.subprocess, 'run', return_value=SimpleNamespace(returncode=0)),\
                 redirect_stdout(StringIO()):
                result = client.execute(packet, {'io': base64.b64encode(b'fixture').decode()}, {}, {}, r3)
            self.assertEqual(result, 1)
            ssh.assert_not_called(); read_password.assert_not_called()
            for root in roots:
                self.assertEqual(io.parse((root/'result.json').read_bytes())['status'], 'HOLD')


class CurrentAuthorityContractTests(unittest.TestCase):
    def profile(self):
        return {'id': 'pid1', 'role': 'kernel_manager', 'purpose': 'Current host service manager',
                'max_instances': 1, 'exe': '/usr/lib/systemd/systemd',
                'uid': [0]*4, 'gid': [0]*4, 'groups': [], 'caps': {k: 0 for k in contexts.CAPS},
                'nnp': 0, 'cgroup': '0::/init.scope',
                'namespaces': {k: k+':[1]' for k in contexts.NS}}

    def row(self, profile):
        return {**{k: copy.deepcopy(profile[k]) for k in contexts.CURRENT_SECURITY}, 'pid': 1, 'starttime': '10'}

    def test_finite_current_profiles_do_not_require_thirteen_contexts_or_history(self):
        profile = self.profile()
        with patch.object(contexts, 'PROGRAMS', {}):
            self.assertEqual(contexts.current_profiles([profile]), [profile])
        self.assertNotIn('origin_sha256', profile)
        for old_requirement in ('argv_sha256', 'initial_env_sha256', 'code_inputs', 'authority_edges'):
            with self.subTest(field=old_requirement), self.assertRaises(io.Hold):
                contexts.current_profile({**profile, old_requirement: 'not a current permission'})

    def test_root_uid_and_same_executable_do_not_admit_an_unknown_context(self):
        profile = self.profile(); row = self.row(profile)
        self.assertTrue(contexts.current_profile_matches(row, profile))
        for field, value in (('pid', 2), ('cgroup', '0::/unknown.slice'), ('groups', [27]), ('nnp', 1),
                             ('namespaces', {k: k+':[2]' for k in contexts.NS})):
            with self.subTest(field=field):
                self.assertFalse(contexts.current_profile_matches({**row, field: value}, profile))
        for change in ({'max_instances': 0}, {'trusted': True}, {'uid': [True]*4}):
            with self.subTest(change=change), self.assertRaises(io.Hold):
                contexts.current_profile({**profile, **change})

    def test_dynamic_maintenance_role_requires_this_authenticated_ancestry(self):
        profile = self.profile(); profile.update(id='ssh-parent', role='authenticated_maintenance',
                                                  exe='/usr/sbin/sshd')
        row = self.row(profile); row.update(pid=123, starttime='20')
        self.assertFalse(contexts.current_profile_matches(row, profile))
        self.assertTrue(contexts.current_profile_matches(row, profile, authenticated_ancestors={(123, '20')}))
        self.assertFalse(contexts.current_profile_matches(row, profile, authenticated_ancestors={(123, '19')}))

    def test_direct_relevance_uses_fsuid_saved_ids_groups_and_active_capability(self):
        row = self.row(self.profile()); row.update(uid=[900]*4, gid=[900]*4, groups=[])
        row['caps']['CapBnd'] = 2**32-1
        def relevant(value):
            return contexts.directly_relevant(value, authority_uids=frozenset((0, 33, 1001)),
                                             authority_gids=frozenset((993,)))
        # False means only no DIRECT match. It grants no irrelevance/permission
        # until actual inherited-channel/policy/Writer checks also complete.
        self.assertFalse(relevant(row))
        for index in range(4):
            changed = copy.deepcopy(row); changed['uid'][index] = 0
            self.assertTrue(relevant(changed))
        self.assertTrue(relevant({**row, 'groups': [993]}))
        self.assertTrue(relevant({**row, 'caps': {**row['caps'], 'CapEff': 1}}))
        with self.assertRaises(io.Hold):relevant({**row, 'uid': [True]*4})


def current_sample(profile, pid, tick='10'):
    security = {k: copy.deepcopy(profile[k]) for k in contexts.CURRENT_SECURITY if k != 'exe'}
    security.update(uid_map=['0', '0', '4294967295'], gid_map=['0', '0', '4294967295'],
                    setgroups='allow', lsm_sha256='1'*64)
    return dict(security, pid=pid, ppid=1, starttime=tick, kernel_thread=0, exe=profile['exe'],
                task_observations=[dict(tid=pid, starttime=tick, security=copy.deepcopy(security))])


class CurrentTaskTests(unittest.TestCase):
    def setUp(self):
        self.profile = CurrentAuthorityContractTests().profile()
        self.profile['caps']['CapEff'] = 3
        self.row = current_sample(self.profile, 1)

    def test_current_task_may_drop_but_never_gain_authority(self):
        low = copy.deepcopy(self.row['task_observations'][0]); low['tid'] = 10
        low['security']['caps']['CapEff'] = 1; low['security']['nnp'] = 1
        self.row['task_observations'].append(low)
        self.assertEqual(contexts.current_task_check(self.row), 2)
        for field, value in (('groups', [27]), ('uid', [1001]*4), ('nnp', True),
                             ('namespaces', {k: k+':[2]' for k in contexts.NS}),
                             ('caps', {**low['security']['caps'], 'CapEff': 4})):
            changed = copy.deepcopy(self.row); changed['task_observations'][1]['security'][field] = value
            with self.subTest(field=field), self.assertRaises(io.Hold):contexts.current_task_check(changed)

    def test_later_good_sample_does_not_erase_bad_observed_worker(self):
        bad = copy.deepcopy(self.row['task_observations'][0]); bad['tid'] = 10
        bad['security']['caps']['CapEff'] = 4
        self.row['task_observations'].insert(0, bad)
        with self.assertRaises(io.Hold):contexts.current_task_check(self.row)

    def test_new_current_contract_cannot_enter_old_authority_or_context_binding(self):
        old = observe.Authority.__new__(observe.Authority)
        new = transition.CurrentReplacementAuthority.__new__(transition.CurrentReplacementAuthority)
        self.assertNotIn(contexts.CURRENT_BASELINE, old.baseline_schemas())
        self.assertEqual(new.baseline_schemas(), (contexts.CURRENT_BASELINE,))
        self.assertEqual(new.baseline_extra_fields({}), {'current_authority'})
        new.b = {'current_authority': {'observation_sha256': 'a'*64}, 'source_origin_receipts': ['b'*64]}
        present = dict(sha256='c'*64, uid=0, gid=0, mode=0o644, attrs={}, flags=0,
                       current_observation_sha256='a'*64)
        new.validate_file_binding(present)
        with self.assertRaises(io.Hold):old.validate_file_binding(present)
        with self.assertRaises(io.Hold):new.validate_file_binding({**present, 'origin_sha256': 'a'*64})

    def read_process(self, samples, listings):
        with patch.object(contexts, 'native'), patch.object(contexts, 'ProcessLifetime') as lifetime, \
             patch.object(contexts, 'read_proc', return_value=b'Kthread: 0\nPPid: 0\n'), \
             patch.object(observe, 'starttime', return_value='10'), \
             patch.object(observe.os, 'readlink', return_value=self.profile['exe']), \
             patch.object(observe.os, 'listdir', side_effect=listings), \
             patch.object(observe, 'thread_security', side_effect=samples):
            try:return observe.current_process(1, deadline=time.monotonic()+60)
            finally:lifetime.return_value.close.assert_called_once()

    def test_current_reader_retains_retired_worker_observation(self):
        security = self.row['task_observations'][0]['security']
        row = self.read_process([('10', security)]*5, [['1', '10'], ['1'], ['1']])
        self.assertEqual(set(row['current_tasks']), {'1'})
        self.assertEqual([r['tid'] for r in row['task_observations']], [1, 10, 1])

    def test_current_reader_fails_immediately_on_bad_worker_before_later_retirement(self):
        security = self.row['task_observations'][0]['security']
        bad = copy.deepcopy(security); bad['caps']['CapEff'] = 4
        with self.assertRaisesRegex(io.Hold, 'ADDITIONAL_OR_UNKNOWN_AUTHORITY'):
            self.read_process([('10', security), ('10', security), ('10', bad)], [['1', '10']])


class CurrentActorCensusTests(unittest.TestCase):
    def setUp(self):
        pid1 = CurrentAuthorityContractTests().profile()
        admin = copy.deepcopy(pid1)
        admin.update(id='daemon', role='administrative_service', purpose='Mapped current daemon',
                     exe='/usr/sbin/example', cgroup='0::/system.slice/example.service', max_instances=2)
        self.a = observe.CurrentAuthority.__new__(observe.CurrentAuthority)
        self.a.b = {'actors': [pid1, admin], 'broker_sockets': [], 'broker_tcp': []}
        self.a.contexts = None; self.a.targets = {}; self.a.rights = set(); self.a.runtime_invocations = {}
        self.a.operator_pid = 999; self.a.operator_start = '10'; self.a.deadline = time.monotonic()+60
        self.a.authenticated_ancestors = frozenset()
        self.a.relevant_identities = Mock(return_value=(frozenset((0, 33, 1001)), frozenset((0, 27, 993))))
        self.a.broker_endpoints = Mock(return_value=([], [])); self.a.delegation_check = Mock()
        self.rows = {1: current_sample(pid1, 1), 20: current_sample(admin, 20)}
        self.a.administrative_process = lambda pid: self.rows[pid]

    def run_census(self):
        with patch.object(observe.os, 'listdir', return_value=list(map(str, self.rows))), \
             patch.object(observe, 'process', side_effect=lambda pid: self.rows[pid]):
            self.a.actors_check(stop_only=False)

    def test_known_current_admin_does_not_need_historical_code_or_twenty_one_negative_queries(self):
        self.run_census(); self.a.delegation_check.assert_not_called()
        self.rows.pop(20)  # no mandatory stale membership list
        self.run_census()

    def test_root_same_uid_and_same_executable_in_unknown_context_is_denied(self):
        self.rows[20]['cgroup'] = '0::/unknown.slice'
        for sample in self.rows[20]['task_observations']:sample['security']['cgroup'] = self.rows[20]['cgroup']
        with self.assertRaisesRegex(io.Hold, 'UNKNOWN_RELEVANT'):self.run_census()
        self.a.delegation_check.assert_not_called()

    def test_no_direct_privilege_still_requires_actual_negative_channel_and_policy_check(self):
        profile = copy.deepcopy(self.a.b['actors'][1])
        profile.update(uid=[900]*4, gid=[900]*4, groups=[], cgroup='0::/system.slice/unrelated.service')
        self.rows[30] = current_sample(profile, 30)
        self.run_census(); self.a.delegation_check.assert_called_once_with(self.rows[30])
        self.a.delegation_check.side_effect = io.Hold('PUBLIC_OPERATOR_INHERITED_UNKNOWN')
        with self.assertRaisesRegex(io.Hold, 'INHERITED_UNKNOWN'):self.run_census()

    def test_known_tcb_does_not_waive_actual_writer_fences(self):
        self.a.paths = SimpleNamespace(check=Mock()); self.a.runtime = SimpleNamespace(check=Mock())
        with patch.object(observe, 'current_writer_check', side_effect=io.Hold('PUBLIC_OPERATOR_EXISTING_SOURCE_WRITABLE_FD')):
            with self.assertRaisesRegex(io.Hold, 'WRITABLE_FD'):self.a.check_writers({(1, 2)})
        self.a.runtime.check.assert_called_once()


class CurrentWriterCensusTests(unittest.TestCase):
    def run_scan(self, listings, worker, *, exists=False, proc=None):
        raw = '10 (synthetic) '+' '.join(['S']+['0']*18+['10'])
        def contents(path):
            return 'Kthread: 0\n' if path.endswith('/status') else raw
        with patch.object(runtime_guard.sys, 'platform', 'linux'), \
             patch.object(os, 'O_NOATIME', 0, create=True), \
             patch.object(runtime_guard.os, 'listdir', side_effect=listings), \
             patch.object(runtime_guard.os.path, 'lexists', return_value=exists), \
             patch.object(runtime_guard, 'proc_text', side_effect=proc or contents), \
             patch.object(runtime_guard, 'writer_task', side_effect=worker) as checked:
            runtime_guard.current_writer_check({(1, 2)}, time.monotonic()+60)
            return checked.call_args_list

    def test_actual_retired_worker_is_not_stale_membership_failure(self):
        def worker(path, *args, **kwargs):
            if path.endswith('/11'):raise FileNotFoundError()
        calls = self.run_scan([['10'], ['10', '11'], ['10'], ['10']], worker)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(c.kwargs == {'allow_closed_unidentified_fd': True} for c in calls))

    def test_live_unknown_worker_new_unmeasured_worker_and_positive_writer_deny(self):
        with self.assertRaisesRegex(io.Hold, 'LIVE_TASK_VIEW_UNKNOWN'):
            self.run_scan([['10'], ['10', '11']], Mock(side_effect=FileNotFoundError()), exists=True)
        with self.assertRaisesRegex(io.Hold, 'UNMEASURED_LIVE_TASK'):
            self.run_scan([['10'], ['10'], ['10'], ['10', '12']], Mock())
        with self.assertRaisesRegex(io.Hold, 'EXISTING_SOURCE_WRITABLE_FD'):
            self.run_scan([['10'], ['10']], Mock(side_effect=io.Hold('PUBLIC_OPERATOR_EXISTING_SOURCE_WRITABLE_FD')))

    def test_fully_exited_process_is_distinct_from_live_inaccessible_process(self):
        self.run_scan([['10']], Mock(), proc=Mock(side_effect=FileNotFoundError()))
        with self.assertRaisesRegex(io.Hold, 'LIVE_PROCESS_VIEW_UNKNOWN'):
            self.run_scan([['10']], Mock(), exists=True, proc=Mock(side_effect=FileNotFoundError()))
        with self.assertRaisesRegex(io.Hold, 'VIEW_UNKNOWN'):
            self.run_scan([['10']], Mock(), proc=Mock(side_effect=PermissionError()))


class OperatorSessionTests(unittest.TestCase):
    def test_private_session_created_once_before_claim_or_existing_own_session_verified(self):
        for existing in (False, True):
            with self.subTest(existing=existing), patch.object(contexts, 'native'), \
                 patch.object(observe.os, 'getpid', return_value=123), \
                 patch.object(observe.os, 'getsid', side_effect=[123 if existing else 1, 123]), \
                 patch.object(observe.os, 'getpgrp', return_value=123), \
                 patch.object(observe.os, 'setsid') as create, \
                 patch.object(observe, 'starttime', return_value='10'):
                self.assertEqual(observe.operator_session_start(deadline=time.monotonic()+30),
                                 dict(pid=123, starttime='10', session=123, process_group=123))
                self.assertEqual(create.call_count, 0 if existing else 1)

    def stat_bytes(self, pid, sid, tick):
        return (str(pid)+' (synthetic) '+' '.join(['S', '1', str(sid), str(sid)]+['0']*15+[tick])).encode()

    def test_orphan_helper_remains_visible_by_session_after_operator_exit(self):
        rows = {'/proc/20/stat': self.stat_bytes(20, 123, '10'),
                '/proc/30/stat': self.stat_bytes(30, 999, '11')}
        with patch.object(contexts, 'native'), patch.object(observe.os, 'listdir', return_value=['20', '30']), \
             patch.object(contexts, 'read_proc', side_effect=lambda path, *a, **k: rows[path]):
            self.assertEqual(observe.operator_session_members(123, deadline=time.monotonic()+30),
                             [dict(pid=20, starttime='10')])

    def test_session_read_cannot_hide_reused_pid_or_live_unknown(self):
        with patch.object(contexts, 'native'), patch.object(observe.os, 'listdir', return_value=['20']), \
             patch.object(contexts, 'read_proc', side_effect=[self.stat_bytes(20, 123, '10'),
                                                            self.stat_bytes(20, 123, '11')]):
            with self.assertRaisesRegex(io.Hold, 'MEMBER_CHANGED'):
                observe.operator_session_members(123, deadline=time.monotonic()+30)
        with patch.object(contexts, 'native'), patch.object(observe.os, 'listdir', return_value=['20']), \
             patch.object(contexts, 'read_proc', side_effect=FileNotFoundError()), \
             patch.object(observe.os.path, 'lexists', return_value=True):
            with self.assertRaisesRegex(io.Hold, 'LIVE_VIEW_UNKNOWN'):
                observe.operator_session_members(123, deadline=time.monotonic()+30)


class StartLimitObservationTests(unittest.TestCase):
    def watcher(self, interval=10_000_000, burst=5):
        watch = transition.StartLimitObservation.__new__(transition.StartLimitObservation)
        watch.owner = ':1.2'; watch.started = 100.0; watch.ready = True; watch.closed = False
        watch.failure = None; watch.pending = set(r3.UNITS); watch.events = 0
        watch.slots = {(u, m): object() for u in r3.UNITS for m in ('JobNew', 'JobRemoved')}
        watch.limits = {u: {'StartLimitIntervalUSec': interval, 'StartLimitBurst': burst} for u in r3.UNITS}
        watch.reader = SimpleNamespace(simple=Mock(return_value=watch.owner),
            start_limits=Mock(side_effect=lambda u: watch.limits[u]), lib=Mock(), check=watch.check_latched,
            broken=False, bus=None)
        watch.reader.lib.sd_bus_process.return_value = 0
        return watch

    def test_zero_restart_counter_is_not_a_quiet_interval_proof(self):
        watch = self.watcher(); unit = r3.UNITS[0]
        with patch.object(transition.time, 'monotonic', return_value=105):
            self.assertGreater(watch.remaining(unit), 5)
            with self.assertRaisesRegex(io.Hold, 'WINDOW_NOT_ELAPSED'):watch.retire_for_start(unit)
        self.assertIn(unit, watch.pending)
        with patch.object(transition.time, 'monotonic', return_value=110.002):watch.retire_for_start(unit)
        self.assertNotIn(unit, watch.pending)
        self.assertEqual(watch.reader.lib.sd_bus_slot_unref.call_count, 2)
        self.assertEqual(watch.started, 100.0)
        with self.assertRaises(io.Hold):watch.retire_for_start(unit)

    def test_existing_disabled_limiter_is_observed_not_written_or_reset(self):
        for interval, burst in ((0, 5), (10_000_000, 0)):
            watch = self.watcher(interval, burst)
            with self.subTest(interval=interval, burst=burst), patch.object(transition.time, 'monotonic', return_value=100):
                self.assertEqual(watch.remaining(r3.UNITS[0]), 0)
        watch = self.watcher(2**64-1)
        with self.assertRaisesRegex(io.Hold, 'INFINITE_WINDOW_UNPROVEN'):watch.remaining(r3.UNITS[0])

    def test_manager_change_limit_change_and_channel_loss_fail_closed(self):
        watch = self.watcher(); watch.reader.simple.return_value = ':1.3'
        with self.assertRaisesRegex(io.Hold, 'MANAGER_CHANGED'):watch.remaining(r3.UNITS[0])
        watch = self.watcher(); watch.reader.start_limits.side_effect = None
        watch.reader.start_limits.return_value = {'StartLimitIntervalUSec': 1, 'StartLimitBurst': 5}
        with self.assertRaisesRegex(io.Hold, 'CONFIGURATION_CHANGED'):watch.remaining(r3.UNITS[0])
        watch = self.watcher(); watch.reader.lib.sd_bus_process.return_value = -5
        with self.assertRaisesRegex(io.Hold, 'CHANNEL_LOST'):watch.remaining(r3.UNITS[0])
        self.assertTrue(watch.reader.broken)

    def test_event_cannot_be_erased_by_later_silence_or_used_as_start_permission(self):
        watch = self.watcher(); lib = watch.reader.lib
        lib.sd_bus_message_get_sender.return_value = b':1.2'
        lib.sd_bus_message_get_member.return_value = b'JobNew'; lib.sd_bus_message_at_end.return_value = 1
        values = iter((1, b'/org/freedesktop/systemd1/job/1', r3.UNITS[0].encode()))
        def basic(message, kind, pointer):pointer._obj.value = next(values); return 1
        lib.sd_bus_message_read_basic.side_effect = basic
        self.assertEqual(watch._event(None, None, None), 1)
        with patch.object(transition.time, 'monotonic', return_value=1000):
            with self.assertRaisesRegex(io.Hold, 'RELEVANT_JOB_OBSERVED'):watch.retire_for_start(r3.UNITS[0])
        self.assertEqual(watch.started, 100.0); self.assertEqual(watch.events, 1)
        watch.close(); self.assertTrue(watch.closed)


class MaintenanceStartAdmissionTests(unittest.TestCase):
    def adapter(self):
        adapter=transition.MaintenanceAdapter.__new__(transition.MaintenanceAdapter)
        adapter.deadline=600;adapter.channel=Mock();adapter.channel.ceiling=600
        adapter.start_limit_proofs={};adapter.condition=Mock()
        before=dict(InvocationID='a'*32, NRestarts='0', ActiveState='inactive', SubState='dead',
                    Result='success', MainPID='0', ControlPID='0', Job='')
        adapter.a=SimpleNamespace(check=Mock(), unit=Mock(return_value=before), empty=Mock(return_value=True))
        adapter.start_limit_observation=SimpleNamespace(remaining=Mock(return_value=0),
            retire_for_start=Mock(), owner=':1.2', started=90,
            limits={u:dict(StartLimitIntervalUSec=10_000_000,StartLimitBurst=5) for u in r3.UNITS})
        return adapter,before

    def test_durable_prior_counter_precedes_retiring_guard_for_one_real_request(self):
        adapter,before=self.adapter();order=[]
        adapter.channel.record.side_effect=lambda *args:order.append('record')
        adapter.start_limit_observation.retire_for_start.side_effect=lambda *args:order.append('retire')
        with patch.object(transition.time,'monotonic',return_value=100.1):
            adapter.before_start_request(r3.UNITS[0],before,old=False,deadline=120)
        self.assertEqual(order,['record','retire'])
        proof=adapter.start_limit_proofs[r3.UNITS[0]]
        self.assertEqual(proof['prior'],before);self.assertFalse(proof['counter_reset'])
        adapter.condition.assert_called_once_with(r3.UNITS[0],present=False)
        with self.assertRaises(io.Hold):adapter.before_start_request(r3.UNITS[0],before,old=False,deadline=120)

    def test_positive_counter_limit_hit_changed_state_or_insufficient_existing_budget_cannot_start(self):
        for change in ({'NRestarts':'1'},{'Result':'start-limit-hit'},{'Job':'1'},{'MainPID':'123'}):
            adapter,before=self.adapter()
            with self.subTest(change=change),self.assertRaises(io.Hold):
                adapter.before_start_request(r3.UNITS[0],{**before,**change},old=False,deadline=120)
            adapter.channel.record.assert_not_called()
            adapter.start_limit_observation.retire_for_start.assert_not_called()
        adapter,before=self.adapter();adapter.start_limit_observation.remaining.return_value=21
        with patch.object(transition.time,'monotonic',return_value=100),self.assertRaisesRegex(io.Hold,'BUDGET'):
            adapter.before_start_request(r3.UNITS[0],before,old=False,deadline=120)
        adapter.channel.record.assert_not_called()
        adapter,before=self.adapter();adapter.a.unit.return_value={**before,'InvocationID':'b'*32}
        with patch.object(transition.time,'monotonic',return_value=100),self.assertRaisesRegex(io.Hold,'STATE_CHANGED'):
            adapter.before_start_request(r3.UNITS[0],before,old=False,deadline=120)
        adapter.start_limit_observation.retire_for_start.assert_not_called()

    def test_no_legacy_start_or_conflicting_job_replacement_is_requested(self):
        adapter,_=self.adapter()
        with patch.object(transition,'command',return_value='synthetic') as command:
            self.assertEqual(adapter.service_action('start',r3.UNITS[0],deadline=120),'synthetic')
            self.assertEqual(command.call_args.args[0],
                             ['/usr/bin/systemctl','--job-mode=fail','start',r3.UNITS[0]])
            with self.assertRaises(io.Hold):adapter.service_action('restart',r3.UNITS[0],deadline=120)
        self.assertEqual(command.call_count,1)


if __name__ == '__main__':
    unittest.main()
