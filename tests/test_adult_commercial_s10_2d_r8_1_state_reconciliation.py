from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/tu1nz_adult_public_s10_2d_state_reconcile.py"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s10_2d_control.sh"
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2d-r8-1-retained-state-reconciliation.json"
CONTROL = ROOT / "docs/COMMERCIAL_S10_2D_R8_1_RETAINED_STATE_RECONCILIATION.md"

SPEC = importlib.util.spec_from_file_location("s10_2d_r8_1_state", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
STATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATE)


class CommercialS102DR81StateReconciliationTests(unittest.TestCase):
    RELEASE = "s10-2d-r3-5"
    RUN = "11111111-1111-4111-8111-111111111111"
    CUTOVER = "2026-09-07T15:37:04.000000Z"
    SUBJECT = "22222222-2222-4222-8222-222222222222"
    USER = "synthetic-test-identity"
    JOIN = "2026-09-08T03:38:05.720000Z"
    ACTIVE = "2026-09-08T03:38:25.905000Z"

    @classmethod
    def _runtime(cls, *, active_product: bool = False) -> dict[str, object]:
        return {
            "release_id": cls.RELEASE,
            "run_id": cls.RUN,
            "cutover_started_at": cls.CUTOVER,
            "readiness": "GREEN" if active_product else "PENDING",
            "acquisition_ready": active_product,
            "baseline_start": "2026-09-08T04:00:00.000000Z" if active_product else None,
        }

    @classmethod
    def _sample(cls, number: int, *, source: str, occurred_at: str) -> dict[str, object]:
        return {
            "sample_id": f"00000000-0000-4000-8000-{number:012d}",
            "source": source,
            "bot_response_latency_ms": 500 + number,
            "poll_lag_ms": 100,
            "handler_duration_ms": 100,
            "send_ack_ms": 100,
            "occurred_at": occurred_at,
            "release_id": cls.RELEASE,
            "run_id": cls.RUN,
            "evidence_class": "TECHNICAL_ACCEPTANCE",
            "cutover_started_at": cls.CUTOVER,
        }

    @classmethod
    def current_r8_fixture(cls) -> dict[str, object]:
        latency = [
            cls._sample(index, source="DIRECT", occurred_at=f"2026-09-08T03:3{index}:00.000000Z")
            for index in range(1, 13)
        ]
        latency.extend((
            cls._sample(13, source="COMMUNITY", occurred_at=cls.JOIN),
            cls._sample(14, source="COMMUNITY", occurred_at=cls.ACTIVE),
        ))
        return {
            "runtime": cls._runtime(),
            "members": [{
                "subject_id": cls.SUBJECT,
                "telegram_user_id": cls.USER,
                "community_state": "ACTIVE",
                "self_attested": True,
                "warning_count": 0,
                "ban_state": False,
                "joined_at": cls.JOIN,
                "updated_at": cls.ACTIVE,
            }],
            "community_events": [
                {"event_id": "30000000-0000-4000-8000-000000000001", "event_type": "COMMUNITY_JOIN", "subject_id": cls.SUBJECT, "occurred_at": cls.JOIN},
                {"event_id": "30000000-0000-4000-8000-000000000002", "event_type": "RULES_ACCEPTED", "subject_id": cls.SUBJECT, "occurred_at": cls.ACTIVE},
                {"event_id": "30000000-0000-4000-8000-000000000003", "event_type": "COMMUNITY_ACTIVE_MEMBER", "subject_id": cls.SUBJECT, "occurred_at": cls.ACTIVE},
            ],
            "rate_limits": [],
            "moderation_events": [],
            "moderation_outbox": [],
            "latency": latency,
        }

    @staticmethod
    def provider(status: str = "left") -> dict[str, object]:
        return {"status": status, "is_human": True, "non_privileged": True}

    def test_current_r8_is_red_then_exact_acceptance_ownership_is_green(self) -> None:
        fixture = self.current_r8_fixture()
        with self.assertRaisesRegex(STATE.StateContractError, "MIGRATION_0029_RETAINED_PRODUCT_STATE"):
            STATE.retained_preflight(fixture)
        report = STATE.classify_retained_state(
            fixture,
            ownership_class="FAILED_RELEASE_TARGET_STATE_CONFIRMED",
            provider=self.provider("restricted"),
        )
        self.assertEqual(report["community_rows"], 1)
        self.assertEqual(report["latency_rows"], 14)
        self.assertEqual(report["unknown_rows"], 0)
        self.assertFalse(report["name_used_as_proof"])

    def test_live_manifest_binding_is_release_run_and_cutover_specific(self) -> None:
        fixture = self.current_r8_fixture()
        expected_run_hash = STATE.sha256_bytes(self.RUN.encode("ascii"))
        STATE.require_manifest_binding(
            fixture,
            expected_release_id=self.RELEASE,
            expected_run_id_sha256=expected_run_hash,
            expected_cutover_started_at=self.CUTOVER,
        )
        with self.assertRaisesRegex(STATE.StateContractError, "RETAINED_MANIFEST_RELEASE_MISMATCH_RED"):
            STATE.require_manifest_binding(
                fixture,
                expected_release_id="different-release",
                expected_run_id_sha256=expected_run_hash,
                expected_cutover_started_at=self.CUTOVER,
            )

    def test_unknown_member_is_never_reconciled(self) -> None:
        fixture = self.current_r8_fixture()
        fixture["community_events"] = fixture["community_events"][:-1]
        with self.assertRaisesRegex(STATE.StateContractError, "RETAINED_MEMBER_EVENT_OWNERSHIP_RED"):
            STATE.reconcile_model(
                fixture,
                ownership_class="INTERNAL_ACCEPTANCE_CONFIRMED",
                provider=self.provider(),
            )

    def test_unknown_latency_is_never_reconciled(self) -> None:
        fixture = self.current_r8_fixture()
        fixture["latency"][0]["run_id"] = "99999999-9999-4999-8999-999999999999"
        with self.assertRaisesRegex(STATE.StateContractError, "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN"):
            STATE.reconcile_model(
                fixture,
                ownership_class="FAILED_RELEASE_TARGET_STATE_CONFIRMED",
                provider=self.provider(),
            )

    def test_real_product_member_is_preserved_and_cleanup_is_forbidden(self) -> None:
        fixture = self.current_r8_fixture()
        fixture["runtime"] = self._runtime(active_product=True)
        report = STATE.retained_preflight(fixture)
        self.assertEqual(report["safe_code"], "S10_2D_REAL_PRODUCT_STATE_PRESERVED")
        self.assertFalse(report["cleanup_permitted"])
        self.assertEqual(report["community_rows"], 1)

    def test_provider_must_exit_before_database_reconciliation(self) -> None:
        with self.assertRaisesRegex(STATE.StateContractError, "RETAINED_PROVIDER_EXIT_REQUIRED"):
            STATE.reconcile_model(
                self.current_r8_fixture(),
                ownership_class="INTERNAL_ACCEPTANCE_CONFIRMED",
                provider=self.provider("restricted"),
            )

    def test_acceptance_lifecycle_reconciles_to_next_release_preflight(self) -> None:
        reconciled, report = STATE.reconcile_model(
            self.current_r8_fixture(),
            ownership_class="FAILED_RELEASE_TARGET_STATE_CONFIRMED",
            provider=self.provider(),
        )
        self.assertEqual(report["safe_code"], "S10_2D_RETAINED_STATE_RECONCILED")
        preflight = STATE.retained_preflight(reconciled)
        self.assertEqual(preflight["safe_code"], "S10_2D_CLEAN_CUTOVER_BASELINE_GREEN")

    def test_repeated_reconciliation_is_idempotent(self) -> None:
        reconciled, first = STATE.reconcile_model(
            self.current_r8_fixture(),
            ownership_class="FAILED_RELEASE_TARGET_STATE_CONFIRMED",
            provider=self.provider(),
        )
        repeated, second = STATE.reconcile_model(
            reconciled,
            ownership_class="FAILED_RELEASE_TARGET_STATE_CONFIRMED",
            provider=self.provider(),
        )
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(repeated, reconciled)

    def test_multi_release_and_safe_summary_never_emit_identifiers(self) -> None:
        reconciled, _ = STATE.reconcile_model(
            self.current_r8_fixture(),
            ownership_class="FAILED_RELEASE_TARGET_STATE_CONFIRMED",
            provider=self.provider(),
        )
        self.assertEqual(STATE.retained_preflight(reconciled)["community_rows"], 0)
        release_b = self.current_r8_fixture()
        release_b["runtime"]["release_id"] = "s10-2d-r8"
        for sample in release_b["latency"]:
            sample["release_id"] = "s10-2d-r8"
        report = STATE.classify_retained_state(
            release_b,
            ownership_class="INTERNAL_ACCEPTANCE_CONFIRMED",
            provider=self.provider("member"),
        )
        self.assertEqual(report["unknown_rows"], 0)
        summary = STATE.safe_summary(release_b, self.provider("member"))
        serialized = STATE.canonical_json(summary).decode("ascii")
        self.assertNotIn(self.USER, serialized)
        self.assertNotIn(self.SUBJECT, serialized)
        self.assertFalse(summary["identifiers_emitted"])

    def test_controller_places_provider_gate_after_backup_preflight_and_before_mutation(self) -> None:
        controller = CONTROLLER.read_text(encoding="utf-8")
        deploy = controller.split("deploy() {", 1)[1].split("observation_snapshot() {", 1)[0]
        self.assertLess(deploy.index('preflight "$1" "$2" "$3"'), deploy.index("target_group_capability_verify"))
        self.assertLess(deploy.index("target_group_capability_verify"), deploy.index('before="$(database_floor)"'))
        self.assertLess(deploy.index("target_group_capability_verify"), deploy.index("quiesce"))
        self.assertIn("1:1)", controller)
        self.assertIn("require_retained_state_preflight", controller)
        self.assertIn("state-preflight)", controller)

    def test_live_contract_is_row_specific_backup_first_and_has_no_bulk_cleanup(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("RETAINED_LIVE_STATE_MISMATCH_RED", source)
        self.assertIn("RETAINED_MANIFEST_RUN_MISMATCH_RED", source)
        self.assertIn("pg_dump", source)
        self.assertIn("ACCESS EXCLUSIVE MODE", source)
        self.assertIn("sample_id IN", source)
        self.assertIn("event_id IN", source)
        self.assertIn("telegram_user_id", source)
        self.assertIn("commercial_s10_2d_runtime_control, commercial_s10_2d_bot_polling_state", source)
        self.assertIn("current_snapshot(snapshot)", source)
        self.assertIn("DISABLE TRIGGER commercial_s10_2d_latency_append_only", source)
        self.assertIn("ENABLE TRIGGER commercial_s10_2d_latency_append_only", source)
        self.assertIn("DISABLE TRIGGER commercial_s10_2d_community_events_append_only", source)
        self.assertIn("ENABLE TRIGGER commercial_s10_2d_community_events_append_only", source)
        self.assertNotIn('command.extend(("--file"', source)
        self.assertIn("_write_new(path, result.stdout)", source)
        self.assertNotIn("DELETE WHERE state='ACTIVE'", source)
        self.assertNotIn("TRUNCATE", source.upper())

    def test_live_sql_rechecks_the_complete_snapshot_after_locking(self) -> None:
        fixture = self.current_r8_fixture()
        fixture["members"][0]["telegram_user_id"] = str(len(fixture["members"]))
        sql = STATE._reconciliation_sql({"inventory": fixture})
        self.assertLess(sql.index("LOCK TABLE"), sql.index("current_snapshot(snapshot)"))
        self.assertLess(sql.index("current_snapshot(snapshot)"), sql.index("DELETE FROM"))
        self.assertIn('"community_state":"ACTIVE"', sql)
        self.assertIn("commercial_s10_2d_runtime_control, commercial_s10_2d_bot_polling_state", sql)
        self.assertLess(
            sql.index("DISABLE TRIGGER commercial_s10_2d_community_events_append_only"),
            sql.index("DELETE FROM commercial_s10_2d_community_events"),
        )
        self.assertLess(
            sql.index("DELETE FROM commercial_s10_2d_community_events"),
            sql.index("ENABLE TRIGGER commercial_s10_2d_community_events_append_only"),
        )

    def test_manifest_and_control_preserve_scope_and_privacy_boundaries(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertFalse(manifest["scope"]["application_change"])
        self.assertFalse(manifest["scope"]["runtime_cutover"])
        self.assertFalse(manifest["scope"]["community_activation"])
        self.assertEqual(manifest["ownership"]["classification"], "FAILED_RELEASE_TARGET_STATE_CONFIRMED")
        self.assertFalse(manifest["ownership"]["display_name_used_as_proof"])
        self.assertTrue(manifest["reconciliation_contract"]["real_product_state_preserved"])
        self.assertFalse(manifest["reconciliation_contract"]["bulk_delete_available"])
        material = MANIFEST.read_text(encoding="utf-8") + CONTROL.read_text(encoding="utf-8")
        self.assertNotIn(self.USER, material)
        self.assertNotIn(self.SUBJECT, material)
        for boundary in ("adult_media", "avs", "payments", "publishing", "controlled_beta"):
            self.assertFalse(manifest["scope"][boundary])


if __name__ == "__main__":
    unittest.main()
