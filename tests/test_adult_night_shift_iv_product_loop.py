from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-night-shift-iv-product-loop.json"
S10_2B_MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-2b-public-telegram-brand-migration.json"
S10_2B_CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s10_2b_control.sh"
CONTROL = ROOT / "docs/NIGHT_SHIFT_IV_PRODUCT_LOOP_CONTROL_2026-09-03.md"


class NightShiftIVProductLoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.s10_2b = json.loads(S10_2B_MANIFEST.read_text(encoding="utf-8"))
        self.controller = S10_2B_CONTROLLER.read_text(encoding="utf-8")
        self.control = CONTROL.read_text(encoding="utf-8")

    def test_application_is_bound_to_green_merge_commit(self) -> None:
        application = self.value["application"]
        self.assertEqual(application["canonical_commit"], "f9747088a31ec6c671e82de24e293ebdec99f717")
        self.assertEqual(application["canonical_tree"], "7defedef032f6af38bbce0165eb6c2bdec327df7")
        self.assertEqual(application["pull_request"], 106)
        self.assertEqual(application["merge_mode"], "MERGE_COMMIT")
        self.assertEqual(application["post_merge_ci"], 33809025595)
        self.assertEqual(application["local_unit_tests"], 959)

    def test_loop_is_single_action_aggregate_and_product_first(self) -> None:
        loop = self.value["product_loop"]
        self.assertEqual(loop["mode"], "ONE_EVIDENCE_BACKED_ACTION")
        self.assertEqual(loop["priorities"][-1], "INFRASTRUCTURE")
        self.assertEqual(loop["funnel_events"], [
            "LANDING_VIEW", "TELEGRAM_CTA", "BOT_START", "INTRO_COMPLETED",
            "WAITLIST_JOINED", "OPT_IN", "REFERRAL",
        ])
        self.assertTrue(loop["aggregate_only"])
        self.assertTrue(loop["attribution_allowlisted"])
        self.assertFalse(loop["autonomous_task_generation"])
        self.assertTrue(loop["p3_p4_require_product_impact"])
        self.assertEqual(loop["ape_state"], "ABSENT")

    def test_s10_2b_is_rebound_but_remains_unmutated_and_waiting(self) -> None:
        cutover = self.value["telegram_cutover"]
        self.assertEqual(cutover["state"], "WAITING_OPERATOR_SUDO_PREFLIGHT")
        self.assertFalse(cutover["preflight_mutation_performed"])
        self.assertFalse(cutover["credential_requested_or_bypassed"])
        self.assertTrue(cutover["legacy_public_path_preserved"])
        self.assertEqual(self.s10_2b["application"]["target_commit"], self.value["application"]["canonical_commit"])
        self.assertEqual(self.s10_2b["application"]["target_tree"], self.value["application"]["canonical_tree"])
        self.assertEqual(self.s10_2b["application"]["post_merge_ci"], self.value["application"]["post_merge_ci"])
        self.assertEqual(
            hashlib.sha256(S10_2B_CONTROLLER.read_bytes()).hexdigest(),
            self.s10_2b["control"]["controller_sha256"],
        )
        subprocess.run(["bash", "-n", str(S10_2B_CONTROLLER)], check=True)

    def test_source_only_state_and_every_new_risk_boundary_are_closed(self) -> None:
        deployment = self.value["deployment"]
        self.assertEqual(deployment["state"], "SOURCE_GREEN_WAITING_OPERATOR")
        self.assertTrue(deployment["source_only"])
        self.assertTrue(deployment["partial_server_sync_forbidden"])
        self.assertFalse(deployment["database_migration"])
        self.assertTrue(all(value is False for value in self.value["product_boundary"].values()))
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", self.control))


if __name__ == "__main__":
    unittest.main()
