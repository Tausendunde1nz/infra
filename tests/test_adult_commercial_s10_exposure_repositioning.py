from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-exposure-repositioning.json"
CONTROL_DOC = ROOT / "docs/COMMERCIAL_S10_EXPOSURE_REPOSITIONING_CONTROL.md"


class CommercialS10ExposureControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_exact_application_binding_and_no_go_decision(self) -> None:
        self.assertEqual(self.value["decision"], "NO_GO_PUBLIC_BRAND_ACTIVATION")
        self.assertFalse(self.value["active"])
        self.assertEqual(
            self.value["application"]["commit"],
            "cacf431f74fb2eccfe22236e8f8bd01614392301",
        )
        self.assertEqual(
            self.value["application"]["tree"],
            "7dd93a783028a2192e1cc868a5a1b5d0ccc74755",
        )
        self.assertEqual(
            self.value["control"]["expected_base_commit"],
            "70ef02af969406d61511a13d5c2b93a62ddb81d7",
        )
        self.assertEqual(self.value["control"]["application_post_merge_binding"], "BOUND")
        self.assertFalse(self.value["control"]["post_merge_binding_required"])

    def test_brand_is_provisional_and_all_external_actions_are_closed(self) -> None:
        brand = self.value["brand"]
        self.assertEqual(brand["provisional_public_name"], "Seen By Choice")
        self.assertEqual(brand["selection_status"], "PROVISIONAL_ONLY")
        self.assertFalse(brand["brand_activation_enabled"])
        self.assertFalse(brand["domain_acquired"])
        self.assertFalse(brand["social_handles_reserved"])
        self.assertFalse(brand["public_channel_rename_enabled"])
        self.assertFalse(brand["public_bot_rename_enabled"])
        self.assertFalse(self.value["research"]["manual_trademark_search_completed"])
        self.assertFalse(self.value["research"]["legal_trademark_clearance_completed"])

    def test_authorization_and_product_boundaries_are_fail_closed(self) -> None:
        self.assertTrue(all(flag is False for flag in self.value["authorization"].values()))
        self.assertTrue(all(flag is False for flag in self.value["product_boundary"].values()))
        required = {
            "MANUAL_DPMA_EUIPO_WIPO_SIMILARITY_SEARCH_REQUIRED",
            "LEGAL_TRADEMARK_CLEARANCE_REQUIRED",
            "DOMAIN_OWNERSHIP_REQUIRED",
            "SOCIAL_HANDLE_OWNERSHIP_REQUIRED",
            "SEPARATE_PUBLIC_ACTIVATION_AUTHORIZATION_REQUIRED",
        }
        self.assertTrue(required.issubset(self.value["blockers"]))

    def test_privacy_review_is_bound_without_opening_real_destinations(self) -> None:
        review = self.value["privacy_review"]
        self.assertEqual(review["status"], "COMPLETE_OFFLINE")
        self.assertEqual(review["findings_corrected"], 3)
        self.assertTrue(review["analytics_dimensions_allowlisted"])
        self.assertTrue(review["identifier_like_dimensions_blocked"])
        self.assertTrue(review["consent_types_exact"])
        self.assertTrue(review["synthetic_destination_only"])
        self.assertTrue(review["persona_inputs_validated"])
        self.assertFalse(review["sensitive_profile_storage"])
        self.assertFalse(review["real_destinations_authorized"])

    def test_evidence_is_offline_only_and_preserves_current_surface(self) -> None:
        self.assertTrue(self.value["public_surface"]["current_s7_s8_s9_surface_preserved"])
        self.assertTrue(self.value["public_surface"]["script_free_landing"])
        self.assertTrue(self.value["public_surface"]["form_free_landing"])
        self.assertTrue(self.value["public_surface"]["noindex_until_activation"])
        self.assertFalse(self.value["rollback"]["server_delta_exists"])
        self.assertFalse(self.value["rollback"]["server_rollback_required"])
        self.assertFalse(self.value["rollback"]["current_public_surface_changed"])

    def test_source_hashes_are_complete_and_token_free(self) -> None:
        hashes = self.value["source_sha256"]
        self.assertEqual(len(hashes), 12)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()))
        combined = MANIFEST.read_text(encoding="utf-8") + CONTROL_DOC.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", combined))


if __name__ == "__main__":
    unittest.main()
