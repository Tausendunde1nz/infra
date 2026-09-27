import copy
import hashlib
import json
import unittest
from tu1nz_privilege_v4_review import reconstruct, classify_root_path

SOURCE = "a" * 64


def fixture():
    section = {"section": "file-0000", "status": "OK", "result": {"absent": True}}
    hashes = {"file-0000.json": hashlib.sha256(json.dumps(section, sort_keys=True).encode()).hexdigest()}
    manifest = {"version": "4.0.0", "source_sha256": SOURCE, "status": "COMPLETE",
                "interrupted": False, "file_hashes": hashes, "sections": [section]}
    return {"status": "COMPLETE", "sections": [section],
            "manifest_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()}


class ReviewTests(unittest.TestCase):
    def test_reconstruction(self):
        report = fixture()
        original = copy.deepcopy(report)
        self.assertFalse(reconstruct(report, SOURCE)["interrupted"])
        self.assertEqual(report, original)

    def test_changed_section_denied(self):
        report = fixture()
        report["sections"][0]["result"]["absent"] = False
        with self.assertRaises(ValueError):
            reconstruct(report, SOURCE)

    def test_wrong_source_denied(self):
        with self.assertRaises(ValueError):
            reconstruct(fixture(), "b" * 64)

    def test_duplicate_section_denied(self):
        report = fixture()
        report["sections"].append(copy.deepcopy(report["sections"][0]))
        with self.assertRaises(ValueError):
            reconstruct(report, SOURCE)

    def test_status_not_reclassified(self):
        report = fixture()
        report["status"] = "INCOMPLETE"
        with self.assertRaises(ValueError):
            reconstruct(report, SOURCE)

    def test_root_exec_and_parent_replacement_are_blockers(self):
        self.assertEqual(classify_root_path(root_caller=True, executable_writable=True,
            parent_replaceable=True, target_writable=True), "BLOCKED_ROOT_EXECUTES_USER_WRITABLE_CODE")
        self.assertEqual(classify_root_path(root_caller=True, executable_writable=False,
            parent_replaceable=True, target_writable=False), "BLOCKED_ROOT_WRITES_THROUGH_REPLACEABLE_PARENT")

    def test_mutable_file_is_not_claimed_replaceable_parent(self):
        self.assertEqual(classify_root_path(root_caller=True, executable_writable=False,
            parent_replaceable=False, target_writable=True), "USER_MUTABLE_ROOT_OUTPUT_INTEGRITY_REVIEW")

    def test_unknown_identity_requires_review(self):
        self.assertEqual(classify_root_path(root_caller=None, executable_writable=True,
            parent_replaceable=True, target_writable=True), "REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
