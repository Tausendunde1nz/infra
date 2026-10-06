"""Serialization/provenance negatives; these fixtures never grant live rights."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"scripts"))
import tu1nz_s8_execution_contract as c
import tu1nz_s8_execution_release as release
from tu1nz_s8_runtime_interfaces import CONFIG_NAMES
from tu1nz_s8_execution_observer import HISTORY_HASHES, BASE_UNIT_SHA256


def sample():
    return dict(schema="TU1NZ_S8_EXECUTION_FREEZE_V1", control=dict(commit="1"*40, tree="2"*40),
        application=dict(commit="3"*40, tree="4"*40), image=dict(sha256="5"*64, size=1024, metadata_sha256="6"*64),
        sources={name: "7"*64 for name in ("runtime.py", "polling.py", "recovery_admission.py")},
        control_sources={name: "8"*64 for name in release.SOURCE_NAMES},
        configurations={name: "9"*64 for name in CONFIG_NAMES},
        history=dict(application=list(c.HISTORICAL_APPLICATION), control=list(c.HISTORICAL_CONTROL),
                     hashes=HISTORY_HASHES.copy(), git_barriers="RETAINED", aborted="RETAINED_NO_CONTINUATION"),
        original_unit_sha256=BASE_UNIT_SHA256,
        safety=dict(slot=c.SLOT, maximum_starts=1, ordinary_claim_fallback=False, restart=False, s11_s12_acceptance=False,
            r15_pause_compatibility="OPEN", historical_cause="UNKNOWN", recovery=False, deployment=False, unlock=False,
            real_avs=False, adult_media=False, publishing=False, payment=False, controlled_beta=False, production=False),
        provenance=dict(control_review_head="a"*40, application_review_head="b"*40, control_pr=1, application_pr=2,
                        control_postmerge_ci=3, application_postmerge_ci=4, private_image_run=4, private_image_artifact=5))


def tag(value):
    raw = ("object "+value["control"]["commit"]+"\ntype commit\ntag "+c.FREEZE_TAG+
           "\ntagger Synthetic <fixture@example.invalid> 1 +0000\n\n").encode()+c.canonical(value)+b"\n"
    identity = hashlib.sha1(b"tag "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    return raw, identity


class ReleaseTests(unittest.TestCase):
    def test_exact_object_and_separate_release_roles(self):
        value = sample()
        raw, identity = tag(value)
        self.assertEqual(release.decode_tag(raw, tag_object=identity), (value, c.canonical(value)))
        self.assertFalse(value["safety"]["s11_s12_acceptance"])

    def test_different_object_name_commit_or_duplicate_header_rejected(self):
        raw, identity = tag(sample())
        for changed in (raw+b"\n", raw.replace(b"type commit", b"type tag"),
                        raw.replace(c.FREEZE_TAG.encode(), b"another-freeze"),
                        raw.replace(b"type commit\n", b"type commit\ntype commit\n")):
            with self.assertRaises(c.ContractError): release.decode_tag(changed, tag_object=identity)
        with self.assertRaises(c.ContractError): release.decode_tag(raw, tag_object="e"*40)

    def test_historical_identity_never_becomes_new_execution(self):
        value = sample(); value["application"]["commit"] = c.HISTORICAL_APPLICATION[0]
        with self.assertRaisesRegex(c.ContractError, "HISTORICAL_NOT_EXECUTION"):
            release.validate(value)
        value = sample(); value["history"]["hashes"]["repository-barrier.json"] = "c"*64
        with self.assertRaisesRegex(c.ContractError, "HISTORICAL_BINDING"):
            release.validate(value)

    def test_missing_provenance_and_relaxed_authority_rejected(self):
        for key in ("restart", "ordinary_claim_fallback", "s11_s12_acceptance", "recovery", "unlock", "production"):
            value = sample(); value["safety"][key] = True
            with self.assertRaises(c.ContractError): release.validate(value)
        for key in sample()["provenance"]:
            value = sample(); del value["provenance"][key]
            with self.assertRaises(c.ContractError): release.validate(value)
        value = sample(); value["image"]["size"] = True
        with self.assertRaises(c.ContractError): release.validate(value)


if __name__ == "__main__": unittest.main()
