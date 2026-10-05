"""Canonical release envelope; historical and isolated execution roles differ.

The annotated tag object is an operator-pinned immutable source identifier,
not human runtime authority. A separately protected, time-bound grant is still
required and cannot be inferred from a tag, CI result or historical success.
"""
import hashlib
import json

import tu1nz_s8_execution_contract as c
from tu1nz_s8_frozen_entry import MODULES
from tu1nz_s8_runtime_interfaces import CONFIG_NAMES
from tu1nz_s8_execution_observer import BASE_UNIT_SHA256, HISTORY_HASHES

SOURCE_NAMES = (*MODULES, "tu1nz_s8_execution", "tu1nz_s8_new_stock", "tu1nz_s8_execution_units",
                "tu1nz_s8_frozen_entry", "tu1nz_s8_execution_release", "tu1nz_s8_provision")


def decode_tag(raw: bytes, *, tag_object: str):
    c.require(type(raw) is bytes and 0 < len(raw) <= 262144 and c.hex_value(tag_object, 40), "FREEZE_OBJECT_RED")
    actual = hashlib.sha1(b"tag "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    c.require(actual == tag_object, "FREEZE_OBJECT_RED")
    head, separator, payload = raw.partition(b"\n\n")
    rows = [line.decode("ascii").split(" ", 1) for line in head.splitlines()]
    c.require(separator and all(len(row) == 2 for row in rows) and len(rows) == len(dict(rows))
              and set(dict(rows)) == {"object", "type", "tag", "tagger"}, "FREEZE_ENVELOPE_RED")
    header = dict(rows)
    c.require(header["type"] == "commit" and header["tag"] == c.FREEZE_TAG, "FREEZE_NAME_RED")
    value = json.loads(payload)
    c.require(c.canonical(value)+b"\n" == payload, "FREEZE_CANONICAL_RED")
    validate(value)
    c.require(value["control"]["commit"] == header["object"], "FREEZE_TARGET_RED")
    return value, c.canonical(value)


def validate(value):
    c.require(type(value) is dict and set(value) == {
        "schema", "control", "application", "image", "sources", "control_sources", "configurations",
        "history", "original_unit_sha256", "safety", "provenance"}
        and value["schema"] == "TU1NZ_S8_EXECUTION_FREEZE_V1", "RELEASE_ENVELOPE_RED")
    for role in ("control", "application"):
        c.require(type(value[role]) is dict and set(value[role]) == {"commit", "tree"}
                  and all(c.hex_value(v, 40) for v in value[role].values()), "RELEASE_IDENTITY_RED")
    c.require(value["application"]["commit"] != c.HISTORICAL_APPLICATION[0], "HISTORICAL_NOT_EXECUTION_RELEASE")
    image = value["image"]
    c.require(type(image) is dict and set(image) == {"sha256", "size", "metadata_sha256"}
              and c.hex_value(image["sha256"], 64) and c.hex_value(image["metadata_sha256"], 64)
              and type(image["size"]) is int and 0 < image["size"] <= 1024*1024*1024, "RELEASE_IMAGE_RED")
    for field, keys in (("sources", {"runtime.py", "polling.py", "recovery_admission.py"}),
                        ("control_sources", set(SOURCE_NAMES)), ("configurations", set(CONFIG_NAMES))):
        c.require(type(value[field]) is dict and set(value[field]) == keys
                  and all(c.hex_value(v, 64) for v in value[field].values()), "RELEASE_ARTIFACTS_RED")
    c.require(value["history"] == dict(application=list(c.HISTORICAL_APPLICATION), control=list(c.HISTORICAL_CONTROL),
              hashes=HISTORY_HASHES, git_barriers="RETAINED", aborted="RETAINED_NO_CONTINUATION")
              and value["original_unit_sha256"] == BASE_UNIT_SHA256, "HISTORICAL_BINDING_RED")
    c.require(value["safety"] == dict(slot=c.SLOT, maximum_starts=1, ordinary_claim_fallback=False,
        restart=False, s11_s12_acceptance=False, r15_pause_compatibility="OPEN", historical_cause="UNKNOWN",
        recovery=False, deployment=False, unlock=False, real_avs=False, adult_media=False,
        publishing=False, payment=False, controlled_beta=False, production=False), "RELEASE_SCOPE_RED")
    p = value["provenance"]
    c.require(type(p) is dict and set(p) == {"control_review_head", "application_review_head", "control_pr",
        "application_pr", "control_postmerge_ci", "application_postmerge_ci", "private_image_run", "private_image_artifact"},
        "RELEASE_PROVENANCE_RED")
    for field in ("control_review_head", "application_review_head"):
        c.require(c.hex_value(p[field], 40), "RELEASE_PROVENANCE_RED")
    for field in set(p)-{"control_review_head", "application_review_head"}:
        c.require(type(p[field]) is int and p[field] > 0, "RELEASE_PROVENANCE_RED")
    # Runtime parses these references only. Source closure must independently
    # verify their actual GitHub outcomes and exact trees before making the tag.
    return value
