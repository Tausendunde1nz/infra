"""Pure review of sanitized V4 output; never changes the original evidence.

A matching reconstruction authenticates consistency with the exported manifest
hash, not a fresh independent read of the private root-owned raw files.
"""
import hashlib
import json
import re


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def reconstruct(report, source_sha):
    if not re.fullmatch(r"[0-9a-f]{64}", source_sha):
        raise ValueError("source_hash")
    if report.get("status") not in ("COMPLETE", "INCOMPLETE"):
        raise ValueError("status")
    sections = report["sections"]
    hashes = {}
    names = set()
    for section in sections:
        name = section["section"]
        if (not re.fullmatch(r"(?:file-[0-9]{4}|tree-[0-9]+|units|privileged-open-writers)", name)
                or name in names or section["status"] not in ("OK", "INCOMPLETE")):
            raise ValueError("section")
        names.add(name)
        hashes[name + ".json"] = digest(section)
        result = section.get("result")
        if isinstance(result, dict) and "content_summary" in result:
            if not name.startswith("file-"):
                raise ValueError("raw_section")
            sha = result["content_summary"]["sha256"]
            if not re.fullmatch(r"[0-9a-f]{64}", sha):
                raise ValueError("raw_hash")
            hashes["raw-" + name.split("-")[1] + ".bin"] = sha
    matches = []
    for interrupted in (False, True):
        candidate = {"version": "4.0.0", "source_sha256": source_sha,
                     "status": report["status"], "interrupted": interrupted,
                     "file_hashes": hashes, "sections": sections}
        if digest(candidate) == report["manifest_sha256"]:
            matches.append(candidate)
    if len(matches) != 1:
        raise ValueError("manifest_mismatch")
    return matches[0]


def classify_root_path(*, root_caller, executable_writable, parent_replaceable,
                       target_writable):
    values = (root_caller, executable_writable, parent_replaceable, target_writable)
    if any(type(v) is not bool for v in values):
        return "REVIEW_REQUIRED"
    if root_caller and executable_writable:
        return "BLOCKED_ROOT_EXECUTES_USER_WRITABLE_CODE"
    if root_caller and parent_replaceable:
        return "BLOCKED_ROOT_WRITES_THROUGH_REPLACEABLE_PARENT"
    if root_caller and target_writable:
        return "USER_MUTABLE_ROOT_OUTPUT_INTEGRITY_REVIEW"
    return "NOT_THIS_FINDING"
