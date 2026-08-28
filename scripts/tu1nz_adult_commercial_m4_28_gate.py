#!/usr/bin/env python3
"""Validate M4.28 sync authorization evidence without host or Git access."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


class GateFailure(RuntimeError):
    pass


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_RELATIVE = (
    "manifests/adult-publishing-commercial-canonical-sync-authorization.m4-28.json"
)
CANONICAL_CONTRACT = ROOT / CONTRACT_RELATIVE
CONTRACT_KEYS = {
    "active",
    "approval",
    "blockers",
    "contract_path",
    "contract_version",
    "decision",
    "environment",
    "evidence_contract",
    "historical_binding",
    "ignored_baseline",
    "post_merge_target",
    "product_boundary",
    "release_binding",
    "rollback",
    "sprint",
    "sync_transaction",
}
TARGET_REPOSITORY = "Tausendunde1nz/infra"
TARGET_BRANCH = "control-main"
TARGET_SHA = "7710acfbadb50ca7a143d6dce84c6556ddf9cb84"
TARGET_TREE = "c226e2dca456d79b1aeef377b3a380d68f83c396"
SOURCE_SHA = "132d971dca214dcfa1cf2e3d48fbec172751e937"
SOURCE_TREE = "c50ce73098d344763fd29f12ba077fb24139b38c"
EXPECTED_HOSTNAME = "ubuntu-8gb-nbg1-2"
EXPECTED_TAILSCALE_IPV4 = "100.121.130.51"
IMMUTABLE_PROFILE_SHA256 = (
    "0380a598a978f4d2a5a5f7c730c69ac00f3506f4460dd997cedfaece51878ef1"
)
EVIDENCE_ROOT = re.compile(
    r"^/opt/tu1nz_repos/backups/m4-28-control-sync/"
    r"[0-9]{8}T[0-9]{2}-[0-9]{2}-[0-9]{2}Z$"
)
ROLLBACK_REF = re.compile(
    r"^refs/tu1nz/rollback/m4-28-control-sync/"
    r"[0-9]{8}T[0-9]{2}-[0-9]{2}-[0-9]{2}Z$"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CLOSED_APPROVAL = {
    "approved_at": None,
    "authorization_maximum_age_seconds": 300,
    "first_start_approved": False,
    "no_swap_risk_accepted": False,
    "separate_first_start_authorization_required": True,
    "source_observed_at": None,
    "source_sha": None,
    "source_tree_sha": None,
    "sync_approved": False,
}
CLOSED_BLOCKERS = [
    "FIRST_START_AUTHORIZATION_CONTRACT_NOT_FINALIZED",
    "FIRST_START_NOT_APPROVED",
    "FRESH_PRESTART_NOT_EXECUTED",
    "FRESH_PRESTART_REVALIDATION_REQUIRED",
    "FRESH_SERVER_SOURCE_REVALIDATION_REQUIRED",
    "NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START",
    "SERVER_CONTROL_SYNC_NOT_APPROVED",
    "SERVER_CONTROL_SYNC_NOT_EXECUTED",
]
AUTHORIZED_BLOCKERS = [
    "FIRST_START_AUTHORIZATION_CONTRACT_NOT_FINALIZED",
    "FIRST_START_NOT_APPROVED",
    "FRESH_PRESTART_NOT_EXECUTED",
    "FRESH_PRESTART_REVALIDATION_REQUIRED",
    "NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START",
    "SERVER_CONTROL_SYNC_NOT_EXECUTED",
]
IGNORED_ENTRIES = [
    ".r28r4-control-payload-clean.tar.gz",
    "_filelist_reference.txt",
    "_filelist_reference.txt.bak_20260215T082155Z",
    "analysis/n8n_fix_2026-03-18/",
    "analysis/n8n_perms_2026-03-18/",
    "analysis/security_incident_2026-08-25/",
    "checksums.txt",
    "checksums_current.txt",
    "checksums_reference.sha256",
    "checksums_reference.txt",
    "emoji_map.sed",
    "integrity_baseline.sha256",
    "integrity_reference.sha256",
    "integrity_reference.txt",
    "last_sync.ok",
    "legacy_units/",
    "monitor_last.txt",
    "nginx/validation.pid",
    "rebaseline_2026/",
    "scripts/__pycache__/",
    "scripts/encrypted_drive_backup",
    "systemd/tu1nz-git-sync.service",
    "systemd/tu1nz-git-sync.timer",
]
IGNORED_ENTRIES_SHA256 = (
    "b23591e86c2b43fbc11a376eb3d0a68c19e3979b1538aa4ac50711b598300e89"
)


def exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise GateFailure("exact " + label + " key set required")
    return value


def canonical_digest(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def require_sha256(value: object, label: str) -> None:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise GateFailure(label + " must be SHA-256")


def parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GateFailure(label + " must be UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise GateFailure(label + " is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise GateFailure(label + " must be UTC")
    return parsed


def require_fresh(
    observed: datetime,
    now: datetime,
    maximum_age_seconds: int,
    label: str,
) -> None:
    age = (now - observed).total_seconds()
    if age < -5:
        raise GateFailure(label + " is in the future")
    if age > maximum_age_seconds:
        raise GateFailure(label + " is stale")


def read_json(path: Path, *, canonical_contract: bool = False) -> dict[str, object]:
    if canonical_contract and path.resolve() != CANONICAL_CONTRACT.resolve():
        raise GateFailure("canonical M4.28 contract path required")
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure("safe regular JSON file required")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise GateFailure("JSON file is too large")
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateFailure("invalid JSON") from error
    if not isinstance(value, dict):
        raise GateFailure("JSON object required")
    return value


def normalized_contract(contract: dict[str, object]) -> dict[str, object]:
    normalized = copy.deepcopy(contract)
    normalized["active"] = False
    normalized["approval"] = copy.deepcopy(CLOSED_APPROVAL)
    normalized["blockers"] = list(CLOSED_BLOCKERS)
    normalized["decision"] = "NO_GO"
    return normalized


def validate_contract(
    contract: dict[str, object],
    *,
    require_closed: bool = True,
) -> None:
    if set(contract) != CONTRACT_KEYS:
        raise GateFailure("exact M4.28 top-level key set required")
    if canonical_digest(normalized_contract(contract)) != IMMUTABLE_PROFILE_SHA256:
        raise GateFailure("M4.28 immutable target or safety profile drift")
    if require_closed and (
        contract["active"] is not False
        or contract["approval"] != CLOSED_APPROVAL
        or contract["blockers"] != CLOSED_BLOCKERS
        or contract["decision"] != "NO_GO"
    ):
        raise GateFailure("committed M4.28 contract must remain closed")


def validate_pre_sync_evidence(
    evidence: dict[str, object],
    *,
    now: datetime,
) -> datetime:
    exact(
        evidence,
        {
            "candidate",
            "captured_at",
            "checkout_mutation",
            "contract_path",
            "evidence_version",
            "ignored",
            "server_identity",
            "source",
            "target",
        },
        "pre-sync evidence",
    )
    if (
        evidence["evidence_version"] != "tu1nz-m4.28-pre-sync-evidence-v1"
        or evidence["contract_path"] != CONTRACT_RELATIVE
    ):
        raise GateFailure("pre-sync evidence identity mismatch")
    captured = parse_utc(evidence["captured_at"], "pre-sync capture")
    require_fresh(captured, now, 300, "pre-sync evidence")

    identity = exact(
        evidence["server_identity"],
        {"hostname", "identity_matched", "tailscale_ipv4"},
        "server identity",
    )
    if identity != {
        "hostname": EXPECTED_HOSTNAME,
        "identity_matched": True,
        "tailscale_ipv4": EXPECTED_TAILSCALE_IPV4,
    }:
        raise GateFailure("Tailscale server identity mismatch")

    candidate = exact(
        evidence["candidate"],
        {
            "active_state",
            "active_enter_timestamp",
            "active_enter_timestamp_monotonic",
            "exec_main_start_timestamp",
            "exec_main_start_timestamp_monotonic",
            "journal_lines",
            "n_restarts",
            "never_started",
            "restart",
            "runtime_lock_present",
            "runtime_maximum_seconds",
            "runtime_status_present",
            "sub_state",
            "unit_file_state",
        },
        "candidate evidence",
    )
    if candidate != {
        "active_state": "inactive",
        "active_enter_timestamp": "",
        "active_enter_timestamp_monotonic": 0,
        "exec_main_start_timestamp": "",
        "exec_main_start_timestamp_monotonic": 0,
        "journal_lines": 0,
        "n_restarts": 0,
        "never_started": True,
        "restart": "no",
        "runtime_lock_present": False,
        "runtime_maximum_seconds": 180,
        "runtime_status_present": False,
        "sub_state": "dead",
        "unit_file_state": "static",
    }:
        raise GateFailure("candidate is not exact never-started boundary")

    source = exact(
        evidence["source"],
        {
            "branch",
            "checkout_path",
            "fast_forward_possible",
            "git_integrity_passed",
            "head_sha",
            "origin_control_main_sha",
            "source_is_ancestor_of_target",
            "tracked_clean",
            "tree_sha",
        },
        "server source evidence",
    )
    if source != {
        "branch": TARGET_BRANCH,
        "checkout_path": "/opt/tu1nz_repos/control",
        "fast_forward_possible": True,
        "git_integrity_passed": True,
        "head_sha": SOURCE_SHA,
        "origin_control_main_sha": SOURCE_SHA,
        "source_is_ancestor_of_target": True,
        "tracked_clean": True,
        "tree_sha": SOURCE_TREE,
    }:
        raise GateFailure("server source is not exact clean fast-forward boundary")

    target = exact(
        evidence["target"],
        {"branch", "repository", "sha", "tree_sha"},
        "target evidence",
    )
    if target != {
        "branch": TARGET_BRANCH,
        "repository": TARGET_REPOSITORY,
        "sha": TARGET_SHA,
        "tree_sha": TARGET_TREE,
    }:
        raise GateFailure("post-merge target SHA or tree mismatch")

    ignored = exact(
        evidence["ignored"],
        {
            "changed_entries",
            "entries",
            "entries_sha256",
            "incoming_tracked_collisions",
            "missing_entries",
            "recursive_inventory_matches_baseline",
            "recursive_inventory_sha256",
        },
        "ignored inventory evidence",
    )
    require_sha256(ignored["recursive_inventory_sha256"], "recursive inventory")
    if (
        ignored["entries"] != IGNORED_ENTRIES
        or ignored["entries_sha256"] != IGNORED_ENTRIES_SHA256
        or ignored["missing_entries"] != []
        or ignored["changed_entries"] != []
        or ignored["incoming_tracked_collisions"] != []
        or ignored["recursive_inventory_matches_baseline"] is not True
    ):
        raise GateFailure("ignored material is missing, changed or colliding")

    mutation = exact(
        evidence["checkout_mutation"],
        {"open_writers", "processes", "services", "timers"},
        "checkout mutation evidence",
    )
    if mutation != {
        "open_writers": [],
        "processes": [],
        "services": [],
        "timers": [],
    }:
        raise GateFailure("another process may mutate canonical Control")
    return captured


def validate_authorization(
    contract: dict[str, object],
    evidence: dict[str, object],
    *,
    now: datetime,
) -> datetime:
    validate_contract(contract, require_closed=False)
    captured = validate_pre_sync_evidence(evidence, now=now)
    approval = exact(
        contract["approval"],
        set(CLOSED_APPROVAL),
        "sync approval",
    )
    if (
        contract["active"] is not True
        or contract["decision"] != "GO_SERVER_CONTROL_SYNC_ONLY"
        or contract["blockers"] != AUTHORIZED_BLOCKERS
        or approval["sync_approved"] is not True
        or approval["authorization_maximum_age_seconds"] != 300
        or approval["first_start_approved"] is not False
        or approval["no_swap_risk_accepted"] is not False
        or approval["separate_first_start_authorization_required"] is not True
        or approval["source_sha"] != SOURCE_SHA
        or approval["source_tree_sha"] != SOURCE_TREE
        or approval["source_observed_at"] != evidence["captured_at"]
    ):
        raise GateFailure("separate server sync authorization is missing")
    approved = parse_utc(approval["approved_at"], "sync approval")
    require_fresh(approved, now, 300, "sync authorization")
    if approved < captured:
        raise GateFailure("sync authorization predates source observation")
    return approved


def validate_mutation_evidence(
    evidence: dict[str, object],
    *,
    now: datetime,
) -> datetime:
    exact(
        evidence,
        {
            "authorization_revalidated",
            "candidate_never_started",
            "contract_path",
            "evidence_root",
            "git_integrity_evidence_sha256",
            "git_status_evidence_sha256",
            "ignored_inventory_sha256",
            "incoming_tracked_collisions",
            "mutation_evidence_version",
            "prepared_at",
            "rollback",
            "root_private",
            "source_sha",
            "source_tree_sha",
            "target_sha",
            "target_tree_sha",
        },
        "mutation evidence",
    )
    if (
        evidence["mutation_evidence_version"]
        != "tu1nz-m4.28-pre-mutation-evidence-v1"
        or evidence["contract_path"] != CONTRACT_RELATIVE
        or not isinstance(evidence["evidence_root"], str)
        or EVIDENCE_ROOT.fullmatch(evidence["evidence_root"]) is None
        or evidence["root_private"] is not True
        or evidence["source_sha"] != SOURCE_SHA
        or evidence["source_tree_sha"] != SOURCE_TREE
        or evidence["target_sha"] != TARGET_SHA
        or evidence["target_tree_sha"] != TARGET_TREE
        or evidence["incoming_tracked_collisions"] != []
        or evidence["authorization_revalidated"] is not True
        or evidence["candidate_never_started"] is not True
    ):
        raise GateFailure("pre-mutation boundary mismatch")
    for key in (
        "git_integrity_evidence_sha256",
        "git_status_evidence_sha256",
        "ignored_inventory_sha256",
    ):
        require_sha256(evidence[key], key)
    prepared = parse_utc(evidence["prepared_at"], "mutation evidence")
    require_fresh(prepared, now, 300, "mutation evidence")

    rollback = exact(
        evidence["rollback"],
        {
            "bundle_contains_source",
            "bundle_contains_target",
            "bundle_exists",
            "bundle_path",
            "bundle_valid",
            "ref",
            "ref_sha",
        },
        "rollback evidence",
    )
    expected_prefix = evidence["evidence_root"] + "/"
    if (
        not isinstance(rollback["ref"], str)
        or ROLLBACK_REF.fullmatch(rollback["ref"]) is None
        or rollback["ref_sha"] != SOURCE_SHA
        or not isinstance(rollback["bundle_path"], str)
        or not rollback["bundle_path"].startswith(expected_prefix)
        or rollback["bundle_path"] != expected_prefix + "control-sync.bundle"
        or rollback["bundle_exists"] is not True
        or rollback["bundle_valid"] is not True
        or rollback["bundle_contains_source"] is not True
        or rollback["bundle_contains_target"] is not True
    ):
        raise GateFailure("verified rollback ref and bundle required")
    return prepared


def validate_mutation_ready(
    contract: dict[str, object],
    pre_sync: dict[str, object],
    mutation: dict[str, object],
    *,
    now: datetime,
) -> bool:
    approved = validate_authorization(contract, pre_sync, now=now)
    prepared = validate_mutation_evidence(mutation, now=now)
    if prepared < approved:
        raise GateFailure("mutation evidence predates authorization")
    if mutation["ignored_inventory_sha256"] != pre_sync["ignored"]["recursive_inventory_sha256"]:
        raise GateFailure("ignored recursive inventory changed before mutation")
    return True


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--pre-sync-evidence", type=Path)
    parser.add_argument("--mutation-evidence", type=Path)
    parser.add_argument("--now")
    parser.add_argument("--require-authorization-ready", action="store_true")
    parser.add_argument("--require-mutation-ready", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        contract = read_json(arguments.contract, canonical_contract=True)
        now = (
            parse_utc(arguments.now, "current time")
            if arguments.now is not None
            else datetime.now(timezone.utc)
        )
        if arguments.require_mutation_ready:
            if arguments.pre_sync_evidence is None or arguments.mutation_evidence is None:
                raise GateFailure("pre-sync and mutation evidence required")
            validate_mutation_ready(
                contract,
                read_json(arguments.pre_sync_evidence),
                read_json(arguments.mutation_evidence),
                now=now,
            )
            print("M4_28_CANONICAL_SYNC_MUTATION_READY")
            return 0
        if arguments.require_authorization_ready:
            if arguments.pre_sync_evidence is None:
                raise GateFailure("pre-sync evidence required")
            validate_authorization(
                contract,
                read_json(arguments.pre_sync_evidence),
                now=now,
            )
            print("M4_28_CANONICAL_SYNC_AUTHORIZATION_READY")
            return 0
        validate_contract(contract, require_closed=True)
    except GateFailure as error:
        print("M4_28_CANONICAL_SYNC_GATE_BLOCKED " + str(error), file=sys.stderr)
        return 1
    print("M4_28_CANONICAL_SYNC_AUTHORIZATION_VALID_NO_GO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
