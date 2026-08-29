#!/usr/bin/env python3
"""Validate M4.29 contact and sync evidence without host or Git access."""

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
    "manifests/adult-publishing-commercial-post-merge-sync-authorization.m4-29.json"
)
CANONICAL_CONTRACT = ROOT / CONTRACT_RELATIVE
TARGET_REPOSITORY = "Tausendunde1nz/infra"
TARGET_BRANCH = "control-main"
TARGET_SHA = "2c17ae00d9c9b6e057ba36a1766166f7f5549d4c"
TARGET_TREE = "c9408b89f994f1f2fc6f57709bebfb11b767209b"
OLD_M4_28_TARGET_SHA = "7710acfbadb50ca7a143d6dce84c6556ddf9cb84"
SOURCE_SHA = "132d971dca214dcfa1cf2e3d48fbec172751e937"
SOURCE_TREE = "c50ce73098d344763fd29f12ba077fb24139b38c"
EXPECTED_HOSTNAME = "ubuntu-8gb-nbg1-2"
EXPECTED_TAILSCALE_IPV4 = "100.121.130.51"
IMMUTABLE_PROFILE_SHA256 = (
    "d4b63784dfc9537d43f7c41da37397081591d571a407829c77e48dc255f6ca5c"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_ROOT = re.compile(
    r"^/opt/tu1nz_repos/backups/m4-29-control-sync/"
    r"[0-9]{8}T[0-9]{2}-[0-9]{2}-[0-9]{2}Z$"
)
ROLLBACK_REF = re.compile(
    r"^refs/tu1nz/rollback/m4-29-control-sync/"
    r"[0-9]{8}T[0-9]{2}-[0-9]{2}-[0-9]{2}Z$"
)
CONTRACT_KEYS = {
    "active",
    "approval",
    "authorization_conditions",
    "blockers",
    "contract_path",
    "contract_version",
    "decision",
    "environment",
    "expected_historical_source",
    "fresh_observed_server_source",
    "historical_binding",
    "ignored_baseline",
    "mutation_ready_conditions",
    "post_merge_target",
    "product_boundary",
    "read_only_server_evidence",
    "release_binding",
    "rollback",
    "sprint",
    "sync_transaction",
}
CLOSED_APPROVAL = {
    "approved_at": None,
    "authorization_maximum_age_seconds": 300,
    "first_start_approved": False,
    "fresh_server_evidence_present": False,
    "mutation_approved": False,
    "mutation_approved_at": None,
    "no_swap_risk_accepted": False,
    "operator_sync_approved": False,
    "separate_first_start_authorization_required": True,
    "server_contact_approved": False,
    "server_contact_approved_at": None,
    "source_observed_at": None,
    "source_sha": None,
    "source_tree_sha": None,
    "sync_approved": False,
}
CLOSED_FRESH_SOURCE = {
    "branch": None,
    "checkout_path": None,
    "observed_at": None,
    "origin_control_main_sha": None,
    "present": False,
    "sha": None,
    "tree_sha": None,
}
CLOSED_BLOCKERS = [
    "FIRST_START_AUTHORIZATION_CONTRACT_NOT_FINALIZED",
    "FIRST_START_NOT_APPROVED",
    "FRESH_PRESTART_NOT_EXECUTED",
    "FRESH_PRESTART_REVALIDATION_REQUIRED",
    "FRESH_SERVER_SOURCE_REVALIDATION_REQUIRED",
    "NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START",
    "SERVER_CONTACT_NOT_APPROVED",
    "SERVER_CONTROL_MUTATION_NOT_APPROVED",
    "SERVER_CONTROL_SYNC_NOT_APPROVED",
    "SERVER_CONTROL_SYNC_NOT_EXECUTED",
]
CONTACT_BLOCKERS = [
    blocker for blocker in CLOSED_BLOCKERS if blocker != "SERVER_CONTACT_NOT_APPROVED"
]
SYNC_BLOCKERS = [
    "FIRST_START_AUTHORIZATION_CONTRACT_NOT_FINALIZED",
    "FIRST_START_NOT_APPROVED",
    "FRESH_PRESTART_NOT_EXECUTED",
    "FRESH_PRESTART_REVALIDATION_REQUIRED",
    "NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START",
    "SERVER_CONTROL_MUTATION_NOT_APPROVED",
    "SERVER_CONTROL_SYNC_NOT_EXECUTED",
]
MUTATION_BLOCKERS = [
    blocker
    for blocker in SYNC_BLOCKERS
    if blocker != "SERVER_CONTROL_MUTATION_NOT_APPROVED"
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
EXPECTED_BINDINGS = {
    "application_sha": "52494d6121660ead53774deb8616701f14bb7a8f",
    "application_tree_sha": "b2820945c52ffdf77c2f5fbdd227c03ee6b245ab",
    "archive_inventory_sha256": "f7dd1b3fea220bc1ef032325edc9bb8033d79f2c52e5893927d93018f3d4aec3",
    "archive_sha256": "f892758dccf2157b4fa11afa38fe61dfcd36f18076230a76f1d23627bf18afc0",
    "installed_control_sha": "3135197ba4ac577bbb7fd28341d0c2dc845a7ebe",
    "installed_control_tree_sha": "da01c5bacb883442e0b556d5e291c8b8206959a2",
    "m4_24_contract_sha256": "bf43aee420e133b9e5167a90c2e4c260d2716c0390c8cfc439fb1d03c1b87da3",
    "m4_25_contract_sha256": "b5ceaff212c8f10529b2c89a2667dd0ef715db5e361a2dcd05007074cbd61ee2",
    "m4_26_contract_sha256": "47c5bca41e2b09e210fb61ab9de31d0ab1e44edf6715a2bc561619fcda4e3d59",
    "m4_27_contract_sha256": "d2333ae8fcd623bb778e9bf1a780ec209b58577c0b2b14336186217784b84a46",
    "m4_28_contract_sha256": "d74acaf3a07b43f05e9abcbe380626a7a1301281e2c388028a7be7d760ecb6b6",
    "manifest_sha256": "68d8e276b2e0442cc9e02937264c6f493e938f7ab0fc3372239dba69a05a6386",
    "restore_evidence_sha256": "013e89b92fda435f978960bb417cf2a7c6da93e6bc5387612b648a2358220b7d",
    "state_sha256": "8311a0072ab0e8165d21256e0edb6980bfc1e2acf7abe97b226cfc979545fd12",
    "unit_sha256": "ff631c7722daf4bd1f1fd9f6a61a1008e10b67f7a683603bec834ecad8722e4d",
}


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


def require_fresh(observed: datetime, now: datetime, label: str) -> None:
    age = (now - observed).total_seconds()
    if age < -5:
        raise GateFailure(label + " is in the future")
    if age > 300:
        raise GateFailure(label + " is stale")


def read_json(path: Path, *, canonical_contract: bool = False) -> dict[str, object]:
    if canonical_contract and path.resolve() != CANONICAL_CONTRACT.resolve():
        raise GateFailure("canonical M4.29 contract path required")
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
    normalized["fresh_observed_server_source"] = copy.deepcopy(CLOSED_FRESH_SOURCE)
    evidence = normalized.get("read_only_server_evidence")
    if isinstance(evidence, dict):
        evidence["capture_status"] = "NOT_EXECUTED"
        evidence["server_contact_approved"] = False
    return normalized


def validate_contract(contract: dict[str, object], *, require_closed: bool = True) -> None:
    if set(contract) != CONTRACT_KEYS:
        raise GateFailure("exact M4.29 top-level key set required")
    if canonical_digest(normalized_contract(contract)) != IMMUTABLE_PROFILE_SHA256:
        raise GateFailure("M4.29 immutable target or safety profile drift")
    if require_closed and (
        contract["active"] is not False
        or contract["approval"] != CLOSED_APPROVAL
        or contract["blockers"] != CLOSED_BLOCKERS
        or contract["decision"] != "NO_GO"
        or contract["fresh_observed_server_source"] != CLOSED_FRESH_SOURCE
    ):
        raise GateFailure("committed M4.29 contract must remain closed")


def validate_server_contact_ready(
    contract: dict[str, object],
    *,
    now: datetime,
) -> datetime:
    validate_contract(contract, require_closed=False)
    approval = exact(contract["approval"], set(CLOSED_APPROVAL), "contact approval")
    expected = copy.deepcopy(CLOSED_APPROVAL)
    expected["server_contact_approved"] = True
    expected["server_contact_approved_at"] = approval["server_contact_approved_at"]
    if (
        contract["active"] is not True
        or contract["decision"] != "GO_READ_ONLY_SERVER_EVIDENCE_ONLY"
        or contract["blockers"] != CONTACT_BLOCKERS
        or approval != expected
        or contract["fresh_observed_server_source"] != CLOSED_FRESH_SOURCE
    ):
        raise GateFailure("read-only server contact is not separately approved")
    approved = parse_utc(approval["server_contact_approved_at"], "server contact approval")
    require_fresh(approved, now, "server contact approval")
    return approved


def validate_server_evidence(
    evidence: dict[str, object],
    *,
    now: datetime,
) -> datetime:
    exact(
        evidence,
        {
            "bindings",
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
        "server evidence",
    )
    if (
        evidence["evidence_version"] != "tu1nz-m4.29-read-only-server-evidence-v1"
        or evidence["contract_path"] != CONTRACT_RELATIVE
    ):
        raise GateFailure("server evidence identity mismatch")
    captured = parse_utc(evidence["captured_at"], "server evidence")
    require_fresh(captured, now, "server evidence")

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
        "fresh source",
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
        raise GateFailure("fresh source differs from expected historical boundary")

    target = exact(
        evidence["target"],
        {"branch", "repository", "sha", "tree_sha"},
        "target",
    )
    if target != {
        "branch": TARGET_BRANCH,
        "repository": TARGET_REPOSITORY,
        "sha": TARGET_SHA,
        "tree_sha": TARGET_TREE,
    }:
        raise GateFailure("new post-M4.28 target SHA or tree mismatch")

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
        "candidate",
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
        raise GateFailure("candidate is not exact never-started unit boundary")

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
        "ignored inventory",
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
        raise GateFailure("ignored inventory is missing, changed or colliding")

    mutation = exact(
        evidence["checkout_mutation"],
        {"open_writers", "processes", "services", "timers"},
        "checkout mutation",
    )
    if mutation != {
        "open_writers": [],
        "processes": [],
        "services": [],
        "timers": [],
    }:
        raise GateFailure("checkout mutator detected")
    if evidence["bindings"] != EXPECTED_BINDINGS:
        raise GateFailure("historical, release, backup or restore binding drift")
    return captured


def validate_evidence_capture(
    contract: dict[str, object],
    evidence: dict[str, object],
    *,
    now: datetime,
) -> datetime:
    contact_approved = validate_server_contact_ready(contract, now=now)
    captured = validate_server_evidence(evidence, now=now)
    if captured < contact_approved:
        raise GateFailure("server evidence predates contact authorization")
    return captured


def expected_fresh_source(evidence: dict[str, object]) -> dict[str, object]:
    source = evidence["source"]
    return {
        "branch": source["branch"],
        "checkout_path": source["checkout_path"],
        "observed_at": evidence["captured_at"],
        "origin_control_main_sha": source["origin_control_main_sha"],
        "present": True,
        "sha": source["head_sha"],
        "tree_sha": source["tree_sha"],
    }


def validate_sync_authorization(
    contract: dict[str, object],
    evidence: dict[str, object],
    *,
    now: datetime,
    allow_mutation_approval: bool = False,
) -> datetime:
    validate_contract(contract, require_closed=False)
    captured = validate_server_evidence(evidence, now=now)
    approval = exact(contract["approval"], set(CLOSED_APPROVAL), "sync approval")
    if (
        contract["active"] is not True
        or contract["decision"] != "GO_SERVER_CONTROL_SYNC_ONLY"
        or approval["server_contact_approved"] is not True
        or approval["fresh_server_evidence_present"] is not True
        or approval["operator_sync_approved"] is not True
        or approval["sync_approved"] is not True
        or approval["first_start_approved"] is not False
        or approval["no_swap_risk_accepted"] is not False
        or approval["separate_first_start_authorization_required"] is not True
        or approval["source_observed_at"] != evidence["captured_at"]
        or approval["source_sha"] != SOURCE_SHA
        or approval["source_tree_sha"] != SOURCE_TREE
        or contract["fresh_observed_server_source"] != expected_fresh_source(evidence)
        or contract["read_only_server_evidence"]["capture_status"] != "CAPTURED"
        or contract["read_only_server_evidence"]["server_contact_approved"] is not True
    ):
        raise GateFailure("server sync authorization is missing or drifted")
    if allow_mutation_approval:
        if contract["blockers"] != MUTATION_BLOCKERS:
            raise GateFailure("mutation-ready blocker boundary mismatch")
    elif (
        approval["mutation_approved"] is not False
        or approval["mutation_approved_at"] is not None
        or contract["blockers"] != SYNC_BLOCKERS
    ):
        raise GateFailure("mutation approval must remain separate")
    approved = parse_utc(approval["approved_at"], "sync authorization")
    contact = parse_utc(approval["server_contact_approved_at"], "server contact approval")
    require_fresh(approved, now, "sync authorization")
    if contact > captured or approved < captured:
        raise GateFailure("authorization order is invalid")
    return approved


def validate_mutation_evidence(
    evidence: dict[str, object],
    *,
    now: datetime,
) -> datetime:
    exact(
        evidence,
        {
            "authorization_drift_free",
            "bundle",
            "candidate_never_started",
            "contract_path",
            "evidence_root",
            "ignored_inventory_sha256",
            "mutation_evidence_version",
            "prepared_at",
            "root_private",
            "source_drift_free",
            "source_sha",
            "source_tree_sha",
            "target_drift_free",
            "target_sha",
            "target_tree_sha",
        },
        "mutation evidence",
    )
    if (
        evidence["mutation_evidence_version"]
        != "tu1nz-m4.29-pre-mutation-evidence-v1"
        or evidence["contract_path"] != CONTRACT_RELATIVE
        or not isinstance(evidence["evidence_root"], str)
        or EVIDENCE_ROOT.fullmatch(evidence["evidence_root"]) is None
        or evidence["root_private"] is not True
        or evidence["source_sha"] != SOURCE_SHA
        or evidence["source_tree_sha"] != SOURCE_TREE
        or evidence["target_sha"] != TARGET_SHA
        or evidence["target_tree_sha"] != TARGET_TREE
        or evidence["authorization_drift_free"] is not True
        or evidence["source_drift_free"] is not True
        or evidence["target_drift_free"] is not True
        or evidence["candidate_never_started"] is not True
    ):
        raise GateFailure("mutation source, target or authorization boundary drift")
    require_sha256(evidence["ignored_inventory_sha256"], "mutation inventory")
    prepared = parse_utc(evidence["prepared_at"], "mutation evidence")
    require_fresh(prepared, now, "mutation evidence")
    bundle = exact(
        evidence["bundle"],
        {
            "contains_source",
            "contains_target",
            "exists",
            "path",
            "rollback_ref",
            "rollback_ref_sha",
            "valid",
        },
        "bundle evidence",
    )
    prefix = evidence["evidence_root"] + "/"
    if (
        bundle["exists"] is not True
        or bundle["valid"] is not True
        or bundle["contains_source"] is not True
        or bundle["contains_target"] is not True
        or bundle["path"] != prefix + "control-sync.bundle"
        or not isinstance(bundle["rollback_ref"], str)
        or ROLLBACK_REF.fullmatch(bundle["rollback_ref"]) is None
        or bundle["rollback_ref_sha"] != SOURCE_SHA
    ):
        raise GateFailure("valid bundle and rollback ref required")
    return prepared


def validate_mutation_ready(
    contract: dict[str, object],
    server_evidence: dict[str, object],
    mutation_evidence: dict[str, object],
    *,
    now: datetime,
) -> bool:
    approved = validate_sync_authorization(
        contract,
        server_evidence,
        now=now,
        allow_mutation_approval=True,
    )
    prepared = validate_mutation_evidence(mutation_evidence, now=now)
    approval = contract["approval"]
    if approval["mutation_approved"] is not True:
        raise GateFailure("mutation approval missing")
    mutation_approved = parse_utc(approval["mutation_approved_at"], "mutation approval")
    require_fresh(mutation_approved, now, "mutation approval")
    if prepared < approved or mutation_approved < prepared:
        raise GateFailure("mutation authorization order is invalid")
    if (
        mutation_evidence["ignored_inventory_sha256"]
        != server_evidence["ignored"]["recursive_inventory_sha256"]
    ):
        raise GateFailure("ignored inventory drift after approval")
    return True


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--server-evidence", type=Path)
    parser.add_argument("--mutation-evidence", type=Path)
    parser.add_argument("--now")
    parser.add_argument("--require-server-contact-ready", action="store_true")
    parser.add_argument("--require-sync-authorization-ready", action="store_true")
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
            if arguments.server_evidence is None or arguments.mutation_evidence is None:
                raise GateFailure("server and mutation evidence required")
            validate_mutation_ready(
                contract,
                read_json(arguments.server_evidence),
                read_json(arguments.mutation_evidence),
                now=now,
            )
            print("M4_29_SERVER_SYNC_MUTATION_READY")
            return 0
        if arguments.require_sync_authorization_ready:
            if arguments.server_evidence is None:
                raise GateFailure("fresh server evidence required")
            validate_sync_authorization(
                contract,
                read_json(arguments.server_evidence),
                now=now,
            )
            print("M4_29_SERVER_SYNC_AUTHORIZATION_READY")
            return 0
        if arguments.require_server_contact_ready:
            validate_server_contact_ready(contract, now=now)
            print("M4_29_READ_ONLY_SERVER_CONTACT_READY")
            return 0
        validate_contract(contract)
    except GateFailure as error:
        print("M4_29_POST_MERGE_SYNC_GATE_BLOCKED " + str(error), file=sys.stderr)
        return 1
    print("M4_29_POST_MERGE_SYNC_AUTHORIZATION_VALID_NO_GO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
