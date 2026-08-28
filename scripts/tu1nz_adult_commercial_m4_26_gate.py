#!/usr/bin/env python3
"""Validate immutable M4.26 read-only first-start preflight evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


class GateFailure(RuntimeError):
    pass


APPLICATION_SHA = "52494d6121660ead53774deb8616701f14bb7a8f"
APPLICATION_TREE = "b2820945c52ffdf77c2f5fbdd227c03ee6b245ab"
ACTIVE_CONTROL_SHA = "3135197ba4ac577bbb7fd28341d0c2dc845a7ebe"
ACTIVE_CONTROL_TREE = "da01c5bacb883442e0b556d5e291c8b8206959a2"
BASE_CONTROL_SHA = "132d971dca214dcfa1cf2e3d48fbec172751e937"
BASE_CONTROL_TREE = "c50ce73098d344763fd29f12ba077fb24139b38c"
MANIFEST_SHA256 = "68d8e276b2e0442cc9e02937264c6f493e938f7ab0fc3372239dba69a05a6386"
UNIT_SHA256 = "ff631c7722daf4bd1f1fd9f6a61a1008e10b67f7a683603bec834ecad8722e4d"
STATE_SHA256 = "8311a0072ab0e8165d21256e0edb6980bfc1e2acf7abe97b226cfc979545fd12"
M4_24_SHA256 = "bf43aee420e133b9e5167a90c2e4c260d2716c0390c8cfc439fb1d03c1b87da3"
M4_25_SHA256 = "b5ceaff212c8f10529b2c89a2667dd0ef715db5e361a2dcd05007074cbd61ee2"
ARCHIVE_NAME = "tu1nz_system_backup_20260828T18-15-58Z.tar.gz"
ARCHIVE_SHA256 = "f892758dccf2157b4fa11afa38fe61dfcd36f18076230a76f1d23627bf18afc0"
ARCHIVE_INVENTORY_SHA256 = (
    "f7dd1b3fea220bc1ef032325edc9bb8033d79f2c52e5893927d93018f3d4aec3"
)
RESTORE_EVIDENCE_SHA256 = (
    "013e89b92fda435f978960bb417cf2a7c6da93e6bc5387612b648a2358220b7d"
)
IGNORED_ENTRIES_SHA256 = (
    "b23591e86c2b43fbc11a376eb3d0a68c19e3979b1538aa4ac50711b598300e89"
)
BLOCKERS = [
    "FIRST_START_NOT_APPROVED",
    "NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START",
    "M4_26_NOT_MERGED_TO_CONTROL_MAIN",
    "M4_26_NOT_DEPLOYED_TO_SERVER_CANONICAL_CONTROL",
    "FRESH_PRESTART_REVALIDATION_REQUIRED",
]
TOP_LEVEL = {
    "active",
    "approval",
    "blockers",
    "contract_version",
    "decision",
    "environment",
    "preflight",
    "product_boundary",
    "release_binding",
    "sprint",
}
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def read_contract(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure("safe regular M4.26 contract required")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise GateFailure("M4.26 contract is too large")
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateFailure("invalid M4.26 contract JSON") from error
    if not isinstance(value, dict):
        raise GateFailure("M4.26 contract object required")
    return value


def exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise GateFailure("exact " + label + " key set required")
    return value


def utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GateFailure(label + " must be UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise GateFailure(label + " is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise GateFailure(label + " must be UTC")
    return parsed


def require_digest(value: object, label: str) -> None:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise GateFailure(label + " must be SHA-256")


def validate_contract(
    contract: dict[str, object], *, require_approved: bool = False
) -> bool:
    if set(contract) != TOP_LEVEL:
        raise GateFailure("exact top-level key set required")
    if (
        contract["contract_version"]
        != "tu1nz-commercial-first-start-m4.26-read-only-v1"
        or contract["sprint"] != "M4.26"
        or contract["environment"] != "STAGING-S0-COMMERCIAL-CANDIDATE"
        or contract["decision"]
        != "M4_26_READ_ONLY_PREFLIGHT_COMPLETE_NO_GO_FIRST_START"
        or contract["active"] is not False
        or contract["blockers"] != BLOCKERS
    ):
        raise GateFailure("M4.26 fail-closed identity mismatch")

    approval = exact(
        contract["approval"],
        {
            "approved_at",
            "first_start_approved",
            "no_swap_risk_accepted",
            "separate_first_start_authorization_required",
        },
        "approval",
    )
    if approval != {
        "approved_at": None,
        "first_start_approved": False,
        "no_swap_risk_accepted": False,
        "separate_first_start_authorization_required": True,
    }:
        raise GateFailure("M4.26 approval boundary must remain closed")
    if require_approved:
        raise GateFailure("M4.26 is read-only evidence and never authorizes first start")

    product = exact(
        contract["product_boundary"],
        {
            "external_providers_enabled",
            "network_enabled",
            "paid_targets",
            "real_media_enabled",
            "real_payment_enabled",
            "synthetic_data_only",
            "synthetic_publishers_only",
            "telegram_intake_enabled",
            "uncompensated_targets",
        },
        "product boundary",
    )
    if product != {
        "external_providers_enabled": False,
        "network_enabled": False,
        "paid_targets": ["REDDIT", "TELEGRAM"],
        "real_media_enabled": False,
        "real_payment_enabled": False,
        "synthetic_data_only": True,
        "synthetic_publishers_only": True,
        "telegram_intake_enabled": False,
        "uncompensated_targets": ["X"],
    }:
        raise GateFailure("product boundary drift")

    binding = exact(
        contract["release_binding"],
        {
            "base_control_main_sha",
            "base_control_main_tree_sha",
            "m4_24_contract_sha256",
            "m4_25_contract_sha256",
            "post_merge_ci_run_id",
            "pr_33_merged",
            "pr_34_merge_commit_sha",
            "pr_34_merged",
        },
        "release binding",
    )
    if binding != {
        "base_control_main_sha": BASE_CONTROL_SHA,
        "base_control_main_tree_sha": BASE_CONTROL_TREE,
        "m4_24_contract_sha256": M4_24_SHA256,
        "m4_25_contract_sha256": M4_25_SHA256,
        "post_merge_ci_run_id": 33202557484,
        "pr_33_merged": True,
        "pr_34_merge_commit_sha": BASE_CONTROL_SHA,
        "pr_34_merged": True,
    }:
        raise GateFailure("exact merged release binding required")

    preflight = exact(
        contract["preflight"],
        {
            "archive",
            "canonical_control",
            "capacity",
            "database",
            "host",
            "isolation",
            "release",
            "services",
            "start_evidence",
            "systemd",
            "technical_checks_passed",
        },
        "preflight",
    )
    if preflight["technical_checks_passed"] is not True:
        raise GateFailure("technical read-only preflight did not pass")

    host = exact(preflight["host"], {"hostname", "observed_at", "tailscale_ipv4"}, "host")
    if host["hostname"] != "ubuntu-8gb-nbg1-2" or host["tailscale_ipv4"] != "100.121.130.51":
        raise GateFailure("Tailscale host identity mismatch")
    utc(host["observed_at"], "observed_at")

    canonical = exact(
        preflight["canonical_control"],
        {
            "branch",
            "head_sha",
            "ignored_entries",
            "ignored_entries_count",
            "ignored_entries_sha256",
            "origin_control_main_sha",
            "tracked_clean",
            "tree_sha",
        },
        "canonical control",
    )
    entries = canonical["ignored_entries"]
    if not isinstance(entries, list) or entries != sorted(entries) or len(entries) != 23:
        raise GateFailure("exact sorted ignored Control baseline required")
    encoded_entries = ("\n".join(entries) + "\n").encode("ascii")
    if (
        canonical["branch"] != "control-main"
        or canonical["head_sha"] != BASE_CONTROL_SHA
        or canonical["origin_control_main_sha"] != BASE_CONTROL_SHA
        or canonical["tree_sha"] != BASE_CONTROL_TREE
        or canonical["tracked_clean"] is not True
        or canonical["ignored_entries_count"] != len(entries)
        or canonical["ignored_entries_sha256"] != IGNORED_ENTRIES_SHA256
        or hashlib.sha256(encoded_entries).hexdigest() != IGNORED_ENTRIES_SHA256
    ):
        raise GateFailure("canonical Control boundary drift")

    release = exact(
        preflight["release"],
        {
            "application_link",
            "application_release_clean",
            "application_sha",
            "application_tree_sha",
            "control_link",
            "control_release_clean",
            "installed_control_sha",
            "installed_control_tree_sha",
            "release_gate_passed",
            "release_manifest_sha256",
            "state_sha256",
            "unit_sha256",
            "venv_link",
        },
        "release",
    )
    expected_release = {
        "application_link": "application/" + APPLICATION_SHA,
        "application_release_clean": True,
        "application_sha": APPLICATION_SHA,
        "application_tree_sha": APPLICATION_TREE,
        "control_link": "control/" + ACTIVE_CONTROL_SHA,
        "control_release_clean": True,
        "installed_control_sha": ACTIVE_CONTROL_SHA,
        "installed_control_tree_sha": ACTIVE_CONTROL_TREE,
        "release_gate_passed": True,
        "release_manifest_sha256": MANIFEST_SHA256,
        "state_sha256": STATE_SHA256,
        "unit_sha256": UNIT_SHA256,
        "venv_link": "venv/" + APPLICATION_SHA,
    }
    if release != expected_release:
        raise GateFailure("installed stopped release boundary drift")

    archive = exact(
        preflight["archive"],
        {
            "archive_inventory_sha256",
            "archive_name",
            "archive_sha256",
            "exact_archive_bytes",
            "isolated_restore_passed",
            "isolated_restore_root",
            "local_remote_sha256_match",
            "restore_evidence_sha256",
        },
        "archive",
    )
    if archive != {
        "archive_inventory_sha256": ARCHIVE_INVENTORY_SHA256,
        "archive_name": ARCHIVE_NAME,
        "archive_sha256": ARCHIVE_SHA256,
        "exact_archive_bytes": 64488092,
        "isolated_restore_passed": True,
        "isolated_restore_root": "/opt/tu1nz_repos/backups/m4-25-commercial-s0-unit-refresh-restore/20260828T18-35-00Z",
        "local_remote_sha256_match": True,
        "restore_evidence_sha256": RESTORE_EVIDENCE_SHA256,
    }:
        raise GateFailure("backup or restore binding drift")
    for key in ("archive_inventory_sha256", "archive_sha256", "restore_evidence_sha256"):
        require_digest(archive[key], key)

    systemd = exact(
        preflight["systemd"],
        {
            "active_state",
            "load_state",
            "native_unit_verify_passed",
            "restart",
            "runtime_maximum_seconds",
            "security_exposure_level",
            "security_rating",
            "sub_state",
            "triggered",
            "unit_file_state",
        },
        "systemd",
    )
    if systemd != {
        "active_state": "inactive",
        "load_state": "loaded",
        "native_unit_verify_passed": True,
        "restart": "no",
        "runtime_maximum_seconds": 180,
        "security_exposure_level": 0.6,
        "security_rating": "SAFE",
        "sub_state": "dead",
        "triggered": False,
        "unit_file_state": "static",
    }:
        raise GateFailure("stopped single-start unit boundary drift")

    start = exact(
        preflight["start_evidence"],
        {
            "active_enter_timestamp",
            "active_enter_timestamp_monotonic",
            "control_pid",
            "exec_main_start_timestamp",
            "exec_main_start_timestamp_monotonic",
            "journal_lines",
            "main_pid",
            "n_restarts",
            "runtime_lock_present",
            "runtime_status_present",
        },
        "start evidence",
    )
    if any(
        start[key] != 0
        for key in (
            "active_enter_timestamp_monotonic",
            "control_pid",
            "exec_main_start_timestamp_monotonic",
            "journal_lines",
            "main_pid",
            "n_restarts",
        )
    ) or any(
        start[key] is not False
        for key in ("runtime_lock_present", "runtime_status_present")
    ) or start["active_enter_timestamp"] != "" or start["exec_main_start_timestamp"] != "":
        raise GateFailure("candidate has start evidence")

    services = exact(
        preflight["services"],
        {"allowed_failed_units", "backup_service", "backup_timer", "postgresql", "staging_s1"},
        "services",
    )
    if services != {
        "allowed_failed_units": ["tu1nz-doc.service"],
        "backup_service": "inactive",
        "backup_timer": "active",
        "postgresql": "active",
        "staging_s1": "active",
    }:
        raise GateFailure("required service boundary drift")

    isolation = exact(
        preflight["isolation"],
        {
            "commercial_container_mount_reference_detected",
            "commercial_cron_reference_detected",
            "commercial_open_file_reference_detected",
            "commercial_process_reference_detected",
            "commercial_timer_reference_detected",
            "manager_sensitive_environment_names",
            "runtime_user_process_reference_detected",
            "unit_sensitive_environment_names",
        },
        "isolation",
    )
    if any(value is not False for key, value in isolation.items() if key.endswith("_detected")):
        raise GateFailure("commercial isolation reference detected")
    if isolation["manager_sensitive_environment_names"] != [] or isolation["unit_sensitive_environment_names"] != []:
        raise GateFailure("sensitive provider environment name detected")

    database = exact(
        preflight["database"],
        {
            "business_rows_zero",
            "content_sha256",
            "function_count",
            "other_sessions",
            "schema_sha256",
            "seed_counts",
            "table_count",
        },
        "database",
    )
    expected_seeds = {
        "country_policy_rules": 1,
        "creators": 1,
        "integration_accounts": 3,
        "platform_policy_rules": 3,
        "policy_versions": 1,
        "publication_destinations": 3,
    }
    if (
        database["business_rows_zero"] is not True
        or database["table_count"] != 39
        or database["function_count"] != 21
        or database["other_sessions"] != 0
        or database["seed_counts"] != expected_seeds
    ):
        raise GateFailure("synthetic database boundary drift")
    require_digest(database["content_sha256"], "database content")
    require_digest(database["schema_sha256"], "database schema")

    capacity = exact(
        preflight["capacity"],
        {"memory_available_kib", "root_filesystem_available_bytes", "swap_total_kib"},
        "capacity",
    )
    if (
        type(capacity["memory_available_kib"]) is not int
        or capacity["memory_available_kib"] < 512 * 1024
        or type(capacity["root_filesystem_available_bytes"]) is not int
        or capacity["root_filesystem_available_bytes"] < 1024 * 1024 * 1024
        or capacity["swap_total_kib"] != 0
    ):
        raise GateFailure("capacity boundary mismatch")
    return False


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--require-approved", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        validate_contract(
            read_contract(arguments.contract),
            require_approved=arguments.require_approved,
        )
    except GateFailure as error:
        print("M4_26_FIRST_START_GATE_BLOCKED " + str(error), file=sys.stderr)
        return 1
    print("M4_26_READ_ONLY_PREFLIGHT_VALID_NO_GO_FIRST_START")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
