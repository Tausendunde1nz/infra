#!/usr/bin/env python3
"""Validate the fail-closed M4.27 preparation draft without system access."""

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


CANONICAL_SHA = "6f47780eb3b21b369db69a65962e0b3d86107deb"
CANONICAL_TREE = "5a202f8a25f1085e30d264d7323874028a58bae6"
LAST_SERVER_SHA = "132d971dca214dcfa1cf2e3d48fbec172751e937"
LAST_SERVER_TREE = "c50ce73098d344763fd29f12ba077fb24139b38c"
APPLICATION_SHA = "52494d6121660ead53774deb8616701f14bb7a8f"
APPLICATION_TREE = "b2820945c52ffdf77c2f5fbdd227c03ee6b245ab"
INSTALLED_CONTROL_SHA = "3135197ba4ac577bbb7fd28341d0c2dc845a7ebe"
INSTALLED_CONTROL_TREE = "da01c5bacb883442e0b556d5e291c8b8206959a2"
UNIT_SHA256 = "ff631c7722daf4bd1f1fd9f6a61a1008e10b67f7a683603bec834ecad8722e4d"
MANIFEST_SHA256 = "68d8e276b2e0442cc9e02937264c6f493e938f7ab0fc3372239dba69a05a6386"
STATE_SHA256 = "8311a0072ab0e8165d21256e0edb6980bfc1e2acf7abe97b226cfc979545fd12"
M4_24_SHA256 = "bf43aee420e133b9e5167a90c2e4c260d2716c0390c8cfc439fb1d03c1b87da3"
M4_25_SHA256 = "b5ceaff212c8f10529b2c89a2667dd0ef715db5e361a2dcd05007074cbd61ee2"
M4_26_SHA256 = "47c5bca41e2b09e210fb61ab9de31d0ab1e44edf6715a2bc561619fcda4e3d59"
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
    "CANONICAL_SYNC_TARGET_REQUIRES_POST_MERGE_REFRESH",
    "FIRST_START_AUTHORIZATION_CONTRACT_NOT_FINALIZED",
    "FIRST_START_NOT_APPROVED",
    "FRESH_PRESTART_NOT_EXECUTED",
    "FRESH_PRESTART_REVALIDATION_REQUIRED",
    "NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START",
    "SERVER_CONTROL_SYNC_NOT_APPROVED",
    "SERVER_CONTROL_SYNC_NOT_EXECUTED",
]
PREFLIGHT_CHECKS = [
    "APPLICATION_SHA_TREE",
    "BACKUP_ARCHIVE_SHA256",
    "BACKUP_SERVICE_IDLE",
    "BACKUP_TIMER_ACTIVE",
    "CANDIDATE_PROCESSES_ABSENT",
    "CANDIDATE_TIMERS_ABSENT",
    "CANONICAL_CONTROL_SHA_TREE",
    "CRON_REFERENCES_ABSENT",
    "DATABASE_21_FUNCTIONS",
    "DATABASE_39_TABLES",
    "DATABASE_BUSINESS_ROWS_ZERO",
    "DATABASE_SYNTHETIC_SEEDS_EXACT",
    "DOCKER_MOUNTS_ABSENT",
    "EXTERNAL_NETWORK_PATHS_DISABLED",
    "INSTALLED_CONTROL_RELEASE",
    "INSTALLED_UNIT_SHA256",
    "MEMORY_AVAILABLE_AT_LEAST_4_GIB",
    "NATIVE_UNIT_VERIFY",
    "NO_OTHER_DATABASE_SESSIONS",
    "ONLY_ACCEPTED_FAILED_UNIT",
    "OPEN_FILES_ABSENT",
    "POSTGRESQL_ACTIVE",
    "RELEASE_GATE",
    "RELEASE_MANIFEST_SHA256",
    "RESTORE_EVIDENCE_SHA256",
    "ROOT_STORAGE_CAPACITY",
    "RUNTIME_LOCK_ABSENT",
    "RUNTIME_STATUS_ABSENT",
    "RUNTIME_USER_PROCESSES_ABSENT",
    "SENSITIVE_PROVIDER_ENVIRONMENT_NAMES_ABSENT",
    "STAGING_S1_ACTIVE",
    "STATE_EMPTY_AND_HASH_BOUND",
    "TAILSCALE_IDENTITY",
    "UNIT_INACTIVE_DEAD_STATIC",
    "UNIT_JOURNAL_EMPTY",
    "UNIT_NRESTARTS_ZERO",
    "UNIT_RESTART_NO",
    "UNIT_RUNTIME_MAX_180",
    "UNIT_START_TIMESTAMPS_ABSENT",
]
SYNC_STEPS = [
    "READ_ONLY_REVALIDATE_SOURCE_AND_IGNORED_INVENTORY",
    "FETCH_CONTROL_MAIN_WITHOUT_MERGE",
    "VERIFY_REMOTE_TARGET_SHA_TREE_AND_POST_MERGE_REFRESH",
    "VERIFY_FAST_FORWARD_ANCESTRY_AND_INCOMING_PATH_COLLISIONS",
    "CREATE_ROOT_PRIVATE_ROLLBACK_REF_BUNDLE_AND_EVIDENCE",
    "FAST_FORWARD_CONTROL_MAIN_ONLY",
    "VERIFY_HEAD_ORIGIN_TREE_TRACKED_STATUS_AND_IGNORED_INVENTORY",
    "VERIFY_HISTORICAL_CONTRACT_HASHES_AND_CANDIDATE_NEVER_STARTED",
]
ROLLBACK_STEPS = [
    "REQUIRE_EXACT_FAILED_POST_SYNC_BOUNDARY",
    "VERIFY_CANDIDATE_NEVER_STARTED",
    "VERIFY_ROLLBACK_BUNDLE_AND_OLD_OBJECT",
    "RESTORE_EXACT_OLD_TRACKED_TREE",
    "VERIFY_IGNORED_RECURSIVE_INVENTORY_UNCHANGED",
    "VERIFY_OLD_HEAD_TREE_AND_CLEAN_STATUS",
    "PRESERVE_ALL_SYNC_AND_ROLLBACK_EVIDENCE",
]
NO_SWAP_RISK_FACTORS = [
    "NO_SWAP_CONFIGURED",
    "NO_CGROUP_MEMORY_MAX_CONFIGURED",
    "NO_EMPIRICAL_FIRST_START_PEAK_RSS",
    "KERNEL_OOM_MAY_AFFECT_CANDIDATE_OR_UNRELATED_PROCESS",
]
NO_SWAP_MITIGATIONS = [
    "FRESH_PREFLIGHT_REQUIRES_AT_LEAST_4_GIB_AVAILABLE_MEMORY",
    "EXACTLY_ONE_START",
    "RESTART_NO",
    "RUNTIME_MAXIMUM_180_SECONDS",
    "NETWORK_FREE_AND_PROVIDER_DISABLED",
    "ZERO_REAL_MEDIA_AND_ZERO_PROJECTED_SUBMISSIONS",
    "BACKUP_SERVICE_IDLE_AND_NO_OTHER_DATABASE_SESSION",
    "ABORT_REQUIRES_VERIFIED_STOP_AND_NO_SECOND_START",
]
OOM_RECOVERY = [
    "OOM_INVALIDATES_THE_WINDOW",
    "SYSTEMD_MUST_NOT_RESTART_THE_CANDIDATE",
    "CONTROLLER_ATTEMPTS_AND_VERIFIES_STOP",
    "NO_SECOND_START_IS_ALLOWED",
    "JOURNAL_AND_RUNTIME_EVIDENCE_ARE_PRESERVED",
    "HOST_OR_UNRELATED_SERVICE_IMPACT_IS_REPORTED_AS_CRITICAL",
]
ABORT_STEPS = [
    "STOP_UNIT",
    "VERIFY_INACTIVE_DEAD",
    "VERIFY_NO_RESTART",
    "FORBID_SECOND_START",
    "VERIFY_DATABASE_UNCHANGED",
    "VERIFY_STATE_UNCHANGED",
    "PRESERVE_RUNTIME_EVIDENCE",
    "PRESERVE_JOURNAL",
    "VERIFY_CANDIDATE_STOPPED",
    "REPORT_STOP_FAILURE_AS_CRITICAL",
]
TOP_LEVEL = {
    "active",
    "approval",
    "blockers",
    "canonical_control_sync",
    "contract_version",
    "decision",
    "environment",
    "first_start_window",
    "fresh_prestart",
    "no_swap_assessment",
    "product_boundary",
    "recovery",
    "release_binding",
    "sprint",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def read_contract(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure("safe regular M4.27 draft required")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise GateFailure("M4.27 draft is too large")
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateFailure("invalid M4.27 draft JSON") from error
    if not isinstance(value, dict):
        raise GateFailure("M4.27 draft object required")
    return value


def exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise GateFailure("exact " + label + " key set required")
    return value


def require_sha256(value: object, label: str) -> None:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise GateFailure(label + " must be SHA-256")


def require_utc(value: object, label: str) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GateFailure(label + " must be UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise GateFailure(label + " is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise GateFailure(label + " must be UTC")


def validate_contract(
    contract: dict[str, object],
    *,
    require_sync_ready: bool = False,
    require_prestart_ready: bool = False,
    require_authorization_ready: bool = False,
) -> bool:
    if set(contract) != TOP_LEVEL:
        raise GateFailure("exact top-level key set required")
    if (
        contract["contract_version"]
        != "tu1nz-commercial-first-start-authorization-preparation-m4.27-v1"
        or contract["sprint"] != "M4.27"
        or contract["environment"] != "STAGING-S0-COMMERCIAL-CANDIDATE"
        or contract["decision"] != "NO_GO"
        or contract["active"] is not False
        or contract["blockers"] != BLOCKERS
    ):
        raise GateFailure("M4.27 fail-closed identity mismatch")

    approval = exact(
        contract["approval"],
        {
            "approved_at",
            "first_start_approved",
            "no_swap_risk_accepted",
            "separate_authorization_contract_required",
            "server_control_sync_approved",
        },
        "approval",
    )
    if approval != {
        "approved_at": None,
        "first_start_approved": False,
        "no_swap_risk_accepted": False,
        "separate_authorization_contract_required": True,
        "server_control_sync_approved": False,
    }:
        raise GateFailure("M4.27 approval boundary must remain closed")

    binding = exact(
        contract["release_binding"],
        {
            "application_sha",
            "application_tree_sha",
            "archive_inventory_sha256",
            "archive_name",
            "archive_sha256",
            "canonical_control_sha",
            "canonical_control_tree_sha",
            "installed_control_sha",
            "installed_control_tree_sha",
            "m4_24_contract_sha256",
            "m4_25_contract_sha256",
            "m4_26_contract_sha256",
            "m4_26_post_merge_ci_run_id",
            "manifest_sha256",
            "restore_evidence_sha256",
            "state_sha256",
            "unit_sha256",
        },
        "release binding",
    )
    if binding != {
        "application_sha": APPLICATION_SHA,
        "application_tree_sha": APPLICATION_TREE,
        "archive_inventory_sha256": ARCHIVE_INVENTORY_SHA256,
        "archive_name": "tu1nz_system_backup_20260828T18-15-58Z.tar.gz",
        "archive_sha256": ARCHIVE_SHA256,
        "canonical_control_sha": CANONICAL_SHA,
        "canonical_control_tree_sha": CANONICAL_TREE,
        "installed_control_sha": INSTALLED_CONTROL_SHA,
        "installed_control_tree_sha": INSTALLED_CONTROL_TREE,
        "m4_24_contract_sha256": M4_24_SHA256,
        "m4_25_contract_sha256": M4_25_SHA256,
        "m4_26_contract_sha256": M4_26_SHA256,
        "m4_26_post_merge_ci_run_id": 33203814784,
        "manifest_sha256": MANIFEST_SHA256,
        "restore_evidence_sha256": RESTORE_EVIDENCE_SHA256,
        "state_sha256": STATE_SHA256,
        "unit_sha256": UNIT_SHA256,
    }:
        raise GateFailure("exact M4.27 release binding required")
    for key in (
        "archive_inventory_sha256",
        "archive_sha256",
        "m4_24_contract_sha256",
        "m4_25_contract_sha256",
        "m4_26_contract_sha256",
        "manifest_sha256",
        "restore_evidence_sha256",
        "state_sha256",
        "unit_sha256",
    ):
        require_sha256(binding[key], key)

    sync = exact(
        contract["canonical_control_sync"],
        {"ignored_material", "last_proven_server", "planned_target", "rollback", "transaction"},
        "canonical Control sync",
    )
    last = exact(
        sync["last_proven_server"],
        {"branch", "head_sha", "observed_at", "origin_control_main_sha", "tracked_clean", "tree_sha"},
        "last proven server",
    )
    if last != {
        "branch": "control-main",
        "head_sha": LAST_SERVER_SHA,
        "observed_at": "2026-08-28T19:13:59Z",
        "origin_control_main_sha": LAST_SERVER_SHA,
        "tracked_clean": True,
        "tree_sha": LAST_SERVER_TREE,
    }:
        raise GateFailure("last proven server boundary drift")
    require_utc(last["observed_at"], "last server observation")

    target = exact(
        sync["planned_target"],
        {"post_m4_27_merge_refresh_required", "sha", "tree_sha"},
        "planned target",
    )
    if target != {
        "post_m4_27_merge_refresh_required": True,
        "sha": CANONICAL_SHA,
        "tree_sha": CANONICAL_TREE,
    }:
        raise GateFailure("planned canonical target drift")

    ignored = exact(
        sync["ignored_material"],
        {"entries", "entries_count", "entries_sha256", "recursive_byte_inventory_required"},
        "ignored material",
    )
    entries = ignored["entries"]
    if (
        not isinstance(entries, list)
        or not all(isinstance(entry, str) for entry in entries)
        or entries != sorted(entries)
        or len(entries) != 23
        or ignored["entries_count"] != 23
        or ignored["entries_sha256"] != IGNORED_ENTRIES_SHA256
        or ignored["recursive_byte_inventory_required"] is not True
        or hashlib.sha256(("\n".join(entries) + "\n").encode("ascii")).hexdigest()
        != IGNORED_ENTRIES_SHA256
    ):
        raise GateFailure("exact ignored material preservation boundary required")

    transaction = exact(
        sync["transaction"],
        {
            "approved",
            "fast_forward_only",
            "mutation_scope",
            "server_path",
            "status",
            "steps",
            "unchanged_paths",
            "unchanged_services",
        },
        "sync transaction",
    )
    if (
        transaction["approved"] is not False
        or transaction["fast_forward_only"] is not True
        or transaction["server_path"] != "/opt/tu1nz_repos/control"
        or transaction["status"] != "NOT_EXECUTED"
        or transaction["mutation_scope"]
        != [
            "/opt/tu1nz_repos/control/.git",
            "/opt/tu1nz_repos/control tracked worktree",
        ]
        or transaction["unchanged_paths"]
        != [
            "/etc/systemd/system/tu1nz-adult-commercial-s0.service",
            "/etc/tu1nz/adult-publishing/staging-s0-commercial",
            "/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial",
            "/var/lib/tausendunde1nz/adult-publishing/staging-s0-commercial",
        ]
        or transaction["unchanged_services"]
        != [
            "tu1nz-adult-commercial-s0.service",
            "tu1nz-adult-publishing-s1.service",
            "tu1nz_encrypted_backup.service",
            "tu1nz_encrypted_backup.timer",
        ]
        or transaction["steps"] != SYNC_STEPS
    ):
        raise GateFailure("sync transaction boundary drift")

    rollback = exact(
        sync["rollback"],
        {
            "bundle_required",
            "evidence_root_pattern",
            "old_head_sha",
            "old_tree_sha",
            "preserved_rollback_ref_required",
            "status",
            "steps",
        },
        "sync rollback",
    )
    if (
        rollback["bundle_required"] is not True
        or rollback["evidence_root_pattern"]
        != "/opt/tu1nz_repos/backups/m4-27-control-sync/YYYYMMDDTHH-MM-SSZ"
        or rollback["old_head_sha"] != LAST_SERVER_SHA
        or rollback["old_tree_sha"] != LAST_SERVER_TREE
        or rollback["preserved_rollback_ref_required"] is not True
        or rollback["status"] != "PLANNED_NOT_AUTHORIZED"
        or rollback["steps"] != ROLLBACK_STEPS
    ):
        raise GateFailure("rollback preparation drift")

    prestart = exact(
        contract["fresh_prestart"],
        {
            "checks",
            "executed",
            "maximum_age_seconds",
            "must_run_after_control_sync",
            "must_run_immediately_before_authorization",
            "observed_at",
            "result",
        },
        "fresh prestart",
    )
    if prestart != {
        "checks": PREFLIGHT_CHECKS,
        "executed": False,
        "maximum_age_seconds": 300,
        "must_run_after_control_sync": True,
        "must_run_immediately_before_authorization": True,
        "observed_at": None,
        "result": "NOT_EXECUTED",
    }:
        raise GateFailure("fresh prestart must remain pending and exact")

    no_swap = exact(
        contract["no_swap_assessment"],
        {
            "assessed_at",
            "assessment_kind",
            "empirical_peak_rss_kib",
            "memory_max_configured",
            "mitigations",
            "observed_memory_available_kib",
            "observed_swap_total_kib",
            "oom_recovery",
            "operator_accepted",
            "recommendation",
            "required_fresh_memory_available_kib",
            "risk_factors",
            "scope",
            "workload_profile",
        },
        "no-swap assessment",
    )
    require_utc(no_swap["assessed_at"], "no-swap assessment")
    if (
        no_swap["assessment_kind"] != "PLANNING_RECOMMENDATION_NOT_ACCEPTANCE"
        or no_swap["recommendation"]
        != "ACCEPTABLE_FOR_ONE_CONTROLLED_FIRST_START"
        or no_swap["operator_accepted"] is not False
        or no_swap["observed_swap_total_kib"] != 0
        or no_swap["observed_memory_available_kib"] != 5948368
        or no_swap["required_fresh_memory_available_kib"] != 4194304
        or no_swap["empirical_peak_rss_kib"] is not None
        or no_swap["memory_max_configured"] is not False
        or no_swap["scope"] != "ONE_SYNTHETIC_NETWORK_FREE_FIRST_START_ONLY"
        or no_swap["workload_profile"]
        != "ONE_PYTHON_PROCESS_LOCAL_POSTGRES_ZERO_SUBMISSIONS_NO_MEDIA_NETWORK_FREE"
        or no_swap["risk_factors"] != NO_SWAP_RISK_FACTORS
        or no_swap["mitigations"] != NO_SWAP_MITIGATIONS
        or no_swap["oom_recovery"] != OOM_RECOVERY
    ):
        raise GateFailure("no-swap recommendation or acceptance boundary drift")

    window = exact(
        contract["first_start_window"],
        {
            "approval_maximum_age_seconds",
            "auto_recovery_enabled",
            "enablement_allowed",
            "exactly_one_start",
            "health_maximum_age_seconds",
            "maximum_runtime_seconds",
            "must_end_stopped",
            "prestart_maximum_age_seconds",
            "ready_timeout_seconds",
            "restart_allowed",
            "sequence",
            "stop_timeout_seconds",
            "timer_allowed",
        },
        "first-start window",
    )
    if window != {
        "approval_maximum_age_seconds": 3600,
        "auto_recovery_enabled": False,
        "enablement_allowed": False,
        "exactly_one_start": True,
        "health_maximum_age_seconds": 90,
        "maximum_runtime_seconds": 180,
        "must_end_stopped": True,
        "prestart_maximum_age_seconds": 300,
        "ready_timeout_seconds": 60,
        "restart_allowed": False,
        "sequence": [
            "FRESH_PREFLIGHT",
            "EXPLICIT_AUTHORIZATION",
            "EXACTLY_ONE_START",
            "READY",
            "LOCAL_HEALTH",
            "CONTROLLED_STOP",
            "POST_STATE_VERIFICATION",
            "EVIDENCE_PRESERVATION",
        ],
        "stop_timeout_seconds": 45,
        "timer_allowed": False,
    }:
        raise GateFailure("first-start window drift")

    recovery = exact(
        contract["recovery"],
        {
            "abort_steps",
            "automatic_database_rollback",
            "automatic_evidence_deletion",
            "evidence_root",
            "second_start_allowed",
            "stop_failure_is_critical",
        },
        "recovery",
    )
    if (
        recovery["automatic_database_rollback"] is not False
        or recovery["automatic_evidence_deletion"] is not False
        or recovery["evidence_root"]
        != "/opt/tu1nz_repos/backups/m4-28-commercial-s0-first-start"
        or recovery["second_start_allowed"] is not False
        or recovery["stop_failure_is_critical"] is not True
        or recovery["abort_steps"] != ABORT_STEPS
    ):
        raise GateFailure("abort or recovery boundary drift")

    product = exact(
        contract["product_boundary"],
        {
            "external_providers_enabled",
            "network_enabled",
            "paid_targets",
            "publishing_enabled",
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
        "publishing_enabled": False,
        "real_media_enabled": False,
        "real_payment_enabled": False,
        "synthetic_data_only": True,
        "synthetic_publishers_only": True,
        "telegram_intake_enabled": False,
        "uncompensated_targets": ["X"],
    }:
        raise GateFailure("product boundary drift")

    if require_sync_ready:
        raise GateFailure("server Control sync is not approved or executed")
    if require_prestart_ready:
        raise GateFailure("fresh prestart is not executed")
    if require_authorization_ready:
        raise GateFailure("M4.27 is preparation evidence and never authorizes first start")
    return False


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--require-sync-ready", action="store_true")
    parser.add_argument("--require-prestart-ready", action="store_true")
    parser.add_argument("--require-authorization-ready", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        validate_contract(
            read_contract(arguments.contract),
            require_sync_ready=arguments.require_sync_ready,
            require_prestart_ready=arguments.require_prestart_ready,
            require_authorization_ready=arguments.require_authorization_ready,
        )
    except GateFailure as error:
        print("M4_27_PREPARATION_GATE_BLOCKED " + str(error), file=sys.stderr)
        return 1
    print("M4_27_PREPARATION_VALID_NO_GO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
