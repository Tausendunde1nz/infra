#!/usr/bin/env python3
"""Validate the fail-closed M4.24 network-free first-start contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


class GateFailure(RuntimeError):
    pass


APPLICATION_SHA = "52494d6121660ead53774deb8616701f14bb7a8f"
APPLICATION_TREE = "b2820945c52ffdf77c2f5fbdd227c03ee6b245ab"
CONTROL_SHA = "8c4e8992a60c215295cf9d0c400afcd9a931f883"
ARCHIVE_NAME = "tu1nz_system_backup_20260828T16-50-53Z.tar.gz"
ARCHIVE_SHA256 = "b96f9efb304b2898758539516d842d27574307de82cbfb49229692ab8c9bcbd7"
ARCHIVE_INVENTORY_SHA256 = (
    "24144ec79a867c7f002da15c80fc7c9a5f429d28c52d16715a5602dded1c80c2"
)
MANIFEST_SHA256 = "2a3dc857205f9cff262edd686bc6db13d799c1e5de8aea954a8f50b9420cdc54"
UNIT_SHA256 = "ecec13e294ded68dfeeaba1300eb2f5247aacf5e9085c9838eca3b50f6a56bf3"
NO_GO_BLOCKERS = {
    "FIRST_START_NOT_APPROVED",
    "NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START",
    "UNIT_SINGLE_START_GUARD_NOT_INSTALLED",
}
APPROVAL_MAXIMUM_AGE_SECONDS = 3600
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TOP_LEVEL = {
    "active",
    "approval",
    "archive",
    "blockers",
    "contract_version",
    "decision",
    "environment",
    "first_start_window",
    "preflight_observation",
    "product_boundary",
    "recovery",
    "release",
    "sprint",
    "starting_database",
}


def read_contract(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure("safe regular first-start contract required")
    if path.stat().st_size > 1024 * 1024:
        raise GateFailure("first-start contract is too large")
    try:
        payload = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateFailure("invalid first-start contract JSON") from error
    if not isinstance(payload, dict):
        raise GateFailure("first-start contract object required")
    return payload


def exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise GateFailure("exact " + label + " key set required")
    return value


def utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GateFailure(label + " must be an explicit UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise GateFailure(label + " is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise GateFailure(label + " must be UTC")
    return parsed


def validate_contract(
    contract: dict[str, object],
    *,
    require_approved: bool,
    now: datetime | None = None,
) -> bool:
    if set(contract) != TOP_LEVEL:
        raise GateFailure("exact top-level key set required")
    if (
        contract["contract_version"]
        != "tu1nz-commercial-network-free-first-start-m4.24-v1"
        or contract["sprint"] != "M4.24"
        or contract["environment"] != "STAGING-S0-COMMERCIAL-CANDIDATE"
    ):
        raise GateFailure("M4.24 first-start identity mismatch")
    if type(contract["active"]) is not bool:
        raise GateFailure("active must be an exact boolean")
    approved = contract["active"] is True

    release = exact_object(
        contract["release"],
        {
            "application_sha",
            "application_tree_sha",
            "control_sha",
            "release_manifest_sha256",
            "unit_sha256",
        },
        "release",
    )
    if release != {
        "application_sha": APPLICATION_SHA,
        "application_tree_sha": APPLICATION_TREE,
        "control_sha": CONTROL_SHA,
        "release_manifest_sha256": MANIFEST_SHA256,
        "unit_sha256": UNIT_SHA256,
    }:
        raise GateFailure("exact stopped release boundary required")
    for key in ("application_sha", "application_tree_sha", "control_sha"):
        if SHA40.fullmatch(str(release[key])) is None:
            raise GateFailure("invalid release SHA")
    for key in ("release_manifest_sha256", "unit_sha256"):
        if SHA256.fullmatch(str(release[key])) is None:
            raise GateFailure("invalid release digest")

    archive = exact_object(
        contract["archive"],
        {
            "archive_inventory_sha256",
            "backup_completed_at",
            "exact_archive_bytes",
            "exact_archive_name",
            "exact_archive_remote_hash_verified",
            "exact_archive_sha256",
            "isolated_restore_passed",
            "isolated_restore_root",
        },
        "archive",
    )
    if (
        archive["exact_archive_name"] != ARCHIVE_NAME
        or archive["exact_archive_sha256"] != ARCHIVE_SHA256
        or archive["archive_inventory_sha256"] != ARCHIVE_INVENTORY_SHA256
        or archive["exact_archive_bytes"] != 63734473
        or archive["exact_archive_remote_hash_verified"] is not True
        or archive["isolated_restore_passed"] is not True
        or archive["isolated_restore_root"]
        != "/opt/tu1nz_repos/backups/m4-23-commercial-s0-restore/20260828T16-50-53Z"
    ):
        raise GateFailure("exact backup and restore boundary required")
    if utc(archive["backup_completed_at"], "backup_completed_at") != datetime(
        2026, 8, 28, 16, 55, 27, tzinfo=timezone.utc
    ):
        raise GateFailure("backup completion boundary mismatch")

    window = exact_object(
        contract["first_start_window"],
        {
            "approval_maximum_age_seconds",
            "health_maximum_age_seconds",
            "maximum_runtime_seconds",
            "must_end_stopped",
            "ready_timeout_seconds",
            "single_controlled_start",
            "stop_timeout_seconds",
        },
        "first-start window",
    )
    if window != {
        "approval_maximum_age_seconds": APPROVAL_MAXIMUM_AGE_SECONDS,
        "health_maximum_age_seconds": 90,
        "maximum_runtime_seconds": 180,
        "must_end_stopped": True,
        "ready_timeout_seconds": 60,
        "single_controlled_start": True,
        "stop_timeout_seconds": 45,
    }:
        raise GateFailure("bounded first-start window required")
    if (
        window["must_end_stopped"] is not True
        or window["single_controlled_start"] is not True
        or any(
            type(window[field]) is not int
            for field in (
                "approval_maximum_age_seconds",
                "health_maximum_age_seconds",
                "maximum_runtime_seconds",
                "ready_timeout_seconds",
                "stop_timeout_seconds",
            )
        )
    ):
        raise GateFailure("exact first-start window types required")

    observation = exact_object(
        contract["preflight_observation"],
        {
            "application_release_clean",
            "backup_service_idle",
            "backup_timer_active",
            "commercial_container_mount_reference_detected",
            "commercial_cron_reference_detected",
            "commercial_open_file_reference_detected",
            "commercial_process_reference_detected",
            "commercial_timer_reference_detected",
            "control_release_clean",
            "memory_available_kib",
            "native_unit_verify_passed",
            "observed_at",
            "release_gate_passed",
            "root_filesystem_available_bytes",
            "runtime_maximum_seconds",
            "s1_active",
            "security_exposure_level",
            "security_rating",
            "swap_total_kib",
            "tailscale_ipv4",
            "unit_active",
            "unit_file_state",
            "unit_installed",
            "unit_previously_started",
            "unit_restart_policy",
            "unit_single_start_guard_installed",
        },
        "preflight observation",
    )
    required_true = {
        "application_release_clean",
        "backup_service_idle",
        "backup_timer_active",
        "control_release_clean",
        "native_unit_verify_passed",
        "release_gate_passed",
        "s1_active",
        "unit_installed",
    }
    required_false = {
        "commercial_container_mount_reference_detected",
        "commercial_cron_reference_detected",
        "commercial_open_file_reference_detected",
        "commercial_process_reference_detected",
        "commercial_timer_reference_detected",
        "unit_active",
        "unit_previously_started",
    }
    if any(observation[field] is not True for field in required_true):
        raise GateFailure("positive technical preflight evidence missing")
    if any(observation[field] is not False for field in required_false):
        raise GateFailure("pre-start interference or prior start detected")
    if (
        observation["unit_file_state"] != "static"
        or observation["security_rating"] != "SAFE"
        or observation["security_exposure_level"] != 0.6
        or observation["swap_total_kib"] != 0
        or observation["tailscale_ipv4"] != "100.121.130.51"
        or not isinstance(observation["root_filesystem_available_bytes"], int)
        or observation["root_filesystem_available_bytes"] < 1024 * 1024 * 1024
        or not isinstance(observation["memory_available_kib"], int)
        or observation["memory_available_kib"] < 512 * 1024
    ):
        raise GateFailure("technical preflight boundary mismatch")
    observed_at = utc(observation["observed_at"], "observed_at")

    database = exact_object(
        contract["starting_database"],
        {"business_rows_zero", "function_count", "seed_counts", "table_count"},
        "starting database",
    )
    if (
        database["business_rows_zero"] is not True
        or database["table_count"] != 39
        or database["function_count"] != 21
        or database["seed_counts"]
        != {
            "country_policy_rules": 1,
            "creators": 1,
            "integration_accounts": 3,
            "platform_policy_rules": 3,
            "policy_versions": 1,
            "publication_destinations": 3,
        }
    ):
        raise GateFailure("synthetic starting database mismatch")
    if (
        type(database["table_count"]) is not int
        or type(database["function_count"]) is not int
        or not isinstance(database["seed_counts"], dict)
        or any(type(value) is not int for value in database["seed_counts"].values())
    ):
        raise GateFailure("exact starting database count types required")

    boundary = exact_object(
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
    if (
        any(
            boundary[field] is not False
            for field in (
                "external_providers_enabled",
                "network_enabled",
                "real_media_enabled",
                "real_payment_enabled",
                "telegram_intake_enabled",
            )
        )
        or boundary["synthetic_data_only"] is not True
        or boundary["synthetic_publishers_only"] is not True
        or boundary["paid_targets"] != ["REDDIT", "TELEGRAM"]
        or boundary["uncompensated_targets"] != ["X"]
    ):
        raise GateFailure("network-free synthetic boundary required")

    recovery = exact_object(
        contract["recovery"],
        {
            "abort_must_stop_unit",
            "abort_preserves_database",
            "abort_preserves_runtime_evidence",
            "evidence_root",
            "never_enable_unit",
            "never_remove_runtime_evidence_automatically",
        },
        "recovery",
    )
    if recovery != {
        "abort_must_stop_unit": True,
        "abort_preserves_database": True,
        "abort_preserves_runtime_evidence": True,
        "evidence_root": "/opt/tu1nz_repos/backups/m4-24-commercial-s0-first-start",
        "never_enable_unit": True,
        "never_remove_runtime_evidence_automatically": True,
    }:
        raise GateFailure("fail-closed recovery contract required")

    approval = exact_object(
        contract["approval"],
        {
            "approved_at",
            "first_start_approved",
            "known_unrelated_failed_unit_accepted",
            "no_swap_risk_accepted",
        },
        "approval",
    )
    if approval["known_unrelated_failed_unit_accepted"] is not True:
        raise GateFailure("known unrelated failed unit must remain explicit")
    blockers = contract["blockers"]
    if (
        not isinstance(blockers, list)
        or any(
            not isinstance(blocker, str)
            or re.fullmatch(r"[A-Z0-9_]+", blocker) is None
            for blocker in blockers
        )
        or len(blockers) != len(set(blockers))
    ):
        raise GateFailure("unique blocker list required")

    if approved:
        current = now or datetime.now(timezone.utc)
        approved_at = utc(approval["approved_at"], "approved_at")
        if (
            contract["decision"] != "GO_FOR_ONE_CONTROLLED_NETWORK_FREE_FIRST_START"
            or blockers != []
            or approval["first_start_approved"] is not True
            or approval["no_swap_risk_accepted"] is not True
            or approved_at < observed_at
            or approved_at > current + timedelta(seconds=5)
            or current - approved_at
            > timedelta(seconds=APPROVAL_MAXIMUM_AGE_SECONDS)
            or observation["unit_single_start_guard_installed"] is not True
            or observation["unit_restart_policy"] != "no"
            or observation["runtime_maximum_seconds"] != 180
        ):
            raise GateFailure("complete post-preflight first-start approval required")
    else:
        if (
            contract["decision"] != "NO_GO"
            or set(blockers) != NO_GO_BLOCKERS
            or approval["first_start_approved"] is not False
            or approval["no_swap_risk_accepted"] is not False
            or approval["approved_at"] is not None
            or observation["unit_single_start_guard_installed"] is not False
            or observation["unit_restart_policy"] != "on-failure"
            or observation["runtime_maximum_seconds"] is not None
        ):
            raise GateFailure("exact pre-approval NO-GO required")
    if require_approved and not approved:
        raise GateFailure("FIRST_START_NOT_APPROVED")
    return approved


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--require-approved", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        approved = validate_contract(
            read_contract(arguments.contract),
            require_approved=arguments.require_approved,
        )
        print(
            "M4_24_FIRST_START_AUTHORIZED"
            if approved
            else "M4_24_FIRST_START_CONTRACT_OK_NO_GO"
        )
        return 0
    except (GateFailure, OSError) as error:
        print("M4_24_FIRST_START_BLOCKED " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
