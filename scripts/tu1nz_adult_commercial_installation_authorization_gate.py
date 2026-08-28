#!/usr/bin/env python3
"""Validate the fail-closed M4.22 commercial installation authorization."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


class GateFailure(RuntimeError):
    pass


SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_APPLICATION_SHA = "52494d6121660ead53774deb8616701f14bb7a8f"
EXPECTED_APPLICATION_TREE = "b2820945c52ffdf77c2f5fbdd227c03ee6b245ab"
EXPECTED_CONTROL_SHA = "e6426429cd44a57afd22801789ad518952098df0"
EXPECTED_CONTROL_TREE = "01c0be0ed03d31901f2132c853771807bbeaebdf"
EXPECTED_BLOCKERS = {
    "FRESH_PREINSTALL_BACKUP_NOT_CREATED",
    "VERSIONED_BACKUP_SCRIPT_NOT_INSTALLED",
    "COMMERCIAL_RELEASE_NOT_STAGED",
    "COMMERCIAL_IDENTITIES_AND_DATABASE_ABSENT",
    "COMMERCIAL_UNIT_NOT_INSTALLED",
    "FIRST_START_NOT_APPROVED",
}
EXPECTED_TOP_LEVEL = {
    "active",
    "activation_decision",
    "authorization",
    "backup_restore",
    "blockers",
    "contract_version",
    "execution_decision",
    "host_access_contract",
    "host_observation",
    "installation_gates",
    "installed",
    "network_enabled",
    "product_boundary",
    "repository_baselines",
    "server",
    "server_changed",
    "sprint",
    "technical_decision",
    "unit",
}


def read_contract(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure("safe regular contract file required")
    if path.stat().st_size > 1024 * 1024:
        raise GateFailure("contract file too large")
    try:
        payload = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateFailure("invalid contract JSON") from error
    if not isinstance(payload, dict):
        raise GateFailure("contract object required")
    return payload


def require_digest_map(payload: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(payload, dict) or set(payload) != fields:
        raise GateFailure("exact " + label + " key set required")
    return payload


def validate_contract(contract: dict[str, object]) -> None:
    if set(contract) != EXPECTED_TOP_LEVEL:
        raise GateFailure("exact top-level key set required")
    if (
        contract["contract_version"] != "tu1nz-commercial-installation-authorization-m4.22-v1"
        or contract["sprint"] != "M4.22"
        or contract["technical_decision"] != "GO_FOR_SEPARATELY_APPROVED_ROOT_WINDOW"
        or contract["execution_decision"] != "GO_FOR_PREINSTALL_BACKUP_AND_STOPPED_INSTALLATION"
        or contract["activation_decision"] != "NO_GO"
    ):
        raise GateFailure("M4.22 split decision required")
    for field in ("active", "installed", "network_enabled", "server_changed"):
        if contract[field] is not False:
            raise GateFailure(field + " must remain false")
    if not isinstance(contract["blockers"], list) or set(contract["blockers"]) != EXPECTED_BLOCKERS:
        raise GateFailure("exact execution blocker set required")

    baselines = require_digest_map(
        contract["repository_baselines"],
        {
            "application_canonical_checkout_sha",
            "application_main_sha",
            "application_tree_sha",
            "control_canonical_checkout_sha",
            "control_main_sha",
            "control_tree_sha",
        },
        "repository baseline",
    )
    if (
        baselines["application_main_sha"] != EXPECTED_APPLICATION_SHA
        or baselines["application_tree_sha"] != EXPECTED_APPLICATION_TREE
        or baselines["control_main_sha"] != EXPECTED_CONTROL_SHA
        or baselines["control_canonical_checkout_sha"] != EXPECTED_CONTROL_SHA
        or baselines["control_tree_sha"] != EXPECTED_CONTROL_TREE
        or baselines["application_canonical_checkout_sha"] == EXPECTED_APPLICATION_SHA
    ):
        raise GateFailure("repository baseline mismatch")
    if any(not isinstance(value, str) or SHA40.fullmatch(value) is None for value in baselines.values()):
        raise GateFailure("invalid repository SHA")

    access = require_digest_map(
        contract["host_access_contract"],
        {
            "hba_rule_sha256",
            "host_access_gate_sha256",
            "ident_map_sha256",
            "manifest_sha256",
            "m4_21_merged",
            "path_access_tool_sha256",
        },
        "host access contract",
    )
    if access["m4_21_merged"] is not True:
        raise GateFailure("M4.21 must be merged")
    for field, value in access.items():
        if field != "m4_21_merged" and (not isinstance(value, str) or SHA256.fullmatch(value) is None):
            raise GateFailure("invalid host-access digest")

    host = contract["host_observation"]
    if not isinstance(host, dict):
        raise GateFailure("host observation required")
    required_true = {
        "application_canonical_checkout_clean",
        "commercial_database_absent",
        "commercial_identity_absent",
        "commercial_paths_absent",
        "commercial_roles_absent",
        "control_canonical_checkout_clean",
        "control_canonical_checkout_matches_final",
        "postgres_cluster_online",
    }
    required_false = {
        "application_canonical_checkout_matches_final",
        "commercial_container_mount_reference_detected",
        "commercial_cron_reference_detected",
        "commercial_open_file_reference_detected",
        "commercial_process_reference_detected",
        "commercial_service_or_timer_reference_detected",
    }
    if any(host.get(field) is not True for field in required_true):
        raise GateFailure("positive host preflight evidence missing")
    if any(host.get(field) is not False for field in required_false):
        raise GateFailure("host collision or stale application claim mismatch")
    if (
        host.get("postgres_listen_addresses") != "localhost"
        or host.get("postgres_tcp_listener") != "127.0.0.1:5432"
        or host.get("unrelated_failed_unit") != "tu1nz-doc.service"
    ):
        raise GateFailure("host boundary mismatch")

    authorization = contract["authorization"]
    if not isinstance(authorization, dict):
        raise GateFailure("authorization object required")
    if (
        authorization.get("operator_approved") is not True
        or authorization.get("known_unrelated_failed_unit_accepted") is not True
        or authorization.get("approved_at") != "2026-08-28T14:35:32Z"
        or authorization.get("selected_profile")
        != {"retention_days": 7, "rpo_target_seconds": 86400, "rto_target_seconds": 14400}
        or authorization.get("recommended_profile")
        != {"retention_days": 7, "rpo_target_seconds": 86400, "rto_target_seconds": 14400}
    ):
        raise GateFailure("exact operator recovery approval required")

    backup = contract["backup_restore"]
    if not isinstance(backup, dict):
        raise GateFailure("backup evidence required")
    if (
        backup.get("existing_archive_remote_present") is not True
        or backup.get("existing_restore_smoke_passed") is not True
        or backup.get("fresh_preinstall_archive_created") is not False
        or backup.get("fresh_preinstall_restore_verified") is not False
        or backup.get("installed_backup_script_matches_versioned") is not False
        or backup.get("installed_backup_script_sha256") == backup.get("versioned_backup_script_sha256")
    ):
        raise GateFailure("backup transition must remain pending")
    for field in ("existing_archive_sha256", "installed_backup_script_sha256", "versioned_backup_script_sha256"):
        if not isinstance(backup.get(field), str) or SHA256.fullmatch(backup[field]) is None:
            raise GateFailure("invalid backup digest")

    gates = contract["installation_gates"]
    expected_gates = {
        "commercial_installation_executed": False,
        "control_sync_verified": True,
        "first_start_approved": False,
        "fresh_preinstall_backup_verified": False,
        "host_access_design_verified": True,
        "immutable_release_staged": False,
        "operator_profile_approved": True,
        "path_and_interference_preflight_passed": True,
        "repository_baselines_final": True,
        "root_installation_window_approved": True,
    }
    if gates != expected_gates:
        raise GateFailure("exact fail-closed installation gate set required")

    boundary = contract["product_boundary"]
    if not isinstance(boundary, dict):
        raise GateFailure("product boundary required")
    for field in ("external_providers_enabled", "real_media_enabled", "real_payment_enabled", "telegram_intake_enabled"):
        if boundary.get(field) is not False:
            raise GateFailure(field + " must remain false")
    if (
        boundary.get("synthetic_data_only") is not True
        or boundary.get("paid_targets") != ["REDDIT", "TELEGRAM"]
        or boundary.get("uncompensated_targets") != ["X"]
    ):
        raise GateFailure("commercial product boundary mismatch")

    unit = contract["unit"]
    if not isinstance(unit, dict) or unit.get("installed") is not False:
        raise GateFailure("unit must remain uninstalled")
    if (
        unit.get("native_verify_result") != "BLOCKED_EXPECTED_MISSING_EXECUTABLE"
        or unit.get("native_security_rating") != "SAFE"
        or unit.get("native_security_exposure_level") != 0.6
        or not isinstance(unit.get("versioned_sha256"), str)
        or SHA256.fullmatch(unit["versioned_sha256"]) is None
    ):
        raise GateFailure("versioned unit evidence mismatch")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        validate_contract(read_contract(arguments.contract))
        print("M4_22_STOPPED_INSTALLATION_AUTHORIZED")
        return 0
    except (GateFailure, OSError) as error:
        print("M4_22_INSTALLATION_AUTHORIZATION_INVALID " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
