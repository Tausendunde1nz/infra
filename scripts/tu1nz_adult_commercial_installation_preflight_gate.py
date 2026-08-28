#!/usr/bin/env python3
"""Validate the immutable, read-only M4.20 installation NO-GO evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


class GateFailure(RuntimeError):
    pass


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
TOP_LEVEL_KEYS = {
    "active",
    "activation_decision",
    "backup_restore",
    "blockers",
    "capacity",
    "contract_version",
    "final_baselines",
    "installed",
    "installation_decision",
    "interference",
    "network_enabled",
    "observation_window",
    "path_and_identity",
    "postgresql",
    "product_boundary",
    "required_next_gates",
    "server",
    "server_changed",
    "sprint",
    "unit",
}
REQUIRED_BLOCKERS = {
    "RUNTIME_PARENT_TRAVERSAL_ACL_NOT_VERSIONED",
    "POSTGRES_PEER_IDENTITY_MAPPING_NOT_VERSIONED",
    "CANONICAL_APPLICATION_CHECKOUT_NOT_FINAL",
    "COMMERCIAL_RELEASE_NOT_STAGED",
    "COMMERCIAL_IDENTITIES_AND_DATABASE_ABSENT",
    "MIGRATION_0014_NOT_INSTALLED",
    "VERSIONED_BACKUP_SCRIPT_NOT_INSTALLED",
    "EXACT_COMMERCIAL_BACKUP_AND_RESTORE_NOT_PROVEN",
    "COMMERCIAL_UNIT_NOT_INSTALLED_OR_NATIVE_VERIFIED",
    "FIRST_START_NOT_APPROVED",
}
EXPECTED_APPLICATION_SHA = "52494d6121660ead53774deb8616701f14bb7a8f"
EXPECTED_CONTROL_SHA = "2a1b46dfb90fb3e6edcdb7fceaf369bcac0f33e9"


def read_contract(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure("safe regular contract file required")
    if path.stat().st_size > 1024 * 1024:
        raise GateFailure("contract file too large")
    try:
        contract = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateFailure("invalid contract JSON") from error
    if not isinstance(contract, dict):
        raise GateFailure("contract object required")
    return contract


def require_boolean_map(payload: object, expected_value: bool, field: str) -> None:
    if (
        not isinstance(payload, dict)
        or not payload
        or any(not isinstance(key, str) or value is not expected_value for key, value in payload.items())
    ):
        raise GateFailure(field + " must be a nonempty exact boolean map")


def validate_contract(contract: dict[str, object]) -> None:
    if set(contract) != TOP_LEVEL_KEYS:
        raise GateFailure("exact top-level key set required")
    if (
        contract["contract_version"] != "tu1nz-commercial-installation-preflight-m4.20-v1"
        or contract["sprint"] != "M4.20"
        or contract["installation_decision"] != "NO_GO"
        or contract["activation_decision"] != "NO_GO"
    ):
        raise GateFailure("M4.20 NO-GO decision required")
    for field in ("active", "installed", "network_enabled", "server_changed"):
        if contract[field] is not False:
            raise GateFailure(field + " must remain false")

    blockers = contract["blockers"]
    if not isinstance(blockers, list) or set(blockers) != REQUIRED_BLOCKERS:
        raise GateFailure("exact installation blocker set required")

    baselines = contract["final_baselines"]
    if not isinstance(baselines, dict):
        raise GateFailure("final baseline object required")
    if (
        baselines.get("application_main_sha") != EXPECTED_APPLICATION_SHA
        or baselines.get("control_main_sha") != EXPECTED_CONTROL_SHA
        or baselines.get("control_canonical_checkout_sha") != EXPECTED_CONTROL_SHA
        or baselines.get("application_main_merged") is not True
        or baselines.get("control_main_merged") is not True
        or baselines.get("application_canonical_checkout_clean") is not True
        or baselines.get("control_canonical_checkout_clean") is not True
        or baselines.get("application_canonical_checkout_matches_final") is not False
        or baselines.get("control_canonical_checkout_matches_final") is not True
    ):
        raise GateFailure("final merge or canonical checkout evidence mismatch")
    for field in (
        "application_canonical_checkout_sha",
        "application_main_sha",
        "application_tree_sha",
        "control_canonical_checkout_sha",
        "control_main_sha",
        "control_tree_sha",
    ):
        if not isinstance(baselines.get(field), str) or SHA_RE.fullmatch(baselines[field]) is None:
            raise GateFailure("invalid baseline SHA: " + field)

    path = contract["path_and_identity"]
    if not isinstance(path, dict):
        raise GateFailure("path and identity evidence required")
    if (
        path.get("access_acl_for_runtime_identity_present") is not False
        or path.get("runtime_parent_traversal_ready") is not False
        or path.get("configuration_root_absent") is not True
        or path.get("release_root_absent") is not True
        or path.get("state_root_absent") is not True
        or path.get("operating_system_identity_absent") is not True
        or path.get("database_and_roles_absent") is not True
        or not isinstance(path.get("traversal_blocking_parents"), list)
        or not path["traversal_blocking_parents"]
    ):
        raise GateFailure("runtime path traversal blocker must remain explicit")

    postgres = contract["postgresql"]
    if not isinstance(postgres, dict):
        raise GateFailure("PostgreSQL evidence required")
    if (
        postgres.get("cluster_online") is not True
        or postgres.get("listen_addresses") != "localhost"
        or postgres.get("tcp_listener") != "127.0.0.1:5432"
        or postgres.get("local_default_authentication") != "peer"
        or postgres.get("ident_mapping_present") is not False
        or postgres.get("runtime_dsn_authentication_ready") is not False
        or postgres.get("planned_runtime_database_role")
        != "tu1nz_adult_commercial_s0_runtime"
        or postgres.get("planned_runtime_operating_system_user")
        != "tu1nz-adult-commercial-s0"
        or postgres.get("database_absent") is not True
        or postgres.get("roles_absent") is not True
    ):
        raise GateFailure("PostgreSQL peer-identity blocker must remain explicit")

    interference = contract["interference"]
    if not isinstance(interference, dict):
        raise GateFailure("interference evidence required")
    false_interference = {
        "commercial_container_mount_reference_detected",
        "commercial_cron_reference_detected",
        "commercial_open_file_reference_detected",
        "commercial_process_reference_detected",
        "commercial_service_or_timer_reference_detected",
        "path_collision_detected",
    }
    if any(interference.get(field) is not False for field in false_interference):
        raise GateFailure("commercial path interference detected")

    backup = contract["backup_restore"]
    if not isinstance(backup, dict):
        raise GateFailure("backup evidence required")
    if (
        backup.get("exact_archive_remote_present") is not True
        or backup.get("restore_smoke_passed") is not True
        or backup.get("commercial_release_bound") is not False
        or backup.get("installed_backup_script_matches_versioned") is not False
        or backup.get("legacy_monthly_restore_false_green_known") is not True
        or backup.get("restore_smoke_archive") != backup.get("exact_archive_name")
        or not isinstance(backup.get("exact_archive_bytes"), int)
        or backup["exact_archive_bytes"] <= 0
    ):
        raise GateFailure("backup and restore evidence mismatch")
    for field in (
        "exact_archive_sha256",
        "installed_backup_script_sha256",
        "versioned_backup_script_sha256",
    ):
        if not isinstance(backup.get(field), str) or DIGEST_RE.fullmatch(backup[field]) is None:
            raise GateFailure("invalid backup digest: " + field)

    capacity = contract["capacity"]
    if not isinstance(capacity, dict) or capacity.get("capacity_preflight_passed") is not True:
        raise GateFailure("capacity preflight must pass")
    if (
        capacity.get("application_tree_truncated") is not False
        or capacity.get("control_tree_truncated") is not False
        or not isinstance(capacity.get("root_filesystem_available_bytes"), int)
        or capacity["root_filesystem_available_bytes"] <= 0
    ):
        raise GateFailure("capacity evidence mismatch")

    unit = contract["unit"]
    if not isinstance(unit, dict):
        raise GateFailure("unit evidence required")
    if (
        unit.get("installed") is not False
        or unit.get("native_verify_result") != "BLOCKED_EXPECTED_MISSING_EXECUTABLE"
        or unit.get("native_security_rating") != "SAFE"
        or unit.get("no_enablement_section") is not True
        or unit.get("private_network") is not True
        or unit.get("restrict_address_families") != "AF_UNIX"
        or not isinstance(unit.get("versioned_sha256"), str)
        or DIGEST_RE.fullmatch(unit["versioned_sha256"]) is None
    ):
        raise GateFailure("uninstalled network-free unit evidence mismatch")

    boundary = contract["product_boundary"]
    if not isinstance(boundary, dict):
        raise GateFailure("product boundary required")
    for field in (
        "external_providers_enabled",
        "real_media_enabled",
        "real_payment_enabled",
        "telegram_intake_enabled",
    ):
        if boundary.get(field) is not False:
            raise GateFailure(field + " must remain false")
    if (
        boundary.get("synthetic_data_only") is not True
        or boundary.get("paid_targets") != ["REDDIT", "TELEGRAM"]
        or boundary.get("uncompensated_targets") != ["X"]
    ):
        raise GateFailure("commercial product boundary mismatch")

    require_boolean_map(contract["required_next_gates"], False, "required_next_gates")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        validate_contract(read_contract(arguments.contract))
        print("M4_20_INSTALLATION_PREFLIGHT_NO_GO_CONFIRMED")
        return 0
    except (GateFailure, OSError) as error:
        print("M4_20_INSTALLATION_PREFLIGHT_INVALID " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
