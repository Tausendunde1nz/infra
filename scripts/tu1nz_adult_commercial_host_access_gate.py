#!/usr/bin/env python3
"""Read-only M4.21 gate for commercial path and PostgreSQL peer design."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path, PurePosixPath


class GateFailure(RuntimeError):
    pass


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
TOP_LEVEL_KEYS = {
    "active",
    "activation_decision",
    "application_sha",
    "artifact_sha256",
    "contract_version",
    "control_parent_sha",
    "design_decision",
    "installed",
    "installation_decision",
    "path_access",
    "postgres_peer",
    "product_boundary",
    "required_installation_gates",
    "rollback",
    "server_changed",
    "sprint",
}
ARTIFACTS = {
    "config/postgresql/adult-publishing-commercial-s0.pg_hba.rule",
    "config/postgresql/adult-publishing-commercial-s0.pg_ident.map",
    "scripts/tu1nz_adult_commercial_path_access.sh",
}
RUNTIME_USER = "tu1nz-adult-commercial-s0"
RUNTIME_GROUP = "tu1nz-adult-commercial-s0"
DATABASE = "tu1nz_adult_commercial_s0"
RUNTIME_ROLE = "tu1nz_adult_commercial_s0_runtime"
MIGRATOR_ROLE = "tu1nz_adult_commercial_s0_migrator"
MAP_NAME = "tu1nz_adult_commercial_s0"
HBA_FIELDS = ["local", DATABASE, RUNTIME_ROLE, "peer", "map=" + MAP_NAME]
HBA_ANCHOR_FIELDS = ["local", "all", "all", "peer"]
IDENT_FIELDS = [MAP_NAME, RUNTIME_USER, RUNTIME_ROLE]
PATHS = [
    {
        "acl_mask": "rwx",
        "expected_metadata": "2770:chatops:chatops",
        "path": "/opt/tu1nz_repos",
    },
    {
        "acl_mask": "r-x",
        "expected_metadata": "2750:root:chatops",
        "path": "/opt/tu1nz_repos/releases",
    },
    {
        "acl_mask": "r-x",
        "expected_metadata": "2750:root:chatops",
        "path": "/opt/tu1nz_repos/releases/adult-publishing",
    },
    {
        "acl_mask": "r-x",
        "expected_metadata": "750:root:chatops",
        "path": "/etc/tu1nz",
    },
    {
        "acl_mask": "r-x",
        "expected_metadata": "2750:root:chatops",
        "path": "/var/lib/tausendunde1nz/adult-publishing",
    },
]


def read_json(path: Path, field: str) -> dict[str, object]:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure(field + ": safe regular file required")
    if path.stat().st_size > 1024 * 1024:
        raise GateFailure(field + ": file too large")
    try:
        payload = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateFailure(field + ": invalid JSON") from error
    if not isinstance(payload, dict):
        raise GateFailure(field + ": object required")
    return payload


def sha256_file(path: Path, expected_mode: int) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure("artifact must be a safe regular file: " + str(path))
    if stat.S_IMODE(path.stat().st_mode) != expected_mode:
        raise GateFailure("artifact mode mismatch: " + str(path))
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve_artifact(repository: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise GateFailure("unsafe artifact path")
    root = repository.resolve(strict=True)
    path = repository.joinpath(*relative.parts)
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as error:
        raise GateFailure("artifact escapes Control repository") from error
    return path


def active_fields(path: Path) -> list[list[str]]:
    fields: list[list[str]] = []
    try:
        content = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise GateFailure("configuration is unreadable: " + str(path)) from error
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].rstrip()
        fields.append(line.split())
    return fields


def validate_artifacts(contract: dict[str, object], repository: Path) -> None:
    artifacts = contract["artifact_sha256"]
    if (
        not isinstance(artifacts, dict)
        or set(artifacts) != ARTIFACTS
        or any(not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None for value in artifacts.values())
    ):
        raise GateFailure("exact reviewed artifact digest set required")
    for name, expected in artifacts.items():
        path = resolve_artifact(repository, name)
        mode = 0o755 if name.endswith(".sh") else 0o644
        if sha256_file(path, mode) != expected:
            raise GateFailure("artifact digest drift: " + name)

    hba = resolve_artifact(
        repository,
        "config/postgresql/adult-publishing-commercial-s0.pg_hba.rule",
    )
    ident = resolve_artifact(
        repository,
        "config/postgresql/adult-publishing-commercial-s0.pg_ident.map",
    )
    if active_fields(hba) != [HBA_FIELDS]:
        raise GateFailure("versioned pg_hba rule mismatch")
    if active_fields(ident) != [IDENT_FIELDS]:
        raise GateFailure("versioned pg_ident mapping mismatch")

    path_tool = resolve_artifact(
        repository,
        "scripts/tu1nz_adult_commercial_path_access.sh",
    )
    source = path_tool.read_text(encoding="ascii")
    required_tokens = {
        "apply|verify|rollback",
        "setfacl --no-mask -m",
        "setfacl --no-mask -x",
        "runtime identity must not belong to $FORBIDDEN_GROUP",
        "runuser -u \"$RUNTIME_USER\" -- test ! -r",
        "runuser -u \"$RUNTIME_USER\" -- test ! -w",
    }
    if any(token not in source for token in required_tokens):
        raise GateFailure("path access transaction is incomplete")
    if "setfacl -R" in source or "setfacl --recursive" in source:
        raise GateFailure("recursive ACL mutation is forbidden")


def validate_contract(contract: dict[str, object]) -> None:
    if set(contract) != TOP_LEVEL_KEYS:
        raise GateFailure("exact top-level contract key set required")
    if (
        contract["contract_version"] != "tu1nz-commercial-host-access-m4.21-v1"
        or contract["sprint"] != "M4.21"
        or contract["design_decision"] != "GO"
        or contract["installation_decision"] != "NO_GO"
        or contract["activation_decision"] != "NO_GO"
    ):
        raise GateFailure("reviewed design-only decision required")
    for field in ("active", "installed", "server_changed"):
        if contract[field] is not False:
            raise GateFailure(field + " must remain false")
    for field in ("application_sha", "control_parent_sha"):
        if not isinstance(contract[field], str) or SHA_RE.fullmatch(contract[field]) is None:
            raise GateFailure("invalid " + field)
    if (
        contract["application_sha"] != "52494d6121660ead53774deb8616701f14bb7a8f"
        or contract["control_parent_sha"] != "7bcf6e1eb064e1d7328caa160030685f9ed10595"
    ):
        raise GateFailure("final application or stacked Control parent mismatch")

    path = contract["path_access"]
    if not isinstance(path, dict):
        raise GateFailure("path access object required")
    if (
        path.get("runtime_user") != RUNTIME_USER
        or path.get("runtime_group") != RUNTIME_GROUP
        or path.get("forbidden_supplementary_group") != "chatops"
        or path.get("entry") != "--x"
        or path.get("preserve_acl_mask") is not True
        or path.get("recursive") is not False
        or path.get("paths") != PATHS
        or path.get("modes") != ["apply", "verify", "rollback"]
    ):
        raise GateFailure("least-privilege path contract mismatch")

    postgres = contract["postgres_peer"]
    if not isinstance(postgres, dict):
        raise GateFailure("PostgreSQL peer object required")
    if (
        postgres.get("database") != DATABASE
        or postgres.get("runtime_role") != RUNTIME_ROLE
        or postgres.get("migrator_role") != MIGRATOR_ROLE
        or postgres.get("operating_system_user") != RUNTIME_USER
        or postgres.get("map_name") != MAP_NAME
        or postgres.get("authentication_method") != "peer"
        or postgres.get("hba_fields") != HBA_FIELDS
        or postgres.get("hba_anchor_fields") != HBA_ANCHOR_FIELDS
        or postgres.get("hba_rule_must_precede_anchor") is not True
        or postgres.get("ident_fields") != IDENT_FIELDS
        or postgres.get("credential_required") is not False
        or postgres.get("migrator_mapping_present") is not False
        or postgres.get("configuration_backup_required") is not True
        or postgres.get("reload_required") is not True
        or postgres.get("native_rule_views_error_free_required") is not True
    ):
        raise GateFailure("credential-free PostgreSQL peer contract mismatch")
    if postgres.get("observed_hba_sha256") != "ad0df9635890926d79a12d5627b68af6b85b6254fa23cace2bbe077838969c9e":
        raise GateFailure("observed pg_hba baseline mismatch")
    if postgres.get("observed_ident_sha256") != "b4dfef08731a7d20a3bb724ad4cf3e1cd91ec01fbe51349c6a3acc5704072965":
        raise GateFailure("observed pg_ident baseline mismatch")

    rollback = contract["rollback"]
    if not isinstance(rollback, dict):
        raise GateFailure("rollback contract required")
    if (
        rollback.get("acl_mode") != "rollback"
        or rollback.get("remove_only_commercial_acl_entry") is not True
        or rollback.get("restore_exact_postgres_file_backups") is not True
        or rollback.get("preserve_s1_acl_and_runtime") is not True
        or rollback.get("postgres_reload_and_rule_validation_required") is not True
        or rollback.get("runtime_connection_must_fail_after_rollback") is not True
    ):
        raise GateFailure("exact rollback contract mismatch")

    boundary = contract["product_boundary"]
    if not isinstance(boundary, dict):
        raise GateFailure("product boundary required")
    false_fields = {
        "external_providers_enabled",
        "network_enabled",
        "real_media_enabled",
        "real_payment_enabled",
        "telegram_intake_enabled",
    }
    if any(boundary.get(field) is not False for field in false_fields):
        raise GateFailure("live product boundary must remain disabled")
    if (
        boundary.get("synthetic_data_only") is not True
        or boundary.get("paid_targets") != ["REDDIT", "TELEGRAM"]
        or boundary.get("uncompensated_targets") != ["X"]
    ):
        raise GateFailure("commercial product target boundary mismatch")

    gates = contract["required_installation_gates"]
    if (
        not isinstance(gates, dict)
        or not gates
        or any(not isinstance(key, str) or value is not False for key, value in gates.items())
    ):
        raise GateFailure("all installation gates must remain false in M4.21")


def validate_installed_postgres(hba: Path, ident: Path) -> None:
    hba_lines = active_fields(hba)
    exact_indexes = [index for index, fields in enumerate(hba_lines) if fields == HBA_FIELDS]
    anchor_indexes = [index for index, fields in enumerate(hba_lines) if fields == HBA_ANCHOR_FIELDS]
    if len(exact_indexes) != 1 or len(anchor_indexes) != 1:
        raise GateFailure("exactly one commercial peer rule and generic peer anchor required")
    if exact_indexes[0] + 1 != anchor_indexes[0]:
        raise GateFailure("commercial peer rule must immediately precede generic peer rule")
    for fields in hba_lines:
        if fields in (HBA_FIELDS, HBA_ANCHOR_FIELDS):
            continue
        if DATABASE in fields or RUNTIME_ROLE in fields or MAP_NAME in fields:
            raise GateFailure("unexpected commercial pg_hba rule")
        if "trust" in fields:
            raise GateFailure("trust authentication is forbidden")

    ident_lines = active_fields(ident)
    exact_mappings = [fields for fields in ident_lines if fields == IDENT_FIELDS]
    if len(exact_mappings) != 1:
        raise GateFailure("exactly one commercial identity mapping required")
    for fields in ident_lines:
        if fields == IDENT_FIELDS:
            continue
        if any(value in fields for value in (MAP_NAME, RUNTIME_USER, RUNTIME_ROLE, MIGRATOR_ROLE)):
            raise GateFailure("unexpected commercial pg_ident mapping")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--control-repository", type=Path, required=True)
    parser.add_argument("--phase", choices=("design", "installed"), default="design")
    parser.add_argument("--pg-hba", type=Path)
    parser.add_argument("--pg-ident", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        contract = read_json(arguments.contract, "contract")
        validate_contract(contract)
        validate_artifacts(contract, arguments.control_repository)
        if arguments.phase == "installed":
            if arguments.pg_hba is None or arguments.pg_ident is None:
                raise GateFailure("installed phase requires pg_hba and pg_ident")
            validate_installed_postgres(arguments.pg_hba, arguments.pg_ident)
            print("M4_21_POSTGRES_PEER_AUTH_OK")
        else:
            if arguments.pg_hba is not None or arguments.pg_ident is not None:
                raise GateFailure("design phase forbids installed configuration arguments")
            print("M4_21_HOST_ACCESS_DESIGN_OK")
        return 0
    except (GateFailure, OSError) as error:
        print("M4_21_HOST_ACCESS_BLOCKED " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
