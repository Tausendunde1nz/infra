#!/usr/bin/env python3
"""Read-only M4.18 gate for the uninstalled commercial runtime candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


class GateFailure(RuntimeError):
    pass


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
CONTRACT_KEYS = {
    "active",
    "activation_decision",
    "application_merged_to_main",
    "application_pr_url",
    "application_repository_url",
    "application_sha",
    "artifact_sha256",
    "commercial_contract_version",
    "contract_version",
    "control_baseline_sha",
    "control_repository_url",
    "database_scope",
    "environment",
    "external_providers_enabled",
    "installed",
    "network_enabled",
    "paid_targets",
    "persistence_schema_version",
    "planned_identities",
    "planned_paths",
    "real_media_enabled",
    "real_payment_enabled",
    "required_activation_gates",
    "required_platforms",
    "runtime_version",
    "server_enabled",
    "server_observation",
    "synthetic_data_only",
    "synthetic_publishers_only",
    "telegram_intake_enabled",
    "uncompensated_targets",
}
REQUIRED_ARTIFACTS = {
    "config/commercial-application-composition.disabled.json",
    "config/commercial-runtime-candidate.disabled.json",
    "migrations/0014_m4_15_durable_commercial_persistence.down.sql",
    "migrations/0014_m4_15_durable_commercial_persistence.sql",
    "requirements-m2.lock",
    "src/tu1nz_application/commercial_composition.py",
    "src/tu1nz_sandbox/commercial_candidate.py",
    "src/tu1nz_sandbox/commercial_runtime.py",
    "tests/postgres/m4_17_commercial_runtime_candidate_acceptance.py",
    "tests/test_m4_17_commercial_runtime_candidate.py",
}
PLANNED_PATHS = {
    "application_release_root": "/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial/application",
    "configuration_root": "/etc/tu1nz/adult-publishing/staging-s0-commercial",
    "control_release_root": "/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial/control",
    "state_root": "/var/lib/tausendunde1nz/adult-publishing/staging-s0-commercial",
    "venv_release_root": "/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial/venv",
}
PLANNED_IDENTITIES = {
    "database": "tu1nz_adult_commercial_s0",
    "database_migrator": "tu1nz_adult_commercial_s0_migrator",
    "database_runtime": "tu1nz_adult_commercial_s0_runtime",
    "operating_system_group": "tu1nz-adult-commercial-s0",
    "operating_system_user": "tu1nz-adult-commercial-s0",
}


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


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise GateFailure("application Git validation failed")
    return result.stdout.strip()


def sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure("artifact must be a safe regular file: " + str(path))
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_contract(contract: dict[str, object]) -> None:
    if set(contract) != CONTRACT_KEYS:
        raise GateFailure("contract exact key set required")
    if (
        contract["contract_version"] != "tu1nz-commercial-control-m4.18-v1"
        or contract["activation_decision"] != "NO_GO"
        or contract["application_repository_url"]
        != "https://github.com/Tausendunde1nz/adult-publishing-core.git"
        or contract["control_repository_url"]
        != "https://github.com/Tausendunde1nz/infra.git"
        or contract["commercial_contract_version"]
        != "tu1nz-commercial-persistence-m4.15-v1"
        or contract["runtime_version"]
        != "tu1nz-commercial-runtime-candidate-m4.17-v1"
        or contract["persistence_schema_version"]
        != "0014_m4_15_durable_commercial_persistence"
        or contract["environment"] != "STAGING-S0-COMMERCIAL-CANDIDATE"
        or contract["database_scope"] != "LOCAL_ONLY"
        or contract["required_platforms"] != ["REDDIT", "TELEGRAM", "X"]
        or contract["paid_targets"] != ["REDDIT", "TELEGRAM"]
        or contract["uncompensated_targets"] != ["X"]
        or contract["planned_paths"] != PLANNED_PATHS
        or contract["planned_identities"] != PLANNED_IDENTITIES
    ):
        raise GateFailure("commercial readiness contract mismatch")
    for field in ("application_sha", "control_baseline_sha"):
        if not isinstance(contract[field], str) or SHA_RE.fullmatch(contract[field]) is None:
            raise GateFailure("invalid " + field)
    false_fields = {
        "active",
        "application_merged_to_main",
        "external_providers_enabled",
        "installed",
        "network_enabled",
        "real_media_enabled",
        "real_payment_enabled",
        "server_enabled",
        "telegram_intake_enabled",
    }
    if any(contract[field] is not False for field in false_fields):
        raise GateFailure("inactive fail-closed flags required")
    if (
        contract["synthetic_data_only"] is not True
        or contract["synthetic_publishers_only"] is not True
    ):
        raise GateFailure("synthetic-only boundary required")
    gates = contract["required_activation_gates"]
    if (
        not isinstance(gates, dict)
        or not gates
        or any(not isinstance(key, str) or not isinstance(value, bool) for key, value in gates.items())
        or all(gates.values())
    ):
        raise GateFailure("at least one activation blocker must remain")
    if gates.get("fresh_privileged_interference_check_complete") is not True:
        raise GateFailure("fresh privileged interference evidence required")
    observation = contract["server_observation"]
    observation_keys = {
        "active_s1_application_sha",
        "active_s1_control_sha",
        "canonical_application_sha",
        "control_sha",
        "control_sync_mutates_canonical_checkout",
        "exact_candidate_sha_in_backup",
        "fresh_backup_archive",
        "fresh_backup_bytes",
        "fresh_backup_remote_present",
        "fresh_backup_sha256",
        "hostname",
        "local_tailscale_cli_daemon_version_skew",
        "observed_at",
        "path_collision_detected",
        "planned_identities_absent",
        "planned_paths_absent",
        "postgres_listener",
        "postgres_version",
        "privileged_open_reference_detected",
        "restore_smoke_completed_at",
        "restore_smoke_passed",
        "ssh_identity",
        "tailscale_ip",
        "vpn_route",
    }
    if not isinstance(observation, dict) or set(observation) != observation_keys:
        raise GateFailure("exact server observation key set required")
    for field in (
        "active_s1_application_sha",
        "active_s1_control_sha",
        "canonical_application_sha",
        "control_sha",
    ):
        if not isinstance(observation[field], str) or SHA_RE.fullmatch(observation[field]) is None:
            raise GateFailure("server observation invalid " + field)
    if (
        observation["control_sha"] != contract["control_baseline_sha"]
        or observation["hostname"] != "ubuntu-8gb-nbg1-2"
        or observation["tailscale_ip"] != "100.121.130.51"
        or observation["ssh_identity"] != "root"
        or observation["vpn_route"] != "DERP_NUE"
        or observation["postgres_listener"] != "127.0.0.1:5432"
        or observation["postgres_version"] != "17.11"
        or observation["planned_paths_absent"] is not True
        or observation["planned_identities_absent"] is not True
        or observation["path_collision_detected"] is not False
        or observation["privileged_open_reference_detected"] is not False
        or observation["fresh_backup_remote_present"] is not True
        or observation["restore_smoke_passed"] is not True
        or observation["exact_candidate_sha_in_backup"] is not False
        or observation["control_sync_mutates_canonical_checkout"] is not True
        or observation["local_tailscale_cli_daemon_version_skew"] is not True
        or not isinstance(observation["fresh_backup_bytes"], int)
        or observation["fresh_backup_bytes"] <= 0
        or not isinstance(observation["fresh_backup_sha256"], str)
        or DIGEST_RE.fullmatch(observation["fresh_backup_sha256"]) is None
    ):
        raise GateFailure("server observation safety evidence mismatch")
    artifacts = contract["artifact_sha256"]
    if (
        not isinstance(artifacts, dict)
        or set(artifacts) != REQUIRED_ARTIFACTS
        or any(not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None for value in artifacts.values())
    ):
        raise GateFailure("exact reviewed artifact set required")


def validate_application(contract: dict[str, object], repository: Path) -> None:
    if not repository.is_dir() or not (repository / ".git").is_dir():
        raise GateFailure("application Git repository missing")
    if git(repository, "rev-parse", "HEAD") != contract["application_sha"]:
        raise GateFailure("application SHA mismatch")
    if git(repository, "status", "--porcelain=v1"):
        raise GateFailure("application worktree is dirty")
    git(repository, "fsck", "--full")
    if git(repository, "remote", "get-url", "origin") != contract["application_repository_url"]:
        raise GateFailure("application origin mismatch")
    artifacts = contract["artifact_sha256"]
    assert isinstance(artifacts, dict)
    root = repository.resolve(strict=True)
    for name, expected in artifacts.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise GateFailure("unsafe artifact path")
        path = repository.joinpath(*relative.parts)
        try:
            path.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as error:
            raise GateFailure("artifact escapes application repository") from error
        if sha256_file(path) != expected:
            raise GateFailure("artifact digest mismatch: " + name)
    candidate = read_json(
        repository / "config/commercial-runtime-candidate.disabled.json",
        "candidate configuration",
    )
    required_candidate = {
        "active": False,
        "commercial_composition_enabled": True,
        "commercial_contract_version": "tu1nz-commercial-persistence-m4.15-v1",
        "database_scope": "LOCAL_ONLY",
        "environment": "STAGING-S0-COMMERCIAL-CANDIDATE",
        "external_providers_enabled": False,
        "installed": False,
        "network_enabled": False,
        "persistence_schema_version": "0014_m4_15_durable_commercial_persistence",
        "real_media_enabled": False,
        "repository_entrypoint_available": True,
        "runtime_version": "tu1nz-commercial-runtime-candidate-m4.17-v1",
        "server_enabled": False,
        "synthetic_data_only": True,
        "synthetic_publishers_only": True,
    }
    if candidate != required_candidate:
        raise GateFailure("candidate configuration mismatch")
    pyproject = (repository / "pyproject.toml").read_text(encoding="utf-8")
    for entrypoint in (
        'tu1nz-commercial-runtime-candidate = "tu1nz_sandbox.commercial_candidate:runtime_entrypoint"',
        'tu1nz-commercial-candidate-health = "tu1nz_sandbox.commercial_candidate:health_entrypoint"',
    ):
        if entrypoint not in pyproject:
            raise GateFailure("candidate entrypoint missing")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--application-repository", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        contract = read_json(arguments.contract, "contract")
        validate_contract(contract)
        validate_application(contract, arguments.application_repository)
        print("M4_18_COMMERCIAL_READINESS_OK")
        return 0
    except (GateFailure, OSError, subprocess.SubprocessError) as error:
        print("M4_18_COMMERCIAL_READINESS_BLOCKED " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
