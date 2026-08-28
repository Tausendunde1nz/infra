#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "manifests" / "tu1nz-agentmode-maintenance.m4-29-2.json"
EXPECTED_VERSION = "tu1nz-m4.29.2-agentmode-maintenance-v1"
EXPECTED_RUNTIME_ROOT = "/var/lib/tausendunde1nz/agentmode"
EXPECTED_CONTROL_ROOT = "/opt/tu1nz_repos/control"


class ContractError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ContractError("contract must be an object")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def validate(contract: dict[str, Any], root: Path = ROOT) -> None:
    require(contract.get("contract_version") == EXPECTED_VERSION, "wrong contract version")
    require(contract.get("decision") == "GO_MAINTENANCE_WINDOW_ONLY", "wrong decision")
    require(contract.get("maintenance_authorized") is True, "maintenance not authorized")

    control = contract.get("canonical_control", {})
    require(control.get("path") == EXPECTED_CONTROL_ROOT, "wrong Control path")
    require(control.get("branch") == "control-main", "wrong Control branch")
    require(control.get("automatic_mutation_allowed") is False, "automatic Control mutation enabled")
    require(
        control.get("remote_probe") == "git-ls-remote-without-local-ref-update",
        "unsafe remote probe",
    )

    runtime = contract.get("runtime_state", {})
    require(runtime.get("root") == EXPECTED_RUNTIME_ROOT, "runtime state is not external")
    require(runtime.get("contains_secrets") is False, "runtime state permits secrets")

    recovery = contract.get("recovery", {})
    require(str(recovery.get("path", "")).startswith("/var/log/tausendunde1nz/health/recovery/"), "invalid recovery path")
    require(len(str(recovery.get("sha256", ""))) == 64, "missing recovery hash")

    artifacts = contract.get("artifacts")
    require(isinstance(artifacts, dict) and len(artifacts) >= 8, "artifact binding incomplete")
    for relative, expected in artifacts.items():
        path = root / relative
        require(path.is_file(), f"missing artifact: {relative}")
        require(sha256(path) == expected, f"artifact hash mismatch: {relative}")

    sync_source = (root / "scripts" / "tu1nz_sync_all.sh").read_text(encoding="utf-8")
    require("git-ls-remote" not in sync_source, "unexpected placeholder remote command")
    require("ls-remote --exit-code" in sync_source, "remote query missing")
    require('"$CONTROL_DIR" fetch' not in sync_source, "Control fetch present")
    require('"$CONTROL_DIR" reset' not in sync_source, "Control reset present")
    require('"$CONTROL_DIR" pull' not in sync_source, "Control pull present")
    require('"$CONTROL_DIR" merge' not in sync_source, "Control merge present")
    require('"$CONTROL_DIR" clean' not in sync_source, "Control clean present")

    for unit_name in (
        "tu1nz_agentmode.service",
        "tu1nz_integrity.service",
        "tu1nz_monitor.service",
    ):
        unit = (root / "systemd" / unit_name).read_text(encoding="ascii")
        require("ReadOnlyPaths=/opt/tu1nz_repos/control" in unit, f"Control not read-only in {unit_name}")
        require("tu1nz-adult-commercial-s0" not in unit, f"candidate referenced by {unit_name}")

    boundary = contract.get("adult_candidate_boundary", {})
    require(boundary.get("active_state") == "inactive", "candidate not inactive")
    require(boundary.get("sub_state") == "dead", "candidate not dead")
    require(boundary.get("unit_file_state") == "static", "candidate not static")
    require(boundary.get("n_restarts") == 0, "candidate restart evidence changed")
    require(boundary.get("never_started") is True, "candidate start evidence present")
    require(boundary.get("first_start_approved") is False, "first start approved")
    require(boundary.get("production_approved") is False, "production approved")

    installation = contract.get("installation", {})
    require(installation.get("status") in {"PENDING", "COMPLETE"}, "invalid install status")
    if installation.get("status") == "COMPLETE":
        require(isinstance(installation.get("commit"), str), "installed commit missing")
        require(isinstance(installation.get("ci_run"), str), "CI binding missing")
        require(isinstance(installation.get("installed_at"), str), "install timestamp missing")
        installed = installation.get("installed_hashes")
        require(isinstance(installed, dict) and len(installed) == 8, "installed hashes incomplete")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    arguments = parser.parse_args()
    try:
        validate(load_json(arguments.contract))
    except ContractError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "status": "M4_29_2_CONTRACT_VALID"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
