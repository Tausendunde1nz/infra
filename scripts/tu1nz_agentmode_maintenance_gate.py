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
    require(installation.get("status") == "COMPLETE", "installation is not complete")
    commit = installation.get("commit")
    require(
        isinstance(commit, str)
        and len(commit) == 40
        and all(character in "0123456789abcdef" for character in commit),
        "installed commit missing or invalid",
    )
    ci_run = installation.get("ci_run")
    require(
        isinstance(ci_run, str)
        and ci_run.startswith("https://github.com/Tausendunde1nz/infra/actions/runs/"),
        "CI binding missing or invalid",
    )
    require(isinstance(installation.get("installed_at"), str), "install timestamp missing")
    installed = installation.get("installed_hashes")
    expected_installed = {
        "/usr/local/bin/tu1nz_sync_all.sh": artifacts["scripts/tu1nz_sync_all.sh"],
        "/usr/local/bin/tu1nz_agent_health.sh": artifacts["scripts/tu1nz_agent_health.sh"],
        "/usr/local/bin/tu1nz_require_sync.sh": artifacts["scripts/tu1nz_require_sync.sh"],
        "/usr/local/bin/tu1nz_integrity_consolidation.sh": artifacts[
            "scripts/tu1nz_integrity_consolidation.sh"
        ],
        "/usr/local/bin/tu1nz_monitor_wrap.sh": artifacts[
            "scripts/tu1nz_monitor_wrap.sh"
        ],
        "/etc/systemd/system/tu1nz_agentmode.service": artifacts[
            "systemd/tu1nz_agentmode.service"
        ],
        "/etc/systemd/system/tu1nz_integrity.service": artifacts[
            "systemd/tu1nz_integrity.service"
        ],
        "/etc/systemd/system/tu1nz_monitor.service": artifacts[
            "systemd/tu1nz_monitor.service"
        ],
    }
    require(installed == expected_installed, "installed hashes do not match bound artifacts")

    postinstall = contract.get("postinstall_validation", {})
    require(postinstall.get("status") == "PASS", "post-install validation did not pass")
    require(postinstall.get("duration_seconds", 0) >= 600, "observation window too short")
    require(postinstall.get("sample_count", 0) >= 3, "observation samples incomplete")
    require(
        postinstall.get("distinct_observations", 0) >= 3,
        "two complete follow-up cycles not observed",
    )
    timestamps = postinstall.get("observation_timestamps")
    require(
        isinstance(timestamps, list)
        and len(timestamps) == postinstall.get("distinct_observations"),
        "observation timestamps incomplete",
    )
    for flag in (
        "control_unchanged",
        "candidate_unchanged",
        "transition_only_notifications",
        "monitor_no_red_status",
    ):
        require(postinstall.get(flag) is True, f"post-install flag is not true: {flag}")
    require(postinstall.get("service_restarts") == 0, "service restart detected")
    require(postinstall.get("agentmode_state") == "active/running", "Agentmode not healthy")
    require(postinstall.get("integrity_state") == "active/exited", "Integrity not healthy")
    require(
        postinstall.get("monitor_state") == "inactive/dead/success",
        "Monitor not healthy",
    )
    preflight = contract.get("preflight", {})
    for key in (
        "control_head",
        "control_tree",
        "control_refs_sha256",
        "control_status_sha256",
        "control_tracked_bytes_sha256",
        "control_full_files_sha256",
        "control_symlinks_sha256",
        "control_file_count",
    ):
        require(
            postinstall.get(key) == preflight.get(key),
            f"post-install Control evidence drift: {key}",
        )


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
