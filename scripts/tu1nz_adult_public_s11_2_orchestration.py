#!/usr/bin/env python3
"""R15.8 phase ledger and source-only deployment simulator.

The runtime controller owns side effects.  This module owns only the ordered,
root-private phase ledger and deterministic planning rules.  It deliberately
has no systemd, database, network, or retry capability.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CONTRACT_VERSION = "S11_2_R15_8_ORCHESTRATION_V1"
PHASES = (
    "PRECHECK",
    "BACKUP_COMPLETE",
    "HEALTH_CONTRACT_INSTALLED",
    "TECHNICAL_EVIDENCE_COMPLETE",
    "S11_INSTALLED_DISABLED",
    "SYNTHETIC_VALIDATION_GREEN",
    "FALLBACK_GREEN",
    "CANARY_REARMED",
    "EVIDENCE_EPOCH_SET",
    "CANARY_ACTIVE",
    "SYSTEMD_HANDOFF",
)
ALLOWED_TECHNICAL_PROVENANCE = {
    ("DIRECT", "INTERNAL_TEST", "DIRECT_BOT_RESPONSE", "INTERNAL_ACCEPTANCE"),
}


class ContractError(ValueError):
    """Fail-closed contract violation."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _read_object(path: Path) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ContractError("S11_2_PHASE_STATE_UNSAFE")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
        raise ContractError("S11_2_PHASE_STATE_UNSAFE")
    payload = json.loads(path.read_text(encoding="ascii"))
    if not isinstance(payload, dict):
        raise ContractError("S11_2_PHASE_STATE_INVALID")
    return payload


def _validate_state(payload: dict[str, Any]) -> None:
    if set(payload) != {
        "schema",
        "contract_version",
        "release_id",
        "run_id",
        "created_at",
        "updated_at",
        "completed",
    }:
        raise ContractError("S11_2_PHASE_STATE_INVALID")
    if payload["schema"] != "TU1NZ_S11_2_PHASE_STATE_V1":
        raise ContractError("S11_2_PHASE_STATE_SCHEMA_RED")
    if payload["contract_version"] != CONTRACT_VERSION:
        raise ContractError("S11_2_PHASE_CONTRACT_VERSION_RED")
    if not all(
        isinstance(payload[key], str) and 1 <= len(payload[key]) <= 128
        for key in ("release_id", "run_id", "created_at", "updated_at")
    ):
        raise ContractError("S11_2_PHASE_STATE_BINDING_RED")
    completed = payload["completed"]
    if not isinstance(completed, list) or len(completed) > len(PHASES):
        raise ContractError("S11_2_PHASE_SEQUENCE_RED")
    if any(not isinstance(record, dict) for record in completed):
        raise ContractError("S11_2_PHASE_RECORD_RED")
    expected = list(PHASES[: len(completed)])
    if [record.get("phase") for record in completed] != expected:
        raise ContractError("S11_2_PHASE_SEQUENCE_RED")
    if any(
        set(record) != {"phase", "completed_at"}
        or not isinstance(record["completed_at"], str)
        for record in completed
    ):
        raise ContractError("S11_2_PHASE_RECORD_RED")


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def initialize(path: Path, release_id: str, run_id: str) -> dict[str, Any]:
    if not path.is_absolute():
        raise ContractError("S11_2_PHASE_STATE_UNSAFE")
    if path.exists() or not release_id or not run_id:
        raise ContractError("S11_2_PHASE_STATE_ALREADY_EXISTS")
    timestamp = _now()
    payload = {
        "schema": "TU1NZ_S11_2_PHASE_STATE_V1",
        "contract_version": CONTRACT_VERSION,
        "release_id": release_id,
        "run_id": run_id,
        "created_at": timestamp,
        "updated_at": timestamp,
        "completed": [],
    }
    _validate_state(payload)
    _atomic_write(path, payload)
    return payload


def complete(path: Path, phase: str, release_id: str, run_id: str) -> dict[str, Any]:
    payload = _read_object(path)
    _validate_state(payload)
    if (payload["release_id"], payload["run_id"]) != (release_id, run_id):
        raise ContractError("S11_2_PHASE_STATE_BINDING_RED")
    position = len(payload["completed"])
    if phase in [record["phase"] for record in payload["completed"]]:
        raise ContractError("S11_2_PHASE_DUPLICATE_RED")
    if position >= len(PHASES) or PHASES[position] != phase:
        raise ContractError("S11_2_PHASE_ORDER_RED")
    timestamp = _now()
    payload["completed"].append({"phase": phase, "completed_at": timestamp})
    payload["updated_at"] = timestamp
    _validate_state(payload)
    _atomic_write(path, payload)
    return payload


def inspect(path: Path, release_id: str, run_id: str) -> dict[str, Any]:
    payload = _read_object(path)
    _validate_state(payload)
    if (payload["release_id"], payload["run_id"]) != (release_id, run_id):
        raise ContractError("S11_2_PHASE_STATE_BINDING_RED")
    completed = [record["phase"] for record in payload["completed"]]
    return {
        "ok": True,
        "contract_version": CONTRACT_VERSION,
        "release_id": release_id,
        "run_id": run_id,
        "completed": completed,
        "next_phase": PHASES[len(completed)] if len(completed) < len(PHASES) else None,
    }


def require_phase(path: Path, phase: str, release_id: str, run_id: str) -> dict[str, Any]:
    result = inspect(path, release_id, run_id)
    if phase not in result["completed"]:
        raise ContractError("S11_2_REQUIRED_PHASE_MISSING")
    return result


def technical_plan(profile: dict[str, Any]) -> dict[str, Any]:
    required = {
        "required_floor",
        "current_valid_samples",
        "state",
        "samples",
        "health",
    }
    if set(profile) != required:
        raise ContractError("S11_2_TECHNICAL_PROFILE_INVALID")
    floor = profile["required_floor"]
    current = profile["current_valid_samples"]
    if type(floor) is not int or type(current) is not int or floor < 1 or current < 0:
        raise ContractError("S11_2_TECHNICAL_COUNT_INVALID")
    if profile["health"] != "GREEN":
        raise ContractError("S11_2_PRE_CANARY_HEALTH_RED")
    samples = profile["samples"]
    if not isinstance(samples, list) or len(samples) != current:
        raise ContractError("S11_2_TECHNICAL_SAMPLE_SET_INVALID")
    for sample in samples:
        if not isinstance(sample, dict):
            raise ContractError("S11_2_TECHNICAL_PROVENANCE_RED")
        provenance = tuple(
            sample.get(key)
            for key in ("source", "evidence_class", "sample_type", "interaction_path")
        )
        if provenance not in ALLOWED_TECHNICAL_PROVENANCE:
            raise ContractError("S11_2_TECHNICAL_PROVENANCE_RED")
    state = profile["state"]
    if state not in {"GREEN", "RED", "INSUFFICIENT_EVIDENCE"}:
        raise ContractError("S11_2_TECHNICAL_STATE_INVALID")
    if current >= floor and state == "RED":
        raise ContractError("S11_2_TECHNICAL_SLO_RED")
    if current >= floor and state != "GREEN":
        raise ContractError("S11_2_TECHNICAL_PROFILE_INCONSISTENT")
    if current < floor and state != "INSUFFICIENT_EVIDENCE":
        raise ContractError("S11_2_TECHNICAL_PROFILE_INCONSISTENT")
    return {
        "ok": True,
        "required_floor": floor,
        "current_valid_samples": current,
        "missing_samples": max(0, floor - current),
        "hard_cap": max(0, floor - current),
        "state": state,
        "provenance": "INTERNAL_TEST/DIRECT_BOT_RESPONSE/INTERNAL_ACCEPTANCE",
    }


def simulate(case: str, completed_through: str | None = None) -> dict[str, Any]:
    fixtures = {
        "empty-0-of-5": (0, "INSUFFICIENT_EVIDENCE", "GREEN", "valid"),
        "happy-4-of-5": (4, "INSUFFICIENT_EVIDENCE", "GREEN", "valid"),
        "zero-missing-5-of-5": (5, "GREEN", "GREEN", "valid"),
        "two-missing-3-of-5": (3, "INSUFFICIENT_EVIDENCE", "GREEN", "valid"),
        "bad-provenance": (4, "INSUFFICIENT_EVIDENCE", "GREEN", "unknown"),
        "slo-red": (5, "RED", "GREEN", "valid"),
        "health-red": (4, "INSUFFICIENT_EVIDENCE", "RED", "valid"),
    }
    if case == "resume":
        if completed_through not in PHASES:
            raise ContractError("S11_2_RESUME_PHASE_INVALID")
        count = PHASES.index(completed_through) + 1
        return {
            "ok": True,
            "case": case,
            "completed": list(PHASES[:count]),
            "next_phase": PHASES[count] if count < len(PHASES) else None,
            "duplicate_side_effects": 0,
            "automatic_retry": False,
        }
    if case in {"rollback-before-canary", "rollback-after-canary"}:
        return {
            "ok": True,
            "case": case,
            "restore_bytes": True,
            "restore_modes": True,
            "restore_units": True,
            "restore_runtime_manifests": True,
            "source_permission_changes": False,
            "canonical_fallback": case == "rollback-after-canary",
        }
    if case in {
        "failure-before-mutation",
        "pre-canary-health-red-after-mutation",
        "nounset-after-mutation",
        "rollback-idempotent",
    }:
        after_mutation = case != "failure-before-mutation"
        return {
            "ok": True,
            "case": case,
            "stopped": True,
            "mutation_started": after_mutation,
            "technical_probes": 0,
            "canary_starts": 0,
            "rollback_requests": 2 if case == "rollback-idempotent" else int(after_mutation),
            "restore_executions": int(after_mutation),
            "rollback_completed": after_mutation,
            "automatic_retry": False,
        }
    if case not in fixtures:
        raise ContractError("S11_2_SIMULATION_CASE_INVALID")
    current, initial_state, health, provenance_mode = fixtures[case]
    samples = [
        {
            "source": "DIRECT",
            "evidence_class": "INTERNAL_TEST",
            "sample_type": "DIRECT_BOT_RESPONSE",
            "interaction_path": "INTERNAL_ACCEPTANCE",
        }
        for _ in range(current)
    ]
    if provenance_mode == "unknown":
        samples.append(
            {
                "source": "DIRECT",
                "evidence_class": "UNKNOWN",
                "sample_type": "DIRECT_BOT_RESPONSE",
                "interaction_path": "INTERNAL_ACCEPTANCE",
            }
        )
        current += 1
    profile = {
        "required_floor": 5,
        "current_valid_samples": current,
        "state": initial_state,
        "samples": samples,
        "health": health,
    }
    try:
        plan = technical_plan(profile)
    except ContractError as error:
        return {
            "ok": True,
            "case": case,
            "stopped": True,
            "safe_code": str(error),
            "technical_probes": 0,
            "canary_starts": 0,
        }
    probes = plan["missing_samples"]
    return {
        "ok": True,
        "case": case,
        "stopped": False,
        "phases": list(PHASES),
        "technical_probes": probes,
        "technical_probe_hard_cap": probes,
        "canary_starts": 1,
        "automatic_retry": False,
        "technical_complete_before_canary": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "complete", "inspect", "require"):
        command = subparsers.add_parser(name)
        command.add_argument("--state", required=True, type=Path)
        command.add_argument("--release-id", required=True)
        command.add_argument("--run-id", required=True)
        if name in {"complete", "require"}:
            command.add_argument("--phase", required=True, choices=PHASES)
    plan = subparsers.add_parser("technical-plan")
    plan.add_argument("--input", required=True, type=Path)
    simulator = subparsers.add_parser("simulate")
    simulator.add_argument("--case", required=True)
    simulator.add_argument("--completed-through", choices=PHASES)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "init":
            result = initialize(arguments.state, arguments.release_id, arguments.run_id)
        elif arguments.command == "complete":
            result = complete(
                arguments.state,
                arguments.phase,
                arguments.release_id,
                arguments.run_id,
            )
        elif arguments.command == "inspect":
            result = inspect(arguments.state, arguments.release_id, arguments.run_id)
        elif arguments.command == "require":
            result = require_phase(
                arguments.state,
                arguments.phase,
                arguments.release_id,
                arguments.run_id,
            )
        elif arguments.command == "technical-plan":
            result = technical_plan(_read_object(arguments.input))
        else:
            result = simulate(arguments.case, arguments.completed_through)
    except (ContractError, json.JSONDecodeError, OSError) as error:
        print(json.dumps({"ok": False, "safe_code": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
