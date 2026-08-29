#!/usr/bin/env python3
"""Build a private, evidence-bound final first-start authorization contract."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import tu1nz_adult_commercial_final_first_start_gate as gate


def sha256(path: Path) -> str:
    return gate.sha256(path)


def build_contract(
    evidence_path: Path,
    *,
    approve_first_start: bool = False,
    accept_no_swap_risk: bool = False,
    approved_at: str | None = None,
) -> dict[str, object]:
    evidence_path = evidence_path.resolve(strict=True)
    evidence = gate.read_json(evidence_path)
    gate.validate_evidence(evidence)
    approved = approve_first_start and accept_no_swap_risk
    if approve_first_start != accept_no_swap_risk:
        raise gate.GateFailure("first-start approval and no-swap acceptance must be atomic")
    if approved:
        if approved_at is None:
            raise gate.GateFailure("approved_at is required for an approved contract")
        gate.utc(approved_at, "approved_at")
    elif approved_at is not None:
        raise gate.GateFailure("closed contract cannot contain approved_at")
    approval = {
        "approved_at": approved_at if approved else None,
        "first_start_approved": approved,
        "no_swap_risk_accepted": approved,
        "operator_accepted": approved,
    }
    return {
        "active": approved,
        "approval": approval,
        "blockers": [] if approved else list(gate.CLOSED_BLOCKERS),
        "candidate": evidence["candidate"],
        "canonical_control": evidence["canonical_control"],
        "contract_version": "tu1nz-commercial-final-first-start-authorization-v1",
        "database": evidence["database"],
        "decision": (
            "GO_FOR_ONE_CONTROLLED_NETWORK_FREE_FIRST_START" if approved else "NO_GO"
        ),
        "environment": "STAGING-S0-COMMERCIAL-CANDIDATE",
        "evidence": {
            "fresh_prestart_path": str(evidence_path),
            "fresh_prestart_sha256": sha256(evidence_path),
            "observed_at": evidence["observed_at"],
            "preflight_to_approval_maximum_seconds": (
                gate.PREFLIGHT_APPROVAL_MAXIMUM_GAP_SECONDS
            ),
        },
        "first_start_window": {
            "approval_maximum_age_seconds": gate.APPROVAL_MAXIMUM_AGE_SECONDS,
            "health_maximum_age_seconds": 90,
            "maximum_runtime_seconds": 180,
            "must_end_stopped": True,
            "ready_timeout_seconds": 60,
            "single_controlled_start": True,
            "stop_timeout_seconds": 45,
        },
        "no_swap_assessment": {
            "mitigations": list(gate.MITIGATIONS),
            "observed_memory_available_kib": evidence["capacity"]["memory_available_kib"],
            "observed_swap_total_kib": evidence["capacity"]["swap_total_kib"],
            "oom_recovery": list(gate.OOM_RECOVERY),
            "operator_accepted": approved,
            "recommendation": "ACCEPTABLE_FOR_ONE_CONTROLLED_FIRST_START",
            "required_memory_available_kib": gate.MIN_MEMORY_KIB,
            "risk_factors": list(gate.RISK_FACTORS),
            "scope": "ONE_SYNTHETIC_NETWORK_FREE_FIRST_START_ONLY",
        },
        "product_boundary": evidence["product_boundary"],
        "recovery": {
            "abort_must_stop_unit": True,
            "controller_path": "scripts/tu1nz_adult_commercial_s0_first_start_final.py",
            "controller_sha256": sha256(gate.CONTROLLER),
            "forbid_second_start": True,
            "gate_path": "scripts/tu1nz_adult_commercial_final_first_start_gate.py",
            "gate_sha256": sha256(Path(gate.__file__).resolve()),
            "preserve_database_state_and_evidence": True,
        },
        "release": evidence["release"],
        "sprint": "FINAL_FIRST_START_READINESS",
    }


def write_private(path: Path, payload: dict[str, object]) -> None:
    material = (
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(material)
        handle.flush()
        os.fsync(handle.fileno())


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prestart-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--approve-first-start", action="store_true")
    parser.add_argument("--accept-no-swap-risk", action="store_true")
    parser.add_argument("--approved-at")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        payload = build_contract(
            arguments.prestart_evidence,
            approve_first_start=arguments.approve_first_start,
            accept_no_swap_risk=arguments.accept_no_swap_risk,
            approved_at=arguments.approved_at,
        )
        write_private(arguments.output, payload)
        gate.validate_contract(
            gate.read_json(arguments.output),
            require_approved=arguments.approve_first_start,
            now=(
                datetime.now(timezone.utc)
                if arguments.approve_first_start
                else None
            ),
        )
    except (gate.GateFailure, OSError, TypeError, ValueError) as error:
        print("FINAL_FIRST_START_CONTRACT_BLOCKED " + str(error))
        return 1
    print(
        "FINAL_FIRST_START_CONTRACT_CREATED path="
        + str(arguments.output)
        + " sha256="
        + sha256(arguments.output)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
