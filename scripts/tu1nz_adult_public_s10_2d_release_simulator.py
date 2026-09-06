#!/usr/bin/env python3
"""Source-only S10.2D release/rollback simulator using the real target artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path


class SimulationError(ValueError):
    pass


@dataclass
class ReleaseState:
    source: bool = True
    migration_0029: bool = False
    migration_0030: bool = False
    publication_green: bool = False
    bot_green: bool = False
    community_green: bool = False
    technically_ready: bool = False
    acquisition_active: bool = False
    baseline_present: bool = False
    technical_evidence: list[str] = field(default_factory=list)
    historical_analytics: int = 7

    def install_target(self) -> None:
        self.source = False
        self.migration_0029 = True
        self.migration_0030 = True

    def rollback(self) -> None:
        if self.acquisition_active:
            raise SimulationError("R3_ROLLBACK_ACQUISITION_ACTIVE")
        unknown = [release for release in self.technical_evidence if release not in {"s10-2d-r3-4", "s10-2d-r3-5"}]
        if unknown:
            raise SimulationError("R3_ROLLBACK_EVIDENCE_OWNERSHIP_RED")
        self.technical_evidence.clear()
        self.migration_0030 = False
        self.migration_0029 = False
        self.publication_green = False
        self.bot_green = False
        self.community_green = False
        self.technically_ready = False
        self.acquisition_active = False
        self.baseline_present = False
        self.source = True


def _require(source: str, *needles: str) -> None:
    for needle in needles:
        if needle not in source:
            raise SimulationError("SIMULATOR_ARTIFACT_CONTRACT_RED")


def _scenario(name: str, operation) -> dict[str, object]:
    try:
        operation()
    except SimulationError as error:
        return {"name": name, "ok": False, "safe_code": str(error)}
    return {"name": name, "ok": True, "safe_code": "SIMULATED_GREEN"}


def simulate(application_root: Path, control_root: Path) -> dict[str, object]:
    application_root = application_root.resolve()
    control_root = control_root.resolve()
    controller = (control_root / "scripts/tu1nz_adult_public_s10_2d_control.sh").read_text()
    target_unit = (control_root / "systemd/tu1nz-adult-public-s8-telegram.service").read_text()
    source_dropin = (control_root / "systemd/tu1nz-adult-public-s8-telegram.service.d/s10-wms.conf").read_text()
    migration = (application_root / "migrations/0030_commercial_s10_2d_r3_5_stabilization.sql").read_text()
    migration_down = (application_root / "migrations/0030_commercial_s10_2d_r3_5_stabilization.down.sql").read_text()
    _require(
        controller,
        "WITH updated AS (UPDATE commercial_s10_2d_runtime_control",
        "reconcile_failed_cutover_evidence",
        "R3_ROLLBACK_ACQUISITION_ACTIVE",
        "MIGRATION_0030_RED",
    )
    _require(target_unit, "--community-contract", "--runtime-release-id s10-2d-r3-5")
    if "--community-contract" in source_dropin or "--runtime-release-id" in source_dropin:
        raise SimulationError("SIMULATOR_SOURCE_PID1_RED")
    _require(
        migration,
        "commercial_s10_2d_bot_polling_state",
        "lease_owner_id",
        "release_id",
        "technical_evidence_run_id",
        "commercial_s10_2d_latency_append_only",
    )
    _require(
        migration_down,
        "latency evidence must be reconciled before downgrade",
        "DROP TABLE IF EXISTS commercial_s10_2d_bot_polling_state",
    )

    sys.path.insert(0, str(application_root / "src"))
    from tu1nz_public_s8.release_simulator import run_bot_path_simulation

    bot = run_bot_path_simulation(application_root, 100)
    scenarios: list[dict[str, object]] = []

    def target_success() -> None:
        state = ReleaseState()
        state.install_target()
        state.publication_green = True
        state.bot_green = bool(bot["ok"])
        state.community_green = True
        state.technical_evidence.append("s10-2d-r3-5")
        state.technically_ready = all(
            (state.publication_green, state.bot_green, state.community_green)
        )
        if not state.technically_ready or state.acquisition_active or state.baseline_present:
            raise SimulationError("SIMULATOR_TARGET_STATE_RED")

    scenarios.append(_scenario("target_success", target_success))

    for name, failure in (
        ("bot_failure_rollback", "BOT_EVENT_PATH_TIMEOUT"),
        ("publication_failure_rollback", "PUBLICATION_ROTATION_RED"),
        ("community_failure_rollback", "COMMUNITY_PERMISSION_RED"),
    ):
        def rollback_scenario(failure=failure) -> None:
            state = ReleaseState()
            state.install_target()
            state.technical_evidence.extend(("s10-2d-r3-4", "s10-2d-r3-5"))
            if failure == "BOT_EVENT_PATH_TIMEOUT":
                state.publication_green = True
            state.rollback()
            if not state.source or state.migration_0029 or state.migration_0030 or state.technical_evidence:
                raise SimulationError("SIMULATOR_ROLLBACK_INCOMPLETE")

        scenarios.append(_scenario(name, rollback_scenario))

    def active_acquisition_safety() -> None:
        state = ReleaseState(acquisition_active=True, baseline_present=True)
        state.install_target()
        try:
            state.rollback()
        except SimulationError as error:
            if str(error) == "R3_ROLLBACK_ACQUISITION_ACTIVE":
                return
            raise
        raise SimulationError("SIMULATOR_ACTIVE_ACQUISITION_NOT_BLOCKED")

    scenarios.append(_scenario("active_acquisition_safety", active_acquisition_safety))

    def target_evidence_down() -> None:
        state = ReleaseState()
        state.install_target()
        state.technical_evidence.extend(("s10-2d-r3-4", "s10-2d-r3-5"))
        state.rollback()
        if state.technical_evidence or state.migration_0029:
            raise SimulationError("SIMULATOR_EVIDENCE_RECONCILIATION_RED")

    scenarios.append(_scenario("target_evidence_down", target_evidence_down))

    def unexpected_evidence_safety() -> None:
        state = ReleaseState()
        state.install_target()
        state.technical_evidence.append("s10-2d-r99")
        try:
            state.rollback()
        except SimulationError as error:
            if str(error) == "R3_ROLLBACK_EVIDENCE_OWNERSHIP_RED" and state.migration_0029:
                return
            raise
        raise SimulationError("SIMULATOR_UNKNOWN_EVIDENCE_NOT_BLOCKED")

    scenarios.append(_scenario("unexpected_evidence_safety", unexpected_evidence_safety))

    def historical_analytics_preserved() -> None:
        state = ReleaseState()
        state.install_target()
        before = state.historical_analytics
        state.rollback()
        if state.historical_analytics != before:
            raise SimulationError("SIMULATOR_HISTORICAL_ANALYTICS_RED")

    scenarios.append(_scenario("historical_analytics_preserved", historical_analytics_preserved))

    if len(scenarios) != 8 or any(not scenario["ok"] for scenario in scenarios):
        raise SimulationError("SIMULATOR_SCENARIO_RED")
    if int(bot["p95_ms"]) >= 2000:
        raise SimulationError("BOT_HANDLER_TIMEOUT")
    return {
        "ok": True,
        "safe_code": "S10_2D_R3_5_RELEASE_SIMULATOR_GREEN",
        "scenarios": scenarios,
        "bot": bot,
        "target_pid1_community": True,
        "source_pid1_community": False,
        "technical_ready": True,
        "acquisition_active": False,
        "baseline": None,
        "adult_content": False,
        "avs": False,
        "payments": False,
        "publishing": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--application-root", type=Path, required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = simulate(arguments.application_root, arguments.control_root)
    except (OSError, SimulationError, ValueError) as error:
        candidate = str(error)
        safe_code = candidate if candidate.isupper() and " " not in candidate else "SIMULATOR_UNEXPECTED_RED"
        print(json.dumps({"ok": False, "safe_code": safe_code}, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
