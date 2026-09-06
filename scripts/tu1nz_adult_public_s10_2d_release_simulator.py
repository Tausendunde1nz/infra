#!/usr/bin/env python3
"""Source-only S10.2D release simulator using the production health gate."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType, SimpleNamespace


class SimulationError(ValueError):
    pass


@dataclass
class ReleaseState:
    source: bool = True
    migration_0029: bool = False
    migration_0030: bool = False
    health_green: bool = False
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
        self.health_green = False
        self.publication_green = False
        self.bot_green = False
        self.community_green = False
        self.technically_ready = False
        self.acquisition_active = False
        self.baseline_present = False
        self.source = True


def _load_module(path: Path, name: str) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise SimulationError("SIMULATOR_ARTIFACT_CONTRACT_RED")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def _require(source: str, *needles: str) -> None:
    for needle in needles:
        if needle not in source:
            raise SimulationError("SIMULATOR_ARTIFACT_CONTRACT_RED")


def _option(command: list[str], name: str) -> str | None:
    if name not in command:
        return None
    position = command.index(name)
    if position + 1 >= len(command):
        raise SimulationError("SIMULATOR_SYSTEMD_EXECSTART_RED")
    return command[position + 1]


def _effective_execstart(control_root: Path, unit: str) -> tuple[list[str], str]:
    paths = [control_root / "systemd" / unit]
    if unit == "tu1nz-adult-public-s9-health.service":
        paths.append(control_root / "systemd" / f"{unit}.d" / "s10-wms.conf")
    exec_start = ""
    combined: list[str] = []
    for path in paths:
        source = path.read_text(encoding="utf-8")
        combined.append(source)
        in_service = False
        for raw_line in source.splitlines():
            line = raw_line.strip()
            if line.startswith("[") and line.endswith("]"):
                in_service = line == "[Service]"
            elif in_service and line.startswith("ExecStart="):
                exec_start = line.removeprefix("ExecStart=")
    if not exec_start:
        raise SimulationError("SIMULATOR_SYSTEMD_EXECSTART_RED")
    return shlex.split(exec_start), "\n".join(combined)


class SystemdLikeHealthClient:
    """Execute the release-bound health contract behind effective unit files."""

    def __init__(self, control_root: Path, scenario: str = "success") -> None:
        self.control_root = control_root
        self.scenario = scenario
        self.started: list[str] = []
        self.commands: dict[str, list[str]] = {}
        self.states: dict[str, tuple[str, int]] = {}
        self.health = _load_module(
            control_root / "scripts/tu1nz_adult_public_s10_1_health.py",
            f"tu1nz_s10_health_{id(self)}",
        )
        target_command, _ = _effective_execstart(
            control_root, "tu1nz-adult-public-s8-telegram.service"
        )
        self.release_id = _option(target_command, "--runtime-release-id")
        if not self.release_id:
            raise SimulationError("SIMULATOR_TARGET_RELEASE_ID_RED")

    def reset_failed(self, unit: str) -> None:
        self.states[unit] = ("success", 0)

    def _validate_unit(self, unit: str, command: list[str], source: str) -> None:
        _require(
            source,
            "Type=oneshot",
            "User=chatops",
            "Group=chatops",
            "WorkingDirectory=/opt/tu1nz_repos/adult-publishing-core",
            "LoadCredential=",
        )
        if unit == "tu1nz-adult-public-s8-health.service":
            _require(" ".join(command), "tu1nz_adult_public_s8_health.py", "--mode runtime")
        else:
            _require(" ".join(command), "tu1nz_adult_public_s10_1_health.py")
        _require(" ".join(command), "--community-contract", "--community-copy")

    def _community_status(self, command: list[str]) -> int:
        release_id = (
            None
            if self.scenario == "r4_missing_health_release_binding"
            else _option(command, "--runtime-release-id")
        )
        community_contract = _option(command, "--community-contract")
        community_copy = _option(command, "--community-copy")
        if self.scenario == "community_contract_missing":
            community_contract = None
            community_copy = None
        arguments = SimpleNamespace(
            local_only=False,
            pre_growth=False,
            s8_contract=Path(_option(command, "--s8-contract") or "/invalid"),
            s8_copy=Path(_option(command, "--s8-copy") or "/invalid"),
            telegram_token=Path(_option(command, "--telegram-token") or "/invalid"),
            database_dsn=Path(_option(command, "--database-dsn") or "/invalid"),
            community_contract=Path(community_contract) if community_contract else None,
            community_copy=Path(community_copy) if community_copy else None,
            runtime_release_id=release_id,
        )

        def synthetic_runtime(child_command: list[str], timeout: int = 30):
            del timeout
            child_release = _option(child_command, "--runtime-release-id")
            if child_release != self.release_id:
                payload = {"ok": False, "safe_code": "BOT_RUNTIME_CONTRACT_MISMATCH"}
                return subprocess.CompletedProcess(child_command, 2, json.dumps(payload), "")
            provider_ok = self.scenario != "community_provider_failure"
            payload = {
                "ok": provider_ok,
                "state": "GREEN" if provider_ok else "RED",
                "community": {
                    "provider": {"ok": provider_ok, "rules_pinned": True},
                    "latency_24h": {
                        "samples": 100,
                        "bot_response_p50_ms": 50,
                        "bot_response_p95_ms": 95,
                        "bot_response_p99_ms": 99,
                    },
                    "pending_moderation": 0,
                    "stuck_restrictions": 0,
                    "latency_degraded": False,
                },
            }
            return subprocess.CompletedProcess(child_command, 0, json.dumps(payload), "")

        original_run = self.health._run
        self.health._run = synthetic_runtime
        try:
            self.health._community(arguments)
        except ValueError as error:
            return self.health.health_exit_status(str(error))
        finally:
            self.health._run = original_run
        return 0

    def start(self, unit: str) -> int:
        command, source = _effective_execstart(self.control_root, unit)
        self._validate_unit(unit, command, source)
        self.started.append(unit)
        self.commands[unit] = command
        status = 0
        if unit == "tu1nz-adult-public-s8-health.service":
            release_id = _option(command, "--runtime-release-id")
            if self.scenario in {"target_process_never_starts", "source_answers_target_absent"}:
                status = 2
            elif self.scenario == "wrong_release_identity" or release_id != self.release_id:
                status = 2
        elif unit == "tu1nz-adult-public-s9-health.service":
            if self.scenario == "public_http_unavailable":
                status = 32
            elif self.scenario == "database_unavailable":
                status = 33
            else:
                status = self._community_status(command)
        else:
            status = self._community_status(command)
        self.states[unit] = ("success" if status == 0 else "exit-code", status)
        return 0 if status == 0 else 1

    def show(self, unit: str, property_name: str) -> str:
        result, status = self.states.get(unit, ("exit-code", 2))
        return result if property_name == "Result" else str(status)


def _scenario(name: str, operation) -> dict[str, object]:
    try:
        operation()
    except SimulationError as error:
        return {"name": name, "ok": False, "safe_code": str(error)}
    return {"name": name, "ok": True, "safe_code": "SIMULATED_GREEN"}


def _health_case(
    health_gate: ModuleType,
    control_root: Path,
    name: str,
    scenario: str,
    expected_red: str | None = None,
) -> dict[str, object]:
    client = SystemdLikeHealthClient(control_root, scenario)
    try:
        report = health_gate.run_health_gates(client)
    except health_gate.HealthGateFailure as error:
        observed = error.report["safe_code"]
        if observed != expected_red:
            raise SimulationError("SIMULATOR_HEALTH_REASON_RED") from None
        return {
            "name": name,
            "ok": True,
            "expected_red": True,
            "safe_code": observed,
            "fingerprint": error.report["fingerprint"],
        }
    if expected_red is not None:
        raise SimulationError("SIMULATOR_HEALTH_FALSE_GREEN")
    return {
        "name": name,
        "ok": True,
        "expected_red": False,
        "safe_code": report["safe_code"],
        "units": client.started,
    }


def simulate(application_root: Path, control_root: Path) -> dict[str, object]:
    application_root = application_root.resolve()
    control_root = control_root.resolve()
    controller = (control_root / "scripts/tu1nz_adult_public_s10_2d_control.sh").read_text()
    target_unit = (control_root / "systemd/tu1nz-adult-public-s8-telegram.service").read_text()
    source_dropin = (control_root / "systemd/tu1nz-adult-public-s8-telegram.service.d/s10-wms.conf").read_text()
    runtime = (application_root / "src/tu1nz_public_s8/runtime.py").read_text()
    migration = (application_root / "migrations/0030_commercial_s10_2d_r3_5_stabilization.sql").read_text()
    migration_down = (application_root / "migrations/0030_commercial_s10_2d_r3_5_stabilization.down.sql").read_text()
    _require(
        controller,
        "WITH updated AS (UPDATE commercial_s10_2d_runtime_control",
        "reconcile_failed_cutover_evidence",
        "R3_ROLLBACK_ACQUISITION_ACTIVE",
        "MIGRATION_0030_RED",
        'report="$("$HEALTH_GATE_SCRIPT")"',
    )
    _require(target_unit, "--community-contract", "--runtime-release-id s10-2d-r3-5")
    _require(
        runtime,
        "arguments.community_contract is not None and arguments.runtime_release_id is None",
        "BOT_RUNTIME_CONTRACT_MISMATCH",
    )
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

    health_gate = _load_module(
        control_root / "scripts/tu1nz_adult_public_s10_2d_health_gate.py",
        "tu1nz_s10_2d_health_gate_simulator",
    )
    health_cases = [
        _health_case(health_gate, control_root, "target_starts_normally", "success"),
        _health_case(health_gate, control_root, "target_process_never_starts", "target_process_never_starts", "HEALTH_GATE_S8_RUNTIME_PROCESS_RED"),
        _health_case(health_gate, control_root, "target_wrong_release", "wrong_release_identity", "HEALTH_GATE_S8_RUNTIME_PROCESS_RED"),
        _health_case(health_gate, control_root, "target_http_unavailable", "public_http_unavailable", "HEALTH_GATE_S9_PUBLIC_HEALTH_PUBLIC_HTTP_RED"),
        _health_case(health_gate, control_root, "database_unavailable", "database_unavailable", "HEALTH_GATE_S9_PUBLIC_HEALTH_GROWTH_DATABASE_RED"),
        _health_case(health_gate, control_root, "bounded_startup_transition", "bounded_startup"),
        _health_case(health_gate, control_root, "source_answers_target_absent", "source_answers_target_absent", "HEALTH_GATE_S8_RUNTIME_PROCESS_RED"),
        _health_case(health_gate, control_root, "community_contract_missing", "community_contract_missing", "HEALTH_GATE_S9_PUBLIC_HEALTH_COMMUNITY_ARGUMENTS_RED"),
        _health_case(health_gate, control_root, "r4_missing_health_release_binding", "r4_missing_health_release_binding", "HEALTH_GATE_S9_PUBLIC_HEALTH_COMMUNITY_RUNTIME_CONTRACT_RED"),
    ]
    if any(not case["ok"] for case in health_cases):
        raise SimulationError("SIMULATOR_HEALTH_SCENARIO_RED")

    sys.path.insert(0, str(application_root / "src"))
    from tu1nz_public_s8.release_simulator import run_bot_path_simulation

    bot = run_bot_path_simulation(application_root, 100)
    scenarios: list[dict[str, object]] = []

    def require_health(state: ReleaseState, scenario: str = "success") -> None:
        report = _health_case(health_gate, control_root, "release_health_gate", scenario)
        state.health_green = report["safe_code"] == "S10_2D_HEALTH_GATES_GREEN"
        if not state.health_green:
            raise SimulationError("SIMULATOR_HEALTH_GATE_RED")

    def target_success() -> None:
        state = ReleaseState()
        state.install_target()
        require_health(state)
        state.publication_green = True
        state.bot_green = bool(bot["ok"])
        state.community_green = True
        state.technical_evidence.append("s10-2d-r3-5")
        state.technically_ready = all((state.health_green, state.publication_green, state.bot_green, state.community_green))
        if not state.technically_ready or state.acquisition_active or state.baseline_present:
            raise SimulationError("SIMULATOR_TARGET_STATE_RED")

    scenarios.append(_scenario("target_success", target_success))

    def health_failure_rollback() -> None:
        state = ReleaseState()
        state.install_target()
        _health_case(health_gate, control_root, "release_health_gate", "r4_missing_health_release_binding", "HEALTH_GATE_S9_PUBLIC_HEALTH_COMMUNITY_RUNTIME_CONTRACT_RED")
        state.technical_evidence.append("s10-2d-r3-5")
        state.rollback()
        if not state.source or state.migration_0029 or state.health_green:
            raise SimulationError("SIMULATOR_ROLLBACK_INCOMPLETE")

    scenarios.append(_scenario("health_start_failure_rollback", health_failure_rollback))

    for name, failure in (
        ("bot_failure_rollback", "BOT_EVENT_PATH_TIMEOUT"),
        ("publication_failure_rollback", "PUBLICATION_ROTATION_RED"),
        ("community_failure_rollback", "COMMUNITY_PERMISSION_RED"),
    ):
        def rollback_scenario(failure=failure) -> None:
            state = ReleaseState()
            state.install_target()
            if failure == "COMMUNITY_PERMISSION_RED":
                _health_case(
                    health_gate,
                    control_root,
                    "release_health_gate",
                    "community_provider_failure",
                    "HEALTH_GATE_S9_PUBLIC_HEALTH_COMMUNITY_PROVIDER_RED",
                )
            else:
                require_health(state)
            state.technical_evidence.extend(("s10-2d-r3-4", "s10-2d-r3-5"))
            if failure == "BOT_EVENT_PATH_TIMEOUT":
                state.publication_green = True
            state.rollback()
            if not state.source or state.migration_0029 or state.migration_0030 or state.technical_evidence:
                raise SimulationError("SIMULATOR_ROLLBACK_INCOMPLETE")

        scenarios.append(_scenario(name, rollback_scenario))

    def rollback_success() -> None:
        state = ReleaseState()
        state.install_target()
        require_health(state)
        state.technical_evidence.append("s10-2d-r3-5")
        state.rollback()
        if not state.source or state.technical_evidence or state.health_green:
            raise SimulationError("SIMULATOR_ROLLBACK_INCOMPLETE")

    scenarios.append(_scenario("rollback", rollback_success))

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

    def migration_evidence_edges() -> None:
        known = ReleaseState()
        known.install_target()
        known.technical_evidence.extend(("s10-2d-r3-4", "s10-2d-r3-5"))
        before = known.historical_analytics
        known.rollback()
        if known.technical_evidence or known.migration_0029 or known.historical_analytics != before:
            raise SimulationError("SIMULATOR_EVIDENCE_RECONCILIATION_RED")
        unknown = ReleaseState()
        unknown.install_target()
        unknown.technical_evidence.append("s10-2d-r99")
        try:
            unknown.rollback()
        except SimulationError as error:
            if str(error) == "R3_ROLLBACK_EVIDENCE_OWNERSHIP_RED" and unknown.migration_0029:
                return
            raise
        raise SimulationError("SIMULATOR_UNKNOWN_EVIDENCE_NOT_BLOCKED")

    scenarios.append(_scenario("migration_evidence_edge_cases", migration_evidence_edges))

    if len(scenarios) != 8 or any(not scenario["ok"] for scenario in scenarios):
        raise SimulationError("SIMULATOR_SCENARIO_RED")
    if int(bot["p95_ms"]) >= 2000:
        raise SimulationError("BOT_HANDLER_TIMEOUT")
    return {
        "ok": True,
        "safe_code": "S10_2D_R4_1_RELEASE_SIMULATOR_GREEN",
        "scenarios": scenarios,
        "health_cases": health_cases,
        "bot": bot,
        "production_health_gate_shared": True,
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
