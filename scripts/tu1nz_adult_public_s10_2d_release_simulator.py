#!/usr/bin/env python3
"""Source-only S10.2D release simulator using the production health gate."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import selectors
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType, SimpleNamespace


class SimulationError(ValueError):
    pass


def _isolated_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


class RealWMSHealthRuntime:
    """Run the production WMS listener path on an isolated localhost port."""

    def __init__(
        self,
        application_root: Path,
        *,
        port: int | None = None,
        release_id: str | None = "s10-2d-r3-5",
        community: bool = True,
    ) -> None:
        self.application_root = application_root
        self.port = port or _isolated_port()
        self.release_id = release_id
        self.community = community
        self.process: subprocess.Popen[str] | None = None
        self._temporary = tempfile.TemporaryDirectory(prefix="tu1nz-s10-2d-r6-1-")

    def _contract_path(self) -> Path:
        source = self.application_root / "config/commercial-s10-1-wms-public.sfw.json"
        contract = json.loads(source.read_text(encoding="utf-8"))
        contract["bind_host"] = "127.0.0.1"
        contract["bind_port"] = self.port
        path = Path(self._temporary.name) / "wms-contract.json"
        path.write_text(json.dumps(contract, sort_keys=True), encoding="utf-8")
        return path

    def _command(self) -> list[str]:
        command = [
            sys.executable,
            "-m",
            "tu1nz_exposure_s10.runtime",
            "--contract",
            str(self._contract_path()),
            "--copy",
            str(self.application_root / "config/commercial-s10-1-wms-copy.v1.json"),
            "--bot-contract",
            str(self.application_root / "config/commercial-s8-public-telegram-early-access.sfw.json"),
        ]
        if self.community:
            command.extend(
                [
                    "--community-contract",
                    str(self.application_root / "config/commercial-s10-2d-community.sfw.json"),
                ]
            )
        if self.release_id is not None:
            command.extend(["--runtime-release-id", self.release_id])
        return command

    def start(self) -> dict[str, object]:
        environment = dict(os.environ)
        source_root = str(self.application_root / "src")
        environment["PYTHONPATH"] = source_root + os.pathsep + environment.get("PYTHONPATH", "")
        self.process = subprocess.Popen(
            self._command(),
            cwd=self.application_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 4
        ready = False
        selector = selectors.DefaultSelector()
        assert self.process.stdout is not None
        selector.register(self.process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            for key, _ in selector.select(timeout=0.05):
                line = key.fileobj.readline()
                try:
                    event = json.loads(line)
                except (TypeError, ValueError, json.JSONDecodeError):
                    event = {}
                if event.get("safe_reason"):
                    raise SimulationError(str(event["safe_reason"]))
                if event.get("event") == "S10_WMS_PUBLIC_READY":
                    ready = True
            if self.process.poll() is not None:
                stdout, _ = self.process.communicate(timeout=1)
                try:
                    safe_code = json.loads(stdout.splitlines()[-1])["safe_reason"]
                except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                    safe_code = "S10_WMS_HEALTH_TASK_FAILED"
                raise SimulationError(str(safe_code))
            try:
                if not ready:
                    continue
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/health", timeout=0.2
                ) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                if isinstance(payload, dict):
                    return payload
            except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError):
                time.sleep(0.05)
        raise SimulationError("S10_WMS_HEALTH_LISTENER_NOT_STARTED")

    def validate(self, payload: dict[str, object], expected_release_id: str) -> None:
        if payload.get("runtime_release_id") != expected_release_id:
            raise SimulationError("S10_WMS_HEALTH_RELEASE_ID_MISMATCH")
        if payload.get("runtime_contract") != "TARGET_COMMUNITY":
            raise SimulationError("S10_WMS_HEALTH_RUNTIME_CONTRACT_MISMATCH")
        if payload.get("bot_id") != 8861935205 or payload.get("community") is not True:
            raise SimulationError("S10_WMS_HEALTH_BOT_COMMUNITY_MISMATCH")
        if payload.get("ok") is not True or payload.get("acquisition_active") is not False:
            raise SimulationError("S10_WMS_HEALTH_BOUNDARY_RED")

    def stop(self, *, require_release: bool = True) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        if require_release:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    probe.bind(("127.0.0.1", self.port))
                except OSError:
                    raise SimulationError("S10_WMS_HEALTH_PORT_NOT_RELEASED") from None
        self._temporary.cleanup()


def _listener_case(name: str, operation) -> dict[str, object]:
    try:
        operation()
    except SimulationError as error:
        return {"name": name, "ok": False, "safe_code": str(error)}
    return {"name": name, "ok": True, "safe_code": "LISTENER_SCENARIO_GREEN"}


def _listener_scenarios(application_root: Path, release_id: str) -> list[dict[str, object]]:
    scenarios: list[dict[str, object]] = []

    def normal() -> None:
        runtime = RealWMSHealthRuntime(application_root, release_id=release_id)
        try:
            runtime.validate(runtime.start(), release_id)
        finally:
            runtime.stop()

    scenarios.append(_listener_case("normal_target_startup", normal))

    def occupied() -> None:
        port = _isolated_port()
        first = RealWMSHealthRuntime(application_root, port=port, release_id=release_id)
        second = RealWMSHealthRuntime(application_root, port=port, release_id=release_id)
        try:
            first.validate(first.start(), release_id)
            try:
                second.start()
            except SimulationError as error:
                if str(error) == "S10_WMS_HEALTH_PORT_IN_USE":
                    return
                raise
            raise SimulationError("S10_WMS_HEALTH_FALSE_GREEN")
        finally:
            second.stop(require_release=False)
            first.stop()

    scenarios.append(_listener_case("port_already_occupied", occupied))

    def health_task_crashes() -> None:
        runtime = RealWMSHealthRuntime(application_root, release_id=release_id)
        try:
            runtime.validate(runtime.start(), release_id)
            assert runtime.process is not None
            runtime.process.kill()
            runtime.process.wait(timeout=2)
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{runtime.port}/health", timeout=0.2)
            except (OSError, TimeoutError, urllib.error.URLError):
                return
            raise SimulationError("S10_WMS_HEALTH_TASK_FALSE_GREEN")
        finally:
            runtime.stop()

    scenarios.append(_listener_case("health_task_crashes", health_task_crashes))

    def wrong_port() -> None:
        runtime = RealWMSHealthRuntime(application_root, release_id=release_id)
        unused = _isolated_port()
        try:
            runtime.validate(runtime.start(), release_id)
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{unused}/health", timeout=0.2)
            except (OSError, TimeoutError, urllib.error.URLError):
                return
            raise SimulationError("S10_WMS_HEALTH_WRONG_PORT_FALSE_GREEN")
        finally:
            runtime.stop()

    scenarios.append(_listener_case("wrong_port_config", wrong_port))

    def wrong_release() -> None:
        runtime = RealWMSHealthRuntime(application_root, release_id=release_id)
        try:
            payload = runtime.start()
            try:
                runtime.validate(payload, "s10-2d-r99")
            except SimulationError as error:
                if str(error) == "S10_WMS_HEALTH_RELEASE_ID_MISMATCH":
                    return
                raise
            raise SimulationError("S10_WMS_HEALTH_FALSE_GREEN")
        finally:
            runtime.stop()

    scenarios.append(_listener_case("wrong_release_identity", wrong_release))

    def poller_without_health() -> None:
        poller_ready = True
        listener_ready = False
        if poller_ready and not listener_ready:
            return
        raise SimulationError("S10_WMS_HEALTH_LISTENER_FALSE_GREEN")

    scenarios.append(_listener_case("poller_starts_health_does_not", poller_without_health))

    def health_without_poller() -> None:
        runtime = RealWMSHealthRuntime(application_root, release_id=release_id)
        try:
            runtime.validate(runtime.start(), release_id)
            poller_ready = False
            if not poller_ready:
                return
            raise SimulationError("S8_POLLER_FALSE_GREEN")
        finally:
            runtime.stop()

    scenarios.append(_listener_case("health_starts_poller_dies", health_without_poller))

    def source_does_not_relinquish() -> None:
        port = _isolated_port()
        source = RealWMSHealthRuntime(
            application_root, port=port, release_id=None, community=False
        )
        target = RealWMSHealthRuntime(application_root, port=port, release_id=release_id)
        try:
            payload = source.start()
            if payload.get("runtime_release_id") != "source":
                raise SimulationError("S10_WMS_SOURCE_HEALTH_RED")
            try:
                target.start()
            except SimulationError as error:
                if str(error) == "S10_WMS_HEALTH_PORT_IN_USE":
                    return
                raise
            raise SimulationError("S10_WMS_SOURCE_PORT_NOT_FENCED")
        finally:
            target.stop(require_release=False)
            source.stop()

    scenarios.append(_listener_case("source_process_not_relinquished", source_does_not_relinquish))

    def rollback_source_restored() -> None:
        port = _isolated_port()
        target = RealWMSHealthRuntime(application_root, port=port, release_id=release_id)
        target.validate(target.start(), release_id)
        target.stop()
        source = RealWMSHealthRuntime(
            application_root, port=port, release_id=None, community=False
        )
        try:
            payload = source.start()
            if (
                payload.get("ok") is not True
                or payload.get("runtime_release_id") != "source"
                or payload.get("runtime_contract") != "SOURCE"
                or payload.get("community") is not False
            ):
                raise SimulationError("S10_WMS_SOURCE_HEALTH_RED")
        finally:
            source.stop()

    scenarios.append(_listener_case("rollback_source_listener_restored", rollback_source_restored))
    return scenarios


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
                status = 47
            elif self.scenario == "wrong_release_identity" or release_id != self.release_id:
                status = 49
            elif self.scenario in {"bounded_startup", "poller_not_ready"}:
                status = 48
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
    wms_unit = (control_root / "systemd/tu1nz-adult-public-s10-wms.service").read_text()
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
        "require_target_wms_listener",
        "require_target_s8_poller",
        "S8_POLLER_NOT_READY",
    )
    _require(target_unit, "--community-contract", "--runtime-release-id s10-2d-r3-5")
    _require(wms_unit, "--community-contract", "--runtime-release-id s10-2d-r3-5")
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
        _health_case(health_gate, control_root, "target_process_never_starts", "target_process_never_starts", "HEALTH_GATE_S8_RUNTIME_PROCESS_NOT_RUNNING"),
        _health_case(health_gate, control_root, "target_wrong_release", "wrong_release_identity", "HEALTH_GATE_S8_RUNTIME_RELEASE_ID_RED"),
        _health_case(health_gate, control_root, "target_http_unavailable", "public_http_unavailable", "HEALTH_GATE_S9_PUBLIC_HEALTH_PUBLIC_HTTP_RED"),
        _health_case(health_gate, control_root, "database_unavailable", "database_unavailable", "HEALTH_GATE_S9_PUBLIC_HEALTH_GROWTH_DATABASE_RED"),
        _health_case(health_gate, control_root, "bounded_startup_transition", "bounded_startup", "HEALTH_GATE_S8_RUNTIME_POLLER_NOT_READY"),
        _health_case(health_gate, control_root, "source_answers_target_absent", "source_answers_target_absent", "HEALTH_GATE_S8_RUNTIME_PROCESS_NOT_RUNNING"),
        _health_case(health_gate, control_root, "community_contract_missing", "community_contract_missing", "HEALTH_GATE_S9_PUBLIC_HEALTH_COMMUNITY_ARGUMENTS_RED"),
        _health_case(health_gate, control_root, "r4_missing_health_release_binding", "r4_missing_health_release_binding", "HEALTH_GATE_S9_PUBLIC_HEALTH_COMMUNITY_RUNTIME_CONTRACT_RED"),
    ]
    if any(not case["ok"] for case in health_cases):
        raise SimulationError("SIMULATOR_HEALTH_SCENARIO_RED")

    listener_cases = _listener_scenarios(application_root, "s10-2d-r3-5")
    if len(listener_cases) != 9 or any(not case["ok"] for case in listener_cases):
        raise SimulationError("SIMULATOR_LISTENER_SCENARIO_RED")

    sys.path.insert(0, str(application_root / "src"))
    from tu1nz_public_s8.release_simulator import run_bot_path_simulation

    bot = run_bot_path_simulation(application_root, 100)
    scenarios: list[dict[str, object]] = []

    def require_health(state: ReleaseState, scenario: str = "success") -> None:
        report = _health_case(health_gate, control_root, "release_health_gate", scenario)
        listener_green = next(
            case for case in listener_cases if case["name"] == "normal_target_startup"
        )["ok"]
        state.health_green = (
            report["safe_code"] == "S10_2D_HEALTH_GATES_GREEN" and listener_green is True
        )
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
        "safe_code": "S10_2D_R6_1_RELEASE_SIMULATOR_GREEN",
        "scenarios": scenarios,
        "health_cases": health_cases,
        "listener_cases": listener_cases,
        "bot": bot,
        "production_health_gate_shared": True,
        "production_wms_listener_shared": True,
        "health_listener_owner": "S10_WMS_RUNTIME",
        "health_listener_bind": "127.0.0.1",
        "health_listener_production_port": 18110,
        "health_release_id": "s10-2d-r3-5",
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
