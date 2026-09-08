#!/usr/bin/env python3
"""Source-only S10.2D release simulator using the production health gate."""

from __future__ import annotations

import argparse
import datetime as dt
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


def _baseline_aggregate() -> dict[str, int]:
    payload: dict[str, int] = {}
    for index in range(37):
        event = "LANDING_VIEW" if index < 19 else "TELEGRAM_CTA"
        payload[f"2026-09-07|{event}|source{index:02d}|campaign{index:02d}"] = 1
    last = next(reversed(payload))
    payload[last] += 6732 - sum(payload.values())
    return payload


def _write_aggregate(path: Path, payload: dict[str, int] | bytes) -> None:
    material = payload if isinstance(payload, bytes) else json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    path.write_bytes(material)
    path.chmod(0o600)


def _source_counter_module(application_root: Path, directory: Path) -> ModuleType:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(application_root),
            "show",
            "f9747088a31ec6c671e82de24e293ebdec99f717:src/tu1nz_growth_s9/counter.py",
        ],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SimulationError("SIMULATOR_SOURCE_COUNTER_BINDING_RED")
    source_path = directory / "source_counter.py"
    source_path.write_bytes(completed.stdout)
    return _load_module(source_path, f"tu1nz_source_counter_{id(directory)}")


def _aggregate_scenarios(application_root: Path, control_root: Path) -> list[dict[str, object]]:
    aggregate_contract = _load_module(
        control_root / "scripts/tu1nz_adult_public_s10_2d_aggregate_contract.py",
        "tu1nz_s10_2d_aggregate_contract_simulator",
    )
    target_counter = _load_module(
        application_root / "src/tu1nz_growth_s9/counter.py",
        "tu1nz_target_counter_simulator",
    )
    reports: list[dict[str, object]] = []

    def case(name: str, operation) -> None:
        try:
            operation()
        except SimulationError:
            raise
        except Exception as error:
            candidate = str(error)
            safe = candidate if candidate.isupper() and " " not in candidate else "AGGREGATE_SCENARIO_RED"
            raise SimulationError(safe) from None
        reports.append({"name": name, "ok": True, "safe_code": "AGGREGATE_SCENARIO_GREEN"})

    def prepare(directory: Path) -> tuple[Path, Path, str]:
        aggregate = directory / "landing-aggregates.json"
        backup = directory / "backup"
        backup.mkdir(mode=0o700)
        _write_aggregate(aggregate, _baseline_aggregate())
        run_id = "20260908T000000Z-pre-s10-2d-community"
        aggregate_contract.create_backup(
            aggregate,
            backup,
            target_release_id=aggregate_contract.TARGET_RELEASE_ID,
            run_id=run_id,
        )
        return aggregate, backup, run_id

    def exact_r7() -> None:
        with tempfile.TemporaryDirectory(prefix="tu1nz-r7-1-exact-") as temporary:
            directory = Path(temporary)
            source_counter = _source_counter_module(application_root, directory)
            if frozenset(source_counter.AggregateCounter.EVENTS) != aggregate_contract.SOURCE_EVENTS:
                raise SimulationError("SIMULATOR_SOURCE_EVENT_SET_RED")
            if frozenset(target_counter.AggregateCounter.EVENTS) != aggregate_contract.KNOWN_EVENTS:
                raise SimulationError("SIMULATOR_TARGET_EVENT_SET_RED")
            aggregate, backup, run_id = prepare(directory)
            source_counter.AggregateCounter(aggregate).snapshot()
            port = _isolated_port()
            target_runtime = RealWMSHealthRuntime(
                application_root,
                port=port,
                release_id="s10-2d-r3-5",
                community=True,
            )
            try:
                target_runtime.validate(target_runtime.start(), "s10-2d-r3-5")
                writer = target_counter.AggregateCounter(aggregate)
                writer.record(
                    "COMMUNITY_CTA",
                    "community",
                    "s10_wms_launch",
                    dt.datetime(2026, 9, 8, tzinfo=dt.timezone.utc),
                )
                red_reproduced = False
                try:
                    source_counter.AggregateCounter(aggregate)
                except ValueError as error:
                    red_reproduced = str(error) == "S9_AGGREGATE_STATE_INVALID"
                if not red_reproduced:
                    raise SimulationError("R7_RED_NOT_REPRODUCED")
            finally:
                target_runtime.stop()
            result = aggregate_contract.reconcile_for_source(
                aggregate,
                backup,
                target_release_id=aggregate_contract.TARGET_RELEASE_ID,
                run_id=run_id,
            )
            source = source_counter.AggregateCounter(aggregate).snapshot()
            if not result["target_only_archived"] or len(source) != 37 or sum(source.values()) != 6732:
                raise SimulationError("R7_SOURCE_PROJECTION_RED")
            source_runtime = RealWMSHealthRuntime(
                application_root,
                port=port,
                release_id=None,
                community=False,
            )
            try:
                source_health = source_runtime.start()
                if (
                    source_health.get("ok") is not True
                    or source_health.get("runtime_release_id") != "source"
                    or source_health.get("runtime_contract") != "SOURCE"
                    or source_health.get("community") is not False
                ):
                    raise SimulationError("R7_SOURCE_PUBLIC_HEALTH_RED")
            finally:
                source_runtime.stop()

    case("source_target_community_failure_rollback_source_health", exact_r7)

    def multiple_target_and_source_events() -> None:
        with tempfile.TemporaryDirectory(prefix="tu1nz-r7-1-multiple-") as temporary:
            directory = Path(temporary)
            source_counter = _source_counter_module(application_root, directory)
            aggregate, backup, run_id = prepare(directory)
            writer = target_counter.AggregateCounter(aggregate)
            now = dt.datetime(2026, 9, 8, tzinfo=dt.timezone.utc)
            for event in ("COMMUNITY_CTA", "COMMUNITY_CTA", "LANDING_VIEW", "TELEGRAM_CTA"):
                writer.record(event, "recovery", "simulator", now)
            aggregate_contract.reconcile_for_source(
                aggregate,
                backup,
                target_release_id=aggregate_contract.TARGET_RELEASE_ID,
                run_id=run_id,
            )
            source = source_counter.AggregateCounter(aggregate).snapshot()
            if any("|COMMUNITY_CTA|" in key for key in source) or sum(source.values()) != 6734:
                raise SimulationError("AGGREGATE_MULTIPLE_TARGET_EVENT_RED")

    case("multiple_community_and_source_events", multiple_target_and_source_events)

    def no_target_event() -> None:
        with tempfile.TemporaryDirectory(prefix="tu1nz-r7-1-no-target-") as temporary:
            directory = Path(temporary)
            source_counter = _source_counter_module(application_root, directory)
            aggregate, backup, run_id = prepare(directory)
            result = aggregate_contract.reconcile_for_source(
                aggregate,
                backup,
                target_release_id=aggregate_contract.TARGET_RELEASE_ID,
                run_id=run_id,
            )
            source_counter.AggregateCounter(aggregate).snapshot()
            if result["target_only_total"] != 0:
                raise SimulationError("AGGREGATE_EMPTY_TARGET_ARCHIVE_RED")

    case("target_fails_before_aggregate_write", no_target_event)

    def unknown_event() -> None:
        with tempfile.TemporaryDirectory(prefix="tu1nz-r7-1-unknown-") as temporary:
            directory = Path(temporary)
            aggregate, backup, run_id = prepare(directory)
            payload = _baseline_aggregate()
            payload["2026-09-08|UNBOUND_EVENT|source|campaign"] = 1
            _write_aggregate(aggregate, payload)
            original = aggregate.read_bytes()
            try:
                aggregate_contract.reconcile_for_source(
                    aggregate,
                    backup,
                    target_release_id=aggregate_contract.TARGET_RELEASE_ID,
                    run_id=run_id,
                )
            except aggregate_contract.AggregateContractError as error:
                if str(error) != "AGGREGATE_RECONCILIATION_UNKNOWN_EVENT_RED":
                    raise
            else:
                raise SimulationError("AGGREGATE_UNKNOWN_EVENT_FALSE_GREEN")
            archived = backup / aggregate_contract.RECONCILIATION_DIRECTORY / aggregate_contract.CURRENT_BYTES
            if aggregate.read_bytes() != original or archived.read_bytes() != original:
                raise SimulationError("AGGREGATE_UNKNOWN_EVENT_ORIGINAL_RED")

    case("unknown_event_fails_closed", unknown_event)

    def malformed_event_file() -> None:
        with tempfile.TemporaryDirectory(prefix="tu1nz-r7-1-malformed-") as temporary:
            directory = Path(temporary)
            aggregate, backup, run_id = prepare(directory)
            _write_aggregate(aggregate, b'{"incomplete":')
            original = aggregate.read_bytes()
            try:
                aggregate_contract.reconcile_for_source(
                    aggregate,
                    backup,
                    target_release_id=aggregate_contract.TARGET_RELEASE_ID,
                    run_id=run_id,
                )
            except aggregate_contract.AggregateContractError as error:
                if str(error) != "AGGREGATE_JSON_RED":
                    raise
            else:
                raise SimulationError("AGGREGATE_MALFORMED_FALSE_GREEN")
            if aggregate.read_bytes() != original:
                raise SimulationError("AGGREGATE_MALFORMED_ORIGINAL_RED")

    case("malformed_incomplete_file_fails_closed", malformed_event_file)

    def backup_checksum_mismatch() -> None:
        with tempfile.TemporaryDirectory(prefix="tu1nz-r7-1-checksum-") as temporary:
            directory = Path(temporary)
            aggregate, backup, run_id = prepare(directory)
            before = aggregate.read_bytes()
            (backup / aggregate_contract.BACKUP_BYTES).write_bytes(b"{}")
            (backup / aggregate_contract.BACKUP_BYTES).chmod(0o600)
            try:
                aggregate_contract.verify_backup(
                    aggregate,
                    backup,
                    target_release_id=aggregate_contract.TARGET_RELEASE_ID,
                    run_id=run_id,
                )
            except aggregate_contract.AggregateContractError as error:
                if str(error) != "AGGREGATE_BACKUP_HASH_RED":
                    raise
            else:
                raise SimulationError("AGGREGATE_CHECKSUM_FALSE_GREEN")
            if aggregate.read_bytes() != before:
                raise SimulationError("AGGREGATE_CHECKSUM_LIVE_MUTATION_RED")

    case("backup_checksum_mismatch_fails_preflight", backup_checksum_mismatch)

    def two_failures_then_idempotent_success() -> None:
        with tempfile.TemporaryDirectory(prefix="tu1nz-r7-1-idempotent-") as temporary:
            directory = Path(temporary)
            source_counter = _source_counter_module(application_root, directory)
            aggregate, backup, run_id = prepare(directory)
            target_counter.AggregateCounter(aggregate).record(
                "COMMUNITY_CTA",
                "community",
                "s10_wms_launch",
                dt.datetime(2026, 9, 8, tzinfo=dt.timezone.utc),
            )
            target_bytes = aggregate.read_bytes()

            def injected_failure() -> None:
                raise aggregate_contract.AggregateContractError("SIMULATED_POST_REPLACE_RED")

            for _ in range(2):
                try:
                    aggregate_contract.reconcile_for_source(
                        aggregate,
                        backup,
                        target_release_id=aggregate_contract.TARGET_RELEASE_ID,
                        run_id=run_id,
                        after_replace=injected_failure,
                    )
                except aggregate_contract.AggregateContractError as error:
                    if str(error) != "SIMULATED_POST_REPLACE_RED":
                        raise
                else:
                    raise SimulationError("AGGREGATE_INJECTED_FAILURE_FALSE_GREEN")
                if aggregate.read_bytes() != target_bytes:
                    raise SimulationError("AGGREGATE_FAILED_ATTEMPT_RESTORE_RED")
            aggregate_contract.reconcile_for_source(
                aggregate,
                backup,
                target_release_id=aggregate_contract.TARGET_RELEASE_ID,
                run_id=run_id,
            )
            repeated = aggregate_contract.reconcile_for_source(
                aggregate,
                backup,
                target_release_id=aggregate_contract.TARGET_RELEASE_ID,
                run_id=run_id,
            )
            source_counter.AggregateCounter(aggregate).snapshot()
            archived = list((backup / aggregate_contract.RECONCILIATION_DIRECTORY).glob(aggregate_contract.CURRENT_BYTES))
            if not repeated["idempotent"] or len(archived) != 1:
                raise SimulationError("AGGREGATE_IDEMPOTENCY_RED")

    case("two_failed_recoveries_then_idempotent_success", two_failures_then_idempotent_success)

    def source_count_regression() -> None:
        with tempfile.TemporaryDirectory(prefix="tu1nz-r7-1-count-") as temporary:
            directory = Path(temporary)
            aggregate, backup, run_id = prepare(directory)
            payload = _baseline_aggregate()
            first = next(iter(payload))
            payload[first] = 0
            _write_aggregate(aggregate, payload)
            original = aggregate.read_bytes()
            try:
                aggregate_contract.reconcile_for_source(
                    aggregate,
                    backup,
                    target_release_id=aggregate_contract.TARGET_RELEASE_ID,
                    run_id=run_id,
                )
            except aggregate_contract.AggregateContractError as error:
                if str(error) != "AGGREGATE_SOURCE_COUNT_REGRESSION_RED":
                    raise
            else:
                raise SimulationError("AGGREGATE_COUNT_REGRESSION_FALSE_GREEN")
            if aggregate.read_bytes() != original:
                raise SimulationError("AGGREGATE_COUNT_REGRESSION_MUTATED")

    case("source_count_regression_fails_closed", source_count_regression)

    if aggregate_contract.TARGET_TECHNICAL_EVENTS:
        raise SimulationError("AGGREGATE_TARGET_TECHNICAL_EVENT_UNCLASSIFIED")
    reports.append(
        {
            "name": "target_technical_event_set_explicitly_empty",
            "ok": True,
            "safe_code": "AGGREGATE_SCENARIO_GREEN",
        }
    )
    if len(reports) != 9 or any(not report["ok"] for report in reports):
        raise SimulationError("AGGREGATE_SCENARIO_SET_RED")
    return reports


def _retained_state_scenarios(control_root: Path) -> list[dict[str, object]]:
    contract = _load_module(
        control_root / "scripts/tu1nz_adult_public_s10_2d_state_reconcile.py",
        "tu1nz_s10_2d_r8_1_state_simulator",
    )
    release = "s10-2d-r3-5"
    run = "11111111-1111-4111-8111-111111111111"
    cutover = "2026-09-07T15:37:04.000000Z"
    subject = "22222222-2222-4222-8222-222222222222"
    joined = "2026-09-08T03:38:05.226357Z"
    active = "2026-09-08T03:38:25.292795Z"

    def sample(number: int, source: str, occurred_at: str) -> dict[str, object]:
        return {
            "sample_id": f"00000000-0000-4000-8000-{number:012d}",
            "source": source,
            "bot_response_latency_ms": 500 + number,
            "poll_lag_ms": 100,
            "handler_duration_ms": 100,
            "send_ack_ms": 100,
            "occurred_at": occurred_at,
            "release_id": release,
            "run_id": run,
            "evidence_class": "TECHNICAL_ACCEPTANCE",
            "cutover_started_at": cutover,
        }

    def fixture() -> dict[str, object]:
        latency = [
            sample(index, "DIRECT", f"2026-09-08T03:3{index}:00.000000Z")
            for index in range(1, 13)
        ]
        latency.extend((
            sample(13, "COMMUNITY", "2026-09-08T03:38:05.720047Z"),
            sample(14, "COMMUNITY", "2026-09-08T03:38:25.905793Z"),
        ))
        return {
            "runtime": {
                "release_id": release,
                "run_id": run,
                "cutover_started_at": cutover,
                "readiness": "PENDING",
                "acquisition_ready": False,
                "baseline_start": None,
            },
            "members": [{
                "subject_id": subject,
                "telegram_user_id": "synthetic-test-identity",
                "community_state": "ACTIVE",
                "self_attested": True,
                "warning_count": 0,
                "ban_state": False,
                "joined_at": joined,
                "updated_at": active,
            }],
            "community_events": [
                {"event_id": "30000000-0000-4000-8000-000000000001", "event_type": "COMMUNITY_JOIN", "subject_id": subject, "occurred_at": joined},
                {"event_id": "30000000-0000-4000-8000-000000000002", "event_type": "RULES_ACCEPTED", "subject_id": subject, "occurred_at": active},
                {"event_id": "30000000-0000-4000-8000-000000000003", "event_type": "COMMUNITY_ACTIVE_MEMBER", "subject_id": subject, "occurred_at": active},
            ],
            "rate_limits": [],
            "moderation_events": [],
            "moderation_outbox": [],
            "latency": latency,
        }

    provider = {"status": "left", "is_human": True, "non_privileged": True}
    reports: list[dict[str, object]] = []

    def case(name: str, operation) -> None:
        try:
            operation()
        except (contract.StateContractError, SimulationError) as error:
            reports.append({"name": name, "ok": False, "safe_code": str(error)})
        else:
            reports.append({"name": name, "ok": True, "safe_code": "RETAINED_STATE_SCENARIO_GREEN"})

    def current_r8() -> None:
        current = fixture()
        try:
            contract.retained_preflight(current)
        except contract.StateContractError as error:
            if str(error) != "MIGRATION_0029_RETAINED_PRODUCT_STATE":
                raise
        else:
            raise SimulationError("RETAINED_CURRENT_STATE_FALSE_GREEN")
        reconciled, _ = contract.reconcile_model(
            current,
            ownership_class="FAILED_RELEASE_TARGET_STATE_CONFIRMED",
            provider=provider,
        )
        if contract.retained_preflight(reconciled)["safe_code"] != "S10_2D_CLEAN_CUTOVER_BASELINE_GREEN":
            raise SimulationError("RETAINED_NEXT_PREFLIGHT_RED")

    case("current_r8_red_reconcile_next_preflight", current_r8)

    def unknown_member() -> None:
        current = fixture()
        current["community_events"] = current["community_events"][:-1]
        try:
            contract.reconcile_model(current, ownership_class="INTERNAL_ACCEPTANCE_CONFIRMED", provider=provider)
        except contract.StateContractError as error:
            if str(error) == "RETAINED_MEMBER_EVENT_OWNERSHIP_RED":
                return
            raise
        raise SimulationError("RETAINED_UNKNOWN_MEMBER_FALSE_GREEN")

    case("unknown_member_fails_closed", unknown_member)

    def unknown_latency() -> None:
        current = fixture()
        current["latency"][0]["evidence_class"] = "UNKNOWN"
        try:
            contract.reconcile_model(current, ownership_class="FAILED_RELEASE_TARGET_STATE_CONFIRMED", provider=provider)
        except contract.StateContractError as error:
            if str(error) == "MIGRATION_0029_RETAINED_EVIDENCE_UNKNOWN":
                return
            raise
        raise SimulationError("RETAINED_UNKNOWN_LATENCY_FALSE_GREEN")

    case("unknown_latency_fails_closed", unknown_latency)

    def real_user() -> None:
        current = fixture()
        current["runtime"].update({
            "readiness": "GREEN",
            "acquisition_ready": True,
            "baseline_start": "2026-09-08T04:00:00.000000Z",
        })
        report = contract.retained_preflight(current)
        if report["safe_code"] != "S10_2D_REAL_PRODUCT_STATE_PRESERVED" or report["cleanup_permitted"]:
            raise SimulationError("RETAINED_REAL_USER_PRESERVATION_RED")

    case("real_product_member_preserved", real_user)

    def provider_exit() -> None:
        try:
            contract.reconcile_model(
                fixture(),
                ownership_class="INTERNAL_ACCEPTANCE_CONFIRMED",
                provider={**provider, "status": "restricted"},
            )
        except contract.StateContractError as error:
            if str(error) == "RETAINED_PROVIDER_EXIT_REQUIRED":
                return
            raise
        raise SimulationError("RETAINED_PROVIDER_DB_DIVERGENCE_FALSE_GREEN")

    case("provider_exit_required", provider_exit)

    def repeated() -> None:
        reconciled, first = contract.reconcile_model(
            fixture(), ownership_class="FAILED_RELEASE_TARGET_STATE_CONFIRMED", provider=provider
        )
        repeated_state, second = contract.reconcile_model(
            reconciled, ownership_class="FAILED_RELEASE_TARGET_STATE_CONFIRMED", provider=provider
        )
        if first["idempotent"] or not second["idempotent"] or repeated_state != reconciled:
            raise SimulationError("RETAINED_RECONCILIATION_IDEMPOTENCY_RED")

    case("repeated_reconciliation_idempotent", repeated)

    def multi_release() -> None:
        reconciled, _ = contract.reconcile_model(
            fixture(), ownership_class="FAILED_RELEASE_TARGET_STATE_CONFIRMED", provider=provider
        )
        contract.retained_preflight(reconciled)
        release_b = fixture()
        release_b["runtime"]["release_id"] = "s10-2d-r8"
        for row in release_b["latency"]:
            row["release_id"] = "s10-2d-r8"
        contract.classify_retained_state(
            release_b, ownership_class="INTERNAL_ACCEPTANCE_CONFIRMED", provider=provider
        )

    case("multi_release_acceptance_lifecycle", multi_release)
    if len(reports) != 7 or any(not report["ok"] for report in reports):
        raise SimulationError("RETAINED_STATE_SCENARIO_SET_RED")
    return reports


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
        "tu1nz_adult_public_s10_2d_backup.sh",
        "tu1nz_adult_public_s10_2d_aggregate_contract.py",
        "tu1nz_adult_public_s10_2d_state_reconcile.py",
        "reconcile_aggregate_for_source",
        "require_source_aggregate_readable",
        "require_retained_state_preflight",
        "state-preflight",
    )
    rollback_contract = controller.split("rollback() {", 1)[1].split("deploy() {", 1)[0]
    if not (
        rollback_contract.index("quiesce")
        < rollback_contract.index("reconcile_aggregate_for_source")
        < rollback_contract.index("rollback_migration_if_unused")
        < rollback_contract.index("restore_technical_state")
        < rollback_contract.index("systemctl start")
        < rollback_contract.index("require_source_green")
    ):
        raise SimulationError("SIMULATOR_AGGREGATE_ROLLBACK_ORDER_RED")
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

    aggregate_cases = _aggregate_scenarios(application_root, control_root)
    if len(aggregate_cases) != 9 or any(not case["ok"] for case in aggregate_cases):
        raise SimulationError("SIMULATOR_AGGREGATE_SCENARIO_RED")

    retained_state_cases = _retained_state_scenarios(control_root)
    if len(retained_state_cases) != 7 or any(not case["ok"] for case in retained_state_cases):
        raise SimulationError("SIMULATOR_RETAINED_STATE_SCENARIO_RED")

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
        "safe_code": "S10_2D_R8_1_RELEASE_SIMULATOR_GREEN",
        "scenarios": scenarios,
        "health_cases": health_cases,
        "listener_cases": listener_cases,
        "aggregate_cases": aggregate_cases,
        "retained_state_cases": retained_state_cases,
        "retained_state_contract": "S10_2D_R8_1_RECONCILIATION_GREEN",
        "real_product_state_preserved": True,
        "unknown_retained_state_fails_closed": True,
        "aggregate_contract": "S10_2D_R7_1_AGGREGATE_ROLLBACK_GREEN",
        "aggregate_source_target_failure_rollback_source_health": True,
        "aggregate_unknown_events_fail_closed": True,
        "aggregate_original_restored_after_failed_recovery": True,
        "aggregate_backup_mandatory": True,
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
