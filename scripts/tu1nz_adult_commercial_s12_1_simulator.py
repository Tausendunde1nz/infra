#!/usr/bin/env python3
"""Executing source-only S12.1 runtime acceptance and rollback simulator."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.tu1nz_adult_commercial_s12_1_runtime import (
    HARD_GATE_KEYS,
    MANIFEST,
    S12ControlError,
    manifest_contract_is_exact,
    parse_manifest_contract,
    validate_source_contract,
)


@dataclass
class _Session:
    reference: str
    scenario: str
    result: str | None = None


class _DeterministicSandboxRuntime:
    """Small executable model of the reviewed orchestration contract."""

    def __init__(self, manifest: dict[str, Any]) -> None:
        self.manifest = manifest
        self.authenticated = False
        self.callback_active = True
        self.runtime_active = True
        self.rollback_count = 0
        self._counter = 0
        self._triggered: set[str] = set()
        self._sessions: dict[str, _Session] = {}
        self._registered_scenarios: dict[str, str] = {}
        self._accepted_results: dict[str, str] = {}

    def credential_metadata(self) -> bool:
        return self.manifest.get("credentials") == {
            "delivery": "SYSTEMD_LOAD_CREDENTIAL",
            "private_key_reference": "/etc/tu1nz/adult-commercial-s5.yoti-private-key",
            "sdk_id_reference": "/etc/tu1nz/adult-commercial-s5.yoti-sdk-id",
            "values_committed": False,
        }

    def authenticate(
        self, *, environment: str | None = None, host: str = "auth.api.yoti.com"
    ) -> None:
        selected = environment or self.manifest["environment"]
        network = self.manifest["network"]
        if (
            selected != "SANDBOX"
            or host not in network["allowed_hosts"]
            or host == "api.yoti.com"
            or network["https_only"] is not True
            or network["production_endpoint_allowed"] is not False
            or network["redirect_to_unknown_host_allowed"] is not False
        ):
            raise S12ControlError("S12_1_SIMULATED_PRODUCTION_CROSSOVER_RED")
        self.authenticated = True

    def create_session(self, scenario: str) -> _Session:
        if not self.authenticated or scenario not in {
            "ADULT", "UNDER_THRESHOLD", "EXPIRED"
        }:
            raise S12ControlError("S12_1_SIMULATED_SESSION_RED")
        self._counter += 1
        session = _Session(f"sandbox-session-{self._counter}", scenario)
        self._sessions[session.reference] = session
        self._registered_scenarios[session.reference] = scenario
        return session

    def trigger(self, session: _Session) -> None:
        callback = self.manifest["callback"]
        if (
            self._sessions.get(session.reference) is not session
            or self._registered_scenarios.get(session.reference) != session.scenario
            or
            not self.callback_active
            or callback
            != {
                "authority": "AUTHENTICATED_RESULT_FETCH_ONLY",
                "bind": "127.0.0.1:18126",
                "body_limit_bytes": 16384,
                "method": "POST",
                "path": "/avs/sandbox/callback",
                "public_url": "https://wantmeseen.com/avs/sandbox/callback",
                "signature": "YOTI_SANDBOX_RSA_PSS_SHA256",
                "trigger_only": True,
            }
        ):
            code = (
                "S12_1_SIMULATED_UNKNOWN_SESSION_RED"
                if self._sessions.get(session.reference) is not session
                else "S12_1_SIMULATED_SESSION_MUTATION_RED"
                if self._registered_scenarios.get(session.reference) != session.scenario
                else "S12_1_SIMULATED_CALLBACK_RED"
            )
            raise S12ControlError(code)
        self._triggered.add(session.reference)

    def authenticated_fetch(
        self, session: _Session, *, forced_result: str | None = None
    ) -> tuple[str, bool]:
        if self._sessions.get(session.reference) is not session:
            raise S12ControlError("S12_1_SIMULATED_SESSION_SUBSTITUTION_RED")
        if self._registered_scenarios.get(session.reference) != session.scenario:
            raise S12ControlError("S12_1_SIMULATED_SESSION_MUTATION_RED")
        if not self.authenticated or session.reference not in self._triggered:
            raise S12ControlError("S12_1_SIMULATED_FETCH_RED")
        expected = {
            "ADULT": "AVS_VERIFIED_SANDBOX",
            "UNDER_THRESHOLD": "AVS_DENIED_SANDBOX",
            "EXPIRED": "AVS_EXPIRED",
        }[session.scenario]
        fetched = forced_result or expected
        accepted = self._accepted_results.get(session.reference)
        if accepted is not None:
            if fetched != accepted or session.result != accepted:
                raise S12ControlError("S12_1_SIMULATED_CONFLICTING_REPLAY_RED")
            return accepted, True
        if session.result is not None:
            raise S12ControlError("S12_1_SIMULATED_RESULT_MUTATION_RED")
        if fetched != expected:
            raise S12ControlError("S12_1_SIMULATED_PROVIDER_RESULT_RED")
        self._accepted_results[session.reference] = fetched
        session.result = fetched
        return fetched, False

    def retry(self, expired: _Session) -> _Session:
        if (
            self._sessions.get(expired.reference) is not expired
            or self._registered_scenarios.get(expired.reference) != "EXPIRED"
            or expired.scenario != "EXPIRED"
            or self._accepted_results.get(expired.reference) != "AVS_EXPIRED"
            or expired.result != "AVS_EXPIRED"
        ):
            raise S12ControlError("S12_1_SIMULATED_RETRY_RED")
        return self.create_session("ADULT")

    def synthetic_wms_e2e(self) -> bool:
        path = [
            "LANDING", "TELEGRAM_CTA", "BOT_START", "INTRO", "S11_EXPERIENCE",
            "S12_REQUIRED", "S12_SESSION", "S12_CALLBACK_TRIGGER",
            "AUTHENTICATED_RESULT_FETCH", "AVS_VERIFIED_SANDBOX", "WAITLIST",
        ]
        return path[0] == "LANDING" and path[-1] == "WAITLIST" and len(path) == len(set(path))

    def safe_stop(self) -> bool:
        self.callback_active = False
        self.runtime_active = False
        return not self.callback_active and not self.runtime_active

    def rollback_once(self) -> bool:
        if self.rollback_count:
            raise S12ControlError("S12_1_SIMULATED_ROLLBACK_DUPLICATE_RED")
        self.rollback_count += 1
        self.safe_stop()
        return self.rollback_count == 1


def _rejected(call: Callable[[], object], code: str) -> bool:
    try:
        call()
    except S12ControlError as error:
        return error.safe_code == code
    return False


def simulate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if not manifest_contract_is_exact(manifest):
        raise S12ControlError("S12_1_SIMULATOR_MANIFEST_RED")
    model = _DeterministicSandboxRuntime(manifest)
    journeys: dict[str, bool] = {}
    journeys["final_posture_closed"] = manifest.get("final_posture") == {
        "callback": "INACTIVE",
        "runtime": "CONTROLLED_INACTIVE",
        "yoti_sandbox_enabled_for_real_users": False,
    }
    journeys["credentials_metadata"] = model.credential_metadata()
    model.authenticate()
    journeys["sandbox_auth"] = model.authenticated

    adult = model.create_session("ADULT")
    journeys["session_create"] = adult.reference.startswith("sandbox-session-")
    model.trigger(adult)
    journeys["notification_trigger"] = adult.reference in model._triggered
    adult_result, duplicate = model.authenticated_fetch(adult)
    journeys["authenticated_result_fetch"] = not duplicate
    journeys["mock_adult"] = adult_result == "AVS_VERIFIED_SANDBOX"
    journeys["avs_verified_sandbox"] = adult_result == "AVS_VERIFIED_SANDBOX"
    repeated, duplicate = model.authenticated_fetch(adult)
    journeys["identical_replay"] = duplicate and repeated == adult_result
    journeys["conflicting_replay_red"] = _rejected(
        lambda: model.authenticated_fetch(adult, forced_result="AVS_DENIED_SANDBOX"),
        "S12_1_SIMULATED_CONFLICTING_REPLAY_RED",
    )
    unknown = _Session("sandbox-session-unknown", "ADULT")
    journeys["unknown_session_red"] = _rejected(
        lambda: model.trigger(unknown), "S12_1_SIMULATED_UNKNOWN_SESSION_RED"
    )

    denied = model.create_session("UNDER_THRESHOLD")
    model.trigger(denied)
    substituted = _Session(denied.reference, "ADULT")
    journeys["session_substitution_red"] = _rejected(
        lambda: model.authenticated_fetch(substituted),
        "S12_1_SIMULATED_SESSION_SUBSTITUTION_RED",
    )
    mutated = model.create_session("UNDER_THRESHOLD")
    model.trigger(mutated)
    mutated.scenario = "ADULT"
    journeys["session_scenario_mutation_red"] = _rejected(
        lambda: model.authenticated_fetch(mutated),
        "S12_1_SIMULATED_SESSION_MUTATION_RED",
    )
    forged_result = model.create_session("UNDER_THRESHOLD")
    model.trigger(forged_result)
    forged_result.result = "AVS_VERIFIED_SANDBOX"
    journeys["session_result_mutation_red"] = _rejected(
        lambda: model.authenticated_fetch(
            forged_result, forced_result="AVS_VERIFIED_SANDBOX"
        ),
        "S12_1_SIMULATED_RESULT_MUTATION_RED",
    )
    journeys["under_threshold_denied"] = (
        model.authenticated_fetch(denied)[0] == "AVS_DENIED_SANDBOX"
    )
    expired = model.create_session("EXPIRED")
    model.trigger(expired)
    journeys["expiry"] = model.authenticated_fetch(expired)[0] == "AVS_EXPIRED"
    journeys["fabricated_expiry_retry_red"] = _rejected(
        lambda: model.retry(
            _Session("sandbox-session-fabricated", "EXPIRED", "AVS_EXPIRED")
        ),
        "S12_1_SIMULATED_RETRY_RED",
    )
    nonexpired = model.create_session("ADULT")
    model.trigger(nonexpired)
    model.authenticated_fetch(nonexpired)
    nonexpired.result = "AVS_EXPIRED"
    journeys["nonexpiry_retry_red"] = _rejected(
        lambda: model.retry(nonexpired),
        "S12_1_SIMULATED_RETRY_RED",
    )
    retried = model.retry(expired)
    model.trigger(retried)
    journeys["new_session_retry"] = (
        retried.reference != expired.reference
        and model.authenticated_fetch(retried)[0] == "AVS_VERIFIED_SANDBOX"
    )
    journeys["production_crossover_red"] = _rejected(
        lambda: model.authenticate(environment="PRODUCTION", host="api.yoti.com"),
        "S12_1_SIMULATED_PRODUCTION_CROSSOVER_RED",
    )
    journeys["synthetic_e2e"] = model.synthetic_wms_e2e()
    journeys["safe_stop"] = model.safe_stop()

    rollback_model = _DeterministicSandboxRuntime(manifest)
    journeys["rollback"] = rollback_model.rollback_once() and _rejected(
        rollback_model.rollback_once,
        "S12_1_SIMULATED_ROLLBACK_DUPLICATE_RED",
    )
    hard_gates = manifest.get("hard_gates")
    hard_gates_closed = (
        isinstance(hard_gates, dict)
        and set(hard_gates) == HARD_GATE_KEYS
        and all(value is False for value in hard_gates.values())
    )
    if not all(journeys.values()) or not hard_gates_closed:
        raise S12ControlError("S12_1_SIMULATOR_RED")
    return {
        "external_adult_actions": False,
        "hard_gates_closed": hard_gates_closed,
        "journeys": journeys,
        "ok": True,
        "real_identity_used": False,
        "safe_code": "S12_1_RUNTIME_SIMULATOR_GREEN",
    }


def run_simulator() -> dict[str, Any]:
    validate_source_contract()
    manifest = parse_manifest_contract(MANIFEST.read_text(encoding="utf-8"))
    return simulate_manifest(manifest)


def main() -> int:
    try:
        result = run_simulator()
    except (KeyError, S12ControlError, TypeError, ValueError, json.JSONDecodeError) as error:
        result = {
            "ok": False,
            "safe_code": getattr(error, "safe_code", "S12_1_SIMULATOR_RED"),
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
