#!/usr/bin/env python3
"""Source-only Application writer / Control reader compatibility gate."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

try:
    from scripts import tu1nz_adult_public_community_health_contract as reader
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    import tu1nz_adult_public_community_health_contract as reader


CONTRACT_CONSTANTS = (
    "APPLICATION_HEALTH_SCHEMA_VERSION",
    "COMMUNITY_FAILURE_ENVELOPE_SCHEMA",
    "COMMUNITY_FAILURE_ENVELOPE_VERSION",
)


def application_constants(path: Path) -> dict[str, object]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in CONTRACT_CONSTANTS:
            values[target.id] = ast.literal_eval(node.value)
    return values


def verify(application_contract: Path, fixture: Path) -> dict[str, object]:
    expected = {name: getattr(reader, name) for name in CONTRACT_CONSTANTS}
    if application_constants(application_contract) != expected:
        raise ValueError("S11_2_COMMUNITY_HEALTH_SCHEMA_MISMATCH")
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    failure = reader.failure_from_payload(payload, 2)
    if (
        failure is None
        or failure.child_code != "BOT_EVENT_PATH_WAITING"
        or failure.component != "POLLING"
    ):
        raise ValueError("S11_2_COMMUNITY_HEALTH_FIXTURE_MISMATCH")
    return {
        "application_health_schema_version": reader.APPLICATION_HEALTH_SCHEMA_VERSION,
        "community_failure_envelope_version": reader.COMMUNITY_FAILURE_ENVELOPE_VERSION,
        "control_reader_version": reader.CONTROL_COMMUNITY_READER_VERSION,
        "ok": True,
        "safe_code": "S11_2_COMMUNITY_HEALTH_COMPATIBILITY_GREEN",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--application-contract", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = verify(arguments.application_contract, arguments.fixture)
    except (OSError, SyntaxError, ValueError, json.JSONDecodeError):
        report = {"ok": False, "safe_code": "S11_2_COMMUNITY_HEALTH_COMPATIBILITY_RED"}
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
