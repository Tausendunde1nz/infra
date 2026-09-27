#!/usr/bin/env python3
"""Generate and verify the immutable S11.2 controller-bound freeze."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Mapping, Sequence


FREEZE_TAG = "s11-2-r15-15-3-profile-scoped-technical-freeze-r1"
LEGACY_FREEZE_TAG = "s11-2-r15-14-1-freeze-provenance-r1"
APPLICATION_COMMIT = "db87896697d56b24f192fc1cd0324b6fe46d734b"
APPLICATION_TREE = "b915a04e19eef8a244c300b16577a44cea89e2ab"

ARTIFACT_PATHS = {
    "runtime_controller_sha256": "scripts/tu1nz_adult_public_s11_2_control.sh",
    "runtime_gate_sha256": "scripts/tu1nz_adult_public_s11_2_gate.py",
    "runtime_orchestration_sha256": "scripts/tu1nz_adult_public_s11_2_orchestration.py",
    "controller_unit_sha256": "systemd/tu1nz-adult-public-s11-canary-controller.service",
    "controller_timer_sha256": "systemd/tu1nz-adult-public-s11-canary-controller.timer",
}

LEGACY_STATIC_BINDINGS = {
    "runtime_access_contract": "SOURCE_CHATOPS_RUNTIME_INSTALLED_V1",
    "umask_077_regression": "GREEN",
    "supplementary_groups": "chatops",
    "canary_contract": "FIRST_10_24H_EPOCH_BOUND",
    "promotion_contract": "FIVE_REAL_AND_TECHNICAL_SLO_GREEN",
    "phase_contract": "S11_2_R15_8_ORCHESTRATION_V1",
    "health_contract": "S10_1_HEALTH_CHILD_V1",
    "application_health_schema": "S8_HEALTH_V2",
    "community_failure_envelope": "COMMUNITY_FAILURE_V1",
    "control_community_reader": "CONTROL_COMMUNITY_READER_V2",
    "gate_failure_contract": "GATE_FAILURE_V1",
    "gate_diagnostic_contract": "GATE_DIAGNOSTIC_V1",
    "gate_error_allowlist": "CANONICAL_EXACT_ONLY",
    "controller_gate_reader": "CONTROL_GATE_READER_V1",
    "r15_15_simulator": "SOURCE_ONLY_GREEN",
    "technical_evidence_contract": "DYNAMIC_MISSING_SAMPLE_HARD_CAP",
    "resume_contract": "EXPLICIT_SEPARATELY_AUTHORIZED_NO_AUTO_RETRY",
    "nounset_contract": "SET_U_PRESERVED_NO_SAME_LOCAL_DEPENDENCIES",
    "phase_error_contract": "EXPLICIT_CHILD_SUPERVISION",
    "rollback_contract": "EXACTLY_ONCE_IDEMPOTENT",
}

STATIC_BINDINGS = {
    **LEGACY_STATIC_BINDINGS,
    "technical_evidence_contract": "PROFILE_SCOPED_MIXED_PROVENANCE_DYNAMIC_HARD_CAP_V2",
}

REQUIRED_KEYS = (
    "application_commit",
    "application_tree",
    "control_commit",
    "control_tree",
    *ARTIFACT_PATHS,
    *STATIC_BINDINGS,
)

REJECTED_ALIASES = frozenset(
    {
        "controller_sha",
        "gate_sha",
        "orchestration_sha",
        "controller_unit_sha",
        "timer_sha",
        "unit_hash",
        "runtime_access",
        "umask",
    }
)


class FreezeError(ValueError):
    """A bounded, safe freeze-contract failure."""


def _git(repo: Path, *arguments: str, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=text,
    )
    return completed.stdout


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def expected_bindings(
    repo: Path,
    control_commit: str,
    application_commit: str = APPLICATION_COMMIT,
    application_tree: str = APPLICATION_TREE,
    static_bindings: Mapping[str, str] = STATIC_BINDINGS,
) -> dict[str, str]:
    commit = str(_git(repo, "rev-parse", f"{control_commit}^{{commit}}")).strip()
    tree = str(_git(repo, "rev-parse", f"{commit}^{{tree}}")).strip()
    values: dict[str, str] = {
        "application_commit": application_commit,
        "application_tree": application_tree,
        "control_commit": commit,
        "control_tree": tree,
    }
    for key, path in ARTIFACT_PATHS.items():
        values[key] = _sha256(bytes(_git(repo, "show", f"{commit}:{path}", text=False)))
    values.update(static_bindings)
    if tuple(values) != REQUIRED_KEYS or len(values) != 29:
        raise FreezeError("S11_2_FREEZE_BINDING_SSOT_RED")
    return values


def controller_binding_keys(source: str) -> tuple[str, ...]:
    try:
        body = source.split("require_local_freeze() {", 1)[1].split(
            "source_access_check() {", 1
        )[0]
    except IndexError as error:
        raise FreezeError("S11_2_FREEZE_CONTROLLER_PARSE_RED") from error
    return tuple(
        re.findall(r'^\s+"([a-z0-9_]+)=', body, flags=re.MULTILINE)
    )


def render_annotation(
    bindings: Mapping[str, str],
    title: str = "TU1NZ S11.2-R15.15.3 profile-scoped Technical freeze",
) -> str:
    if tuple(bindings) != REQUIRED_KEYS:
        raise FreezeError("S11_2_FREEZE_BINDING_SSOT_RED")
    return title + "\n\n" + "".join(
        f"{key}={bindings[key]}\n" for key in REQUIRED_KEYS
    )


def parse_annotation(annotation: str) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    for line in annotation.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed.append((key, value))
    return parsed


def verify_annotation(
    annotation: str, expected: Mapping[str, str]
) -> dict[str, object]:
    parsed = parse_annotation(annotation)
    counts = Counter(key for key, _ in parsed)
    actual = {key: value for key, value in parsed}
    missing = [key for key in REQUIRED_KEYS if counts[key] == 0]
    duplicates = [key for key in REQUIRED_KEYS if counts[key] > 1]
    incorrect = [
        key
        for key in REQUIRED_KEYS
        if counts[key] == 1 and actual.get(key) != expected[key]
    ]
    aliases = sorted(REJECTED_ALIASES.intersection(counts))
    unknown = sorted(
        key for key in counts if key not in REQUIRED_KEYS and key not in REJECTED_ALIASES
    )
    matching = sum(
        counts[key] == 1 and actual.get(key) == expected[key]
        for key in REQUIRED_KEYS
    )
    ok = not (missing or duplicates or incorrect or aliases or unknown) and matching == 29
    return {
        "ok": ok,
        "safe_code": (
            "S11_2_FREEZE_PROVENANCE_GREEN"
            if ok
            else "S11_2_FREEZE_PROVENANCE_RED"
        ),
        "required_count": len(REQUIRED_KEYS),
        "binding_count": len(parsed),
        "matching_count": matching,
        "missing": missing,
        "duplicates": duplicates,
        "incorrect": incorrect,
        "aliases": aliases,
        "unknown": unknown,
    }


def verify_controller_contract(
    repo: Path,
    control_commit: str,
    freeze_tag: str = FREEZE_TAG,
) -> dict[str, object]:
    source = bytes(
        _git(
            repo,
            "show",
            f"{control_commit}:scripts/tu1nz_adult_public_s11_2_control.sh",
            text=False,
        )
    ).decode("utf-8")
    keys = controller_binding_keys(source)
    ok = keys == REQUIRED_KEYS and source.count(f'FINAL_CONTROL_TAG="{freeze_tag}"') == 1
    return {
        "ok": ok,
        "safe_code": (
            "S11_2_FREEZE_CONTROLLER_CONTRACT_GREEN"
            if ok
            else "S11_2_FREEZE_CONTROLLER_CONTRACT_RED"
        ),
        "required_count": len(REQUIRED_KEYS),
        "controller_count": len(keys),
    }


def tag_annotation(repo: Path, tag: str) -> str:
    return str(_git(repo, "for-each-ref", "--format=%(contents)", f"refs/tags/{tag}"))


def verify_tag(repo: Path, tag: str = FREEZE_TAG) -> dict[str, object]:
    tag_type = str(_git(repo, "cat-file", "-t", f"refs/tags/{tag}")).strip()
    target = str(_git(repo, "rev-parse", f"refs/tags/{tag}^{{commit}}")).strip()
    static_bindings = (
        LEGACY_STATIC_BINDINGS if tag == LEGACY_FREEZE_TAG else STATIC_BINDINGS
    )
    expected = expected_bindings(repo, target, static_bindings=static_bindings)
    annotation_report = verify_annotation(tag_annotation(repo, tag), expected)
    controller_report = verify_controller_contract(repo, target, tag)
    ok = tag_type == "tag" and annotation_report["ok"] and controller_report["ok"]
    return {
        "ok": ok,
        "safe_code": (
            "S11_2_FREEZE_TAG_GREEN" if ok else "S11_2_FREEZE_PROVENANCE_RED"
        ),
        "tag": tag,
        "tag_type": tag_type,
        "tag_object": str(_git(repo, "rev-parse", f"refs/tags/{tag}")).strip(),
        "target_commit": target,
        "target_tree": expected["control_tree"],
        "annotation": annotation_report,
        "controller": controller_report,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    generate.add_argument("--repo", type=Path, required=True)
    generate.add_argument("--control-commit", required=True)
    verify = subparsers.add_parser("verify-tag")
    verify.add_argument("--repo", type=Path, required=True)
    verify.add_argument("--tag", default=FREEZE_TAG)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "generate":
            bindings = expected_bindings(arguments.repo, arguments.control_commit)
            controller = verify_controller_contract(arguments.repo, arguments.control_commit)
            if not controller["ok"]:
                raise FreezeError(str(controller["safe_code"]))
            sys.stdout.write(render_annotation(bindings))
            return 0
        report = verify_tag(arguments.repo, arguments.tag)
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0 if report["ok"] else 2
    except (FreezeError, subprocess.CalledProcessError, UnicodeDecodeError):
        print(
            json.dumps(
                {"ok": False, "safe_code": "S11_2_FREEZE_PROVENANCE_RED"},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
