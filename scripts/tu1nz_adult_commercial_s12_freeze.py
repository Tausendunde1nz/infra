#!/usr/bin/env python3
"""Generate and verify the immutable S12 Sandbox-only source freeze."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Mapping, Sequence


FREEZE_TAG = "s12-yoti-sandbox-source-freeze-r1"
APPLICATION_COMMIT = "41340900abdff09a03891761ac114646958eff9a"
APPLICATION_TREE = "b7285dca2218d7249769f5369a53ff8d7e5d6f14"
CONTRACT_VERSION = "tu1nz-commercial-s12-yoti-sandbox-source-v1"

APPLICATION_ARTIFACTS = {
    "application_avs_sha256": "src/tu1nz_s12/avs.py",
    "application_workflow_sha256": "src/tu1nz_s12/workflow.py",
    "application_simulator_sha256": "src/tu1nz_s12/simulator.py",
    "application_tests_sha256": "tests/test_commercial_s12_yoti_sandbox_e2e.py",
    "application_avs_doc_sha256": "docs/COMMERCIAL_S12_YOTI_SANDBOX_AVS_CONTRACT.md",
    "application_workflow_doc_sha256": "docs/COMMERCIAL_S12_SYNTHETIC_END_TO_END_WORKFLOW.md",
}

CONTROL_ARTIFACTS = {
    "control_manifest_sha256": "manifests/adult-publishing-commercial-s12-yoti-sandbox-source.json",
    "control_freeze_tool_sha256": "scripts/tu1nz_adult_commercial_s12_freeze.py",
    "control_test_sha256": "tests/test_adult_commercial_s12_yoti_sandbox_source.py",
    "control_doc_sha256": "docs/COMMERCIAL_S12_YOTI_SANDBOX_SOURCE_CONTROL.md",
}

STATIC_BINDINGS = {
    "contract_version": CONTRACT_VERSION,
    "environment": "SANDBOX",
    "sandbox_only": "true",
    "real_avs_enabled": "false",
    "adult_media_enabled": "false",
    "external_publishing_enabled": "false",
    "payments_enabled": "false",
    "controlled_beta_enabled": "false",
    "production_enabled": "false",
    "runtime_deployed": "false",
    "provider_readiness": "YOTI_SANDBOX_CREDENTIALS_ABSENT",
    "source_readiness": "S12_SANDBOX_SOURCE_GREEN",
    "next_s12_sandbox_runtime_ready": "true",
    "external_blocker": "YOTI_SANDBOX_CREDENTIALS_REQUIRED",
}

REQUIRED_KEYS = (
    "application_commit",
    "application_tree",
    "control_commit",
    "control_tree",
    *APPLICATION_ARTIFACTS,
    *CONTROL_ARTIFACTS,
    *STATIC_BINDINGS,
)

REJECTED_ALIASES = frozenset(
    {
        "app_commit",
        "app_tree",
        "control_sha",
        "avs_hash",
        "workflow_hash",
        "manifest_hash",
        "sandbox",
        "real_avs",
        "runtime",
    }
)


class FreezeError(ValueError):
    """Privacy-safe S12 freeze failure."""


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


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise FreezeError("S12_CONTROL_MANIFEST_DUPLICATE_KEY_RED")
        value[key] = item
    return value


def parse_manifest(payload: str) -> dict[str, object]:
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, FreezeError) as error:
        raise FreezeError("S12_CONTROL_MANIFEST_JSON_RED") from error
    if not isinstance(value, dict):
        raise FreezeError("S12_CONTROL_MANIFEST_ROOT_RED")
    return value


def validate_tagged_manifest(
    control_repo: Path,
    control_commit: str,
) -> dict[str, object]:
    payload = bytes(
        _git(
            control_repo,
            "show",
            f"{control_commit}:manifests/adult-publishing-commercial-s12-yoti-sandbox-source.json",
            text=False,
        )
    ).decode("utf-8")
    report = validate_manifest_payload(payload)
    if not report["ok"]:
        raise FreezeError("S12_FREEZE_TAGGED_MANIFEST_RED")
    return report


def expected_bindings(
    control_repo: Path,
    application_repo: Path,
    control_commit: str,
    application_commit: str = APPLICATION_COMMIT,
) -> dict[str, str]:
    app_commit = str(
        _git(application_repo, "rev-parse", f"{application_commit}^{{commit}}")
    ).strip()
    app_tree = str(_git(application_repo, "rev-parse", f"{app_commit}^{{tree}}")).strip()
    if app_commit != APPLICATION_COMMIT or app_tree != APPLICATION_TREE:
        raise FreezeError("S12_FREEZE_APPLICATION_BINDING_RED")
    ctrl_commit = str(
        _git(control_repo, "rev-parse", f"{control_commit}^{{commit}}")
    ).strip()
    ctrl_tree = str(_git(control_repo, "rev-parse", f"{ctrl_commit}^{{tree}}")).strip()
    validate_tagged_manifest(control_repo, ctrl_commit)
    values: dict[str, str] = {
        "application_commit": app_commit,
        "application_tree": app_tree,
        "control_commit": ctrl_commit,
        "control_tree": ctrl_tree,
    }
    for key, path in APPLICATION_ARTIFACTS.items():
        values[key] = _sha256(
            bytes(_git(application_repo, "show", f"{app_commit}:{path}", text=False))
        )
    for key, path in CONTROL_ARTIFACTS.items():
        values[key] = _sha256(
            bytes(_git(control_repo, "show", f"{ctrl_commit}:{path}", text=False))
        )
    values.update(STATIC_BINDINGS)
    if tuple(values) != REQUIRED_KEYS:
        raise FreezeError("S12_FREEZE_BINDING_SSOT_RED")
    return values


def render_annotation(bindings: Mapping[str, str]) -> str:
    if tuple(bindings) != REQUIRED_KEYS:
        raise FreezeError("S12_FREEZE_BINDING_SSOT_RED")
    title = "TU1NZ S12 Yoti Sandbox-only source freeze"
    return title + "\n\n" + "".join(
        f"{key}={bindings[key]}\n" for key in REQUIRED_KEYS
    )


def parse_annotation(annotation: str) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    for line in annotation.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            parsed.append((key, value))
    return parsed


def verify_annotation(annotation: str, expected: Mapping[str, str]) -> dict[str, object]:
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
    ok = not (missing or duplicates or incorrect or aliases or unknown) and matching == len(
        REQUIRED_KEYS
    )
    return {
        "ok": ok,
        "safe_code": "S12_FREEZE_PROVENANCE_GREEN" if ok else "S12_FREEZE_PROVENANCE_RED",
        "required_count": len(REQUIRED_KEYS),
        "binding_count": len(parsed),
        "matching_count": matching,
        "missing": missing,
        "duplicates": duplicates,
        "incorrect": incorrect,
        "aliases": aliases,
        "unknown": unknown,
    }


def tag_annotation(repo: Path, tag: str) -> str:
    return str(_git(repo, "for-each-ref", "--format=%(contents)", f"refs/tags/{tag}"))


def verify_tag(
    control_repo: Path,
    application_repo: Path,
    tag: str = FREEZE_TAG,
) -> dict[str, object]:
    tag_type = str(_git(control_repo, "cat-file", "-t", f"refs/tags/{tag}")).strip()
    target = str(
        _git(control_repo, "rev-parse", f"refs/tags/{tag}^{{commit}}")
    ).strip()
    expected = expected_bindings(control_repo, application_repo, target)
    annotation = verify_annotation(tag_annotation(control_repo, tag), expected)
    ok = tag_type == "tag" and annotation["ok"]
    return {
        "ok": ok,
        "safe_code": "S12_FREEZE_TAG_GREEN" if ok else "S12_FREEZE_PROVENANCE_RED",
        "tag": tag,
        "tag_type": tag_type,
        "tag_object": str(_git(control_repo, "rev-parse", f"refs/tags/{tag}")).strip(),
        "target_commit": target,
        "target_tree": expected["control_tree"],
        "application_commit": expected["application_commit"],
        "application_tree": expected["application_tree"],
        "annotation": annotation,
    }


def validate_manifest_payload(payload: str) -> dict[str, object]:
    try:
        raw = parse_manifest(payload)
    except FreezeError as error:
        return {
            "ok": False,
            "safe_code": "S12_CONTROL_MANIFEST_RED",
            "failures": [str(error)],
        }
    expected = {
        "application": {"commit": APPLICATION_COMMIT, "tree": APPLICATION_TREE},
        "boundaries": {
            "adult_media_enabled": False,
            "controlled_beta_enabled": False,
            "external_publishing_enabled": False,
            "payments_enabled": False,
            "production_enabled": False,
            "real_avs_enabled": False,
            "sandbox_only": True,
        },
        "contract_version": CONTRACT_VERSION,
        "credentials": {
            "private_key_reference": "/etc/tu1nz/adult-commercial-s5.yoti-private-key",
            "sdk_id_reference": "/etc/tu1nz/adult-commercial-s5.yoti-sdk-id",
            "status": "ABSENT",
            "values_committed": False,
        },
        "decision": "SOURCE_GREEN_RUNTIME_NOT_AUTHORIZED",
        "environment": "SANDBOX",
        "external_blocker": "YOTI_SANDBOX_CREDENTIALS_REQUIRED",
        "feature_flags": {
            "ADULT_MEDIA_ENABLED": False,
            "CONTROLLED_BETA_ENABLED": False,
            "EXTERNAL_PUBLISHING_ENABLED": False,
            "PAYMENTS_ENABLED": False,
            "PRODUCTION_ENABLED": False,
            "REAL_AVS_ENABLED": False,
            "YOTI_SANDBOX_ENABLED": False,
        },
        "network": {
            "allowed_hosts": ["age.yoti.com", "auth.api.yoti.com"],
            "enabled": False,
            "production_endpoint_allowed": False,
        },
        "next_s12_sandbox_runtime_ready": True,
        "provider": "YOTI",
        "provider_readiness": "YOTI_SANDBOX_CREDENTIALS_ABSENT",
        "runtime": {
            "deployed": False,
            "installed": False,
            "started": False,
            "unit_present": False,
        },
        "sandbox_policy": {
            "allowed_methods": ["AGE_ESTIMATION"],
            "provider_result_authority": "AUTHENTICATED_RESULT_FETCH",
            "real_identity_allowed": False,
            "synthetic_subject_only": True,
            "threshold": 18,
        },
        "source_readiness": "S12_SANDBOX_SOURCE_GREEN",
    }
    failures = [
        key
        for key, value in expected.items()
        if json.dumps(raw.get(key), sort_keys=True, separators=(",", ":"))
        != json.dumps(value, sort_keys=True, separators=(",", ":"))
    ]
    failures.extend(f"unexpected:{key}" for key in raw if key not in expected)
    ok = not failures
    return {
        "ok": ok,
        "safe_code": "S12_CONTROL_MANIFEST_GREEN" if ok else "S12_CONTROL_MANIFEST_RED",
        "failures": sorted(set(failures)),
    }


def validate_manifest(path: Path) -> dict[str, object]:
    return validate_manifest_payload(path.read_text(encoding="utf-8"))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    manifest = commands.add_parser("verify-manifest")
    manifest.add_argument("--manifest", type=Path, required=True)
    generate = commands.add_parser("generate")
    generate.add_argument("--control-repo", type=Path, required=True)
    generate.add_argument("--application-repo", type=Path, required=True)
    generate.add_argument("--control-commit", required=True)
    verify = commands.add_parser("verify-tag")
    verify.add_argument("--control-repo", type=Path, required=True)
    verify.add_argument("--application-repo", type=Path, required=True)
    verify.add_argument("--tag", default=FREEZE_TAG)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "verify-manifest":
        report = validate_manifest(arguments.manifest)
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0 if report["ok"] else 1
    if arguments.command == "generate":
        print(
            render_annotation(
                expected_bindings(
                    arguments.control_repo,
                    arguments.application_repo,
                    arguments.control_commit,
                )
            ),
            end="",
        )
        return 0
    report = verify_tag(arguments.control_repo, arguments.application_repo, arguments.tag)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
