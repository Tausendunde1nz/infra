#!/usr/bin/env python3
"""Generate and verify the immutable S12.1 Sandbox runtime freeze."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Mapping, Sequence


FREEZE_TAG = "s12-yoti-sandbox-runtime-freeze-r5"
APPLICATION_COMMIT = "93555d8a141caf8ace33522f9340d30bfc47d2bb"
APPLICATION_TREE = "1e8a644115127818f394b6f9d24f31826e04ecba"
CONTRACT_VERSION = "tu1nz-s12-yoti-sandbox-runtime-v1"
RUNTIME_PYTHON_SHA256 = "1d3cf64f97cadc79fdc6fe2496a21b7b456cb94211978cfef5a65f616af74fd5"
RUNTIME_VENV_SHA256 = "e7a8a8ffa3cba387541f4d0cc0ebea09bd2ade9901c7ab88aaf5e62b3d1df9fa"

APPLICATION_ARTIFACTS = {
    "application_runtime_sha256": "src/tu1nz_s12/runtime.py",
    "application_avs_sha256": "src/tu1nz_s12/avs.py",
    "application_simulator_sha256": "src/tu1nz_s12/simulator.py",
    "application_yoti_adapter_sha256": "src/tu1nz_providers/avs_yoti.py",
    "application_yoti_sandbox_sha256": "src/tu1nz_providers/avs_yoti_sandbox.py",
    "application_runtime_tests_sha256": "tests/test_commercial_s12_1_runtime.py",
    "application_sandbox_tests_sha256": "tests/test_commercial_s12_yoti_sandbox_e2e.py",
    "application_runtime_doc_sha256": "docs/COMMERCIAL_S12_1_YOTI_SANDBOX_RUNTIME.md",
}

CONTROL_ARTIFACTS = {
    "control_manifest_sha256": "manifests/adult-publishing-commercial-s12-1-yoti-sandbox-runtime.json",
    "control_runtime_sha256": "scripts/tu1nz_adult_commercial_s12_1_runtime.py",
    "control_freeze_sha256": "scripts/tu1nz_adult_commercial_s12_1_freeze.py",
    "control_simulator_sha256": "scripts/tu1nz_adult_commercial_s12_1_simulator.py",
    "control_unit_sha256": "systemd/tu1nz-adult-commercial-s12-yoti-runtime.service",
    "control_nginx_sha256": "nginx/current/wantmeseen.s12-1-acceptance.conf",
    "control_base_nginx_sha256": "nginx/current/wantmeseen.s10-1-final.conf",
    "control_tests_sha256": "tests/test_adult_commercial_s12_1_yoti_runtime.py",
    "control_doc_sha256": "docs/COMMERCIAL_S12_1_YOTI_SANDBOX_RUNTIME_CONTROL.md",
    "control_recovery_doc_sha256": "docs/COMMERCIAL_S12_1_R4_GIT_METADATA_RECOVERY_BARRIER.md",
    "control_recovery_diagnosis_sha256": "analysis/COMMERCIAL_S12_1_R4_PRISTINE_ORPHAN_RECOVERY_2026-10-02.diagnose",
}

STATIC_BINDINGS = {
    "contract_version": CONTRACT_VERSION,
    "provider": "YOTI",
    "environment": "SANDBOX",
    "allowed_method": "AGE_ESTIMATION",
    "threshold": "18",
    "sandbox_hosts": "age.yoti.com,auth.api.yoti.com",
    "callback_path": "/avs/sandbox/callback",
    "callback_contract": "SIGNED_TRIGGER_ONLY_AUTHENTICATED_FETCH_AUTHORITATIVE",
    "credential_contract": "SYSTEMD_LOAD_CREDENTIAL_FIXED_REFERENCES",
    "rollback_contract": "EXACTLY_ONCE_BACKUP_FIRST_CONTROLLED_INACTIVE",
    "deployment_contract": "EXACTLY_ONE_NO_HOTFIX_NO_RETRY",
    "recovery_barrier_contract": "GIT_METADATA_SCOPED_TRAVERSAL_PRESERVING",
    "recovery_fix_classification": "PRISTINE_LEGACY_ORPHAN_RELEASE_AND_METADATA_SCOPING_SUFFICIENT",
    "runtime_python_sha256": RUNTIME_PYTHON_SHA256,
    "runtime_venv_sha256": RUNTIME_VENV_SHA256,
    "real_avs_enabled": "false",
    "adult_media_enabled": "false",
    "adult_submission_enabled": "false",
    "community_adult_media_enabled": "false",
    "external_publishing_enabled": "false",
    "payments_enabled": "false",
    "controlled_beta_enabled": "false",
    "production_enabled": "false",
    "final_runtime_posture": "CONTROLLED_INACTIVE",
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
    {"app_commit", "app_tree", "control_sha", "unit_hash", "runtime_hash", "sandbox"}
)


def expected_manifest_contract() -> dict[str, object]:
    """Return the complete immutable manifest, including every nested key."""

    return {
        "application": {
            "commit": APPLICATION_COMMIT,
            "tree": APPLICATION_TREE,
        },
        "callback": {
            "authority": "AUTHENTICATED_RESULT_FETCH_ONLY",
            "bind": "127.0.0.1:18126",
            "body_limit_bytes": 16384,
            "method": "POST",
            "path": "/avs/sandbox/callback",
            "public_url": "https://wantmeseen.com/avs/sandbox/callback",
            "signature": "YOTI_SANDBOX_RSA_PSS_SHA256",
            "trigger_only": True,
        },
        "contract_version": CONTRACT_VERSION,
        "control": {
            "commit_binding": "ANNOTATED_RUNTIME_FREEZE_TARGET",
            "tree_binding": "ANNOTATED_RUNTIME_FREEZE_TARGET_TREE",
        },
        "credentials": {
            "delivery": "SYSTEMD_LOAD_CREDENTIAL",
            "private_key_reference": "/etc/tu1nz/adult-commercial-s5.yoti-private-key",
            "sdk_id_reference": "/etc/tu1nz/adult-commercial-s5.yoti-sdk-id",
            "values_committed": False,
        },
        "decision": "SOURCE_GREEN_RUNTIME_DEPLOYMENT_REQUIRES_EXACT_FREEZE",
        "environment": "SANDBOX",
        "final_posture": {
            "callback": "INACTIVE",
            "runtime": "CONTROLLED_INACTIVE",
            "yoti_sandbox_enabled_for_real_users": False,
        },
        "hard_gates": {
            "adult_media": False,
            "adult_submission": False,
            "community_adult_media": False,
            "controlled_beta": False,
            "external_publishing": False,
            "payments": False,
            "production": False,
            "real_avs": False,
        },
        "health": {
            "credential_values_visible": False,
            "privacy_safe": True,
            "required_safe_code": "S12_RUNTIME_HEALTH_GREEN",
        },
        "network": {
            "allowed_hosts": ["age.yoti.com", "auth.api.yoti.com"],
            "https_only": True,
            "production_endpoint_allowed": False,
            "redirect_to_unknown_host_allowed": False,
        },
        "provider": "YOTI",
        "rollback": {
            "contract": "EXACTLY_ONCE_BACKUP_FIRST_CONTROLLED_INACTIVE",
            "credentials_preserved": True,
            "second_deployment_allowed": False,
        },
        "runtime_environment": {
            "python_sha256": RUNTIME_PYTHON_SHA256,
            "source": "REVIEWED_APPLICATION_VENV_SHA256",
            "venv_sha256": RUNTIME_VENV_SHA256,
        },
        "runtime_freeze": FREEZE_TAG,
        "sandbox_policy": {
            "allowed_methods": ["AGE_ESTIMATION"],
            "provider_result_authority": "AUTHENTICATED_RESULT_FETCH",
            "real_identity_allowed": False,
            "synthetic_subject_only": True,
            "threshold": 18,
        },
        "systemd": {
            "credential_names": [
                "s12-runtime-contract",
                "yoti-private-key",
                "yoti-sdk-id",
            ],
            "unit": "tu1nz-adult-commercial-s12-yoti-runtime.service",
        },
    }


class FreezeError(ValueError):
    """Privacy-safe immutable freeze failure."""


def _git(repo: Path, *arguments: str, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={repo}", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=text,
    )
    return completed.stdout


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise FreezeError("S12_1_CONTROL_MANIFEST_DUPLICATE_KEY_RED")
        value[key] = item
    return value


def parse_manifest(payload: str) -> dict[str, object]:
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicates)
    except (json.JSONDecodeError, FreezeError) as error:
        raise FreezeError("S12_1_CONTROL_MANIFEST_JSON_RED") from error
    if not isinstance(value, dict):
        raise FreezeError("S12_1_CONTROL_MANIFEST_ROOT_RED")
    return value


def _exact_json_equal(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return (
            actual.keys() == expected.keys()
            and all(_exact_json_equal(actual[key], value) for key, value in expected.items())
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _exact_json_equal(actual_item, expected_item)
            for actual_item, expected_item in zip(actual, expected)
        )
    return actual == expected


def validate_manifest_payload(payload: str) -> dict[str, object]:
    try:
        raw = parse_manifest(payload)
        failures = [] if _exact_json_equal(raw, expected_manifest_contract()) else ["contract"]
    except (AttributeError, FreezeError, TypeError):
        failures = ["parse"]
    ok = not failures
    return {
        "ok": ok,
        "safe_code": "S12_1_CONTROL_MANIFEST_GREEN" if ok else "S12_1_CONTROL_MANIFEST_RED",
        "failures": failures,
    }


def validate_manifest(path: Path) -> dict[str, object]:
    return validate_manifest_payload(path.read_text(encoding="utf-8"))


def expected_bindings(
    control_repo: Path,
    application_repo: Path,
    control_commit: str,
) -> dict[str, str]:
    app_commit = str(
        _git(application_repo, "rev-parse", f"{APPLICATION_COMMIT}^{{commit}}")
    ).strip()
    app_tree = str(_git(application_repo, "rev-parse", f"{app_commit}^{{tree}}" )).strip()
    if (app_commit, app_tree) != (APPLICATION_COMMIT, APPLICATION_TREE):
        raise FreezeError("S12_1_APPLICATION_BINDING_RED")
    ctrl_commit = str(_git(control_repo, "rev-parse", f"{control_commit}^{{commit}}" )).strip()
    ctrl_tree = str(_git(control_repo, "rev-parse", f"{ctrl_commit}^{{tree}}" )).strip()
    manifest_payload = bytes(
        _git(
            control_repo,
            "show",
            f"{ctrl_commit}:manifests/adult-publishing-commercial-s12-1-yoti-sandbox-runtime.json",
            text=False,
        )
    ).decode("utf-8")
    if not validate_manifest_payload(manifest_payload)["ok"]:
        raise FreezeError("S12_1_TAGGED_MANIFEST_RED")
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
        raise FreezeError("S12_1_FREEZE_BINDING_SSOT_RED")
    return values


def render_annotation(bindings: Mapping[str, str]) -> str:
    if tuple(bindings) != REQUIRED_KEYS:
        raise FreezeError("S12_1_FREEZE_BINDING_SSOT_RED")
    return "TU1NZ S12.1 Yoti Sandbox runtime freeze\n\n" + "".join(
        f"{key}={bindings[key]}\n" for key in REQUIRED_KEYS
    )


def parse_annotation(annotation: str) -> list[tuple[str, str]]:
    return [tuple(line.split("=", 1)) for line in annotation.splitlines() if "=" in line]


def verify_annotation(annotation: str, expected: Mapping[str, str]) -> dict[str, object]:
    parsed = parse_annotation(annotation)
    counts = Counter(key for key, _ in parsed)
    actual = dict(parsed)
    missing = [key for key in REQUIRED_KEYS if counts[key] == 0]
    duplicates = [key for key in REQUIRED_KEYS if counts[key] > 1]
    incorrect = [
        key for key in REQUIRED_KEYS
        if counts[key] == 1 and actual.get(key) != expected[key]
    ]
    aliases = sorted(REJECTED_ALIASES.intersection(counts))
    unknown = sorted(
        key for key in counts if key not in REQUIRED_KEYS and key not in REJECTED_ALIASES
    )
    matching = sum(
        counts[key] == 1 and actual.get(key) == expected[key] for key in REQUIRED_KEYS
    )
    exact = annotation == render_annotation(expected)
    ok = not (missing or duplicates or incorrect or aliases or unknown) and exact
    return {
        "ok": ok,
        "safe_code": "S12_1_FREEZE_PROVENANCE_GREEN" if ok else "S12_1_FREEZE_PROVENANCE_RED",
        "required_count": len(REQUIRED_KEYS),
        "binding_count": len(parsed),
        "matching_count": matching,
        "format_exact": exact,
        "missing": missing,
        "duplicates": duplicates,
        "incorrect": incorrect,
        "aliases": aliases,
        "unknown": unknown,
    }


def tag_annotation(repo: Path, tag: str) -> str:
    raw = bytes(_git(repo, "cat-file", "tag", f"refs/tags/{tag}", text=False))
    _, separator, message = raw.partition(b"\n\n")
    if not separator:
        raise FreezeError("S12_1_FREEZE_TAG_OBJECT_RED")
    return message.decode("utf-8")


def verify_tag(
    control_repo: Path,
    application_repo: Path,
    tag: str = FREEZE_TAG,
) -> dict[str, object]:
    tag_type = str(_git(control_repo, "cat-file", "-t", f"refs/tags/{tag}" )).strip()
    target = str(_git(control_repo, "rev-parse", f"refs/tags/{tag}^{{commit}}" )).strip()
    expected = expected_bindings(control_repo, application_repo, target)
    annotation = verify_annotation(tag_annotation(control_repo, tag), expected)
    ok = tag_type == "tag" and annotation["ok"]
    return {
        "ok": ok,
        "safe_code": "S12_1_FREEZE_TAG_GREEN" if ok else "S12_1_FREEZE_PROVENANCE_RED",
        "tag": tag,
        "tag_type": tag_type,
        "tag_object": str(_git(control_repo, "rev-parse", f"refs/tags/{tag}" )).strip(),
        "target_commit": target,
        "target_tree": expected["control_tree"],
        "application_commit": expected["application_commit"],
        "application_tree": expected["application_tree"],
        "annotation": annotation,
    }


def main(argv: Sequence[str] | None = None) -> int:
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
    arguments = parser.parse_args(argv)
    try:
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
    except FreezeError as error:
        failure = str(error)
    except subprocess.CalledProcessError:
        failure = "S12_1_FREEZE_GIT_RED"
    except (OSError, UnicodeError):
        failure = "S12_1_FREEZE_IO_RED"
    print(
        json.dumps(
            {"ok": False, "safe_code": "S12_1_FREEZE_PROVENANCE_RED", "failure": failure},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
