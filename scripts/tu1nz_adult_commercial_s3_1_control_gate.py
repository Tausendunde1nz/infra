#!/usr/bin/env python3
"""Offline gate for the Commercial S3.1 bootstrap/ownership server fix."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s3-1-bootstrap-ownership.json"
APPLICATION_SHA = "2ff3af411ed58328ee4189255f13c7d5766552ad"
APPLICATION_TREE = "82b8f5f888309a3dce47f8609c78b96dd1bd2200"
REFERENCE_CANONICAL_SHA256 = "3f7ac26960ac29aea471d33cac634ca1f6e8d572724701cf7fd8268101c0442a"
MIGRATION_SHA256 = "24c116ae3f37eba0be1470f1b401fd4edcb03f8679dd0c95e9881ad20cafb42f"


class GateFailure(RuntimeError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise GateFailure(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(root: Path = ROOT) -> dict[str, object]:
    payload = json.loads((root / MANIFEST.relative_to(ROOT)).read_text(encoding="ascii"))
    require(payload["version"] == "tu1nz-commercial-s3-1-bootstrap-ownership-control-v1", "wrong version")
    require(payload["decision"] == "GO_FOR_S3_1_FIX_INSTALL_AND_EXACTLY_ONE_BOOTSTRAP", "wrong decision")
    application = payload["application"]
    require(application["sha"] == APPLICATION_SHA, "application SHA drift")
    require(application["tree"] == APPLICATION_TREE, "application tree drift")
    require(application["bootstrap_reference_canonical_sha256"] == REFERENCE_CANONICAL_SHA256, "reference digest drift")
    require(payload["control_binding"]["exact_post_merge_sha_and_tree_required_before_server_install"], "post-merge Control binding not required")

    for artifact in payload["artifacts"].values():
        path = root / artifact["path"]
        require(path.is_file() and not path.is_symlink(), f"missing artifact: {path}")
        require(digest(path) == artifact["sha256"], f"artifact hash drift: {path}")

    authorization_path = root / payload["artifacts"]["bootstrap_authorization"]["path"]
    authorization = json.loads(authorization_path.read_text(encoding="ascii"))
    require(authorization["active"] is True, "bootstrap authorization must be active")
    require(authorization["single_bootstrap_authorized"] is True, "single bootstrap not authorized")
    require(authorization["decision"] == "GO_FOR_EXACTLY_ONE_S3_BOOTSTRAP", "wrong bootstrap decision")
    require(authorization["application_sha"] == APPLICATION_SHA, "authorization SHA drift")
    require(authorization["application_tree"] == APPLICATION_TREE, "authorization tree drift")
    require(authorization["bootstrap_reference_sha256"] == REFERENCE_CANONICAL_SHA256, "authorization reference drift")
    require(authorization["migration_chain_sha256"] == MIGRATION_SHA256, "authorization migration drift")
    require(authorization["database_name"] == "tu1nz_adult_commercial_s3", "wrong database")
    require(authorization["database_role"] == "tu1nz_adult_commercial_s3_runtime", "wrong database role")
    required_boundary = {
        "adult_media_enabled": False,
        "avs_provider": "MOCK",
        "external_publish_enabled": False,
        "payment_provider": "MOCK",
        "production_enabled": False,
        "publisher_adapter": "SYNTHETIC",
        "runtime_mode": "STAGING",
        "service_start_authorized": False,
    }
    require(authorization["boundaries"] == required_boundary, "bootstrap product boundary drift")

    bootstrap = payload["bootstrap"]
    require(bootstrap["expected_reference_rows"] == {
        "country_policy_rules": 1,
        "creators": 1,
        "integration_accounts": 3,
        "platform_policy_rules": 3,
        "policy_versions": 1,
        "publication_destinations": 3,
        "total": 12,
    }, "reference row contract drift")
    require([item["name"] for item in bootstrap["destinations"]] == ["REDDIT_TEST", "TELEGRAM_TEST", "X_TEST"], "destination contract drift")
    require(bootstrap["business_rows_after"] == 0 and bootstrap["external_targets_after"] == 0, "business boundary open")

    permissions = payload["authorization"]
    require(permissions["install_authorized"] is True, "install not authorized")
    require(permissions["maximum_bootstrap_invocations"] == 1, "bootstrap is not single-run")
    require(permissions["service_start_authorized"] is False, "service start must remain forbidden")
    require(permissions["restart_authorized"] is False, "restart must remain forbidden")
    require(permissions["service_enable_authorized"] is False, "enablement must remain forbidden")

    state = payload["state_recovery"]
    require(state["runtime_user"] == state["runtime_group"] == "chatops", "wrong runtime identity")
    require(state["legacy_cursor_takeover"] is False, "legacy cursor takeover forbidden")
    require(state["legacy_cursor_preserved_in_recovery_delta"] is True, "legacy cursor not preserved")
    require(state["cursor_created_by_runtime_user"] is True, "cursor not runtime-created")
    require(state["symlinks_allowed"] is False and state["unexpected_paths_allowed"] is False, "state boundary open")

    dependencies = set(payload["prestart"]["required_dependencies"])
    require(dependencies == {
        "allowlist", "application_release", "bootstrap_manifest", "bootstrap_reference_data",
        "business_rows_zero", "cursor_ownership", "database_read_write", "database_schema",
        "harmless_media_manifest", "policy", "runtime_state", "synthetic_creator",
        "synthetic_destinations",
    }, "prestart/runtime parity drift")
    require(payload["prestart"]["external_network"] is False, "prestart network boundary open")
    require(payload["prestart"]["service_started"] is False, "prestart may not start service")

    unit = (root / payload["artifacts"]["unit"]["path"]).read_text(encoding="ascii")
    require("LoadCredential=bootstrap-manifest:" in unit, "bootstrap credential missing")
    require("--bootstrap-manifest %d/bootstrap-manifest" in unit, "bootstrap argument missing")
    unit_lines = unit.splitlines()
    sections = [line.strip() for line in unit_lines if line.startswith("[")]
    require("Restart=no" in unit_lines, "unit restart drift")
    require("[Install]" not in sections, "unit can be enabled")
    require(not any(line.startswith("WantedBy=") for line in unit_lines), "unit can be enabled")

    controller = (root / payload["artifacts"]["server_fix_controller"]["path"]).read_text(encoding="utf-8")
    require(re.search(r"systemctl\s+(start|restart|enable)\b", controller) is None, "controller contains activation")
    require("rm -rf" not in controller and "chown" not in controller, "controller contains unsafe repair")
    require(re.search(r"[0-9]{8,12}:[A-Za-z0-9_-]{30,}", controller) is None, "controller contains token")

    return {
        "application_sha": application["sha"],
        "application_tree": application["tree"],
        "decision": payload["decision"],
        "expected_reference_rows": bootstrap["expected_reference_rows"]["total"],
        "ok": True,
        "service_start_authorized": permissions["service_start_authorized"],
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True))
    except (GateFailure, KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"detail": str(exc), "ok": False, "safe_code": "COMMERCIAL_S3_1_CONTROL_GATE_FAILED"}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
