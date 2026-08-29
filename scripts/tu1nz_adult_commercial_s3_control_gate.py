#!/usr/bin/env python3
"""Offline validation for the versioned Commercial S3 server-staging SSOT."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s3-server-staging.json"
EXPECTED_APPLICATION_SHA = "aba69dfc706fc71e7b1ff12446e5a24f94642762"
EXPECTED_APPLICATION_TREE = "ad67864654c2a1c80b992960163696e20de9998b"
EXPECTED_MIGRATION_DIGEST = "24c116ae3f37eba0be1470f1b401fd4edcb03f8679dd0c95e9881ad20cafb42f"


class GateFailure(RuntimeError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise GateFailure(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(root: Path = ROOT) -> dict[str, object]:
    manifest_path = root / MANIFEST.relative_to(ROOT)
    payload = json.loads(manifest_path.read_text(encoding="ascii"))

    require(payload["version"] == "tu1nz-commercial-s3-server-staging-control-v1", "wrong version")
    require(payload["decision"] == "GO_CONTROLLED_SERVER_STAGING_WINDOW", "wrong decision")
    require(payload["application"]["sha"] == EXPECTED_APPLICATION_SHA, "application SHA drift")
    require(payload["application"]["tree"] == EXPECTED_APPLICATION_TREE, "application tree drift")
    require(payload["control_binding"]["branch"] == "control-main", "wrong Control branch")
    require(payload["control_binding"]["exact_merge_sha_and_tree_required_in_external_contract"], "dynamic Control binding not required")

    authorization = payload["authorization"]
    require(authorization["install_authorized"], "installation not authorized")
    require(authorization["single_bounded_start_authorized"], "single start not authorized")
    require(authorization["single_product_acceptance_authorized"], "single acceptance not authorized")
    require(not authorization["enable_authorized"], "enablement must remain forbidden")
    require(not authorization["restart_authorized"], "restart must remain forbidden")
    require(authorization["stop_required"], "stop is mandatory")
    require(authorization["maximum_window_seconds"] == 1800, "window must be exactly 1800 seconds")

    for artifact in payload["artifacts"].values():
        path = root / artifact["path"]
        require(path.is_file(), f"missing artifact: {path}")
        require(digest(path) == artifact["sha256"], f"artifact hash drift: {path}")

    disabled_contract = json.loads(
        (root / payload["artifacts"]["disabled_contract"]["path"]).read_text(encoding="ascii")
    )
    require(disabled_contract["active"] is False, "committed contract must be inactive")
    require(disabled_contract["decision"] == "NO_GO", "committed contract must remain NO_GO")
    require(disabled_contract["telegram_intake"]["enabled"] is False, "committed intake must be disabled")

    unit = (root / payload["artifacts"]["unit"]["path"]).read_text(encoding="ascii")
    sections = [line.strip() for line in unit.splitlines() if line.startswith("[")]
    require("[Install]" not in sections, "unit must have no Install section")
    require("Restart=no" in unit.splitlines(), "unit must use Restart=no")
    require("RuntimeMaxSec=1800" in unit.splitlines(), "unit window must be bounded")
    require("WantedBy=" not in unit, "unit cannot be enabled")

    database = payload["database"]
    require(database["isolated"], "database must be isolated")
    require(database["business_rows_before_acceptance"] == 0, "database must begin empty")
    require(database["migration_chain_sha256"] == EXPECTED_MIGRATION_DIGEST, "migration digest drift")

    boundary = payload["product_boundary"]
    require(boundary["avs_provider"] == "MOCK", "AVS must remain mock")
    require(boundary["payment_provider"] == "MOCK", "payment must remain mock")
    require(boundary["external_publish_enabled"] is False, "external publishing must remain disabled")
    require(boundary["adult_media_enabled"] is False, "adult media must remain disabled")
    require(boundary["production_enabled"] is False, "production must remain disabled")
    require(all(value == "SYNTHETIC" for value in boundary["publishers"].values()), "publishers must remain synthetic")

    secrets = payload["secret_boundary"]
    require(secrets["mechanism"] == "systemd LoadCredential", "wrong secret mechanism")
    require(secrets["file_mode"] == "0600", "secret files must be private")
    require(secrets["token_value_allowed_in_control"] is False, "token value cannot enter Control")

    return {
        "application_sha": payload["application"]["sha"],
        "application_tree": payload["application"]["tree"],
        "artifact_count": len(payload["artifacts"]),
        "decision": payload["decision"],
        "migration_chain_sha256": database["migration_chain_sha256"],
        "ok": True,
        "production_enabled": boundary["production_enabled"],
        "service_enabled": payload["service"]["enabled"],
    }


def main() -> int:
    try:
        print(json.dumps(validate(), sort_keys=True))
    except (GateFailure, KeyError, TypeError, ValueError, OSError) as exc:
        print(json.dumps({"ok": False, "safe_code": "COMMERCIAL_S3_CONTROL_GATE_FAILED", "detail": str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
