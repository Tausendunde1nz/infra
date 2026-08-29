#!/usr/bin/env python3
"""Validate the final, external, fail-closed first-start authorization."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class GateFailure(RuntimeError):
    pass


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts" / "tu1nz_adult_commercial_s0_first_start_final.py"
APPLICATION_SHA = "52494d6121660ead53774deb8616701f14bb7a8f"
APPLICATION_TREE = "b2820945c52ffdf77c2f5fbdd227c03ee6b245ab"
INSTALLED_CONTROL_SHA = "3135197ba4ac577bbb7fd28341d0c2dc845a7ebe"
INSTALLED_CONTROL_TREE = "da01c5bacb883442e0b556d5e291c8b8206959a2"
UNIT_SHA256 = "ff631c7722daf4bd1f1fd9f6a61a1008e10b67f7a683603bec834ecad8722e4d"
MANIFEST_SHA256 = "68d8e276b2e0442cc9e02937264c6f493e938f7ab0fc3372239dba69a05a6386"
STATE_SHA256 = "8311a0072ab0e8165d21256e0edb6980bfc1e2acf7abe97b226cfc979545fd12"
ARCHIVE_SHA256 = "f892758dccf2157b4fa11afa38fe61dfcd36f18076230a76f1d23627bf18afc0"
RESTORE_EVIDENCE_SHA256 = (
    "013e89b92fda435f978960bb417cf2a7c6da93e6bc5387612b648a2358220b7d"
)
CONTENT_SHA256 = "1be33016fecef1f1918dbbd505328712ef2c9121c143c1057bdc18aecdc980ed"
SCHEMA_SHA256 = "d14fb552afaebe8ae847eaab46145c9a2d1b1d208fcde9332ef9468c0424223f"
MIN_MEMORY_KIB = 4 * 1024 * 1024
APPROVAL_MAXIMUM_AGE_SECONDS = 3600
PREFLIGHT_APPROVAL_MAXIMUM_GAP_SECONDS = 300
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CLOSED_BLOCKERS = [
    "FIRST_START_NOT_APPROVED",
    "NO_SWAP_RISK_NOT_ACCEPTED_FOR_FIRST_START",
]
RISK_FACTORS = [
    "NO_SWAP_CONFIGURED",
    "NO_CGROUP_MEMORY_MAX_CONFIGURED",
    "NO_EMPIRICAL_FIRST_START_PEAK_RSS",
    "KERNEL_OOM_MAY_AFFECT_CANDIDATE_OR_UNRELATED_PROCESS",
]
MITIGATIONS = [
    "FRESH_PREFLIGHT_REQUIRES_AT_LEAST_4_GIB_AVAILABLE_MEMORY",
    "EXACTLY_ONE_START",
    "RESTART_NO",
    "RUNTIME_MAXIMUM_180_SECONDS",
    "NETWORK_FREE_AND_PROVIDER_DISABLED",
    "ZERO_REAL_MEDIA_AND_ZERO_PROJECTED_SUBMISSIONS",
    "BACKUP_SERVICE_IDLE_AND_NO_OTHER_DATABASE_SESSION",
    "ABORT_REQUIRES_VERIFIED_STOP_AND_NO_SECOND_START",
]
OOM_RECOVERY = [
    "OOM_INVALIDATES_THE_WINDOW",
    "SYSTEMD_MUST_NOT_RESTART_THE_CANDIDATE",
    "CONTROLLER_ATTEMPTS_AND_VERIFIES_STOP",
    "NO_SECOND_START_IS_ALLOWED",
    "JOURNAL_AND_RUNTIME_EVIDENCE_ARE_PRESERVED",
    "HOST_OR_UNRELATED_SERVICE_IMPACT_IS_REPORTED_AS_CRITICAL",
]
PRODUCT_BOUNDARY = {
    "external_providers_enabled": False,
    "network_enabled": False,
    "publishing_enabled": False,
    "real_media_enabled": False,
    "real_payment_enabled": False,
    "synthetic_data_only": True,
    "synthetic_publishers_only": True,
    "telegram_intake_enabled": False,
}
CONTROL_AUTOMATION_HASHES = {
    "/etc/systemd/system/tu1nz_agentmode.service": "cc0ebe655f5fc843e8d8ded5ba321214aed58a8b1062b198606d1667dff356e1",
    "/etc/systemd/system/tu1nz_integrity.service": "cdd3b055c90dcf41f7ba306849e37e4ee9a1b04d96e166753d06e85b5d948692",
    "/etc/systemd/system/tu1nz_monitor.service": "00bbb6a449bda39bfa8fa6b818eb1648fab1ac3ed5bd7fb58451b296374a4547",
    "/usr/local/bin/tu1nz_agent_health.sh": "76476746122f97be5dce43bd7f3053d8b62a5b941b5fc212329c9830d0f79e23",
    "/usr/local/bin/tu1nz_integrity_consolidation.sh": "97cfcd27a13c66088f3dca1becc25417b4f9391223bd2f950415bb1f41214ef2",
    "/usr/local/bin/tu1nz_monitor_wrap.sh": "06d5d803282b9650c5671797639a4718233376206354f2006d2ad10e18699ed6",
    "/usr/local/bin/tu1nz_require_sync.sh": "eb91971c3b5c1cbca7910d5277111780867dc9eb27869402ffaa31b4e08fc80c",
    "/usr/local/bin/tu1nz_sync_all.sh": "96a03614f5c5eacc94576975a7d38251b5cc3da7c673a690914942b298d359df",
}
SERVICES = {
    "tu1nz-adult-publishing-s1.service": {
        "ActiveState": "active", "LoadState": "loaded", "NRestarts": "0",
        "Result": "success", "SubState": "running",
    },
    "tu1nz_agentmode.service": {
        "ActiveState": "active", "LoadState": "loaded", "NRestarts": "0",
        "Result": "success", "SubState": "running",
    },
    "tu1nz_encrypted_backup.service": {
        "ActiveState": "inactive", "LoadState": "loaded", "NRestarts": "0",
        "Result": "success", "SubState": "dead",
    },
    "tu1nz_encrypted_backup.timer": {
        "ActiveState": "active", "LoadState": "loaded", "Result": "success",
        "SubState": "waiting",
    },
    "tu1nz_integrity.service": {
        "ActiveState": "active", "LoadState": "loaded", "NRestarts": "0",
        "Result": "success", "SubState": "exited",
    },
    "tu1nz_monitor.service": {
        "ActiveState": "inactive", "LoadState": "loaded", "NRestarts": "0",
        "Result": "success", "SubState": "dead",
    },
}
SEED_COUNTS = {
    "country_policy_rules": 1,
    "creators": 1,
    "integration_accounts": 3,
    "platform_policy_rules": 3,
    "policy_versions": 1,
    "publication_destinations": 3,
}
BUSINESS_TABLES = {
    "adult_verification_events",
    "adult_verifications",
    "audit_events",
    "command_receipts",
    "commercial_dispatch_entitlements",
    "consent_events",
    "consent_invites",
    "credit_transactions",
    "depicted_persons",
    "external_identities",
    "external_identity_aliases",
    "integration_event_receipts",
    "media_assets",
    "moderation_decisions",
    "payment_attempts",
    "payment_intent_events",
    "payment_intents",
    "payment_provider_event_receipts",
    "payments",
    "platform_dispatch_events",
    "platform_dispatches",
    "platform_provider_receipts",
    "policy_decisions",
    "policy_evaluations",
    "publication_entitlement_events",
    "publication_entitlements",
    "publications",
    "safety_complaint_events",
    "safety_complaints",
    "submission_intake_sessions",
    "submission_state_events",
    "submissions",
    "takedowns",
}
TOP_LEVEL = {
    "active",
    "approval",
    "blockers",
    "candidate",
    "canonical_control",
    "contract_version",
    "database",
    "decision",
    "environment",
    "evidence",
    "first_start_window",
    "no_swap_assessment",
    "product_boundary",
    "recovery",
    "release",
    "sprint",
}
EVIDENCE_TOP_LEVEL = {
    "business_rows_zero",
    "candidate",
    "canonical_control",
    "capacity",
    "control_automation_installed_hashes",
    "control_open_files",
    "control_process_references",
    "database",
    "evidence_version",
    "failed_units",
    "first_start_executed",
    "host",
    "load_average",
    "observed_at",
    "product_boundary",
    "release",
    "services",
    "state_empty",
    "swap_free_kib",
    "technical_checks_passed",
}
RELEASE_KEYS = {
    "application_sha",
    "application_tree_sha",
    "archive",
    "archive_bytes",
    "installed_control_sha",
    "installed_control_tree_sha",
    "links",
    "manifest",
    "restore_evidence_path",
    "restore_evidence_sha256",
    "state",
    "unit",
}
CANDIDATE_KEYS = {
    "ActiveEnterTimestamp",
    "ActiveEnterTimestampMonotonic",
    "ActiveState",
    "ControlPID",
    "ExecMainStartTimestamp",
    "ExecMainStartTimestampMonotonic",
    "LoadState",
    "MainPID",
    "NRestarts",
    "Restart",
    "RuntimeMaxUSec",
    "SubState",
    "TriggeredBy",
    "Triggers",
    "UnitFileState",
    "journal_lines",
    "never_started",
    "runtime_lock_present",
    "runtime_status_present",
    "timers",
}


def read_json(path: Path, *, maximum_bytes: int = 2 * 1024 * 1024) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise GateFailure("safe regular JSON file required")
    if path.stat().st_size > maximum_bytes:
        raise GateFailure("JSON file is too large")
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateFailure("invalid JSON") from error
    if not isinstance(value, dict):
        raise GateFailure("JSON object required")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise GateFailure("exact " + label + " key set required")
    return value


def utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GateFailure(label + " must be UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise GateFailure(label + " is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise GateFailure(label + " must be UTC")
    return parsed


def validate_database(database: object) -> None:
    value = exact(
        database,
        {
            "content_sha256",
            "function_count",
            "other_sessions",
            "schema_sha256",
            "table_count",
            "tables",
        },
        "database",
    )
    tables = value["tables"]
    expected_tables = {**{name: 0 for name in BUSINESS_TABLES}, **SEED_COUNTS}
    if (
        value["table_count"] != 39
        or value["function_count"] != 21
        or value["other_sessions"] != 0
        or value["content_sha256"] != CONTENT_SHA256
        or value["schema_sha256"] != SCHEMA_SHA256
        or tables != expected_tables
    ):
        raise GateFailure("exact synthetic empty database required")


def validate_evidence(evidence: dict[str, Any]) -> datetime:
    exact(evidence, EVIDENCE_TOP_LEVEL, "fresh prestart evidence")
    if evidence.get("evidence_version") != "tu1nz-final-first-start-readiness-fresh-prestart-v1":
        raise GateFailure("fresh prestart evidence version mismatch")
    if evidence.get("technical_checks_passed") is not True or evidence.get("first_start_executed") is not False:
        raise GateFailure("fresh prestart did not remain read-only")
    observed = utc(evidence.get("observed_at"), "prestart observed_at")
    control = exact(
        evidence.get("canonical_control"),
        {"branch", "origin_sha", "sha", "tracked_clean", "tree_sha"},
        "canonical Control evidence",
    )
    if (
        control["branch"] != "control-main"
        or control["tracked_clean"] is not True
        or control["sha"] != control["origin_sha"]
        or SHA40.fullmatch(str(control["sha"])) is None
        or SHA40.fullmatch(str(control["tree_sha"])) is None
    ):
        raise GateFailure("canonical Control evidence mismatch")
    release = exact(evidence.get("release"), RELEASE_KEYS, "release evidence")
    required_release = {
        "application_sha": APPLICATION_SHA,
        "application_tree_sha": APPLICATION_TREE,
        "installed_control_sha": INSTALLED_CONTROL_SHA,
        "installed_control_tree_sha": INSTALLED_CONTROL_TREE,
        "unit": UNIT_SHA256,
        "manifest": MANIFEST_SHA256,
        "state": STATE_SHA256,
        "archive": ARCHIVE_SHA256,
        "archive_bytes": 64488092,
        "restore_evidence_sha256": RESTORE_EVIDENCE_SHA256,
    }
    if any(release.get(key) != value for key, value in required_release.items()):
        raise GateFailure("release, backup or restore evidence mismatch")
    if release["links"] != {
        "application": "application/" + APPLICATION_SHA,
        "control": "control/" + INSTALLED_CONTROL_SHA,
        "venv": "venv/" + APPLICATION_SHA,
    } or release["restore_evidence_path"] != (
        "/opt/tu1nz_repos/backups/m4-25-commercial-s0-unit-refresh-restore/"
        "20260828T18-35-00Z/restore-evidence.txt"
    ):
        raise GateFailure("release links or restore evidence path mismatch")
    candidate = exact(evidence.get("candidate"), CANDIDATE_KEYS, "candidate evidence")
    if (
        candidate.get("never_started") is not True
        or candidate.get("LoadState") != "loaded"
        or candidate.get("ActiveState") != "inactive"
        or candidate.get("SubState") != "dead"
        or candidate.get("UnitFileState") != "static"
        or candidate.get("Restart") != "no"
        or candidate.get("RuntimeMaxUSec") != "3min"
        or candidate.get("NRestarts") != "0"
        or candidate.get("MainPID") != "0"
        or candidate.get("ControlPID") != "0"
        or candidate.get("ExecMainStartTimestamp") != ""
        or candidate.get("ExecMainStartTimestampMonotonic") != "0"
        or candidate.get("ActiveEnterTimestamp") != ""
        or candidate.get("ActiveEnterTimestampMonotonic") != "0"
        or candidate.get("journal_lines") != 0
        or candidate.get("runtime_status_present") is not False
        or candidate.get("runtime_lock_present") is not False
        or candidate.get("TriggeredBy") != ""
        or candidate.get("Triggers") != ""
        or candidate.get("timers") != []
    ):
        raise GateFailure("candidate is not exact never-started boundary")
    validate_database(evidence.get("database"))
    if evidence.get("business_rows_zero") is not True or evidence.get("state_empty") is not True:
        raise GateFailure("database or state is not synthetic empty")
    if evidence.get("product_boundary") != PRODUCT_BOUNDARY:
        raise GateFailure("network-free synthetic product boundary required")
    capacity = evidence.get("capacity")
    if not isinstance(capacity, dict) or (
        not isinstance(capacity.get("memory_available_kib"), int)
        or capacity["memory_available_kib"] < MIN_MEMORY_KIB
        or capacity.get("swap_total_kib") != 0
        or not isinstance(capacity.get("root_available_bytes"), int)
        or capacity["root_available_bytes"] < 1024 * 1024 * 1024
    ):
        raise GateFailure("fresh capacity boundary mismatch")
    if evidence.get("failed_units") != ["tu1nz-doc.service"]:
        raise GateFailure("unexpected failed unit")
    if evidence.get("host") != {
        "hostname": "ubuntu-8gb-nbg1-2",
        "tailscale_ipv4": "100.121.130.51",
    }:
        raise GateFailure("host or Tailscale identity mismatch")
    if evidence.get("services") != SERVICES:
        raise GateFailure("infrastructure service boundary mismatch")
    if evidence.get("control_automation_installed_hashes") != CONTROL_AUTOMATION_HASHES:
        raise GateFailure("Control automation installation drift")
    references = evidence.get("control_process_references")
    if (
        not isinstance(references, list)
        or len(references) != 1
        or re.fullmatch(
            r"[0-9]+ chatops  bash /usr/local/bin/tu1nz_sync_all\.sh --loop",
            str(references[0]),
        ) is None
        or evidence.get("control_open_files") != []
        or evidence.get("swap_free_kib") != 0
    ):
        raise GateFailure("Control observer, open-file or swap boundary mismatch")
    return observed


def validate_contract(
    contract: dict[str, Any],
    *,
    require_approved: bool,
    now: datetime | None = None,
) -> bool:
    if set(contract) != TOP_LEVEL:
        raise GateFailure("exact final authorization key set required")
    if (
        contract["contract_version"] != "tu1nz-commercial-final-first-start-authorization-v1"
        or contract["sprint"] != "FINAL_FIRST_START_READINESS"
        or contract["environment"] != "STAGING-S0-COMMERCIAL-CANDIDATE"
        or type(contract["active"]) is not bool
    ):
        raise GateFailure("final authorization identity mismatch")
    approval = exact(
        contract["approval"],
        {"approved_at", "first_start_approved", "no_swap_risk_accepted", "operator_accepted"},
        "approval",
    )
    evidence_binding = exact(
        contract["evidence"],
        {
            "fresh_prestart_path",
            "fresh_prestart_sha256",
            "observed_at",
            "preflight_to_approval_maximum_seconds",
        },
        "evidence binding",
    )
    evidence_path = Path(str(evidence_binding["fresh_prestart_path"]))
    if sha256(evidence_path) != evidence_binding["fresh_prestart_sha256"]:
        raise GateFailure("fresh prestart evidence digest mismatch")
    evidence = read_json(evidence_path)
    observed = validate_evidence(evidence)
    if (
        evidence_binding["observed_at"] != evidence["observed_at"]
        or evidence_binding["preflight_to_approval_maximum_seconds"]
        != PREFLIGHT_APPROVAL_MAXIMUM_GAP_SECONDS
    ):
        raise GateFailure("fresh prestart evidence binding mismatch")
    if contract["canonical_control"] != evidence["canonical_control"]:
        raise GateFailure("canonical Control contract drift")
    if contract["candidate"] != evidence["candidate"]:
        raise GateFailure("candidate contract drift")
    if contract["database"] != evidence["database"]:
        raise GateFailure("database contract drift")
    if contract["product_boundary"] != PRODUCT_BOUNDARY:
        raise GateFailure("product boundary contract drift")
    release = exact(contract["release"], RELEASE_KEYS, "release")
    if release != evidence["release"]:
        raise GateFailure("release contract drift")
    window = contract["first_start_window"]
    if window != {
        "approval_maximum_age_seconds": APPROVAL_MAXIMUM_AGE_SECONDS,
        "health_maximum_age_seconds": 90,
        "maximum_runtime_seconds": 180,
        "must_end_stopped": True,
        "ready_timeout_seconds": 60,
        "single_controlled_start": True,
        "stop_timeout_seconds": 45,
    }:
        raise GateFailure("exact first-start window required")
    assessment = exact(
        contract["no_swap_assessment"],
        {
            "mitigations",
            "observed_memory_available_kib",
            "observed_swap_total_kib",
            "oom_recovery",
            "operator_accepted",
            "recommendation",
            "required_memory_available_kib",
            "risk_factors",
            "scope",
        },
        "no-swap assessment",
    )
    if (
        assessment.get("recommendation") != "ACCEPTABLE_FOR_ONE_CONTROLLED_FIRST_START"
        or assessment.get("operator_accepted") is not contract["approval"].get("no_swap_risk_accepted")
        or assessment.get("observed_memory_available_kib")
        != evidence["capacity"]["memory_available_kib"]
        or assessment.get("observed_swap_total_kib") != 0
        or assessment.get("required_memory_available_kib") != MIN_MEMORY_KIB
        or assessment.get("risk_factors") != RISK_FACTORS
        or assessment.get("mitigations") != MITIGATIONS
        or assessment.get("oom_recovery") != OOM_RECOVERY
        or assessment.get("scope") != "ONE_SYNTHETIC_NETWORK_FREE_FIRST_START_ONLY"
    ):
        raise GateFailure("no-swap assessment drift")
    recovery = exact(
        contract["recovery"],
        {
            "abort_must_stop_unit",
            "controller_path",
            "controller_sha256",
            "forbid_second_start",
            "gate_path",
            "gate_sha256",
            "preserve_database_state_and_evidence",
        },
        "recovery",
    )
    if (
        recovery.get("controller_path")
        != "scripts/tu1nz_adult_commercial_s0_first_start_final.py"
        or recovery.get("controller_sha256") != sha256(CONTROLLER)
        or recovery.get("gate_path")
        != "scripts/tu1nz_adult_commercial_final_first_start_gate.py"
        or recovery.get("gate_sha256") != sha256(Path(__file__).resolve())
        or recovery.get("abort_must_stop_unit") is not True
        or recovery.get("forbid_second_start") is not True
        or recovery.get("preserve_database_state_and_evidence") is not True
    ):
        raise GateFailure("abort controller binding drift")
    approved = contract["active"] is True
    current = now or datetime.now(timezone.utc)
    if approved:
        approved_at = utc(approval["approved_at"], "approved_at")
        if (
            contract["decision"] != "GO_FOR_ONE_CONTROLLED_NETWORK_FREE_FIRST_START"
            or contract["blockers"] != []
            or approval["first_start_approved"] is not True
            or approval["no_swap_risk_accepted"] is not True
            or approval["operator_accepted"] is not True
            or approved_at < observed
            or approved_at - observed
            > timedelta(seconds=PREFLIGHT_APPROVAL_MAXIMUM_GAP_SECONDS)
            or approved_at > current + timedelta(seconds=5)
            or current - approved_at > timedelta(seconds=APPROVAL_MAXIMUM_AGE_SECONDS)
        ):
            raise GateFailure("complete fresh operator approval required")
    elif (
        contract["decision"] != "NO_GO"
        or contract["blockers"] != CLOSED_BLOCKERS
        or approval
        != {
            "approved_at": None,
            "first_start_approved": False,
            "no_swap_risk_accepted": False,
            "operator_accepted": False,
        }
    ):
        raise GateFailure("committed final authorization must remain closed")
    if require_approved and not approved:
        raise GateFailure("FIRST_START_NOT_APPROVED")
    return approved


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--require-approved", action="store_true")
    parser.add_argument("--now")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        current = utc(arguments.now, "now") if arguments.now else None
        approved = validate_contract(
            read_json(arguments.contract),
            require_approved=arguments.require_approved,
            now=current,
        )
    except (GateFailure, OSError, TypeError, ValueError) as error:
        print("FINAL_FIRST_START_BLOCKED " + str(error), file=sys.stderr)
        return 1
    print(
        "FINAL_FIRST_START_AUTHORIZED"
        if approved
        else "FINAL_FIRST_START_CONTRACT_VALID_NO_GO"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
