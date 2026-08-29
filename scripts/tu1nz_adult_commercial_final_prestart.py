#!/usr/bin/env python3
"""Capture the final read-only first-start evidence into one private file."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import tu1nz_adult_commercial_final_first_start_contract as contract_builder
import tu1nz_adult_commercial_final_first_start_gate as gate
import tu1nz_adult_commercial_s0_first_start as base
import tu1nz_adult_commercial_s0_first_start_final as final


SERVICE_PROPERTIES = ("LoadState", "ActiveState", "SubState", "Result", "NRestarts")
CANDIDATE_PROPERTIES = (
    "LoadState", "ActiveState", "SubState", "UnitFileState", "Restart",
    "RuntimeMaxUSec", "NRestarts", "MainPID", "ControlPID",
    "ExecMainStartTimestamp", "ExecMainStartTimestampMonotonic",
    "ActiveEnterTimestamp", "ActiveEnterTimestampMonotonic", "TriggeredBy", "Triggers",
)


def systemd_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
    result = base.command(
        [base.SYSTEMCTL, "show", unit, *["--property=" + item for item in properties]]
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    if set(values) != set(properties):
        base.fail("SYSTEMD_PROPERTY_SET_MISMATCH", unit)
    return values


def candidate() -> dict[str, object]:
    values: dict[str, object] = systemd_properties(base.UNIT, CANDIDATE_PROPERTIES)
    journal = base.command(
        [base.JOURNALCTL, "-u", base.UNIT, "--no-pager", "--output=cat"],
        check=False,
    )
    timers = [
        line for line in base.command(
            [base.SYSTEMCTL, "list-timers", "--all", "--no-legend", "--no-pager"]
        ).stdout.splitlines()
        if base.UNIT in line
    ]
    values.update(
        {
            "journal_lines": len([line for line in journal.stdout.splitlines() if line]),
            "never_started": (
                values["NRestarts"] == "0"
                and values["ExecMainStartTimestamp"] == ""
                and values["ExecMainStartTimestampMonotonic"] == "0"
                and values["ActiveEnterTimestamp"] == ""
                and values["ActiveEnterTimestampMonotonic"] == "0"
                and not journal.stdout.strip()
            ),
            "runtime_lock_present": base.LOCK_FILE.exists() or base.LOCK_FILE.is_symlink(),
            "runtime_status_present": base.STATUS_FILE.exists() or base.STATUS_FILE.is_symlink(),
            "timers": timers,
        }
    )
    return values


def service_states() -> dict[str, object]:
    result: dict[str, object] = {}
    for unit in gate.SERVICES:
        properties = SERVICE_PROPERTIES
        if unit.endswith(".timer"):
            properties = tuple(item for item in SERVICE_PROPERTIES if item != "NRestarts")
        result[unit] = systemd_properties(unit, properties)
    return result


def failed_units() -> list[str]:
    output = base.command(
        [base.SYSTEMCTL, "--failed", "--plain", "--no-legend", "--no-pager"],
        check=False,
    ).stdout
    return sorted(line.split()[0] for line in output.splitlines() if line.strip())


def control_process_references() -> list[str]:
    output = base.command(["/bin/ps", "-eo", "pid=,user=,args="]).stdout
    references: list[str] = []
    for line in output.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) == 3 and "/usr/local/bin/tu1nz_sync_all.sh --loop" in fields[2]:
            references.append(fields[0] + " " + fields[1] + "  " + fields[2])
    return references


def control_open_files() -> list[str]:
    result = base.command(
        [base.LSOF, "-Fn", "+D", str(base.CANONICAL_CONTROL)],
        check=False,
        timeout=30,
    )
    if result.returncode not in {0, 1}:
        base.fail("CONTROL_OPEN_FILE_CHECK_FAILED", str(base.CANONICAL_CONTROL))
    return sorted(line for line in result.stdout.splitlines() if line.startswith("p"))


def build_evidence() -> dict[str, object]:
    final.configure(Path("/nonexistent/closed-contract"))
    base.require_root()
    base.verify_manifest()
    if (
        base.sha256_file(base.ARCHIVE) != final.ARCHIVE_SHA256
        or base.ARCHIVE.stat().st_size != final.ARCHIVE_BYTES
        or base.sha256_file(final.RESTORE_EVIDENCE) != final.RESTORE_EVIDENCE_SHA256
    ):
        base.fail("BACKUP_OR_RESTORE_BOUNDARY_MISMATCH", str(base.ARCHIVE))
    base.verify_clean_release(base.APPLICATION, base.APPLICATION_SHA, base.APPLICATION_TREE)
    base.verify_clean_release(base.CONTROL, final.CONTROL_SHA, final.CONTROL_TREE)
    base.run_release_gate()
    base.verify_unit()
    base.verify_provider_environment_boundary()
    base.verify_services()
    state_sha = base.verify_empty_state()
    database = base.database_snapshot()
    base.verify_initial_database(database)
    for code, references in (
        ("COMMERCIAL_PROCESS_PRESENT", base.process_references()),
        ("COMMERCIAL_RUNTIME_USER_BUSY", base.runtime_user_processes()),
        ("COMMERCIAL_CRON_PRESENT", base.cron_references()),
        ("COMMERCIAL_CONTAINER_MOUNT_PRESENT", base.docker_mount_references()),
        ("COMMERCIAL_OPEN_FILE_PRESENT", base.open_file_references()),
    ):
        if references:
            base.fail(code, ",".join(map(str, references)))
    capacity = base.capacity_snapshot()
    control = {
        "branch": base.git_value(base.CANONICAL_CONTROL, "symbolic-ref", "--short", "HEAD"),
        "origin_sha": base.git_value(base.CANONICAL_CONTROL, "rev-parse", "origin/control-main"),
        "sha": base.git_value(base.CANONICAL_CONTROL, "rev-parse", "HEAD"),
        "tracked_clean": base.git_value(base.CANONICAL_CONTROL, "status", "--porcelain") == "",
        "tree_sha": base.git_value(base.CANONICAL_CONTROL, "rev-parse", "HEAD^{tree}"),
    }
    tailscale_ip = base.command([base.TAILSCALE, "ip", "-4"]).stdout.splitlines()[0].strip()
    load_one, load_five, load_fifteen = os.getloadavg()
    payload: dict[str, object] = {
        "business_rows_zero": True,
        "candidate": candidate(),
        "canonical_control": control,
        "capacity": capacity,
        "control_automation_installed_hashes": {
            path: base.sha256_file(Path(path)) for path in gate.CONTROL_AUTOMATION_HASHES
        },
        "control_open_files": control_open_files(),
        "control_process_references": control_process_references(),
        "database": database,
        "evidence_version": "tu1nz-final-first-start-readiness-fresh-prestart-v1",
        "failed_units": failed_units(),
        "first_start_executed": False,
        "host": {"hostname": os.uname().nodename, "tailscale_ipv4": tailscale_ip},
        "load_average": {"fifteen": load_fifteen, "five": load_five, "one": load_one},
        "observed_at": base.utc_now(),
        "product_boundary": dict(gate.PRODUCT_BOUNDARY),
        "release": {
            "application_sha": base.APPLICATION_SHA,
            "application_tree_sha": base.APPLICATION_TREE,
            "archive": final.ARCHIVE_SHA256,
            "archive_bytes": final.ARCHIVE_BYTES,
            "installed_control_sha": final.CONTROL_SHA,
            "installed_control_tree_sha": final.CONTROL_TREE,
            "links": {
                "application": os.readlink(base.BASE / "application-current"),
                "control": os.readlink(base.BASE / "control-current"),
                "venv": os.readlink(base.BASE / "venv-current"),
            },
            "manifest": final.MANIFEST_SHA256,
            "restore_evidence_path": str(final.RESTORE_EVIDENCE),
            "restore_evidence_sha256": final.RESTORE_EVIDENCE_SHA256,
            "state": state_sha,
            "unit": final.UNIT_SHA256,
        },
        "services": service_states(),
        "state_empty": True,
        "swap_free_kib": 0,
        "technical_checks_passed": True,
    }
    gate.validate_evidence(payload)
    return payload


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        contract_builder.write_private(arguments.output, build_evidence())
    except (base.FirstStartFailure, gate.GateFailure, OSError, TypeError, ValueError) as error:
        print("FINAL_PRESTART_BLOCKED " + str(error))
        return 1
    print(
        "FINAL_PRESTART_OK_FIRST_START_NOT_EXECUTED path="
        + str(arguments.output)
        + " sha256="
        + gate.sha256(arguments.output)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
