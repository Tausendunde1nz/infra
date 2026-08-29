#!/usr/bin/env python3
"""Final fail-closed wrapper for one network-free synthetic first start."""

from __future__ import annotations

import argparse
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import tu1nz_adult_commercial_s0_first_start as base


CONTROL_SHA = "3135197ba4ac577bbb7fd28341d0c2dc845a7ebe"
CONTROL_TREE = "da01c5bacb883442e0b556d5e291c8b8206959a2"
ARCHIVE_NAME = "tu1nz_system_backup_20260828T18-15-58Z.tar.gz"
ARCHIVE_SHA256 = "f892758dccf2157b4fa11afa38fe61dfcd36f18076230a76f1d23627bf18afc0"
ARCHIVE_BYTES = 64488092
MANIFEST_SHA256 = "68d8e276b2e0442cc9e02937264c6f493e938f7ab0fc3372239dba69a05a6386"
UNIT_SHA256 = "ff631c7722daf4bd1f1fd9f6a61a1008e10b67f7a683603bec834ecad8722e4d"
RESTORE_EVIDENCE_SHA256 = (
    "013e89b92fda435f978960bb417cf2a7c6da93e6bc5387612b648a2358220b7d"
)
RESTORE_ROOT = Path(
    "/opt/tu1nz_repos/backups/m4-25-commercial-s0-unit-refresh-restore/"
    "20260828T18-35-00Z"
)
RESTORE_EVIDENCE = RESTORE_ROOT / "restore-evidence.txt"
EVIDENCE_PARENT = Path(
    "/opt/tu1nz_repos/backups/final-first-start-readiness"
)


def configure(contract: Path) -> None:
    base.CONTROL_SHA = CONTROL_SHA
    base.CONTROL_TREE = CONTROL_TREE
    base.ARCHIVE_NAME = ARCHIVE_NAME
    base.ARCHIVE_SHA256 = ARCHIVE_SHA256
    base.MANIFEST_SHA256 = MANIFEST_SHA256
    base.UNIT_SHA256 = UNIT_SHA256
    base.CONTROL = base.BASE / "control" / CONTROL_SHA
    base.ARCHIVE = Path("/opt/tu1nz_repos/backups/encrypted-system") / ARCHIVE_NAME
    base.RESTORE_ROOT = RESTORE_ROOT
    base.EVIDENCE_PARENT = EVIDENCE_PARENT
    base.CONTRACT = contract
    base.AUTHORIZATION_GATE = (
        base.CANONICAL_CONTROL
        / "scripts"
        / "tu1nz_adult_commercial_final_first_start_gate.py"
    )
    base.RELEASE_GATE = (
        base.CONTROL / "scripts" / "tu1nz_adult_commercial_s0_release_gate.py"
    )
    base.MIN_MEMORY_AVAILABLE_KIB = 4 * 1024 * 1024


def verify_external_contract(contract: Path) -> None:
    base.require_root()
    try:
        absolute = contract.resolve(strict=True)
        relative = absolute.relative_to(EVIDENCE_PARENT)
    except (OSError, ValueError) as error:
        base.fail("NONCANONICAL_CONTRACT", str(error))
    if len(relative.parts) != 2 or relative.name != "first-start-authorization.json":
        base.fail("NONCANONICAL_CONTRACT", str(absolute))
    for directory in (EVIDENCE_PARENT, absolute.parent):
        metadata = directory.stat()
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            base.fail("CONTRACT_DIRECTORY_UNSAFE", str(directory))
    metadata = absolute.stat()
    if (
        absolute.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        base.fail("CONTRACT_METADATA_UNSAFE", str(absolute))
    payload = base.read_json(absolute, "final first-start authorization")
    if not isinstance(payload, dict) or not isinstance(payload.get("canonical_control"), dict):
        base.fail("CONTRACT_CONTROL_BINDING_INVALID", str(absolute))
    control = payload["canonical_control"]
    if not base.CANONICAL_CONTROL.is_dir() or base.CANONICAL_CONTROL.is_symlink():
        base.fail("CANONICAL_CONTROL_UNSAFE", str(base.CANONICAL_CONTROL))
    if base.git_value(base.CANONICAL_CONTROL, "status", "--porcelain"):
        base.fail("CANONICAL_CONTROL_DIRTY", str(base.CANONICAL_CONTROL))
    if base.git_value(base.CANONICAL_CONTROL, "symbolic-ref", "--short", "HEAD") != "control-main":
        base.fail("CANONICAL_CONTROL_BRANCH_MISMATCH", "control-main required")
    head = base.git_value(base.CANONICAL_CONTROL, "rev-parse", "HEAD")
    tree = base.git_value(base.CANONICAL_CONTROL, "rev-parse", "HEAD^{tree}")
    origin = base.git_value(base.CANONICAL_CONTROL, "rev-parse", "origin/control-main")
    if (
        head != origin
        or control.get("sha") != head
        or control.get("origin_sha") != origin
        or control.get("tree_sha") != tree
        or control.get("branch") != "control-main"
        or control.get("tracked_clean") is not True
    ):
        base.fail("CANONICAL_CONTROL_CONTRACT_DRIFT", str(base.CANONICAL_CONTROL))


def technical_preflight(contract: Path) -> dict[str, object]:
    configure(contract)
    base.require_root()
    base.validate_contract(contract, require_approved=False)
    base.verify_manifest()
    if (
        base.sha256_file(base.ARCHIVE) != ARCHIVE_SHA256
        or base.ARCHIVE.stat().st_size != ARCHIVE_BYTES
    ):
        base.fail("ARCHIVE_BOUNDARY_MISMATCH", str(base.ARCHIVE))
    if (
        not RESTORE_ROOT.is_dir()
        or RESTORE_ROOT.is_symlink()
        or base.sha256_file(RESTORE_EVIDENCE) != RESTORE_EVIDENCE_SHA256
    ):
        base.fail("RESTORE_EVIDENCE_MISSING", str(RESTORE_EVIDENCE))
    base.verify_clean_release(base.APPLICATION, base.APPLICATION_SHA, base.APPLICATION_TREE)
    base.verify_clean_release(base.CONTROL, CONTROL_SHA, CONTROL_TREE)
    if os.readlink(base.BASE / "application-current") != "application/" + base.APPLICATION_SHA:
        base.fail("APPLICATION_LINK_MISMATCH", str(base.BASE))
    if os.readlink(base.BASE / "control-current") != "control/" + CONTROL_SHA:
        base.fail("CONTROL_LINK_MISMATCH", str(base.BASE))
    if os.readlink(base.BASE / "venv-current") != "venv/" + base.APPLICATION_SHA:
        base.fail("VENV_LINK_MISMATCH", str(base.BASE))
    base.run_release_gate()
    unit_state = base.verify_unit()
    base.verify_provider_environment_boundary()
    base.verify_services()
    if base.STATUS_FILE.exists() or base.STATUS_FILE.is_symlink():
        base.fail("PRIOR_RUNTIME_STATUS_PRESENT", str(base.STATUS_FILE))
    if base.LOCK_FILE.exists() or base.LOCK_FILE.is_symlink():
        base.fail("PRIOR_RUNTIME_LOCK_PRESENT", str(base.LOCK_FILE))
    state_sha = base.verify_empty_state()
    database = base.database_snapshot()
    base.verify_initial_database(database)
    checks = (
        ("COMMERCIAL_PROCESS_PRESENT", base.process_references()),
        ("COMMERCIAL_RUNTIME_USER_BUSY", base.runtime_user_processes()),
        ("COMMERCIAL_CRON_PRESENT", base.cron_references()),
        ("COMMERCIAL_CONTAINER_MOUNT_PRESENT", base.docker_mount_references()),
        ("COMMERCIAL_OPEN_FILE_PRESENT", base.open_file_references()),
    )
    for code, references in checks:
        if references:
            base.fail(code, ",".join(map(str, references)))
    tailscale_ip = base.command([base.TAILSCALE, "ip", "-4"]).stdout.splitlines()[0].strip()
    if tailscale_ip != "100.121.130.51":
        base.fail("TAILSCALE_IDENTITY_MISMATCH", tailscale_ip)
    capacity = base.capacity_snapshot()
    contract_device, contract_inode = base.file_identity(contract)
    return {
        "archive_sha256": ARCHIVE_SHA256,
        "application_sha": base.APPLICATION_SHA,
        "canonical_control_sha": base.git_value(base.CANONICAL_CONTROL, "rev-parse", "HEAD"),
        "captured_at": base.utc_now(),
        "contract_sha256": base.sha256_file(contract),
        "contract_identity": {"device": contract_device, "inode": contract_inode},
        "control_sha": CONTROL_SHA,
        "database": database,
        "manifest_sha256": MANIFEST_SHA256,
        "state_sha256": state_sha,
        "tailscale_ipv4": tailscale_ip,
        "unit": unit_state,
        "unit_sha256": UNIT_SHA256,
        **capacity,
    }


def create_evidence_directory() -> Path:
    base.require_root()
    if EVIDENCE_PARENT.exists():
        if EVIDENCE_PARENT.is_symlink() or not EVIDENCE_PARENT.is_dir():
            base.fail("EVIDENCE_ROOT_UNSAFE", str(EVIDENCE_PARENT))
        metadata = EVIDENCE_PARENT.stat()
        if metadata.st_uid != 0 or metadata.st_gid != 0:
            base.fail("EVIDENCE_ROOT_OWNER_MISMATCH", str(EVIDENCE_PARENT))
    else:
        EVIDENCE_PARENT.mkdir(mode=0o700)
    os.chmod(EVIDENCE_PARENT, 0o700)
    run = EVIDENCE_PARENT / datetime.now(timezone.utc).strftime("%Y%m%dT%H-%M-%SZ")
    run.mkdir(mode=0o700)
    os.chmod(run, 0o700)
    return base.safe_evidence_directory(run)


base.verify_canonical_contract = verify_external_contract
base.technical_preflight = technical_preflight
base.create_evidence_directory = create_evidence_directory


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("preflight", "execute", "postcheck", "abort"))
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--before-snapshot", type=Path)
    parser.add_argument("--evidence-directory", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    configure(arguments.contract)
    try:
        if arguments.mode == "preflight":
            technical_preflight(arguments.contract)
            print("FINAL_TECHNICAL_PREFLIGHT_OK_FIRST_START_NOT_EXECUTED")
        elif arguments.mode == "execute":
            evidence = base.execute_window(arguments.contract)
            print("FINAL_FIRST_START_ACCEPTED_STOPPED evidence=" + str(evidence))
        elif arguments.mode == "postcheck":
            base.require_root()
            if arguments.before_snapshot is None:
                base.fail("BEFORE_SNAPSHOT_REQUIRED", "--before-snapshot")
            before = base.load_before_snapshot(arguments.before_snapshot)
            base.postcheck(before)
            print("FINAL_POSTCHECK_OK_STOPPED")
        else:
            base.require_root()
            if arguments.evidence_directory is None:
                base.fail("EVIDENCE_DIRECTORY_REQUIRED", "--evidence-directory")
            evidence = base.safe_evidence_directory(arguments.evidence_directory)
            snapshot = evidence / "preflight.json"
            before = base.load_before_snapshot(snapshot) if snapshot.is_file() else None
            base.abort_window(evidence, "manual operator abort", before)
            print("FINAL_ABORT_COMPLETED_STOPPED evidence=" + str(evidence))
        return 0
    except (base.FirstStartFailure, OSError, TypeError, ValueError) as error:
        code = error.code if isinstance(error, base.FirstStartFailure) else "UNEXPECTED_FAILURE"
        print(
            "FINAL_FIRST_START_BLOCKED code=" + code + " detail=" + str(error),
            file=__import__("sys").stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
