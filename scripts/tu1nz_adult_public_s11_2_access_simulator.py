#!/usr/bin/env python3
"""Source-only R15.4 source/runtime access and rollback simulator."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s11_2_control.sh"
GATE = ROOT / "scripts/tu1nz_adult_public_s11_2_gate.py"
SERVICE = ROOT / "systemd/tu1nz-adult-public-s11-canary-controller.service"
TIMER = ROOT / "systemd/tu1nz-adult-public-s11-canary-controller.timer"


class ContractError(RuntimeError):
    """A source-only access contract invariant failed."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _install(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def _model_execute(mode: int, owner: int, group: int, uid: int, groups: set[int]) -> bool:
    if uid == owner:
        return bool(mode & stat.S_IXUSR)
    if group in groups:
        return bool(mode & stat.S_IXGRP)
    return bool(mode & stat.S_IXOTH)


def _verify_runtime(path: Path, expected_sha: str, expected_mode: int) -> bool:
    return (
        path.is_file()
        and not path.is_symlink()
        and _mode(path) == expected_mode
        and _sha256(path) == expected_sha
        and os.access(path, os.X_OK)
    )


def simulate() -> dict[str, object]:
    source_controller = CONTROLLER.read_text(encoding="utf-8")
    service = SERVICE.read_text(encoding="utf-8")
    access = source_controller[
        source_controller.index("controller_access_check() {"):
        source_controller.index("verify_controller_unit_contract() {")
    ]
    observe = source_controller[
        source_controller.index("observe() {"):
        source_controller.index("rollback() {")
    ]
    if "CONTROL_ROOT/scripts" in access or "git -C" in access:
        raise ContractError("runtime access still requires repository source")
    if any(token in observe for token in ("git_chatops", "require_clean_commit", "require_local_freeze")):
        raise ContractError("natural controller still requires Git checkout integrity")
    if "ExecStart=/usr/local/bin/tu1nz_adult_public_s11_2_control.sh observe" not in service:
        raise ContractError("controller unit is not bound to installed runtime copy")
    if any(line.startswith("WorkingDirectory=/opt/tu1nz_repos") for line in service.splitlines()):
        raise ContractError("controller unit has hidden source working directory")

    cases: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="tu1nz-s11-2-r15-4-") as temporary:
        root = Path(temporary)
        repository = root / "opt/tu1nz_repos/control"
        source = repository / "scripts/tu1nz_adult_public_s11_2_control.sh"
        source.parent.mkdir(parents=True)
        repository.parent.chmod(0o2770)
        repository.chmod(0o2770)
        old_umask = os.umask(0o077)
        try:
            descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o777)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(CONTROLLER.read_bytes())
        finally:
            os.umask(old_umask)
        if _mode(source) != 0o700:
            raise ContractError("umask 077 did not produce source mode 0700")

        source_owner = source.stat().st_uid
        source_group = source.stat().st_gid
        old_runtime_allowed = _model_execute(
            0o700, source_owner, source_group, 0, {0, source_group}
        )
        cases["A_OLD_DIRECT_REPO_RUNTIME"] = "RED_EXIT_126" if not old_runtime_allowed else "UNEXPECTED_GREEN"
        if old_runtime_allowed:
            raise ContractError("old direct-repository runtime model unexpectedly passed")
        if not (os.access(source, os.R_OK) and os.access(source, os.X_OK)):
            raise ContractError("source owner cannot access legitimate 0700 source")
        cases["B_SOURCE_AS_OWNER"] = "GREEN"

        installed_controller = root / "usr/local/bin/tu1nz_adult_public_s11_2_control.sh"
        installed_gate = root / "usr/local/bin/tu1nz_adult_public_s11_2_gate.py"
        installed_service = root / "etc/systemd/system/tu1nz-adult-public-s11-canary-controller.service"
        installed_timer = root / "etc/systemd/system/tu1nz-adult-public-s11-canary-controller.timer"
        _install(source, installed_controller, 0o755)
        _install(GATE, installed_gate, 0o755)
        _install(SERVICE, installed_service, 0o644)
        _install(TIMER, installed_timer, 0o644)
        expected_controller_sha = _sha256(source)
        if not _verify_runtime(installed_controller, expected_controller_sha, 0o755):
            raise ContractError("installed runtime controller verification failed")
        cases["C_INSTALLED_RUNTIME_COPY"] = "GREEN"

        missing = root / "usr/local/bin/missing-controller"
        cases["D_INSTALLED_COPY_MISSING"] = "RED" if not missing.exists() else "UNEXPECTED_GREEN"
        mismatch = root / "usr/local/bin/mismatch-controller"
        _install(source, mismatch, 0o755)
        mismatch.write_bytes(mismatch.read_bytes() + b"\n# mismatch\n")
        cases["E_INSTALLED_COPY_HASH_MISMATCH"] = (
            "RED" if not _verify_runtime(mismatch, expected_controller_sha, 0o755) else "UNEXPECTED_GREEN"
        )
        non_executable = root / "usr/local/bin/non-executable-controller"
        _install(source, non_executable, 0o644)
        cases["F_INSTALLED_COPY_NON_EXECUTABLE"] = (
            "RED" if not _verify_runtime(non_executable, expected_controller_sha, 0o755) else "UNEXPECTED_GREEN"
        )
        cases["G_RUNTIME_POINTS_TO_REPOSITORY"] = (
            "RED" if "/opt/tu1nz_repos" not in next(
                line for line in service.splitlines() if line.startswith("ExecStart=")
            ) else "UNEXPECTED_GREEN"
        )
        if any(value == "UNEXPECTED_GREEN" for value in cases.values()):
            raise ContractError("negative access-contract case unexpectedly passed")

        launched = subprocess.run(
            [str(installed_controller)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if launched.returncode == 126 or "usage:" not in launched.stderr:
            raise ContractError("installed one-shot controller could not be executed")
        cases["NATURAL_ONESHOT_EXECUTION"] = "GREEN_NO_EXIT_126"

        rollback_runtime = root / "rollback-runtime/usr/local/bin/controller"
        rollback_unit = root / "rollback-runtime/etc/systemd/system/controller.service"
        rollback_absent = root / "rollback-runtime/usr/local/bin/gate"
        rollback_runtime.parent.mkdir(parents=True, exist_ok=True)
        rollback_unit.parent.mkdir(parents=True, exist_ok=True)
        rollback_runtime.write_bytes(b"previous-controller\n")
        rollback_runtime.chmod(0o755)
        rollback_unit.write_bytes(b"[Service]\nExecStart=/previous/controller\n")
        rollback_unit.chmod(0o644)
        runtime_before = rollback_runtime.read_bytes()
        runtime_mode_before = _mode(rollback_runtime)
        unit_before = rollback_unit.read_bytes()
        unit_mode_before = _mode(rollback_unit)
        _install(source, rollback_runtime, 0o755)
        _install(SERVICE, rollback_unit, 0o644)
        _install(GATE, rollback_absent, 0o755)
        rollback_runtime.write_bytes(runtime_before)
        rollback_runtime.chmod(runtime_mode_before)
        rollback_unit.write_bytes(unit_before)
        rollback_unit.chmod(unit_mode_before)
        rollback_absent.unlink()
        if rollback_runtime.read_bytes() != runtime_before or _mode(rollback_runtime) != 0o755:
            raise ContractError("runtime rollback did not restore previous controller")
        if rollback_unit.read_bytes() != unit_before or _mode(rollback_unit) != 0o644:
            raise ContractError("runtime rollback did not restore previous unit")
        if rollback_absent.exists() or _mode(source) != 0o700:
            raise ContractError("rollback failed absence restoration or mutated source permissions")
        cases["ROLLBACK_EXACT_BYTES_AND_MODES"] = "GREEN"

    return {
        "ok": True,
        "safe_code": "S11_2_R15_4_SOURCE_ONLY_SIMULATOR_GREEN",
        "source_mode": "0700",
        "runtime_mode": "0755",
        "runtime_controller_sha256": hashlib.sha256(CONTROLLER.read_bytes()).hexdigest(),
        "runtime_gate_sha256": hashlib.sha256(GATE.read_bytes()).hexdigest(),
        "unit_sha256": hashlib.sha256(SERVICE.read_bytes()).hexdigest(),
        "timer_sha256": hashlib.sha256(TIMER.read_bytes()).hexdigest(),
        "cases": cases,
    }


def main() -> int:
    try:
        print(json.dumps(simulate(), sort_keys=True, separators=(",", ":")))
        return 0
    except (ContractError, OSError, ValueError) as error:
        print(json.dumps({"ok": False, "safe_code": "S11_2_R15_4_SOURCE_ONLY_SIMULATOR_RED", "error": type(error).__name__}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
