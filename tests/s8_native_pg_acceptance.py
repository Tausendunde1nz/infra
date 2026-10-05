"""Native isolated systemd -> sealed App -> real PostgreSQL acceptance.

Run only in the private CI container with network=none and a disposable
PostgreSQL socket. All state, units, credentials and rows are synthetic.
"""
import array
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, "/source/scripts")
import tu1nz_s8_execution_contract as c
from tu1nz_s8_execution_units import render
import tu1nz_s8_frozen_entry as frozen_entry


def command(*args, check=True, timeout=60):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=check)


def main():
    c.require(os.geteuid() == 0 and os.environ.get("container") == "docker"
              and Path("/.dockerenv").is_file(), "ISOLATED_NATIVE_CONTAINER_REQUIRED")
    image = Path("/capsule.squashfs")
    image_sha = hashlib.sha256(image.read_bytes()).hexdigest()
    metadata = json.loads(command("unsquashfs", "-cat", str(image), "control/capsule.json").stdout)
    migration = command("unsquashfs", "-cat", str(image),
                        "application/migrations/0030_commercial_s10_2d_r3_5_stabilization.sql").stdout
    c.require(hashlib.sha256(migration.encode()).hexdigest() ==
              "9e39223ae7c129355185f2fa48723a4034bfc4a8bb987e448b0d45ac567ed58b", "NATIVE_MIGRATION_RED")
    start = migration.index("CREATE TABLE commercial_s10_2d_bot_polling_state (")
    boundary = migration.index("CREATE FUNCTION tu1nz_s10_2d_guard_bot_polling_state()")
    # Seed only the disposable preexisting-row fixture before installing the
    # exact canonical trigger. Every actual admission runs with that trigger.
    seed = """INSERT INTO commercial_s10_2d_bot_polling_state
      (bot_id,release_id,last_event_path_code,revision,created_at,updated_at,last_successful_poll_at)
      VALUES (8861935205,'s10-2d-r3-5','BOT_POLLER_NOT_RUNNING',277132,
      '2026-10-04T08:49:01.753806+00:00','2026-10-04T08:51:02.165718+00:00',
      '2026-10-04T08:49:01.753806+00:00');\n"""
    setup = ("BEGIN;\nCREATE ROLE tu1nz_adult_commercial_s3_runtime LOGIN;\n" +
             migration[start:boundary] + seed + migration[boundary:])
    admin = "postgresql://tu1nz_test@/tu1nz_s8_exec_native?host=/run/postgresql"
    result = subprocess.run(["/usr/bin/psql", "-X", "-q", "--set=ON_ERROR_STOP=1", admin],
                            input=setup, text=True, capture_output=True, timeout=30)
    c.require(result.returncode == 0, "NATIVE_SCHEMA_RED")
    runtime_dsn = "postgresql://tu1nz_adult_commercial_s3_runtime@/tu1nz_s8_exec_native?host=/run/postgresql"
    unit_paths = []
    temporary = tempfile.TemporaryDirectory(prefix="tu1nz-s8-full-native-", dir="/etc")
    root = Path(temporary.name)
    coordinator = root.name.replace("_", "-") + "-coordinator.service"
    dispatch = root.name.replace("_", "-") + "-dispatch.service"
    c.require(not (Path("/run/systemd/system") / c.UNIT).exists()
              and not (Path("/etc/systemd/system") / c.UNIT).exists(), "NATIVE_UNIT_ALREADY_PRESENT")
    module_sources = {name: (Path("/source/scripts") / (name + ".py")).read_bytes()
                      for name in frozen_entry.MODULES}
    main_source = ("import sys\n" +
        f"sys.argv=['<native-coordinator>',{str(root)!r},sys.argv[1]]\n").encode() + \
        Path("/source/tests/s8_native_pg_coordinator.py").read_bytes()
    expected = {name: hashlib.sha256(source).hexdigest()
                for name, source in {**module_sources, "entry": main_source}.items()}
    frozen_program = frozen_entry.build(module_sources, main_source, expected)
    (root / "fixture.json").write_text(json.dumps(dict(
        coordinator=coordinator, dispatch=dispatch, image_sha256=image_sha,
        application=metadata["application"], sources=metadata["sources"], live_authority=False)))
    (root / "isolation").write_bytes(b"TU1NZ_ISOLATED_NO_PROVIDER\n")
    (root / "dsn").write_text(runtime_dsn)
    (root / "token").write_text("123456789:" + "x" * 35)
    for name in ("dsn", "token"):
        (root / name).chmod(0o600)
    units = render(runtime=c.UNIT, coordinator=coordinator,
                   runtime_user="nobody", runtime_group="nogroup", frozen_program=frozen_program)
    try:
        for name, value in units.items():
            c.require("_" not in name, "NATIVE_UNIT_NAME_RED")
            value = "\n".join(line for line in value.splitlines() if not line.startswith(
                ("ReadWritePaths=", "LoadCredential=", "InaccessiblePaths=")))
            value += "\nReadWritePaths=" + str(root) + "\nEnvironment=container=docker\n"
            if name == c.UNIT:
                value += ("LoadCredential=s8_database_dsn:" + str(root / "dsn") + "\n" +
                          "LoadCredential=s8_telegram_token:" + str(root / "token") + "\n")
            path = Path("/run/systemd/system") / name
            with path.open("x") as stream:
                stream.write(value)
            unit_paths.append(path)
        command("systemctl", "daemon-reload")
        outcome = command("systemctl", "start", coordinator, check=False, timeout=100)
        if outcome.returncode != 0:
            # Synthetic fixture only. Never attach arbitrary real journal data.
            print(command("journalctl", "--no-pager", "-u", coordinator, "-u", c.UNIT, "-n", "45").stdout)
        c.require(outcome.returncode == 0, "NATIVE_SEALED_SQL_CHAIN_RED")
        accepted = json.loads((root / "journal/accepted.json").read_bytes())
        c.require(accepted["live_authority"] is False and accepted["provider_calls"] == 0,
                  "NATIVE_ISOLATION_RED")
        before = {p.name: p.read_bytes() for p in (root / "journal").iterdir()}
        c.require(command("systemctl", "restart", c.UNIT, check=False).returncode != 0,
                  "NATIVE_DIRECT_REPLAY_RED")
        command("systemctl", "stop", c.UNIT)
        command("systemctl", "stop", coordinator)
        # Deliberate loss of PID-1's volatile counters ONLY in this disposable
        # fixture. Production exposes no reset operation. Durable consumption
        # must still prevent a second helper, permit or initial SQL dispatch.
        # An inactive unreferenced unit is normally garbage-collected; targeted
        # ResetFailed then returns "not loaded". Clear volatile failed counters
        # in this freshly created, network-isolated disposable PID 1 only.
        # No production controller exposes this operation. The next assertion
        # requires the durable marker error, not merely any start rejection.
        command("systemctl", "reset-failed")
        stable_sql = command("/usr/bin/psql", "-X", "-qAt", admin, "--command",
            "SELECT row_to_json(s)::text FROM commercial_s10_2d_bot_polling_state s").stdout
        c.require(command("systemctl", "start", coordinator, check=False).returncode != 0,
                  "NATIVE_DURABLE_REPLAY_RED")
        replay_journal = command("journalctl", "--no-pager", "-u", coordinator, "-n", "30").stdout
        c.require("S8_EXECUTION_JOURNAL_ALREADY_PROTECTED" in replay_journal,
                  "NATIVE_REPLAY_NOT_DURABLE_RED")
        c.require(stable_sql == command("/usr/bin/psql", "-X", "-qAt", admin, "--command",
            "SELECT row_to_json(s)::text FROM commercial_s10_2d_bot_polling_state s").stdout,
            "NATIVE_REPLAY_DATABASE_DRIFT")
        c.require(before == {p.name: p.read_bytes() for p in (root / "journal").iterdir()},
                  "NATIVE_REPLAY_JOURNAL_DRIFT")
        print(json.dumps(dict(component="S8_NATIVE_PID1_SEALED_APP_POSTGRES",
            application=metadata["application"], image_sha256=image_sha,
            initial_admission=True, subsequent_polling=True, durable_replay_rejected=True,
            provider_calls=0, live_authority=False, production_entrypoint=False), sort_keys=True))
    finally:
        command("systemctl", "stop", c.UNIT, coordinator, check=False)
        for path in unit_paths:
            path.unlink()
        command("systemctl", "daemon-reload")
        journal = root / "journal"
        objects = list(journal.iterdir()) + [journal] if journal.exists() else []
        for path in [*objects, root]:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                flags = array.array("L", [0])
                fcntl.ioctl(fd, 0x80086601, flags, True)
                flags[0] &= ~0x30
                fcntl.ioctl(fd, 0x40086602, flags)
            finally:
                os.close(fd)
        temporary.cleanup()


if __name__ == "__main__":
    main()
