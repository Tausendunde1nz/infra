"""Production provisioning/admission functions in a fresh netless test host.

Substitutions: synthetic incident UUID and historical Git/journal fixtures,
peer-auth database address, empty provider responses/unrelated store, public
HTTP response fixture. No lease/permission/journal/systemd/kernel predicate is
mocked. The production provisioner, coordinator, unit renderer and launcher run
unchanged. Test-only module trailers adapt external interfaces, never a live API.
"""
import array
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/source/scripts")
sys.path.insert(0, "/source")
import tu1nz_s8_execution_contract as c
import tu1nz_s8_execution_observer as observer
import tu1nz_s8_execution_release as release
import tu1nz_s8_provision as provision
from tu1nz_s8_execution_units import COORDINATOR
from tu1nz_s8_runtime_interfaces import CONFIG_NAMES

FIXTURE = Path("/etc/tu1nz-s8-provision-native-fixture")
ADMIN = "postgresql://tu1nz_test@/tu1nz_s8_exec_native?host=/run/postgresql"


def cmd(argv, *, input=None, check=True):
    return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=45, check=check)


def sql(query):
    return cmd(["/usr/bin/psql", "-X", "-qAt", "--set=ON_ERROR_STOP=1", ADMIN], input=query).stdout


def until(check, seconds=30):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        if check(): return
        time.sleep(.1)
    raise AssertionError("NATIVE_PHASE_DEADLINE")


def empty_git(root):
    root.mkdir(parents=True)
    root.parent.chmod(0o755); root.chmod(0o755)
    cmd(["git", "init", "--quiet", str(root)])
    (root/"synthetic").write_bytes(b"synthetic historical fixture, no real recovery\n")
    cmd(["git", "-C", str(root), "add", "synthetic"])
    cmd(["git", "-C", str(root), "-c", "user.name=Synthetic", "-c", "user.email=fixture@example.invalid",
         "commit", "--quiet", "-m", "synthetic historical identity"])
    pair = tuple(cmd(["git", "-C", str(root), "rev-parse", ref]).stdout.strip() for ref in ("HEAD", "HEAD^{tree}"))
    (root/".git").rename(root/".git.s12-1-recovery")
    (root/".git.s12-1-recovery").chmod(0o700)
    (root/".git").mkdir(mode=0)
    return pair


def setup(image):
    c.require(not FIXTURE.exists() and not observer.ROOT.exists(), "NATIVE_FRESH_HOST_REQUIRED")
    FIXTURE.mkdir(mode=0o700)
    (FIXTURE/"isolation").write_bytes(b"TU1NZ_ISOLATED_NO_PROVIDER\n")
    cmd(["useradd", "--system", "--no-create-home", "--user-group", "chatops"])
    metadata = json.loads(cmd(["unsquashfs", "-cat", str(image), "control/capsule.json"]).stdout)
    migration = cmd(["unsquashfs", "-cat", str(image),
                    "application/migrations/0030_commercial_s10_2d_r3_5_stabilization.sql"]).stdout
    c.require(hashlib.sha256(migration.encode()).hexdigest() ==
              "9e39223ae7c129355185f2fa48723a4034bfc4a8bb987e448b0d45ac567ed58b", "NATIVE_MIGRATION_RED")
    start = migration.index("CREATE TABLE commercial_s10_2d_bot_polling_state (")
    boundary = migration.index("CREATE FUNCTION tu1nz_s10_2d_guard_bot_polling_state()")
    seed = """INSERT INTO commercial_s10_2d_bot_polling_state
      (bot_id,release_id,last_event_path_code,revision,created_at,updated_at,last_successful_poll_at)
      VALUES (8861935205,'s10-2d-r3-5','BOT_POLLER_NOT_RUNNING',277132,
      '2026-10-04T08:49:01.753806+00:00','2026-10-04T08:51:02.165718+00:00',
      '2026-10-04T08:49:01.753806+00:00');\n"""
    sql("BEGIN; CREATE ROLE tu1nz_adult_commercial_s3_runtime LOGIN;\n"+migration[start:boundary]+seed+migration[boundary:])
    # Only the exact columns read by the production readonly aggregate; no
    # identity, messages, notifications, media, provider or real-user records.
    sql("""CREATE TABLE commercial_s11_runtime_control(singleton boolean,enabled boolean,release_state text,
      promotion_state text,community_user_content_publishing_enabled boolean,adult_media_enabled boolean,
      real_avs_enabled boolean,payments_enabled boolean,external_publishing_enabled boolean,
      controlled_beta_enabled boolean,production_enabled boolean);
      INSERT INTO commercial_s11_runtime_control VALUES(true,false,'S11_DISABLED','CANARY_RED',false,false,false,false,false,false,false);
      CREATE TABLE commercial_s10_2d_runtime_control(singleton boolean,wms_real_acquisition_ready boolean,
        real_acquisition_baseline_start timestamptz);
      INSERT INTO commercial_s10_2d_runtime_control VALUES(true,true,'2026-09-18T00:41:06.710027+00:00');""")
    pairs = {text: empty_git(Path(text)) for text in observer.HISTORICAL_ROOTS}
    # The actual unchanged historical unit fails exactly once, from its real
    # ExecStart pathname. Only that pathname's synthetic fixture returns 2.
    executable = Path("/opt/tu1nz_repos/adult-publishing-core/.venv/bin/tu1nz-public-s8-telegram")
    executable.parent.mkdir(parents=True)
    executable.parent.parent.chmod(0o755); executable.parent.chmod(0o755)
    executable.write_text("#!/bin/sh\nexit 2\n"); executable.chmod(0o755)
    observer.HISTORY.mkdir(parents=True)
    hashes = {}
    for name in observer.HISTORY_HASHES:
        data = c.canonical(dict(synthetic=True, object=name, historical_cause="UNKNOWN"))
        (observer.HISTORY/name).write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    config_root = Path("/etc/tu1nz")
    names = ("commercial-s8-public-telegram-early-access.sfw.json", "commercial-s8-public-telegram-copy.v1.json",
             "commercial-s10-2d-community.sfw.json", "commercial-s10-2d-community-copy.v1.json",
             "commercial-s11-interactive-experience.sfw.json", "commercial-s11-interactive-copy.v1.json")
    configs = {}
    for target, source in zip(CONFIG_NAMES, names):
        payload = cmd(["unsquashfs", "-cat", str(image), "application/config/"+source]).stdout.encode()
        (config_root/target).write_bytes(payload)
        configs[target] = hashlib.sha256(payload).hexdigest()
    for name, payload in {
        "adult-commercial-s10-2b-telegram.token": "123456789:"+"x"*35,
        "adult-commercial-s7-database.dsn": "postgresql://tu1nz_adult_commercial_s3_runtime@/tu1nz_s8_exec_native?host=/run/postgresql",
    }.items():
        (config_root/name).write_text(payload); (config_root/name).chmod(0o600)
    for unit in observer.PUBLIC_UNITS:
        Path("/etc/systemd/system", unit).write_text("[Service]\nExecStart=/usr/bin/sleep infinity\n")
    observer.BASE_UNIT.write_bytes((Path("/source/systemd")/c.UNIT).read_bytes())
    cmd(["systemctl", "daemon-reload"])
    cmd(["systemctl", "start", *observer.PUBLIC_UNITS])
    cmd(["systemctl", "start", c.UNIT], check=False)
    until(lambda: observer.service(c.UNIT)["ActiveState"] == "failed")
    invocation = observer.service(c.UNIT)["InvocationID"]
    return metadata, pairs, hashes, configs, invocation


def main():
    c.require(os.geteuid() == 0 and os.environ.get("container") == "docker" and Path("/.dockerenv").is_file(),
              "ISOLATED_NATIVE_CONTAINER_REQUIRED")
    os.umask(0o077)
    mode = sys.argv[1] if len(sys.argv) == 2 else "success"
    c.require(mode in {"success", "unknown-start"}, "NATIVE_MODE_RED")
    image = Path("/capsule.squashfs")
    metadata, pairs, hashes, configs, incident = setup(image)
    core_trailer = (f"\nFAILED_INVOCATION={incident!r}\nHISTORICAL_APPLICATION={pairs['/opt/tu1nz_repos/adult-publishing-core']!r}\n"
                    f"HISTORICAL_CONTROL={pairs['/opt/tu1nz_repos/control']!r}\n").encode()
    observer_trailer = (f"\nHISTORY_HASHES={hashes!r}\nHISTORICAL_ROOTS={pairs!r}\n"+f"""
_native_original_command=command
def command(argv, *, input=None, timeout=15):
    if argv[:5]==['/usr/sbin/runuser','-u','postgres','--','/usr/bin/psql']:
        return _native_original_command(['/usr/bin/psql','-X','-qAt','--set=ON_ERROR_STOP=1',{ADMIN!r}],input=input,timeout=timeout)
    if argv and argv[0]=='/usr/bin/curl':
        require_url=argv[-1]
        c.require(require_url in {{'https://wantmeseen.com/','https://wantmeseen.com/health','https://wantmeseen.com/privacy',
          'https://wantmeseen.com/terms','https://wantmeseen.com/imprint','https://wantmeseen.de/'}},'NATIVE_URL_RED')
        return '308' if require_url=='https://wantmeseen.de/' else '200'
    return _native_original_command(argv,input=input,timeout=timeout)
_native_original_pollers=recognized_pollers
def recognized_pollers():
    result=_native_original_pollers()
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:
            before=(p/'stat').read_text().rpartition(')')[2].split()
            if b'/application/tests/execution_root/native_admission_probe.py' in (p/'cmdline').read_bytes().split(b'\\0'):
                identity=c.process_identity(int(p.name))
                c.require(identity['start_ticks']==int(before[19]) and c.process_identity(int(p.name))==identity,'NATIVE_PROCESS_DRIFT')
                result.append(identity)
        except FileNotFoundError:continue
    return result
""").encode()
    sealed_trailer = b'''
# Isolated provider/store harness only; launcher/metadata/UID/capability/mount
# code stays real. The ordinary product entrypoint is never given this switch.
def enter_capsule(mounted, *, uid, gid, image_sha256, argv, environment):
    require(argv[:5]==['/usr/bin/python3','-I','-B','-S','/control/tu1nz_s8_capsule_bootstrap.py']
      and '--recovery-admission' in argv and '--runtime-release-id' in argv,'NATIVE_PRODUCT_ARGV_RED')
    bind_readonly(Path('/etc/tu1nz-s8-provision-native-fixture/isolation'),mounted.destination/'run/s8-isolated-proof')
    _drop_exec(mounted,uid=uid,gid=gid,image_sha256=image_sha256,
      argv=['/usr/bin/python3','-I','-B','-S','/application/tests/execution_root/native_admission_probe.py'],environment=environment)
'''
    sources = {name: (Path("/source/scripts")/(name+".py")).read_bytes() for name in release.SOURCE_NAMES}
    sources["tu1nz_s8_execution_contract"] += core_trailer
    sources["tu1nz_s8_execution_observer"] += observer_trailer
    sources["tu1nz_s8_sealed_root"] += sealed_trailer
    # Apply precisely the same synthetic external bindings to the caller's
    # observer and tag validator. No admission/provisioning functions replaced.
    exec(core_trailer, c.__dict__)
    exec(observer_trailer, observer.__dict__)
    release.HISTORY_HASHES = hashes
    from tests.test_s8_execution_release import sample, tag
    value = sample()
    value.update(application=metadata["application"], sources=metadata["sources"], configurations=configs,
        control_sources={name: hashlib.sha256(payload).hexdigest() for name, payload in sources.items()},
        image=dict(sha256=hashlib.sha256(image.read_bytes()).hexdigest(), size=image.stat().st_size,
                   metadata_sha256=hashlib.sha256(c.canonical(metadata)).hexdigest()))
    value["history"] = dict(application=list(c.HISTORICAL_APPLICATION), control=list(c.HISTORICAL_CONTROL),
        hashes=hashes, git_barriers="RETAINED", aborted="RETAINED_NO_CONTINUATION")
    tag_bytes, tag_object = tag(value)
    instant = datetime.now(timezone.utc)
    grant = c.canonical(dict(schema="TU1NZ_S8_EXECUTION_GRANT_V1", slot=c.SLOT, incident_invocation=incident,
        freeze_sha256=hashlib.sha256(c.canonical(value)).hexdigest(), image_sha256=value["image"]["sha256"],
        human_authorization_sha256=hashlib.sha256(b"ISOLATED_SYNTHETIC_NOT_HUMAN_AUTHORITY").hexdigest(),
        issued_at=instant.isoformat(), expires_at=(instant+timedelta(minutes=8)).isoformat()))
    original_build = provision.build
    captured = {}
    def capture(*args):
        captured["program"] = original_build(*args)
        return captured["program"]
    provision.build = capture
    original_popen = subprocess.Popen
    if mode == "unknown-start":
        def unknown(argv, *args, **kwargs):
            result = original_popen(argv, *args, **kwargs)
            if argv[:2] == ["/usr/bin/systemd-run", "--quiet"]:
                result.wait(timeout=5)
                raise OSError("synthetic lost dispatch acknowledgement")
            return result
        provision.subprocess.Popen = unknown
    try:
        result = provision.provision(tag_bytes=tag_bytes, tag_object=tag_object, grant_bytes=grant,
            image_bytes=image.read_bytes(), control_sources=sources)
        c.require(mode == "success" and result["status"] == "S8_SINGLE_ADMISSION_ACCEPTED", "NATIVE_PROVISION_RED")
        c.require(result["acceptance"]["initial_admission"]["claimed_revision"] == 277133
                  and result["acceptance"]["subsequent_poll"]["lease"]["revision"] > 277133, "NATIVE_INITIAL_OR_POLL_RED")
        c.require(result["acceptance"]["s11_s12_acceptance"] is False, "NATIVE_OTHER_ROLE_NOT_GREEN")
    except provision.ProvisionAborted as error:
        c.require(mode == "unknown-start" and error.evidence["primary"]["type"] == "OSError", "NATIVE_UNEXPECTED_ABORT")
        until(lambda: observer.service(COORDINATOR)["ActiveState"] == "failed")
        c.lease_admission(observer.database()["leases"][0])
        c.require(not (observer.ROOT/"state/runtime").exists(), "NATIVE_ADMISSION_AFTER_LOST_HANDOFF")
    finally:
        subprocess.Popen = original_popen
    history = observer.history()
    cmd(["systemctl", "stop", COORDINATOR, c.UNIT], check=False)
    cmd(["systemctl", "reset-failed"])  # Only this disposable PID 1; no production API.
    stable = sql("SELECT row_to_json(s) FROM commercial_s10_2d_bot_polling_state s")
    records = {str(p.relative_to(observer.ROOT)): p.read_bytes() for p in observer.ROOT.rglob("*.json")}
    # Recreate the exact transient coordinator command after manager state
    # loss. The original live handoff is gone and cannot be recreated.
    cmd(provision.transient_command(captured["program"]))
    until(lambda: observer.service(COORDINATOR)["ActiveState"] == "failed")
    journal = cmd(["journalctl", "--no-pager", "-o", "cat", "-u", COORDINATOR, "-n", "20"]).stdout
    c.require("S8_EXECUTION_DISPATCH_NO_LIVE_HANDOFF" in journal, "NATIVE_REPLAY_NOT_DURABLE")
    c.require(stable == sql("SELECT row_to_json(s) FROM commercial_s10_2d_bot_polling_state s")
              and records == {str(p.relative_to(observer.ROOT)): p.read_bytes() for p in observer.ROOT.rglob("*.json")}
              and history == observer.history(), "NATIVE_REPLAY_MUTATION")
    c.require(cmd(["systemctl", "start", c.UNIT], check=False).returncode != 0, "NATIVE_NORMAL_FALLBACK")
    print(json.dumps(dict(component="S8_NATIVE_PROVISION_COORDINATOR_SEALED_SQL", mode=mode,
        application=metadata["application"], image_sha256=value["image"]["sha256"], history_unchanged=True,
        replay_rejected=True, provider_calls=0, live_authority=False, production_entrypoint=False,
        external_substitutions=["synthetic_incident_and_history", "database_address", "public_http", "provider_and_unrelated_store"]), sort_keys=True))


def cleanup():
    cmd(["systemctl", "stop", COORDINATOR, c.UNIT, *observer.PUBLIC_UNITS], check=False)
    # Only fresh fixture objects in this disposable test container. Production
    # APIs have no flag-removal, unlink, rollback-to-normal or retry operation.
    for root in (observer.ROOT, Path(str(observer.BASE_UNIT)+".d")):
        if not root.exists(): continue
        for path in sorted([*root.rglob("*"), root], key=lambda p: len(p.parts), reverse=True):
            if not path.is_file() and not path.is_dir(): continue
            fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
            try:
                flags = array.array("L", [0]); fcntl.ioctl(fd, 0x80086601, flags, True)
                flags[0] &= ~0x30; fcntl.ioctl(fd, 0x40086602, flags)
            finally: os.close(fd)


if __name__ == "__main__":
    try: main()
    except BaseException as error:
        # Fresh fixture journal only, never a server journal. All credentials,
        # identities and SQL rows were created synthetically by this file.
        print(cmd(["journalctl", "--no-pager", "-u", COORDINATOR, "-u", c.UNIT, "-n", "35"]).stdout)
        if isinstance(error, provision.ProvisionAborted): print(json.dumps(error.evidence, sort_keys=True))
        raise
    finally: cleanup()
