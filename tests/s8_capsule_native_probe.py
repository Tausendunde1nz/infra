"""Full sealed OS -> unprivileged real Application entrypoint, negative probe.

Private isolated CI only. The empty permit must reject before database/provider
work. This is a component boundary proof, not the integrated admission gate.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import tu1nz_s8_sealed_root as s


def main():
    if os.geteuid()!=0 or os.environ.get("container")!="docker" or not Path("/.dockerenv").is_file():
        raise SystemExit("S8_NATIVE_ISOLATED_CONTAINER_REQUIRED")
    if len(sys.argv)!=2:raise SystemExit("S8_NATIVE_IMAGE_REQUIRED")
    image=Path(sys.argv[1])
    sha=hashlib.sha256(image.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="s8-full-capsule-",dir="/var/tmp") as directory:
        output=Path(directory)/"result.jsonl"
        child=os.fork()
        if child==0:
            try:
                fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                os.dup2(fd,1);os.dup2(fd,2);os.close(fd)
                s.private_namespace()
                image_fd=s.sealed_copy(image,sha)
                mountpoint=Path(directory)/"root";mountpoint.mkdir(mode=0o700)
                mounted=s.MountedImage(image_fd,mountpoint).attach()
                s.bind_readonly(Path("/proc"),mountpoint/"proc")
                # No credentials, bus or database interfaces are exposed. Even
                # a wrong permit implementation cannot reach real services.
                argv=["/usr/bin/python3","-I","-B","-S","/control/tu1nz_s8_capsule_bootstrap.py",
                      "--recovery-admission","/etc/tu1nz/s8-atomic-admission-r1/permit.json",
                      "--contract","/etc/tu1nz/adult-commercial-s8-public-telegram.json",
                      "--copy","/unused-copy","--telegram-token","/unused-token",
                      "--database-dsn","/unused-dsn","--runtime-release-id","s10-2d-r3-5"]
                s.enter_capsule(mounted,uid=65534,gid=65534,image_sha256=sha,argv=argv,
                                environment={"INVOCATION_ID":"1"*32,"LANG":"C.UTF-8"})
            except BaseException as error:
                # Imports and tempfile cleanup may be inaccessible after a
                # failing chroot/drop. Preserve the primary safe error first;
                # never unwind the parent's temporary-directory context here.
                os.write(2,(json.dumps(dict(stage="launch",error_type=type(error).__name__,
                                           errno=getattr(error,"errno",None),uid=os.geteuid()))+"\n").encode())
                os._exit(99)
        _,status=os.waitpid(child,0)
        lines=output.read_text().splitlines()
        if os.waitstatus_to_exitcode(status)!=2:
            print("\n".join(lines[-10:]))
            raise SystemExit("S8_NATIVE_CAPSULE_ENTRYPOINT_RED")
        records=[json.loads(line) for line in lines]
        if (len(records)!=2 or records[0].get("event")!="S8_EXECUTION_ROOT_ATTESTED"
                or records[0].get("image_sha256")!=sha
                or records[0].get("admission_accepted") is not False
                or records[1].get("event")!="S8_RUNTIME_STARTUP_RED"
                or records[1].get("retryable") is not False):
            raise SystemExit("S8_NATIVE_EMPTY_PERMIT_REJECTION_RED")
        print(json.dumps(dict(component="S8_SEALED_FULL_CAPSULE_NEGATIVE",ok=True,
            application=records[0]["application"],image_sha256=sha,
            provider_calls=0,full_chain_acceptance=False,live_authority=False),sort_keys=True))


if __name__=="__main__":main()
