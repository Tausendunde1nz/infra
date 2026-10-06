#!/usr/bin/python3
"""Only executable inside the sealed, chrooted S8 stock; never a host fallback.

Python is started with -I -B -S. No site startup, .pth evaluation, PYTHONPATH,
working directory or historical checkout is part of the import path. The full
userland, interpreter, ELF loader/libraries and dependencies belong to the image.
"""
import hashlib
import ctypes
import json
import os
from pathlib import Path
import sys


def fail():
    raise SystemExit("S8_EXECUTION_CAPSULE_BOUNDARY_RED")


def attest():
    if not (sys.platform=="linux" and sys.flags.isolated and sys.flags.no_site
            and sys.flags.dont_write_bytecode and os.geteuid()!=0
            and os.getcwd()=="/application"):
        fail()
    status=Path("/proc/self/status").read_text()
    fields=dict(line.split(":",1) for line in status.splitlines() if ":" in line)
    if any(int(fields[name].strip(),16) for name in ("CapInh","CapPrm","CapEff","CapAmb")):
        fail()
    if fields.get("NoNewPrivs","").strip()!="1":fail()
    # exec resets dumpability. Yama closes the same-UID attach window before
    # this first instruction; then non-dumpability protects descriptor/memory
    # access throughout the application lifetime. Neither mechanism permits an
    # existing tracer. Missing kernel support is RED, never a relaxed fallback.
    try:
        if int(Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip()) not in {1,2,3}:fail()
        if fields.get("TracerPid","").strip()!="0":fail()
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.prctl(4,0,0,0,0)!=0 or libc.prctl(3,0,0,0,0)!=0:fail()
        fresh=dict(line.split(":",1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
        if fresh.get("TracerPid","").strip()!="0":fail()
    except (OSError,ValueError):fail()
    # A mount path alone is not proof: the retained descriptor must still be
    # the completely sealed image bound by the external one-shot invocation.
    import fcntl
    try:
        fd=int(os.environ.pop("TU1NZ_S8_SEALED_FD"))
        expected=os.environ.pop("TU1NZ_S8_SEALED_SHA256")
        if fcntl.fcntl(fd,fcntl.F_GET_SEALS)!=15:fail()
        h=hashlib.sha256()
        offset=0
        while True:
            part=os.pread(fd,1024*1024,offset)
            if not part:break
            h.update(part);offset+=len(part)
        if not offset or h.hexdigest()!=expected:fail()
        root_device=os.stat("/").st_dev
        for path in ("/application","/control","/usr","/runtime"):
            if os.stat(path).st_dev!=root_device:fail()
    except (KeyError,ValueError,OSError):fail()
    metadata=json.loads(Path("/control/capsule.json").read_bytes())
    if metadata.get("schema")!="TU1NZ_S8_CAPSULE_V1" or metadata.get("test_only") is not False:
        fail()
    version=f"python{sys.version_info.major}.{sys.version_info.minor}"
    if metadata.get("python_version")!=version:fail()
    # Drop every implicit path; do not import site or append all of sys.path.
    sys.path[:]=[f"/usr/lib/{version}",f"/usr/lib/{version}/lib-dynload",
                 "/application/src",f"/runtime/lib/{version}/site-packages"]
    for path in sys.path:
        if not Path(path).is_dir() or Path(path).resolve()!=Path(path):fail()
    os.environ.pop("PYTHONPATH",None);os.environ.pop("PYTHONHOME",None)
    os.environ["PATH"]="/usr/bin:/bin"
    os.environ["PYTHONDONTWRITEBYTECODE"]="1"
    # Component evidence only. It does not assert admission, polling, S11
    # health, release acceptance or permission to repeat this invocation.
    print(json.dumps(dict(event="S8_EXECUTION_ROOT_ATTESTED",image_sha256=expected,
                          application=metadata["application"],pid=os.getpid(),
                          invocation=os.environ.get("INVOCATION_ID"),
                          admission_accepted=False),sort_keys=True),flush=True)
    return metadata


def bootstrap():
    attest()
    from tu1nz_public_s8.runtime import entrypoint
    raise SystemExit(entrypoint())


if __name__=="__main__":bootstrap()
