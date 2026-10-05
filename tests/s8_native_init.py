"""Disposable PID-1 container bootstrap; never a host repair command."""
import json
import os
from pathlib import Path
import subprocess


def prepare():
    if os.getpid()!=1 or os.geteuid()!=0 or os.environ.get("container")!="docker" or not Path("/.dockerenv").is_file():
        raise SystemExit("S8_NATIVE_ISOLATED_PID1_REQUIRED")
    # This is the container's own tmpfs, not a bind of the host /run. systemd
    # credential creation in its child mount namespace requires propagation to
    # the manager. A private root prevents propagation to the Docker host.
    result=subprocess.run(["/usr/bin/findmnt","--json","--mountpoint","/run",
                           "--output","TARGET,FSTYPE,SOURCE,PROPAGATION"],
                          capture_output=True,text=True,check=True)
    mounts=json.loads(result.stdout)["filesystems"]
    if len(mounts)!=1 or mounts[0]!={"target":"/run","fstype":"tmpfs","source":"tmpfs","propagation":"private"}:
        raise SystemExit("S8_NATIVE_PRIVATE_RUN_TMPFS_REQUIRED")
    propagation=subprocess.check_output(["/usr/bin/findmnt","--noheadings","--output","PROPAGATION",
                                         "--mountpoint","/"],text=True).strip()
    if propagation!="private":
        raise SystemExit("S8_NATIVE_PRIVATE_ROOT_REQUIRED")
    subprocess.run(["/usr/bin/mount","--make-shared","/run"],check=True)
    os.execv("/sbin/init",["/sbin/init"])


if __name__=="__main__":prepare()
