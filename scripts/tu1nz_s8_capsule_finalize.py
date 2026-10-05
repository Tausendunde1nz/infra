#!/usr/bin/python3
"""Offline image construction only, inside a fresh private build container.

No provider/lease/service operations. This is not a host provisioning command.
The OCI output is an input to SquashFS construction, never directly deployed.
"""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def main():
    if not Path("/.dockerenv").is_file() or os.geteuid()!=0:
        raise SystemExit("S8_CAPSULE_ISOLATED_BUILD_REQUIRED")
    if len(sys.argv)!=3 or any(not re.fullmatch("[0-9a-f]{40}",v) for v in sys.argv[1:]):
        raise SystemExit("S8_CAPSULE_EXACT_SOURCE_REQUIRED")
    app=Path("/application")
    commit,tree=sys.argv[1:]
    sys.path.insert(0,str(app/"src"))
    from tu1nz_public_s8.recovery_admission import _verify_application_tree
    _verify_application_tree(app,commit,tree)
    versions={name:importlib.metadata.version(name) for name in (
        "psycopg","psycopg-binary","cryptography","cffi","pycparser","typing-extensions","setuptools")}
    expected={"psycopg":"3.3.4","psycopg-binary":"3.3.4","cryptography":"50.0.1", "cffi":"2.1.1",
              "pycparser":"3.0","typing-extensions":"4.16.0","setuptools":"83.0.0"}
    if versions!=expected or sys.version_info[:2]!=(3,12):
        raise SystemExit("S8_CAPSULE_DEPENDENCIES_RED")
    # Define empty interface mountpoints before sealing. The launcher may only
    # bind the fixed read-only credential/configuration/OS interfaces here.
    for directory in ("/run/dbus","/run/postgresql","/run/credentials/tu1nz-adult-public-s8-telegram.service",
                      "/etc/tu1nz/s8-atomic-admission-r1","/proc","/dev","/tmp"):
        Path(directory).mkdir(parents=True,exist_ok=True)
    for file in ("/run/dbus/system_bus_socket","/etc/tu1nz/s8-atomic-admission-r1/permit.json",
                 "/etc/tu1nz/adult-commercial-s8-public-telegram.json",
                 "/etc/tu1nz/adult-commercial-s10-2d-community.json"):
        with open(file,"xb") as stream:stream.write(b"")
    dpkg=subprocess.check_output(["/usr/bin/dpkg-query","-W","-f=${binary:Package}=${Version}\n"])
    source_names=("runtime.py","polling.py","recovery_admission.py")
    metadata=dict(schema="TU1NZ_S8_CAPSULE_V1",test_only=False,
        application=dict(commit=commit,tree=tree),python_version="python3.12",
        os_base="ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3",
        dpkg_inventory_sha256=hashlib.sha256(dpkg).hexdigest(),dependency_versions=versions,
        dependency_locks={name:hashlib.sha256((app/name).read_bytes()).hexdigest()
                          for name in ("requirements-m2.lock","requirements-s5.lock")},
        sources={name:hashlib.sha256((app/"src/tu1nz_public_s8"/name).read_bytes()).hexdigest()
                 for name in source_names},
        import_roots=["/usr/lib/python3.12","/usr/lib/python3.12/lib-dynload",
                      "/application/src","/runtime/lib/python3.12/site-packages"],
        host_imports=False,historical_repository_access=False,
        live_authority=False)
    with open("/control/capsule.json","x") as stream:
        json.dump(metadata,stream,sort_keys=True,separators=(",",":"));stream.write("\n")


if __name__=="__main__":main()
