"""Build a deterministic PID-1-loaded entry; no mutable Control imports.

This pure renderer creates no authority or unit. The final reviewed freeze
must bind all input source digests, and the provisioner must protect and verify
the resulting unit before PID 1 loads it. Python's interpreter and stdlib are
explicit host OS bootstrap dependencies, just like mount/systemctl/kernel;
Application and third-party Python code never enter through those paths.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import zlib


MODULES = (
    "tu1nz_s8_execution_contract",
    "tu1nz_s8_path_policy",
    "tu1nz_s8_journal_fence",
    "tu1nz_s8_protected_journal",
    "tu1nz_s8_anchor",
    "tu1nz_s8_admission_channel",
    "tu1nz_s8_sealed_root",
    "tu1nz_s8_runtime_interfaces",
    "tu1nz_s8_execution_observer",
    "tu1nz_s8_dispatch_boundary",
)
INSTALLER_MODULES = (*MODULES, "tu1nz_s8_execution", "tu1nz_s8_new_stock", "tu1nz_s8_existing_dropin", "tu1nz_s8_anchor_bootstrap", "tu1nz_s8_execution_units",
    "tu1nz_s8_frozen_entry", "tu1nz_s8_execution_release", "tu1nz_s8_provision", "tu1nz_s8_installer_entry")


def build(modules: dict[str, bytes], entry: bytes, expected: dict[str, str]) -> str:
    """Expected digests come from release provenance, never from live files.

    Dependency order is fixed; sys.modules contains only the exact embedded
    Control modules. No sys.path insertion, disk loader or fallback exists.
    This is also testable without any service installation.
    """
    return _build(MODULES, modules, entry, expected)


def _build(order, modules, entry, expected, *, expose_sources=False):
    if set(modules) != set(order) or set(expected) != {*order, "entry"}:
        raise ValueError("S8_FROZEN_ENTRY_SOURCE_SET_RED")
    values = {**modules, "entry": entry}
    for name, source in values.items():
        if (type(source) is not bytes or not 0 < len(source) <= 262144
                or not re.fullmatch("[0-9a-f]{64}", expected[name])
                or hashlib.sha256(source).hexdigest() != expected[name]):
            raise ValueError("S8_FROZEN_ENTRY_SOURCE_BINDING_RED")
        compile(source, "<frozen-s8/" + name + ">", "exec")
    payload = json.dumps({name: base64.b64encode(values[name]).decode("ascii")
                          for name in (*order, "entry")}, sort_keys=True, separators=(",", ":"))
    loader = f'''import base64,json,sys,types
if not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode:
 raise SystemExit("S8_FROZEN_ENTRY_ISOLATION_REQUIRED")
_sources=json.loads({payload!r})
for _name in {order!r}:
 if _name in sys.modules:raise SystemExit("S8_FROZEN_ENTRY_MODULE_COLLISION")
 _module=types.ModuleType(_name)
 _module.__file__="<frozen-s8/"+_name+">"
 sys.modules[_name]=_module
 exec(compile(base64.b64decode(_sources[_name]),_module.__file__,"exec"),_module.__dict__)
_entry=base64.b64decode(_sources["entry"])
_scope={{"__name__":"__main__","__file__":"<frozen-s8/entry>"}}
if {expose_sources!r}:_scope["BUNDLE_SOURCES"]={{name:base64.b64decode(_sources[name]) for name in {order!r}}}
exec(compile(_entry,"<frozen-s8/entry>","exec"),_scope)
'''
    compressed = base64.b64encode(zlib.compress(loader.encode(), 9)).decode("ascii")
    program = "import base64,zlib;exec(zlib.decompress(base64.b64decode('" + compressed + "')))"
    if len(program) > 100000:
        raise ValueError("S8_FROZEN_ENTRY_COMMAND_SIZE_RED")
    return program


def build_installer(sources, expected):
    """Build-only helper. The expected map is the exact verified tag content.

    No source files are loaded by the resulting program. The operator pins
    this deterministic output's digest before invoking it with isolated Python.
    """
    entry = b"from tu1nz_s8_installer_entry import main\nmain(BUNDLE_SOURCES)\n"
    if set(expected) != set(INSTALLER_MODULES): raise ValueError("S8_FROZEN_ENTRY_SOURCE_SET_RED")
    return _build(INSTALLER_MODULES, sources, entry,
                  {**expected, "entry": hashlib.sha256(entry).hexdigest()}, expose_sources=True)


def systemd_command(program: str, phase: str) -> str:
    if phase not in {"coordinate", "condition", "execute"} or not program.startswith("import base64,zlib;"):
        raise ValueError("S8_FROZEN_ENTRY_COMMAND_RED")
    # Only a renderer output is accepted. Its compressed alphabet cannot carry
    # systemd expansion/quoting tokens; phase is never shell-evaluated.
    if any(value in program for value in ('"', "\\", "$", "%", "\n", "\r")):
        raise ValueError("S8_FROZEN_ENTRY_COMMAND_RED")
    return '/usr/bin/python3 -I -B -S -c "' + program + '" ' + phase
