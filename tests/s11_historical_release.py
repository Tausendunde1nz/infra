"""Check historical S11 bindings at the last reviewed canonical snapshot.

The R14 controller is a new release; existing S11 manifest hashes are not
rewritten to misrepresent it as their historical controller.
"""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "4652b1725dd2444c805d643dcb6381dfeb423ab8"


def artifact_bytes(path: Path) -> bytes:
    relative = path.resolve().relative_to(ROOT).as_posix()
    return subprocess.check_output(["git", "-c", "safe.directory=" + str(ROOT),
        "-C", str(ROOT), "show", BASELINE + ":" + relative])
