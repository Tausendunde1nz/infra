"""Test-only fork boundary; never return into the inherited unittest runner."""
from contextlib import contextmanager
import os


@contextmanager
def child_failure_boundary():
    # Intended outcomes use os._exit themselves. Exceptions (including
    # SystemExit) and accidental fallthrough are always distinct failures.
    try:
        yield
    except BaseException:
        os._exit(99)
    os._exit(98)
