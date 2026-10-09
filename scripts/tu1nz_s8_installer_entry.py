"""Frozen source bundle's only operator entry. No grant generation or resume.

The separate live approval must name the exact tag object, installer digest
and fixed slot. Files are protected root-owned inputs; passwords, tokens and
Telegram identifiers are neither arguments nor output. Preflight is read-only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

from tu1nz_s8_execution_observer import file_bytes
from tu1nz_s8_provision import prepare_inputs, provision, ProvisionAborted, failure


def main(sources):
    parser = argparse.ArgumentParser(description="Fixed S8 one-shot admission; no retry or normal-claim restoration")
    parser.add_argument("mode", choices=("preflight", "execute"))
    parser.add_argument("--tag-file", required=True, type=Path)
    parser.add_argument("--expected-tag-object", required=True)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--grant", required=True, type=Path)
    parser.add_argument("--expected-grant-sha256", required=True)
    args = parser.parse_args()
    # This isolated process owns its umask. Existing filesystem metadata is
    # never adjusted to pass a gate; the new-object constructors require 0077.
    os.umask(0o077)
    try:
        values = dict(tag_bytes=file_bytes(args.tag_file, limit=262144), tag_object=args.expected_tag_object,
            grant_bytes=file_bytes(args.grant, limit=16384), image_bytes=file_bytes(args.image, limit=1024*1024*1024),
            expected_grant_sha256=args.expected_grant_sha256,
            control_sources=sources)
        if args.mode == "preflight":
            result = prepare_inputs(**values)
            print(json.dumps(dict(event="S8_READONLY_PREFLIGHT_GREEN", binding=result["binding"],
                grant_expires_at=result["grant"]["expires_at"], target_mutations=0,
                historical_cause="UNKNOWN", r15_pause_compatibility="OPEN",
                s11_s12_acceptance=False, reusable_admission=False), sort_keys=True))
        else:
            result = provision(**values)
            print(json.dumps(dict(event=result["status"], freeze_sha256=result["freeze_sha256"],
                tag_object=result["tag_object"], acceptance=result["acceptance"],
                recovery=False, deployment=False, unlock=False), sort_keys=True))
    except BaseException as error:
        evidence = error.evidence if isinstance(error, ProvisionAborted) else dict(primary=failure(error))
        print(json.dumps(dict(event="S8_EXECUTION_STOP_NO_RETRY", evidence=evidence), sort_keys=True))
        raise SystemExit(2)
