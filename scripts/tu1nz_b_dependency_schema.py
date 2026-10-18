#!/usr/bin/env python3
"""Private, pinned-source schema recipe for an EMPTY isolated B builder only.

No SQL execution, network, Host admission, activation or source rewriting.
Private Application SQL is never embedded in the public infra repository.
The output is private source material: do not print/upload it in public CI.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tu1nz_b_data_handoff as b

APP = '93555d8a141caf8ace33522f9340d30bfc47d2bb'
SOURCES = {
    '0031_commercial_s11_interactive_experience.sql': '5792180ca628740d6a3b644958b3ba0c4f82d68bc93bd17673f3445d02429606',
    '0032_commercial_s11_1_latency_provenance.sql': '5dcde95be109f9aa6bd482e395d3052265928093c95e7c55f79a855a01ece343',
    '0033_commercial_s11_2_canary_bootstrap.sql': '97cca3f1a59ec125ef621cdb79ce85931682011ec88ad0b5f164617767f68e77',
    '0035_commercial_s11_2_pre_canary_epoch.sql': 'c745307910c117df9a8f8fbf98f54d9b1e6bb382841e95dccc23e1ebf0e477db',
}
BASE_SOURCES = {
    '0001_m1_core.sql': '89138dd33d3c8e21184a097813261f7cc7c3c27b385913b5de29df585004b271',
    '0021_commercial_s7_public_soft_launch.sql': 'a71350ae6d9ce544558ced38b0b032b28ac9885d0e3b4b9855e4c2db88d8b021',
    '0022_commercial_s8_public_telegram_early_access.sql': '5d3abd9bb863d3001c6af9c8775799b3bde69d6079af6062d4d607f07f4e7ec6',
    '0023_commercial_s8_health_recovery.sql': 'feb157b5625113a3c4774b570d8a73265356a87c5fe70d491c36b5b7a25a6691',
    '0024_commercial_s8_runtime_least_privilege.sql': '3152cfff48e48ccead115a8e3e56ef658f9e1d326d466dc7016ee9f89e998ac4',
    '0025_commercial_s9_automated_growth.sql': 'b0b64bc6ca8d549f15b423fed66172ec16d764fbd5b7c97c129f9be03da583a1',
    '0026_commercial_s9_telegram_channel.sql': '0b5e4ff8d6073cf4a23ea3136962c43a6dc6cbfadd1066a7b446f0ea488c760f',
    '0027_commercial_s9_publication_completion.sql': '148753478cfd57a0e9e0e7235849d83dd0587e054a96a85d411eac5c7ac7b9ab',
    '0028_commercial_s10_1_wms_public_growth.sql': '6dc77fd37ee65a1d8f67eb47dd75869b265289d007b1b8986a0474dadd449edc',
    '0029_commercial_s10_2d_community.sql': '66eae1c5022e5e005b278984d3b5580928fdd4133a0cfe9653e63957bb933d20',
    '0030_commercial_s10_2d_r3_5_stabilization.sql': '9e39223ae7c129355185f2fa48723a4034bfc4a8bb987e448b0d45ac567ed58b',
}
# Inclusive 1-based ranges in the EXACT hash-bound private originals. These
# select definitions, never seed INSERTs, bootstrap UPDATEs, transition/rearm
# entrypoints, session/product tables or fresh admission/audit histories.
RANGES = (
    ('0031', 3, 22),
    ('0033', 3, 23), ('0033', 35, 73), ('0035', 6, 64),
    ('0032', 6, 30), ('0033', 396, 403),
    ('0035', 66, 188), ('0033', 176, 178),
    ('0033', 180, 209), ('0033', 405, 464),
)


def recipe(source, empty_builder=False):
    source = Path(source)
    raw = {}
    for name, digest in SOURCES.items():
        data = b.read_small(source / 'migrations' / name)
        b.need(b.sha(data) == digest, 'DEPENDENCY_SOURCE_HASH')
        raw[name[:4]] = data.splitlines(keepends=True)
    chunks = [b''.join(raw[prefix][first-1:last]) for prefix, first, last in RANGES]
    sql = b'BEGIN;\n' + b'\n\n'.join(chunks) + b'\nCOMMIT;\n'
    hashes = dict(SOURCES)
    if empty_builder:
        base = []
        for name, digest in BASE_SOURCES.items():
            data = b.read_small(source / 'migrations' / name)
            b.need(b.sha(data) == digest, 'BASE_SOURCE_HASH')
            if name.startswith('0001_'):
                # Only the common append-only guard; no unrelated core tables.
                data = b'BEGIN;\n' + b''.join(data.splitlines(keepends=True)[2:10]) + b'\nCOMMIT;\n'
            base.append(data)
        sql = b'\n'.join(base) + b'\n' + sql
        hashes.update(BASE_SOURCES)
    return sql, {'schema': 'TU1NZ_B_DEPENDENCY_RECIPE_V1', 'source_app': APP,
                 'source_files_sha256': hashes, 'ranges_inclusive': RANGES,
                 'includes_empty_base_builder': empty_builder,
                 'sql_sha256': b.sha(sql), 'purpose': 'EMPTY_PRIVATE_BUILDER_ONLY',
                 'host_admission': False, 's11_activation': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--empty-builder', action='store_true',
                        help='include authentic base migrations/seeds in EMPTY private builder, NEVER restore target')
    parser.add_argument('--output', type=Path, required=True,
                        help='new private file in an existing private directory; never stdout')
    args = parser.parse_args(argv)
    try:
        sql, receipt = recipe(args.source, args.empty_builder)
        b.need(args.output.is_absolute(), 'ABSOLUTE_OUTPUT_REQUIRED')
        b.need(sys.platform.startswith('linux') and hasattr(os, 'listxattr'),
               'LINUX_OUTPUT_METADATA_SUPPORT_REQUIRED')
        from contextlib import ExitStack
        with ExitStack() as stack:
            parent = b.directory(args.output.parent, stack)
            info = os.fstat(parent)
            b.need(info.st_uid == os.geteuid() and info.st_mode & 0o777 == 0o700,
                   'PRIVATE_OUTPUT_DIRECTORY_REQUIRED')
            b.need(not os.listxattr(parent), 'OUTPUT_DIRECTORY_ATTRIBUTES_REQUIRE_REVIEW')
            fd = os.open(args.output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(sql); stream.flush(); os.fsync(stream.fileno())
            os.fsync(parent)
        # Only public source/range/digest metadata, never private SQL bytes.
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (b.Denied, OSError, ValueError, TypeError):
        print(json.dumps({'status': 'HOLD', 'code': 'DEPENDENCY_RECIPE_NOT_CREATED_OR_PARTIAL',
                          'host_admission': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
