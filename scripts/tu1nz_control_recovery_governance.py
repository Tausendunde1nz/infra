"""Authentic, finite bootstrap intent; not a replacement policy or live authority.

The unmodified target preflight supports --codex-home. Its global layer is
relocated using exactly the transformation already tested in that target.
Nothing consults HOME, an existing global context or historical Git here.
Only a signed, current bootstrap intent permits creation; actual filesystem
preflight follows sealing and must pass before view acceptance.
"""
import json
from pathlib import Path
import re

import tu1nz_control_recovery_contract as c

FREEZE_TAG = 'control-only-recovery-source-freeze-r2'
VERSION = 'TU1NZ_CONTROL_ISOLATED_GOVERNANCE_V1'
MERGE = '414ce1bba87f71016d3c72618d07784c6524b97f'
ANCESTOR = '0b2c0a3978b50348de9f095ada23793f52bd2409'
POLICY_HASHES = {
    'AGENTS.md': '3c135adbe51276f8572613793f1a2db59d938dea184622160d97cd6660327d3e',
    'governance/operative-policy-v1.1.md': '83506c27c6adc4fce97cf9faa0c4a4d60dbe15380fc473c1d4ae4d746554423c',
    'governance/preflight.py': 'a5b502acdbfb6cb9368a19f8796987826031f09ceb4f4b9fc4f562fc1c5b600c',
    'governance/efficiency-standard-v1.1.md': '183b768a6bc8ff83ecd1679af09c878b692c7ee9a0ebf3257eaf6bf22ff07c90',
    'governance/SUPERSEDED.json': '785bb98a8622ff5af92a39033b6bb97824d19ad95d47c035e9d76b2372ac0e09',
}
COMMAND = 'python3.12 "$(git rev-parse --show-toplevel)/governance/preflight.py"'


def validate_source(source):
    c.require(type(source) is dict and set(source) ==
              {'tag', 'tag_object', 'commit', 'tree', 'executor_sha256'}, 'GOVERNANCE_SOURCE_BINDING_RED')
    c.require(source['tag'] == FREEZE_TAG and all(type(source[k]) is str and
              re.fullmatch('[0-9a-f]{40}', source[k]) for k in ('tag_object', 'commit', 'tree')) and
              type(source['executor_sha256']) is str and
              re.fullmatch('[0-9a-f]{64}', source['executor_sha256']), 'GOVERNANCE_SOURCE_BINDING_RED')


def prepare(capsule, layout, source):
    # Synthetic object/lease fixtures are not a supported production target.
    # Production memory entry ALWAYS constructs Layout.production()/c.TARGET.
    if capsule.target != c.TARGET:
        c.require(layout.historical != c.HISTORICAL and
                  'governance/preflight.py' not in capsule.files, 'GOVERNANCE_TARGET_BINDING_RED')
        return None
    validate_source(source)
    if layout.historical == c.HISTORICAL:
        c.require(layout == c.Layout.production(), 'GOVERNANCE_LAYOUT_BINDING_RED')
    for name, sha in POLICY_HASHES.items():
        c.require(name in capsule.files and c.digest(capsule.files[name]['bytes']) == sha,
                  'GOVERNANCE_POLICY_BINDING_RED')
    c.require(MERGE in capsule.history_done and ANCESTOR in capsule.history_done,
              'GOVERNANCE_PROVENANCE_RED')
    policy = capsule.files['governance/operative-policy-v1.1.md']['bytes']
    agents = capsule.files['AGENTS.md']['bytes'].decode()
    c.require(agents.startswith(policy.decode() + '\n') and agents.count(COMMAND) == 1,
              'GOVERNANCE_TRANSFORM_RED')
    manifest = json.loads(capsule.files['governance/SUPERSEDED.json']['bytes'])
    c.require(manifest['active_version'] == 'v1.1' and manifest['merge_commit'] == MERGE and
              manifest['sha256'] == POLICY_HASHES['governance/efficiency-standard-v1.1.md'],
              'GOVERNANCE_PROVENANCE_RED')
    release = layout.anchor / 'release'; context = layout.anchor / 'governance-context'
    c.require(layout.anchor.is_absolute() and str(layout.anchor) == str(layout.anchor.resolve()) and
              '"' not in str(layout.anchor) and '\n' not in str(layout.anchor), 'GOVERNANCE_PATH_RED')
    command = '/opt/homebrew/bin/python3.12 "' + str(release / 'governance/preflight.py') + '"'
    global_agents = agents.replace(COMMAND, command).encode()
    return {'schema': VERSION, 'policy_version': 'v1.1', 'provenance': MERGE,
            'policy_source': dict(capsule.target), 'policy_hashes': dict(POLICY_HASHES),
            'source_release': dict(source), 'host': layout.host, 'slot': c.SLOT,
            'reader': {'uid': 1001, 'gid': 1001, 'groups': [1001]},
            'cwd': str(release), 'target': str(release), 'context': str(context),
            'global_agents_sha256': c.digest(global_agents),
            'scope': 'CONTROL_ONLY_READONLY_SOURCE_VIEW_NO_RUNTIME_AUTHORITY',
            'bootstrap': 'AUTHENTICATED_INTENT_NOT_FILESYSTEM_PREFLIGHT',
            'global_agents': global_agents}


def intent(plan):
    return None if plan is None else {k: v for k, v in plan.items() if k != 'global_agents'}


def context_files(plan, transaction):
    c.require(plan is not None and transaction['governance'] == intent(plan), 'GOVERNANCE_TRANSACTION_RED')
    # The transaction includes the live PID/boot/nonce, source artifact, exact
    # host/endpoints/ancestors and SAME fixed logical slot; not reusable intent.
    binding = {'schema': VERSION + '_BOUND_CONTEXT', 'intent': intent(plan),
               'transaction_sha256': c.digest(c.canonical(transaction))}
    return {'AGENTS.md': plan['global_agents'], 'binding.json': c.canonical(binding)}


def check_context(root, plan, transaction):
    """No discovery/fallback; exact two immutable owned files only."""
    expected = context_files(plan, transaction)
    c.require(str(root) == plan['context'] and root.resolve() == root,
              'GOVERNANCE_CONTEXT_PATH_RED')
    c.require({p.name for p in root.iterdir()} == set(expected), 'GOVERNANCE_CONTEXT_INCOMPLETE')
    for name, raw in expected.items():
        path = root / name
        c.require(path.is_file() and not path.is_symlink() and path.read_bytes() == raw,
                  'GOVERNANCE_CONTEXT_BINDING_RED')
    return {'intent_sha256': c.digest(c.canonical(intent(plan))),
            'context_files': {name: c.digest(raw) for name, raw in expected.items()},
            'transaction_sha256': c.digest(c.canonical(transaction))}
