"""Finite source locations for failed isolated Rev4 fixture assertions only.

IDs come from public source/function/kind/ordinal, never exception text or
locals. Both guest capture and CI validation use the same bound source. An
unmapped innermost frame is not replaced by a misleading caller location.
"""
import ast
from pathlib import Path

SOURCES = {
    'tests/public_maintenance_native.py': 'REV4_NATIVE',
    'tests/public_maintenance_fixture.py': 'REV4_FIXTURE',
    'tests/public_operator_native.py': 'REV4_GUEST',
    'tests/public_runtime_fixture.py': 'REV4_RUNTIME',
}
UNMAPPED = {'checkpoint': 'UNMAPPED_TEST_FAILURE'}


def validated_start_limit(value):
    """Finite error-only predicates; never unit values, PIDs or identifiers."""
    fields={'type_simple','restarts_zero','control_pid_zero','job_empty',
            'result_not_limit_hit','invocation_id_valid','active_running_pid','empty_terminal_pid'}
    if type(value) is not dict or set(value)!={'checkpoint','caller','unit','require_active','anchor_present','checks'}:
        return None
    enums={'checkpoint':{'START_LIMIT_STATE_NOT_ELIGIBLE'},
           'caller':{'pre_stop','check_prepared_state','bind_current_permission','remaining',
                     'recover_state','start_limit_permission','OTHER'},'unit':{'S7','S8','WMS','OTHER'}}
    if any(type(value[k]) is not str or value[k] not in allowed for k,allowed in enums.items()):return None
    if any(type(value[k]) is not bool for k in ('require_active','anchor_present')):return None
    checks=value['checks']
    if type(checks) is not dict or set(checks)!=fields or any(type(v) is not bool for v in checks.values()):return None
    common=all(checks[k] for k in fields-{'active_running_pid','empty_terminal_pid'})
    eligible=checks['active_running_pid'] or (checks['empty_terminal_pid'] and not value['require_active'])
    if common and eligible:return None  # a purported failure must actually describe denial
    return {**value,'checks':dict(checks)}


def checkpoints():
    root = Path(__file__).resolve().parents[1]
    points = {}
    for relative, prefix in SOURCES.items():
        counts = {}

        def visit(node, scope='MODULE'):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope = node.name.upper() if scope == 'MODULE' else scope+'__'+node.name.upper()
            if isinstance(node, (ast.Assert, ast.Raise)):
                key = prefix+'_'+scope+'_'+type(node).__name__.upper()
                counts[key] = counts.get(key, 0)+1
                checkpoint = key+'_'+str(counts[key]).zfill(2)
                for line in range(node.lineno, node.end_lineno+1):
                    points[(relative, line)] = {'checkpoint': checkpoint, 'file': relative, 'line': line}
            for child in ast.iter_child_nodes(node):
                visit(child, scope)

        visit(ast.parse((root/relative).read_bytes()))
    return points


def capture(error):
    trace = error.__traceback__
    if trace is None:
        return dict(UNMAPPED)
    while trace.tb_next is not None:
        trace = trace.tb_next
    # Exact owned filenames only. No suffix matching, arbitrary paths, source
    # text, exception values or traceback serialization can cross this boundary.
    root = Path(__file__).resolve().parents[1]
    relative = next((p for p in SOURCES if trace.tb_frame.f_code.co_filename == str(root/p)), None)
    if relative is None:
        return dict(UNMAPPED)
    return dict(checkpoints().get((relative, trace.tb_lineno), UNMAPPED))


def validated(value):
    if type(value) is not dict:
        return None
    if value == UNMAPPED:
        return dict(UNMAPPED)
    if set(value) != {'checkpoint', 'file', 'line'} or type(value['checkpoint']) is not str or \
            type(value['file']) is not str or type(value['line']) is not int:
        return None
    point = checkpoints().get((value['file'], value['line']))
    return dict(point) if point is not None and point == value else None
