"""Finite source locations for failed isolated Rev4 fixture assertions only.

IDs come from public source/function/kind/ordinal, never exception text or
locals. Both guest capture and CI validation use the same bound source. An
unmapped innermost frame is not replaced by a misleading caller location.
"""
import ast
import builtins
import math
from pathlib import Path

SOURCES = {
    'tests/public_maintenance_native.py': 'REV4_NATIVE',
    'tests/public_maintenance_fixture.py': 'REV4_FIXTURE',
    'tests/public_operator_native.py': 'REV4_GUEST',
    'tests/public_runtime_fixture.py': 'REV4_RUNTIME',
}
UNMAPPED = {'checkpoint': 'UNMAPPED_TEST_FAILURE'}

TRANSPORT_CODES = frozenset('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_'+v for v in
                            ('WIRE_LOST_NO_RETRY', 'WIRE_DEADLINE'))
TRANSPORT_PHASES = {
    'recovery_context': 'RECOVERY_ADMITTED',
    'recovery_flow_claim': 'RECOVERY_FLOW',
    'recovery_flow_observation': 'RECOVERY_FLOW',
    'recovery_flow_intent': 'RECOVERY_FLOW',
    'recovery_flow_ack': 'RECOVERY_FLOW',
    'owner_admission_intent': 'OWNER_ADMISSION',
    'owner_admission_markers_confirmed': 'OWNER_ADMISSION',
    'owner_claim_intent': 'OWNER_ADMISSION',
    'owner_ready': 'OWNER_ADMISSION',
    'owner_object_intent': 'OWNER_APPLY',
    'owner_object_ack': 'OWNER_APPLY',
    'operator_pending_cleanup': 'ENTRY_CLEANUP',
    'operator_cleanup': 'ENTRY_CLEANUP',
}
UNKNOWN = 'UNKNOWN'


def unknown_transport():
    return {k: UNKNOWN for k in ('code', 'last_journal_kind', 'last_journal_phase',
        'cleanup_receipt', 'ssh_exit', 'local_ssh_outcome', 'ssh_exit_observation',
        'remote_final_record', 'remote_process_state', 'clock_scope',
        'wire_remaining_milliseconds', 'owner_remaining_milliseconds', 'entry_remaining_milliseconds')}


def validated_transport(value):
    """Finite public projection. SSH exit after cleanup never proves Host exit."""
    if type(value) is not dict or set(value) != set(unknown_transport()):
        return None
    enums = {
        'code': TRANSPORT_CODES | {UNKNOWN},
        'last_journal_kind': set(TRANSPORT_PHASES) | {UNKNOWN},
        'last_journal_phase': set(TRANSPORT_PHASES.values()) | {UNKNOWN},
        'cleanup_receipt': {'BOUND_READBACK', UNKNOWN},
        'local_ssh_outcome': {'EXIT', 'SIGNAL', UNKNOWN},
        'ssh_exit_observation': {'AFTER_CLIENT_CLEANUP', UNKNOWN},
        'remote_final_record': {'PRESENT_BOUND', 'ABSENT_BOUND', UNKNOWN},
        'remote_process_state': {UNKNOWN},
        'clock_scope': {'SAME_ISOLATED_GUEST_MONOTONIC', UNKNOWN},
    }
    if any(type(value[k]) is not str or value[k] not in choices for k, choices in enums.items()):
        return None
    if value['last_journal_phase'] != TRANSPORT_PHASES.get(value['last_journal_kind'], UNKNOWN):
        return None
    exit_code = value['ssh_exit']
    if not (exit_code == UNKNOWN if type(exit_code) is str else
            type(exit_code) is int and -128 <= exit_code <= 255):
        return None
    expected = UNKNOWN if exit_code == UNKNOWN else ('SIGNAL' if exit_code < 0 else 'EXIT')
    if value['local_ssh_outcome'] != expected:
        return None
    if value['cleanup_receipt'] == UNKNOWN:
        if any(value[k] != UNKNOWN for k in ('ssh_exit', 'ssh_exit_observation', 'remote_final_record')):
            return None
    elif value['ssh_exit_observation'] != 'AFTER_CLIENT_CLEANUP' or value['remote_final_record'] == UNKNOWN:
        return None
    times = ('wire_remaining_milliseconds', 'owner_remaining_milliseconds', 'entry_remaining_milliseconds')
    if any(not (type(value[k]) is int and -600000 <= value[k] <= 600000 or
                type(value[k]) is str and value[k] == UNKNOWN) for k in times):
        return None
    if value['clock_scope'] == UNKNOWN and any(value[k] != UNKNOWN for k in times):
        return None
    if value['code'] == UNKNOWN and (value['last_journal_kind'] != UNKNOWN or
                                    value['clock_scope'] != UNKNOWN):
        return None
    return dict(value)


def capture_transport(error, observer, transport, now_ns):
    """Error-only in-memory capture; no poll, journal reread or remote query."""
    from tu1nz_public_operator_io import parse, sha
    code = getattr(error, 'primary', None)
    if code not in TRANSPORT_CODES or transport is None:
        return {}
    out = {'code': code, 'abort_monotonic_ns': now_ns,
           'wire_deadline': observer.wire.deadline, 'entry_deadline': transport.deadline,
           'last_journal_kind': UNKNOWN}
    # The last already durable client record can still lack a Host ACK.
    if observer.records:
        raw = next(reversed(observer.records.values()))
        row = parse(raw)
        if sha(raw) == observer.last and row['sequence'] == observer.sequence and row['binding'] == observer.binding:
            out['last_journal_kind'] = row['kind'] if row['kind'] in TRANSPORT_PHASES else UNKNOWN
    return out


def transport_projection(observed, cleanup, trace):
    """Only the loopback native guest shares this monotonic clock domain.

    Owner ceiling is reconstructed exactly from the existing trace assignment:
    owner_begin = int(channel.ceiling * 1e9) - 120000000001. A lost trace stays
    UNKNOWN; client receipt time is never substituted for Owner admission.
    """
    out = unknown_transport()
    if type(cleanup) is dict and cleanup.get('cleanup_receipt') == 'BOUND_READBACK':
        out.update({k: cleanup.get(k, UNKNOWN) for k in
                    ('cleanup_receipt', 'ssh_exit', 'ssh_exit_observation', 'remote_final_record')})
        exit_code = out['ssh_exit']
        if type(exit_code) is int:
            out['local_ssh_outcome'] = 'SIGNAL' if exit_code < 0 else 'EXIT'
    if type(observed) is dict and type(observed.get('code')) is str and observed['code'] in TRANSPORT_CODES:
        out['code'] = observed['code']
        kind = observed.get('last_journal_kind')
        if type(kind) is str and kind in TRANSPORT_PHASES:
            out.update(last_journal_kind=kind, last_journal_phase=TRANSPORT_PHASES[kind])
        now = observed.get('abort_monotonic_ns')
        if type(now) is int and 0 < now < 2**63:
            out['clock_scope'] = 'SAME_ISOLATED_GUEST_MONOTONIC'
            for key in ('wire', 'entry'):
                deadline = observed.get(key+'_deadline')
                if type(deadline) in (int, float) and math.isfinite(deadline) and 0 < deadline < 2**53:
                    delta = (int(deadline*1_000_000_000)-now)//1_000_000
                    if -600000 <= delta <= 600000: out[key+'_remaining_milliseconds'] = delta
            began = trace.get('owner_begin') if type(trace) is dict else None
            if type(began) is int and 0 < began <= now:
                delta = (began+120_000_000_001-now)//1_000_000
                if -600000 <= delta <= 120000: out['owner_remaining_milliseconds'] = delta
    return validated_transport(out) or unknown_transport()


def validated_host_fault(value):
    """The already captured first Host source location, never error text."""
    from tu1nz_public_operator_io import MODULES
    types = {n for n, v in vars(builtins).items()
             if isinstance(v, type) and issubclass(v, BaseException)} | {
                 'Hold', 'Denied', 'FlowFailure', 'OwnerFailure', 'NativeFSUIDFailure'}
    if type(value) is not dict or set(value) != {'component', 'line', 'type'}:
        return None
    if type(value['component']) is not str or value['component'] not in {
            '<authenticated-memory:'+n+'>' for n in MODULES if n != 'io'}:
        return None
    if type(value['line']) is not int or not 0 < value['line'] < 10000 or \
            type(value['type']) is not str or value['type'] not in types:
        return None
    return dict(value)


def validated_owner_counts(value):
    # Permit excess/mismatched counts as diagnostics, never as acceptance.
    if type(value) is not dict or set(value) != {'owner_intents', 'owner_acks'} or not all(
            type(n) is int and 0 <= n <= 512 for n in value.values()):
        return None
    return dict(value)


def capture_owner_counts(error):
    """Use the actual failed comparison's integers; no journal reread."""
    filename = str(Path(__file__).resolve().parents[1]/'tests/public_maintenance_native.py')
    trace = error.__traceback__
    while trace is not None:
        frame = trace.tb_frame
        if frame.f_code.co_filename == filename and frame.f_code.co_name == 'measured':
            return validated_owner_counts({'owner_intents': frame.f_locals.get('intents'),
                                           'owner_acks': frame.f_locals.get('acks')})
        trace = trace.tb_next
    return None


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
