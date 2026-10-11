"""Exact history-only stdin entry; no installer, admission, database or start."""
import json

import tu1nz_s8_execution_contract as c
from tu1nz_s8_execution_observer import history


def main():
    out = dict(schema='TU1NZ_S8_HISTORICAL_READ_R5_DELTA_V1', historical_capture='RED',
               primary=None, abort=None, cleanup=[], fd_capacity={}, live_authority=False,
               slot_consumed=False, retry_allowed=False, historical_cause='UNKNOWN')
    try:
        out['history'] = history(fd_evidence=out['fd_capacity'])
        out['historical_capture'] = 'GREEN'
    except BaseException as error:
        out['primary'] = c.failure_record(error)
        out['primary']['errno'] = getattr(error, 'errno', None)
        out['read_failure'] = getattr(error, '_s8_read_failure', None)
        out['abort'] = getattr(error, '_s8_abort_error', None)
        out['cleanup'] = getattr(error, '_s8_cleanup_errors', [])
    print(json.dumps(out, sort_keys=True))
    raise SystemExit(0 if out['historical_capture'] == 'GREEN' else 2)
