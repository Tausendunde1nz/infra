"""Review redacted evidence; exit zero is not semantic closure."""
READER = '3b9e28472b66c6c17c438a8075fe29eca2d86c835fae76a3dc7f369ece3dd64b'
SOURCE = '878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311'

def review(record):
    if record.get('reader_sha256') != READER:
        raise ValueError('reader binding')
    data=record.get('result',{})
    if record.get('ssh_returncode') != 0 or data.get('source_sha256') != SOURCE:
        raise ValueError('collection not verified')
    rows=data.get('statement_shapes')
    if not isinstance(rows,list):raise ValueError('missing statement evidence')
    errors=[r['line'] for r in rows if r.get('parse_error') is True]
    return dict(collection='VERIFIED',semantics='INCOMPLETE',activation_ready=False,
        parse_error_lines=errors,findings=data.get('findings',[]),
        caller_status='NOT_PROVED',safe_parser_status='NOT_PROVED',
        reason='V7 is lexical evidence only; false proof flags are not negative evidence.')
