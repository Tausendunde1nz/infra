#!/usr/bin/python3
"""One fixed archive source; bounded lexical/dataflow evidence, never shell execution.

No .env reads, no subprocesses, no raw text output. Ambiguous grammar remains open.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys

ARCHIVE = Path('/var/lib/tu1nz-root-trust-v51/run-20260927T145810Z-09700d05ed357f5d')
SOURCE = ARCHIVE / 'source-02923.bin'
EXPECTED = '878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311'
ENV_PATH = '/opt/telegram_chatbot/.env'
PROGRAMS = frozenset(('bash','sh','dash','source','.','eval','curl','wget','grep','sed',
    'awk','cut','tr','cat','printf','echo','date','tail','head','test','[','true','false',
    'python','python3','jq','env','xargs','find','tee','cp','mv','rm','mkdir','chmod',
    'chown','rclone','tar','gzip','logger','systemctl','docker','read','export','exit',
    'set','return','basename','dirname','wc','timeout','flock'))
KNOWN_PATHS = frozenset((ENV_PATH, '/dev/null', '/usr/local/bin/backup_notify.sh'))


def label(value):
    if value in KNOWN_PATHS:
        return value
    return 'sha256:' + hashlib.sha256(value.encode()).hexdigest()


def summarize(data):
    if len(data) > 131072:
        raise ValueError('source_size')
    text = data.decode('utf-8', errors='strict')
    rows = []
    findings = set()
    assignment_dependencies = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith('#'):
            continue
        # Preserve only variable-name fingerprints, never variable values or names.
        refs = re.findall(r'\$(?:\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}|([A-Za-z_][A-Za-z0-9_]*))', line)
        variables = sorted({label(a or b) for a,b in refs})
        if '$(' in line or '`' in line:
            findings.add('COMMAND_SUBSTITUTION_REQUIRES_REVIEW')
        if re.search(r'<<|\\\s*$|\b(?:function|case|while|for|if)\b', line):
            findings.add('COMPOUND_SHELL_REQUIRES_REVIEW')
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=';&|<>()')
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            findings.add('LEXICAL_PARSE_ERROR')
            rows.append({'line':lineno, 'parse_error':True})
            continue
        assignment = re.match(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=', line)
        if assignment:
            assignment_dependencies.append({'line':lineno, 'variable':label(assignment.group(1)), 'depends_on':variables})
        programs = set()
        files = []
        source_env = False
        eval_seen = False
        command_start = True
        commands = []
        for i, token in enumerate(tokens):
            if token in (';', '&&', '||', '|', '(', ')', '&'):
                command_start = True
                continue
            if command_start and re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', token):
                continue
            basename = token.rsplit('/',1)[-1]
            if command_start:
                commands.append(basename if basename in PROGRAMS else label(token))
                if basename in PROGRAMS:
                    programs.add(basename)
                else:
                    findings.add('UNKNOWN_COMMAND_REQUIRES_REVIEW')
                if basename == 'eval':
                    eval_seen = True
                if basename in ('source','.'):
                    if i+1 < len(tokens) and tokens[i+1] == ENV_PATH:
                        source_env = True
                    else:
                        findings.add('DYNAMIC_SOURCE_REQUIRES_REVIEW')
                command_start = False
            if token.startswith('/'):
                files.append(label(token))
        if source_env:
            findings.add('ENV_SHELL_SOURCE_PRESENT')
        if eval_seen:
            findings.add('EVAL_PRESENT')
        if ENV_PATH in line and not source_env:
            findings.add('ENV_REFERENCE_REQUIRES_DATAFLOW_REVIEW')
        if any(x in programs for x in ('python','python3','awk','sed','sh','bash','dash','xargs')):
            findings.add('INTERPRETER_OR_TRANSFORM_REQUIRES_REVIEW')
        redirects = [x for x in tokens if re.fullmatch(r'[<>]+', x)]
        rows.append(dict(line=lineno, program_candidates=sorted(programs), command_positions=commands,
            file_candidates=sorted(set(files)), variable_dependencies=variables,
            redirection_operators=redirects, env_literal_present=ENV_PATH in line,
            env_shell_source=source_env, eval_candidate=eval_seen))
    return dict(source_sha256=hashlib.sha256(data).hexdigest(), source_bytes=len(data),
        source_lines=len(text.splitlines()), statement_shapes=rows,
        assignment_dependencies=assignment_dependencies, findings=sorted(findings),
        safe_parser_proved=False, active_caller_proved=False,
        status='REVIEW_REQUIRED', limitation='Lexical candidates are not an AST or caller proof; no automatic SAFE classification.')


def read_fixed():
    # Every ancestor checked before opening; root-private chain prevents chatops swaps.
    for p in reversed(SOURCE.parents):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('unsafe_archive_chain')
        if any('posix_acl' in x for x in os.listxattr(p)):
            raise ValueError('unexpected_archive_acl')
    before=SOURCE.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_mode & 0o077:
        raise ValueError('unsafe_archive_source')
    if os.listxattr(SOURCE):
        raise ValueError('unexpected_source_xattr')
    fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        start=os.fstat(f.fileno())
        data=f.read(131073)
        end=os.fstat(f.fileno())
    def identity(s): return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    if identity(before)!=identity(start) or identity(start)!=identity(end):
        raise ValueError('source_changed')
    if hashlib.sha256(data).hexdigest()!=EXPECTED:
        raise ValueError('source_hash_mismatch')
    return data


def main():
    if os.geteuid()!=0 or len(sys.argv)!=1:
        return 77
    os.environ.clear()
    try:
        result=summarize(read_fixed())
    except Exception as e:
        result={'status':'INCOMPLETE','error_class':type(e).__name__}
        print('TU1NZ_SEMANTIC_V7='+json.dumps(result,sort_keys=True))
        return 2
    print('TU1NZ_SEMANTIC_V7='+json.dumps(result,sort_keys=True))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
