"""Static Bash analysis only. No shell execution of source, no environment reads."""
import hashlib
import json
import re
import shlex
import subprocess

ENV_PATH='/opt/telegram_chatbot/.env'
TARGET='/usr/local/bin/backup_notify.sh'
SHELLS={'bash','sh','dash'}
DATA_READERS={'cat','grep','sed','awk','head','tail','cut'}
SAFE_PROGRAMS=DATA_READERS|SHELLS|{'source','.','eval','curl','wget','printf','echo','exit','set','test','[','read','export','true','false','date','jq','python3','python','flock'}


def walk(node):
    yield node
    for key,value in vars(node).items():
        if key=='pos':continue
        if hasattr(value,'kind'):yield from walk(value)
        elif isinstance(value,list):
            for child in value:
                if hasattr(child,'kind'):yield from walk(child)


def shell_syntax(source,bash='/usr/bin/bash'):
    # Fixed parse-only command, no startup files or inherited BASH_ENV/SHELLOPTS.
    p=subprocess.run([bash,'--noprofile','--norc','-n','-s'],input=source,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,cwd='/',
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/nonexistent'})
    return p.returncode==0 and not p.stdout and not p.stderr


def structural(source,parser):
    text=source.decode('utf-8',errors='strict')
    roots=parser.parse(text)
    nodes=[n for root in roots for n in walk(root)]
    coverage=bytearray(len(text));unsupported=[]
    for n in nodes:
        start,end=n.pos
        if not (0<=start<=end<=len(text)):raise ValueError('AST_range')
        coverage[start:end]=b'1'*(end-start)
        if n.kind in ('word','assignment'):
            raw=text[start:end]
            if re.search(r'\$\{(?![A-Za-z_][A-Za-z0-9_]*\})',raw):
                unsupported.append('COMPLEX_OR_INDIRECT_PARAMETER')
            if '$[[' in raw or '$((' in raw:unsupported.append('ARITHMETIC')
    # Only whitespace and comments may remain outside every parsed node range.
    for line_start,line in _lines(text):
        for j,char in enumerate(line):
            if coverage[line_start+j] or char.isspace():continue
            if char=='#':break
            raise ValueError('AST_incomplete_coverage')
    return text,roots,nodes,sorted(set(unsupported))


def _lines(text):
    start=0
    for line in text.splitlines(keepends=True):yield start,line;start+=len(line)


def params(node):
    return {n.value for n in walk(node) if n.kind=='parameter'}


def _resolve(word,constants):
    if any(n.kind in ('commandsubstitution','processsubstitution') for n in walk(word)):return None
    value=word.word
    for name in params(word):
        if name not in constants:return None
        value=re.sub(r'\$\{'+re.escape(name)+r'\}|\$'+re.escape(name)+r'(?![A-Za-z0-9_])',lambda m:constants[name],value)
    return value


def analyse(source,parser,bash_check=None):
    if bash_check is None:bash_check=shell_syntax
    digest=hashlib.sha256(source).hexdigest()
    try:bash_ok=bash_check(source)
    except Exception as e:return dict(status='INCOMPLETE',error_class=type(e).__name__,source_sha256=digest)
    try:text,roots,nodes,unsupported=structural(source,parser);ast_ok=not unsupported
    except Exception as e:
        return dict(status='PARSER_DISAGREEMENT' if bash_ok else 'SYNTAX_REJECTED',
            bash_parse_ok=bool(bash_ok),structural_parse_ok=False,error_class=type(e).__name__,source_sha256=digest,
            env_facts=['ENV_SEMANTICS_REVIEW_REQUIRED'])
    if not bash_ok or not ast_ok:
        return dict(status='PARSER_DISAGREEMENT',bash_parse_ok=bool(bash_ok),structural_parse_ok=ast_ok,
            unsupported=unsupported,source_sha256=digest,env_facts=['ENV_SEMANTICS_REVIEW_REQUIRED'])
    constants={};tainted=set();env_commands=set();facts=set();uncertainty=set();commands=[]
    assignments=[n for n in nodes if n.kind=='assignment']
    command_nodes=[n for n in nodes if n.kind=='command']
    # Conservative fixed point: never erase taint across branches or later assignments.
    for iteration in range(len(assignments)+2):
        changed=False
        for a in assignments:
            name,sep,value=a.word.partition('=')
            if not sep or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name):
                uncertainty.add('DYNAMIC_ASSIGNMENT');continue
            if not list(getattr(a,'parts',[])):
                if name not in constants:constants[name]=value;changed=True
                elif constants[name]!=value:uncertainty.add('MULTIPLE_STATIC_ASSIGNMENTS')
        for command in command_nodes:
            words=[p for p in command.parts if p.kind=='word']
            if not words:continue
            program=_resolve(words[0],constants);base=program.rsplit('/',1)[-1] if program else None
            arguments=[_resolve(w,constants) for w in words[1:]]
            if ENV_PATH in arguments:
                if base in ('source','.'):
                    env_commands.add(id(command));facts.add('ENV_SOURCED_AS_SHELL');uncertainty.add('SOURCED_CONTENT_UNKNOWN')
                elif base in DATA_READERS:
                    env_commands.add(id(command));facts.add('ENV_PARSED_AS_DATA')
                else:uncertainty.add('ENV_READER_NOT_PROVED')
            for redirection in [n for n in walk(command) if n.kind=='redirect']:
                output=getattr(redirection,'output',None)
                if hasattr(output,'word') and _resolve(output,constants)==ENV_PATH:
                    if redirection.type.startswith('<'):
                        env_commands.add(id(command));facts.add('ENV_SOURCED_AS_SHELL' if base in SHELLS else 'ENV_PARSED_AS_DATA')
                        if base not in DATA_READERS|SHELLS:uncertainty.add('INPUT_CONSUMPTION_NOT_PROVED')
                    else:uncertainty.add('ENV_WRITE_REFERENCE')
        for a in assignments:
            name=a.word.partition('=')[0]
            reads=any(id(n) in env_commands for n in walk(a))
            if reads or params(a)&tainted:
                if name not in tainted:tainted.add(name);changed=True
        if not changed:break
    for command in command_nodes:
        words=[p for p in command.parts if p.kind=='word']
        if not words:continue
        program=_resolve(words[0],constants);base=program.rsplit('/',1)[-1] if program else None
        args=[_resolve(w,constants) for w in words[1:]]
        line=text.count('\n',0,command.pos[0])+1
        row=dict(line=line,program_category=base if base in SAFE_PROGRAMS else 'FIXED_OTHER' if program else 'DYNAMIC',
            argument_count=len(words)-1,tainted_arguments=[],env_read=id(command) in env_commands)
        if params(words[0])&tainted:facts.add('ENV_VALUES_REACH_COMMAND')
        for i,w in enumerate(words[1:],1):
            dependent=bool(params(w)&tainted) or any(id(n) in env_commands for n in walk(w))
            if not dependent:continue
            raw=text[w.pos[0]:w.pos[1]]
            # Conservatively recognize a single fully double-quoted argument only.
            quoted=raw.startswith('"') and raw.endswith('"') and not re.search(r'(?<!\\)".+(?<!\\)"',raw[1:-1])
            row['tainted_arguments'].append(dict(position=i,quoted=quoted))
            facts.add('ENV_VALUES_REACH_FIXED_ARGUMENT' if quoted else 'ENV_VALUES_REACH_ARGUMENT_BOUNDARIES')
            if not quoted:uncertainty.add('UNQUOTED_TAINTED_EXPANSION')
            if base in ('eval','source','.','trap') or base in SHELLS:facts.add('ENV_SOURCED_AS_SHELL')
            if base in ('curl','wget'):uncertainty.add('URL_OPTION_AND_REQUEST_VALIDATION_NOT_PROVED')
        if base in ('eval','source','.') or (base in SHELLS and '-c' in args):
            if not row['tainted_arguments'] and id(command) not in env_commands:uncertainty.add('DYNAMIC_SHELL_EFFECTS')
        if base in ('awk','sed','python','python3','jq'):
            uncertainty.add('EMBEDDED_LANGUAGE_REQUIRES_SEMANTIC_REVIEW')
        if base is None:uncertainty.add('DYNAMIC_COMMAND')
        elif base not in SAFE_PROGRAMS:uncertainty.add('UNKNOWN_COMMAND_EFFECTS')
        if base in DATA_READERS|SHELLS|{'source','.'} and any(a is None for a in args):uncertainty.add('DYNAMIC_INPUT_OR_CODE_ARGUMENT')
        commands.append(row)
    if not env_commands:
        if not uncertainty and ENV_PATH not in text and not any(n.kind in ('commandsubstitution','processsubstitution') for n in nodes):facts.add('ENV_NOT_READ')
        else:uncertainty.add('ENV_READ_NOT_CLOSED')
    if uncertainty:facts.add('ENV_SEMANTICS_REVIEW_REQUIRED')
    shapes=[dict(kind=n.kind,start=n.pos[0],end=n.pos[1]) for n in nodes]
    previous={}
    for line in (22,23,29):
        offset=sum(len(x) for x in text.splitlines(keepends=True)[:line-1])
        covering=[n for n in nodes if n.pos[0]<=offset<n.pos[1]]
        forms=set()
        for n in covering:
            raw=text[n.pos[0]:n.pos[1]]
            if n.kind=='assignment':raw=raw.partition('=')[2]
            if '\n' in raw and raw.startswith('"'):forms.add('MULTILINE_DOUBLE_QUOTE')
            if '\n' in raw and raw.startswith("'"):forms.add('MULTILINE_SINGLE_QUOTE')
            if n.kind in ('heredoc','commandsubstitution','processsubstitution','function','compound'):
                forms.add(n.kind.upper())
        lines=text.splitlines()
        legacy_error=False
        if line<=len(lines):
            rawline=lines[line-1]
            if rawline.endswith('\\'):forms.add('LINE_CONTINUATION')
            try:
                lexer=shlex.shlex(rawline,posix=True,punctuation_chars=';&|<>()')
                lexer.whitespace_split=True;list(lexer)
            except ValueError:legacy_error=True
        previous[str(line)]=dict(present=line<=len(lines),ast_kinds=sorted({n.kind for n in covering}),
            multiline=any('\n' in text[n.pos[0]:n.pos[1]] for n in covering),syntax_forms=sorted(forms),
            legacy_line_lexer_error=legacy_error,redaction_preceded_legacy_lexing=False)
    return dict(status='PARSED_COMPLETE',source_sha256=digest,bash_parse_ok=True,structural_parse_ok=True,
        ast_nodes=len(nodes),ast_shape_sha256=hashlib.sha256(json.dumps(shapes,sort_keys=True).encode()).hexdigest(),
        previous_error_coverage=previous,env_facts=sorted(facts),semantics_complete=not uncertainty,
        semantic_limits=sorted(uncertainty),commands=commands,validation_proved=False,
        # No names, literals, AST word values, URLs or messages leave this function.
        activation_ready=False)


def direct_callers(source,parser):
    """Only exact literal program positions count. Comments/echo are not callers."""
    text,roots,nodes,unsupported=structural(source,parser)
    if unsupported:return dict(status='REVIEW_REQUIRED',calls=[])
    calls=[];dynamic=False
    for n in nodes:
        if n.kind!='command':continue
        words=[p for p in n.parts if p.kind=='word']
        if not words:continue
        program=_resolve(words[0],{});args=[_resolve(w,{}) for w in words[1:]]
        if program is None:dynamic=True
        kind=None
        if program in (TARGET,'backup_notify.sh'):kind='EXEC' if program==TARGET else 'PATH_EXEC_REVIEW'
        elif program in ('source','.') and args and args[0]==TARGET:kind='SOURCE'
        elif program and program.rsplit('/',1)[-1] in SHELLS and args and args[0]==TARGET:kind='WRAPPER'
        elif program in ('eval',) or (program in SHELLS and '-c' in args):dynamic=True
        if kind:
            if 'REVIEW' in kind:dynamic=True
            calls.append(dict(line=text.count('\n',0,n.pos[0])+1,kind=kind,argument_count=len(args)))
    return dict(status='REVIEW_REQUIRED' if dynamic else 'PARSED',calls=calls)


def caller_decision(env_result,callers,coverage_closed=False):
    if any(c.get('hash_matches') is not True for c in callers):return 'REVIEW_REQUIRED'
    if any(c.get('semantic_call') and c.get('active') is not False and c.get('resolution_closed') is not True for c in callers):return 'REVIEW_REQUIRED'
    active=[c for c in callers if c.get('root') is True and c.get('active') is True and c.get('semantic_call') is True]
    if not active:return 'NO_ACTIVE_CALLER' if coverage_closed else 'REVIEW_REQUIRED'
    facts=set(env_result.get('env_facts',[]))
    if env_result.get('status')!='PARSED_COMPLETE':return 'REVIEW_REQUIRED'
    if 'ENV_SOURCED_AS_SHELL' in facts:return 'ACTIVE_ROOT_SHELL_EVALUATION'
    if facts & {'ENV_VALUES_REACH_COMMAND','ENV_VALUES_REACH_ARGUMENT_BOUNDARIES'}:return 'ACTIVE_ROOT_ARGUMENT_INFLUENCE'
    if env_result.get('semantics_complete') and env_result.get('validation_proved') and 'ENV_PARSED_AS_DATA' in facts:return 'ACTIVE_SAFE_DATA_PARSER'
    return 'REVIEW_REQUIRED'


def caller_fragments(raw,path,parser):
    """Recognize cron/systemd outer grammar; pass only shell commands to Bash AST.

    Current root/state evidence is joined separately; neither filenames nor a text
    match alone grants root context or activation.
    """
    text=raw.decode('utf-8',errors='strict');fragments=[];unknown=False
    if path.endswith('.service') or '.service.d/' in path:
        # Continuations are systemd syntax. Do not silently interpret specifiers.
        logical=text.replace('\\\n','')
        for lineno,line in enumerate(logical.splitlines(),1):
            key,sep,value=line.partition('=')
            if not sep or key.strip() not in ('ExecStart','ExecStartPre','ExecStartPost','ExecStop','ExecStopPost','ExecReload'):continue
            if 'backup_notify.sh' not in value:continue
            prefix=value[:len(value)-len(value.lstrip('-+!:@'))]
            if '%' in value or '$' in value or '!' in prefix or ':' in prefix or '@' in prefix:
                unknown=True
            command=value.lstrip('-+')
            try:match=direct_callers(command.encode(),parser)
            except Exception:unknown=True;continue
            fragments.append(dict(line=lineno,context='SYSTEMD',force_root='+' in prefix,
                calls=match['calls'],status=match['status']))
    elif path.startswith('/etc/cron.d/') or path in ('/etc/crontab','/var/spool/cron/crontabs/root'):
        for lineno,line in enumerate(text.splitlines(),1):
            line=line.strip()
            if not line or line.startswith('#') or re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=',line):continue
            if 'backup_notify.sh' not in line:continue
            fields=line.split(None,7)
            schedule=1 if line.startswith('@') else 5
            has_user=path!='/var/spool/cron/crontabs/root'
            pieces=line.split(None,schedule+(1 if has_user else 0))
            if len(pieces)<schedule+(2 if has_user else 1):unknown=True;continue
            root_context=not has_user or pieces[schedule]=='root'
            command=pieces[-1]
            if re.search(r'(?<!\\)%',command):unknown=True;continue
            try:match=direct_callers(command.encode(),parser)
            except Exception:unknown=True;continue
            fragments.append(dict(line=lineno,context='CRON',root=root_context,
                calls=match['calls'],status=match['status']))
    else:
        match=direct_callers(raw,parser);fragments.append(dict(context='SCRIPT',calls=match['calls'],status=match['status']))
    return dict(status='REVIEW_REQUIRED' if unknown or any(f['status']=='REVIEW_REQUIRED' for f in fragments) else 'PARSED',fragments=fragments)
