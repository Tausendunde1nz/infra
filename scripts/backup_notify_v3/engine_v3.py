"""Final bounded caller/sink projection. UNKNOWN never implies trusted input."""
import hashlib
import re
import shlex

TARGET='/usr/local/bin/backup_notify.sh'
ENV='/opt/telegram_chatbot/.env'
SHELL={'sh','bash','dash'}
CATEGORIES={'curl':'NETWORK','wget':'NETWORK','send_telegram':'NOTIFICATION',
 'logger':'LOGGING','tee':'LOGGING','printf':'LOGGING','echo':'LOGGING',
 'test':'FILE_CHECK','[':'FILE_CHECK','stat':'FILE_CHECK','find':'FILE_CHECK',
 'grep':'BACKUP_STATUS','tail':'BACKUP_STATUS','head':'BACKUP_STATUS',
 'cat':'FILE_READ','cut':'DATA_PARSE','sed':'DATA_PARSE','awk':'DATA_PARSE',
 'date':'TIME','true':'CONTROL','false':'CONTROL','exit':'CONTROL','set':'CONTROL'}
# Only public fixed executable names may leave the protected analysis.
PUBLIC_PROGRAMS={'/usr/bin/'+x for x in CATEGORIES if re.fullmatch('[a-z_]+',x)}|{
 '/bin/sh','/bin/bash','/usr/bin/bash','/usr/bin/sh','/usr/local/bin/tu1nz_lock.sh'}


def walk(n):
 yield n
 for key,v in vars(n).items():
  if key=='pos':continue
  for x in v if isinstance(v,list) else [v]:
   if hasattr(x,'kind'):yield from walk(x)


def parse(raw,parser):
 text=raw.decode('utf-8','strict')
 roots=parser.parse(text)
 nodes=[n for r in roots for n in walk(r)]
 # Unknown syntax stays unknown; do not certify safety from a parser success.
 if not nodes and text.strip() and not all(x.lstrip().startswith('#') for x in text.splitlines() if x.strip()):raise ValueError('empty_ast')
 return text,nodes


def parameters(n):return {x.value for x in walk(n) if x.kind=='parameter'}

def constants(nodes):
 values={};bad=set()
 for n in nodes:
  if n.kind!='assignment':continue
  name,sep,value=n.word.partition('=')
  if not sep:continue
  if getattr(n,'parts',[]):bad.add(name);continue
  if name in values and values[name]!=value:bad.add(name)
  values[name]=value
 return {k:v for k,v in values.items() if k not in bad}


def resolve(w,values):
 if any(n.kind in ('commandsubstitution','processsubstitution') for n in walk(w)):return None
 value=w.word
 for name in parameters(w):
  if name not in values:return None
  value=re.sub(r'\$\{'+re.escape(name)+r'\}|\$'+re.escape(name)+r'(?![A-Za-z0-9_])',lambda _:values[name],value)
 if '$' in value or '`' in value:return None
 return value


def path_category(value):
 if value is None:return 'UNKNOWN'
 if value==ENV:return 'UNTRUSTED_ENV'
 if value=='/dev/null':return 'NULL_DEVICE'
 if value.startswith('/var/log/'):return 'LOG_PATH'
 if value.startswith(('/backups/','/var/lib/')):return 'STATE_OR_BACKUP'
 if value.startswith('/tmp/'):return 'TEMPORARY'
 if value.startswith('/'):return 'OTHER_FIXED_ABSOLUTE'
 return 'RELATIVE_OR_UNKNOWN'


def sink_matrix(raw,parser):
 try:text,nodes=parse(raw,parser)
 except Exception:return {'status':'UNKNOWN','commands':[],'return_status_effect':'UNKNOWN'}
 vals=constants(nodes);taint={};env_read=set()
 for n in nodes:
  if n.kind!='command':continue
  words=[p for p in n.parts if p.kind=='word']
  if any(resolve(w,vals)==ENV for w in words):env_read.add(id(n))
  if any(getattr(r,'type','').startswith('<') and path_category(resolve(r.output,vals))=='UNTRUSTED_ENV' for r in walk(n) if r.kind=='redirect' and hasattr(getattr(r,'output',None),'word')):env_read.add(id(n))
 assignments=[n for n in nodes if n.kind=='assignment']
 for _ in range(len(assignments)+1):
  changed=False
  for n in assignments:
   name=n.word.partition('=')[0];deps=parameters(n)
   kind=None
   if any(id(x) in env_read for x in walk(n)):kind='ENV_TAINTED'
   elif any(taint.get(d) in ('ENV_TAINTED','DERIVED_FROM_ENV') for d in deps):kind='DERIVED_FROM_ENV'
   elif any(x.kind=='command' and any(getattr(w,'word','') in ('cat','/usr/bin/cat','tail','/usr/bin/tail','head','/usr/bin/head') for w in getattr(x,'parts',[])[:1]) for x in walk(n)):kind='FILE_DERIVED'
   elif any(x.kind in ('commandsubstitution','processsubstitution') for x in walk(n)):kind='UNKNOWN'
   elif deps:kind='UNKNOWN'
   if kind and taint.get(name)!=kind:
    # Never erase env taint because of subsequent assignment or uncertain branch.
    if taint.get(name) in ('ENV_TAINTED','DERIVED_FROM_ENV'):continue
    taint[name]=kind;changed=True
  if not changed:break
 rows=[]
 for n in nodes:
  if n.kind!='command':continue
  words=[p for p in n.parts if p.kind=='word']
  if not words:continue
  program=resolve(words[0],vals);base=program.rsplit('/',1)[-1] if program else None
  args=[]
  for i,w in enumerate(words[1:],1):
   deps=parameters(w)
   if any(id(x) in env_read for x in walk(w)):kind='ENV_TAINTED'
   elif any(taint.get(d)=='ENV_TAINTED' for d in deps):kind='ENV_TAINTED'
   elif any(taint.get(d)=='DERIVED_FROM_ENV' for d in deps):kind='DERIVED_FROM_ENV'
   elif any(taint.get(d)=='FILE_DERIVED' for d in deps):kind='FILE_DERIVED'
   elif deps:kind='UNKNOWN'
   elif any(x.kind in ('commandsubstitution','processsubstitution') for x in walk(w)):kind='UNKNOWN'
   else:kind='STATIC'
   args.append({'position':i,'origin':kind})
  redirs=[]
  for r in walk(n):
   if r.kind=='redirect':
    output=getattr(r,'output',None)
    redirs.append(path_category(resolve(output,vals)) if hasattr(output,'word') else 'FD_OR_UNKNOWN')
  shell=base in ('source','.','eval') or (base in SHELL and any(resolve(w,vals)=='-c' for w in words[1:]))
  rows.append({'line':text.count('\n',0,n.pos[0])+1,'program_kind':'FIXED_ABSOLUTE' if program and program.startswith('/') else 'PATH_LOOKUP' if program else 'DYNAMIC',
   'public_program':program if program in PUBLIC_PROGRAMS else None,
   'function':CATEGORIES.get(base,'UNKNOWN'),'arguments':args,'redirection_categories':redirs,
   'shell_evaluation':shell,'return_status_effect':'UNKNOWN','untrusted_env_reference':id(n) in env_read})
 return {'status':'PROJECTED','commands':rows,'return_status_effect':'UNKNOWN','safety_certified':False}


def shell_edges(raw,parser,known):
 try:text,nodes=parse(raw,parser)
 except Exception:return [],True
 vals=constants(nodes);edges=[];unknown=False
 for n in nodes:
  if n.kind!='command':continue
  words=[p for p in n.parts if p.kind=='word']
  if not words:continue
  prog=resolve(words[0],vals);args=[resolve(w,vals) for w in words[1:]]
  kind='EXEC';dest=prog
  if prog in ('source','.'):kind='SOURCE';dest=args[0] if args else None
  elif prog and prog.rsplit('/',1)[-1] in SHELL:
   kind='WRAPPER'
   if args and args[0] and not args[0].startswith('-'):dest=args[0]
   else:unknown=True;dest=None
  if dest in known:edges.append({'target':dest,'kind':kind,'resolution':'FIXED','line':text.count('\n',0,n.pos[0])+1})
  elif dest and not dest.startswith('/'):
   hits=[p for p in known if p.rsplit('/',1)[-1]==dest]
   for p in hits:edges.append({'target':p,'kind':kind,'resolution':'PATH_LOOKUP_UNKNOWN','line':text.count('\n',0,n.pos[0])+1})
   # PATH builtins don't introduce arbitrary script calls; unknown external programs do.
   if dest not in CATEGORIES and dest not in ('export','read','local','return','shift','cd',':'):unknown=True
  elif dest is None:unknown=True
  elif dest not in PUBLIC_PROGRAMS and dest not in known:unknown=True
  if prog in ('eval','exec','env','sudo','su','xargs','run-parts','python','python3','perl'):unknown=True
 return edges,unknown


def fragments(raw,path):
 """Known outer grammars only. Unsupported entries remain unknown."""
 text=raw.decode('utf-8','strict');rows=[];unknown=False
 if path.endswith(('.service','.timer','.conf')) and ('/systemd/' in path):
  lines=text.replace('\\\n',' ').splitlines()
  for line in lines:
   key,sep,val=line.partition('=')
   if key.strip().startswith('Exec') and sep:
    # systemd exec grammar is not a shell grammar; only plain argv supported.
    try:words=shlex.split(val)
    except ValueError:unknown=True;continue
    if not words:continue
    while words[0] and words[0][0] in '-+!:@':words[0]=words[0][1:]
    if any(x in val for x in ('$','%','\\')):unknown=True
    rows.append(('SYSTEMD',None,words))
  return rows,unknown
 if path=='/etc/crontab' or path.startswith('/etc/cron.d/') or '/crontabs/' in path:
  root_tab=path.endswith('/root')
  for line in text.splitlines():
   line=line.strip()
   if not line or line.startswith('#'):continue
   if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=',line):continue
   parts=line.split(None,6 if not root_tab else 5)
   index=1 if line.startswith('@') else 5
   fields=line.split(None,index+(0 if root_tab else 1))
   if len(fields)<=index:unknown=True;continue
   user='root' if root_tab else fields[index]
   cmd=fields[index if root_tab else index+1] if len(fields)>index+(0 if root_tab else 1) else ''
   rows.append(('CRON',user,cmd))
  return rows,unknown
 return [('SCRIPT',None,text)],False


def caller_projection(raw,path,parser,known):
 try:parts,unknown=fragments(raw,path)
 except Exception:return {'edges':[],'unknown':True,'root_cron':False}
 edges=[];root_cron=False
 for context,user,payload in parts:
  if context=='SYSTEMD':
   if not payload:continue
   prog=payload[0];dest=prog;kind='EXEC'
   if prog.rsplit('/',1)[-1] in SHELL:
    if len(payload)>=3 and payload[1]=='-c':
     new,u=shell_edges(payload[2].encode(),parser,known);edges.extend(new);unknown|=u;continue
    elif len(payload)>1 and not payload[1].startswith('-'):dest=payload[1];kind='WRAPPER'
    else:unknown=True
   if dest in known:edges.append({'target':dest,'kind':kind,'resolution':'FIXED','line':None})
   elif dest not in PUBLIC_PROGRAMS:unknown=True
  else:
   if context=='CRON' and user not in ('root','0'):continue
   root_cron|=context=='CRON'
   new,u=shell_edges(payload.encode(),parser,known);edges.extend(new);unknown|=u
 return {'edges':edges,'unknown':unknown,'root_cron':root_cron,'text_reference':TARGET in raw.decode('utf8','replace') and not any(x['target']==TARGET for x in edges)}


def graph_decision(nodes,roots,target=TARGET):
 """Precautionary category does not pretend UNKNOWN is a proven active caller."""
 chains=[];uncertain=[]
 for root in roots:
  if root['root'] is False or root['active'] is False:continue
  stack=[(root['path'],[])];seen=set()
  while stack:
   path,chain=stack.pop()
   if path in seen:continue
   seen.add(path);chain=chain+[path]
   if path==target:
    chains.append({'root':root['path'],'chain':chain,'active':root['active'],'root_context':root['root']});continue
   node=nodes.get(path)
   if node is None or node.get('unknown') or root['active']=='UNKNOWN' or root['root']=='UNKNOWN':uncertain.append(root['path'])
   if node:
    for edge in node['edges']:
     if edge['resolution']!='FIXED':uncertain.append(root['path'])
     stack.append((edge['target'],chain))
 proven=any(c['active'] is True and c['root_context'] is True for c in chains)
 category='ACTIVE_ROOT_CALLER_UNSAFE_OR_UNKNOWN' if chains or uncertain else 'NO_ACTIVE_ROOT_CALLER'
 return {'classification':category,'active_root_call_proved':proven,'classification_basis':'PROVEN_OR_POSSIBLE_ROOT_REACHABILITY' if category!='NO_ACTIVE_ROOT_CALLER' else 'CLOSED_DECLARED_ROOT_SET',
 'chains':chains,'uncertain_root_entries':sorted(set(uncertain)),
 'replacement_contract_complete':False,'activation_ready':False}


def quarantine_plan(decision):
 # A bounded target guard closes calls through this pathname even when wrapper
 # names are dynamically assembled. It does not claim to close unrelated code.
 if decision['classification']=='NO_ACTIVE_ROOT_CALLER':return {'action':'PRESERVE_HISTORICAL','activation_ready':False}
 return {'action':'QUARANTINE_EXACT_TARGET_AND_PROVEN_CALLERS','target':TARGET,
 'backup_original_bytes':True,'verify_parent_identity_and_hash':True,
 'guard_exit':78,'automatic_rollback':'KEEP_QUARANTINE','manual_original_recovery_only':True,
 'functional_loss':'BACKUP_NOTIFICATION_FUNCTION_UNKNOWN','activation_ready':False}


def strict_data_parser(data):
 """Offline component contract, not a claimed production replacement schema."""
 if not isinstance(data,bytes) or len(data)>512:raise ValueError('invalid_data')
 try:text=data.decode('ascii')
 except UnicodeError:raise ValueError('invalid_data') from None
 out={}
 rules={'ENABLED':r'[01]','TIMEOUT_SECONDS':r'(?:[1-9]|[12][0-9]|30)'}
 for line in text.split('\n'):
  if not line:continue
  key,sep,value=line.partition('=')
  if not sep or key not in rules or key in out or not re.fullmatch(rules.get(key,r'(?!)'),value):raise ValueError('invalid_data')
  out[key]=value
 if set(out)!=set(rules):raise ValueError('invalid_data')
 return {'enabled':out['ENABLED']=='1','timeout_seconds':int(out['TIMEOUT_SECONDS'])}
