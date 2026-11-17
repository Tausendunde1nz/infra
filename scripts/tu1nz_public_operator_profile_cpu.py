"""Test-only, fixed-label CPU attribution; no observations/results are replaced."""

LABELS = frozenset(('reader_properties', 'reader_decode', 'reader_value',
    'process', 'threads', 'proc_text', 'proc_bytes', 'writer', 'paths',
    'authority', 'units', 'actors', 'files', 'object_writers'))
PHASES = frozenset(('admission', 'apply', 'finish', 'close'))

CORE = r'''
import time as _pc_time
_pc_rows={}
_pc_stack=[]
def _pc_wrap(label,actual):
 def measured(*args,**kwargs):
  phase=_owner_phase
  if phase is None:return actual(*args,**kwargs)
  wall=_pc_time.monotonic_ns();cpu=_pc_time.process_time_ns();frame=[0,0]
  _pc_stack.append(frame)
  try:return actual(*args,**kwargs)
  finally:
   used_cpu=_pc_time.process_time_ns()-cpu;used_wall=_pc_time.monotonic_ns()-wall
   _pc_stack.pop()
   if _pc_stack:
    _pc_stack[-1][0]+=used_cpu;_pc_stack[-1][1]+=used_wall
   row=_pc_rows.setdefault(phase,{}).setdefault(label,dict(calls=0,cpu_ns=0,wall_ns=0,
     exclusive_cpu_ns=0,exclusive_wall_ns=0))
   row['calls']+=1;row['cpu_ns']+=used_cpu;row['wall_ns']+=used_wall
   row['exclusive_cpu_ns']+=used_cpu-frame[0];row['exclusive_wall_ns']+=used_wall-frame[1]
 return measured
'''

INSTALL = r'''
# Append AFTER the existing READ_COST_WRAPPER. Same delegates/aliases/results;
# CPU accounting is active only inside the already measured Owner phases.
for _name,_label in (('properties','reader_properties'),('selected_values','reader_decode'),
                    ('observed_value','reader_value')):
 setattr(_reader,_name,_pc_wrap(_label,getattr(_reader,_name)))
for _name,_label in (('process','process'),('threads_check','threads'),
                    ('proc_text','proc_text'),('proc_bytes','proc_bytes'),('writer_check','writer')):
 _old=getattr(_observer,_name);_new=_pc_wrap(_label,_old);setattr(_observer,_name,_new)
 if _name=='process':
  for _role in ('host','probes'):
   if getattr(s.load(_role),_name,None) is _old:setattr(s.load(_role),_name,_new)
for _name,_label in (('check','authority'),('units_check','units'),('actors_check','actors'),('check_files','files')):
 setattr(_observer.Authority,_name,_pc_wrap(_label,getattr(_observer.Authority,_name)))
_paths.check=_pc_wrap('paths',_paths.check)
_fence.writer_check=_pc_wrap('object_writers',_fence.writer_check)
_pc_save_original=_save_read_cost
def _save_read_cost():
 try:_pc_save_original()
 finally:
  import json,os
  raw=json.dumps({'rows':_pc_rows,'stack_empty':not _pc_stack},sort_keys=True).encode()
  fd=os.open('/fixture-r4/cpu-profile.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
  except BaseException:raise
'''

WRAPPER = CORE + INSTALL


def validate(value):
    if type(value) is not dict or set(value) != {'rows', 'stack_empty'} or value['stack_empty'] is not True:
        raise ValueError('PROFILE_SCHEMA')
    rows = value['rows']
    if type(rows) is not dict or not set(rows) <= PHASES:
        raise ValueError('PROFILE_SCHEMA')
    for group in rows.values():
        if type(group) is not dict or not set(group) <= LABELS:
            raise ValueError('PROFILE_SCHEMA')
        for row in group.values():
            if type(row) is not dict or set(row) != {'calls', 'cpu_ns', 'wall_ns', 'exclusive_cpu_ns', 'exclusive_wall_ns'}:
                raise ValueError('PROFILE_SCHEMA')
            if not all(type(v) is int and 0 <= v <= 720_000_000_000 for v in row.values()):
                raise ValueError('PROFILE_SCHEMA')
            if not 1 <= row['calls'] <= 10_000_000 or row['exclusive_cpu_ns'] > row['cpu_ns'] or row['exclusive_wall_ns'] > row['wall_ns']:
                raise ValueError('PROFILE_SCHEMA')
    return value
