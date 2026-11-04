"""R5 forward-only runtime replacement within the SAME R3 transaction.

Legacy bytes are protected as an UNTRUSTED read witness, not execution origin.
Only the three hook-free, source-bound units may be stopped. New bytes are
installed after quiet/backup/restore/probes; no old-runtime return is admitted.
No CLI/import mutation. All methods require the surviving production adapter.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import ctypes
import fcntl
import hashlib
import io as memory_io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import tarfile
import time

import tu1nz_public_operator_io as io
import tu1nz_public_operator_context as context
import tu1nz_public_runtime_artifact as artifact
from tu1nz_public_operator_runtime_guard import RuntimeFence, metadata, READ, EXCLUDED
from tu1nz_public_operator_observe import (Authority, CurrentAuthority, UNITS, ENV, process, command,
    typed_exec_properties, EXEC_PROPERTIES, operator_session_start, operator_session_members,
    unit_rows, LEGACY_CONTEXTS_SHA)
from tu1nz_public_operator_host import Adapter, STAGING, LIGHTING, HELPER, DROPIN, ASSET_NAMES
from tu1nz_public_operator_fs import security, OWNED_FILE_FIELDS, Backup

OVERLAY = 'zzz-public-runtime-r5.conf'
CHUNK = 512*1024
REFERENCE = 'TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1'
BUS_PROVIDER = 'libsystemd-shared-255.so'  # exact ABI covered by native255 tests


def elf_loader_profile(raw, *, standalone=False):
    """Read bounded ELF64 headers, never run an unbound census helper.

    The independently originated busctl chooses its PT_INTERP. The loader
    itself must be independently bound AND have no interpreter/DT_NEEDED or
    audit dependencies. This is not a replacement ELF dependency resolver.
    """
    io.require(type(raw) is bytes and 64<=len(raw)<=32*1024*1024 and
        raw[:7]==b'\x7fELF\x02\x01\x01','REPLACEMENT_CENSUS_ELF_PROFILE')
    kind,machine,version,_,offset,_,_,size,stride,count=struct.unpack_from('<HHIQQQIHHH',raw,16)
    io.require(kind in (2,3) and machine in (62,183) and version==1 and size==64 and
        stride==56 and 0<count<=256 and offset>=64 and offset+count*stride<=len(raw),
        'REPLACEMENT_CENSUS_ELF_PROFILE')
    interpreters=[];dynamic=[]
    for index in range(count):
        tag,_,start,_,_,length,_,_=struct.unpack_from('<IIQQQQQQ',raw,offset+index*stride)
        io.require(start<=len(raw) and length<=len(raw)-start,'REPLACEMENT_CENSUS_ELF_BOUNDS')
        if tag==3:interpreters.append(raw[start:start+length])
        if tag==2:dynamic.append(raw[start:start+length])
    if standalone:
        io.require(not interpreters and len(dynamic)<=1,'REPLACEMENT_CENSUS_LOADER_NOT_STANDALONE')
        for body in dynamic:
            io.require(0<len(body)<=65536 and len(body)%16==0,'REPLACEMENT_CENSUS_ELF_DYNAMIC')
            tags=[struct.unpack_from('<qQ',body,i)[0] for i in range(0,len(body),16)]
            io.require(0 in tags and not set(tags[:tags.index(0)]) &
                {1,0x6ffffefb,0x6ffffefc,0x7ffffffd,0x7fffffff},
                'REPLACEMENT_CENSUS_LOADER_NOT_STANDALONE')
        return machine
    io.require(len(interpreters)==1 and 1<len(interpreters[0])<=4096 and
        interpreters[0][-1:]==b'\0' and b'\0' not in interpreters[0][:-1],
        'REPLACEMENT_CENSUS_INTERPRETER')
    try:path=interpreters[0][:-1].decode('ascii')
    except UnicodeError:raise io.Hold('PUBLIC_OPERATOR_REPLACEMENT_CENSUS_INTERPRETER')
    io.require(path.startswith(('/lib/','/lib64/','/usr/lib/')) and
        '..' not in PurePosixPath(path).parts and str(PurePosixPath(path))==path,
        'REPLACEMENT_CENSUS_INTERPRETER')
    return path,machine


validate_receipt = artifact.validate_receipt
inspect_archive = artifact.inspect_archive


def dbus_properties(path,interface,deadline):
    row=command(['/usr/bin/busctl','--system','--auto-start=no','--allow-interactive-authorization=no',
        '--json=short','call','org.freedesktop.systemd1',path,'org.freedesktop.DBus.Properties',
        'GetAll','s',interface],deadline)
    io.require(row.returncode==0,'REPLACEMENT_LOADER_ENVIRONMENT_READ_UNKNOWN')
    body=io.parse(row.stdout)
    io.require(type(body) is dict and set(body)=={'type','data'} and body['type']=='a{sv}' and
        type(body['data']) is list and len(body['data'])==1 and type(body['data'][0]) is dict,
        'REPLACEMENT_LOADER_ENVIRONMENT_TYPE_UNKNOWN')
    return body


def dbus_manager_environment(deadline):
    # Read the SAME complete typed Environment, not all unrelated Manager
    # properties, on EVERY check. No previous GREEN or value is reused.
    row=command(['/usr/bin/busctl','--system','--auto-start=no','--allow-interactive-authorization=no',
        '--json=short','get-property','org.freedesktop.systemd1','/org/freedesktop/systemd1',
        'org.freedesktop.systemd1.Manager','Environment'],deadline)
    io.require(row.returncode==0,'REPLACEMENT_LOADER_ENVIRONMENT_READ_UNKNOWN')
    values={'Environment':io.parse(row.stdout)}
    string_array(values,'Environment')
    return values


def string_array(values,key):
    row=values.get(key)
    io.require(type(row) is dict and set(row)=={'type','data'} and row['type']=='as' and
        type(row['data']) is list and all(type(x) is str for x in row['data']),
        'REPLACEMENT_LOADER_ENVIRONMENT_TYPE_UNKNOWN')
    return row['data']


def manager_loader_environment(values):
    env=string_array(values,'Environment');names=set()
    unsafe={'GLIBC_TUNABLES','GCONV_PATH','GETCONF_DIR','HOSTALIASES','LOCALDOMAIN','LOCPATH',
        'MALLOC_TRACE','NIS_PATH','NLSPATH','RESOLV_HOST_CONF','RES_OPTIONS','TMPDIR','TZDIR'}
    for item in env:
        name,separator,_=item.partition('=')
        io.require(separator and name and name not in names and not name.startswith(('LD_','MALLOC_')) and
                   name not in unsafe,'REPLACEMENT_MANAGER_LOADER_ENVIRONMENT_UNSAFE')
        names.add(name)
    return io.sha(io.canonical(sorted(env)))  # never disclose values


class ReadOnlyBus:
    """Fresh finite Gets/GetAll through authenticated busctl's SAME provider.

    Caller authenticates/fences the ELF closure BEFORE supplying its FD.
    Explicit messages preserve NO_AUTO_START/noninteractive flags. No
    actions, generic call interface, reconnect or cached observation.
    """
    KEYS={**{k:'a(sasbttttuii)' for k in EXEC_PROPERTIES},
          'Environment':'as','PassEnvironment':'as','UnsetEnvironment':'as','EnvironmentFiles':'a(sb)'}

    def __init__(self,fd,deadline):
        self.deadline=deadline;self.bus=ctypes.c_void_p();self.broken=False;self.pid=os.getpid()
        self.start_limit_watch=None
        io.require('DBUS_SYSTEM_BUS_ADDRESS' not in os.environ and
                   not any(k in os.environ for k in artifact.LOADER_UNSET),'REPLACEMENT_READER_ENVIRONMENT_UNBOUND')
        self.lib=ctypes.CDLL('/proc/self/fd/'+str(fd),mode=os.RTLD_LOCAL|os.RTLD_NOW,use_errno=True)
        P=ctypes.c_void_p;S=ctypes.c_char_p;I=ctypes.c_int;U=ctypes.c_uint64
        signatures={
            'sd_bus_new':([ctypes.POINTER(P)],I),
            'sd_bus_set_address':([P,S],I),'sd_bus_set_bus_client':([P,I],I),
            'sd_bus_set_method_call_timeout':([P,U],I),'sd_bus_start':([P],I),
            'sd_bus_close':([P],None),
            'sd_bus_unref':([P],P),'sd_bus_message_unref':([P],P),
            'sd_bus_message_new_method_call':([P,ctypes.POINTER(P),S,S,S,S],I),
            'sd_bus_message_set_auto_start':([P,I],I),
            'sd_bus_message_set_allow_interactive_authorization':([P,I],I),
            'sd_bus_message_append':([P,S],I),
            'sd_bus_call':([P,P,U,P,ctypes.POINTER(P)],I),
            'sd_bus_message_enter_container':([P,ctypes.c_char,S],I),
            'sd_bus_message_exit_container':([P],I),
            'sd_bus_message_at_end':([P,I],I),
            'sd_bus_message_read_basic':([P,ctypes.c_char,P],I)}
        signatures['sd_bus_message_skip']=([P,S],I)
        signatures['bus_message_get_blob']=([P,ctypes.POINTER(P),ctypes.POINTER(ctypes.c_size_t)],I)
        for name,(args,result) in signatures.items():
            function=getattr(self.lib,name);function.argtypes=args;function.restype=result
        self.libc=ctypes.CDLL(None,use_errno=True)
        self.libc.free.argtypes=[P];self.libc.free.restype=None
        try:
            L=self.lib
            remaining=min(20,self.deadline-time.monotonic())
            io.require(remaining>0,'REPLACEMENT_READER_DEADLINE')
            for result in (L.sd_bus_new(ctypes.byref(self.bus)),):
                io.require(result>=0,'REPLACEMENT_READER_CONNECT_UNKNOWN')
            io.require(L.sd_bus_set_address(self.bus,b'unix:path=/run/dbus/system_bus_socket')>=0 and
                       L.sd_bus_set_bus_client(self.bus,1)>=0 and
                       L.sd_bus_set_method_call_timeout(self.bus,int(remaining*1000000))>=0 and
                       L.sd_bus_start(self.bus)>=0,'REPLACEMENT_READER_CONNECT_UNKNOWN')
            self.check()
        except BaseException:
            self.close();raise

    def check(self):
        if not (not self.broken and self.bus and os.getpid()==self.pid and
                time.monotonic()<self.deadline):
            self.broken=True
            raise io.Hold('PUBLIC_OPERATOR_REPLACEMENT_READER_LOST')

    def get(self,path,interface,key,signature):
        manager=path=='/org/freedesktop/systemd1' and interface=='org.freedesktop.systemd1.Manager'
        service=path in {self.unit_path(u) for u in UNITS} and interface=='org.freedesktop.systemd1.Service'
        io.require((manager and key in ('Environment','UnitPath') and signature=='as') or
                   (service and self.KEYS.get(key)==signature),'REPLACEMENT_READER_SCOPE')
        message=ctypes.c_void_p();reply=ctypes.c_void_p();L=self.lib
        def ok(value):io.require(value>=0,'REPLACEMENT_READER_REPLY_UNKNOWN');return value
        try:
            self.check()
            ok(L.sd_bus_message_new_method_call(self.bus,ctypes.byref(message),b'org.freedesktop.systemd1',
                path.encode(),b'org.freedesktop.DBus.Properties',b'Get'))
            ok(L.sd_bus_message_set_auto_start(message,0))
            ok(L.sd_bus_message_set_allow_interactive_authorization(message,0))
            ok(L.sd_bus_message_append(message,b'ss',ctypes.c_char_p(interface.encode()),ctypes.c_char_p(key.encode())))
            remaining=min(20,self.deadline-time.monotonic());io.require(remaining>0,'REPLACEMENT_READER_DEADLINE')
            ok(L.sd_bus_call(self.bus,message,int(remaining*1000000),None,ctypes.byref(reply)))
            self.check()
            io.require(ok(L.sd_bus_message_enter_container(reply,b'v',signature.encode()))==1,'REPLACEMENT_READER_TYPE')
            io.require(ok(L.sd_bus_message_enter_container(reply,b'a',signature[1:].encode()))==1,'REPLACEMENT_READER_TYPE')
            values=[];size=0
            if signature!='as':
                # Only EMPTY exec/environment-file arrays are admissible.
                io.require(ok(L.sd_bus_message_at_end(reply,0))==1,
                    'REPLACEMENT_LEGACY_EXEC_HOOK_OR_ROOT' if key in EXEC_PROPERTIES else
                    'REPLACEMENT_UNIT_ENVIRONMENT_FILES_FORBIDDEN')
            else:
                while not ok(L.sd_bus_message_at_end(reply,0)):
                    self.check();value=ctypes.c_char_p()
                    io.require(ok(L.sd_bus_message_read_basic(reply,b's',ctypes.byref(value)))==1 and
                               value.value is not None,'REPLACEMENT_READER_TYPE')
                    raw=value.value;size+=len(raw)
                    io.require(size<=2*1024*1024 and len(values)<32768,'REPLACEMENT_READER_OUTPUT_BOUND')
                    values.append(raw.decode())
            ok(L.sd_bus_message_exit_container(reply))
            io.require(ok(L.sd_bus_message_at_end(reply,0))==1,'REPLACEMENT_READER_EXTRA_VALUE')
            ok(L.sd_bus_message_exit_container(reply))
            io.require(ok(L.sd_bus_message_at_end(reply,1))==1,'REPLACEMENT_READER_EXTRA_VALUE')
            self.check();return {'type':signature,'data':values}
        except BaseException:
            self.broken=True;raise
        finally:
            if reply:L.sd_bus_message_unref(reply)
            if message:L.sd_bus_message_unref(message)

    @staticmethod
    def unit_path(unit):
        io.require(unit in UNITS,'REPLACEMENT_READER_SCOPE')
        return '/org/freedesktop/systemd1/unit/'+''.join(c if c.isascii() and c.isalnum() else '_'+format(ord(c),'02x') for c in unit)

    def service(self,unit):
        return self.properties(unit, 'org.freedesktop.systemd1.Service', self.KEYS)

    LIMIT_KEYS={'StartLimitIntervalUSec':'t', 'StartLimitBurst':'u'}
    LIMIT_STATE_KEYS={**LIMIT_KEYS, 'ActiveEnterTimestampMonotonic':'t',
                      'ConditionTimestampMonotonic':'t', 'StateChangeTimestampMonotonic':'t'}

    def start_limits(self,unit):
        body=self.properties(unit, 'org.freedesktop.systemd1.Unit', self.LIMIT_KEYS)
        return {k: v['data'] for k, v in body['data'][0].items()}

    def start_limit_state(self,unit):
        body=self.properties(unit, 'org.freedesktop.systemd1.Unit', self.LIMIT_STATE_KEYS)
        return {k: v['data'] for k, v in body['data'][0].items()}

    def properties(self,unit,interface,keys):
        io.require((interface=='org.freedesktop.systemd1.Service' and keys==self.KEYS) or
                   (interface=='org.freedesktop.systemd1.Unit' and keys in (self.LIMIT_KEYS,self.LIMIT_STATE_KEYS)),
                   'REPLACEMENT_READER_SCOPE')
        # Preserve the original ONE GetAll manager dispatch, not nine
        # separately interleavable property requests. Bound the ENTIRE wire
        # body; the library validates/consumes every unknown variant too.
        message=ctypes.c_void_p();reply=ctypes.c_void_p();L=self.lib
        def ok(value):io.require(value>=0,'REPLACEMENT_READER_REPLY_UNKNOWN');return value
        try:
            self.check();path=self.unit_path(unit)
            ok(L.sd_bus_message_new_method_call(self.bus,ctypes.byref(message),b'org.freedesktop.systemd1',
                path.encode(),b'org.freedesktop.DBus.Properties',b'GetAll'))
            ok(L.sd_bus_message_set_auto_start(message,0))
            ok(L.sd_bus_message_set_allow_interactive_authorization(message,0))
            ok(L.sd_bus_message_append(message,b's',ctypes.c_char_p(interface.encode())))
            remaining=min(20,self.deadline-time.monotonic());io.require(remaining>0,'REPLACEMENT_READER_DEADLINE')
            ok(L.sd_bus_call(self.bus,message,int(remaining*1000000),None,ctypes.byref(reply)))
            self.check();blob=ctypes.c_void_p();size=ctypes.c_size_t()
            try:
                ok(L.bus_message_get_blob(reply,ctypes.byref(blob),ctypes.byref(size)))
                # Complete wire bytes, including every UNKNOWN variant. This
                # stricter 64KiB wire ceiling bounds their JSON expansion well
                # below the original2MiB; never ignore an oversized reply.
                io.require(blob and 0<size.value<=65536,'REPLACEMENT_READER_OUTPUT_BOUND')
            finally:
                if blob:self.libc.free(blob)
            values=self.selected_values(reply,keys=keys)
            io.require(ok(L.sd_bus_message_at_end(reply,1))==1,'REPLACEMENT_READER_EXTRA_VALUE')
            body={'type':'a{sv}','data':[values]}
            io.require(len(io.canonical(body))<=2*1024*1024 and set(keys)==set(values),
                       'REPLACEMENT_READER_OUTPUT_BOUND_OR_MISSING')
            self.check();return body
        except BaseException:
            self.broken=True;raise
        finally:
            if reply:L.sd_bus_message_unref(reply)
            if message:L.sd_bus_message_unref(message)

    def selected_values(self,message,*,keys=None):
        keys=self.KEYS if keys is None else keys
        io.require(keys in (self.KEYS,self.LIMIT_KEYS,self.LIMIT_STATE_KEYS),'REPLACEMENT_READER_SCOPE')
        L=self.lib;result={};seen=set()
        def ok(value):io.require(value>=0,'REPLACEMENT_READER_REPLY_UNKNOWN');return value
        io.require(ok(L.sd_bus_message_enter_container(message,b'a',b'{sv}'))==1,'REPLACEMENT_READER_TYPE')
        while not ok(L.sd_bus_message_at_end(message,0)):
            self.check()
            io.require(len(seen)<512 and ok(L.sd_bus_message_enter_container(message,b'e',b'sv'))==1,
                       'REPLACEMENT_READER_OUTPUT_BOUND')
            name=ctypes.c_char_p()
            io.require(ok(L.sd_bus_message_read_basic(message,b's',ctypes.byref(name)))==1 and
                       name.value is not None,'REPLACEMENT_READER_TYPE')
            key=name.value.decode()
            io.require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,255}',key) and key not in seen,
                       'REPLACEMENT_READER_DICTIONARY_UNKNOWN')
            seen.add(key)
            if key not in keys:
                # Library consumes/validates the complete variant; no current
                # safety property is skipped and missing required keys deny.
                io.require(ok(L.sd_bus_message_skip(message,b'v'))==1,'REPLACEMENT_READER_TYPE')
            else:
                signature=keys[key]
                io.require(ok(L.sd_bus_message_enter_container(message,b'v',signature.encode()))==1,
                           'REPLACEMENT_READER_TYPE')
                values=[];size=0
                if signature in ('t','u'):
                    scalar=ctypes.c_uint64() if signature=='t' else ctypes.c_uint()
                    io.require(ok(L.sd_bus_message_read_basic(message,signature.encode(),ctypes.byref(scalar)))==1,
                               'REPLACEMENT_READER_TYPE')
                    values=scalar.value
                else:
                    io.require(ok(L.sd_bus_message_enter_container(message,b'a',signature[1:].encode()))==1,
                               'REPLACEMENT_READER_TYPE')
                if signature not in ('as','t','u'):
                    io.require(ok(L.sd_bus_message_at_end(message,0))==1,
                        'REPLACEMENT_LEGACY_EXEC_HOOK_OR_ROOT' if key in EXEC_PROPERTIES else
                        'REPLACEMENT_UNIT_ENVIRONMENT_FILES_FORBIDDEN')
                elif signature=='as':
                    while not ok(L.sd_bus_message_at_end(message,0)):
                        self.check();value=ctypes.c_char_p()
                        io.require(ok(L.sd_bus_message_read_basic(message,b's',ctypes.byref(value)))==1 and
                                   value.value is not None,'REPLACEMENT_READER_TYPE')
                        raw=value.value;size+=len(raw)
                        io.require(size<=2*1024*1024 and len(values)<32768,'REPLACEMENT_READER_OUTPUT_BOUND')
                        values.append(raw.decode())
                if signature not in ('t','u'):ok(L.sd_bus_message_exit_container(message))
                io.require(ok(L.sd_bus_message_at_end(message,0))==1,'REPLACEMENT_READER_EXTRA_VALUE')
                ok(L.sd_bus_message_exit_container(message))
                result[key]={'type':signature,'data':values}
            io.require(ok(L.sd_bus_message_at_end(message,0))==1,'REPLACEMENT_READER_EXTRA_VALUE')
            ok(L.sd_bus_message_exit_container(message))
        ok(L.sd_bus_message_exit_container(message));return result

    def environment(self):
        return {'Environment':self.get('/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','Environment','as')}

    def manager_paths(self):
        return self.get('/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','UnitPath','as')['data']

    def simple(self,kind):
        # Exactly the two EXISTING read-only CLI requests. No caller-selected
        # destination, method, policy subject, action or reconnect is exposed.
        io.require(kind in ('owner','manager_owner','jobs'),'REPLACEMENT_READER_SCOPE')
        destination,path,interface,member=(
            (b'org.freedesktop.DBus',b'/org/freedesktop/DBus',b'org.freedesktop.DBus',b'GetNameOwner')
            if kind!='jobs' else (b'org.freedesktop.systemd1',b'/org/freedesktop/systemd1',
                b'org.freedesktop.systemd1.Manager',b'ListJobs'))
        message=ctypes.c_void_p();reply=ctypes.c_void_p();L=self.lib
        def ok(value):io.require(value>=0,'REPLACEMENT_READER_REPLY_UNKNOWN');return value
        try:
            self.check()
            ok(L.sd_bus_message_new_method_call(self.bus,ctypes.byref(message),destination,path,interface,member))
            ok(L.sd_bus_message_set_auto_start(message,0))
            ok(L.sd_bus_message_set_allow_interactive_authorization(message,0))
            if kind!='jobs':
                name=b'org.freedesktop.PolicyKit1' if kind=='owner' else b'org.freedesktop.systemd1'
                ok(L.sd_bus_message_append(message,b's',ctypes.c_char_p(name)))
            remaining=min(20,self.deadline-time.monotonic());io.require(remaining>0,'REPLACEMENT_READER_DEADLINE')
            ok(L.sd_bus_call(self.bus,message,int(remaining*1000000),None,ctypes.byref(reply)))
            self.check();blob=ctypes.c_void_p();size=ctypes.c_size_t()
            try:
                ok(L.bus_message_get_blob(reply,ctypes.byref(blob),ctypes.byref(size)))
                io.require(blob and 0<size.value<=65536,'REPLACEMENT_READER_OUTPUT_BOUND')
            finally:
                if blob:self.libc.free(blob)
            if kind!='jobs':
                value=ctypes.c_char_p()
                io.require(ok(L.sd_bus_message_read_basic(reply,b's',ctypes.byref(value)))==1 and
                    value.value is not None and len(value.value)<=256,'EXISTING_POLICY_DAEMON_UNKNOWN_NO_ACTIVATION')
                result=value.value.decode()
                io.require(re.fullmatch(r':\d+\.\d+',result),'EXISTING_POLICY_DAEMON_UNKNOWN_NO_ACTIVATION')
            else:
                io.require(ok(L.sd_bus_message_enter_container(reply,b'a',b'(usssoo)'))==1 and
                    ok(L.sd_bus_message_at_end(reply,0))==1,'QUEUED_MANAGER_JOB_UNKNOWN')
                ok(L.sd_bus_message_exit_container(reply));result=None
            io.require(ok(L.sd_bus_message_at_end(reply,1))==1,'REPLACEMENT_READER_EXTRA_VALUE')
            self.check();return result
        except BaseException:
            self.broken=True;raise
        finally:
            if reply:L.sd_bus_message_unref(reply)
            if message:L.sd_bus_message_unref(message)

    def close(self):
        if getattr(self,'start_limit_watch',None) is not None:
            self.start_limit_watch.close();self.start_limit_watch=None
        if self.bus:
            self.lib.sd_bus_close(self.bus);self.lib.sd_bus_unref(self.bus);self.bus=ctypes.c_void_p()
        self.broken=True


START_LIMIT_UNIT_FIELDS=('Type','ActiveState','SubState','InvocationID','NRestarts','Result',
                         'MainPID','ControlPID','Job')


def start_limit_state_read(reader, unit_reader, unit):
    """Fresh typed PID1 timestamps bracketed by the existing finite unit view."""
    io.require(unit in UNITS, 'START_LIMIT_UNIT_SCOPE')
    owner=reader.simple('manager_owner')
    before=unit_reader(unit); properties=reader.start_limit_state(unit); after=unit_reader(unit)
    io.require(reader.simple('manager_owner')==owner and
               all(before[k]==after[k] for k in START_LIMIT_UNIT_FIELDS), 'START_LIMIT_STATE_CHANGED')
    return {'unit':unit, 'manager_owner':owner, 'properties':properties,
            'unit_state':{k:after[k] for k in START_LIMIT_UNIT_FIELDS},
            'observed_monotonic_us':time.monotonic_ns()//1000}


def start_limit_permission(current, *, anchor=None, require_active=False):
    """Prove NEXT-request eligibility, never read or claim a zero live counter.

    Pinned systemd255: unit_start returns before the rate test while ACTIVE;
    otherwise it timestamps condition evaluation, except while ACTIVATING.
    A terminal state change follows all such activating attempts. Thus an
    aged successful active invocation, or an aged terminal transition strictly
    AFTER condition evaluation, bounds the last possible rate test. Condition
    time alone is insufficient (the activating/hurry-up path skips it).

    The active anchor survives only the same invocation/condition/active-entry
    and successful stop. A later attempt or failure cannot be silently adopted.
    This relies on the approved current PID1/clock trust, not gap surveillance.
    Native255 counterexamples and the final independent review remain gates.
    https://github.com/systemd/systemd/blob/v255/src/core/unit.c
    https://github.com/systemd/systemd/blob/v255/src/core/service.c
    """
    io.require(type(current) is dict and set(current)==
               {'unit','manager_owner','properties','unit_state','observed_monotonic_us'} and
               current['unit'] in UNITS and type(current['manager_owner']) is str and
               re.fullmatch(r':\d+\.\d+',current['manager_owner']), 'START_LIMIT_STATE_SHAPE')
    p=current['properties'];s=current['unit_state'];now=current['observed_monotonic_us']
    io.require(type(p) is dict and set(p)==set(ReadOnlyBus.LIMIT_STATE_KEYS) and
               all(type(p[k]) is int and 0<=p[k]<2**(32 if k=='StartLimitBurst' else 64)
                   for k in p) and type(now) is int and now>0 and
               type(s) is dict and set(s)==set(START_LIMIT_UNIT_FIELDS) and
               all(type(v) is str for v in s.values()), 'START_LIMIT_STATE_TYPES')
    io.require(s['Type']=='simple' and s['NRestarts']=='0' and s['ControlPID']=='0' and
               not s['Job'] and s['Result']!='start-limit-hit' and
               re.fullmatch('[0-9a-f]{32}',s['InvocationID']), 'START_LIMIT_STATE_NOT_ELIGIBLE')
    active=s['ActiveState']=='active' and s['SubState']=='running' and s['MainPID'].isdecimal() and int(s['MainPID'])>0
    empty=(s['ActiveState'],s['SubState']) in (('inactive','dead'),('failed','failed')) and s['MainPID']=='0'
    io.require(active or (empty and not require_active), 'START_LIMIT_STATE_NOT_ELIGIBLE')
    a=p['ActiveEnterTimestampMonotonic'];c=p['ConditionTimestampMonotonic'];t=p['StateChangeTimestampMonotonic']
    io.require(0<c<=t<=now and 0<=a<=t, 'START_LIMIT_TIMESTAMPS_UNKNOWN')
    interval=p['StartLimitIntervalUSec']
    io.require(interval<2**64-1, 'START_LIMIT_INFINITE_WINDOW_UNPROVEN')
    if not interval or not p['StartLimitBurst']:return 'EXISTING_LIMITER_DISABLED'
    if active:
        io.require(s['Result']=='success' and c<=a and now-a>interval+1000,
                   'START_LIMIT_ACTIVE_WINDOW_NOT_ELAPSED')
        return 'AGED_SUCCESSFUL_ACTIVE_INVOCATION'
    if anchor is not None:
        # A bound original READ_WITNESS is still revalidated as evidence, not
        # accepted merely because its hash or a supplied GREEN bit matches.
        start_limit_permission(anchor, require_active=True)
        ap=anchor['properties'];old=anchor['unit_state']
        same=(anchor['unit']==current['unit'] and anchor['manager_owner']==current['manager_owner'] and
              anchor['observed_monotonic_us']<=now and s['Result']=='success' and
              old['InvocationID']==s['InvocationID'] and
              all(p[k]==ap[k] for k in (*ReadOnlyBus.LIMIT_KEYS,
                  'ActiveEnterTimestampMonotonic','ConditionTimestampMonotonic')))
        if same:return 'SAME_AGED_INVOCATION_NOW_SUCCESSFULLY_EMPTY'
    io.require(c<t and now-t>interval+1000, 'START_LIMIT_TERMINAL_WINDOW_NOT_ELAPSED_OR_ATTEMPT_UNKNOWN')
    return 'AGED_TERMINAL_TRANSITION_AFTER_LAST_CONDITION'


class StartLimitObservation:
    """One passive job-free interval for exactly the three maintenance units.

    systemd255 exports interval/burst, not the live limiter counter. Its
    ratelimit_below() starts a fresh window after a strictly greater elapsed
    interval (CLOCK_MONOTONIC). Observing no relevant job for a full interval,
    with an unchanged manager and current empty/nonrestarting unit, permits
    one start without reset-failed or a trial request. Any observed job or
    reader loss permanently invalidates this observation; no restart of it.

    Only notification subscription changes on this existing connection. No
    unit operation, generic method, provider activation or new infrastructure.
    https://github.com/systemd/systemd/blob/v255/src/basic/ratelimit.c
    https://github.com/systemd/systemd/blob/v255/src/core/service.c
    """
    def __init__(self, reader):
        io.require(reader.start_limit_watch is None, 'START_LIMIT_OBSERVATION_NO_REENTRY')
        self.reader=reader;self.slots={};self.pending=set(UNITS);self.failure=None
        self.ready=False;self.closed=False;self.started=None;self.limits={};self.events=0
        self.state_permissions={}
        reader.start_limit_watch=self  # acquire cleanup ownership before C calls
        P=ctypes.c_void_p;S=ctypes.c_char_p;I=ctypes.c_int
        self.callback_type=ctypes.CFUNCTYPE(I,P,P,P)
        signatures={'sd_bus_add_match':([P,ctypes.POINTER(P),S,self.callback_type,P],I),
                    'sd_bus_slot_unref':([P],P),'sd_bus_process':([P,ctypes.POINTER(P)],I),
                    'sd_bus_message_get_sender':([P],S),'sd_bus_message_get_member':([P],S)}
        for name,(args,result) in signatures.items():
            function=getattr(reader.lib,name);function.argtypes=args;function.restype=result
        self.callback=self.callback_type(self._event)
        try:
            self.owner=reader.simple('manager_owner')
            for unit in UNITS:
                for member in ('JobNew','JobRemoved'):
                    slot=ctypes.c_void_p();self.slots[(unit,member)]=slot
                    match=("type='signal',sender='"+self.owner+"',path='/org/freedesktop/systemd1',"
                           "interface='org.freedesktop.systemd1.Manager',member='"+member+"',arg2='"+unit+"'")
                    io.require(reader.lib.sd_bus_add_match(reader.bus,ctypes.byref(slot),match.encode(),
                               self.callback,None)>=0 and slot, 'START_LIMIT_SIGNAL_MATCH_UNKNOWN')
            self._subscribe()
            self.drain()
            reader.simple('jobs')  # empty at the beginning, not just absent future signals
            for unit in UNITS:self.limits[unit]=reader.start_limits(unit)
            io.require(reader.simple('manager_owner')==self.owner, 'START_LIMIT_MANAGER_CHANGED')
            self.drain();self.started=time.monotonic();self.ready=True
        except BaseException:
            reader.broken=True;self.close();raise

    def _subscribe(self):
        L=self.reader.lib;message=ctypes.c_void_p();reply=ctypes.c_void_p()
        def ok(n):io.require(n>=0,'START_LIMIT_SUBSCRIPTION_UNKNOWN')
        try:
            self.reader.check()
            ok(L.sd_bus_message_new_method_call(self.reader.bus,ctypes.byref(message),self.owner.encode(),
                b'/org/freedesktop/systemd1',b'org.freedesktop.systemd1.Manager',b'Subscribe'))
            ok(L.sd_bus_message_set_auto_start(message,0));ok(L.sd_bus_message_set_allow_interactive_authorization(message,0))
            remaining=min(20,self.reader.deadline-time.monotonic())
            io.require(remaining>0,'START_LIMIT_SUBSCRIPTION_DEADLINE')
            ok(L.sd_bus_call(self.reader.bus,message,int(remaining*1000000),None,ctypes.byref(reply)))
            io.require(L.sd_bus_message_at_end(reply,1)==1,'START_LIMIT_SUBSCRIPTION_REPLY_UNKNOWN')
        finally:
            if reply:L.sd_bus_message_unref(reply)
            if message:L.sd_bus_message_unref(message)

    def _event(self,message,_userdata,_error):
        # Exceptions cannot cross a ctypes callback. Keep the first fault
        # latched; no subsequent observation can make it GREEN again.
        try:
            L=self.reader.lib;member=L.sd_bus_message_get_member(message)
            io.require(not self.closed and L.sd_bus_message_get_sender(message)==self.owner.encode() and
                       member in (b'JobNew',b'JobRemoved'),'START_LIMIT_EVENT_SOURCE_UNKNOWN')
            # Six exact sender/member/arg2 matches are installed above. Any
            # delivery invalidates the interval; no job ID/result/body needs
            # to be copied or interpreted to grant a permission here.
            self.events+=1
            self.failure=self.failure or 'PUBLIC_OPERATOR_START_LIMIT_RELEVANT_JOB_OBSERVED'
        except BaseException:
            self.failure=self.failure or 'PUBLIC_OPERATOR_START_LIMIT_EVENT_VIEW_UNKNOWN'
        return 1

    def check_latched(self):
        if self.failure:raise io.Hold(self.failure)
        io.require(not self.closed,'START_LIMIT_OBSERVATION_CLOSED')

    def drain(self):
        self.reader.check();self.check_latched()
        for _ in range(1024):
            count=self.reader.lib.sd_bus_process(self.reader.bus,None)
            if count<0:
                self.reader.broken=True
                raise io.Hold('PUBLIC_OPERATOR_START_LIMIT_CHANNEL_LOST')
            self.reader.check();self.check_latched()
            if count==0:return
        self.failure='PUBLIC_OPERATOR_START_LIMIT_EVENT_BOUND'
        self.check_latched()

    def remaining(self,unit):
        io.require(self.ready and unit in self.pending and self.started is not None,
                   'START_LIMIT_CURRENT_OBSERVATION_REQUIRED')
        self.drain()
        io.require(self.reader.simple('manager_owner')==self.owner, 'START_LIMIT_MANAGER_CHANGED')
        current=self.reader.start_limits(unit)
        io.require(current==self.limits[unit] and set(current)==set(ReadOnlyBus.LIMIT_KEYS) and
                   type(current['StartLimitIntervalUSec']) is int and 0<=current['StartLimitIntervalUSec']<2**64 and
                   type(current['StartLimitBurst']) is int and 0<=current['StartLimitBurst']<2**32,
                   'START_LIMIT_CONFIGURATION_CHANGED_OR_UNKNOWN')
        interval=current['StartLimitIntervalUSec'];burst=current['StartLimitBurst']
        self.drain()
        if unit in self.state_permissions:
            saved=self.state_permissions[unit]
            fresh=start_limit_state_read(self.reader,saved['unit_reader'],unit)
            io.require(all(fresh[k]==saved['snapshot'][k] for k in
                           ('unit','manager_owner','properties','unit_state')) and
                       start_limit_permission(fresh,anchor=saved['anchor'])==saved['basis'],
                       'START_LIMIT_QUALIFIED_STATE_CHANGED')
            self.drain()
            return 0.0
        if not interval or not burst:return 0.0  # actual existing disabled limiter; never change it
        io.require(interval<2**64-1, 'START_LIMIT_INFINITE_WINDOW_UNPROVEN')
        elapsed=time.monotonic()-self.started
        io.require(elapsed>=0,'START_LIMIT_CLOCK_CHANGED')
        return max(0.0, interval/1_000_000+.001-elapsed)

    def bind_current_permission(self,unit,unit_reader,*,anchor):
        io.require(self.ready and unit in self.pending and unit not in self.state_permissions,
                   'START_LIMIT_PERMISSION_NO_REENTRY')
        self.drain();current=start_limit_state_read(self.reader,unit_reader,unit)
        io.require(current['unit_state']['ActiveState'] in ('inactive','failed') and
                   current['manager_owner']==self.owner and
                   {k:current['properties'][k] for k in ReadOnlyBus.LIMIT_KEYS}==self.limits[unit],
                   'START_LIMIT_PERMISSION_NOT_CURRENT_EMPTY')
        basis=start_limit_permission(current,anchor=anchor)
        self.drain()
        self.state_permissions[unit]={'snapshot':current,'basis':basis,'anchor':anchor,'unit_reader':unit_reader}
        return {'snapshot':current,'basis':basis,'live_counter_read':False,'counter_reset':False}

    def retire_for_start(self,unit):
        io.require(self.remaining(unit)==0,'START_LIMIT_WINDOW_NOT_ELAPSED')
        self._retire(unit)  # AFTER last drain and BEFORE the one owned start

    def retire_already_active(self,unit):
        io.require(self.ready and unit in self.pending,'START_LIMIT_CURRENT_OBSERVATION_REQUIRED')
        self.drain();self._retire(unit)  # no start permission or counter assertion

    def _retire(self,unit):
        for member in ('JobNew','JobRemoved'):
            slot=self.slots.pop((unit,member))
            if slot:self.reader.lib.sd_bus_slot_unref(slot)
        self.pending.remove(unit)

    def close(self):
        if self.closed:return
        for slot in self.slots.values():
            if slot:self.reader.lib.sd_bus_slot_unref(slot)
        self.slots.clear();self.pending.clear();self.closed=True


class LoaderConfiguration:
    """Exact authenticated cache + absent preload, fenced through cleanup.

    Separate inotify instance: later ordinary Paths watches cannot remove the
    creation bit needed to bind an ABSENT preload name. No normalization or
    cache generation; an occupied preload (even empty) is rejected.
    """
    CACHE='/etc/ld.so.cache';PRELOAD='/etc/ld.so.preload'

    def __init__(self,paths,baseline,deadline):
        self.paths=paths;self.deadline=deadline;self.events=self.fd=None;self.ready=False;self.broken=False
        self.cache_path=self.CACHE;self.preload_path=self.PRELOAD
        io.require(Path(self.cache_path).parent==Path(self.preload_path).parent,
                   'REPLACEMENT_LOADER_CONFIGURATION_SCOPE')
        self.parent=paths.get(str(Path(self.cache_path).parent))
        self.libc=ctypes.CDLL(None,use_errno=True)
        self.events=self.libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
        io.require(self.events>=0,'REPLACEMENT_LOADER_CONFIGURATION_WATCH_UNKNOWN')
        self.parent_watch=self.libc.inotify_add_watch(self.events,
            os.fsencode('/proc/self/fd/'+str(self.parent)),0x2fce)
        io.require(self.parent_watch>=0,'REPLACEMENT_LOADER_CONFIGURATION_WATCH_UNKNOWN')
        self.expected=baseline['files'].get(self.cache_path)
        io.require(type(self.expected) is dict and self.expected.get('origin_sha256') in
            baseline['source_origin_receipts'],'REPLACEMENT_LOADER_CACHE_ORIGIN_UNBOUND')
        raw,row=paths.read(self.cache_path)
        io.require(0<len(raw)<=4*1024*1024 and io.sha(raw)==self.expected.get('sha256') and
            all(row[k]==self.expected.get(k) for k in ('uid','gid','mode','attrs','flags')),
            'REPLACEMENT_LOADER_CACHE_BINDING')
        self.identity=tuple(row[k] for k in ('device','inode','mtime_ns','ctime_ns'))
        self.fd=os.open(Path(self.cache_path).name,READ,dir_fd=self.parent)
        before=os.fstat(self.fd)
        io.require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
            (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)==self.identity,
            'REPLACEMENT_LOADER_CACHE_CHANGED')
        self.file_watch=self.libc.inotify_add_watch(self.events,
            os.fsencode('/proc/self/fd/'+str(self.fd)),0x2fce)
        io.require(self.file_watch>=0,'REPLACEMENT_LOADER_CONFIGURATION_WATCH_UNKNOWN')
        self.ready=True;self.check()

    def check(self):
        try:self._check()
        except BaseException:self.broken=True;raise

    def _check(self):
        io.require(self.ready and not self.broken and time.monotonic()<self.deadline,'REPLACEMENT_LOADER_CONFIGURATION_LOST')
        self.paths.check()
        while True:
            try:raw=os.read(self.events,65536)
            except BlockingIOError:break
            offset=0
            while offset<len(raw):
                wd,mask,_,count=struct.unpack_from('iIII',raw,offset)
                name=raw[offset+16:offset+16+count].split(b'\0',1)[0].decode()
                io.require(not mask&(0x4000|0x2000|0x400|0x800|0x8000) and wd!=self.file_watch and
                    not(wd==self.parent_watch and name in (Path(self.cache_path).name,Path(self.preload_path).name)),
                    'REPLACEMENT_LOADER_CONFIGURATION_EVENT')
                offset+=16+count
        try:os.stat(Path(self.preload_path).name,dir_fd=self.parent,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise io.Hold('PUBLIC_OPERATOR_REPLACEMENT_GLOBAL_PRELOAD_FORBIDDEN')
        raw,row=self.paths.read(self.cache_path)
        io.require(io.sha(raw)==self.expected['sha256'] and tuple(row[k] for k in
            ('device','inode','mtime_ns','ctime_ns'))==self.identity and
            all(row[k]==self.expected[k] for k in ('uid','gid','mode','attrs','flags')),
            'REPLACEMENT_LOADER_CACHE_CHANGED')

    def close(self):
        errors=[]
        if self.ready:
            try:self.check()
            except BaseException as error:errors.append(getattr(error,'primary',
                'PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_LOADER_CONFIG_CLOSE_UNKNOWN'))
        for name in ('fd','events'):
            fd=getattr(self,name,None)
            if fd is not None:
                try:os.close(fd)
                except OSError:errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_LOADER_CONFIG_FD_CLOSE_UNKNOWN')
                setattr(self,name,None)
        self.ready=False
        return errors


class LegacyStopFence(RuntimeFence):
    snapshot_only=True

    def reference(self, reference, origins):
        io.require(reference['schema']==REFERENCE and reference['origin_sha256'] in origins and
            io.sha(io.canonical(reference['artifact']))==reference['origin_sha256'],
            'REPLACEMENT_ORIGIN_REFERENCE')
        return {'.':{'kind':'directory'}}

    def identity_digest(self):
        # Current protected legacy snapshot ONLY; never an execution origin.
        return ReplacementFence.identity_digest(self)


class ReplacementFence(RuntimeFence):
    root=artifact.ROOT
    required_objects={'.','python/bin/python3.12','app/src','app/.venv',
        'app/.venv/bin/tu1nz-public-s7','app/.venv/bin/tu1nz-public-s8-landing',
        'app/src/tu1nz_exposure_s10/runtime.py'}

    def __init__(self, reference, paths, origins, **kwargs):
        self.artifact=reference['artifact']
        self.elf_files=set()
        super().__init__(reference,paths,origins,**kwargs)

    def reference(self, reference, origins):
        io.require(reference['schema']==REFERENCE and reference['origin_sha256'] in origins and
            io.sha(io.canonical(reference['artifact']))==reference['origin_sha256'],
            'REPLACEMENT_ORIGIN_REFERENCE')
        out={'.':{'kind':'directory'}}
        for name,row in reference['artifact']['objects'].items():
            out[name]={k:v for k,v in row.items() if k in ('kind','sha256','target')}
        return out

    def profile_match(self,key,row):
        expected={'mode':0o555} if key=='.' else self.artifact['objects'][key]
        io.require(row[2]==row[3]==0 and stat.S_IMODE(row[4])==expected['mode'] and
                   not row[9] and not row[10]&~(0x1000|0x80000), 'REPLACEMENT_METADATA_NOT_SEALED')

    def link_profile_match(self,key,row):
        io.require(row.st_uid==row.st_gid==0 and row.st_nlink==1 and
                   stat.S_IMODE(row.st_mode)==0o777,'REPLACEMENT_LINK_METADATA')

    def content_match(self,key,raw):
        if raw.startswith(b'\x7fELF'):self.elf_files.add(key)

    def identity_digest(self):
        """Fresh full sealed-tree bytes AND metadata digest for R4 READY.

        This is a read, not materialization, adoption, or a historical origin.
        Existing latched watches bracket it. Do not reuse RuntimeFence._walk:
        it admits new watches and updates its initial capture accumulators.
        """
        self.check()
        digest = hashlib.sha256(); count = 0; byte_count = 0; observed = set()
        def record(path, value):
            nonlocal count
            count += 1
            io.require(path in self.expected and path not in observed and count <= 32768 and
                       time.monotonic() < min(self.deadline, self.paths.deadline),
                       'PREPARED_RUNTIME_IDENTITY_BOUND')
            observed.add(path)
            raw = io.canonical({'path': path, **value})
            digest.update(len(raw).to_bytes(4, 'big')); digest.update(raw)
        def walk(fd, path, depth):
            nonlocal byte_count
            io.require(depth < 32, 'PREPARED_RUNTIME_IDENTITY_DEPTH')
            before = metadata(self.paths.d, fd); self.profile_match(path, before)
            record(path, {'kind': 'directory', 'metadata': before})
            names = sorted(os.listdir(fd))
            for name in names:
                if path == '.' and self.snapshot_only and name in EXCLUDED:continue
                rel = name if path == '.' else path+'/'+name
                io.require(rel in self.expected, 'PREPARED_RUNTIME_EXTRA_OBJECT')
                expected = self.expected[rel]
                first = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(first.st_mode):
                    self.link_profile_match(rel, first)
                    attrs = os.listxattr('/proc/self/fd/'+str(fd)+'/'+name, follow_symlinks=False)
                    target = os.readlink(name, dir_fd=fd)
                    io.require(not attrs and expected == {'kind': 'link', 'target': target},
                               'PREPARED_RUNTIME_LINK_CHANGED')
                    fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
                              'st_size', 'st_mtime_ns', 'st_ctime_ns')
                    row = {k: getattr(first, k) for k in fields}
                    again = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    io.require(row == {k: getattr(again, k) for k in fields}, 'PREPARED_RUNTIME_LINK_RACE')
                    record(rel, {'kind': 'link', 'metadata': row, 'attrs': {},
                                 'flags': 'NOT_APPLICABLE_SYMLINK', 'target': target})
                    continue
                io.require(stat.S_ISREG(first.st_mode) or stat.S_ISDIR(first.st_mode),
                           'PREPARED_RUNTIME_OBJECT_TYPE')
                child = os.open(name, READ|(os.O_DIRECTORY if stat.S_ISDIR(first.st_mode) else 0), dir_fd=fd)
                try:
                    row = metadata(self.paths.d, child); self.profile_match(rel, row)
                    io.require(row[:2] == (first.st_dev, first.st_ino), 'PREPARED_RUNTIME_NAME_RACE')
                    if stat.S_ISDIR(first.st_mode):
                        io.require(expected == {'kind': 'directory'}, 'PREPARED_RUNTIME_TYPE_CHANGED')
                        walk(child, rel, depth+1)
                    else:
                        io.require(first.st_nlink == 1 and 0 <= first.st_size <= 32*1024*1024,
                                   'PREPARED_RUNTIME_FILE_BOUND')
                        byte_count += first.st_size
                        io.require(byte_count <= 512*1024*1024, 'PREPARED_RUNTIME_BYTES_BOUND')
                        raw = os.pread(child, first.st_size+1, 0)
                        content = io.sha(raw)
                        io.require(len(raw) == first.st_size and expected == {'kind': 'file', 'sha256': content},
                                   'PREPARED_RUNTIME_FILE_BYTES')
                        record(rel, {'kind': 'file', 'metadata': row, 'sha256': content})
                    io.require(metadata(self.paths.d, child) == row, 'PREPARED_RUNTIME_METADATA_RACE')
                    again = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    io.require((again.st_dev, again.st_ino, again.st_mtime_ns, again.st_ctime_ns) ==
                               (first.st_dev, first.st_ino, first.st_mtime_ns, first.st_ctime_ns),
                               'PREPARED_RUNTIME_NAME_RACE')
                finally:
                    os.close(child)
            io.require(sorted(os.listdir(fd)) == names and metadata(self.paths.d, fd) == before,
                       'PREPARED_RUNTIME_DIRECTORY_RACE')
        walk(self.fd, '.', 0)
        io.require(observed == set(self.expected), 'PREPARED_RUNTIME_INCOMPLETE')
        self.check()
        return {'sha256': digest.hexdigest(), 'objects': count, 'file_bytes': byte_count}


class ReplacementAuthority(Authority):
    def policy_owner(self):return self.read_bus().simple('owner')

    def manager_jobs_clear(self):self.read_bus().simple('jobs')

    def manager_paths(self):return self.read_bus().manager_paths()

    @contextmanager
    def limit(self,deadline):
        # A completed phase's temporary cap must not poison later phases.
        # Mirror the existing Authority/Paths/Channel scoped restoration; do
        # NOT extend the transaction/Owner ceiling or unbreak a failed bus.
        prior=self.reader.deadline if self.reader is not None else self.deadline
        try:
            with super().limit(deadline):yield
        finally:
            if self.reader is not None:
                self.reader.deadline=min(prior,self.deadline)

    def release_fields(self):
        return super().release_fields()|{'operator_dependencies'}

    def admit_prospective_names(self,binding):
        """Additional exact prospective profile, not replacement of live fences."""
        files=io.prospective_names(binding,self.b)
        for path in sorted(files):self.bind_loader_path(path)
        for path,expected in binding['names'].items():
            if expected['kind']=='directory':
                self.paths.get(path);row=self.paths.rows[path][1]
                io.require(all(row[k]==expected[k] for k in ('uid','gid','mode','attrs','flags')),
                           'PROSPECTIVE_DIRECTORY_DRIFT')
            else:
                parent,leaf=str(Path(path).parent),Path(path).name
                identity,target=self.loader_aliases[(parent,leaf)]
                io.require(identity[2:5]==(expected['uid'],expected['gid'],stat.S_IFLNK|expected['mode']) and
                    target==expected['target'],'PROSPECTIVE_ALIAS_DRIFT')
        metadata={}
        for path,expected in binding['metadata'].items():
            canonical=self.bind_loader_path(path)
            io.require(canonical not in metadata or metadata[canonical]==expected,'PROSPECTIVE_METADATA_ALIAS_CONFLICT')
            metadata[canonical]=expected
        self.prospective_metadata=metadata
        self.check_loader_paths()

    def open_runtime(self, baseline, paths, deadline):
        io.operator_dependency_reference(baseline['source_release'],baseline['source_origin_receipts'])
        self.replacement_active=False
        self.prepared_runtime=None
        self.external_dependencies={};self.external_identities={}
        self.loader_bindings={};self.loader_aliases={}
        self.loader_config=LoaderConfiguration.__new__(LoaderConfiguration)
        self.loader_config.__init__(paths,baseline,deadline)
        self.manager_environment=None
        self.census_loader=None
        self.reader=None
        legacy=LegacyStopFence(baseline['source_release']['runtime_reference'],paths,
            baseline['source_origin_receipts'],python_binary=baseline['source_release']['python_binary'],deadline=deadline)
        legacy.files.add(self.loader_config.identity[:2])  # existing cache writers are not exempt
        self.legacy_runtime=legacy
        return legacy

    def extra_unit_contract(self, unit, value, *, stop_only):
        body=self.read_bus().service(unit)
        hooks=typed_exec_properties(io.canonical(body),EXEC_PROPERTIES)
        io.require(not any(hooks.values()) and not value['RootDirectory'] and not value['RootImage'],
                   'REPLACEMENT_LEGACY_EXEC_HOOK_OR_ROOT')
        values=body['data'][0]
        for key in ('Environment','PassEnvironment'):
            io.require(not string_array(values,key),'REPLACEMENT_UNIT_LOADER_ENVIRONMENT_OVERRIDE')
        loaded=self.dropin_path(unit) in value['DropInPaths'].split()
        unset=string_array(values,'UnsetEnvironment');wanted=list(artifact.LOADER_UNSET) if loaded else []
        io.require(len(unset)==len(wanted) and set(unset)==set(wanted),
                   'REPLACEMENT_UNIT_LOADER_UNSET_PROFILE')
        files=values.get('EnvironmentFiles')
        io.require(type(files) is dict and set(files)=={'type','data'} and files['type']=='a(sb)' and
                   files['data']==[],'REPLACEMENT_UNIT_ENVIRONMENT_FILES_FORBIDDEN')

    @staticmethod
    def dropin_path(unit):return '/etc/systemd/system/'+unit+'.d/'+OVERLAY

    def read_bus(self):
        if self.reader is not None:
            self.reader.deadline=min(self.reader.deadline,self.deadline)
            self.reader.check();return self.reader
        # Authenticate the SAME255 library already used by mandatory busctl and
        # its COMPLETE actual ELF closure BEFORE dlopen. No SONAME fallback,
        # new installation, inferred origin or extra administrative right.
        self.loader_config.check()
        reference=self.b['source_release']['operator_dependencies'];tool='/usr/bin/busctl'
        used=set()
        def bind(path):
            raw=self.bind_operator_dependency(path);used.add(path);return raw
        binary=bind(tool)
        loader,machine=elf_loader_profile(binary)
        io.require(elf_loader_profile(bind(loader),standalone=True)==machine,
                   'REPLACEMENT_CENSUS_LOADER_ARCHITECTURE')
        self.census_loader=loader
        self.verify_external_libraries()
        result=self.dependency_census(tool)
        io.require(result.returncode==0 and b'not found' not in result.stdout,'REPLACEMENT_READER_LIBRARY_CLOSURE')
        selected=[]
        for line in result.stdout.decode().splitlines():
            words=line.split();names=[w for w in words if w.startswith('/')]
            io.require(names or 'linux-vdso.so.' in line,'REPLACEMENT_READER_LIBRARY_CLOSURE')
            for path in names:bind(path)
            if words and words[0]==BUS_PROVIDER:selected.extend(names)
        io.require(len(selected)==1,'REPLACEMENT_READER_LIBRARY_CLOSURE')
        io.require(used==set(reference),'REPLACEMENT_READER_FOREIGN_OR_UNUSED_DEPENDENCY')
        self.verify_external_libraries();path=reference[selected[0]]['source']
        fd=os.open(path,READ)
        try:
            row=os.fstat(fd)
            io.require((row.st_dev,row.st_ino,row.st_mtime_ns,row.st_ctime_ns)==self.external_identities[selected[0]],
                       'REPLACEMENT_READER_LIBRARY_CHANGED')
            reader=ReadOnlyBus(fd,self.deadline)
            try:self.verify_external_libraries()
            except BaseException:reader.close();raise
            self.reader=reader;return reader
        finally:os.close(fd)

    def bind_operator_dependency(self,path):
        reference=self.b['source_release']['operator_dependencies']
        fields={'source','sha256','uid','gid','mode','attrs','flags','origin_sha256'}
        io.require(path in reference and type(reference[path]) is dict and set(reference[path])==fields and
            reference[path]['source'].startswith(('/usr/lib/','/usr/bin/')) and
            reference[path]['origin_sha256'] in self.b['source_origin_receipts'],
            'REPLACEMENT_READER_LIBRARY_ORIGIN_UNBOUND')
        io.require(self.bind_loader_path(path)==reference[path]['source'],'REPLACEMENT_READER_LIBRARY_ALIAS')
        raw,row=self.paths.read(reference[path]['source'])
        io.require(io.sha(raw)==reference[path]['sha256'] and all(row[k]==reference[path][k] for k in
                   ('uid','gid','mode','attrs','flags')),'REPLACEMENT_READER_LIBRARY_PROFILE')
        self.external_dependencies[path]={k:reference[path][k] for k in ('source','sha256')}
        return raw

    def dependency_census(self,target,*,prepared=None):
        # Execute ONLY the independently authenticated, self-contained loader
        # selected by bound busctl. No ldd/shell/helper or guessed SONAME, no
        # generic command-scope expansion. Both census sites use this path.
        loader=self.census_loader
        selected=self.runtime if prepared is None else prepared
        if prepared is not None:
            io.require(prepared is self.prepared_runtime and isinstance(prepared,ReplacementFence) and
                       not self.replacement_active and self.runtime is self.legacy_runtime,
                       'PREPARED_CENSUS_NOT_ACTIVATION')
            prepared.check()
        io.require(loader is not None and loader in self.external_identities and
            (target=='/usr/bin/busctl' or target.startswith(artifact.ROOT+'/') and
             target[len(artifact.ROOT)+1:] in selected.elf_files),
            'REPLACEMENT_CENSUS_SCOPE')
        self.loader_config.check();self.verify_external_libraries(prepared=prepared)
        remaining=min(20,self.deadline-time.monotonic())
        io.require(remaining>0,'REPLACEMENT_CENSUS_DEADLINE')
        result=subprocess.run([self.loader_bindings[loader],'--list',target],capture_output=True,
            timeout=remaining,env=dict(ENV),cwd='/')
        io.require(time.monotonic()<self.deadline and len(result.stdout)<=2*1024*1024 and
            len(result.stderr)<=2*1024*1024,'REPLACEMENT_CENSUS_TIME_OR_OUTPUT_BOUND')
        self.loader_config.check();self.verify_external_libraries(prepared=prepared)
        if prepared is not None:prepared.check()
        return result

    def interpreter_binding(self,row,*,old):
        if old:
            io.require(not self.replacement_active,'LEGACY_START_AFTER_REPLACEMENT_DENIED')
            return super().interpreter_binding(row,old=True)
        io.require(self.replacement_active and isinstance(self.runtime,ReplacementFence),
                   'UNTRUSTED_LEGACY_RUNTIME_NOT_START_AUTHORITY')
        binary=artifact.ROOT+'/python/bin/python3.12'
        expected=self.b['source_release']['runtime_reference']['artifact']['objects']['python/bin/python3.12']['sha256']
        io.require(row['exe']==binary and row['exe_sha256']==expected,'REPLACEMENT_INTERPRETER_BINDING')
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
        normal=io.sha(b''.join((k+'='+v).encode()+b'\0' for k,v in env.items()))
        env['PYTHONPATH']=artifact.VIEW+'/src'
        wms=io.sha(b''.join((k+'='+v).encode()+b'\0' for k,v in env.items()))
        io.require(row['initial_env_sha256'] in (normal,wms),'REPLACEMENT_ACTUAL_LOADER_ENVIRONMENT_CHANGED')
        current=Path('/proc')/str(row['pid'])/'root'/artifact.VIEW.lstrip('/')
        actual=os.stat(current);wanted=os.stat(artifact.ROOT+'/app',follow_symlinks=False)
        io.require((actual.st_dev,actual.st_ino)==(wanted.st_dev,wanted.st_ino) and
            os.statvfs(current).f_flag&os.ST_RDONLY, 'REPLACEMENT_SERVICE_VIEW_NOT_READ_ONLY_BOUND')

    def initial_application_ready(self,unit,row):
        expected=artifact.ROOT+'/python/bin/python3.12'
        if row['exe']!=expected:
            old=self.b['source_release']['python_binary']
            io.require(row['exe']==old and row['exe_sha256']==
                self.b['source_release']['probe_dependencies'][old]['sha256'],
                'REPLACEMENT_FIRST_EXECUTABLE_UNKNOWN')
            return False  # Bound helper AFTER drop, BEFORE its one exec.
        # exe may already name the new image while its exec is still filling
        # /proc/environ. This is ONLY a not-yet-admitted readiness observation.
        # Never defer a concrete, nonempty bad profile. The caller takes a
        # fresh full profile AFTER the PID-owned listener and applies the
        # unchanged strict interpreter_binding, including rejection of EMPTY.
        digest=self.b['source_release']['runtime_reference']['artifact']['objects']['python/bin/python3.12']['sha256']
        io.require(row['exe_sha256']==digest,'REPLACEMENT_INTERPRETER_BINDING')
        if row['initial_env_sha256']!=io.sha(b''):
            self.interpreter_binding(row,old=False)
        name=('adult-commercial-s7-public.json','adult-commercial-s8-landing.json',
              'adult-commercial-s10-wms.json')[UNITS.index(unit)]
        raw,_=self.paths.read('/etc/tu1nz/'+name)
        return self.listener_binding(row,io.parse(raw),allow_initial_unbound=True) is not None

    @staticmethod
    def loader_link_identity(row):
        return tuple(getattr(row,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode',
                                             'st_nlink','st_mtime_ns','st_ctime_ns'))

    def check_loader_paths(self):
        self.paths.check()
        for (parent,leaf),(identity,target) in self.loader_aliases.items():
            fd=self.paths.get(parent)
            row=os.stat(leaf,dir_fd=fd,follow_symlinks=False)
            io.require(self.loader_link_identity(row)==identity and
                os.readlink(leaf,dir_fd=fd)==target and
                not os.listxattr('/proc/self/fd/'+str(fd)+'/'+leaf,follow_symlinks=False),
                'REPLACEMENT_LOADER_ALIAS_CHANGED')
        # Exact prospective TCB metadata is NOT inferred from Publisher bytes.
        # Existing held parents/name watches remain active; regular flags also
        # need fresh inspection (not all ioctl changes have inotify semantics).
        for path,expected in getattr(self,'prospective_metadata',{}).items():
            fd=os.open(Path(path).name,READ,dir_fd=self.paths.get(str(Path(path).parent)))
            try:
                row=self.paths.d.metadata(fd)
                io.require(all(row[k]==expected[k] for k in ('uid','gid','mode','attrs','flags')),
                           'PROSPECTIVE_FILE_METADATA_DRIFT')
            finally:os.close(fd)
        self.paths.check()  # rename-and-return is latched, not just final identity

    def bind_loader_path(self,path):
        """Fence EVERY loader-visible component before following any symlink.

        Canonical-target hashes alone do not bind /lib -> /usr/lib, a leaf
        alias or a name restored after replacement. Existing no-follow secure
        directory bindings and their latched named inotify events are retained
        through final cleanup. This adds no Host write or broad root exception.
        """
        self.check_loader_paths()
        if path in self.loader_bindings:return self.loader_bindings[path]
        io.require(type(path) is str and path.startswith('/') and '\0' not in path and
                   len(path)<=4096 and len(self.loader_bindings)<512,'REPLACEMENT_LOADER_PATH_BOUND')
        pending=path.split('/')[1:];current=PurePosixPath('/');links=steps=0
        while pending:
            steps+=1
            io.require(steps<=512 and len(pending)<=256 and time.monotonic()<self.deadline,
                       'REPLACEMENT_LOADER_PATH_BOUND')
            leaf=pending.pop(0)
            if leaf in ('','.'):continue
            if leaf=='..':current=current.parent;continue
            parent=str(current);fd=self.paths.get(parent)
            # Install the exact name watch BEFORE the first lstat/readlink.
            wd=self.paths.libc.inotify_add_watch(self.paths.events,
                os.fsencode('/proc/self/fd/'+str(fd)),0x2ec4)
            io.require(wd>=0,'REPLACEMENT_LOADER_NAME_WATCH_UNAVAILABLE')
            self.paths.names.setdefault(wd,set()).add(leaf)
            self.paths.check()
            row=os.stat(leaf,dir_fd=fd,follow_symlinks=False)
            if stat.S_ISLNK(row.st_mode):
                links+=1;identity=self.loader_link_identity(row)
                target=os.readlink(leaf,dir_fd=fd)
                io.require(links<=40 and row.st_uid==0 and row.st_nlink==1 and target and
                    len(target)<=4096 and not os.listxattr('/proc/self/fd/'+str(fd)+'/'+leaf,
                    follow_symlinks=False),'REPLACEMENT_LOADER_ALIAS_PROFILE')
                io.require(self.loader_link_identity(os.stat(leaf,dir_fd=fd,follow_symlinks=False))==identity,
                           'REPLACEMENT_LOADER_ALIAS_CHANGED')
                key=(parent,leaf);before=self.loader_aliases.setdefault(key,(identity,target))
                io.require(before==(identity,target),'REPLACEMENT_LOADER_ALIAS_CHANGED')
                if target.startswith('/'):current=PurePosixPath('/')
                pending=target.split('/')+pending
            elif stat.S_ISDIR(row.st_mode):
                current=current/leaf;self.paths.get(str(current))
            else:
                io.require(stat.S_ISREG(row.st_mode) and not pending,'REPLACEMENT_LOADER_PATH_TYPE')
                resolved=str(current/leaf)
                self.loader_bindings[path]=resolved
                self.check_loader_paths()
                return resolved
        raise io.Hold('PUBLIC_OPERATOR_REPLACEMENT_LOADER_PATH_TYPE')

    def bind_external_libraries(self,*,prepared=None):
        self.check_loader_configuration()
        selected=self.runtime if prepared is None else prepared
        if prepared is None:
            io.require(self.replacement_active and isinstance(selected,ReplacementFence),
                       'REPLACEMENT_NOT_CURRENT')
        else:
            io.require(prepared is self.prepared_runtime and isinstance(prepared,ReplacementFence) and
                       not self.replacement_active and self.runtime is self.legacy_runtime,
                       'PREPARED_DEPENDENCIES_NOT_ACTIVATION')
            prepared.check()
        io.require(0<len(selected.elf_files)<=256,'REPLACEMENT_ELF_COUNT')
        reference=self.b['source_release']['probe_dependencies']
        roots=artifact.loader_context_roots(selected.elf_files)
        covered=set(roots)
        for name in roots:
            result=(self.dependency_census(artifact.ROOT+'/'+name) if prepared is None else
                    self.dependency_census(artifact.ROOT+'/'+name,prepared=prepared))
            io.require(result.returncode==0 and b'not found' not in result.stdout,'REPLACEMENT_LOADER_UNKNOWN')
            for line in result.stdout.decode().splitlines():
                words=line.split();paths=[w for w in words if w.startswith('/')]
                io.require(paths or 'linux-vdso.so.' in line or line.strip()=='statically linked',
                           'REPLACEMENT_LOADER_OUTPUT_UNKNOWN')
                for path in paths:
                    resolved=Path(self.bind_loader_path(path))
                    if resolved.is_relative_to(artifact.ROOT):
                        key=str(resolved.relative_to(artifact.ROOT))
                        io.require(selected.expected.get(key,{}).get('kind')=='file',
                                   'REPLACEMENT_LOADER_ESCAPED_ARTIFACT')
                        io.require(key in selected.elf_files,'REPLACEMENT_LOADER_NON_ELF_TARGET')
                        covered.add(key)
                    else:
                        io.require(path in reference and set(reference[path])=={'source','sha256'} and
                            reference[path]['source'].startswith(('/usr/lib/','/usr/bin/')),
                            'REPLACEMENT_EXTERNAL_LIBRARY_ORIGIN_UNBOUND')
                        self.external_dependencies[path]=reference[path]
        artifact.require_elf_coverage(selected.elf_files,covered)
        self.verify_external_libraries(prepared=prepared)

    def check_loader_configuration(self):
        self.loader_config.check()
        measured=manager_loader_environment(self.read_bus().environment())
        if self.manager_environment is None:self.manager_environment=measured
        else:io.require(measured==self.manager_environment,'REPLACEMENT_MANAGER_ENVIRONMENT_CHANGED')
        self.loader_config.check()

    def verify_external_libraries(self,*,prepared=None):
        selected=self.runtime if prepared is None else prepared
        if prepared is not None:
            io.require(prepared is self.prepared_runtime and isinstance(prepared,ReplacementFence) and
                       not self.replacement_active and self.runtime is self.legacy_runtime,
                       'PREPARED_EXTERNAL_FENCE_REQUIRED')
        self.check_loader_paths()
        samples={}  # ONE current batch only; discarded on every call.
        for path,expected in self.external_dependencies.items():
            io.require(self.loader_bindings[path]==expected['source'],'REPLACEMENT_LOADER_LIBRARY_REPLACED')
            source=expected['source']
            if source not in samples:
                p=PurePosixPath(source)
                # Same secure stable-file primitive and fresh bytes/metadata.
                # Retained parent/name fences are checked before AND after the
                # complete no-effect batch, not redundantly after each file.
                raw,row=self.paths.d.stable_file(self.paths.get(str(p.parent)),p.name)
                samples[source]=(io.sha(raw),row)
            digest,row=samples[source]
            io.require(digest==expected['sha256'],'REPLACEMENT_EXTERNAL_LIBRARY_DRIFT')
            identity=tuple(row[k] for k in ('device','inode','mtime_ns','ctime_ns'))
            if path in self.external_identities:
                io.require(self.external_identities[path]==identity,'REPLACEMENT_EXTERNAL_LIBRARY_REPLACED')
            if path not in self.external_identities or identity[:2] not in selected.files:
                fd=os.open(expected['source'],READ)
                try:
                    observed=os.fstat(fd)
                    io.require((observed.st_dev,observed.st_ino,observed.st_mtime_ns,observed.st_ctime_ns)==identity,
                               'REPLACEMENT_EXTERNAL_LIBRARY_CHANGED')
                    selected._watch(fd)
                    # Establish the initial byte binding AFTER installing the
                    # watch too; a write between the first sample and watch
                    # cannot be hidden by a later alias sharing that sample.
                    again,after=self.paths.d.stable_file(self.paths.get(str(PurePosixPath(source).parent)),
                                                        PurePosixPath(source).name)
                    io.require(io.sha(again)==digest and tuple(after[k] for k in
                        ('device','inode','mtime_ns','ctime_ns'))==identity,
                        'REPLACEMENT_EXTERNAL_LIBRARY_CHANGED')
                finally:os.close(fd)
                self.external_identities[path]=identity
                selected.files.add(identity[:2])
        if self.replacement_active or prepared is not None:selected.check()
        self.check_loader_paths()

    def check(self,*,stop_only=False):
        # No actions, records, starts, writes or authorization effects occur
        # here. Every process/manager/file/loader fact remains freshly read.
        # Keep every event check; bracket this complete read-only census with
        # full ancestor metadata instead of O(reads*parents) rescans.
        with self.paths.read_census():
            self.check_loader_configuration()
            super().check(stop_only=stop_only)
            if self.legacy_runtime is not self.runtime:self.legacy_runtime.check()
            self.verify_external_libraries()

    def close(self):
        errors=[]
        reader=getattr(self,'reader',None)
        if reader is not None:
            try:reader.close()
            except BaseException:errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_READER_CLOSE_UNKNOWN')
            self.reader=None
        loader=getattr(self,'loader_config',None)
        if loader is not None:
            try:errors.extend(loader.close())
            except BaseException:errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_LOADER_CONFIG_CLOSE_UNKNOWN')
        errors.extend(super().close())
        return errors


class CurrentReplacementAuthority(ReplacementAuthority, CurrentAuthority):
    """R4 replacement fences plus present-authority contract; no legacy bypass."""
    def platform_identity(self):
        """Only the platform inputs actually used by probes/rights/leases.

        Present fingerprint for possible reuse of completed probes, not a
        claim that the interrupted interval had continuous monitoring.
        """
        self.check_loader_configuration(); self.verify_external_libraries()
        kernel = os.uname(); values = {}
        for path in ('/proc/sys/kernel/yama/ptrace_scope',
                     '/proc/sys/kernel/unprivileged_userns_clone',
                     '/proc/sys/user/max_user_namespaces',
                     '/proc/sys/fs/leases-enable', '/proc/sys/fs/lease-break-time'):
            try:raw = context.read_proc(path, 4096, deadline=self.deadline)
            except FileNotFoundError:
                io.require(not os.path.lexists(path), 'PLATFORM_INPUT_VIEW_UNKNOWN')
                values[path] = {'state': 'ABSENT'}; continue
            io.require(re.fullmatch(rb'[0-9]+\n?', raw), 'PLATFORM_INPUT_VALUE_UNKNOWN')
            values[path] = {'state': 'PRESENT', 'sha256': io.sha(raw)}
        tick = context.read_proc('/proc/1/stat', 32768, deadline=self.deadline)
        fields = tick[tick.rfind(b')')+2:].split()
        io.require(len(fields) >= 20 and fields[19].isdigit(), 'PLATFORM_MANAGER_LIFETIME_UNKNOWN')
        fd = os.open('/proc/1/exe', os.O_RDONLY | os.O_CLOEXEC | os.O_NOATIME)
        try:
            before = os.fstat(fd)
            io.require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
                       0 < before.st_size <= 32*1024*1024, 'PLATFORM_MANAGER_EXECUTABLE_UNKNOWN')
            raw = os.pread(fd, before.st_size+1, 0)
            again = os.fstat(fd)
            keys = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
                    'st_size', 'st_mtime_ns', 'st_ctime_ns')
            identity = {k: getattr(before, k) for k in keys}
            io.require(identity == {k: getattr(again, k) for k in keys} and len(raw) == before.st_size,
                       'PLATFORM_MANAGER_EXECUTABLE_CHANGED')
        finally:os.close(fd)
        final_stat = context.read_proc('/proc/1/stat', 32768, deadline=self.deadline)
        final_fields = final_stat[final_stat.rfind(b')')+2:].split()
        io.require(len(final_fields) >= 20 and final_fields[19] == fields[19],
                   'PLATFORM_MANAGER_LIFETIME_CHANGED')
        self.check_loader_configuration(); self.verify_external_libraries()
        return {'schema': 'TU1NZ_REV4_USED_PLATFORM_IDENTITY_V1', 'boot_id': self.b['boot_id'],
                'kernel': {k: getattr(kernel, k) for k in ('sysname', 'release', 'version', 'machine')},
                'manager': {'starttime': fields[19].decode(), 'metadata': identity, 'sha256': io.sha(raw)},
                'inputs': values, 'probe_dependencies_sha256': io.sha(io.canonical(
                    self.b['source_release']['probe_dependencies'])),
                'operator_dependencies_sha256': io.sha(io.canonical(
                    self.b['source_release']['operator_dependencies']))}


def overlay():
    return artifact.overlay()


class ReplacementAdapter(Adapter):
    authority_type=ReplacementAuthority
    forbid_legacy_return=True

    def pre_stop(self):
        io.require(os.uname().sysname=='Linux' and os.uname().machine=='x86_64',
                   'REPLACEMENT_HOST_ARCHITECTURE_BEFORE_STOP')
        self.extra_runtime_fences=[]
        self.replacement_receipt=validate_receipt(self.a.b['source_release']['runtime_reference']['artifact'],
                                                 io.parse(self.source.bytes['runtime_inputs']))
        self.replacement_ready=False
        self.absent(str(Path(artifact.ROOT).parent));self.absent(artifact.ROOT)
        for unit in UNITS:self.absent(self.dropdir(unit)+'/'+OVERLAY)
        super().pre_stop()
        self.read_witness['legacy_runtime_origin']='UNKNOWN_STOP_WITNESS_ONLY_NO_OLD_RETURN'
        self.read_witness['replacement_artifact_sha256']=io.sha(io.canonical(self.replacement_receipt))

    def receive_artifact(self, *, preparing=False):
        if preparing:
            io.require(isinstance(self, MaintenanceAdapter) and self.prepared_ready is None and
                       not self.a.replacement_active, 'PREPARATION_RECEIVER_SCOPE')
            self.preparation_check()
        expected=self.replacement_receipt;parts=[]
        for index,offset in enumerate(range(0,expected['archive_bytes'],CHUNK)):
            # Transport changes no Host objects. Full fresh quiet admission is
            # repeated AFTER all bytes, immediately before construction.
            self.now();self.a.runtime.check();self.p.check()
            self.channel.wire.send({'type':'runtime_chunk_request','index':index,
                                    'archive_sha256':expected['archive_sha256']})
            row=self.channel.wire.receive()
            io.require(set(row)=={'type','index','data'} and row['type']=='runtime_chunk' and row['index']==index,
                       'REPLACEMENT_CHUNK_SEQUENCE_NO_RETRY')
            raw=base64.b64decode(row['data'],validate=True)
            io.require(len(raw)==min(CHUNK,expected['archive_bytes']-offset),'REPLACEMENT_CHUNK_SIZE')
            parts.append(raw)
        raw=b''.join(parts);inspect_archive(raw,expected)
        if preparing:self.preparation_check()
        else:self.quiet()
        return raw

    def construct_runtime(self, raw, *, deadline):
        # Root is private0700 during construction, not admitted by Paths until
        # fully populated/sealed. Only newly created own objects are chmodded.
        prefix=str(Path(artifact.ROOT).parent)
        self.parent(str(Path(prefix).parent))
        self.directory(prefix,0o555)
        parent=self.p.get(prefix);leaf=Path(artifact.ROOT).name
        self.p.d.new_directory(parent,leaf,0o700)
        root=os.open(leaf,READ|os.O_DIRECTORY,dir_fd=parent);fds={'.':root};before=os.fstat(root)
        try:
            with tarfile.open(fileobj=memory_io.BytesIO(raw),mode='r:gz') as archive:
                for count,member in enumerate(archive,1):
                    io.require(time.monotonic()<deadline,'REPLACEMENT_INSTALL_DEADLINE')
                    p=PurePosixPath(member.name);parent_fd=fds[str(p.parent)]
                    if member.isdir():
                        self.p.d.new_directory(parent_fd,p.name,0o700)
                        fds[member.name]=os.open(p.name,READ|os.O_DIRECTORY,dir_fd=parent_fd)
                    elif member.issym():os.symlink(member.linkname,p.name,dir_fd=parent_fd);os.fsync(parent_fd)
                    else:
                        data=archive.extractfile(member).read(artifact.MAX_MEMBER+1)
                        self.p.d.new_file(parent_fd,p.name,data,member.mode)
                    if count%512==0:
                        self.channel.record('replacement_install_progress',{
                            'objects_created':count,'archive_sha256':self.replacement_receipt['archive_sha256'],
                            'not_admitted_until_full_verification':True})
            for name,fd in reversed(list(fds.items())):
                os.fchmod(fd,0o555);os.fsync(fd)
            current=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            io.require((current.st_dev,current.st_ino)==(before.st_dev,before.st_ino),'REPLACEMENT_INSTALL_ROOT_CHANGED')
        finally:
            for fd in reversed(list(fds.values())):os.close(fd)
        self.p.check()
        # Own every handle BEFORE construction/transfer; interruption cannot
        # strand a newly acquired fence between return and Python assignment.
        next_fence=ReplacementFence.__new__(ReplacementFence)
        self.extra_runtime_fences.append(next_fence)
        next_fence.__init__(self.a.b['source_release']['runtime_reference'],self.p,
            self.a.b['source_origin_receipts'],python_binary=artifact.ROOT+'/python/bin/python3.12',
            deadline=min(deadline, self.deadline))
        # A successful bounded capture becomes a surviving transaction fence.
        # Never restore an expired/broken capture or extend the outer deadline.
        next_fence.check()
        next_fence.deadline=self.deadline
        return next_fence

    def materialize(self, raw, *, deadline):
        # Historical R5 order is unchanged. The new R4 maintenance adapter
        # separately calls construct_runtime before Stop without activating it.
        next_fence=self.construct_runtime(raw,deadline=deadline)
        previous=self.a.runtime
        self.extra_runtime_fences.append(previous)
        # Retain the old witness AND writer targets until final cleanup.
        # A successful new runtime cannot prove unchanged historical bytes.
        next_fence.files |= previous.files
        self.a.runtime=next_fence;self.a.replacement_active=True
        previous.check()
        self.a.bind_external_libraries()

    def _perform(self,action,unit=None,*,deadline):
        io.require(action not in ('start_old','return_stop','return_old_configuration',
            'establish_return_barriers','quarantine_own_return_barrier'), 'REPLACEMENT_OLD_RETURN_FORBIDDEN')
        if action=='start':io.require(self.replacement_ready,'REPLACEMENT_NOT_INSTALLED_NO_START')
        if action=='install_four_artifacts':
            self.quiet()
            io.require(self.backup_hash and self.restore_hash==self.backup_hash and self.probe_hash,
                       'REPLACEMENT_INSTALL_PREREQUISITES')
            self.channel.record('replacement_artifact_intent',{
                'receipt_sha256':io.sha(io.canonical(self.replacement_receipt)),
                'archive_sha256':self.replacement_receipt['archive_sha256'],'old_return':False})
            raw=self.receive_artifact();self.materialize(raw,deadline=deadline)
            for u in UNITS:
                path=self.dropdir(u)+'/'+OVERLAY
                self.artifacts[path]=('runtime_overlay',0o644)
            # Four unchanged approved artifacts plus three explicit R5 overlays.
            # Source bytes are immutable; this one generated member is fixed by
            # reviewed code, not a user-supplied destination or arbitrary unit.
            io.require(self.source.bytes['runtime_overlay']==overlay(),'REPLACEMENT_OVERLAY_SOURCE')
            self.replacement_ready=True
            result=super()._perform(action,unit,deadline=deadline)
            self.a.legacy_runtime.check()
            self.channel.record('replacement_artifact_verified',{
                'runtime_sha256':self.a.runtime.digest,'receipt_sha256':io.sha(io.canonical(self.replacement_receipt)),
                'legacy_root_unchanged':True,'old_return':False})
            return result
        return super()._perform(action,unit,deadline=deadline)

    def observe(self,phase,*,deadline):
        io.require(not phase.startswith('return_') and phase not in ('old_function',) and
                   not phase.startswith('old_started:'),'REPLACEMENT_OLD_RETURN_FORBIDDEN')
        if phase=='install' or phase.startswith(('release:','started:')) or phase in ('rights','owner_ready','owner_done'):
            io.require(self.replacement_ready and self.a.replacement_active and
                       isinstance(self.a.runtime,ReplacementFence),'REPLACEMENT_NOT_CURRENT')
        return super().observe(phase,deadline=deadline)

    def close(self):
        errors=[]
        current=getattr(getattr(self,'a',None),'runtime',None)
        for fence in getattr(self,'extra_runtime_fences',()):
            if fence is not current:
                try:errors.extend(fence.close())
                except BaseException:errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_REPLACEMENT_FENCE_CLOSE_UNKNOWN')
        try:errors.extend(super().close())
        except BaseException:
            errors.append('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_REPLACEMENT_ADAPTER_CLOSE_UNKNOWN')
        return errors


MAINTENANCE_CONTRACT = 'TU1NZ_MAIN_SERVER_REV4_20261104'


def prepared_asset_map(r3):
    """Compiled destinations only. Neither Scope nor READY supplies paths."""
    assets = r3.BOOT+'/prepared/assets/'
    mapping = {'helper': {'candidate': assets+'helper', 'target': HELPER,
                         'source': 'runtime', 'mode': 0o555, 'unit': None}}
    for index, unit in enumerate(UNITS):
        parent = Adapter.dropdir(unit)+'/'
        for kind, name, source in (('isolation', DROPIN, ASSET_NAMES[index]),
                                   ('overlay', OVERLAY, 'runtime_overlay'),
                                   ('barrier', r3.BARRIER, None)):
            key = str(index)+'-'+kind
            mapping[key] = {'candidate': assets+key, 'target': parent+name,
                            'source': source, 'mode': 0o644, 'unit': unit}
            if kind == 'barrier':
                mapping[key]['quarantine'] = r3.BOOT+'/quarantine/forward-'+unit
    return mapping


def recovery_asset_history(key, spec, expected, observed, records):
    """Constrain a FRESH pair read by original intents and actual observations.

    A surviving intent permits classification of either side of that one
    operation; it does not say the effect happened. A completed observation
    forbids rolling the inode/ctime backwards. No old ACK is synthesized.
    """
    places = ('candidate', 'target', 'quarantine') if 'quarantine' in spec else ('candidate', 'target')
    io.require(observed.get('place') in places and type(records) is list and len(records) <= 512,
               'RECOVERY_ASSET_HISTORY_INPUT')
    requested = confirmed = 0; prior = expected['metadata']; publication = release = False
    for row in records:
        kind, value = row['kind'], row['value']
        if kind == 'prepared_publication_intent' and value.get('key') == key:
            io.require(not publication and value.get('mapping') == spec,
                       'RECOVERY_PUBLICATION_INTENT_SCOPE_OR_REPEAT')
            publication = True; requested = 1
        elif kind == 'prepared_publication_observed' and value.get('key') == key:
            actual = value.get('actual', {})
            io.require(publication and confirmed == 0 and actual.get('place') == 'target' and
                       type(actual.get('metadata')) is dict and set(actual['metadata']) == OWNED_FILE_FIELDS,
                       'RECOVERY_PUBLICATION_OBSERVATION_ORDER')
            prior = actual['metadata']; confirmed = 1
        elif (kind == 'host_action_intent' and 'quarantine' in spec and
              value.get('action') == 'quarantine_own_barrier' and value.get('unit') == spec['unit']):
            io.require(confirmed == 1 and not release, 'RECOVERY_RELEASE_WITHOUT_PUBLISHED_BARRIER')
            requested = 2; release = True
        elif (kind == 'barrier_quarantined' and 'quarantine' in spec and value.get('unit') == spec['unit']):
            io.require(release and value.get('path') == spec['quarantine'] and
                       type(value.get('actual')) is dict and set(value['actual']) == OWNED_FILE_FIELDS,
                       'RECOVERY_QUARANTINE_OBSERVATION_ORDER')
            confirmed = 2; prior = value['actual']
        elif kind == 'prepared_barrier_release_observed' and value.get('key') == key:
            actual = value.get('actual', {})
            io.require(release and confirmed == 2 and actual.get('place') == 'quarantine' and
                       Adapter.same_file(actual.get('metadata', {}), prior) and
                       set(actual.get('metadata', {})) == OWNED_FILE_FIELDS,
                       'RECOVERY_BARRIER_RELEASE_OBSERVATION_ORDER')
    now = places.index(observed['place'])
    io.require(confirmed <= now <= requested, 'RECOVERY_ASSET_UNEXPLAINED_PLACEMENT')
    if now == confirmed:
        io.require(Adapter.same_file(observed['metadata'], prior), 'RECOVERY_CONFIRMED_ASSET_CHANGED')
    else:
        io.require(observed['metadata']['ctime_ns'] >= prior['ctime_ns'], 'RECOVERY_RENAME_CTIME_REVERSED')
    return {'place': observed['place'], 'metadata': observed['metadata'],
            'basis': 'CURRENT_OBJECT_OBSERVATION_NOT_ORIGINAL_ACK',
            'original_last_confirmed_place': places[confirmed], 'original_last_requested_place': places[requested]}


def recovery_failure_assessment(records, supplements):
    """Keep original failure/HOLD; never overrule a recorded adverse finding.

    No diagnostic is not a clean bill of health: it denotes an interrupted,
    unconfirmed outcome requiring ALL fresh R0/F1–F4 checks. Known negative or
    unclassified diagnostics are excluded. This finite allowlist covers only
    transport/interruption/deadline or explicitly unconfirmed operation
    outcomes; it does not turn them into success or absent effects.
    """
    mechanical = {'PUBLIC_BOOTSTRAP_INTERRUPTED', 'PUBLIC_BOOTSTRAP_IO_UNCONFIRMED',
        *('PUBLIC_BOOTSTRAP_'+v for v in ('OBSERVATION_DEADLINE_HOLD',
          'OBSERVATION_PERSISTENCE_DEADLINE_HOLD', 'TRANSACTION_DEADLINE',
          'INTENT_PERSISTENCE_DEADLINE_HOLD', 'ACTION_DEADLINE_HOLD', 'ACTION_UNKNOWN_HOLD')),
        *('PUBLIC_BOOTSTRAP_PUBLIC_OPERATOR_'+v for v in ('WIRE_DEADLINE', 'WIRE_LOST_NO_RETRY',
          'CLIENT_CUSTODY_ACK_LOST', 'LINKED_CUSTODY_DEADLINE', 'TRANSACTION_DEADLINE',
          'AUTHORITY_DEADLINE', 'MAINTENANCE_ACTION_LATE', 'RELOAD_OUTCOME_UNKNOWN_NO_RETRY',
          'STOP_OUTCOME_UNKNOWN', 'START_OUTCOME_UNKNOWN_NO_RETRY', 'FIRST_START_KERNEL_PROFILE_DEADLINE'))}
    cleanup_unknown = {'PUBLIC_BOOTSTRAP_CLEANUP_RECORD_UNCONFIRMED',
        'PUBLIC_BOOTSTRAP_HOLD_RECORD_PERSISTENCE_RED', 'PUBLIC_BOOTSTRAP_HOLD_RECORD_UNCONFIRMED',
        'PUBLIC_BOOTSTRAP_FOLLOWUP_UNCONFIRMED', 'PUBLIC_BOOTSTRAP_MIRROR_CLOSE_UNCONFIRMED',
        'PUBLIC_BOOTSTRAP_MAINTENANCE_HELPER_CLEANUP_UNKNOWN',
        'PUBLIC_BOOTSTRAP_MAINTENANCE_LOCK_CLEANUP_UNKNOWN'}
    diagnoses = [r['value'] for r in records if r['kind'] in
                 ('flow_hold', 'operator_pending_cleanup', 'operator_cleanup')]
    diagnoses += [p['record'] for p in supplements.values()]
    observed = []
    for value in diagnoses:
        io.require(type(value) is dict and value.get('status', 'HOLD') == 'HOLD',
                   'RECOVERY_ORIGINAL_NOT_FAILED_HOLD')
        primary = value.get('primary')
        io.require(primary is None or primary in mechanical, 'RECOVERY_RECORDED_NEGATIVE_OR_UNCLASSIFIED_FAILURE')
        for key in ('abort', 'cleanup'):
            codes = value.get(key, [])
            io.require(type(codes) is list and len(codes) <= 512 and
                       all(c in mechanical | cleanup_unknown for c in codes),
                       'RECOVERY_RECORDED_ABORT_OR_CLEANUP_NOT_CLASSIFIED')
        observed.append({'primary': primary, 'abort': value.get('abort', []),
                         'cleanup': value.get('cleanup', [])})
    return {'original_status': 'FAILED_HOLD', 'diagnostics': observed,
            'cause': 'RECORDED_MECHANICAL_OR_UNCONFIRMED_OUTCOME' if any(v['primary'] for v in observed)
                     else 'INCOMPLETE_ORIGINAL_NO_CAUSE_CLAIM',
            'original_effects': 'UNKNOWN_UNTIL_FRESH_CLASSIFICATION',
            'fresh_admission_still_required': True, 'original_records_changed': False}


class RecoveryOriginalEvidence:
    """Read only fixed original custody and hold its original lock.

    This object does not create a recovery claim, initialize Authority, change
    services, declare data/probes healthy, or admit recovery execution. The
    explicit recovery session must already have consumed its one entry. The
    caller retains this partially initialized object for cleanup on failure.
    """
    def __init__(self, paths, source, manifest, *, original_binding, maintenance_inputs,
                 boot_id, deadline):
        self.p, self.source, self.r = paths, source, source.load('r3')
        self.deadline = deadline; self.original_fd = None; self.lock_fd = None
        self.binding = original_binding; self.manifest = io.parse(io.canonical(manifest))
        self.original_fd = os.dup(paths.get(self.r.BOOT+'/intents'))
        self.snapshot = io.read_original_chain(self.original_fd, original_binding, owner=0, deadline=deadline)
        raw, ready_metadata = paths.read(self.r.BOOT+'/prepared/READY.json')
        io.require(len(raw) < 48*1024, 'RECOVERY_READY_BOUND')
        self.ready = io.parse(raw); self.ready_raw = raw
        io.require(type(self.ready) is dict and io.canonical(self.ready) == raw,
                   'RECOVERY_READY_CANONICAL')
        self.pair = io.original_manifest_pair(manifest, self.snapshot, binding=original_binding,
                                             ready_sha256=io.sha(raw))
        self.records = [v['record'] for v in self.snapshot['records']]
        if self.pair['unconfirmed_mac_record'] is not None:self.records.append(self.pair['unconfirmed_mac_record'])
        self.failure = recovery_failure_assessment(self.records, self.pair['mac_supplements'])
        entries = [r['value'] for r in self.records if r['kind'] == 'maintenance_ready']
        io.require(len(entries) == 1 and set(entries[0]) ==
                   {'ready', 'sha256', 'file_metadata', 'actual_prepared_directories'} and
                   Adapter.same_file(ready_metadata, entries[0]['file_metadata']), 'RECOVERY_READY_OBJECT_CHANGED')
        self.ready_metadata = ready_metadata; self.ready_record = entries[0]
        mapping = prepared_asset_map(self.r)
        ready = self.ready
        io.require(set(ready) == {'schema', 'transaction', 'machine', 'boot_id', 'inputs',
                   'owner_plan_sha256', 'artifact_sha256', 'archive_sha256', 'read_witness_sha256',
                   'legacy_runtime_identity', 'operator_session', 'runtime', 'mapping', 'assets',
                   'directories', 'checks', 'activation', 'old_return'} and
                   ready['schema'] == MAINTENANCE_CONTRACT and ready['transaction'] == self.r.TX and
                   ready['machine'] == self.r.MACHINE and ready['boot_id'] == boot_id and
                   ready['owner_plan_sha256'] == self.r.OWNER_PLAN and ready['mapping'] == mapping and
                   ready['inputs'] == maintenance_inputs and maintenance_inputs['scope_sha256'] == original_binding and
                   maintenance_inputs['source_sha256'] == io.sha(io.canonical(
                       {k: io.sha(v) for k, v in source.bytes.items()})) and
                   ready['activation'] == 'NOT_ACTIVATED' and ready['old_return'] is False,
                   'RECOVERY_ORIGINAL_INPUTS_CHANGED')
        # The check names describe original preparation only; present fences,
        # actual data and independent approval still have to be established.
        io.require(ready['checks'] == ['complete_runtime', 'prepared_dependencies', 'complete_candidates',
                   'current_old_stop_authority', 'current_writers', 'exclusive_lock'] and
                   type(ready['assets']) is dict and set(ready['assets']) == set(mapping),
                   'RECOVERY_ORIGINAL_PREPARATION_SCHEMA')
        witness_raw, self.witness_metadata = paths.read(self.r.BOOT+'/read-witness/witness.json')
        self.witness = io.parse(witness_raw); self.witness_raw = witness_raw
        witnesses = [r['value'] for r in self.records if r['kind'] == 'prestate_read_witness']
        io.require(len(witnesses) == 1 and io.canonical(self.witness) == witness_raw and
                   self.witness == witnesses[0] and io.sha(witness_raw) == ready['read_witness_sha256'] and
                   self.witness['boot'] == boot_id and self.witness['operator_session'] == ready['operator_session'],
                   'RECOVERY_READ_WITNESS_CHANGED')
        locks = [r['value'] for r in self.records if r['kind'] == 'maintenance_lock_held']
        io.require(len(locks) == 1 and locks[0]['path'] == self.r.BOOT+'/transaction.lock' and
                   locks[0]['operator_session'] == ready['operator_session'], 'RECOVERY_ORIGINAL_LOCK_BINDING')
        session = ready['operator_session']
        io.require(type(session) is dict and set(session) == {'pid', 'starttime', 'session', 'process_group'} and
                   type(session['pid']) is int and session['pid'] > 1 and
                   session['pid'] == session['session'] == session['process_group'] and
                   type(session['starttime']) is str and session['starttime'].isdecimal() and
                   locks[0]['operator']['pid'] == session['pid'] and
                   locks[0]['operator']['starttime'] == session['starttime'], 'RECOVERY_ORIGINAL_SESSION_BINDING')
        io.require(not operator_session_members(session['session'], deadline=deadline),
                   'RECOVERY_ORIGINAL_OPERATOR_OR_HELPER_STILL_PRESENT')
        self.lock_metadata = locks[0]['metadata']
        lock_raw, actual = paths.read(self.r.BOOT+'/transaction.lock')
        io.require(lock_raw == b'' and Adapter.same_file(actual, self.lock_metadata),
                   'RECOVERY_ORIGINAL_LOCK_CHANGED')
        self.lock_fd = os.open('transaction.lock', READ, dir_fd=paths.get(self.r.BOOT))
        held = os.fstat(self.lock_fd)
        io.require((held.st_dev, held.st_ino) == (actual['device'], actual['inode']),
                   'RECOVERY_LOCK_NAME_RACE')
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.check_original()

    def check_original(self):
        io.require(time.monotonic() < self.deadline and self.lock_fd is not None,
                   'RECOVERY_ORIGINAL_EVIDENCE_DEADLINE_OR_LOCK')
        self.p.check(full=True)
        current = io.read_original_chain(self.original_fd, self.binding, owner=0, deadline=self.deadline)
        io.require(current == self.snapshot, 'RECOVERY_ORIGINAL_CUSTODY_CHANGED')
        for path, expected, metadata in (
                (self.r.BOOT+'/prepared/READY.json', self.ready_raw, self.ready_metadata),
                (self.r.BOOT+'/read-witness/witness.json', self.witness_raw, self.witness_metadata),
                (self.r.BOOT+'/transaction.lock', b'', self.lock_metadata)):
            raw, actual = self.p.read(path)
            io.require(raw == expected and Adapter.same_file(actual, metadata), 'RECOVERY_ORIGINAL_OBJECT_CHANGED')
        held = os.fstat(self.lock_fd)
        io.require((held.st_dev, held.st_ino) == (self.lock_metadata['device'], self.lock_metadata['inode']) and
                   not operator_session_members(self.ready['operator_session']['session'], deadline=self.deadline),
                   'RECOVERY_EXCLUSIVITY_LOST')
        self.p.check(full=True)

    def assets_current(self):
        self.check_original(); out = {}
        for key, spec in prepared_asset_map(self.r).items():
            expected = self.ready['assets'][key]
            raw = self.r.BARRIER_BYTES if spec['source'] is None else self.source.bytes[spec['source']]
            io.require(expected['sha256'] == io.sha(raw) and expected['metadata']['mode'] == spec['mode'],
                       'RECOVERY_CANDIDATE_SOURCE_CHANGED')
            observed = self.p.classify_owned_pair(spec['candidate'], spec['target'], expected,
                                                 quarantine=spec.get('quarantine'))
            out[key] = recovery_asset_history(key, spec, expected, observed, self.records)
        self.check_original()
        return out

    def close(self):
        errors = []
        for name in ('original_fd', 'lock_fd'):
            fd = getattr(self, name, None)
            if fd is not None:
                try:os.close(fd)
                except OSError:errors.append('PUBLIC_BOOTSTRAP_RECOVERY_ORIGINAL_EVIDENCE_CLOSE_UNKNOWN')
                setattr(self, name, None)
        return errors


def recovery_phase(mapping, assets, units):
    """Finite classification of freshly checked objects and unit identities.

    Not a packet schema or permission by itself. Only RecoveryAuthority's
    in-process readers supply these classifications; all data/probe/backup
    prerequisites and source/clock/custody gates remain separate.
    """
    io.require(set(mapping) == set(assets) and set(units) == set(UNITS) and
               all(v in ('known_old_active', 'known_new_active', 'empty_inactive',
                         'empty_terminal_failed') for v in units.values()), 'RECOVERY_UNIT_CLASSIFICATION')
    barriers = {spec['unit']: assets[key]['place'] for key, spec in mapping.items() if spec['source'] is None}
    installed = [assets[key]['place'] for key, spec in mapping.items() if spec['source'] is not None]
    io.require(len(installed) == 7 and set(barriers) == set(UNITS) and
               all(v in ('candidate', 'target') for v in installed) and
               all(v in ('candidate', 'target', 'quarantine') for v in barriers.values()),
               'RECOVERY_ASSET_CLASSIFICATION')
    old = [u for u in UNITS if units[u] == 'known_old_active']
    new = [u for u in UNITS if units[u] == 'known_new_active']
    count = installed.count('target')
    if old or 'candidate' in barriers.values():
        io.require(not new and count == 0 and 'quarantine' not in barriers.values(),
                   'RECOVERY_OLD_ACTIVE_WITH_NEW_OR_RELEASED_ASSETS')
        return 'F1'
    if count < 7:
        io.require(not old and not new and set(barriers.values()) == {'target'},
                   'RECOVERY_PARTIAL_INSTALL_NOT_QUIET_AND_BARRIERED')
        return 'F2' if count == 0 else 'F3'
    io.require(not old and new == list(UNITS[:len(new)]), 'RECOVERY_NEW_ACTIVE_NOT_PREFIX')
    for index, unit in enumerate(UNITS):
        place = barriers[unit]
        if index < len(new):io.require(place == 'quarantine', 'RECOVERY_ACTIVE_BARRIER_UNEXPLAINED')
        elif index > len(new):io.require(place == 'target', 'RECOVERY_DOWNSTREAM_RELEASE_UNEXPLAINED')
        else:io.require(place in ('target', 'quarantine'), 'RECOVERY_NEXT_START_BARRIER_UNKNOWN')
    return 'F4'


class RecoveryProbeEvidence:
    """Reuse only fully completed original probes, or prove never entered.

    There is no start/stop/run method. Completed measurements remain historic
    measurements of those three owned probes, with fresh platform, fixed-name
    inactivity and retained-object validation. Failed/partial probes cannot be
    converted into an unused slot by finding their cgroups empty now.
    """
    def __init__(self, authority, evidence):
        self.a, self.e = authority, evidence
        self.module = evidence.source.load('probes'); self.reused = None; self.hash = None
        rows = [v['record'] for v in evidence.snapshot['records']]
        complete = [r['value'] for r in rows if r['kind'] == 'maintenance_probes_complete']
        attempted = any(r['kind'].startswith('probe_') or r['kind'].startswith('maintenance_probe') or
                        (r['kind'] in ('host_action_intent', 'flow_intent') and
                         r['value'].get('action') == 'bounded_synthetic_probes') for r in evidence.records)
        if not complete:
            io.require(not attempted, 'RECOVERY_PARTIAL_OR_UNKNOWN_PROBE_NOT_REPLAYABLE')
            self.unused_current()
            self.state = 'UNUSED'; return
        io.require(len(complete) == 1 and type(complete[0]) is dict and set(complete[0]) ==
                   {'platform', 'proof_sha256', 'reports', 'owned', 'retained', 'private_root',
                    'private_root_metadata', 'cleanup'}, 'RECOVERY_PROBE_COMPLETION_SCHEMA')
        receipt = complete[0]; reports = [r['value'] for r in rows if r['kind'] == 'probe_completed']
        io.require(len(reports) == 3 and [r['unit'] for r in reports] == list(self.module.NAMES) and
                   receipt['reports'] == [{'unit': r['unit'], 'sha256': io.sha(io.canonical(r))} for r in reports] and
                   receipt['proof_sha256'] == io.sha(io.canonical(reports)) and receipt['cleanup'] == [] and
                   receipt['private_root'] == self.module.ROOT+'/root' and
                   set(receipt['owned']) == set(self.module.NAMES) and
                   set(receipt['retained']) <= set(self.module.NAMES), 'RECOVERY_PROBE_COMPLETION_INCOMPLETE')
        cleanup = [r['value'] for r in rows if r['kind'] == 'probe_cleanup']
        io.require(len(cleanup) == 1 and cleanup[0]['cleanup'] == [] and
                   cleanup[0]['owned_units'] == list(self.module.NAMES) and
                   cleanup[0]['persistent_objects_retained'] == self.module.ROOT and
                   cleanup[0]['retained_transient_units'] == sorted(receipt['retained']),
                   'RECOVERY_PROBE_CLEANUP_NOT_CONFIRMED')
        starts = [r['value'] for r in rows if r['kind'] == 'probe_start_intent']
        results = [r['value'] for r in rows if r['kind'] == 'probe_start_result']
        io.require([r['unit'] for r in starts] == list(self.module.NAMES) and
                   [r['unit'] for r in results] == list(self.module.NAMES) and
                   all(r['exit'] == 0 for r in results), 'RECOVERY_PROBE_START_OR_RESULT_NOT_COMPLETE')
        for unit, profile, report in zip(self.module.NAMES, self.module.PROFILES, reports):
            owned = receipt['owned'][unit]; row = report['kernel_process']
            io.require(owned['requested'] == 1 and type(owned['pid']) is int and owned['pid'] > 1 and
                       (owned['pid'], owned['start']) == (row['pid'], row['starttime']) and
                       owned['cgroup'] == '/system.slice/'+unit and
                       re.fullmatch('[0-9a-f]{32}', owned['invocation']) and
                       report['measurements_sha256'] == io.sha(io.canonical(
                           {'profile': profile, 'peer': '1001:1001', 'admin': 'DENIED'})),
                       'RECOVERY_ORIGINAL_PROBE_IDENTITY_CHANGED')
        probe = self.module.Probes.__new__(self.module.Probes)
        probe.p, probe.a, probe.channel = authority.paths, authority, authority.channel
        probe.deadline = authority.deadline; probe.private = receipt['private_root']
        probe.owned = io.parse(io.canonical(receipt['owned']))
        probe.retained = io.parse(io.canonical(receipt['retained']))
        # Read methods only, no __init__/prepare/run/cleanup actions. All
        # retained paths are derived from fixed names before registration.
        for unit, retained in probe.retained.items():
            io.require(set(retained) == {'path', 'row', 'sha256', 'absent_after_gc'} and
                       retained['path'] == '/run/systemd/transient/'+unit and
                       type(retained['absent_after_gc']) is bool, 'RECOVERY_RETAINED_PROBE_PATH_SCOPE')
        self.reused = probe; self.receipt = receipt; self.hash = receipt['proof_sha256']
        self.state = 'COMPLETE_CURRENTLY_VERIFIED'
        self.check()
        io.require(authority.probe_check is None, 'RECOVERY_PROBE_CHECKER_OCCUPIED')
        authority.probe_check = self.check

    def unused_current(self):
        module = self.module; self.a.paths.absent(module.ROOT)
        probe = module.Probes.__new__(module.Probes)
        probe.deadline = self.a.deadline; probe.owned = {}
        for unit in module.NAMES:
            value = probe.show(unit)
            io.require(value.get('LoadState') == 'not-found' and probe.empty(unit, value),
                       'RECOVERY_UNUSED_PROBE_NAME_OR_CGROUP_OCCUPIED')
            self.a.paths.absent('/run/systemd/transient/'+unit)

    def check(self):
        if self.reused is None:
            self.unused_current(); return
        p = self.reused; p.deadline = min(self.a.deadline, self.a.channel.ceiling)
        io.require(self.a.platform_identity() == self.receipt['platform'], 'RECOVERY_USED_PLATFORM_CHANGED')
        actual = self.a.paths.d.metadata(self.a.paths.get(p.private))
        io.require(Adapter.same_file(actual, self.receipt['private_root_metadata']),
                   'RECOVERY_PROBE_ROOT_CHANGED')
        for unit in self.module.NAMES:
            path = p.inactive_profile(unit, p.deadline)
            if path is None:
                self.a.paths.absent('/run/systemd/transient/'+unit)
                if unit in p.retained:p.retained[unit]['absent_after_gc'] = True
                self.a.own_config_paths.discard('/run/systemd/transient/'+unit)
            else:
                io.require(unit in p.retained and not p.retained[unit]['absent_after_gc'],
                           'RECOVERY_UNBOUND_OR_REUSED_PROBE_UNIT')
                raw, row = self.a.paths.read(path); retained = p.retained[unit]
                io.require(io.sha(raw) == retained['sha256'] and Adapter.same_file(row, retained['row']),
                           'RECOVERY_RETAINED_PROBE_BYTES_CHANGED')
                self.a.own_config_paths.add(path)
        self.e.check_original()


class RecoveryAuthority(CurrentReplacementAuthority):
    """Fresh F1–F4 authority, never the original absence constructor.

    Expected old identities are evidence constraints only. stopped/rights and
    current runtime selection below are populated AFTER actual kernel/file
    reads, not copied from the interrupted adapter or its success records.
    No service effects, claim reset, or runtime construction occurs here.
    """
    def __init__(self, baseline, paths, channel, *, machine, deadline, evidence):
        io.require(isinstance(evidence, RecoveryOriginalEvidence), 'RECOVERY_FIXED_ORIGINAL_EVIDENCE_REQUIRED')
        self.evidence = evidence; self.recovery_assets = {}; self.recovery_units = {}
        self.recovery_prepared = None; self.recovery_allow_load_delta = True
        self.recovery_probes = None
        self.terminal_profiles = None
        self.recovery_reload_units = set()
        super().__init__(baseline, paths, channel, machine=machine, deadline=deadline)

    @contextmanager
    def limit(self, deadline):
        prior = self.evidence.deadline
        self.evidence.deadline = min(prior, deadline)
        try:
            with super().limit(deadline):yield
        finally:
            # Only the surrounding unchanged transaction ceiling survives;
            # no failed action is retried or granted a new action window.
            self.evidence.deadline = prior

    def initial_current_admission(self):
        e = self.evidence; e.check_original()
        io.require(io.sha(io.canonical(self.b)) == e.ready['inputs']['baseline_sha256'] and
                   self.initial == {p: tuple(v) for p, v in e.witness['files'].items()},
                   'RECOVERY_PROTECTED_ORIGINAL_SOURCE_CHANGED')
        self.recovery_assets = e.assets_current()
        self.admit_prepared_directories()
        mapping = prepared_asset_map(e.r)
        for key, spec in mapping.items():
            if spec['unit'] is not None and self.recovery_assets[key]['place'] == 'target':
                self.own_config_paths.add(spec['target']); self.own_dropins[spec['unit']].add(spec['target'])
        self.new_parent_paths = set(e.ready['directories']) & {Adapter.dropdir(u) for u in UNITS}
        io.require(self.legacy_runtime.identity_digest() == e.ready['legacy_runtime_identity'],
                   'RECOVERY_LEGACY_SNAPSHOT_CHANGED_NO_HISTORICAL_ATTESTATION')
        receipt = validate_receipt(self.b['source_release']['runtime_reference']['artifact'],
                                   io.parse(e.source.bytes['runtime_inputs']))
        io.require(io.sha(io.canonical(receipt)) == e.ready['artifact_sha256'] and
                   receipt['archive_sha256'] == e.ready['archive_sha256'], 'RECOVERY_AUTHENTIC_ARTIFACT_CHANGED')
        fence = ReplacementFence.__new__(ReplacementFence); self.recovery_prepared = fence
        fence.__init__(self.b['source_release']['runtime_reference'], self.paths,
            self.b['source_origin_receipts'], python_binary=artifact.ROOT+'/python/bin/python3.12',
            deadline=self.deadline)
        io.require(fence.identity_digest() == e.ready['runtime'], 'RECOVERY_RUNTIME_INCOMPLETE_OR_CHANGED_NO_REPAIR')
        self.prepared_runtime = fence
        self.bind_external_libraries(prepared=fence)
        self.check_writers(fence.files | self.legacy_runtime.files)
        all_installed = all(self.recovery_assets[k]['place'] == 'target' for k,s in mapping.items()
                            if s['source'] is not None)
        if all_installed:
            # This changes only this fresh authority's selected read fence;
            # no activation or service start is performed. All actual active
            # processes must still prove this new identity below.
            self.runtime = fence; self.replacement_active = True
            fence.files |= self.legacy_runtime.files
            self.bind_external_libraries()
        self.initial_units = unit_rows(UNITS, self.deadline)
        self.original_profiles = io.parse(io.canonical(e.witness['stop_profiles']))
        self.legacy_contexts = io.parse(io.canonical(e.witness['legacy_contexts']))
        io.require(set(self.original_profiles) == set(UNITS) and set(self.legacy_contexts) == set(UNITS) and
                   io.sha(io.canonical(self.legacy_contexts)) == LEGACY_CONTEXTS_SHA,
                   'RECOVERY_ORIGINAL_STOP_CONTRACT_CHANGED')
        self.policies_check(); self.manager_jobs_clear()
        for unit in UNITS:
            value = self.initial_units[unit]
            current = process(int(value['MainPID'])) if int(value['MainPID']) else None
            kind = self.classify_current_unit(unit, value, current)
            self.recovery_units[unit] = kind
            if kind.startswith('empty_'):self.stopped.add(unit)
            elif kind == 'known_old_active':self.targets[unit] = (current['pid'], current['starttime'])
            else:
                self.runtime_invocations[unit] = (value['InvocationID'], current['pid'], current['starttime'])
                self.rights.add(unit)
        self.recovery_phase = recovery_phase(mapping, self.recovery_assets, self.recovery_units)
        self.recovery_probes = RecoveryProbeEvidence(self, e)
        io.require(self.recovery_phase not in ('F3', 'F4') or self.recovery_probes.hash is not None,
                   'RECOVERY_INSTALLED_ASSETS_WITHOUT_COMPLETE_PROBES')
        io.require(self.unit_search() == self.b['unit_search_sha256'], 'RECOVERY_FOREIGN_MANAGER_DELTA')
        self.check()

    def admit_prepared_directories(self):
        e = self.evidence; boot = e.r.BOOT
        required = {boot, STAGING, LIGHTING, boot+'/prepared', boot+'/prepared/assets',
                    *(boot+'/'+n for n in ('read-witness', 'intents', 'acknowledgments', 'quarantine', 'reports')),
                    *(STAGING+'/'+n for n in ('quarantine', 'reports', 'result')), str(Path(artifact.ROOT).parent)}
        allowed = required | {str(PurePosixPath(p).parent) for p in (boot, STAGING, LIGHTING)} | {
                    Adapter.dropdir(u) for u in UNITS}
        directories = e.ready['directories']
        io.require(type(directories) is dict and required <= set(directories) <= allowed,
                   'RECOVERY_PREPARED_DIRECTORY_SCOPE')
        for path, expected in directories.items():
            actual = self.paths.d.metadata(self.paths.get(path))
            io.require(security(actual) == security(expected), 'RECOVERY_PREPARED_DIRECTORY_REPLACED')
        io.require(set(os.listdir(self.paths.get(boot+'/prepared'))) == {'assets', 'READY.json'} and
                   set(os.listdir(self.paths.get(boot+'/prepared/assets'))) == {
                       PurePosixPath(spec['candidate']).name for k, spec in prepared_asset_map(e.r).items()
                       if self.recovery_assets[k]['place'] == 'candidate'}, 'RECOVERY_PREPARED_NAMES_CHANGED')

    def classify_current_unit(self, unit, value, current):
        io.require(unit in UNITS and not value['Job'] and value['ControlPID'] == '0' and
                   value['SubState'] not in ('auto-restart', 'auto-restart-queued'),
                   'RECOVERY_UNIT_JOB_OR_AUTOMATIC_TRANSITION')
        if current is None:
            io.require(value['MainPID'] == '0' and value['NRestarts'] == '0' and self.empty(unit) and
                       value['Result'] != 'start-limit-hit', 'RECOVERY_EMPTY_COUNTER_OR_CGROUP_UNKNOWN')
            if value['ActiveState'] == 'inactive' and value['SubState'] == 'dead':return 'empty_inactive'
            io.require(value['ActiveState'] == 'failed' and value['SubState'] == 'failed',
                       'RECOVERY_EMPTY_NOT_TERMINAL')
            return 'empty_terminal_failed'
        io.require(value['ActiveState'] == 'active' and value['SubState'] == 'running' and
                   value['ControlGroup'] == '/system.slice/'+unit and
                   current['cgroup'] == '0::'+value['ControlGroup'] and
                   re.fullmatch('[0-9a-f]{32}', value['InvocationID']), 'RECOVERY_ACTIVE_IDENTITY_UNKNOWN')
        if self.replacement_active:
            io.require(value['NRestarts'] == '0', 'RECOVERY_NEW_RESTART_COUNTER')
            self.interpreter_binding(current, old=False)
            self.rights_check(unit, current)
            io.require(self.initial_application_ready(unit, current), 'RECOVERY_NEW_LISTENER_NOT_READY')
            return 'known_new_active'
        old = self.evidence.witness['units'][unit]
        io.require((current['pid'], current['starttime']) == tuple(self.evidence.witness['targets'][unit]) and
                   value['InvocationID'] == old['InvocationID'] and value['NRestarts'] == old['NRestarts'] and
                   all(current[k] == v for k,v in self.original_profiles[unit].items()),
                   'RECOVERY_OLD_STOP_IDENTITY_CHANGED')
        self.interpreter_binding(current, old=True)
        self.delegation_check(current, known_stop=True)
        return 'known_old_active'

    def unit_configuration_check(self, unit, value, expected):
        if not self.recovery_allow_load_delta:return super().unit_configuration_check(unit, value, expected)
        base = set(expected['dropins']); loaded = set(value['DropInPaths'].split())
        disk = self.own_dropins[unit]
        historical = {spec['target'] for key,spec in prepared_asset_map(self.evidence.r).items()
                      if spec['unit'] == unit and self.recovery_assets[key]['place'] in ('target', 'quarantine')}
        io.require(value['FragmentPath'] == expected['fragment'] and not value['Job'] and
                   value['KillMode'] == 'control-group' and value['NeedDaemonReload'] in ('yes', 'no') and
                   base <= loaded <= base | historical, 'RECOVERY_UNEXPLAINED_EFFECTIVE_CONFIG')
        delta = loaded != base | disk or value['NeedDaemonReload'] == 'yes'
        io.require(not delta or historical, 'RECOVERY_RELOAD_WITHOUT_OWN_CONFIG_DELTA')
        if delta:self.recovery_reload_units.add(unit)

    def unit_process_check(self, unit, value, current, *, stop_only):
        if self.terminal_profiles is not None:
            expected = self.terminal_profiles[unit]
            io.require(not value['Job'] and value['ControlPID'] == '0', 'RECOVERY_TERMINAL_JOB_OR_CONTROL_PROCESS')
            if expected['kind'] == 'empty':
                io.require(current is None and value['MainPID'] == '0' and self.empty(unit) and
                           value['ActiveState'] in ('inactive', 'failed'), 'RECOVERY_TERMINAL_EMPTY_CHANGED')
            else:
                io.require(current is not None and value['ActiveState'] == 'active' and value['NRestarts'] == '0' and
                           (value['InvocationID'], current['pid'], current['starttime']) == expected['identity'],
                           'RECOVERY_TERMINAL_BOUND_INVOCATION_CHANGED')
                self.accepted_runtime_actor(unit, current)
            return
        if unit in self.stopped:
            kind = self.classify_current_unit(unit, value, current)
            io.require(kind in ('empty_inactive', 'empty_terminal_failed'), 'RECOVERY_UNIT_NO_LONGER_QUIET')
            return
        if unit in self.rights:
            super().unit_process_check(unit, value, current, stop_only=False)
            self.interpreter_binding(current, old=False)
        else:
            io.require(self.classify_current_unit(unit, value, current) == 'known_old_active' and
                       (current['pid'], current['starttime']) == self.targets.get(unit),
                   'RECOVERY_OLD_CURRENT_IDENTITY_LOST')

    def accepted_runtime_actor(self, unit, row):
        if self.terminal_profiles is None:return super().accepted_runtime_actor(unit, row)
        expected = self.terminal_profiles[unit]
        fields = (*context.CURRENT_SECURITY, 'uid_map', 'gid_map', 'setgroups', 'exe_sha256',
                  'initial_env_sha256', 'lsm_sha256')
        io.require(expected['kind'] == 'known_new_stop_only' and
                   (row['pid'], row['starttime']) == expected['identity'][1:] and
                   {k:row[k] for k in fields} == expected['kernel'], 'RECOVERY_TERMINAL_PROCESS_PROFILE_CHANGED')
        self.interpreter_binding(row, old=False)
        # This exact new invocation can be stopped despite its measured bad
        # runtime rights. It gets no operation/owner trust. Actual source
        # writers, foreign actors, namespaces, dependencies and jobs are still
        # checked by the enclosing current authority before every stop.

    def stop_contexts_check(self, *, stop_only):
        # Only the retained expected original contexts; every still-live old
        # target was freshly compared above. Empty units gain no exemption.
        io.require(io.sha(io.canonical(self.legacy_contexts)) == LEGACY_CONTEXTS_SHA,
                   'RECOVERY_STOP_CONTEXT_CONSTRAINT_CHANGED')

    def check(self, *, stop_only=False):
        self.evidence.check_original()
        if self.recovery_assets:
            for key,spec in prepared_asset_map(self.evidence.r).items():
                actual = self.paths.classify_owned_pair(spec['candidate'], spec['target'],
                    self.evidence.ready['assets'][key], quarantine=spec.get('quarantine'))
                expected = self.recovery_assets[key]
                io.require(actual['place'] == expected['place'] and
                           Adapter.same_file(actual['metadata'], expected['metadata']),
                           'RECOVERY_OWNED_ASSET_CHANGED_AFTER_ADMISSION')
        old_live = bool(set(self.targets)-self.stopped-self.rights)
        super().check(stop_only=old_live)
        self.evidence.check_original()

    def close(self):
        errors = []; current = getattr(self, 'runtime', None)
        for fence in (getattr(self, 'legacy_runtime', None), getattr(self, 'recovery_prepared', None)):
            if fence is not None and fence is not current:
                try:errors.extend(fence.close())
                except BaseException:errors.append('PUBLIC_BOOTSTRAP_RECOVERY_RUNTIME_FENCE_CLOSE_UNKNOWN')
        errors.extend(super().close())
        return errors


class MaintenanceAdapter(ReplacementAdapter):
    """R4 original-run preparation; no recovery admission through __init__.

    This adapter is not selected by the legacy dispatcher. The reviewed R4
    session must bind its inputs, protection/restore and native timing proof
    before constructing it. Recovery needs its own fresh admission instead of
    this absence-based constructor. No method here resets a consumed claim.
    """
    authority_type = CurrentReplacementAuthority

    def __init__(self, source, baseline, plan_raw, channel, binding, *, deadline,
                 maintenance_inputs, after_ready_seconds):
        io.require(type(maintenance_inputs) is dict and set(maintenance_inputs) ==
                   {'scope_sha256', 'baseline_sha256', 'source_sha256',
                    'pre_stop_protection_sha256', 'native_timing_sha256'} and
                   all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v)
                       for v in maintenance_inputs.values()), 'MAINTENANCE_INPUT_BINDING')
        io.require(maintenance_inputs['scope_sha256'] == binding and
                   maintenance_inputs['baseline_sha256'] == io.sha(io.canonical(baseline)) and
                   maintenance_inputs['source_sha256'] == io.sha(io.canonical(
                       {k: io.sha(v) for k, v in source.bytes.items()})), 'MAINTENANCE_INPUT_DRIFT')
        # This is a checked value from the bound native timing result, not an
        # operator guess. 180s is only the irreducible 3*20 + 120 floor; the
        # caller must also include backup/probes/admission/cleanup/reserve.
        io.require(type(after_ready_seconds) is int and 180 < after_ready_seconds < 600,
                   'MAINTENANCE_TIMING_INPUT')
        self.maintenance_inputs = dict(maintenance_inputs)
        self.after_ready_seconds = after_ready_seconds
        self.transaction_lock = None
        self.prepared_ready = None; self.ready_raw = None; self.ready_metadata = None
        self.prepared_assets = {}; self.asset_states = {}; self.prepared_directories = {}
        self.prepared_directory_states = {}
        self.start_limit_observation = None; self.start_limit_proofs = {}
        self.operator_session = operator_session_start(deadline=deadline)
        super().__init__(source, baseline, plan_raw, channel, binding, deadline=deadline)
        self.asset_map = prepared_asset_map(self.r)
        self.artifacts.update({self.dropdir(u)+'/'+OVERLAY: ('runtime_overlay', 0o644) for u in UNITS})

    def pre_stop(self):
        super().pre_stop()
        self.read_witness['stop_profiles'] = self.a.original_profiles
        self.read_witness['legacy_contexts'] = self.a.legacy_contexts
        self.read_witness['operator_session'] = dict(self.operator_session)
        anchors={}
        for unit in UNITS:
            current=start_limit_state_read(self.a.read_bus(),self.a.unit,unit)
            start_limit_permission(current,require_active=True)
            anchors[unit]=current
        self.read_witness['start_limit_anchors']=anchors

    def service_action(self, action, unit, *, deadline):
        io.require(action in ('start', 'stop') and unit in UNITS, 'MAINTENANCE_SERVICE_ACTION_SCOPE')
        # A new conflicting job must fail rather than be silently replaced.
        return command(['/usr/bin/systemctl', '--job-mode=fail', action, unit], deadline)

    def arm_start_limit_observation(self):
        io.require(self.start_limit_observation is None, 'START_LIMIT_OBSERVATION_NO_REPLAY')
        self.a.check();self.a.manager_jobs_clear()
        watch=StartLimitObservation(self.a.read_bus())
        self.start_limit_observation=watch
        permissions={}
        for unit in UNITS:
            if self.a.unit(unit)['ActiveState']=='active':continue  # observe only, never a new start grant
            permissions[unit]=watch.bind_current_permission(unit,self.a.unit,
                anchor=self.read_witness['start_limit_anchors'][unit])
        self.channel.record('maintenance_start_limit_observation', {'manager_owner': watch.owner,
            'started_monotonic': watch.started, 'limits': watch.limits,
            'permissions':permissions,'kind': 'FRESH_TIMESTAMP_PROOF_AND_PASSIVE_JOB_GUARD_NO_COUNTER_RESET'})

    def before_start_request(self, unit, before, *, old, deadline):
        watch=self.start_limit_observation
        io.require(not old and unit in UNITS and watch is not None and unit not in self.start_limit_proofs,
                   'MAINTENANCE_START_OBSERVATION_REQUIRED')
        io.require(before['NRestarts']=='0' and before['Result']!='start-limit-hit' and
                   not before['Job'] and before['MainPID']==before['ControlPID']=='0',
                   'MAINTENANCE_PRESTART_COUNTER_OR_JOB_UNKNOWN')
        while True:
            remaining=watch.remaining(unit)
            io.require(time.monotonic()+remaining < min(deadline,self.deadline,self.channel.ceiling),
                       'START_LIMIT_WINDOW_EXCEEDS_EXISTING_ACTION_BUDGET')
            self.a.check();self.channel.check()
            if remaining==0:break
            time.sleep(min(.05,remaining))  # within the SAME20s, never a new timer
        current=self.a.unit(unit)
        fields=('InvocationID','NRestarts','ActiveState','SubState','Result','MainPID','ControlPID','Job')
        io.require(all(current[k]==before[k] for k in fields) and self.a.empty(unit),
                   'MAINTENANCE_PRESTART_STATE_CHANGED')
        self.condition(unit,present=False)
        proof={'unit':unit, 'prior':{k:current[k] for k in fields}, 'manager_owner':watch.owner,
               'limits':watch.limits[unit], 'observation_started_monotonic':watch.started,
               'observed_monotonic':time.monotonic(), 'counter_reset':False}
        self.channel.record('maintenance_start_permission',proof)
        # Final fresh signal drain after custody ACK; then disarm ONLY this
        # unit so its one requested job is not confused with foreign activity.
        watch.retire_for_start(unit)
        self.start_limit_proofs[unit]=proof

    def preparation_check(self):
        """Old units remain old; no quiet(), new-runtime or rights assertion."""
        self.now(); self.p.check(full=True); self.a.check(stop_only=True)
        io.require(not self.a.stopped and not self.a.rights and not self.a.replacement_active and
                   self.a.runtime is self.a.legacy_runtime, 'PREPARATION_NOT_OLD_RUNNING_STATE')
        targets = set(self.a.runtime.files)
        targets.update((row['device'], row['inode']) for _, row, *_ in self.p.rows.values())
        targets.update((v['metadata']['device'], v['metadata']['inode']) for v in self.prepared_assets.values())
        if self.a.prepared_runtime is not None:
            self.a.prepared_runtime.check(); targets.update(self.a.prepared_runtime.files)
        self.a.check_writers(targets)
        self.channel.check(); self.p.check(full=True)

    def check_transaction_lock(self):
        io.require(self.transaction_lock is not None, 'MAINTENANCE_LOCK_MISSING')
        path = self.r.BOOT+'/transaction.lock'
        raw, actual = self.p.read(path)
        held = os.fstat(self.transaction_lock)
        io.require(raw == b'' and self.same_file(actual, self.lock_metadata) and
                   (held.st_dev, held.st_ino) == (actual['device'], actual['inode']),
                   'MAINTENANCE_LOCK_IDENTITY_CHANGED')
        # No LOCK_UN/LOCK_EX gap. A lock retained on this same open description
        # remains exclusive until close, including on an interrupted action.

    def prepare_private_roots(self):
        self.preparation_check(); self.space()
        self.parent(str(PurePosixPath(self.r.BOOT).parent)); self.directory(self.r.BOOT)
        path = self.r.BOOT+'/transaction.lock'
        self.lock_metadata = self.p.create_file(path, b'')
        self.transaction_lock = os.open(PurePosixPath(path).name, READ,
                                        dir_fd=self.p.get(self.r.BOOT))
        fcntl.flock(self.transaction_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.check_transaction_lock()
        for name in ('read-witness', 'intents', 'acknowledgments', 'quarantine', 'reports', 'prepared'):
            self.directory(self.r.BOOT+'/'+name)
        self.directory(self.r.BOOT+'/prepared/assets')
        self.channel.attach(self.p.get(self.r.BOOT+'/intents'))
        self.p.create_file(self.r.BOOT+'/read-witness/witness.json', io.canonical(self.read_witness))
        row = process(os.getpid())
        self.channel.record('maintenance_lock_held', {'path': path, 'metadata': self.lock_metadata,
            'operator': {k: row[k] for k in ('pid', 'starttime', 'cgroup')},
            'operator_session': self.operator_session,
            'not_a_recovery_claim': True})
        for path in (STAGING, LIGHTING):
            self.parent(str(PurePosixPath(path).parent)); self.directory(path)
        for name in ('quarantine', 'reports', 'result'):
            self.directory(STAGING+'/'+name)
        for unit in UNITS:
            self.parent(self.dropdir(unit), 0o755)
        self.a.new_parent_paths |= self.created & {self.dropdir(u) for u in UNITS}
        self.preparation_check()

    def prepare_asset_candidates(self):
        io.require(not self.prepared_assets and self.prepared_ready is None,
                   'NO_PREPARATION_REPLAY')
        io.require(self.source.bytes['runtime_overlay'] == overlay(), 'REPLACEMENT_OVERLAY_SOURCE')
        for key, spec in self.asset_map.items():
            self.preparation_check(); self.p.absent(spec['target'])
            if 'quarantine' in spec:self.p.absent(spec['quarantine'])
            raw = self.r.BARRIER_BYTES if spec['source'] is None else self.source.bytes[spec['source']]
            row = self.p.create_file(spec['candidate'], raw, spec['mode'])
            expected = {'sha256': io.sha(raw), 'metadata': row}
            actual = self.p.classify_owned_pair(spec['candidate'], spec['target'], expected,
                                                quarantine=spec.get('quarantine'))
            io.require(actual['place'] == 'candidate', 'PREPARED_ASSET_NOT_PRIVATE')
            self.prepared_assets[key] = expected; self.asset_states[key] = actual
        self.preparation_check()

    def check_prepared_dependencies(self):
        selected = self.a.prepared_runtime
        io.require(isinstance(selected, ReplacementFence) and not self.a.replacement_active,
                   'PREPARED_RUNTIME_REQUIRED')
        selected.check()
        self.a.bind_external_libraries(prepared=selected)
        self.a.check_writers(selected.files)
        selected.check()

    def prepare_runtime_bundle(self, *, deadline):
        io.require(self.prepared_ready is None and self.a.prepared_runtime is None and
                   self.transaction_lock is None, 'NO_PREPARATION_REPLAY')
        self.prepare_private_roots()
        raw = self.receive_artifact(preparing=True)
        self.a.prepared_runtime = self.construct_runtime(raw, deadline=deadline)
        self.check_prepared_dependencies(); self.prepare_asset_candidates()
        self.preparation_check(); self.check_transaction_lock()
        runtime = self.a.prepared_runtime.identity_digest()
        # Exact created directory identities, including private roots. Their
        # real timestamps are retained; later intentional child changes have
        # separate receipts. Security and inode bindings never become mutable.
        self.prepared_directories = {p: self.p.d.metadata(self.p.get(p)) for p in sorted(self.created)}
        ready = {'schema': MAINTENANCE_CONTRACT, 'transaction': self.r.TX,
                 'machine': self.r.MACHINE, 'boot_id': self.a.b['boot_id'],
                 'inputs': self.maintenance_inputs, 'owner_plan_sha256': self.r.OWNER_PLAN,
                 'artifact_sha256': io.sha(io.canonical(self.replacement_receipt)),
                 'archive_sha256': self.replacement_receipt['archive_sha256'],
                 'read_witness_sha256': io.sha(io.canonical(self.read_witness)),
                 'legacy_runtime_identity': self.a.legacy_runtime.identity_digest(),
                 'operator_session': self.operator_session,
                 'runtime': runtime, 'mapping': self.asset_map, 'assets': self.prepared_assets,
                 'directories': self.prepared_directories,
                 'checks': ['complete_runtime', 'prepared_dependencies', 'complete_candidates',
                            'current_old_stop_authority', 'current_writers', 'exclusive_lock'],
                 'activation': 'NOT_ACTIVATED', 'old_return': False}
        raw = io.canonical(ready)
        io.require(len(raw) < 48*1024, 'PREPARED_READY_RECORD_BOUND')
        self.ready_metadata = self.p.create_file(self.r.BOOT+'/prepared/READY.json', raw)
        self.prepared_directory_states = {p: self.p.d.metadata(self.p.get(p)) for p in
            (self.r.BOOT+'/prepared', self.r.BOOT+'/prepared/assets')}
        # Setting ready only AFTER the linked record completes prevents Stop
        # if either custody or its ACK is missing. No later state read invents
        # that missing original ACK.
        self.channel.record('maintenance_ready', {'ready': ready, 'sha256': io.sha(raw),
            'file_metadata': self.ready_metadata,
            'actual_prepared_directories': self.prepared_directory_states})
        self.ready_raw = raw; self.prepared_ready = ready
        self.check_prepared_state(before_stop=True)
        return io.sha(raw)

    def check_prepared_state(self, *, before_stop=False):
        io.require(self.prepared_ready is not None, 'PREPARED_READY_MISSING')
        self.check_transaction_lock(); self.p.check(full=True)
        raw, row = self.p.read(self.r.BOOT+'/prepared/READY.json')
        io.require(raw == self.ready_raw and self.same_file(row, self.ready_metadata), 'PREPARED_READY_CHANGED')
        for path, expected in self.prepared_directories.items():
            actual = self.p.d.metadata(self.p.get(path))
            io.require(security(actual) == security(expected), 'PREPARED_DIRECTORY_IDENTITY_CHANGED')
        for path, expected in self.prepared_directory_states.items():
            io.require(self.same_file(self.p.d.metadata(self.p.get(path)), expected),
                       'PREPARED_DIRECTORY_UNEXPLAINED_CHANGE')
        io.require(set(os.listdir(self.p.get(self.r.BOOT+'/prepared'))) == {'assets', 'READY.json'} and
                   set(os.listdir(self.p.get(self.r.BOOT+'/prepared/assets'))) ==
                   {PurePosixPath(self.asset_map[k]['candidate']).name for k, v in self.asset_states.items()
                    if v['place'] == 'candidate'}, 'PREPARED_PRIVATE_SUBSTRUCTURE_CHANGED')
        for key, spec in self.asset_map.items():
            observed = self.p.classify_owned_pair(spec['candidate'], spec['target'], self.prepared_assets[key],
                                                  quarantine=spec.get('quarantine'))
            prior = self.asset_states[key]
            io.require(observed['place'] == prior['place'] and
                       self.same_file(observed['metadata'], prior['metadata']), 'PREPARED_ASSET_UNEXPLAINED_CHANGE')
        selected = self.a.prepared_runtime
        io.require(selected is not None and selected.identity_digest() == self.prepared_ready['runtime'],
                   'PREPARED_RUNTIME_CHANGED')
        if not self.a.replacement_active:self.check_prepared_dependencies()
        else:self.a.verify_external_libraries()
        self.a.check_writers(selected.files | {(v['metadata']['device'], v['metadata']['inode'])
                             for v in self.prepared_assets.values()})
        if before_stop:
            self.preparation_check()
            for unit in UNITS:
                current=start_limit_state_read(self.a.read_bus(),self.a.unit,unit)
                start_limit_permission(current,require_active=True)
                anchor=self.read_witness['start_limit_anchors'][unit]
                io.require(all(current[k]==anchor[k] for k in ('unit','manager_owner','properties','unit_state')),
                           'START_LIMIT_ORIGINAL_ANCHOR_CHANGED_BEFORE_STOP')
            io.require(time.monotonic()+self.after_ready_seconds < min(self.deadline, self.channel.ceiling),
                       'INSUFFICIENT_AFTER_READY_BUDGET_NO_STOP')
        self.channel.check(); self.p.check(full=True)

    def publish_prepared_asset(self, key):
        self.check_transaction_lock()
        io.require(key in self.asset_map and self.asset_states[key]['place'] == 'candidate',
                   'NO_ASSET_PUBLICATION_REPLAY')
        spec = self.asset_map[key]
        assets = self.r.BOOT+'/prepared/assets'
        io.require(self.same_file(self.p.d.metadata(self.p.get(assets)), self.prepared_directory_states[assets]),
                   'PREPARED_PUBLICATION_PARENT_DRIFT')
        self.channel.record('prepared_publication_intent', {'key': key,
            'ready_sha256': io.sha(self.ready_raw), 'mapping': spec})
        proof = self.p.publish_owned_candidate(spec['candidate'], spec['target'], self.prepared_assets[key])
        # Bind real post-rename ctime before any later operation. If record
        # persistence fails, this action remains failed; no in-process retry.
        self.asset_states[key] = proof
        self.prepared_directory_states[assets] = proof['parents'][assets]
        if spec['source'] is None:
            self.barriers[spec['unit']] = proof['metadata']
            self.barrier_places[spec['unit']] = (spec['target'], proof['metadata'])
        else:self.installed[spec['target']] = proof['metadata']
        if spec['unit'] is not None:
            self.a.own_config_paths.add(spec['target'])
            self.a.own_dropins[spec['unit']].add(spec['target'])
        self.channel.record('prepared_publication_observed', {'key': key, 'actual': proof})

    def activate_prepared_runtime(self):
        self.quiet(); self.check_prepared_state()
        io.require(not self.a.replacement_active and not self.replacement_ready and
                   set(self.installed) == set(self.artifacts), 'PREPARED_ACTIVATION_INCOMPLETE')
        previous = self.a.runtime; selected = self.a.prepared_runtime
        io.require(previous is self.a.legacy_runtime, 'PREPARED_ACTIVATION_OLD_STATE')
        self.check_prepared_dependencies()
        selected.files |= previous.files
        self.retain_old_fence(previous)
        self.a.runtime = selected; self.a.replacement_active = True
        previous.check(); selected.check(); self.a.bind_external_libraries()
        self.replacement_ready = True
        self.channel.record('prepared_runtime_activated', {'ready_sha256': io.sha(self.ready_raw),
            'runtime_sha256': selected.digest, 'old_return': False})

    def retain_old_fence(self, fence):
        self.extra_runtime_fences.append(fence)

    def _perform(self, action, unit=None, *, deadline):
        watch=getattr(self,'start_limit_observation',None)
        if watch is not None:watch.drain()
        if action == 'bounded_synthetic_probes':
            self.quiet(); platform = self.a.platform_identity()
            self.arm_start_limit_observation()
            self.channel.record('maintenance_probe_platform', platform)
            result = super()._perform(action, unit, deadline=deadline)
            io.require(self.probes.cleanup_complete and not self.probes.unconfirmed and
                       self.a.platform_identity() == platform, 'MAINTENANCE_PROBE_PLATFORM_OR_CLEANUP_CHANGED')
            self.channel.record('maintenance_probes_complete', {'platform': platform,
                'proof_sha256': self.probe_hash,
                'reports': [{'unit': r['unit'], 'sha256': io.sha(io.canonical(r))} for r in self.probes.reports],
                'owned': self.probes.owned, 'retained': self.probes.retained,
                'private_root': self.probes.private,
                'private_root_metadata': self.p.d.metadata(self.p.get(self.probes.private)), 'cleanup': []})
            return result
        if action in ('prepare_runtime_bundle', 'create_persistent_barriers', 'install_four_artifacts'):
            io.require(unit is None and self.pending is None and
                       time.monotonic() < deadline <= self.deadline, 'MAINTENANCE_ACTION_SCOPE')
            self.pending = (action, unit)
            self.channel.record('host_action_intent', {'action': action, 'unit': unit})
            result = {'action': action, 'unit': unit, 'outcome': 'CONFIRMED'}
            if action == 'prepare_runtime_bundle':
                result['proof_sha256'] = self.prepare_runtime_bundle(deadline=deadline)
            elif action == 'create_persistent_barriers':
                self.check_prepared_state(before_stop=True)
                io.require(not self.barriers, 'NO_BARRIER_REPLAY')
                # No check against effective DropInPaths between publishing
                # this fixed set and the one bound reload: the manager still
                # has its old loaded view until that reload completes.
                for key, spec in self.asset_map.items():
                    if spec['source'] is None:self.publish_prepared_asset(key)
                self.reload()
                for u in UNITS:self.condition(u, present=True)
            else:
                self.quiet(); self.check_prepared_state()
                io.require(self.backup_hash and self.restore_hash == self.backup_hash and self.probe_hash,
                           'PREPARED_INSTALL_PREREQUISITES')
                io.require(not self.installed and not self.replacement_ready, 'NO_INSTALL_REPLAY')
                for key, spec in self.asset_map.items():
                    if spec['source'] is not None:self.publish_prepared_asset(key)
                self.reload(); self.activate_prepared_runtime()
                for u in UNITS:self.isolation(u)
                result['proof_sha256'] = io.sha(self.ready_raw)
            io.require(time.monotonic() < deadline, 'MAINTENANCE_ACTION_LATE')
            self.channel.record('host_action_ack', result)
            self.pending = None
            return result
        io.require(action != 'create_sealed_staging', 'MAINTENANCE_ROOTS_ALREADY_PREPARED')
        if action == 'stop':
            self.check_prepared_state(before_stop=not self.a.stopped)
        if action == 'quarantine_own_barrier':
            key = next(k for k, s in self.asset_map.items() if s['source'] is None and s['unit'] == unit)
            io.require(self.asset_states[key]['place'] == 'target', 'NO_BARRIER_RELEASE_REPLAY')
            result = super()._perform(action, unit, deadline=deadline)
            spec = self.asset_map[key]
            actual = self.p.classify_owned_pair(spec['candidate'], spec['target'], self.prepared_assets[key],
                                                quarantine=spec['quarantine'])
            io.require(actual['place'] == 'quarantine' and
                       self.same_file(actual['metadata'], self.barrier_places[unit][1]),
                       'PREPARED_BARRIER_QUARANTINE_CHANGED')
            actual['parents'] = {str(PurePosixPath(p).parent):
                                self.p.d.metadata(self.p.get(str(PurePosixPath(p).parent)))
                                for p in (spec['target'], spec['quarantine'])}
            self.asset_states[key] = actual
            self.channel.record('prepared_barrier_release_observed', {'key': key, 'actual': actual})
            return result
        return super()._perform(action, unit, deadline=deadline)

    def _observe(self, phase, *, deadline):
        watch=getattr(self,'start_limit_observation',None)
        if watch is not None:watch.drain()
        if phase.startswith('started:'):
            unit=phase.split(':',1)[1]
            io.require(unit in self.start_limit_proofs, 'MAINTENANCE_START_PERMISSION_NOT_RECORDED')
            observed=super()._observe(phase,deadline=deadline)
            return self.r.Observation(self.r.TX,self.binding,phase,
                observed.facts | {'current_no_start_limit_before_request'},time.monotonic())
        if phase == 'prepared':
            self.check_prepared_state(before_stop=True)
            return self.r.Observation(self.r.TX, self.binding, phase, frozenset((
                'ready_two_custodies', 'full_runtime_identity_digest', 'ten_complete_candidates',
                'prepared_external_dependencies', 'old_runtime_not_activated',
                'private_roots_and_exclusive_lock', 'native_after_ready_budget_remaining')),
                time.monotonic())
        if phase == 'owner_ready':
            io.require(not self.owner_admission_started and isinstance(self.channel, io.MaintenanceLinkedRecords),
                       'OWNER_ENTRY_REQUIRES_REV4_CHANNEL')
            self.now()
            started = time.monotonic()
            io.require(started+120 < min(deadline, self.deadline, self.channel.ceiling),
                       'OWNER_FULL_WINDOW_NOT_AVAILABLE_NO_ENTRY')
            self.owner_admission_started = True
            owner_deadline = started+120
            self.channel.cap(owner_deadline)
            with self.a.limit(owner_deadline):
                # No Supervisor, leases or writer-preparation exists before
                # the two fixed entry markers. Every step shares THIS120s.
                self.channel.begin_owner_admission(self.p, ready_sha256=io.sha(self.ready_raw))
                self.a.check(); self.function_all(old=False)
                self.owner = self.source.load('owner').Supervisor(self.source.load('guard'), self.plan_raw,
                    self.r.OWNER_PLAN, self.a.bounded(owner_deadline), self.channel.bounded(owner_deadline),
                    deadline=owner_deadline)
                self.owner.check_all()
                self.now()
            return self.r.Observation(self.r.TX, self.binding, phase, frozenset((
                'original_exact_owner_plan_matches', 'rights_acceptance_current',
                'all82_file_leases_namespace_FD_mapping_fences', 'owner120s512FD_bound',
                'actual_owner_backup_independent_read_restore', 'separate_owner_journal_and_intent_unspent',
                'first_owner_marker_two_custodies_same_window')), time.monotonic())
        io.require(phase != 'staging_ready', 'MAINTENANCE_ROOTS_ALREADY_PREPARED')
        return super()._observe(phase, deadline=deadline)

    def close(self):
        errors = []
        if getattr(self, 'operator_session', None) is not None:
            try:
                members = operator_session_members(self.operator_session['session'], deadline=self.deadline)
                io.require(members == [{k: self.operator_session[k] for k in ('pid', 'starttime')}],
                           'MAINTENANCE_HELPER_SESSION_NOT_EMPTY')
            except BaseException:errors.append('PUBLIC_BOOTSTRAP_MAINTENANCE_HELPER_CLEANUP_UNKNOWN')
        if getattr(self, 'transaction_lock', None) is not None:
            try:self.check_transaction_lock()
            except BaseException:errors.append('PUBLIC_BOOTSTRAP_MAINTENANCE_LOCK_CLEANUP_UNKNOWN')
        errors.extend(super().close())
        if getattr(self, 'transaction_lock', None) is not None:
            try:os.close(self.transaction_lock)
            except OSError:errors.append('PUBLIC_BOOTSTRAP_MAINTENANCE_LOCK_CLOSE_UNKNOWN')
            self.transaction_lock = None
        return errors


class RecoveryAdapter(MaintenanceAdapter):
    """One separately entered recovery; original __init__/pre_stop are unused.

    The session consumes its fixed entry before construction, checks the bound
    pre-stop protection/native proof, and supplies RecoveryAdmissionChannel.
    Fresh admission forms the binding; no effect is allowed before the
    independent input checks and dual-custody binding are complete.
    """
    authority_type = RecoveryAuthority

    def __init__(self, source, baseline, plan_raw, channel, *, evidence, deadline,
                 terminal_prepare_seconds, terminal_cleanup_seconds):
        io.require(isinstance(channel, io.RecoveryAdmissionChannel) and
                   isinstance(evidence, RecoveryOriginalEvidence) and channel.binding == evidence.binding and
                   deadline == channel.ceiling == channel.wire.deadline and
                   channel.context['mac_snapshot_sha256'] == evidence.pair['mac_snapshot_sha256'],
                   'RECOVERY_ADMISSION_CHANNEL_OR_EVIDENCE_MISMATCH')
        # Values from the session's actually validated native timing proof,
        # whose digest is part of READY. Never guessed from a JSON GREEN bit.
        io.require(type(terminal_prepare_seconds) is int and 0 < terminal_prepare_seconds <= 120 and
                   type(terminal_cleanup_seconds) is int and 0 < terminal_cleanup_seconds <= 120 and
                   terminal_prepare_seconds+60+terminal_cleanup_seconds < 600,
                   'RECOVERY_TERMINAL_TIMING_INPUT')
        self.terminal_prepare_seconds = terminal_prepare_seconds
        self.terminal_cleanup_seconds = terminal_cleanup_seconds
        self.terminal_reserve_seconds = terminal_prepare_seconds+60+terminal_cleanup_seconds
        self.source, self.r = source, source.load('r3')
        self.channel, self.binding, self.deadline = channel, None, deadline
        io.require(io.sha(plan_raw) == self.r.OWNER_PLAN, 'ORIGINAL_OWNER_PLAN_REQUIRED')
        self.plan_raw = plan_raw; self.evidence = evidence; self.p = evidence.p; self.a = None
        self.transaction_lock = None; self.extra_runtime_fences = []
        self.initialize_operation_state()
        self.operator_session = operator_session_start(deadline=deadline)
        self.preparing = False; self.read_witness = evidence.witness
        self.maintenance_inputs = evidence.ready['inputs']
        self.ready_raw, self.ready_metadata = evidence.ready_raw, evidence.ready_metadata
        self.prepared_ready = evidence.ready; self.prepared_assets = evidence.ready['assets']
        self.prepared_directories = evidence.ready['directories']; self.prepared_directory_states = {}
        self.asset_map = prepared_asset_map(self.r); self.asset_states = {}
        self.start_limit_observation = None; self.start_limit_proofs = {}
        self.recovery_bound = False; self.recovery_terminal = False; self.recovery_state_proof = None
        self.recovery_once_actions = set(); self.terminal_stop_invocations = set()
        self.recovery_new_seen = {}
        self.backup_mode = None; self.recovery_backup_used = False
        self.artifacts.update({self.dropdir(u)+'/'+OVERLAY: ('runtime_overlay', 0o644) for u in UNITS})
        self.check_unspent_owner()
        channel.check()
        self.lock_metadata = evidence.lock_metadata; self.transaction_lock = os.dup(evidence.lock_fd)
        self.a = RecoveryAuthority.__new__(RecoveryAuthority)
        self.a.__init__(baseline, self.p, channel, machine=self.r.MACHINE, deadline=deadline, evidence=evidence)
        self.asset_states = self.a.recovery_assets  # this fresh in-process state only
        self.prepared_directory_states = {p: self.p.d.metadata(self.p.get(p)) for p in
            (self.r.BOOT+'/prepared', self.r.BOOT+'/prepared/assets')}
        self.replacement_receipt = baseline['source_release']['runtime_reference']['artifact']
        self.replacement_ready = self.a.replacement_active
        self.synchronize_current_assets()
        self.probe_hash = self.a.recovery_probes.hash
        self.original_backup_proof = self.inspect_original_backup()
        io.require(self.a.recovery_phase not in ('F3', 'F4') or self.backup_mode == 'ORIGINAL_CURRENT',
                   'RECOVERY_INSTALL_WITHOUT_COMPLETE_BACKUP_AND_RESTORE')
        self.recover_state()

    def pre_stop(self):
        raise io.Hold('PUBLIC_OPERATOR_RECOVERY_CANNOT_ENTER_ORIGINAL_PRE_STOP')

    def preparation_check(self):
        raise io.Hold('PUBLIC_OPERATOR_RECOVERY_CANNOT_PREPARE_OR_REBUILD_RUNTIME')

    def receive_artifact(self, **kwargs):
        raise io.Hold('PUBLIC_OPERATOR_RECOVERY_RUNTIME_TRANSFER_FORBIDDEN')

    def check_unspent_owner(self):
        io.require(not self.owner_admission_started, 'RECOVERY_OWNER_ALREADY_ENTERED')
        self.p.absent(self.r.BOOT+'/owner-admission-intent')
        self.p.absent(LIGHTING+'/writer-preparation-r2')
        io.require(not os.listdir(self.p.get(LIGHTING)), 'RECOVERY_LIGHTING_ROOT_NOT_UNUSED')

    def synchronize_current_assets(self):
        self.installed.clear(); self.barriers.clear(); self.barrier_places.clear()
        for key, spec in self.asset_map.items():
            value = self.asset_states[key]
            if spec['source'] is None:
                if value['place'] == 'target':self.barriers[spec['unit']] = value['metadata']
                if value['place'] != 'candidate':
                    self.barrier_places[spec['unit']] = (spec[value['place']], value['metadata'])
            elif value['place'] == 'target':self.installed[spec['target']] = value['metadata']

    def protected_state(self):
        self.now(); self.evidence.check_original(); self.a.check(); self.channel.check()

    def inspect_original_backup(self):
        requested = [r for r in self.evidence.records if r['kind'] == 'host_action_intent' and
                     r['value'].get('action') == 'protected_rights_backup']
        io.require(len(requested) <= 1, 'RECOVERY_ORIGINAL_BACKUP_REPLAY')
        present = any(os.path.lexists(STAGING+'/'+name) for name in ('before', 'restore-test'))
        io.require(not present or requested, 'RECOVERY_BACKUP_OBJECTS_WITHOUT_ORIGINAL_INTENT')
        backup = Backup(self.p, {p:v['sha256'] for p,v in self.a.b['files'].items()}, STAGING, self.protected_state)
        proof = backup.classify_original_for_recovery()
        acks = {name: [r['value'] for r in self.evidence.records if r['kind'] == 'host_action_ack' and
                      r['value'].get('action') == name] for name in
                ('protected_rights_backup', 'isolated_restore_rehearsal')}
        io.require(all(len(v) <= 1 for v in acks.values()), 'RECOVERY_ORIGINAL_BACKUP_ACK_REPEAT')
        if proof['state'] == 'COMPLETE_CURRENT_COPY_AND_RESTORE':
            io.require(requested and all(not v or v[0]['proof_sha256'] == proof['manifest_sha256']
                                        for v in acks.values()), 'RECOVERY_BACKUP_RECEIPT_MISMATCH')
            self.backup = backup; self.backup_hash = self.restore_hash = proof['manifest_sha256']
            self.backup_mode = 'ORIGINAL_CURRENT'
        else:
            io.require(not acks['isolated_restore_rehearsal'], 'RECOVERY_COMPLETED_RESTORE_NOW_INCOMPLETE')
            if acks['protected_rights_backup']:
                raw, _ = self.p.read(STAGING+'/before/manifest.json')
                io.require(io.sha(raw) == acks['protected_rights_backup'][0]['proof_sha256'],
                           'RECOVERY_COMPLETED_BACKUP_NOW_INCOMPLETE')
            self.backup_mode = 'NEW_RECOVERY_REQUIRED'
        return proof

    def current_backup_verified(self):
        io.require(self.backup is not None and self.backup_hash is not None and
                   self.restore_hash == self.backup_hash, 'RECOVERY_BACKUP_RESTORE_NOT_COMPLETE')
        fresh = Backup(self.p, self.backup.files, self.backup.root, self.protected_state)
        return fresh.load_verified_existing(expected_sha256=self.backup_hash)

    def check_probe_current(self):
        io.require(self.probe_hash is not None, 'RECOVERY_PROBES_NOT_COMPLETE')
        if self.probes is None:
            self.a.recovery_probes.check()
            io.require(self.a.recovery_probes.hash == self.probe_hash, 'RECOVERY_REUSED_PROBE_HASH_CHANGED')
        else:
            io.require(self.probes.cleanup_complete and not self.probes.unconfirmed and
                       io.sha(io.canonical(self.probes.reports)) == self.probe_hash and
                       self.a.platform_identity() == self.recovery_new_probe_platform,
                       'RECOVERY_NEW_PROBE_CLEANUP_OR_PLATFORM_CHANGED')
            self.probes.check_retained()

    def publish_prepared_asset(self, key):
        # Enable only the independently bound own load delta while publishing;
        # a complete reload must restore strict effective-config comparison.
        self.a.recovery_allow_load_delta = True
        return super().publish_prepared_asset(key)

    def retain_old_fence(self, fence):
        io.require(fence is self.a.legacy_runtime, 'RECOVERY_LEGACY_FENCE_OWNERSHIP')
        # RecoveryAuthority already owns both original and prepared fences.

    def recover_state(self):
        self.now(); self.evidence.check_original(); self.check_unspent_owner()
        self.a.check(); self.check_prepared_state()
        rows = unit_rows(UNITS, self.a.deadline); kinds = {}; identities = {}; start_permissions={}
        for unit, value in rows.items():
            current = process(int(value['MainPID'])) if int(value['MainPID']) else None
            kinds[unit] = self.a.classify_current_unit(unit, value, current)
            identities[unit] = {k:value[k] for k in ('ActiveState', 'SubState', 'InvocationID', 'NRestarts',
                'Result', 'MainPID', 'ControlPID', 'ControlGroup', 'Job', 'NeedDaemonReload', 'DropInPaths')}
            if current is not None:identities[unit]['actual_starttime'] = current['starttime']
            if kinds[unit]!='known_new_active':
                snapshot=start_limit_state_read(self.a.read_bus(),self.a.unit,unit)
                basis=start_limit_permission(snapshot,anchor=self.read_witness['start_limit_anchors'][unit])
                start_permissions[unit]={'snapshot':snapshot,'basis':basis,'live_counter_read':False}
        phase = recovery_phase(self.asset_map, self.asset_states, kinds)
        io.require(phase == self.a.recovery_phase, 'RECOVERY_STATE_CHANGED_DURING_ADMISSION')
        data = self.a.current_data_readonly()
        io.require(self.site_read_witness() == self.evidence.witness['site_read_witness_sha256'],
                   'RECOVERY_OWNER_PLAN_CURRENT_OBJECTS_CHANGED')
        self.check_unspent_owner(); self.evidence.check_original(); self.channel.check()
        self.recovery_state_proof = {'schema': 'TU1NZ_REV4_FRESH_RECOVERY_STATE', 'phase': phase,
            'units': identities, 'classes': kinds, 'assets': self.asset_states, 'start_permissions':start_permissions,
            'runtime': self.prepared_ready['runtime'], 'current_data': data,
            'probe_state': self.a.recovery_probes.state, 'probe_hash': self.probe_hash,
            'backup': self.original_backup_proof,
            'original_failure': self.evidence.failure, 'operator_session': self.operator_session,
            'original_ack_reconstructed': False, 'gap_monitoring_claimed': False}
        io.require(len(io.canonical(self.recovery_state_proof)) < 48*1024, 'RECOVERY_STATE_RECORD_BOUND')
        return self.recovery_state_proof

    def bind_execution(self, channel):
        """Session-owned transition after all actual admission inputs pass."""
        io.require(not self.recovery_bound and self.binding is None and
                   isinstance(self.channel, io.RecoveryAdmissionChannel) and
                   isinstance(channel, io.RecoveryLinkedRecords) and channel.approval_bound and
                   channel.host_fd is not None and channel.sequence == 1 and
                   channel.seed['original_binding'] == self.evidence.binding and
                   channel.seed['ready_sha256'] == io.sha(self.ready_raw) and
                   channel.seed['source_sha256'] == self.maintenance_inputs['source_sha256'] and
                   channel.seed['artifact_sha256'] == self.prepared_ready['artifact_sha256'] and
                   channel.seed['boot_id'] == self.prepared_ready['boot_id'] and
                   all(channel.seed[k] == self.evidence.pair[k] for k in
                       ('mac_tail_sha256', 'host_tail_sha256', 'unconfirmed_mac_tail')) and
                   channel.seed['fresh_state_sha256'] == io.sha(io.canonical(self.recovery_state_proof)) and
                   channel.seed['original_failure_sha256'] == io.sha(io.canonical(self.evidence.failure)) and
                   channel.ceiling == self.deadline, 'RECOVERY_EXECUTION_BINDING_NOT_ADMITTED')
        self.evidence.check_original(); self.check_unspent_owner()
        self.channel.finish()
        self.channel = self.a.channel = channel; self.binding = channel.binding
        self.recovery_bound = True
        channel.record('recovery_state_observation', self.recovery_state_proof)

    def start_baseline_check(self, unit, before, *, old):
        io.require(not old and self.replacement_ready and self.a.replacement_active and
                   self.a.classify_current_unit(unit, before, None) in
                   ('empty_inactive', 'empty_terminal_failed'), 'RECOVERY_START_BASELINE_NOT_ADMITTED')

    def record_start_attempt(self, unit, before, *, old):
        io.require(not old, 'RECOVERY_OLD_RUNTIME_START_FORBIDDEN')
        self.channel.record('recovery_start_attempt', {'unit': unit, 'original_binding': self.evidence.binding,
            'prior_invocation': before['InvocationID'], 'prior_restart_counter': before['NRestarts'],
            'prior_result': before['Result'], 'prior_active_state': before['ActiveState'],
            'original_attempt_not_reclassified': True, 'counter_reset_requested': False})

    def observe_start_identity(self, unit, identity, *, old):
        io.require(not old and unit not in self.recovery_new_seen and self.replacement_ready,
                   'RECOVERY_START_IDENTITY_NOT_NEW_REQUEST')
        self.recovery_new_seen[unit] = identity
        self.channel.record('recovery_new_invocation_observed', {'unit': unit, 'identity': identity,
            'rights_or_function_accepted': False, 'only_possible_terminal_stop_constraint': True})

    def reload(self):
        # Only the explicit fresh-admission delta or this recovery's own new
        # rename may reach here. The existing global source census remains.
        self.a.recovery_allow_load_delta = False
        Adapter.reload(self)
        self.a.recovery_reload_units.clear()

    def reconcile_config(self):
        self.a.check(); rows = unit_rows(UNITS, self.a.deadline)
        changed = [u for u,v in rows.items() if v['NeedDaemonReload'] != 'no' or
                   set(v['DropInPaths'].split()) != set(self.a.b['unit_files'][u]['dropins']) | self.a.own_dropins[u]]
        if changed:
            self.channel.record('recovery_reload_intent', {'units_with_own_load_delta': changed,
                'original_ack_reconstructed': False})
            self.reload()
            self.channel.record('recovery_reload_current', {'units': list(UNITS)})
        else:
            self.a.recovery_allow_load_delta = False; self.a.check()

    def _perform(self, action, unit=None, *, deadline):
        io.require(self.recovery_bound and not self.recovery_terminal and self.pending is None and
                   time.monotonic() < deadline <= self.deadline, 'RECOVERY_EFFECT_NOT_ADMITTED_OR_TERMINAL')
        allowed = {'recovery_reconcile_config', 'recovery_complete_barriers', 'recovery_stop',
                   'recovery_private_backup', 'recovery_private_restore', 'recovery_unused_or_verified_probes',
                   'recovery_publish_assets', 'recovery_release_barrier', 'recovery_start',
                   'supervised_owner_transaction'}
        io.require(action in allowed and (action, unit) not in self.recovery_once_actions,
                   'RECOVERY_ACTION_SCOPE_OR_REPEAT')
        if self.start_limit_observation is not None:self.start_limit_observation.drain()
        self.recovery_once_actions.add((action, unit))
        if action == 'supervised_owner_transaction':
            return Adapter._perform(self, action, unit, deadline=deadline)
        self.protected_state(); self.check_prepared_state(); self.check_unspent_owner()
        if action in ('recovery_stop', 'recovery_start'):
            io.require(unit in UNITS, 'RECOVERY_SERVICE_UNIT_SCOPE')
            value = self.a.unit(unit)
            current = process(int(value['MainPID'])) if int(value['MainPID']) else None
            kind = self.a.classify_current_unit(unit, value, current)
            if action == 'recovery_stop':
                io.require(kind == 'known_old_active', 'RECOVERY_STOP_NOT_KNOWN_ORIGINAL')
                for u in UNITS:self.condition(u, present=True)
            else:
                io.require(kind in ('empty_inactive', 'empty_terminal_failed') and self.replacement_ready,
                           'RECOVERY_START_NOT_EMPTY_NEW_RUNTIME')
                io.require(time.monotonic()+20+self.terminal_reserve_seconds <
                           min(self.deadline, self.channel.ceiling), 'RECOVERY_START_WITHOUT_TERMINAL_RESERVE')
                self.current_backup_verified(); self.check_probe_current()
                io.require(self.probe_hash is not None, 'RECOVERY_START_WITHOUT_PROBES')
                self.isolation(unit)
            self.channel.record('recovery_controlled_service_intent', {'action': action, 'unit': unit,
                'prior': {k:value[k] for k in ('InvocationID', 'NRestarts', 'Result', 'ActiveState', 'Job')},
                'original_binding': self.evidence.binding, 'original_effects_not_reclassified': True})
            value = Adapter._perform(self, 'stop' if action == 'recovery_stop' else 'start', unit, deadline=deadline)
            return {**value, 'action': action}
        io.require(unit is None or action == 'recovery_release_barrier', 'RECOVERY_ACTION_UNIT_SCOPE')
        self.pending = (action, unit)
        self.channel.record('recovery_action_intent', {'action': action, 'unit': unit})
        result = {'action': action, 'unit': unit, 'outcome': 'CONFIRMED'}
        if action == 'recovery_reconcile_config':
            self.reconcile_config()
            if self.a.recovery_phase == 'F4':self.arm_start_limit_observation()
        elif action == 'recovery_complete_barriers':
            io.require(self.a.recovery_phase == 'F1', 'RECOVERY_BARRIER_COMPLETION_PHASE')
            for key,spec in self.asset_map.items():
                if spec['source'] is None:
                    if self.asset_states[key]['place'] == 'candidate':self.publish_prepared_asset(key)
                    else:io.require(self.asset_states[key]['place'] == 'target', 'RECOVERY_EARLY_RELEASE_UNKNOWN')
            self.reconcile_config()
            for u in UNITS:self.condition(u, present=True)
        elif action == 'recovery_private_backup':
            self.quiet(); self.a.current_data_readonly(); self.space()
            if self.start_limit_observation is None:self.arm_start_limit_observation()
            if self.backup_mode == 'ORIGINAL_CURRENT':self.current_backup_verified()
            else:
                io.require(self.backup_mode == 'NEW_RECOVERY_REQUIRED' and not self.recovery_backup_used,
                           'RECOVERY_PRIVATE_BACKUP_NO_REPLAY')
                self.recovery_backup_used = True
                self.p.absent(STAGING+'/recovery-once'); self.p.create_directory(STAGING+'/recovery-once')
                self.backup = Backup(self.p, {p:v['sha256'] for p,v in self.a.b['files'].items()},
                                     STAGING+'/recovery-once', self.quiet)
                self.backup_hash = self.backup.create(); self.backup_mode = 'RECOVERY_COPY_CREATED'
            result['proof_sha256'] = self.backup_hash
        elif action == 'recovery_private_restore':
            self.quiet()
            if self.backup_mode == 'ORIGINAL_CURRENT':self.current_backup_verified()
            else:
                io.require(self.backup_mode == 'RECOVERY_COPY_CREATED' and self.restore_hash is None,
                           'RECOVERY_PRIVATE_RESTORE_NO_REPLAY')
                self.restore_hash = self.backup.restore_test(); self.backup_mode = 'RECOVERY_CURRENT'
            result['proof_sha256'] = self.restore_hash
        elif action == 'recovery_unused_or_verified_probes':
            self.quiet(); self.current_backup_verified()
            if self.probe_hash is not None:self.check_probe_current()
            else:
                io.require(self.a.recovery_probes.state == 'UNUSED' and self.probes is None,
                           'RECOVERY_PROBE_ENTRY_ALREADY_USED')
                self.a.recovery_probes.unused_current()
                self.recovery_new_probe_platform = self.a.platform_identity()
                module = self.source.load('probes')
                self.probes = module.Probes(self.p, self.source, self.a, self.channel, deadline=deadline)
                self.probe_hash = self.probes.run()
                self.check_probe_current()
                self.channel.record('recovery_probes_complete', {
                    'proof_sha256': self.probe_hash, 'platform': self.recovery_new_probe_platform,
                    'reports': [{'unit': r['unit'], 'sha256': io.sha(io.canonical(r))} for r in self.probes.reports],
                    'cleanup': [], 'original_probe_replayed': False})
            result['proof_sha256'] = self.probe_hash
        elif action == 'recovery_publish_assets':
            self.quiet(); self.current_backup_verified(); self.check_probe_current()
            self.a.current_data_readonly()
            for key,spec in self.asset_map.items():
                if spec['source'] is not None:
                    if self.asset_states[key]['place'] == 'candidate':self.publish_prepared_asset(key)
                    else:io.require(self.asset_states[key]['place'] == 'target', 'RECOVERY_ASSET_PLACE_CHANGED')
            self.reconcile_config()
            if not self.replacement_ready:self.activate_prepared_runtime()
            for u in UNITS:self.isolation(u)
            if self.start_limit_observation is None:self.arm_start_limit_observation()
            result['proof_sha256'] = io.sha(self.ready_raw)
        elif action == 'recovery_release_barrier':
            io.require(unit in UNITS and all(u in self.accepted for u in UNITS[:UNITS.index(unit)]),
                       'RECOVERY_RELEASE_PREDECESSOR_NOT_ACCEPTED')
            key = next(k for k,s in self.asset_map.items() if s['source'] is None and s['unit'] == unit)
            spec = self.asset_map[key]; current = self.asset_states[key]
            if current['place'] == 'target':
                self.condition(unit, present=True)
                self.channel.record('recovery_barrier_release_intent', {'key': key, 'actual_before': current})
                row = self.p.quarantine(spec['target'], spec['quarantine'], current['metadata'])
                actual = self.p.classify_owned_pair(spec['candidate'], spec['target'], self.prepared_assets[key],
                                                    quarantine=spec['quarantine'])
                io.require(actual['place'] == 'quarantine' and self.same_file(actual['metadata'], row),
                           'RECOVERY_BARRIER_RELEASE_POSTSTATE_UNKNOWN')
                self.asset_states[key] = actual; self.barrier_places[unit] = (spec['quarantine'], row)
                self.a.own_dropins[unit].remove(spec['target']); self.a.recovery_allow_load_delta = True
                self.channel.record('recovery_barrier_release_observed', {'key': key, 'actual': actual})
                self.reconcile_config()
            else:io.require(current['place'] == 'quarantine', 'RECOVERY_RELEASE_NOT_OWN_PUBLISHED_BARRIER')
            self.condition(unit, present=False)
        else:
            raise io.Hold('PUBLIC_OPERATOR_RECOVERY_ACTION_NOT_YET_IMPLEMENTED')
        io.require(time.monotonic() < deadline, 'RECOVERY_ACTION_LATE')
        self.channel.record('recovery_action_ack', result); self.pending = None
        return result

    def _observe(self, phase, *, deadline):
        io.require(self.recovery_bound and not self.recovery_terminal and deadline <= self.deadline,
                   'RECOVERY_OBSERVATION_NOT_ADMITTED')
        if self.start_limit_observation is not None:self.start_limit_observation.drain()
        if phase == 'recovery_admitted':
            self.protected_state(); self.check_prepared_state(); self.check_unspent_owner()
            self.a.current_data_readonly()
            io.require(self.site_read_witness() == self.evidence.witness['site_read_witness_sha256'],
                       'RECOVERY_CURRENT_OWNER_PLAN_CHANGED')
            self.channel.check(); self.now()
            return self.r.Observation(self.r.TX, self.binding, phase,
                self.r.RECOVERY_BASE | {self.a.recovery_phase}, time.monotonic())
        if phase.startswith('recovery_state:'):
            unit = phase.split(':', 1)[1]; io.require(unit in UNITS, 'RECOVERY_OBSERVATION_UNIT_SCOPE')
            self.protected_state(); self.check_prepared_state()
            value = self.a.unit(unit)
            current = process(int(value['MainPID'])) if int(value['MainPID']) else None
            kind = self.a.classify_current_unit(unit, value, current)
            key = next(k for k,s in self.asset_map.items() if s['source'] is None and s['unit'] == unit)
            self.condition(unit, present=self.asset_states[key]['place'] == 'target')
            self.channel.record('recovery_prior_unit_observation', {'unit': unit, 'kind': kind,
                'current': {k:value[k] for k in ('InvocationID', 'NRestarts', 'Result', 'ActiveState',
                           'SubState', 'MainPID', 'ControlPID', 'Job', 'ControlGroup')},
                'barrier_place': self.asset_states[key]['place'], 'original_ack_reconstructed': False})
            if kind == 'known_new_active' and self.start_limit_observation is not None:
                self.start_limit_observation.retire_already_active(unit)
            return self.r.Observation(self.r.TX, self.binding, phase, self.r.RECOVERY_UNIT | {kind}, time.monotonic())
        if phase.startswith('recovery_active:'):
            unit = phase.split(':', 1)[1]; io.require(unit in UNITS, 'RECOVERY_OBSERVATION_UNIT_SCOPE')
            io.require(all(u in self.accepted for u in UNITS[:UNITS.index(unit)]), 'RECOVERY_ACTIVE_PREFIX_NOT_ACCEPTED')
            self.a.check(); self.isolation(unit); self.condition(unit, present=False)
            self.function(unit, old=False); self.a.check(); self.check_probe_current(); self.current_backup_verified()
            return self.r.Observation(self.r.TX, self.binding, phase, frozenset((
                'existing_new_invocation_freshly_accepted', 'actual_rights_data_DB_HTTP',
                'no_start_or_restart_performed')), time.monotonic())
        io.require(phase not in ('pre_stop', 'prepared', 'staging_ready', 'staging'),
                   'RECOVERY_ORIGINAL_PHASE_FORBIDDEN')
        return super()._observe(phase, deadline=deadline)

    def hold_known_new_units(self, *, deadline):
        """K4's sole terminal action. No forward retry or subsequent owner.

        This deliberately does NOT use the normal rights-acceptance path:
        an exact, authentic new invocation with bad measured rights can be
        stop-only. Unknown/replaced processes, live jobs, source/writer loss,
        unavailable custody or insufficient reserve still deny every effect.
        """
        io.require(self.recovery_bound and not self.recovery_terminal and not self.owner_admission_started and
                   self.owner is None and self.replacement_ready and self.a.replacement_active and
                   deadline <= self.deadline, 'RECOVERY_TERMINAL_ENTRY_NOT_ALLOWED')
        self.recovery_terminal = True  # even failed admission cannot be retried
        started = time.monotonic(); end = min(deadline, self.deadline, self.channel.ceiling)
        io.require(started+self.terminal_reserve_seconds < end, 'RECOVERY_TERMINAL_RESERVE_UNAVAILABLE')
        prepare_end = min(end-60-self.terminal_cleanup_seconds, started+self.terminal_prepare_seconds)
        with self.a.limit(prepare_end):
            self.channel.check(); self.check_unspent_owner(); self.evidence.check_original()
            self.check_transaction_lock(); self.check_prepared_state()
            self.a.check_files(); self.a.check_loader_configuration(); self.a.verify_external_libraries()
            self.a.manager_jobs_clear()
            io.require(self.a.unit_search() == self.a.b['unit_search_sha256'], 'RECOVERY_TERMINAL_FOREIGN_UNIT_DELTA')
            profiles = {}; units = unit_rows(UNITS, self.a.deadline)
            fields = (*context.CURRENT_SECURITY, 'uid_map', 'gid_map', 'setgroups', 'exe_sha256',
                      'initial_env_sha256', 'lsm_sha256')
            for unit, value in units.items():
                io.require(not value['Job'] and value['ControlPID'] == '0', 'RECOVERY_TERMINAL_JOB_UNKNOWN')
                if value['MainPID'] == '0':
                    io.require(value['ActiveState'] in ('inactive', 'failed') and self.a.empty(unit),
                               'RECOVERY_TERMINAL_EMPTY_UNIT_UNKNOWN')
                    profiles[unit] = {'kind': 'empty', 'prior_restart_counter': value['NRestarts'],
                                      'prior_result': value['Result']}
                    continue
                row = process(int(value['MainPID']))
                identity = (value['InvocationID'], row['pid'], row['starttime'])
                expected = self.a.runtime_invocations.get(unit, self.recovery_new_seen.get(unit))
                io.require(value['ActiveState'] == 'active' and value['SubState'] == 'running' and
                           value['NRestarts'] == '0' and identity == expected and
                           value['ControlGroup'] == '/system.slice/'+unit and
                           row['cgroup'] == '0::'+value['ControlGroup'], 'RECOVERY_TERMINAL_NOT_BOUND_NEW_INVOCATION')
                self.a.interpreter_binding(row, old=False)
                profiles[unit] = {'kind': 'known_new_stop_only', 'identity': identity,
                                  'kernel': {k:row[k] for k in fields}, 'operational_acceptance': False}
            # This finite stop-only view is never deserialized or reused for
            # operation. It is derived above from current source-bound reads.
            self.a.terminal_profiles = profiles
            self.a.rights = {u for u,v in profiles.items() if v['kind'] == 'known_new_stop_only'}
            self.a.stopped = set(UNITS)-self.a.rights
            self.a.runtime_invocations = {u:profiles[u]['identity'] for u in self.a.rights}
            self.a.check()
            self.channel.record('recovery_terminal_stop_only_admission', {'profiles': profiles,
                'original_status': 'FAILED_HOLD', 'recovery_status': 'HOLD',
                'no_start_or_owner_after_this_entry': True})
            for key,spec in self.asset_map.items():
                if spec['source'] is not None:continue
                current = self.asset_states[key]
                io.require(current['place'] in ('target', 'quarantine'), 'RECOVERY_TERMINAL_BARRIER_NOT_OWNED')
                if current['place'] == 'target':continue
                self.a.check(); self.check_prepared_state(); self.channel.check()
                self.channel.record('recovery_terminal_barrier_intent', {'key': key, 'actual_before': current})
                row = self.p.quarantine(spec['quarantine'], spec['target'], current['metadata'])
                actual = self.p.classify_owned_pair(spec['candidate'], spec['target'], self.prepared_assets[key],
                                                    quarantine=spec['quarantine'])
                io.require(actual['place'] == 'target' and self.same_file(actual['metadata'], row),
                           'RECOVERY_TERMINAL_BARRIER_OUTCOME_UNKNOWN')
                self.asset_states[key] = actual; self.barriers[spec['unit']] = row
                self.barrier_places[spec['unit']] = (spec['target'], row)
                self.a.own_dropins[spec['unit']].add(spec['target']); self.a.own_config_paths.add(spec['target'])
                self.a.recovery_allow_load_delta = True
                self.channel.record('recovery_terminal_barrier_observed', {'key': key, 'actual': actual})
            self.reconcile_config()
            for unit in UNITS:self.condition(unit, present=True)
            io.require(time.monotonic() < prepare_end, 'RECOVERY_TERMINAL_PREPARATION_LATE')
        for unit in reversed(UNITS):
            if self.a.terminal_profiles[unit]['kind'] == 'empty':continue
            stop_end = min(end-self.terminal_cleanup_seconds, time.monotonic()+20)
            with self.a.limit(stop_end):
                self.a.check(); self.channel.check(); self.check_transaction_lock()
                for u in UNITS:self.condition(u, present=True)
                identity = self.a.terminal_profiles[unit]['identity']
                io.require(identity not in self.terminal_stop_invocations, 'RECOVERY_TERMINAL_STOP_NO_REPLAY')
                self.terminal_stop_invocations.add(identity)
                self.channel.record('recovery_terminal_stop_intent', {'unit': unit, 'identity': identity})
                result = self.service_action('stop', unit, deadline=stop_end)
                value = self.a.unit(unit)
                io.require(result.returncode == 0 and value['MainPID'] == value['ControlPID'] == '0' and
                           not value['Job'] and self.a.empty(unit), 'RECOVERY_TERMINAL_STOP_OUTCOME_UNKNOWN')
                self.a.terminal_profiles[unit] = {'kind': 'empty', 'prior_restart_counter': value['NRestarts'],
                                                'prior_result': value['Result']}
                self.a.stopped.add(unit); self.a.rights.discard(unit)
                self.channel.record('recovery_terminal_stop_observed', {'unit': unit,
                    'cgroup_empty': True, 'no_job': True, 'recovery_status': 'HOLD'})
                self.a.check()
        self.a.check(); self.channel.check()
        io.require(self.a.stopped == set(UNITS) and time.monotonic()+self.terminal_cleanup_seconds < end,
                   'RECOVERY_TERMINAL_STOP_OR_CLEANUP_RESERVE_INCOMPLETE')
        self.channel.record('recovery_terminal_hold_current', {'known_new_units_stopped': list(UNITS),
            'original_status': 'FAILED_HOLD', 'recovery_status': 'HOLD', 'host_complete': False,
            'owner_entered': False, 'operator_cleanup_still_required': True})

    def close(self):
        errors = []
        try:errors.extend(super().close())
        finally:
            if getattr(self, 'evidence', None) is not None:errors.extend(self.evidence.close())
        return errors
