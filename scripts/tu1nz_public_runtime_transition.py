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
import tu1nz_public_runtime_artifact as artifact
from tu1nz_public_operator_runtime_guard import RuntimeFence, metadata, READ
from tu1nz_public_operator_observe import Authority, UNITS, ENV, process, command, typed_exec_properties, EXEC_PROPERTIES
from tu1nz_public_operator_host import Adapter

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
            ok(L.sd_bus_message_append(message,b's',ctypes.c_char_p(b'org.freedesktop.systemd1.Service')))
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
            values=self.selected_values(reply)
            io.require(ok(L.sd_bus_message_at_end(reply,1))==1,'REPLACEMENT_READER_EXTRA_VALUE')
            body={'type':'a{sv}','data':[values]}
            io.require(len(io.canonical(body))<=2*1024*1024 and set(self.KEYS)==set(values),
                       'REPLACEMENT_READER_OUTPUT_BOUND_OR_MISSING')
            self.check();return body
        except BaseException:
            self.broken=True;raise
        finally:
            if reply:L.sd_bus_message_unref(reply)
            if message:L.sd_bus_message_unref(message)

    def selected_values(self,message):
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
            if key not in self.KEYS:
                # Library consumes/validates the complete variant; no current
                # safety property is skipped and missing required keys deny.
                io.require(ok(L.sd_bus_message_skip(message,b'v'))==1,'REPLACEMENT_READER_TYPE')
            else:
                signature=self.KEYS[key]
                io.require(ok(L.sd_bus_message_enter_container(message,b'v',signature.encode()))==1 and
                           ok(L.sd_bus_message_enter_container(message,b'a',signature[1:].encode()))==1,
                           'REPLACEMENT_READER_TYPE')
                values=[];size=0
                if signature!='as':
                    io.require(ok(L.sd_bus_message_at_end(message,0))==1,
                        'REPLACEMENT_LEGACY_EXEC_HOOK_OR_ROOT' if key in EXEC_PROPERTIES else
                        'REPLACEMENT_UNIT_ENVIRONMENT_FILES_FORBIDDEN')
                else:
                    while not ok(L.sd_bus_message_at_end(message,0)):
                        self.check();value=ctypes.c_char_p()
                        io.require(ok(L.sd_bus_message_read_basic(message,b's',ctypes.byref(value)))==1 and
                                   value.value is not None,'REPLACEMENT_READER_TYPE')
                        raw=value.value;size+=len(raw)
                        io.require(size<=2*1024*1024 and len(values)<32768,'REPLACEMENT_READER_OUTPUT_BOUND')
                        values.append(raw.decode())
                ok(L.sd_bus_message_exit_container(message))
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
        io.require(kind in ('owner','jobs'),'REPLACEMENT_READER_SCOPE')
        destination,path,interface,member=(
            (b'org.freedesktop.DBus',b'/org/freedesktop/DBus',b'org.freedesktop.DBus',b'GetNameOwner')
            if kind=='owner' else (b'org.freedesktop.systemd1',b'/org/freedesktop/systemd1',
                b'org.freedesktop.systemd1.Manager',b'ListJobs'))
        message=ctypes.c_void_p();reply=ctypes.c_void_p();L=self.lib
        def ok(value):io.require(value>=0,'REPLACEMENT_READER_REPLY_UNKNOWN');return value
        try:
            self.check()
            ok(L.sd_bus_message_new_method_call(self.bus,ctypes.byref(message),destination,path,interface,member))
            ok(L.sd_bus_message_set_auto_start(message,0))
            ok(L.sd_bus_message_set_allow_interactive_authorization(message,0))
            if kind=='owner':
                ok(L.sd_bus_message_append(message,b's',ctypes.c_char_p(b'org.freedesktop.PolicyKit1')))
            remaining=min(20,self.deadline-time.monotonic());io.require(remaining>0,'REPLACEMENT_READER_DEADLINE')
            ok(L.sd_bus_call(self.bus,message,int(remaining*1000000),None,ctypes.byref(reply)))
            self.check();blob=ctypes.c_void_p();size=ctypes.c_size_t()
            try:
                ok(L.bus_message_get_blob(reply,ctypes.byref(blob),ctypes.byref(size)))
                io.require(blob and 0<size.value<=65536,'REPLACEMENT_READER_OUTPUT_BOUND')
            finally:
                if blob:self.libc.free(blob)
            if kind=='owner':
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
        if self.bus:
            self.lib.sd_bus_close(self.bus);self.lib.sd_bus_unref(self.bus);self.bus=ctypes.c_void_p()
        self.broken=True


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

    def open_runtime(self, baseline, paths, deadline):
        io.operator_dependency_reference(baseline['source_release'],baseline['source_origin_receipts'])
        self.replacement_active=False
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

    def dependency_census(self,target):
        # Execute ONLY the independently authenticated, self-contained loader
        # selected by bound busctl. No ldd/shell/helper or guessed SONAME, no
        # generic command-scope expansion. Both census sites use this path.
        loader=self.census_loader
        io.require(loader is not None and loader in self.external_identities and
            (target=='/usr/bin/busctl' or target.startswith(artifact.ROOT+'/') and
             target[len(artifact.ROOT)+1:] in self.runtime.elf_files),
            'REPLACEMENT_CENSUS_SCOPE')
        self.loader_config.check();self.verify_external_libraries()
        remaining=min(20,self.deadline-time.monotonic())
        io.require(remaining>0,'REPLACEMENT_CENSUS_DEADLINE')
        result=subprocess.run([self.loader_bindings[loader],'--list',target],capture_output=True,
            timeout=remaining,env=dict(ENV),cwd='/')
        io.require(time.monotonic()<self.deadline and len(result.stdout)<=2*1024*1024 and
            len(result.stderr)<=2*1024*1024,'REPLACEMENT_CENSUS_TIME_OR_OUTPUT_BOUND')
        self.loader_config.check();self.verify_external_libraries()
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

    def bind_external_libraries(self):
        self.check_loader_configuration()
        io.require(self.replacement_active and isinstance(self.runtime,ReplacementFence),
                   'REPLACEMENT_NOT_CURRENT')
        io.require(0<len(self.runtime.elf_files)<=256,'REPLACEMENT_ELF_COUNT')
        reference=self.b['source_release']['probe_dependencies']
        roots=artifact.loader_context_roots(self.runtime.elf_files)
        covered=set(roots)
        for name in roots:
            result=self.dependency_census(artifact.ROOT+'/'+name)
            io.require(result.returncode==0 and b'not found' not in result.stdout,'REPLACEMENT_LOADER_UNKNOWN')
            for line in result.stdout.decode().splitlines():
                words=line.split();paths=[w for w in words if w.startswith('/')]
                io.require(paths or 'linux-vdso.so.' in line or line.strip()=='statically linked',
                           'REPLACEMENT_LOADER_OUTPUT_UNKNOWN')
                for path in paths:
                    resolved=Path(self.bind_loader_path(path))
                    if resolved.is_relative_to(artifact.ROOT):
                        key=str(resolved.relative_to(artifact.ROOT))
                        io.require(self.runtime.expected.get(key,{}).get('kind')=='file',
                                   'REPLACEMENT_LOADER_ESCAPED_ARTIFACT')
                        io.require(key in self.runtime.elf_files,'REPLACEMENT_LOADER_NON_ELF_TARGET')
                        covered.add(key)
                    else:
                        io.require(path in reference and set(reference[path])=={'source','sha256'} and
                            reference[path]['source'].startswith(('/usr/lib/','/usr/bin/')),
                            'REPLACEMENT_EXTERNAL_LIBRARY_ORIGIN_UNBOUND')
                        self.external_dependencies[path]=reference[path]
        artifact.require_elf_coverage(self.runtime.elf_files,covered)
        self.verify_external_libraries()

    def check_loader_configuration(self):
        self.loader_config.check()
        measured=manager_loader_environment(self.read_bus().environment())
        if self.manager_environment is None:self.manager_environment=measured
        else:io.require(measured==self.manager_environment,'REPLACEMENT_MANAGER_ENVIRONMENT_CHANGED')
        self.loader_config.check()

    def verify_external_libraries(self):
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
            if path not in self.external_identities:
                fd=os.open(expected['source'],READ)
                try:
                    observed=os.fstat(fd)
                    io.require((observed.st_dev,observed.st_ino,observed.st_mtime_ns,observed.st_ctime_ns)==identity,
                               'REPLACEMENT_EXTERNAL_LIBRARY_CHANGED')
                    self.runtime._watch(fd)
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
                self.runtime.files.add(identity[:2])
            else:io.require(self.external_identities[path]==identity,'REPLACEMENT_EXTERNAL_LIBRARY_REPLACED')
        if self.replacement_active:self.runtime.check()
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

    def receive_artifact(self):
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
        raw=b''.join(parts);inspect_archive(raw,expected);self.quiet()
        return raw

    def materialize(self, raw, *, deadline):
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
            self.a.b['source_origin_receipts'],python_binary=artifact.ROOT+'/python/bin/python3.12',deadline=self.deadline)
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
