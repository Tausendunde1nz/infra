"""R5 forward-only runtime replacement within the SAME R3 transaction.

Legacy bytes are protected as an UNTRUSTED read witness, not execution origin.
Only the three hook-free, source-bound units may be stopped. New bytes are
installed after quiet/backup/restore/probes; no old-runtime return is admitted.
No CLI/import mutation. All methods require the surviving production adapter.
"""
from __future__ import annotations

import base64
import io as memory_io
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time

import tu1nz_public_operator_io as io
import tu1nz_public_runtime_artifact as artifact
from tu1nz_public_operator_runtime_guard import RuntimeFence, metadata, READ
from tu1nz_public_operator_observe import Authority, UNITS, process, command
from tu1nz_public_operator_host import Adapter

OVERLAY = 'zzz-public-runtime-r5.conf'
CHUNK = 512*1024
REFERENCE = 'TU1NZ_PUBLIC_RUNTIME_REPLACEMENT_REFERENCE_R5_V1'


validate_receipt = artifact.validate_receipt
inspect_archive = artifact.inspect_archive


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
    def open_runtime(self, baseline, paths, deadline):
        self.replacement_active=False
        self.external_dependencies={};self.external_identities={}
        return LegacyStopFence(baseline['source_release']['runtime_reference'],paths,
            baseline['source_origin_receipts'],python_binary=baseline['source_release']['python_binary'],deadline=deadline)

    def extra_unit_contract(self, unit, value, *, stop_only):
        io.require(not any(value[k] for k in ('ExecStop','ExecStopPost','ExecStartPre','ExecStartPost','ExecCondition',
                                            'RootDirectory','RootImage')), 'REPLACEMENT_LEGACY_EXEC_HOOK_OR_ROOT')

    def interpreter_binding(self,row,*,old):
        if old:
            io.require(not self.replacement_active,'LEGACY_START_AFTER_REPLACEMENT_DENIED')
            return super().interpreter_binding(row,old=True)
        io.require(self.replacement_active and isinstance(self.runtime,ReplacementFence),
                   'UNTRUSTED_LEGACY_RUNTIME_NOT_START_AUTHORITY')
        binary=artifact.ROOT+'/python/bin/python3.12'
        expected=self.b['source_release']['runtime_reference']['artifact']['objects']['python/bin/python3.12']['sha256']
        io.require(row['exe']==binary and row['exe_sha256']==expected,'REPLACEMENT_INTERPRETER_BINDING')
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

    def bind_external_libraries(self):
        io.require(self.replacement_active and isinstance(self.runtime,ReplacementFence),
                   'REPLACEMENT_NOT_CURRENT')
        io.require(0<len(self.runtime.elf_files)<=256,'REPLACEMENT_ELF_COUNT')
        reference=self.b['source_release']['probe_dependencies']
        for name in sorted(self.runtime.elf_files):
            result=command(['/usr/bin/ldd',artifact.ROOT+'/'+name],self.deadline)
            io.require(result.returncode==0 and b'not found' not in result.stdout,'REPLACEMENT_LOADER_UNKNOWN')
            for line in result.stdout.decode().splitlines():
                words=line.split();paths=[w for w in words if w.startswith('/')]
                io.require(paths or 'linux-vdso.so.' in line or line.strip()=='statically linked',
                           'REPLACEMENT_LOADER_OUTPUT_UNKNOWN')
                for path in paths:
                    resolved=Path(path).resolve(strict=True)
                    if resolved.is_relative_to(artifact.ROOT):
                        key=str(resolved.relative_to(artifact.ROOT))
                        io.require(self.runtime.expected.get(key,{}).get('kind')=='file',
                                   'REPLACEMENT_LOADER_ESCAPED_ARTIFACT')
                    else:
                        io.require(path in reference and set(reference[path])=={'source','sha256'} and
                            reference[path]['source'].startswith(('/usr/lib/','/usr/bin/')),
                            'REPLACEMENT_EXTERNAL_LIBRARY_ORIGIN_UNBOUND')
                        self.external_dependencies[path]=reference[path]
        self.verify_external_libraries()

    def verify_external_libraries(self):
        for path,expected in self.external_dependencies.items():
            resolved=Path(path).resolve(strict=True)
            io.require(str(resolved)==expected['source'],'REPLACEMENT_LOADER_LIBRARY_REPLACED')
            raw,row=self.paths.read(expected['source'])
            io.require(io.sha(raw)==expected['sha256'],'REPLACEMENT_EXTERNAL_LIBRARY_DRIFT')
            identity=tuple(row[k] for k in ('device','inode','mtime_ns','ctime_ns'))
            if path not in self.external_identities:
                fd=os.open(expected['source'],READ)
                try:
                    observed=os.fstat(fd)
                    io.require((observed.st_dev,observed.st_ino,observed.st_mtime_ns,observed.st_ctime_ns)==identity,
                               'REPLACEMENT_EXTERNAL_LIBRARY_CHANGED')
                    self.runtime._watch(fd)
                finally:os.close(fd)
                self.external_identities[path]=identity
                self.runtime.files.add(identity[:2])
            else:io.require(self.external_identities[path]==identity,'REPLACEMENT_EXTERNAL_LIBRARY_REPLACED')
        if self.replacement_active:self.runtime.check()

    def check(self,*,stop_only=False):
        super().check(stop_only=stop_only)
        self.verify_external_libraries()


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
        self.a.runtime=next_fence;self.a.replacement_active=True
        errors=previous.close()
        if errors:
            raise io.Hold('PUBLIC_OPERATOR_LEGACY_WITNESS_CLEANUP_UNCONFIRMED')
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
