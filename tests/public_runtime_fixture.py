"""Synthetic EXPECTED artifact bindings for native R5 production-entry tests.

No admission/result/fact/action is substituted. This fixture changes only the
expected machine/plan/catalog coordinates in authenticated-memory TEST Source,
just as R4 changes its target coordinates. Production exposes no such option.
Real pinned CPython/wheel inputs are used; only the private Application is
replaced by650 synthetic files, and that expected catalog is explicitly bound.
"""
import base64
import copy
import io
from pathlib import Path
import json
import os
import tarfile

from tests import public_operator_native as f


def runtime(s):
    a=s.load('artifact')
    inputs=copy.deepcopy(json.loads(s.bytes['runtime_inputs']))
    source={'requirements-m2.lock':('\n'.join('--hash=sha256:'+w['sha256'] for w in inputs['wheels'])+'\n').encode(),
            'requirements-s5.lock':b'# synthetic closure already bound above\n'}
    main=('def entrypoint():\n    exec('+repr(f.SERVER)+', {"__name__": "__main__"})\n\n'
          'if __name__=="__main__":\n    entrypoint()\n').encode()
    for package,file in [('tu1nz_public_s7','runtime.py'),('tu1nz_public_s8','landing.py'),
                         ('tu1nz_exposure_s10','runtime.py')]:
        source['src/'+package+'/__init__.py']=b''
        source['src/'+package+'/'+file]=main
    for i in range(650-len(source)):source['docs/synthetic-source-'+str(i).zfill(4)+'.txt']=b'SYNTHETIC SOURCE ONLY\n'
    catalog={k:{'kind':'file','sha256':a.sha(v)} for k,v in source.items()}
    inputs['application'].update(commit='0'*40,tree='1'*40,manifest_sha256=a.sha(a.canonical(catalog)))
    a.APP=('0'*40,'1'*40);a.SOURCE_MANIFEST=inputs['application']['manifest_sha256']
    a.INPUTS_SHA=a.sha(a.canonical(inputs))
    root=Path('/runtime-inputs')
    python=(root/inputs['python']['filename']).read_bytes()
    wheels={w['filename']:(root/w['filename']).read_bytes() for w in inputs['wheels']}
    raw,receipt=a.assemble(source,python,wheels,inputs)
    # Local expected data, not Code/action/observation replacement.
    s.bytes['runtime_inputs']=a.canonical(inputs)
    return raw,receipt,inputs


def substitutions(s,inputs):
    a=s.load('artifact')
    return ('s.load("artifact").APP='+repr(a.APP)+'\n'+
        's.load("artifact").SOURCE_MANIFEST='+repr(a.SOURCE_MANIFEST)+'\n'+
        's.load("artifact").INPUTS_SHA='+repr(a.INPUTS_SHA)+'\n'+
        's.bytes["runtime_inputs"]=__import__("base64").b64decode('+repr(base64.b64encode(a.canonical(inputs)).decode())+')\n')


def external_dependencies(s,payload,receipt):
    """Read the real pinned artifact's ELF closure BEFORE synthetic baseline.

    The distro Python's closure is insufficient for the different portable
    interpreter and binary wheels. This is fixture construction, not a Host
    origin assertion or substitution for the production ldd/hash/watch checks.
    Never create the proposed production root here: the actual installer must
    still prove its create-only transition through the production entry.
    """
    a=s.load('artifact');a.inspect_archive(payload,receipt)
    root=f.ROOT/'runtime-dependency-reference';root.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(payload),mode='r:gz') as archive:
        for member in archive:
            path=root/member.name
            if member.isdir():path.mkdir(mode=0o755)
            elif member.issym():
                target=member.linkname
                if target.startswith(a.ROOT+'/'):target=str(root)+target[len(a.ROOT):]
                path.symlink_to(target)
            else:
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,member.mode)
                with os.fdopen(fd,'wb') as output:output.write(archive.extractfile(member).read())
    dependencies={};elf_files=set()
    for name,row in receipt['objects'].items():
        if row['kind']!='file':continue
        path=root/name
        with path.open('rb') as stream:magic=stream.read(4)
        if magic!=b'\x7fELF':continue
        elf_files.add(name)
    roots=a.loader_context_roots(elf_files);covered=set(roots)
    for name in roots:
        path=root/name
        for line in f.run('/usr/bin/ldd',str(path)).decode().splitlines():
            assert 'not found' not in line
            paths=[w for w in line.split() if w.startswith('/')]
            assert paths or 'linux-vdso.so.' in line or line.strip()=='statically linked'
            for candidate in paths:
                resolved=Path(candidate).resolve(strict=True)
                if resolved.is_relative_to(root):
                    key=str(resolved.relative_to(root))
                    assert receipt['objects'].get(key,{}).get('kind')=='file' and key in elf_files
                    covered.add(key)
                else:
                    assert str(resolved).startswith(('/usr/lib/','/usr/bin/'))
                    dependencies[candidate]={'source':str(resolved),'sha256':a.sha(resolved.read_bytes())}
    a.require_elf_coverage(elf_files,covered)
    assert dependencies
    assert not Path(a.ROOT).exists()  # no premature production installation
    return dependencies
