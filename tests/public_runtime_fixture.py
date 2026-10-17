"""Synthetic EXPECTED artifact bindings for native R5 production-entry tests.

No admission/result/fact/action is substituted. This fixture changes only the
expected machine/plan/catalog coordinates in authenticated-memory TEST Source,
just as R4 changes its target coordinates. Production exposes no such option.
Real pinned CPython/wheel inputs are used; only the private Application is
replaced by650 synthetic files, and that expected catalog is explicitly bound.
"""
import base64
import copy
from pathlib import Path
import json

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
