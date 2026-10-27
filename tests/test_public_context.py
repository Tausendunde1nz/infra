"""Only synthetic context/kernel adapters. Never Host admission or native PASS."""
import ctypes
import copy
import contextlib
import errno
from pathlib import Path
import select
import socket
import stat
import struct
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import tu1nz_public_operator as client
import tu1nz_public_operator_context as context
import tu1nz_public_operator_observe as observe
import test_public_prospective_admission as prospective_fixture
io = client.io


def context_fixture(change=None):
    """Entirely synthetic: no real container IDs/PIDs/hashes or Host claims."""
    scope,b,actual = prospective_fixture.ProspectiveAdmission().fixture()
    b['source_release']['runtime_reference']={'origin_sha256':io.sha(b'SYNTHETIC_RUNTIME_REFERENCE_NOT_HOST')}
    old_bh,old_ah = scope['prospective_binding_sha256'],scope['prospective_acceptance_sha256']
    binding,acceptance = io.parse(actual.pop(old_bh)),io.parse(actual.pop(old_ah))
    def put(value):
        raw = io.canonical(value); h = io.sha(raw); actual[h] = raw; return h
    def meta(mode=0o755): return dict(uid=0,gid=0,mode=mode,attrs={},flags=0)
    for a in binding['actors']: a['profile']['context_id'] = 'HOST'
    host_bytes = {a['profile']['exe']:a['profile']['exe_sha256'] for a in binding['actors']}
    shared = {path:io.sha(('synthetic:'+path).encode()) for programs in context.PROGRAMS.values() for path in programs}
    shared.update(host_bytes)
    contexts = {}; next_pid = 10000
    source = put({'synthetic_publisher':'not a real publisher or actual byte attestation'})
    for index,(key,programs) in enumerate(context.PROGRAMS.items()):
        is_user = key.startswith('U'); ns = {n:n+':['+str(1 if is_user else 200+index)+']' for n in context.NS}
        cgroup = ('0::/user.slice/user-1001.slice/session-'+str(500+index)+'.scope' if is_user else
                  '0::/system.slice/docker-'+io.sha(('synthetic-container:'+key).encode())+'.scope')
        files = {}; profiles = []; members = []; mappings = {}
        for exe,count in programs.items():
            h = shared[exe] if is_user else io.sha((key+':synthetic:'+exe).encode())
            files[exe] = dict(sha256=h,**meta())
            profile = dict(role=context.ROLES[1 if is_user else 0],exe=exe,exe_sha256=h,
                uid=[1001 if is_user else 0]*4,gid=[1001 if is_user else 0]*4,
                groups=[1001 if is_user else 0],caps={k:0 for k in context.CAPS},nnp=1,
                argv_sha256=io.sha((key+exe).encode()),cgroup=cgroup,initial_env_sha256='2'*64,
                lsm_sha256='3'*64,namespaces=ns,max_instances=count,context_id=key)
            ph = io.sha(io.canonical(profile)); profiles.append(ph)
            binding['actors'].append(dict(profile=profile,justification='Synthetic coexistence slot only; never a production task or TCB approval.'))
            for _ in range(count):
                next_pid += 1; members.append(dict(pid=next_pid,starttime=next_pid+100,profile_sha256=ph))
                mappings[str(next_pid)] = [exe]
        origin = put(dict(schema=io.BYTE_ORIGIN,basis='PUBLISHER',source_evidence_sha256=[source],
                          objects={p:r['sha256'] for p,r in files.items()}))
        for r in files.values(): r['origin_sha256'] = origin
        names = {}
        for path in files:
            parent = Path(path).parent
            while True:
                names[str(parent)] = dict(kind='directory',**meta())
                if str(parent) == '/': break
                parent = parent.parent
        edges = []
        for m in members:
            for kind in ('identity','administration','descriptors','same_uid','mount_idmap'):
                measured = {'synthetic_kind':kind,'synthetic_member':m['pid']}
                evidence = put(dict(schema='TU1NZ_CONTEXT_AUTHORITY_EVIDENCE_V1',measurement=measured,
                    explanation='Synthetic expected measurement only, not actual authority or isolation.'))
                edges.append(dict(kind=kind,member=m['pid'],objects=context.protected_paths(b),
                    source_profile_sha256=m['profile_sha256'],target_profiles=[],actions=context.edge_actions(kind),
                    reserved_targets=context.reserved_templates(b) if kind in ('same_uid','mount_idmap') else [],channels=[],
                    measurement_sha256=io.sha(io.canonical(measured)),evidence_sha256=evidence,
                    effect='POTENTIAL_SUBJECT_AUTHORITY_ACCEPTED_TCB'))
        contexts[key] = dict(id=key,kind='user_session' if is_user else 'container',full_cgroup=cgroup,
            anchor_pid=members[0]['pid'],anchor_starttime=members[0]['starttime'],
            root_identity=dict(device=1,inode=1 if is_user else 100+index,mount_id=1 if is_user else 200+index),
            namespaces=ns,uid_map=['0','0','4294967295'],gid_map=['0','0','4294967295'],setgroups='allow',
            profiles=sorted(profiles),instance_policy=dict(mode='transaction-pinned',members=members),
            authority_edges=edges,code_inputs=dict(files=files,names=names,aliases={},executable_mappings=mappings,
                dynamic_risk='DYNAMIC_MEMORY_NOT_ATTESTED',mountinfo_sha256='7'*64 if is_user else io.sha(key.encode())),
            purpose_evidence_sha256=put({'synthetic_purpose':key,'actual_task_not_accepted':True}),
            review_sha256=put({'synthetic_review':key,'not_independent_production_review':True}))
    binding.update(schema=context.BINDING,contexts=contexts)
    scope['schema'] = context.SCOPE; b['schema'] = context.BASELINE
    acceptance.update(schema=context.ACCEPTANCE,risk=[io.PROSPECTIVE_RISK,context.RISK])
    if change: change(binding,acceptance,b,actual)
    bh = put(binding); acceptance['binding_sha256'] = bh; ah = put(acceptance)
    scope.update(prospective_binding_sha256=bh,prospective_acceptance_sha256=ah)
    for entry in b['files'].values():
        if entry['origin_sha256'] == old_bh: entry['origin_sha256'] = bh
    b['actors'] = [dict(a['profile'],origin_sha256=bh) for a in binding['actors']]
    b['contexts'] = copy.deepcopy(binding['contexts']); b['source_origin_receipts'] = sorted(actual)
    return scope,b,actual


class ContextMaterial(unittest.TestCase):
    def check(self, fixture):
        with patch.object(io.time,'time',return_value=1792923000): return io.prospective_binding(*fixture)

    def test_T01_complete_finite_twenty_four_member_schema(self):
        s,b,a = context_fixture(); used = self.check((s,b,a))
        self.assertGreater(len(used),20); self.assertEqual(len(b['contexts']),13)
        self.assertEqual(sum(len(r['instance_policy']['members']) for r in b['contexts'].values()),24)
        self.assertEqual(len({b['contexts'][c]['code_inputs']['files']['/usr/local/bin/python3.11']['sha256']
                              for c in ('D3','D4','D6')}),3)

    def test_T01_unknown_extra_missing_context_and_schema_downgrade_deny(self):
        cases=[lambda x,y,b,a:x['contexts'].pop('U7'),
               lambda x,y,b,a:x['contexts'].update(D7=copy.deepcopy(x['contexts']['D6'])),
               lambda x,y,b,a:x['contexts']['U4'].update(trusted=True),
               lambda x,y,b,a:y.update(risk=io.PROSPECTIVE_RISK),
               lambda x,y,b,a:x.update(schema=io.PROSPECTIVE_BINDING)]
        for mutate in cases:
            with self.subTest(mutate=mutate),self.assertRaises(io.Hold):self.check(context_fixture(mutate))
        s,b,a = context_fixture(); s['schema'] = io.PROSPECTIVE_SCOPE
        with self.assertRaises(io.Hold):self.check((s,b,a))

    def test_T01_missing_semantic_authority_evidence_never_becomes_safe(self):
        for field in ('purpose_evidence_sha256','review_sha256'):
            def mutate(x,y,b,a):a.pop(x['contexts']['D5'][field])
            with self.subTest(field=field),self.assertRaises(io.Hold):self.check(context_fixture(mutate))
        def wrong(x,y,b,a):x['contexts']['U4']['authority_edges'][0]['measurement_sha256']='f'*64
        with self.assertRaisesRegex(io.Hold,'MEASUREMENT_EVIDENCE'):self.check(context_fixture(wrong))

    def test_T06_missing_action_target_source_or_channel_never_defaults_to_tcb(self):
        for field in ('source_profile_sha256','target_profiles','reserved_targets','actions','channels'):
            def mutate(x,y,b,a):x['contexts']['U5']['authority_edges'][0].pop(field)
            with self.subTest(field=field),self.assertRaises(io.Hold):self.check(context_fixture(mutate))
        def mutate(x,y,b,a):
            e=next(e for e in x['contexts']['U5']['authority_edges'] if e['kind']=='administration')
            e['actions'][0]['unit']='unbound.service'
        with self.assertRaises(io.Hold):self.check(context_fixture(mutate))

    def test_T02_same_host_root_conflicting_user_binary_denies(self):
        def mutate(x,y,b,a):x['contexts']['U7']['root_identity']['inode']=2
        with self.assertRaisesRegex(io.Hold,'USER_ROOT_CONFLICT'):self.check(context_fixture(mutate))

    def test_T03_instance_pool_replacement_duplicate_or_extra_pid_denies(self):
        changes=[lambda r:r['instance_policy'].update(mode='profile-pool'),
                 lambda r:r['instance_policy']['members'].append(dict(r['instance_policy']['members'][0])),
                 lambda r:r['instance_policy']['members'][0].update(starttime=0),
                 lambda r:r['instance_policy']['members'][0].update(profile_sha256='f'*64)]
        for change in changes:
            def mutate(x,y,b,a):change(x['contexts']['U5'])
            with self.subTest(change=change),self.assertRaises(io.Hold):self.check(context_fixture(mutate))

    def test_T07_unbound_code_alias_origin_map_or_metadata_denies(self):
        changes=[lambda r:r['code_inputs']['files'][next(iter(r['code_inputs']['files']))].update(origin_sha256='f'*64),
                 lambda r:r['code_inputs']['files'][next(iter(r['code_inputs']['files']))].update(mode=0o777),
                 lambda r:r['code_inputs']['names'].pop('/'),
                 lambda r:r['code_inputs']['aliases'].update({'/proc/self/exe':next(iter(r['code_inputs']['files']))}),
                 lambda r:r['code_inputs']['executable_mappings'].clear()]
        for change in changes:
            def mutate(x,y,b,a):change(x['contexts']['D3'])
            with self.subTest(change=change),self.assertRaises(io.Hold):self.check(context_fixture(mutate))

    def test_T09_context_module_is_an_authenticated_source_member(self):
        self.assertEqual(client.INFRA_FILES['context'],'scripts/tu1nz_public_operator_context.py')
        self.assertEqual(io.MODULES['context'],'tu1nz_public_operator_context')

    def census(self):
        _,baseline,_ = context_fixture()
        subject = observe.Authority.__new__(observe.Authority); subject.b = baseline
        baseline.update(nginx_groups=[33],broker_sockets=[],broker_tcp=[])
        ctx = context.ContextBindings.__new__(context.ContextBindings)
        ctx.rows = baseline['contexts']; ctx.members = {}; ctx.profiles = {}
        rows = {}; subject.contexts = ctx
        for i,p in enumerate(baseline['actors']):
            profile = {k:v for k,v in p.items() if k != 'origin_sha256'}
            if p['context_id'] == 'HOST':
                pid = i+1; rows[pid] = dict(profile,pid=pid,starttime=str(pid+20),kernel_thread=0,ppid=1)
            else:
                ph = io.sha(io.canonical(profile)); ctx.profiles[ph] = p
        for key,r in ctx.rows.items():
            for m in r['instance_policy']['members']:
                ctx.members[m['pid']] = (key,m)
                p = ctx.profiles[m['profile_sha256']]
                rows[m['pid']] = dict(p,pid=m['pid'],starttime=str(m['starttime']),kernel_thread=0,ppid=1,
                                     uid_map=r['uid_map'],gid_map=r['gid_map'],setgroups=r['setgroups'])
        ctx.lifetimes={pid:Mock() for pid in ctx.members}
        ctx.check_actor = Mock(); ctx.authority_check = Mock()
        subject.targets = {}; subject.rights = set(); subject.runtime_invocations = {}
        subject.operator_pid = 999; subject.operator_start = '1010'
        rows[999] = dict(rows[2],pid=999,starttime='1010')
        subject.deadline = time.monotonic()+10; subject.delegation_check = Mock()
        subject.broker_endpoints = Mock(return_value=([],[]))
        return subject,rows

    def run_census(self, subject, rows):
        def status(path):
            return 'PPid:\t'+('2' if str(path)=='/proc/999/status' else '1')+'\n'
        with patch.object(observe.os,'listdir',return_value=[str(n) for n in rows]), \
             patch.object(observe,'process',side_effect=lambda pid:rows[pid]), patch.object(observe.Path,'read_text',status):
            subject.actors_check(stop_only=False)

    def test_T03_full_synthetic_census_routes_all_old_roles_and_twenty_four_members(self):
        subject,rows = self.census(); self.run_census(subject,rows)
        self.assertEqual(subject.contexts.check_actor.call_count,24)
        subject.delegation_check.assert_called_once()  # unchanged nginx negative gate
        captured = subject.contexts.authority_check.call_args.args[1]
        self.assertEqual(len(captured),29)  # four old roles +24 members +exact operator

    def test_T03_unknown_new_same_image_pid_is_not_replacement(self):
        subject,rows = self.census(); first=next(iter(subject.contexts.members))
        rows[70000] = dict(rows[first],pid=70000)
        with self.assertRaisesRegex(io.Hold,'UNCLASSIFIED_OR_EXTRA_ACTOR'):self.run_census(subject,rows)

    def test_T03_missing_or_reused_pinned_identity_and_exception_collision_deny(self):
        for mode in ('missing','reused','exception'):
            subject,rows = self.census(); first=next(iter(subject.contexts.members))
            if mode=='missing': rows.pop(first)
            elif mode=='reused': rows[first]['starttime']='999999'
            else: subject.targets={'synthetic':(first,rows[first]['starttime'])}
            with self.subTest(mode=mode),self.assertRaises(io.Hold):self.run_census(subject,rows)

    def test_T03_container_may_not_fall_back_to_administrative_host_role(self):
        subject,rows = self.census(); row = dict(rows[3],cgroup=next(iter(subject.contexts.rows.values()))['full_cgroup'])
        self.assertFalse(subject.actor_matches(row,subject.b['actors'][2]))

    def test_T04_member_idmap_drift_denies_before_native_operations(self):
        subject,rows = self.census(); ctx=subject.contexts; del ctx.check_actor
        first=next(iter(ctx.members)); _,member=ctx.members[first]
        ctx.roots={k:Mock() for k in ctx.rows}
        with self.assertRaisesRegex(io.Hold,'NAMESPACE_OR_IDMAP_CHANGED'):
            ctx.check_actor(dict(rows[first],uid_map=['0','1000','1']),ctx.profiles[member['profile_sha256']])

    def test_T05_global_writer_targets_include_every_context_inode(self):
        subject=observe.Authority.__new__(observe.Authority); subject.deadline=time.monotonic()+10
        subject.runtime=SimpleNamespace(files={(1,2)},check=Mock()); subject.initial={'synthetic':(3,4)}
        subject.contexts=SimpleNamespace(files={(5,6)})
        subject.paths=Mock(); subject.b={'unit_search_sha256':'synthetic'}
        for method in ('check_files','policies_check','manager_jobs_clear','units_check','actors_check'):
            setattr(subject,method,Mock())
        subject.probe_check=None; subject.unit_search=lambda:'synthetic'
        subject.authorization_epoch=lambda:contextlib.nullcontext()
        with patch.object(observe,'writer_check') as writer:subject._check()
        writer.assert_called_once_with({(1,2),(3,4),(5,6)},subject.deadline)

    def test_T06_full_positive_authority_comparison_and_unknown_changed_target_deny(self):
        subject,rows=self.census();ctx=subject.contexts;del ctx.authority_check
        key='U5';domain=ctx.rows[key];member=domain['instance_policy']['members'][0];pid=member['pid'];row=rows[pid]
        ctx.members={pid:(key,member)};ctx.baseline=subject.b;ctx.deadline=time.monotonic()+10
        ctx.reserved_witnesses={};ctx.process=lambda p:rows[p];ctx.roots={key:SimpleNamespace(root=7,events_check=Mock())}
        subject._authorization_owner=':1.9';subject.runtime_invocations={}
        subject.actor_matches=lambda r,p:observe.exact_actor(r,p,contextual=True)
        subject.paths=SimpleNamespace(read=lambda p:(b'SYNTHETIC_POLICY',None))
        domain['authority_edges']=[e for e in domain['authority_edges'] if e['member']==pid]
        def targets(predicate):
            return sorted({io.sha(io.canonical({k:v for k,v in p.items() if k!='origin_sha256'}))
                for r in rows.values() if predicate(r) and r['pid']!=subject.operator_pid
                for p in subject.b['actors'] if subject.actor_matches(r,p)})
        same=targets(lambda r:bool(set(row['uid'])&set(r['uid'])))
        mounts=targets(lambda r:r['namespaces']['user']==row['namespaces']['user'] or r['namespaces']['mnt']==row['namespaces']['mnt'])
        identity=context.identity_sample(row,domain);descriptors={'descriptors':[]};effects={'synthetic_tuples':21}
        policy_paths=set(io.PROSPECTIVE_NSS)|{directory+'/'+name for directory,names in subject.b['policy_roots'].items() for name in names}
        facts=dict(identity=identity,descriptors=descriptors,
            administration=dict(policy_sha256={p:io.sha(b'SYNTHETIC_POLICY') for p in sorted(policy_paths)},
                policy_owner=':1.9',broker_paths=[],action_effects=effects,
                interpretation='BOUND_POLICY_POTENTIAL_AUTHORITY_NOT_A_NEGATIVE_DECISION'),
            same_uid=dict(target_profiles=same,reserved_targets=context.reserved_templates(subject.b),source=identity,
                effect='POTENTIAL_MEMORY_FD_SIGNAL_AUTHORITY_NOT_EXCLUDED'),
            mount_idmap=dict(target_profiles=mounts,reserved_targets=context.reserved_templates(subject.b),source=identity,
                effect='POTENTIAL_NAMESPACE_MOUNT_AUTHORITY_NOT_EXCLUDED'))
        for e in domain['authority_edges']:
            e['measurement_sha256']=io.sha(io.canonical(facts[e['kind']]))
            e['target_profiles']=same if e['kind']=='same_uid' else mounts if e['kind']=='mount_idmap' else []
        with patch.object(context,'broker_sample',return_value=[]),patch.object(context,'positive_admin',return_value=effects), \
             patch.object(context,'descriptors_sample',return_value=descriptors):
            ctx.authority_check(subject,rows,Mock())
            next(e for e in domain['authority_edges'] if e['kind']=='same_uid')['target_profiles']=[]
            with self.assertRaisesRegex(io.Hold,'TARGET_DRIFT'):ctx.authority_check(subject,rows,Mock())


class ContextKernelContracts(unittest.TestCase):
    def test_T03_same_pid_tick_profile_cannot_replace_exited_held_lifetime(self):
        poll=Mock();poll.poll.side_effect=[[],[],[(91,select.POLLIN)],[],[]]
        with patch.object(context.os,'pidfd_open',return_value=91,create=True) as opened, \
             patch.object(context.select,'poll',return_value=poll), \
             patch.object(context,'read_proc',return_value=b'Pid:\t23\n'),patch.object(context.os,'close') as close:
            lifetime=context.ProcessLifetime(23,time.monotonic()+10)
            # All user-visible PID/start/profile values could be identical;
            # this kernel lifetime still exited and cannot be replaced.
            with self.assertRaisesRegex(io.Hold,'MEMBER_EXITED'):lifetime.check()
            with self.assertRaisesRegex(io.Hold,'LIFETIME_LOST'):lifetime.check()
            lifetime.close();lifetime.close();opened.assert_called_once_with(23,0)
            close.assert_called_once_with(91)
        self.assertTrue(lifetime.failed)

    def test_T07_bytes_changed_during_watch_setup_are_not_accepted_by_stable_metadata(self):
        obj=context.RootBindings.__new__(context.RootBindings);identity=dict(device=1,inode=2,mount_id=3)
        obj.root=7;obj.dirs={'/':(7,identity)};obj.files={};obj.links={};obj.targets=set()
        obj.deadline=time.monotonic()+10;obj.exec=SimpleNamespace(mark=Mock());obj.events_check=Mock()
        metadata=dict(uid=0,gid=0,mode=0o755,attrs={},flags=0);state=[b'old']
        obj.row={'code_inputs':{'files':{'/code':dict(sha256=io.sha(b'old'),origin_sha256='0'*64,**metadata)},'names':{}}}
        obj.watch=Mock(side_effect=lambda fd,leaf:state.__setitem__(0,b'new') if leaf is None else None)
        stable=SimpleNamespace(st_mode=stat.S_IFREG|0o755,st_nlink=1,st_size=3,st_dev=1,st_ino=2,st_mtime_ns=5,st_ctime_ns=5)
        with patch.object(context,'open_rooted',side_effect=[91,92]),patch.object(context.os,'fstat',return_value=stable), \
             patch.object(context,'fd_identity',return_value=identity),patch.object(context,'file_metadata',return_value=metadata), \
             patch.object(context.os,'pread',side_effect=lambda *args:state[0]),patch.object(context.os,'close'), \
             self.assertRaisesRegex(io.Hold,'CODE_BYTES_DRIFT'):obj.pin('/code')
        self.assertEqual(obj.files,{})

    def test_T06_channels_require_exact_peer_direction_provider_and_effect(self):
        obj=context.ContextBindings.__new__(context.ContextBindings)
        obj.reserved_witnesses={}
        source={'exe':'/usr/bin/bash','role':'coexisting_user_tcb'};peer={'exe':'/usr/bin/tmux','role':'coexisting_user_tcb'}
        sh,ph=io.sha(io.canonical(source)),io.sha(io.canonical(peer))
        sock={'kind':'connected','peer_profile_sha256':ph,'cookie':44,'local':'0100','peer':'0100'}
        channel=dict(fd=5,direction='bound-peer',authority='tmux_command',target_profile_sha256=ph,
                     socket_sha256=io.sha(io.canonical(sock)))
        edge={'source_profile_sha256':sh,'channels':[channel]};descriptors={'descriptors':[dict(fd=5,socket=sock)]}
        obj.channel_check(edge,descriptors,[source,peer])
        for change in ({'target_profile_sha256':sh},{'direction':'bound-listener'},
                       {'socket_sha256':'0'*64},{'authority':'agent_signing'}):
            with self.subTest(change=change),self.assertRaises(io.Hold):
                obj.channel_check(dict(edge,channels=[dict(channel,**change)]),descriptors,[source,peer])
        with self.assertRaises(io.Hold):obj.channel_check(dict(edge,channels=[]),descriptors,[source,peer])

    def test_T06_positive_policy_has_all_twenty_one_named_tuples_and_no_interaction(self):
        auth=SimpleNamespace(_authorization_owner=':1.9',paths=SimpleNamespace(read=lambda p:(b'chatops:x:1001:1001::/:/bin/bash\n',None)))
        row=dict(pid=123,starttime='45',uid=[1001]*4);calls=[]
        def command(argv,deadline):
            calls.append(argv)
            return SimpleNamespace(returncode=0,stderr=b'',stdout=(b'(bba{ss}) true false 0\n' if argv[0].endswith('busctl') else b'Synthetic exact reviewed sudo listing\n'))
        value=context.positive_admin(auth,row,command,deadline=time.monotonic()+10)
        self.assertEqual(len(value['polkit']),21);self.assertEqual(len(calls),22)
        self.assertTrue(all(v['authorized'] for v in value['polkit']))
        self.assertTrue(all('--auto-start=no' in argv and '--allow-interactive-authorization=no' in argv
                            and argv[-2:]==['0',''] for argv in calls[:-1]))
        def challenged(argv,deadline):return SimpleNamespace(returncode=0,stderr=b'',stdout=b'(bba{ss}) false true 0\n')
        with self.assertRaisesRegex(io.Hold,'CHALLENGE'):
            context.positive_admin(auth,row,challenged,deadline=time.monotonic()+10)

    def test_reserved_slots_use_actual_pinned_identity_not_dictionary_key_or_uid(self):
        obj=context.ContextBindings.__new__(context.ContextBindings)
        obj.reserved_witnesses={}
        auth=SimpleNamespace(operator_pid=4,operator_start='5',targets={'unit':(6,'7')},runtime_invocations={'other':('inv',8,'9')})
        for pid,tick,label in ((4,'5','operator'),(6,'7','stop:unit'),(8,'9','runtime:other')):
            self.assertEqual(obj.reserved_target(auth,dict(pid=pid,starttime=tick)),label)
            with self.assertRaises(io.Hold):obj.reserved_target(auth,dict(pid=pid,starttime='99'))
        with self.assertRaises(io.Hold):obj.reserved_target(auth,dict(pid=10,starttime='9'))

    def test_proc_short_reads_continue_to_real_eof_and_bound_sentinel(self):
        with patch.object(context.os,'open',return_value=91),patch.object(context.os,'close') as close, \
             patch.object(context.os,'read',side_effect=[b'first\n',b'later executable mapping\n',b'']) as read:
            self.assertEqual(context.read_proc('/synthetic',64,deadline=time.monotonic()+10),
                             b'first\nlater executable mapping\n')
            self.assertEqual(read.call_count,3);close.assert_called_once_with(91)
        for chunks in ([b'ab',b'c',b''],[b'ab',b'cd']):
            with patch.object(context.os,'open',return_value=91),patch.object(context.os,'close'), \
                 patch.object(context.os,'read',side_effect=chunks), self.assertRaisesRegex(io.Hold,'PROC_BOUND'):
                context.read_proc('/synthetic',2,deadline=time.monotonic()+10)
        with patch.object(context.os,'open',return_value=91),patch.object(context.os,'close'), \
             patch.object(context.os,'read',side_effect=[b'ab',b'']) as read:
            self.assertEqual(context.read_proc('/synthetic',2,deadline=time.monotonic()+10),b'ab')
            self.assertEqual(read.call_args.args,(91,1))  # EOF must be established after exact bound

    def test_proc_deadline_never_resets_on_short_read(self):
        with patch.object(context.os,'open',return_value=91),patch.object(context.os,'close') as close, \
             patch.object(context.os,'read',return_value=b'x') as read, \
             patch.object(context.time,'monotonic',side_effect=[0,1,2,10]),self.assertRaisesRegex(io.Hold,'DEADLINE'):
            context.read_proc('/synthetic',100,deadline=10)
        read.assert_called_once();close.assert_called_once_with(91)

    def test_peer_lifetime_live_exact_and_dead_reused_or_changed_deny(self):
        row=dict(pid=23,starttime='55',uid=[1001]*4,gid=[1001]*4)
        sock=dict(peer_pid=23,peer_uid=1001,peer_gid=1001);profile={'synthetic':'profile'}
        def run(events, fdinfo=b'Pid:\t23\n', actual=None):
            poll=Mock();poll.poll.side_effect=events
            with patch.object(context,'socket_get',return_value=struct.pack('=i',91)), \
                 patch.object(context.select,'poll',return_value=poll),patch.object(context.os,'close') as close, \
                 patch.object(context,'read_proc',return_value=fdinfo):
                try:
                    return context.peer_binding(Mock(),5,sock,{23:row},lambda r,p:True,[profile],
                                                lambda p:row if actual is None else actual,deadline=time.monotonic()+10)
                finally:close.assert_called_once_with(91)
        self.assertEqual(run([[],[]])['peer_starttime'],'55')
        for events,info,actual in (([[(91,1)]],b'Pid:\t23\n',None),
                                   ([[]],b'Pid:\t-1\n',None),([[]],b'Pid:\t24\n',None),
                                   ([[]],b'Pid:\t23\n',dict(row,starttime='999')),
                                   ([[],[(91,1)]],b'Pid:\t23\n',None)):
            with self.subTest(events=events,info=info),self.assertRaises(io.Hold):run(events,info,actual)

    def test_same_namespaces_credentials_fds_but_nonleader_root_denies(self):
        obj=context.ContextBindings.__new__(context.ContextBindings);obj.deadline=time.monotonic()+10
        identity=dict(device=1,inode=2,mount_id=3)
        raw=b'10 (synthetic) '+b' '.join([b'0']*19+[b'555'])
        with patch.object(context.os,'listdir',return_value=['10','11']),patch.object(context,'read_proc',return_value=raw), \
             patch.object(context.os,'open',return_value=91),patch.object(context.os,'close'), \
             patch.object(context,'fd_identity',side_effect=[identity,dict(identity,inode=99)]), \
             self.assertRaisesRegex(io.Hold,'TASK_ROOT_DRIFT'):obj.task_roots(10,identity)

    def mount(self, events):
        poll = Mock(); poll.poll.side_effect = events
        with patch.object(context, 'native'), patch.object(context.os, 'open', return_value=91), \
             patch.object(context.select, 'poll', return_value=poll):
            epoch = context.MountEpoch(12, time.monotonic()+10)
        return epoch, poll

    def test_mount_epoch_armed_before_sample_and_ignores_no_later_events(self):
        epoch, poll = self.mount([[(91, select.POLLPRI)], [], [(91, select.POLLPRI)], []])
        epoch.check()
        with self.assertRaisesRegex(io.Hold, 'MOUNT_EVENT'): epoch.check()
        with self.assertRaisesRegex(io.Hold, 'MOUNT_EPOCH_LOST'): epoch.check()
        self.assertEqual(poll.poll.call_count, 3)  # failed epoch cannot acknowledge/reset again
        with patch.object(context.os, 'close') as close:
            epoch.close(); epoch.close(); close.assert_called_once_with(91)

    def test_unmount_and_return_still_latches_an_event(self):
        epoch, _ = self.mount([[], [(91, select.POLLERR | select.POLLPRI)]])
        # A final topology equal to its initial value is deliberately irrelevant.
        with self.assertRaisesRegex(io.Hold, 'MOUNT_EVENT'): epoch.check()

    def test_mount_epoch_deadline_is_not_extended(self):
        epoch, _ = self.mount([[]]); epoch.deadline = 0
        with self.assertRaisesRegex(io.Hold, 'MOUNT_EPOCH_LOST'): epoch.check()

    def test_rooted_open_requires_all_three_resolution_flags_and_no_fallback(self):
        syscall = Mock(return_value=42)
        with patch.object(context, 'native'), patch.object(context.ctypes, 'CDLL', return_value=SimpleNamespace(syscall=syscall)), \
             patch.object(context.os, 'open') as fallback:
            self.assertEqual(context.open_rooted(3, '/synthetic/code', 0), 42)
            args = syscall.call_args.args
            self.assertEqual(args[:3], (437, 3, b'/synthetic/code'))
            self.assertEqual(args[3]._obj.resolve, 0x16)
            fallback.assert_not_called()

    def test_rooted_open_unknown_syscall_or_permission_is_deny(self):
        with patch.object(context, 'native'), patch.object(context.ctypes, 'CDLL', return_value=SimpleNamespace(syscall=lambda *a:-1)), \
             patch.object(context.ctypes, 'get_errno', return_value=errno.ENOSYS):
            with self.assertRaisesRegex(io.Hold, 'ROOTED_OPEN_UNKNOWN') as raised:
                context.open_rooted(3, '/synthetic/code', 0)
            self.assertEqual(raised.exception.native_errno, errno.ENOSYS)

    def test_path_traversal_and_noncanonical_paths_never_reach_kernel(self):
        for name in ('relative', '/../outside', '/x/../outside', '/a//b', '/a/', '/x\x00', '/a\n'):
            with self.subTest(name=name), self.assertRaises(io.Hold): context.path_name(name)

    @staticmethod
    def event(pid=19, fd=71, pidfd=72, mask=0x1000):
        return struct.pack('=IBBHQiiBBHi', 32, 3, 0, 24, mask, fd, pid, 4, 0, 8, pidfd)

    def exec_epoch(self):
        result = context.ExecEpoch.__new__(context.ExecEpoch)
        result.pids = {19}; result.failed = False
        return result

    def test_same_image_exec_is_rejected_and_every_queued_handle_closed(self):
        epoch = self.exec_epoch()
        with patch.object(context.os, 'close') as close:
            with self.assertRaisesRegex(io.Hold, 'EXEC_EVENT_OR_VIEW_UNKNOWN'):
                epoch.consume(self.event()+self.event(pid=20, fd=73, pidfd=74))
            self.assertEqual({c.args[0] for c in close.call_args_list}, {71,72,73,74})
        self.assertTrue(epoch.failed)

    def test_unrelated_exec_does_not_waive_selected_subject_checks(self):
        epoch = self.exec_epoch()
        with patch.object(context.os, 'close') as close: epoch.consume(self.event(pid=20))
        self.assertFalse(epoch.failed); self.assertEqual(close.call_count, 2)

    def test_exec_overflow_missing_pidfd_or_pid_are_not_negative_proof(self):
        for raw in (self.event(mask=0x4000), self.event(pid=0), self.event(pidfd=-1)):
            with self.subTest(raw=raw), patch.object(context.os, 'close'), self.assertRaises(io.Hold):
                self.exec_epoch().consume(raw)

    def test_bad_exec_abi_denies(self):
        for raw in (b'x', struct.pack('=IBBHQii', 24, 2, 0, 24, 0x1000, -1, 19)):
            with self.subTest(raw=raw), self.assertRaisesRegex(io.Hold, 'EXEC_EVENT_SCHEMA'):
                self.exec_epoch().consume(raw)

    def test_bad_exec_version_still_closes_all_recognized_queued_handles(self):
        raw=bytearray(self.event());raw[4]=2;epoch=self.exec_epoch()
        with patch.object(context.os,'close') as close,self.assertRaisesRegex(io.Hold,'EXEC_EVENT_SCHEMA'):
            epoch.consume(bytes(raw)+self.event(pid=20,fd=73,pidfd=74))
        self.assertTrue(epoch.failed);self.assertEqual({c.args[0] for c in close.call_args_list},{71,72,73,74})

    def test_unix_listener_is_not_misrepresented_as_a_connected_peer(self):
        values={39:struct.pack('=i',socket.AF_UNIX), socket.SO_ACCEPTCONN:struct.pack('=i',1),
                socket.SO_TYPE:struct.pack('=i',socket.SOCK_STREAM),57:struct.pack('=Q',123)}
        with patch.object(context,'socket_get',side_effect=lambda l,f,o,s:values[o]), \
             patch.object(context,'socket_name',return_value='010073796e746865746963') as name:
            row=context.unix_descriptor(Mock(), 5)
        self.assertEqual(row['kind'],'listener'); self.assertIsNone(row['peer_pid'])
        name.assert_called_once_with(unittest.mock.ANY,5)

    def test_unix_connected_peer_credentials_and_addresses_are_exact(self):
        values={39:struct.pack('=i',socket.AF_UNIX), socket.SO_ACCEPTCONN:struct.pack('=i',0),
                socket.SO_TYPE:struct.pack('=i',socket.SOCK_STREAM),57:struct.pack('=Q',124),
                17:struct.pack('=iII',23,1001,1001)}
        with patch.object(context,'socket_get',side_effect=lambda l,f,o,s:values[o]), \
             patch.object(context,'socket_name',side_effect=['0100','01000073796e746865746963']):
            row=context.unix_descriptor(Mock(),5)
        self.assertEqual((row['kind'],row['peer_pid'],row['peer_uid']),('connected',23,1001))
        self.assertEqual(row['peer'],'01000073796e746865746963')


if __name__ == '__main__': unittest.main()
