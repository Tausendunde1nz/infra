"""Pure, reproducible chatops authority and reachable-edge review. No live I/O."""
from collections import deque

SEMANTIC_KINDS = frozenset(('EXEC', 'IMPORT', 'CONFIG', 'PRIVILEGED_WRITE', 'TRIGGER'))


def authority_scope(*, chatops_influence, privileged_effect, independent_contract=False):
    if chatops_influence is False:
        return 'REQUIRED_CONTRACT' if independent_contract else 'SAFE'
    if chatops_influence is True and privileged_effect is True:
        return 'BLOCKER'
    if privileged_effect is False and chatops_influence is True:
        return 'SEPARATE_INTEGRITY_FINDING'
    return 'REVIEW_REQUIRED'


def docker_revocation_complete(member, fresh_session_groups, processes, broker_passthrough):
    """Independent service identities are not descendants merely by having GID 987.

    Caller must provide proven inheritance, not infer it from UID or unit name.
    Unknown provenance of a remaining Docker carrier refuses closure.
    """
    if not isinstance(fresh_session_groups,list) or any(type(g) is not int for g in fresh_session_groups):
        return False
    if member is not False or 987 in fresh_session_groups or broker_passthrough is not False:
        return False
    for p in processes:
        if not isinstance(p.get('groups'),list) or any(type(g) is not int for g in p['groups']):
            return False
        if 987 not in p['groups']:
            continue
        if type(p.get('uid')) is not int or p['uid']==1001 or p.get('origin_uid')==1001:
            return False
        if p.get('inherited_chatops') is not False:
            return False
        if p.get('independent_contract_verified') is not True:
            return False
    return True


def reachable_review(entries, edges, closed_sources):
    """Only semantically proved edges are traversed. Literal matches never prove calls.

    Absence of a proved incoming edge is insufficient for UNREACHABLE_LITERAL:
    all reachable sources must first have a closed resolution contract. A query
    failure or unresolved dynamic reference makes that closure impossible.
    """
    if not entries or len({e['id'] for e in entries})!=len(entries):
        raise ValueError('missing or duplicate entry coverage')
    by_source = {}
    for i, edge in enumerate(edges):
        if edge.get('kind') not in SEMANTIC_KINDS | {'LITERAL_CANDIDATE', 'DYNAMIC'}:
            raise ValueError('unknown edge kind')
        by_source.setdefault(edge['source'], []).append((i, edge))
    pending = deque()
    excluded, findings = [], []
    for e in entries:
        if e.get('query_ok') is not True:
            findings.append({'entry': e['id'], 'reason': 'QUERY_FAILED_OR_UNKNOWN'})
        elif e.get('quarantine_verified') is True:
            excluded.append({'entry': e['id'], 'reason': 'VERIFIED_QUARANTINE'})
        elif e.get('template_without_instance_verified') is True:
            excluded.append({'entry': e['id'], 'reason': 'UNINSTANTIATED_TEMPLATE'})
        elif e.get('root_capable') is True:
            pending.append(e['source'])
        elif e.get('root_capable') is not False:
            findings.append({'entry': e['id'], 'reason': 'UNKNOWN_PRIVILEGE_CONTEXT'})
    reached = set()
    decisions = {}
    while pending:
        source = pending.popleft()
        if source in reached:
            continue
        reached.add(source)
        if closed_sources.get(source) is not True:
            findings.append({'source': source, 'reason': 'SOURCE_RESOLUTION_NOT_CLOSED'})
        for i, e in by_source.get(source, []):
            if e['kind'] == 'LITERAL_CANDIDATE':
                continue
            if e.get('proven') is not True or e['kind'] == 'DYNAMIC':
                findings.append({'edge': i, 'reason': 'REACHABLE_UNKNOWN_EDGE'})
                decisions[i] = 'REVIEW_REQUIRED'
                continue
            decisions[i] = e.get('classification', 'REVIEW_REQUIRED')
            if decisions[i] not in ('SAFE', 'REQUIRED_CONTRACT', 'BLOCKER', 'NOT_PRESENT'):
                findings.append({'edge': i, 'reason': 'UNDECIDED_SEMANTIC_EDGE'})
                decisions[i] = 'REVIEW_REQUIRED'
            if decisions[i] == 'REQUIRED_CONTRACT' and e.get('contract_verified') is not True:
                findings.append({'edge': i, 'reason': 'UNVERIFIED_CONTRACT'})
            if decisions[i] != 'NOT_PRESENT':
                pending.append(e['target'])
    closure = not findings
    for i, e in enumerate(edges):
        if i not in decisions:
            if e['kind'] == 'LITERAL_CANDIDATE':
                decisions[i] = 'UNREACHABLE_LITERAL' if closure else 'UNRESOLVED_LITERAL'
            else:
                decisions[i] = 'UNREACHABLE' if closure else 'UNRESOLVED_REACHABILITY'
    return dict(reached=sorted(reached), excluded=excluded, findings=findings,
                edges=decisions, activation_ready=closure and 'BLOCKER' not in decisions.values())


def rollback_policy(before, security_triggers):
    """Restore non-security state exactly; unsafe trigger bytes stay archived only."""
    import copy
    result = copy.deepcopy(before)
    for name in security_triggers:
        if name not in result['triggers']:
            raise ValueError('unknown trigger')
        result['triggers'][name] = {'enabled': False, 'masked': True, 'running': False}
    return result


def v51_projection(report):
    """Project existing metadata only; never invent executable semantics from literals.

    Unit properties omit some per-command privilege prefixes and install state.
    Unknown privilege context therefore remains explicit, including nonroot units.
    Cron/package/hook roots need their archived source contracts, not new inventory.
    """
    sections={s['section']:s for s in report['sections']}
    rows=sections['systemd-effective']['result']['units']
    entries=[]
    for row in rows:
        name=row['unit']
        if not name.endswith('.service'):
            continue
        p=row.get('properties',{})
        root=p.get('User') in ('','root','0') if 'User' in p else None
        # Nonroot User does not exclude '+' / '!' command prefixes.
        if root is False:root=None
        entries.append(dict(id=name,source=p.get('FragmentPath') or name,
            query_ok=bool(p) and p.get('LoadState')=='loaded',root_capable=root,
            observed_state=p.get('ActiveState'),
            template_without_instance_verified=('@.' in name and
                not any(other['unit'].startswith(name.split('@')[0]+'@') and
                        '@.' not in other['unit'] for other in rows))))
    for source in ('/etc/crontab','/var/spool/cron/crontabs/root','/etc/cron.d',
                   '/etc/logrotate.d','/etc/apt/apt.conf.d','/etc/dpkg',
                   '/etc/network','/etc/init.d','/etc/kernel','/etc/initramfs-tools',
                   '/etc/dbus-1','/etc/polkit-1','/etc/sudoers'):
        entries.append(dict(id=source,source=source,query_ok=True,root_capable=True))
    edges=[]
    for e in report['graph']['edges']:
        if e.get('kind')=='SYSTEMD_QUERY_FAILED':
            if not any(x['id']==e['from'] for x in entries):
                entries.append(dict(id=e['from'],source=e['from'],query_ok=False,root_capable=None))
            continue
        edges.append(dict(source=e['from'],target=e['to'],kind='LITERAL_CANDIDATE'))
    return entries,edges
