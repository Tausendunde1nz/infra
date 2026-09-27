"""Offline policy gates only. No subprocess, filesystem mutation or live adapter."""
from copy import deepcopy

CATEGORIES = frozenset(('SAFE', 'BLOCKER', 'REQUIRED_CONTRACT', 'NOT_PRESENT', 'REVIEW_REQUIRED'))

class Refused(ValueError):
    pass

def classify_container(facts):
    """UID 0 by itself is not evidence of host authority. Unknowns stay unknown."""
    dangerous = ('docker_socket', 'host_root_mount', 'privileged', 'host_code_consumer')
    if any(facts.get(key) is True for key in dangerous):
        return 'BLOCKER'
    required = dangerous + ('namespaces_reviewed', 'capabilities_reviewed',
                             'mounts_reviewed', 'devices_reviewed')
    if any(type(facts.get(key)) is not bool for key in required):
        return 'REVIEW_REQUIRED'
    if not all(facts[key] for key in required[4:]):
        return 'REVIEW_REQUIRED'
    return 'REQUIRED_CONTRACT' if facts.get('container_uid') == 0 else 'SAFE'

def compose_gate(facts):
    # Missing paths are not safe when an untrusted parent permits recreation.
    if facts.get('root_execution') and (facts.get('user_writable_ancestor') or
                                        facts.get('implicit_lookup')):
        return 'BLOCKER'
    if any(facts.get(k) is not True for k in ('explicit_config', 'root_owned_chain',
            'env_bound', 'image_bound', 'endpoint_bound', 'source_hash_matches')):
        return 'REVIEW_REQUIRED'
    return 'SAFE'

def readiness(edges, contracts):
    if not edges:
        raise Refused('empty graph')
    ids = set()
    for edge in edges:
        if edge.get('id') in ids or not edge.get('id'):
            raise Refused('missing/duplicate edge')
        ids.add(edge['id'])
        category = edge.get('classification')
        if category not in CATEGORIES or category in ('BLOCKER', 'REVIEW_REQUIRED'):
            raise Refused('unresolved graph')
        if category == 'REQUIRED_CONTRACT' and contracts.get(edge['id']) is not True:
            raise Refused('unproved contract')
    return True

def restart_gate(service, evidence):
    if evidence.get('identity_bound') is not True:
        raise Refused('identity drift')
    if service == 'mychatbuddy-private-alpha.service':
        for key in ('poller_quiescent', 'lease_expired', 'no_delivery_ambiguity',
                    'no_external_action', 'governance_preserved'):
            if evidence.get(key) is not True:
                raise Refused('MyChatBuddy pause/resume unproved: ' + key)
    if service == 'tu1nz_agentmode.service':
        for key in ('single_instance', 'control_unchanged', 'state_preserved',
                    'no_duplicate_sync', 'no_duplicate_notification'):
            if evidence.get(key) is not True:
                raise Refused('Agentmode pause/resume unproved: ' + key)
    return True

class CampaignModel:
    """Pure in-memory failure model; NOT an installer or watchdog implementation.

    Each exact snapshot includes opaque unit/config/ACL/group/endpoint state.
    A real adapter must independently verify restoration before using this model.
    """
    def __init__(self, state, edges, contracts):
        readiness(edges, contracts)
        self.initial = deepcopy(state)
        self.state = deepcopy(state)
        self.next_phase = 0
        self.checkpoints = []
        self.locked = False
        self.failed = False

    def start(self):
        if self.locked:
            raise Refused('concurrent campaign')
        self.locked = True

    def step(self, phase, expected, candidate, validate, fail_at=None):
        if not self.locked or self.failed or phase != self.next_phase or phase not in range(6):
            raise Refused('invalid phase transition')
        if self.state != expected:
            self.failed = True
            raise Refused('drift before activation')
        before = deepcopy(self.state)
        try:
            if fail_at == 'before':
                raise Refused('injected pre-apply failure')
            self.state = deepcopy(candidate)
            if fail_at == 'after' or validate(deepcopy(self.state)) is not True:
                raise Refused('validation failure')
            self.checkpoints.append((phase, before, deepcopy(self.state)))
            self.next_phase += 1
        except Exception:
            self.state = before
            self.failed = True
            raise

    def acknowledge_verified_rollback(self, exact_state):
        if not self.failed or self.state != exact_state:
            raise Refused('rollback mismatch')
        self.failed = False

    def total_rollback(self):
        self.state = deepcopy(self.initial)
        self.next_phase = 0
        self.failed = False
        self.checkpoints = []
        self.locked = False
        return deepcopy(self.state)

    def ssh_disconnect(self):
        # Models independence; no actual systemd implementation is claimed.
        return self.next_phase

    def complete(self, docker_gid_carriers):
        if self.next_phase != 6 or self.failed or docker_gid_carriers:
            raise Refused('incomplete campaign or residual Docker authority')
        return True
