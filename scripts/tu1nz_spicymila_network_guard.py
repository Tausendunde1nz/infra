"""Pure network-coverage guard. No Docker commands, file writes or activation CLI.

Matching network names is necessary, not sufficient for lossless endpoint recreation.
Aliases, IPAM, routing and other endpoint properties still need independent validation.
"""
NAME = 'spicymila_bot'


class Refuse(RuntimeError):
    pass


def require_compose_network_coverage(resolved, baseline):
    try:
        service_networks = resolved['services'][NAME]['networks']
        actual = set(baseline['NetworkSettings']['Networks'])
        declared = set()
        for key in service_networks:
            network = resolved.get('networks', {}).get(key, {})
            name = network.get('name')
            if not isinstance(name, str) or not name:
                raise Refuse('unresolved Compose network name')
            declared.add(name)
        if not declared or declared != actual:
            raise Refuse('out-of-Compose network attachment; recreation blocked')
    except (KeyError, TypeError, AttributeError):
        raise Refuse('malformed network inventory; recreation blocked') from None
