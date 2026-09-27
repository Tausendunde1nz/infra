#!/usr/bin/env python3
"""Strict offline Fail2ban dump comparison; never executes action commands."""
import copy

def validate(original, candidate):
    if not isinstance(original, list) or not isinstance(candidate, list):
        raise ValueError("dump must be a list")
    expected = copy.deepcopy(original)
    matches = [c for c in expected if isinstance(c,list) and c[:4] == ["multi-set","sshd","action","nftables"]]
    if len(matches) != 1 or len(matches[0]) != 5:
        raise ValueError("expected exactly one sshd/nftables action")
    props = matches[0][4]
    for name in ("port", "actionstart", "actionflush"):
        entries = [p for p in props if isinstance(p,list) and p and p[0] == name]
        if len(entries) != 1 or len(entries[0]) != 2:
            raise ValueError("missing or duplicate property: " + name)
        p = entries[0]
        if name == "port":
            if p[1] != "ssh":
                raise ValueError("unexpected original port")
            p[1] = "2222"
        else:
            old = "$(echo 'ssh' | sed s/:/-/g)"
            new = "$(echo '2222' | sed s/:/-/g)"
            if not isinstance(p[1],str) or p[1].count(old) != 1:
                raise ValueError("unexpected original action template")
            p[1] = p[1].replace(old,new)
    if candidate != expected:
        raise ValueError("unexpected command, property, order or port difference")
    return True
