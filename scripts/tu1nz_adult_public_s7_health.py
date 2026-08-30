#!/usr/bin/env python3
"""State-aware, credential-free Commercial S7 loopback health check."""

from __future__ import annotations

import json
import sys
import urllib.request


URL = "http://127.0.0.1:8095/adult/health"


def main() -> int:
    try:
        with urllib.request.urlopen(URL, timeout=5) as response:
            if response.status != 200:
                raise ValueError("HTTP_STATUS")
            payload = json.loads(response.read(16384).decode("utf-8"))
        components = payload.get("components", {})
        forbidden = payload.get("forbidden_capabilities", {})
        if payload.get("ok") is not True:
            raise ValueError("NOT_OK")
        if components.get("LANDING") != "READY" or components.get("WAITLIST") != "READY":
            raise ValueError("PUBLIC_COMPONENT_NOT_READY")
        if components.get("X") != "DISABLED_FOR_NOW" or components.get("REDDIT") != "DISABLED_FOR_NOW":
            raise ValueError("DISABLED_CHANNEL_DRIFT")
        if any(forbidden.values()):
            raise ValueError("FORBIDDEN_CAPABILITY_ENABLED")
    except Exception:
        print('{"ok":false,"safe_code":"S7_PUBLIC_HEALTH_RED"}')
        return 2
    print('{"ok":true,"safe_code":"S7_PUBLIC_HEALTH_GREEN"}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
