from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "systemd" / "tu1nz-adult-commercial-s0.service"
REFRESH = ROOT / "scripts" / "tu1nz_adult_commercial_s0_unit_refresh.sh"
M4_24_CONTRACT = ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-24.json"


class CommercialS0UnitRefreshTest(unittest.TestCase):
    def test_unit_is_exact_single_start_static_guard(self) -> None:
        source = UNIT.read_text(encoding="ascii")
        self.assertEqual(source.count("Restart=no\n"), 1)
        self.assertEqual(source.count("RuntimeMaxSec=180\n"), 1)
        for forbidden in (
            "Restart=on-failure",
            "Restart=always",
            "RestartSec=",
            "OnFailure=",
            "[Install]",
            "WantedBy=",
        ):
            self.assertNotIn(forbidden, source)
        for network_guard in (
            "IPAddressDeny=any",
            "PrivateNetwork=yes",
            "RestrictAddressFamilies=AF_UNIX",
        ):
            self.assertIn(network_guard, source)

    def test_controller_has_separate_guarded_modes(self) -> None:
        source = REFRESH.read_text(encoding="ascii")
        for required in (
            "preflight|restore-test|install|resume-verify|recover-bytecode-resume|verify|rollback",
            "M4_25_STOPPED_UNIT_PREFLIGHT_OK",
            "M4_25_ISOLATED_RESTORE_OK",
            "M4_25_STOPPED_UNIT_REFRESH_OK",
            "M4_25_STOPPED_UNIT_RESUME_VERIFY_OK",
            "M4_25_STOPPED_UNIT_BYTECODE_RECOVERY_OK",
            "M4_25_STOPPED_UNIT_VERIFY_OK",
            "M4_25_STOPPED_UNIT_ROLLBACK_OK",
            "systemctl daemon-reload",
            "another M4.25 transaction is active",
            "Restart=no",
            "RuntimeMaxSec=180",
            "RuntimeMaxUSec",
            "systemd_duration_microseconds",
            "phase=daemon-reloaded",
            "ExecMainStartTimestampMonotonic",
            "ActiveEnterTimestampMonotonic",
            "runtime-status.json",
            "runtime.lock",
            "tu1nz-adult-publishing-s1.service",
            "tu1nz_encrypted_backup.timer",
            "tu1nz_encrypted_backup.service",
            "synthetic database counts changed",
            "commercial schema changed",
            "pg_restore --list",
            "release-manifest.json.before",
            "m4-25-commercial-s0-unit-refresh-input",
            "control-current.before",
            "phase=verified-stopped",
            "rejected-python-bytecode",
            "PYTHONDONTWRITEBYTECODE=1",
        ):
            self.assertIn(required, source)

    def test_controller_never_activates_candidate_or_providers(self) -> None:
        source = REFRESH.read_text(encoding="ascii")
        for forbidden in (
            "systemctl start \"$UNIT\"",
            "systemctl restart \"$UNIT\"",
            "systemctl enable \"$UNIT\"",
            "docker run",
            "curl ",
            "wget ",
            "TELEGRAM_TOKEN",
            "X_TOKEN",
            "REDDIT_TOKEN",
            "PAYMENT_TOKEN",
            "AVS_TOKEN",
            "rm -rf",
            "git clean -fdx",
        ):
            self.assertNotIn(forbidden, source)
        install_body = source.split("install_refresh()", 1)[1].split("rollback_refresh()", 1)[0]
        self.assertNotIn("rollback_refresh", install_body)

    def test_m4_24_historical_contract_remains_no_go(self) -> None:
        source = M4_24_CONTRACT.read_text(encoding="ascii")
        self.assertIn('"active": false', source)
        self.assertIn('"first_start_approved": false', source)
        self.assertIn('"decision": "NO_GO"', source)


if __name__ == "__main__":
    unittest.main()
