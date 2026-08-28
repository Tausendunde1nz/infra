from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "systemd" / "tu1nz-adult-commercial-s0.service"
REFRESH = ROOT / "scripts" / "tu1nz_adult_commercial_s0_unit_refresh.sh"
M4_24_CONTRACT = ROOT / "manifests" / "adult-publishing-commercial-first-start.m4-24.json"
M4_25_CONTRACT = ROOT / "manifests" / "adult-publishing-commercial-unit-refresh.m4-25.json"


class CommercialS0UnitRefreshTest(unittest.TestCase):
    def test_unit_is_exact_single_start_static_guard(self) -> None:
        source = UNIT.read_text(encoding="ascii")
        lines = source.splitlines()
        self.assertEqual([line for line in lines if line.startswith("Restart=")], ["Restart=no"])
        self.assertEqual(
            [line for line in lines if line.startswith("RuntimeMaxSec=")],
            ["RuntimeMaxSec=180"],
        )
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
            "exactly one Restart directive",
            "exactly one RuntimeMaxSec directive",
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

    def test_executed_evidence_is_stopped_and_hash_bound(self) -> None:
        payload = json.loads(M4_25_CONTRACT.read_text(encoding="ascii"))
        self.assertEqual(payload["decision"], "GO_M4_25_STOPPED_NO_GO_FIRST_START")
        self.assertFalse(payload["active"])
        self.assertFalse(payload["first_start_approved"])
        self.assertFalse(payload["network_enabled"])
        self.assertFalse(payload["external_providers_enabled"])
        self.assertEqual(payload["installed_control_sha"], "3135197ba4ac577bbb7fd28341d0c2dc845a7ebe")
        self.assertEqual(payload["unit_sha256"], "ff631c7722daf4bd1f1fd9f6a61a1008e10b67f7a683603bec834ecad8722e4d")
        self.assertEqual(payload["systemd"]["restart"], "no")
        self.assertEqual(payload["systemd"]["runtime_maximum_seconds"], 180)
        self.assertEqual(payload["systemd"]["active_state"], "inactive")
        self.assertEqual(payload["systemd"]["sub_state"], "dead")
        self.assertEqual(payload["systemd"]["unit_file_state"], "static")
        self.assertEqual(payload["start_evidence"]["n_restarts"], 0)
        self.assertEqual(payload["start_evidence"]["main_pid"], 0)
        self.assertEqual(payload["start_evidence"]["journal_lines"], 0)
        self.assertTrue(payload["backup"]["local_remote_sha256_match"])
        self.assertTrue(payload["backup"]["restore_verified"])
        self.assertTrue(payload["database"]["synthetic_only"])
        self.assertEqual(
            payload["m4_24_contract_sha256"],
            hashlib.sha256(M4_24_CONTRACT.read_bytes()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
