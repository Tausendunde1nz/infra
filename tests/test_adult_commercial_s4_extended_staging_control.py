from __future__ import annotations

import hashlib
import json
import py_compile
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s4-extended-staging.json"
CONTROLLER = ROOT / "scripts/tu1nz_adult_commercial_s4_control.sh"
OBSERVER = ROOT / "scripts/tu1nz_adult_commercial_s4_observe.py"
BACKUP = ROOT / "scripts/tu1nz_adult_commercial_s4_backup.sh"
UNIT = ROOT / "systemd/tu1nz-adult-commercial-s4.service"


class CommercialS4ExtendedStagingControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(MANIFEST.read_text(encoding="ascii"))

    def test_release_and_recovery_point_are_exactly_bound(self) -> None:
        self.assertEqual(
            self.value["application"]["sha"],
            "d544a190ffb86ab49fd47e01067ff3750055a0a0",
        )
        self.assertEqual(
            self.value["application"]["tree"],
            "6492a0cc6efcfaca8d8c8fd19e38ccb770f9c85a",
        )
        self.assertEqual(
            self.value["decision"],
            "GO_FOR_BOUNDED_SERVER_STAGING",
        )
        self.assertEqual(
            self.value["backup_and_rollback"]["path"],
            "/opt/tu1nz_repos/backups/commercial-s4-extended-staging/20260829T202700Z-pre-mutation",
        )
        self.assertEqual(
            self.value["backup_and_rollback"]["index_sha256"],
            "34b9d5019db0ad48df8f73bddd77e079eb515659b9e2fabbd0c49ee7753361d7",
        )
        self.assertFalse(self.value["backup_and_rollback"]["server_activation_blocked_until_bound"])
        self.assertEqual(
            self.value["database"]["schema"],
            "0018_commercial_s4_provider_beta_readiness",
        )

    def test_provider_and_product_boundaries_are_closed(self) -> None:
        boundary = self.value["product_boundary"]
        for key in (
            "adult_media_enabled",
            "controlled_beta_enabled",
            "external_publish_enabled",
            "production_enabled",
            "provider_calls_enabled",
            "provider_credentials_present",
            "public_registration",
            "real_money_enabled",
            "telegram_stars_enabled",
        ):
            self.assertFalse(boundary[key])
        self.assertEqual(boundary["avs_provider"], "MOCK")
        self.assertEqual(boundary["payment_provider"], "MOCK")
        self.assertTrue(all(item == "SYNTHETIC" for item in boundary["publishers"].values()))
        self.assertEqual(self.value["provider_readiness"]["avs"]["primary"], "YOTI")
        self.assertEqual(self.value["provider_readiness"]["payment"]["primary"], "SEGPAY")
        gate = self.value["external_risk_gate"]
        self.assertTrue(gate["separate_authorization_required"])
        self.assertEqual(gate["status"], "STOP_REQUIRED")
        self.assertIn("REAL_PROVIDER_CREDENTIALS", gate["blocked_capabilities"])
        self.assertIn("PRODUCTION", gate["blocked_capabilities"])

    def test_two_hour_acceptance_is_exact_and_green(self) -> None:
        acceptance = self.value["acceptance"]
        self.assertEqual(acceptance["status"], "GREEN_TWO_HOUR_BOUNDED_STAGING")
        self.assertEqual(acceptance["sample_count"], 25)
        self.assertEqual(acceptance["health_red_samples"], 0)
        self.assertEqual(acceptance["health_yellow_samples"], 0)
        self.assertEqual(acceptance["restarts_max"], 0)
        self.assertEqual(acceptance["main_pid_changes"], 0)
        self.assertEqual(acceptance["network_other_max"], 0)
        self.assertEqual(acceptance["provider_event_rows"], 0)
        self.assertEqual(
            acceptance["evidence_index_sha256"],
            "3548bc31f478aa7643f339954464814d551904857d408aa549e30bf3d6aa8569",
        )

    def test_runtime_authorization_is_exact_verify_only(self) -> None:
        reference = self.value["runtime_release_authorization"]
        path = ROOT / reference["path"]
        payload = json.loads(path.read_text(encoding="ascii"))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), reference["sha256"])
        self.assertEqual(payload["application_sha"], self.value["application"]["sha"])
        self.assertEqual(payload["application_tree"], self.value["application"]["tree"])
        self.assertEqual(
            payload["bootstrap_reference_sha256"],
            "57c56623b210afaa713accf168ab12a45aa4a48ad5d8a13bfbf38876c5919dd3",
        )
        self.assertEqual(payload["decision"], "GO_FOR_RUNTIME_RELEASE_VERIFY_ONLY")
        self.assertFalse(payload["single_bootstrap_authorized"])
        self.assertFalse(payload["boundaries"]["service_start_authorized"])
        self.assertEqual(
            payload["authorization_version"],
            "tu1nz-commercial-s3-bootstrap-authorization-v1",
        )
        self.assertEqual(payload["boundaries"]["runtime_mode"], "STAGING")
        self.assertEqual(
            set(payload["boundaries"]),
            {
                "adult_media_enabled",
                "avs_provider",
                "external_publish_enabled",
                "payment_provider",
                "production_enabled",
                "publisher_adapter",
                "runtime_mode",
                "service_start_authorized",
            },
        )

    def test_unit_has_static_six_hour_hard_ceiling_without_recovery(self) -> None:
        source = UNIT.read_text(encoding="utf-8")
        self.assertEqual(self.value["service"]["source_path"], UNIT.relative_to(ROOT).as_posix())
        self.assertEqual(
            self.value["service"]["source_sha256"],
            hashlib.sha256(UNIT.read_bytes()).hexdigest(),
        )
        self.assertIn("Restart=no", source)
        self.assertIn("RuntimeMaxSec=21600", source)
        self.assertIsNone(re.search(r"(?m)^\[Install\]$", source))
        self.assertNotIn("Restart=on-failure", source)
        self.assertNotIn("Restart=always", source)

    def test_controller_is_fail_closed_and_has_no_start_capability(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        completed = subprocess.run(
            ["bash", "-n", CONTROLLER],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("GO_FOR_BOUNDED_SERVER_STAGING", source)
        self.assertIn("7200", source)
        self.assertIn("21600", source)
        self.assertIn("require_backup", source)
        self.assertIn("require_stopped", source)
        self.assertIn("require_installed_static_files", source)
        self.assertIn("close-window", source)
        self.assertIn("fresh-prestart", source)
        self.assertIn("await-readiness", source)
        self.assertIn("18_READY", source)
        self.assertIn("EVIDENCE-SHA256SUMS", source)
        self.assertIn("! -name EVIDENCE-SHA256SUMS", source)
        self.assertIn("systemd-run", source)
        fresh = source.split("fresh_prestart() {", 1)[1].split("\n}\n\ncase", 1)[0]
        self.assertIn("IPAddressDeny=any", fresh)
        self.assertIn("IPAddressAllow=localhost", fresh)
        self.assertNotIn("telegram-token", fresh)
        self.assertIn("require_installed_static_files", fresh)
        self.assertNotIn("require_installed_release_files", fresh)
        self.assertNotIn("systemctl start", source)
        self.assertNotIn("systemctl restart", source)
        self.assertNotIn("systemctl enable", source)
        self.assertNotIn("daemon-reload", source)
        self.assertNotIn("git fetch", source)
        self.assertNotIn("git pull", source)
        self.assertNotIn("rm -rf", source)
        self.assertIsNone(re.search(r"[0-9]{7,12}:[A-Za-z0-9_-]{30,}", source))

    def test_observer_is_bounded_and_privacy_safe(self) -> None:
        source = OBSERVER.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            py_compile.compile(
                str(OBSERVER),
                cfile=str(Path(temporary) / "observer.pyc"),
                doraise=True,
            )
        self.assertIn("21600", source)
        self.assertIn("S4_EXTENDED_OBSERVATION_GREEN", source)
        self.assertIn("network_classes", source)
        self.assertIn("database_connections_max", source)
        self.assertIn("health_red_samples", source)
        self.assertNotIn("telegram_response_body", source)
        self.assertNotIn("provider_response_body", source)
        self.assertNotIn("sendMessage", source)
        self.assertNotIn("getUpdates", source)
        self.assertIsNone(re.search(r"[0-9]{7,12}:[A-Za-z0-9_-]{30,}", source))

    def test_backup_is_stopped_bounded_and_strictly_verified(self) -> None:
        source = BACKUP.read_text(encoding="utf-8")
        completed = subprocess.run(
            ["bash", "-n", BACKUP],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("find . -maxdepth 1 -type f -name 'adult-commercial-s3.*' -print0", source)
        self.assertIn("tar --null -T -", source)
        self.assertIn("chmod 0700", source)
        self.assertIn("verify-existing", source)
        self.assertIn("700|2700", source)
        self.assertIn("sha256sum --check --strict", source)
        self.assertIn("bundle verify", source)
        self.assertIn("pg_restore --list", source)
        self.assertNotIn("systemctl start", source)
        self.assertNotIn("systemctl restart", source)
        self.assertNotIn("systemctl enable", source)
        self.assertNotIn("rm -rf", source)


if __name__ == "__main__":
    unittest.main()
