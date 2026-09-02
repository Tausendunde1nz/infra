from __future__ import annotations

import json
import hashlib
import importlib.util
import py_compile
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests/adult-publishing-commercial-s10-1-wms-public-activation.json"
CONTROLLER = ROOT / "scripts/tu1nz_adult_public_s10_1_control.sh"
BACKUP = ROOT / "scripts/tu1nz_adult_public_s10_1_backup.sh"
HEALTH = ROOT / "scripts/tu1nz_adult_public_s10_1_health.py"
OBSERVER = ROOT / "scripts/tu1nz_adult_public_s10_1_observer.py"
PUBLIC_NGINX = ROOT / "nginx/current/wantmeseen.s10-1-public.conf"
FINAL_NGINX = ROOT / "nginx/current/wantmeseen.s10-1-final.conf"
ACME_NGINX = ROOT / "nginx/current/wantmeseen.s10-1-acme.conf"
WMS_SERVICE = ROOT / "systemd/tu1nz-adult-public-s10-wms.service"
LOCAL_HEALTH_SERVICE = ROOT / "systemd/tu1nz-adult-public-s10-local-health.service"
PRE_GROWTH_HEALTH_SERVICE = ROOT / "systemd/tu1nz-adult-public-s10-pre-growth-health.service"
LEGACY_PREARM_SERVICE = ROOT / "systemd/tu1nz-adult-public-s10-rollback-prearm-health.service"
HEALTH_SERVICE = ROOT / "systemd/tu1nz-adult-public-s10-health.service"
HEALTH_TIMER = ROOT / "systemd/tu1nz-adult-public-s10-health.timer"
DROP_INS = tuple(sorted((ROOT / "systemd").glob("tu1nz-adult-public-s9-*.service.d/s10-wms.conf")))
S8_DROP_IN = ROOT / "systemd/tu1nz-adult-public-s8-telegram.service.d/s10-wms.conf"
LEGACY_PREARM = ROOT / "scripts/tu1nz_adult_public_s10_1_s9_prearm.py"


class CommercialS101WmsPublicActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_manifest_is_exactly_bound_and_public_sfw_only(self) -> None:
        application = self.value["application"]
        self.assertEqual(application["commit"], "cdeab77c17c28f4ade46c27975f1c20e74cb8737")
        self.assertEqual(application["tree"], "88d8869fbbb9931b16451f7bb1483e1fa6d483df")
        self.assertEqual(application["post_merge_ci"], 33553805658)
        self.assertEqual(
            self.value["deployment"]["source_application_commit"],
            "d3ae2764cc1623bfcc32d2c3f15264ca74fb2e79",
        )
        self.assertEqual(
            self.value["deployment"]["source_application_tree"],
            "c9fa052bceb1e7ec3b84a5254d399acde9ff0989",
        )
        self.assertEqual(self.value["decision"], "GO_PUBLIC_SFW_ACTIVATION_WITH_EXTERNAL_GATES")
        self.assertEqual(self.value["brand"]["public_name"], "Want Me Seen")
        self.assertEqual(self.value["brand"]["primary_domain"], "wantmeseen.com")
        self.assertFalse(self.value["legal"]["adult_publication_legal_clearance"])
        self.assertTrue(self.value["legal"]["legal_final_review_required"])
        self.assertEqual(self.value["growth"]["x"], "X_DISABLED_FOR_NOW")
        self.assertEqual(self.value["growth"]["reddit"], "REDDIT_DISABLED_FOR_NOW")
        self.assertTrue(all(flag is False for flag in self.value["product_boundary"].values()))
        self.assertEqual(
            self.value["files"]["migration_0028_sha256"],
            "6dc77fd37ee65a1d8f67eb47dd75869b265289d007b1b8986a0474dadd449edc",
        )

    def test_telegram_renames_are_deferred_and_rights_minimal(self) -> None:
        telegram = self.value["telegram"]
        self.assertEqual(telegram["expected_bot_id"], 8622690874)
        self.assertFalse(telegram["bot_rename_enabled"])
        self.assertFalse(telegram["channel_rename_enabled"])
        self.assertEqual(telegram["minimum_channel_admin_rights"], ["post_messages"])

    def test_all_deployable_control_material_is_hash_bound(self) -> None:
        hashes = self.value["control_files"]
        expected = {
            BACKUP: hashes["backup_script_sha256"],
            CONTROLLER: hashes["controller_sha256"],
            HEALTH: hashes["health_script_sha256"],
            OBSERVER: hashes["observer_sha256"],
            WMS_SERVICE: hashes["wms_service_sha256"],
            LOCAL_HEALTH_SERVICE: hashes["local_health_service_sha256"],
            PRE_GROWTH_HEALTH_SERVICE: hashes["pre_growth_health_service_sha256"],
            LEGACY_PREARM_SERVICE: hashes["legacy_prearm_service_sha256"],
            HEALTH_SERVICE: hashes["health_service_sha256"],
            HEALTH_TIMER: hashes["health_timer_sha256"],
            S8_DROP_IN: hashes["s8_drop_in_sha256"],
            DROP_INS[0]: hashes["audience_drop_in_sha256"],
            DROP_INS[1]: hashes["nurture_drop_in_sha256"],
            DROP_INS[2]: hashes["report_drop_in_sha256"],
            DROP_INS[3]: hashes["seed_drop_in_sha256"],
            ACME_NGINX: hashes["acme_nginx_sha256"],
            PUBLIC_NGINX: hashes["public_nginx_sha256"],
            FINAL_NGINX: hashes["final_nginx_sha256"],
            LEGACY_PREARM: hashes["legacy_prearm_script_sha256"],
        }
        for path, digest in expected.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_units_and_drop_ins_are_hardened_and_wms_bound(self) -> None:
        self.assertEqual(len(DROP_INS), 4)
        service = WMS_SERVICE.read_text(encoding="utf-8")
        local_health = LOCAL_HEALTH_SERVICE.read_text(encoding="utf-8")
        pre_growth_health = PRE_GROWTH_HEALTH_SERVICE.read_text(encoding="utf-8")
        health = HEALTH_SERVICE.read_text(encoding="utf-8")
        timer = HEALTH_TIMER.read_text(encoding="utf-8")
        legacy_prearm_service = LEGACY_PREARM_SERVICE.read_text(encoding="utf-8")
        for source in (service, local_health, pre_growth_health, legacy_prearm_service, health):
            self.assertIn("NoNewPrivileges=true", source)
            self.assertIn("ProtectSystem=strict", source)
            self.assertIn("MemoryDenyWriteExecute=true", source)
            self.assertNotIn("Environment=", source)
        self.assertIn("IPAddressDeny=any", service)
        self.assertIn("IPAddressAllow=localhost", service)
        self.assertIn(".venv/bin/python -m tu1nz_exposure_s10.runtime", service)
        self.assertIn("--bot-contract /etc/tu1nz/adult-commercial-s10-wms-bot-identity.json", service)
        self.assertNotIn("--bot-contract /etc/tu1nz/adult-commercial-s8-public-telegram.json", service)
        self.assertIn("--local-only", local_health)
        self.assertIn("--pre-growth", pre_growth_health)
        self.assertIn("tu1nz_adult_public_s10_1_s9_prearm.py", legacy_prearm_service)
        self.assertIn("WantedBy=timers.target", timer)
        self.assertIn("Persistent=true", timer)
        combined = "\n".join(path.read_text(encoding="utf-8") for path in DROP_INS)
        self.assertIn("--s10-contract /etc/tu1nz/adult-commercial-s10-wms.json", combined)
        self.assertIn("--s10-copy /etc/tu1nz/adult-commercial-s10-wms-copy.json", combined)
        self.assertIn("--public-origin https://wantmeseen.com", combined)
        self.assertNotIn("api.x.com", combined)
        self.assertNotIn("reddit.com", combined)
        s8_drop_in = S8_DROP_IN.read_text(encoding="utf-8")
        self.assertIn("PYTHONPATH=/opt/tu1nz_repos/adult-publishing-core/src", s8_drop_in)
        self.assertIn("-m tu1nz_public_s8.runtime", s8_drop_in)

    def test_nginx_is_canonical_small_and_reversible(self) -> None:
        public = PUBLIC_NGINX.read_text(encoding="utf-8")
        final = FINAL_NGINX.read_text(encoding="utf-8")
        acme = ACME_NGINX.read_text(encoding="utf-8")
        self.assertIn("server 127.0.0.1:18110", public)
        self.assertIn("server_name wantmeseen.com www.wantmeseen.com", public)
        self.assertIn("server_name wantmeseen.de www.wantmeseen.de", public)
        self.assertIn("return 302 https://tu1nz.com/adult/", public)
        self.assertGreaterEqual(public.count("return 302 https://tu1nz.com/adult/"), 2)
        self.assertIn("return 308 https://wantmeseen.com$request_uri", final)
        self.assertIn("client_max_body_size 32k", public)
        self.assertIn("/.well-known/acme-challenge/", acme)
        self.assertIn("return 302 https://tu1nz.com/adult/", acme)

    def test_health_is_privacy_safe_and_compiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            py_compile.compile(str(HEALTH), cfile=str(Path(temporary) / "health.pyc"), doraise=True)
            py_compile.compile(str(OBSERVER), cfile=str(Path(temporary) / "observer.pyc"), doraise=True)
        source = HEALTH.read_text(encoding="utf-8")
        for expected in (
            "S10_1_WMS_PUBLIC_SFW_GREEN",
            "S10_1_WMS_LOCAL_SFW_GREEN",
            "S10_1_WMS_PRE_GROWTH_SFW_GREEN",
            "S10_PUBLIC_LEGACY_BRAND_LEAK",
            "normalized_page = page.lower()",
            'b"want me seen"',
            'b"exposed on purpose"',
            "S10_PRODUCT_BOUNDARY_RED",
            "S10_GROWTH_BOUNDARY_RED",
            "S9_FORBIDDEN_CAPABILITIES",
            "S9_COMPONENTS",
            "SOURCE_S9_COMPONENTS",
            "S9_RUNTIME_FLAGS",
            "SOURCE_S9_RUNTIME_FLAGS",
            "S9_CHANNELS",
            "SOURCE_S9_CHANNELS",
            "expected_components = SOURCE_S9_COMPONENTS if arguments.local_only else S9_COMPONENTS",
            "expected_runtime = SOURCE_S9_RUNTIME_FLAGS if arguments.local_only else S9_RUNTIME_FLAGS",
            "expected_channels = SOURCE_S9_CHANNELS if arguments.local_only else S9_CHANNELS",
            '"bot_can_post": True',
            '"channel_bound": True',
            "S10_PUBLIC_ROBOTS_RED",
            "S10_PUBLIC_SITEMAP_RED",
            "legal_expectations",
            "expected_locations",
            "contact@wantmeseen.com",
            "health.get(key) is not False",
            "tu1nz-adult-public-s9-health.timer",
        ):
            self.assertIn(expected, source)
        for forbidden in ("message_text", "telegram_user_id", "private_chat_id", "identity_document"):
            self.assertNotIn(forbidden, source)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", source))
        observer = OBSERVER.read_text(encoding="utf-8")
        self.assertIn("S10_1_WMS_OBSERVATION_GREEN", observer)
        self.assertIn("S10_1_OBSERVATION_LEGACY_BOUNDARY_RED", observer)
        self.assertIn("S10_1_OBSERVATION_DE_FALLBACK_RED", observer)
        self.assertIn('redirect != "302|https://tu1nz.com/adult/"', observer)
        self.assertIn("S10_1_OBSERVATION_ACTIVATION_TIME_RED", observer)
        self.assertIn("resolved_output.parent != resolved_parent", observer)
        self.assertIn("next_sample_at += arguments.interval", observer)
        self.assertIn('"real_creator_publishing"', observer)
        self.assertIn('"activation_id": arguments.activation_id', observer)
        self.assertIn('["/usr/sbin/runuser", "-u", "chatops", "--", "/usr/bin/git"', observer)
        self.assertIn('OBSERVATION_PREFIX = "/opt/tu1nz_repos/backups/commercial-s10-1-wms-observation-"', observer)
        self.assertIn('["/usr/bin/systemctl", "start", HEALTH_SERVICE]', observer)
        self.assertNotIn('str(HEALTH)', observer)
        self.assertNotIn("message_text", observer)
        self.assertNotIn("telegram_user_id", observer)

    def test_local_health_accepts_only_the_closed_source_growth_boundary(self) -> None:
        spec = importlib.util.spec_from_file_location("s10_health_regression", HEALTH)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        payload = {
            "ok": True,
            "state": "GREEN",
            "forbidden_capabilities": {
                name: False for name in module.S9_FORBIDDEN_CAPABILITIES
            },
            "components": module.SOURCE_S9_COMPONENTS,
            "runtime": {
                **module.SOURCE_S9_RUNTIME_FLAGS,
                "channels": module.SOURCE_S9_CHANNELS,
                "publication_total": 0,
                "publication_failed": 0,
            },
        }
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(payload), stderr=""
        )
        arguments = SimpleNamespace(
            s9_contract=Path("/source-s9.json"),
            database_dsn=Path("/database.dsn"),
            contract=Path("/s10.json"),
            local_only=True,
        )
        with mock.patch.object(module, "_run", return_value=completed):
            self.assertEqual(
                module._growth(arguments),
                {"application": "GREEN", "telegram": "NOT_PROBED_LOCAL_ONLY"},
            )
        payload["runtime"] = {
            **module.S9_RUNTIME_FLAGS,
            "channels": module.S9_CHANNELS,
            "publication_total": 0,
            "publication_failed": 0,
        }
        completed.stdout = json.dumps(payload)
        with mock.patch.object(module, "_run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "S10_GROWTH_BOUNDARY_RED"):
                module._growth(arguments)

    def test_controller_is_exact_backup_first_bounded_and_reversible(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        completed = subprocess.run(["bash", "-n", CONTROLLER], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for expected in (
            'TARGET_SHA="cdeab77c17c28f4ade46c27975f1c20e74cb8737"',
            'TARGET_TREE="88d8869fbbb9931b16451f7bb1483e1fa6d483df"',
            "require_backup",
            "BACKUP_APPLICATION_PROVENANCE_DIVERGED",
            '"$SOURCE_SHA:$SOURCE_TREE"',
            "require_adult_runtime_closed",
            "require_paths_unshared",
            "require_s9_restored_green",
            "ROLLBACK_S9_RUNTIME_BOUNDARY_RED",
            "ROLLBACK_S9_CHANNEL_BOUNDARY_RED",
            "ROLLBACK_S8_COPY_DRIFT",
            'SOURCE_S8_COPY_SHA="95c4d6f62d4319417a0bac601cd7ee8f4567541fb616220016eec408b5853093"',
            'SOURCE_S8_CONTRACT_SHA="fe20aea4b80206a5eaa79b94d2b74c85d2883240ea68b6d4734618daadac452d"',
            'SOURCE_S9_CONTRACT_SHA="12022dbc0c6dd8c748db91d526b374a690c6bb9f43c7ac89ea525aef7c9b28a0"',
            'MIGRATION_0026_SHA="0b5e4ff8d6073cf4a23ea3136962c43a6dc6cbfadd1066a7b446f0ea488c760f"',
            'MIGRATION_0026_DOWN_SHA="35cb7182bcaa038bc47fd3b1246d8616fd31f446540de9ace5202825ad241ef4"',
            'MIGRATION_0027_SHA="148753478cfd57a0e9e0e7235849d83dd0587e054a96a85d411eac5c7ac7b9ab"',
            'MIGRATION_0027_DOWN_SHA="2d72e8fb5de5b7cd9e1824cfcb465b59d815a69394e4340277435ae245b7241e"',
            "activate_s9_public_channel_database",
            "restore_s9_public_channel_database",
            "run_bound_target_migration",
            "BOUND_MIGRATION_HASH_DIVERGED",
            "S9_TELEGRAM_CHANNEL_MIGRATION_RED",
            "S9_PUBLICATION_GRANT_RED",
            "S9_PUBLICATION_GRANT_DIVERGED",
            "ROLLBACK_S9_PUBLICATION_GRANT_RED",
            "ROLLBACK_S9_PUBLICATION_GRANT_DIVERGED",
            "CASE privilege_count WHEN 0 THEN 'source' WHEN 5 THEN 'target' ELSE 'diverged' END",
            "ROLLBACK_S9_PREARM_HEALTH_RED",
            "ROLLBACK_S9_TIMER_ENABLE_RED",
            "ROLLBACK_S9_TIMER_STATE_DIVERGED",
            "restore_s9_timer_state",
            "configure_bot_profile",
            "WMS_TELEGRAM_PROFILE_CONFIGURATION_RED",
            "ROLLBACK_TELEGRAM_PROFILE_CONFIGURATION_RED",
            "--configure-only",
            "wait_http_ready",
            "WMS_LOCAL_READINESS_RED",
            "ROLLBACK_S7_READINESS_RED",
            'systemctl disable --now "${S9_TIMERS[@]}"',
            "S9_HEALTH_TIMER_STOP_RED",
            "S9_GROWTH_TIMER_STOP_RED",
            "S9_GROWTH_WORKER_STOP_RED",
            "fail_after_growth_cleanup",
            "WMS_POST_START_VERIFY_RED",
            "ACTIVATION_STATE_WRITE_RED",
            "WMS_PUBLIC_ACTIVATION_ROLLED_BACK",
            "/usr/bin/python3",
            'set(f)==expected and all(f[k] is False for k in expected)',
            "0028_commercial_s10_1_wms_public_growth.sql",
            "systemd-analyze verify",
            "dns-preflight",
            "issue-tls",
            "activate-public",
            "require_application_target",
            "WMS_EXISTING_STOP_RED",
            "dig +noall +answer",
            '$4 == "A"',
            '$4 == "AAAA"',
            "DNS_IPV6_NOT_APPROVED",
            "require_tls_certificate",
            "TLS_FULLCHAIN_BINDING_MISMATCH",
            'cmp -s "$fullchain" <(cat "$cert" "$chain")',
            "openssl verify -CApath /etc/ssl/certs -untrusted",
            "TLS_CERTIFICATE_CHAIN_UNTRUSTED",
            "openssl x509 -checkend 86400",
            "openssl x509 -checkhost",
            "TLS_CERTIFICATE_KEY_MISMATCH",
            "ACTIVATION_STATE",
            "write_activation_state",
            "require_observation_path",
            "readlink -m --",
            '$(dirname -- "$canonical")" = "/opt/tu1nz_repos/backups"',
            "OBSERVATION_PATH_NOT_CANONICAL",
            'value["activation_id"] == activation["activation_id"]',
            'value["started_at_epoch"] >= activation["activated_at_epoch"]',
            "verify-public",
            "start-observation",
            "observation-status",
            "finalize-de-redirect",
            "duration_seconds",
            "rollback",
            "ROLLBACK_APPLICATION_BUNDLE_STAGE_RED",
            "ROLLBACK_APPLICATION_BUNDLE_VERIFY_RED",
            "ROLLBACK_APPLICATION_BUNDLE_IMPORT_RED",
            "ROLLBACK_APPLICATION_BUNDLE_CLEANUP_RED",
            'bundle unbundle "$rollback_bundle"',
            "ROLLBACK_APPLICATION_TREE_DIVERGED",
            "ROLLBACK_LEGACY_SERVICE_STOP_RED",
            "ROLLBACK_HEALTH_TIMER_STOP_RED",
            "ROLLBACK_WMS_STOP_RED",
            'systemctl stop "$S8_SERVICE" "$S8_LANDING_SERVICE" "$S7_SERVICE"',
            'systemctl start "$S7_SERVICE"',
            'systemctl start "$S8_LANDING_SERVICE"',
            "S10_1_WMS_ROLLBACK_TO_LEGACY_SFW_GREEN",
        ):
            self.assertIn(expected, source)
        install_local = source.split("install_local() {", 1)[1].split("dns_preflight() {", 1)[0]
        self.assertLess(install_local.index("require_backup \"$3\""), install_local.index("install_release"))
        self.assertNotIn('systemctl stop "$WMS_SERVICE" >/dev/null 2>&1 || true', install_local)
        self.assertLess(
            install_local.index('systemctl start "$WMS_SERVICE"'),
            install_local.index('wait_http_ready "http://127.0.0.1:18110/health"'),
        )
        self.assertLess(
            install_local.index('wait_http_ready "http://127.0.0.1:18110/health"'),
            install_local.index("local_health"),
        )
        local_configuration = source.split("install_local_configuration() {", 1)[1].split("install_public_configuration() {", 1)[0]
        self.assertIn('/etc/tu1nz/adult-commercial-s10-wms-bot-identity.json', local_configuration)
        self.assertIn('commercial-s8-public-telegram-early-access.sfw.json', local_configuration)
        for forbidden_local_action in (
            "stop_growth",
            'systemctl stop "$S8_SERVICE"',
            "install_public_configuration",
            "install_public_drop_ins",
        ):
            self.assertNotIn(forbidden_local_action, install_local)
        activate_public = source.split("activate_public() {", 1)[1].split("verify_public() {", 1)[0]
        post_growth = activate_public.split("start_growth", 1)[1]
        self.assertGreaterEqual(post_growth.count("fail_after_growth_cleanup"), 2)
        self.assertIn('rollback "$1" "$2" "$3" >/dev/null', activate_public)
        self.assertLess(activate_public.index('run_health_gate "$PRE_GROWTH_HEALTH_SERVICE"'), activate_public.index('rollback "$1" "$2" "$3"'))
        stop_growth = source.split("stop_growth() {", 1)[1].split("start_growth() {", 1)[0]
        self.assertNotIn("|| true", stop_growth)
        self.assertLess(activate_public.index('systemctl reload nginx.service'), activate_public.index('run_health_gate "$PRE_GROWTH_HEALTH_SERVICE"'))
        self.assertLess(activate_public.index("stop_growth"), activate_public.index("activate_s9_public_channel_database"))
        self.assertLess(activate_public.index("activate_s9_public_channel_database"), activate_public.index('systemctl stop "$S8_SERVICE"'))
        self.assertLess(activate_public.index('systemctl stop "$S8_SERVICE"'), activate_public.index('configure_bot_profile "WMS_TELEGRAM_PROFILE_CONFIGURATION_RED"'))
        self.assertLess(activate_public.index('configure_bot_profile "WMS_TELEGRAM_PROFILE_CONFIGURATION_RED"'), activate_public.index('systemctl start "$S8_SERVICE"'))
        self.assertLess(activate_public.index('run_health_gate "$PRE_GROWTH_HEALTH_SERVICE"'), activate_public.index("start_growth"))
        rollback = source.split("rollback() {", 1)[1].split('case "${1:-}"', 1)[0]
        restored = source.split("require_s9_restored_green() {", 1)[1].split("require_paths_unshared() {", 1)[0]
        self.assertIn('$SOURCE_S8_CONTRACT_SHA', restored)
        self.assertIn('$SOURCE_S8_COPY_SHA', restored)
        self.assertIn('$SOURCE_S9_CONTRACT_SHA', restored)
        self.assertNotIn('= "$S8_CONTRACT_SHA"', restored)
        self.assertNotIn('= "$S9_CONTRACT_SHA"', restored)
        self.assertIn('install -o chatops -g chatops -m 0400 "$3/application.bundle" "$rollback_bundle"', rollback)
        self.assertLess(rollback.index('bundle unbundle "$rollback_bundle"'), rollback.index("stop_growth"))
        self.assertLess(rollback.index('unlink "$rollback_bundle" || fail'), rollback.index("stop_growth"))
        self.assertLess(rollback.index("ROLLBACK_APPLICATION_TREE_DIVERGED"), rollback.index("stop_growth"))
        self.assertLess(rollback.index("stop_growth"), rollback.index("restore_s9_public_channel_database"))
        self.assertLess(rollback.index("restore_s9_public_channel_database"), rollback.index('systemctl stop "$S8_SERVICE"'))
        migration_runner = source.split("run_bound_target_migration() {", 1)[1].split("activate_s9_public_channel_database() {", 1)[0]
        self.assertIn('git -C "$APPLICATION_ROOT" show "${TARGET_SHA}:$path"', migration_runner)
        self.assertIn('actual_hash=', migration_runner)
        self.assertIn('sha256sum', migration_runner)
        self.assertIn('"${TARGET_SHA}^{tree}"', migration_runner)
        self.assertNotIn('<"$APPLICATION_ROOT/migrations/', rollback)
        self.assertNotIn('systemctl stop "$S8_SERVICE" "$S8_LANDING_SERVICE" "$S7_SERVICE" >/dev/null 2>&1 || true', rollback)
        self.assertLess(rollback.index("require_s9_restored_green"), rollback.index("restore_s9_timer_state"))
        self.assertLess(rollback.index('run_health_gate "$LEGACY_PREARM_SERVICE"'), rollback.index("restore_s9_timer_state"))
        self.assertNotIn('systemctl enable --now "${S9_TIMERS[@]}"', rollback)
        self.assertLess(
            rollback.index('systemctl start "$S7_SERVICE"'),
            rollback.index('wait_http_ready "http://127.0.0.1:8095/adult/health"'),
        )
        self.assertLess(
            rollback.index('wait_http_ready "http://127.0.0.1:8095/adult/health"'),
            rollback.index("require_s9_restored_green"),
        )
        self.assertLess(
            rollback.index('configure_bot_profile "ROLLBACK_TELEGRAM_PROFILE_CONFIGURATION_RED"'),
            rollback.index('systemctl start "$S8_SERVICE"'),
        )
        for forbidden in ("rm -rf", "git reset", "git clean", "systemctl restart", "api.x.com", "reddit.com"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn('$APPLICATION_ROOT/.venv/bin/python', source)
        self.assertNotIn("assert ", source)
        self.assertIsNone(re.search(r"[0-9]{7,16}:[A-Za-z0-9_-]{30,}", source))

    def test_backup_captures_complete_s10_rollback_surface(self) -> None:
        source = BACKUP.read_text(encoding="utf-8")
        for expected in (
            "0026_commercial_s9_telegram_channel",
            "0027_commercial_s9_publication_completion",
            "0028_commercial_s10_1_wms_public_growth",
            "BACKUP_PATH_NOT_CANONICAL",
            "S10_CHECKSUM_INDEX_INCOMPLETE",
            "expected=\"./$indexed\"",
            "readlink -m --",
            "adult-commercial-s10-wms*.json",
            "tu1nz-adult-public-s10*",
            "tu1nz-adult-public-s8-telegram.service.d/s10-wms.conf",
            "s10-nginx-enabled-before.conf",
            "s10-nginx-enabled-link-before.txt",
            "enabled=symlink",
            "readlink /etc/nginx/sites-enabled/wantmeseen.conf",
            "s10-nginx-available-before.conf",
            "s10-s9-timer-state-before.txt",
            "S10_S9_TIMER_STATE_INCOMPLETE",
        ):
            self.assertIn(expected, source)


if __name__ == "__main__":
    unittest.main()
