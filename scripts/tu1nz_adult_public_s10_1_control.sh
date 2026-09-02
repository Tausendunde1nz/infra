#!/usr/bin/env bash
set -euo pipefail
umask 0027

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly DATABASE_DSN_PATH="/etc/tu1nz/adult-commercial-s7-database.dsn"
readonly TOKEN_PATH="/etc/tu1nz/adult-commercial-s8-telegram.token"
readonly SOURCE_SHA="d3ae2764cc1623bfcc32d2c3f15264ca74fb2e79"
readonly SOURCE_TREE="c9fa052bceb1e7ec3b84a5254d399acde9ff0989"
readonly TARGET_SHA="cdeab77c17c28f4ade46c27975f1c20e74cb8737"
readonly TARGET_TREE="88d8869fbbb9931b16451f7bb1483e1fa6d483df"
readonly EXPECTED_PUBLIC_IP="91.98.112.14"
readonly S10_CONTRACT_SHA="cf0dd7f72b9501fef98a640ee7f48faefa69a6de014c9a21c1c510f827079856"
readonly S10_COPY_SHA="a7a4a79cdd2dd3795d0603d8c9976242403805a0b14557ad17bc2824cb59b24f"
readonly S8_COPY_SHA="28fe75b7ff10d121e59dba30e09b8c90278df706956015fec5b7120b2653a124"
readonly S8_CONTRACT_SHA="cea242a0c749f5e10b15c527248a60a9c429ad7a3f3d655ca0a71e61d7ff6193"
readonly S9_CONTRACT_SHA="274677854b3067cf970f103fc3f541f31e4244df017f9bbcaa0da0c707aa2bf5"
readonly MIGRATION_SHA="6dc77fd37ee65a1d8f67eb47dd75869b265289d007b1b8986a0474dadd449edc"
readonly MIGRATION_DOWN_SHA="6e18a45f9d2a202be268f4636a9d00abc82ed549de3b422551939e06e908311d"
readonly WMS_SERVICE="tu1nz-adult-public-s10-wms.service"
readonly LOCAL_HEALTH_SERVICE="tu1nz-adult-public-s10-local-health.service"
readonly PRE_GROWTH_HEALTH_SERVICE="tu1nz-adult-public-s10-pre-growth-health.service"
readonly LEGACY_PREARM_SERVICE="tu1nz-adult-public-s10-rollback-prearm-health.service"
readonly HEALTH_SERVICE="tu1nz-adult-public-s10-health.service"
readonly HEALTH_TIMER="tu1nz-adult-public-s10-health.timer"
readonly OBSERVER="/usr/local/bin/tu1nz_adult_public_s10_1_observer.py"
readonly LEGACY_PREARM="/usr/local/bin/tu1nz_adult_public_s10_1_s9_prearm.py"
readonly ACTIVATION_STATE="/etc/tu1nz/adult-commercial-s10-wms-activation.json"
readonly S8_SERVICE="tu1nz-adult-public-s8-telegram.service"
readonly S8_LANDING_SERVICE="tu1nz-adult-public-s8-landing.service"
readonly S7_SERVICE="tu1nz-adult-public-s7.service"
readonly S9_SEED_SERVICE="tu1nz-adult-public-s9-seed.service"
readonly S9_HEALTH_TIMER="tu1nz-adult-public-s9-health.timer"
readonly S9_TIMERS=(
  tu1nz-adult-public-s9-audience.timer
  tu1nz-adult-public-s9-nurture.timer
  tu1nz-adult-public-s9-report.timer
)

fail() {
  printf 'S10_1_WMS_CONTROL_RED %s\n' "$1" >&2
  exit 2
}

git_value() {
  runuser -u chatops -- git -C "$1" rev-parse "$2"
}

service_value() {
  systemctl show "$1" -p "$2" --value 2>/dev/null || true
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
}

require_control() {
  [ -d "$CONTROL_ROOT/.git" ] && [ ! -L "$CONTROL_ROOT" ] || fail "CONTROL_PATH_UNSAFE"
  [ -z "$(runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain=v1)" ] || fail "CONTROL_DIRTY"
  [ "$(git_value "$CONTROL_ROOT" HEAD)" = "$1" ] || fail "CONTROL_SHA_MISMATCH"
  [ "$(git_value "$CONTROL_ROOT" 'HEAD^{tree}')" = "$2" ] || fail "CONTROL_TREE_MISMATCH"
}

require_application_clean() {
  [ -d "$APPLICATION_ROOT/.git" ] && [ ! -L "$APPLICATION_ROOT" ] || fail "APPLICATION_PATH_UNSAFE"
  [ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain=v1)" ] || fail "APPLICATION_DIRTY"
}

require_application_source_or_target() {
  case "$(git_value "$APPLICATION_ROOT" HEAD):$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" in
    "$SOURCE_SHA:$SOURCE_TREE"|"$TARGET_SHA:$TARGET_TREE") ;;
    *) fail "APPLICATION_BASELINE_UNEXPECTED" ;;
  esac
}

require_application_target() {
  require_application_clean
  [ "$(git_value "$APPLICATION_ROOT" HEAD)" = "$TARGET_SHA" ] || fail "APPLICATION_SHA_MISMATCH"
  [ "$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$TARGET_TREE" ] || fail "APPLICATION_TREE_MISMATCH"
}

require_service_green() {
  [ "$(service_value "$1" ActiveState)" = "active" ] || fail "$2_NOT_ACTIVE"
  [ "$(service_value "$1" NRestarts)" = "0" ] || fail "$2_RESTARTED"
}

require_adult_runtime_closed() {
  local unit
  for unit in tu1nz-adult-commercial-s0.service tu1nz-adult-commercial-s3.service tu1nz-adult-commercial-s3-s3-1.service tu1nz-adult-commercial-s4.service; do
    case "$(service_value "$unit" ActiveState)" in inactive|failed|"") ;; *) fail "ADULT_RUNTIME_NOT_CLOSED" ;; esac
  done
}

require_credentials_metadata() {
  local path
  for path in "$DATABASE_DSN_PATH" "$TOKEN_PATH"; do
    [ -f "$path" ] && [ ! -L "$path" ] || fail "CREDENTIAL_PATH_UNSAFE"
    [ "$(stat -c '%U:%G' "$path")" = "root:root" ] || fail "CREDENTIAL_OWNER_DRIFT"
    [ "$(stat -c '%a' "$path")" = "600" ] || fail "CREDENTIAL_MODE_DRIFT"
    [ "$(stat -c '%h' "$path")" = "1" ] || fail "CREDENTIAL_LINK_DRIFT"
  done
}

require_base_green() {
  require_service_green "$S7_SERVICE" "S7"
  require_service_green "$S8_SERVICE" "S8"
  require_service_green "$S8_LANDING_SERVICE" "S8_LANDING"
  require_service_green nginx.service "NGINX"
  curl --fail --silent --show-error --max-time 10 https://tu1nz.com/adult/health \
    | /usr/bin/python3 -c 'import json,sys; p=json.load(sys.stdin); expected={"adult_content","payments","real_avs","real_creator_publishing"}; f=p.get("forbidden_capabilities"); valid=p.get("ok") is True and isinstance(f,dict) and set(f)==expected and all(f[k] is False for k in expected); sys.exit(0 if valid else 1)' \
    || fail "LEGACY_PUBLIC_HEALTH_RED"
}

require_s9_restored_green() {
  local runtime_state channels
  require_base_green
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s8-public-telegram.json | awk '{print $1}')" = "$S8_CONTRACT_SHA" ] \
    || fail "ROLLBACK_S8_CONTRACT_DRIFT"
  [ "$(sha256sum /etc/tu1nz/adult-commercial-s9-growth.json | awk '{print $1}')" = "$S9_CONTRACT_SHA" ] \
    || fail "ROLLBACK_S9_CONTRACT_DRIFT"
  runtime_state="$(database_scalar "SELECT (public_sfw_growth_enabled AND audience_seeding_enabled AND telegram_channel_enabled AND NOT x_enabled AND NOT reddit_enabled AND organic_discovery_enabled AND nurture_enabled AND NOT invite_automation_enabled)::int FROM commercial_s9_runtime_control WHERE singleton;")"
  [ "$runtime_state" = "1" ] || fail "ROLLBACK_S9_RUNTIME_BOUNDARY_RED"
  channels="$(database_scalar "SELECT string_agg(platform || '=' || status, ',' ORDER BY platform) FROM commercial_s9_channel_state WHERE platform IN ('telegram_channel','x','reddit');")"
  [ "$channels" = "reddit=DISABLED_FOR_NOW,telegram_channel=AUTOMATED_SUPPORTED,x=DISABLED_FOR_NOW" ] \
    || fail "ROLLBACK_S9_CHANNEL_BOUNDARY_RED"
}

require_paths_unshared() {
  if findmnt -rn -o TARGET,SOURCE,FSTYPE | grep -F "$APPLICATION_ROOT" | grep -qE 'docker|overlay|container'; then
    fail "APPLICATION_PATH_CONTAINER_MOUNTED"
  fi
  if findmnt -rn -o TARGET,SOURCE,FSTYPE | grep -F "$CONTROL_ROOT" | grep -qE 'docker|overlay|container'; then
    fail "CONTROL_PATH_CONTAINER_MOUNTED"
  fi
}

require_source_hashes() {
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s10-1-wms-public.sfw.json" | awk '{print $1}')" = "$S10_CONTRACT_SHA" ] || fail "S10_CONTRACT_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s10-1-wms-copy.v1.json" | awk '{print $1}')" = "$S10_COPY_SHA" ] || fail "S10_COPY_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s8-public-telegram-copy.v1.json" | awk '{print $1}')" = "$S8_COPY_SHA" ] || fail "S8_COPY_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" | awk '{print $1}')" = "$S8_CONTRACT_SHA" ] || fail "S8_CONTRACT_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/config/commercial-s9-growth.sfw.json" | awk '{print $1}')" = "$S9_CONTRACT_SHA" ] || fail "S9_CONTRACT_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0028_commercial_s10_1_wms_public_growth.sql" | awk '{print $1}')" = "$MIGRATION_SHA" ] || fail "MIGRATION_0028_DRIFT"
  [ "$(sha256sum "$APPLICATION_ROOT/migrations/0028_commercial_s10_1_wms_public_growth.down.sql" | awk '{print $1}')" = "$MIGRATION_DOWN_SHA" ] || fail "MIGRATION_0028_DOWN_DRIFT"
}

require_backup() {
  local recorded_sha recorded_tree
  "$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_1_backup.sh" verify-existing "$1" >/dev/null
  [ -f "$1/application.bundle" ] && [ -f "$1/control.bundle" ] || fail "BACKUP_BUNDLES_MISSING"
  [ -f "$1/database-before.dump" ] || fail "BACKUP_DATABASE_MISSING"
  [ -f "$1/public-configuration-before.tar" ] || fail "BACKUP_CONFIGURATION_MISSING"
  [ -f "$1/public-units-before.tar" ] || fail "BACKUP_UNITS_MISSING"
  [ -f "$1/nginx-enabled-before.conf" ] || fail "BACKUP_NGINX_ENABLED_MISSING"
  [ -f "$1/nginx-available-before.conf" ] || fail "BACKUP_NGINX_AVAILABLE_MISSING"
  [ -f "$1/migration-binding-before.txt" ] || fail "BACKUP_MIGRATION_BINDING_MISSING"
  [ -f "$1/s10-migration-binding-before.txt" ] || fail "BACKUP_S10_MIGRATION_BINDING_MISSING"
  [ -f "$1/s10-configuration-before.tar" ] || fail "BACKUP_S10_CONFIGURATION_MISSING"
  [ -f "$1/s10-units-before.tar" ] || fail "BACKUP_S10_UNITS_MISSING"
  [ -f "$1/s10-nginx-state-before.txt" ] || fail "BACKUP_S10_NGINX_STATE_MISSING"
  [ -f "$1/s10-s9-timer-state-before.txt" ] || fail "BACKUP_S9_TIMER_STATE_MISSING"
  [ -f "$1/application-provenance.txt" ] || fail "BACKUP_APPLICATION_PROVENANCE_MISSING"
  recorded_sha="$(sed -n '1p' "$1/application-provenance.txt")"
  recorded_tree="$(sed -n '2p' "$1/application-provenance.txt")"
  [ "$recorded_sha:$recorded_tree" = "$SOURCE_SHA:$SOURCE_TREE" ] \
    || fail "BACKUP_APPLICATION_PROVENANCE_DIVERGED"
}

database_scalar() {
  runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 --dbname="$DATABASE" --command="$1" | tr -d '[:space:]'
}

install_release() {
  runuser -u chatops -- git -C "$APPLICATION_ROOT" fetch --no-tags origin refs/heads/main:refs/remotes/origin/main || fail "CANONICAL_APPLICATION_FETCH_FAILED"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" cat-file -e "${TARGET_SHA}^{commit}" || fail "TARGET_COMMIT_MISSING"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" merge-base --is-ancestor "$TARGET_SHA" origin/main || fail "TARGET_NOT_CANONICAL"
  [ "$(git_value "$APPLICATION_ROOT" "${TARGET_SHA}^{tree}")" = "$TARGET_TREE" ] || fail "TARGET_TREE_MISMATCH"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$TARGET_SHA"
  require_application_clean
  require_source_hashes
}

install_local_configuration() {
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s10-1-wms-public.sfw.json" /etc/tu1nz/adult-commercial-s10-wms.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s10-1-wms-copy.v1.json" /etc/tu1nz/adult-commercial-s10-wms-copy.json
  # The loopback-only WMS process needs only the future public bot identity.
  # Keep this bound copy separate so the live S8 worker retains its current
  # legal contract until activate_public performs the atomic re-consent cutover.
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" /etc/tu1nz/adult-commercial-s10-wms-bot-identity.json
}

install_public_configuration() {
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-copy.v1.json" /etc/tu1nz/adult-commercial-s8-copy.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s8-public-telegram-early-access.sfw.json" /etc/tu1nz/adult-commercial-s8-public-telegram.json
  install -o root -g root -m 0644 "$APPLICATION_ROOT/config/commercial-s9-growth.sfw.json" /etc/tu1nz/adult-commercial-s9-growth.json
}

install_local_units() {
  local unit
  for unit in "$WMS_SERVICE" "$LOCAL_HEALTH_SERVICE" "$PRE_GROWTH_HEALTH_SERVICE" "$LEGACY_PREARM_SERVICE" "$HEALTH_SERVICE" "$HEALTH_TIMER"; do
    install -o root -g root -m 0644 "$CONTROL_ROOT/systemd/$unit" "/etc/systemd/system/$unit"
  done
  install -o root -g root -m 0755 "$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_1_health.py" /usr/local/bin/tu1nz_adult_public_s10_1_health.py
  install -o root -g root -m 0755 "$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_1_observer.py" "$OBSERVER"
  install -o root -g root -m 0755 "$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_1_s9_prearm.py" "$LEGACY_PREARM"
  systemd-analyze verify \
    "/etc/systemd/system/$WMS_SERVICE" \
    "/etc/systemd/system/$LOCAL_HEALTH_SERVICE" \
    "/etc/systemd/system/$PRE_GROWTH_HEALTH_SERVICE" \
    "/etc/systemd/system/$LEGACY_PREARM_SERVICE" \
    "/etc/systemd/system/$HEALTH_SERVICE" \
    "/etc/systemd/system/$HEALTH_TIMER" \
    || fail "SYSTEMD_LOCAL_VERIFY_RED"
}

install_public_drop_ins() {
  local unit dropin
  for unit in tu1nz-adult-public-s9-seed.service tu1nz-adult-public-s9-audience.service tu1nz-adult-public-s9-nurture.service tu1nz-adult-public-s9-report.service; do
    install -d -o root -g root -m 0755 "/etc/systemd/system/$unit.d"
    dropin="$CONTROL_ROOT/systemd/$unit.d/s10-wms.conf"
    install -o root -g root -m 0644 "$dropin" "/etc/systemd/system/$unit.d/s10-wms.conf"
  done
  install -d -o root -g root -m 0755 /etc/systemd/system/tu1nz-adult-public-s8-telegram.service.d
  install -o root -g root -m 0644 \
    "$CONTROL_ROOT/systemd/tu1nz-adult-public-s8-telegram.service.d/s10-wms.conf" \
    /etc/systemd/system/tu1nz-adult-public-s8-telegram.service.d/s10-wms.conf
  systemd-analyze verify \
    "/etc/systemd/system/$WMS_SERVICE" \
    "/etc/systemd/system/$LOCAL_HEALTH_SERVICE" \
    "/etc/systemd/system/$PRE_GROWTH_HEALTH_SERVICE" \
    "/etc/systemd/system/$HEALTH_SERVICE" \
    "/etc/systemd/system/$HEALTH_TIMER" \
    /etc/systemd/system/tu1nz-adult-public-s8-telegram.service \
    /etc/systemd/system/tu1nz-adult-public-s9-seed.service \
    /etc/systemd/system/tu1nz-adult-public-s9-audience.service \
    /etc/systemd/system/tu1nz-adult-public-s9-nurture.service \
    /etc/systemd/system/tu1nz-adult-public-s9-report.service \
    || fail "SYSTEMD_VERIFY_RED"
}

apply_migration() {
  local installed
  installed="$(database_scalar "SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='commercial_s9_nurture_templates' AND column_name='copy_version';")"
  if [ "$installed" = "0" ]; then
    runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$DATABASE" <"$APPLICATION_ROOT/migrations/0028_commercial_s10_1_wms_public_growth.sql" >/dev/null
  elif [ "$installed" != "1" ]; then
    fail "MIGRATION_0028_STATE_DIVERGED"
  fi
}

stop_growth() {
  systemctl disable --now "$S9_HEALTH_TIMER" >/dev/null \
    || fail "S9_HEALTH_TIMER_STOP_RED"
  systemctl disable --now "${S9_TIMERS[@]}" >/dev/null \
    || fail "S9_GROWTH_TIMER_STOP_RED"
  systemctl stop \
    tu1nz-adult-public-s9-audience.service \
    tu1nz-adult-public-s9-nurture.service \
    tu1nz-adult-public-s9-report.service \
    || fail "S9_GROWTH_WORKER_STOP_RED"
}

fail_after_growth_cleanup() {
  local failure="$1"
  stop_growth
  fail "$failure"
}

start_growth() {
  systemctl start "$S9_SEED_SERVICE" || fail "WMS_CONTENT_SEED_RED"
  systemctl enable "${S9_TIMERS[@]}" >/dev/null \
    || fail_after_growth_cleanup "S9_TIMER_ENABLE_RED"
  systemctl start "${S9_TIMERS[@]}" \
    || fail_after_growth_cleanup "S9_TIMER_START_RED"
  systemctl enable "$S9_HEALTH_TIMER" >/dev/null \
    || fail_after_growth_cleanup "S9_HEALTH_TIMER_ENABLE_RED"
  systemctl start "$S9_HEALTH_TIMER" \
    || fail_after_growth_cleanup "S9_HEALTH_TIMER_START_RED"
}

run_health_gate() {
  local unit="$1" failure="$2"
  systemctl start "$unit" || fail "$failure"
  [ "$(service_value "$unit" Result)" = "success" ] || fail "$failure"
  [ "$(service_value "$unit" ExecMainStatus)" = "0" ] || fail "$failure"
}

restore_s9_timer_state() {
  local state_file="$1" unit expected_enabled expected_active actual_enabled actual_active count
  count="$(wc -l <"$state_file" | tr -d '[:space:]')"
  [ "$count" = "4" ] || fail "ROLLBACK_S9_TIMER_STATE_INCOMPLETE"
  [ "$(cut -d'|' -f1 "$state_file" | sort -u | wc -l | tr -d '[:space:]')" = "4" ] \
    || fail "ROLLBACK_S9_TIMER_STATE_DUPLICATED"
  while IFS='|' read -r unit expected_enabled expected_active; do
    case "$unit" in
      tu1nz-adult-public-s9-audience.timer|tu1nz-adult-public-s9-nurture.timer|tu1nz-adult-public-s9-report.timer|tu1nz-adult-public-s9-health.timer) ;;
      *) fail "ROLLBACK_S9_TIMER_STATE_UNIT_UNEXPECTED" ;;
    esac
    case "$expected_enabled" in
      enabled) systemctl enable "$unit" >/dev/null || fail "ROLLBACK_S9_TIMER_ENABLE_RED" ;;
      disabled) systemctl disable "$unit" >/dev/null || fail "ROLLBACK_S9_TIMER_DISABLE_RED" ;;
      *) fail "ROLLBACK_S9_TIMER_ENABLEMENT_UNEXPECTED" ;;
    esac
    case "$expected_active" in
      active) systemctl start "$unit" || fail "ROLLBACK_S9_TIMER_START_RED" ;;
      inactive) systemctl stop "$unit" || fail "ROLLBACK_S9_TIMER_STOP_RED" ;;
      *) fail "ROLLBACK_S9_TIMER_ACTIVITY_UNEXPECTED" ;;
    esac
    actual_enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    actual_active="$(service_value "$unit" ActiveState)"
    [ "$actual_enabled:$actual_active" = "$expected_enabled:$expected_active" ] \
      || fail "ROLLBACK_S9_TIMER_STATE_DIVERGED"
  done <"$state_file"
}

local_health() {
  run_health_gate "$LOCAL_HEALTH_SERVICE" "LOCAL_HEALTH_RED"
}

preflight() {
  require_root
  require_control "$1" "$2"
  require_application_clean
  require_application_source_or_target
  require_adult_runtime_closed
  require_credentials_metadata
  require_paths_unshared
  require_base_green
  [ "$(service_value postgresql.service ActiveState)" = "active" ] || fail "POSTGRES_NOT_ACTIVE"
  printf '{"ok":true,"safe_code":"S10_1_WMS_PREFLIGHT_GREEN","adult_media":false,"avs":false,"payments":false,"publishing":false}\n'
}

install_local() {
  preflight "$1" "$2" >/dev/null
  require_backup "$3"
  case "$(service_value "$WMS_SERVICE" LoadState)" in
    not-found|"") ;;
    *) systemctl stop "$WMS_SERVICE" || fail "WMS_EXISTING_STOP_RED" ;;
  esac
  install_release
  install_local_configuration
  install_local_units
  apply_migration
  systemctl daemon-reload
  systemctl start "$WMS_SERVICE" || fail "WMS_LOCAL_START_RED"
  local_health
  printf '{"ok":true,"safe_code":"S10_1_WMS_LOCAL_INSTALL_GREEN","public_cutover":false,"adult_media":false,"avs":false,"payments":false,"publishing":false}\n'
}

dns_preflight() {
  require_root
  require_control "$1" "$2"
  local host ipv4 ipv6
  for host in wantmeseen.com www.wantmeseen.com wantmeseen.de www.wantmeseen.de; do
    ipv4="$(dig +noall +answer "$host" A | awk '$4 == "A" {print $5}' | sort -u | paste -sd, -)"
    ipv6="$(dig +noall +answer "$host" AAAA | awk '$4 == "AAAA" {print $5}' | sort -u | paste -sd, -)"
    [ "$ipv4" = "$EXPECTED_PUBLIC_IP" ] || fail "DNS_TARGET_MISMATCH_${host//./_}"
    [ -z "$ipv6" ] || fail "DNS_IPV6_NOT_APPROVED_${host//./_}"
  done
  printf '{"ok":true,"safe_code":"S10_1_WMS_DNS_GREEN","target":"%s"}\n' "$EXPECTED_PUBLIC_IP"
}

prepare_acme() {
  dns_preflight "$1" "$2" >/dev/null
  install -d -o root -g root -m 0755 /var/www/letsencrypt
  if [ ! -f /etc/nginx/sites-available/wantmeseen.conf ] \
    || ! grep -Fq '/.well-known/acme-challenge/' /etc/nginx/sites-available/wantmeseen.conf; then
    install -o root -g root -m 0644 "$CONTROL_ROOT/nginx/current/wantmeseen.s10-1-acme.conf" /etc/nginx/sites-available/wantmeseen.conf
  fi
  ln -sfn /etc/nginx/sites-available/wantmeseen.conf /etc/nginx/sites-enabled/wantmeseen.conf
  nginx -t || fail "NGINX_ACME_VERIFY_RED"
  systemctl reload nginx.service || fail "NGINX_ACME_RELOAD_RED"
  printf '{"ok":true,"safe_code":"S10_1_WMS_ACME_READY"}\n'
}

issue_tls() {
  prepare_acme "$1" "$2" >/dev/null
  certbot certonly --non-interactive --agree-tos --no-eff-email \
    --email contact@wantmeseen.com --webroot -w /var/www/letsencrypt \
    -d wantmeseen.com -d www.wantmeseen.com -d wantmeseen.de -d www.wantmeseen.de \
    || fail "TLS_ISSUANCE_RED"
  require_tls_certificate
  nginx -t || fail "NGINX_TLS_VERIFY_RED"
  systemctl reload nginx.service || fail "NGINX_TLS_RELOAD_RED"
  printf '{"ok":true,"safe_code":"S10_1_WMS_TLS_GREEN"}\n'
}

require_tls_certificate() {
  local cert chain fullchain key cert_public key_public host
  cert="/etc/letsencrypt/live/wantmeseen.com/cert.pem"
  chain="/etc/letsencrypt/live/wantmeseen.com/chain.pem"
  fullchain="/etc/letsencrypt/live/wantmeseen.com/fullchain.pem"
  key="/etc/letsencrypt/live/wantmeseen.com/privkey.pem"
  [ -s "$cert" ] && [ -s "$chain" ] && [ -s "$fullchain" ] && [ -s "$key" ] \
    || fail "TLS_CERTIFICATE_MISSING"
  cmp -s "$fullchain" <(cat "$cert" "$chain") || fail "TLS_FULLCHAIN_BINDING_MISMATCH"
  openssl verify -CApath /etc/ssl/certs -untrusted "$chain" "$cert" >/dev/null \
    || fail "TLS_CERTIFICATE_CHAIN_UNTRUSTED"
  openssl x509 -checkend 86400 -noout -in "$cert" >/dev/null || fail "TLS_CERTIFICATE_EXPIRED_OR_EXPIRING"
  for host in wantmeseen.com www.wantmeseen.com wantmeseen.de www.wantmeseen.de; do
    openssl x509 -checkhost "$host" -noout -in "$cert" >/dev/null || fail "TLS_CERTIFICATE_HOSTNAME_MISMATCH"
  done
  cert_public="$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')" \
    || fail "TLS_CERTIFICATE_PUBLIC_KEY_RED"
  key_public="$(openssl pkey -in "$key" -pubout -outform DER | sha256sum | awk '{print $1}')" \
    || fail "TLS_PRIVATE_KEY_RED"
  [ "$cert_public" = "$key_public" ] || fail "TLS_CERTIFICATE_KEY_MISMATCH"
}

write_activation_state() {
  local activation_id activated_at_epoch temporary
  activation_id="$(cat /proc/sys/kernel/random/uuid)"
  activated_at_epoch="$(date -u +%s)"
  temporary="${ACTIVATION_STATE}.tmp"
  unlink "$temporary" 2>/dev/null || true
  /usr/bin/python3 - "$temporary" "$activation_id" "$activated_at_epoch" "$TARGET_SHA" "$TARGET_TREE" "$1" "$2" "$(basename "$3")" <<'PY'
import json
import os
import sys

path, activation_id, activated_at_epoch, application_sha, application_tree, control_sha, control_tree, backup_id = sys.argv[1:]
with open(path, "x", encoding="utf-8") as stream:
    json.dump({
        "activation_id": activation_id,
        "activated_at_epoch": int(activated_at_epoch),
        "application_sha": application_sha,
        "application_tree": application_tree,
        "control_sha": control_sha,
        "control_tree": control_tree,
        "backup_id": backup_id,
    }, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
os.chmod(path, 0o600)
PY
  chown root:root "$temporary"
  mv -f "$temporary" "$ACTIVATION_STATE"
}

activate_public() {
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  require_application_target
  require_source_hashes
  dns_preflight "$1" "$2" >/dev/null
  require_tls_certificate
  local_health
  if ! (
    unlink "$ACTIVATION_STATE" 2>/dev/null || true
    install_public_configuration
    install_public_drop_ins
    install -o root -g root -m 0644 "$CONTROL_ROOT/nginx/current/wantmeseen.s10-1-public.conf" /etc/nginx/sites-available/wantmeseen.conf
    ln -sfn /etc/nginx/sites-available/wantmeseen.conf /etc/nginx/sites-enabled/wantmeseen.conf
    nginx -t || fail "NGINX_PUBLIC_VERIFY_RED"
    stop_growth
    systemctl stop "$S8_SERVICE"
    systemctl daemon-reload
    systemctl start "$S8_SERVICE" || fail "S8_WMS_START_RED"
    systemctl reload nginx.service || fail "NGINX_PUBLIC_RELOAD_RED"
    run_health_gate "$PRE_GROWTH_HEALTH_SERVICE" "WMS_PRE_GROWTH_HEALTH_RED"
    start_growth
    systemctl enable "$WMS_SERVICE" "$HEALTH_TIMER" >/dev/null \
      || fail_after_growth_cleanup "WMS_ENABLE_RED"
    systemctl start "$HEALTH_TIMER" \
      || fail_after_growth_cleanup "WMS_HEALTH_TIMER_START_RED"
    run_health_gate "$HEALTH_SERVICE" "WMS_PUBLIC_HEALTH_RED"
    verify_public "$1" "$2" >/dev/null || fail "WMS_POST_START_VERIFY_RED"
    write_activation_state "$1" "$2" "$3" || fail "ACTIVATION_STATE_WRITE_RED"
  ); then
    rollback "$1" "$2" "$3" >/dev/null
    fail "WMS_PUBLIC_ACTIVATION_ROLLED_BACK"
  fi
  printf '{"ok":true,"safe_code":"S10_1_WMS_PUBLIC_SFW_GREEN","activation_bound":true,"legacy_fallback":"GREEN","x":"DISABLED_FOR_NOW","reddit":"DISABLED_FOR_NOW","adult_media":false,"avs":false,"payments":false,"publishing":false}\n'
}

verify_public() {
  require_root
  require_control "$1" "$2"
  require_application_target
  require_source_hashes
  require_adult_runtime_closed
  require_base_green
  require_service_green "$WMS_SERVICE" "WMS"
  [ "$(systemctl is-enabled "$HEALTH_TIMER" 2>/dev/null || true)" = "enabled" ] || fail "WMS_HEALTH_TIMER_NOT_ENABLED"
  run_health_gate "$HEALTH_SERVICE" "WMS_HEALTH_RED"
  case "$(redirect_state)" in
    "302|https://tu1nz.com/adult/"|"308|https://wantmeseen.com/") ;;
    *) fail "WMS_DE_REDIRECT_RED" ;;
  esac
  printf '{"ok":true,"safe_code":"S10_1_WMS_PUBLIC_SFW_GREEN","legacy_fallback":"GREEN","x":"DISABLED_FOR_NOW","reddit":"DISABLED_FOR_NOW","adult_media":false,"avs":false,"payments":false,"publishing":false}\n'
}

redirect_state() {
  curl --silent --show-error --max-time 10 --output /dev/null \
    --write-out '%{http_code}|%{redirect_url}' https://wantmeseen.de/
}

require_observation_path() {
  local canonical name
  canonical="$(readlink -m -- "$1")"
  [ "$canonical" = "$1" ] || fail "OBSERVATION_PATH_NOT_CANONICAL"
  [ "$(dirname -- "$canonical")" = "/opt/tu1nz_repos/backups" ] \
    || fail "OBSERVATION_PATH_OUTSIDE_BOUNDARY"
  name="$(basename -- "$canonical")"
  case "$name" in
    commercial-s10-1-wms-observation-[0-9]*) ;;
    *) fail "OBSERVATION_PATH_OUTSIDE_BOUNDARY" ;;
  esac
}

require_observation_green() {
  require_observation_path "$1"
  [ -d "$1" ] && [ ! -L "$1" ] || fail "OBSERVATION_PATH_UNSAFE"
  [ -f "$1/result.json" ] && [ ! -e "$1/failure.json" ] || fail "OBSERVATION_NOT_GREEN"
  [ -f "$ACTIVATION_STATE" ] && [ ! -L "$ACTIVATION_STATE" ] || fail "ACTIVATION_STATE_MISSING"
  /usr/bin/python3 - "$1/result.json" "$ACTIVATION_STATE" "$TARGET_SHA" "$TARGET_TREE" "$2" "$3" <<'PY' \
    || fail "OBSERVATION_EVIDENCE_DIVERGED"
import json
import sys

path, activation_path, app_sha, app_tree, control_sha, control_tree = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    value = json.load(stream)
with open(activation_path, encoding="utf-8") as stream:
    activation = json.load(stream)
valid = all((
    value["ok"] is True,
    value["state"] == "GREEN",
    value["safe_code"] == "S10_1_WMS_OBSERVATION_GREEN",
    value["duration_seconds"] >= 7200,
    value["sample_count"] >= 25,
    value["application_sha"] == app_sha,
    value["application_tree"] == app_tree,
    value["control_sha"] == control_sha,
    value["control_tree"] == control_tree,
    activation["application_sha"] == app_sha,
    activation["application_tree"] == app_tree,
    activation["control_sha"] == control_sha,
    activation["control_tree"] == control_tree,
    value["activation_id"] == activation["activation_id"],
    value["started_at_epoch"] >= activation["activated_at_epoch"],
    value["adult_media"] is False,
    value["real_avs"] is False,
    value["payments"] is False,
    value["external_adult_publishing"] is False,
))
raise SystemExit(0 if valid else 2)
PY
}

start_observation() {
  local activation_id activated_at_epoch
  require_root
  verify_public "$1" "$2" >/dev/null
  [ -f "$ACTIVATION_STATE" ] && [ ! -L "$ACTIVATION_STATE" ] || fail "ACTIVATION_STATE_MISSING"
  activation_id="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["activation_id"])' "$ACTIVATION_STATE")"
  activated_at_epoch="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["activated_at_epoch"])' "$ACTIVATION_STATE")"
  [ "$(redirect_state)" = "302|https://tu1nz.com/adult/" ] || fail "DE_REDIRECT_FINALIZED_TOO_EARLY"
  require_observation_path "$3"
  [ ! -e "$3" ] || fail "OBSERVATION_PATH_EXISTS"
  install -d -o root -g root -m 0700 "$3"
  nohup "$OBSERVER" \
    --output "$3" \
    --application-sha "$TARGET_SHA" --application-tree "$TARGET_TREE" \
    --control-sha "$1" --control-tree "$2" \
    --activation-id "$activation_id" --activated-at-epoch "$activated_at_epoch" \
    --duration 7200 --interval 300 \
    >"$3/observer.log" 2>&1 &
  local observer_pid=$!
  printf '%s\n' "$observer_pid" >"$3/observer.pid"
  chmod 0600 "$3/observer.log" "$3/observer.pid"
  printf '{"ok":true,"safe_code":"S10_1_WMS_OBSERVATION_STARTED","pid":%s,"path":"%s"}\n' "$observer_pid" "$3"
}

observation_status() {
  require_root
  require_observation_path "$1"
  [ -d "$1" ] && [ ! -L "$1" ] || fail "OBSERVATION_PATH_UNSAFE"
  if [ -e "$1/failure.json" ]; then
    fail "OBSERVATION_RED"
  fi
  if [ -e "$1/result.json" ]; then
    printf '{"ok":true,"safe_code":"S10_1_WMS_OBSERVATION_COMPLETE"}\n'
    return 0
  fi
  [ -f "$1/observer.pid" ] || fail "OBSERVER_PID_MISSING"
  local observer_pid
  observer_pid="$(cat "$1/observer.pid")"
  kill -0 "$observer_pid" 2>/dev/null || fail "OBSERVER_NOT_RUNNING"
  printf '{"ok":true,"safe_code":"S10_1_WMS_OBSERVATION_RUNNING","pid":%s}\n' "$observer_pid"
}

finalize_de_redirect() {
  require_root
  require_control "$1" "$2"
  require_observation_green "$3" "$1" "$2"
  verify_public "$1" "$2" >/dev/null
  install -o root -g root -m 0644 "$CONTROL_ROOT/nginx/current/wantmeseen.s10-1-final.conf" /etc/nginx/sites-available/wantmeseen.conf
  nginx -t || fail "NGINX_FINAL_VERIFY_RED"
  systemctl reload nginx.service || fail "NGINX_FINAL_RELOAD_RED"
  [ "$(redirect_state)" = "308|https://wantmeseen.com/" ] || fail "WMS_DE_FINAL_REDIRECT_RED"
  printf '{"ok":true,"safe_code":"S10_1_WMS_DE_REDIRECT_FINAL_GREEN","legacy_tu1nz_fallback":"PRESERVED"}\n'
}

rollback() {
  local recorded_sha recorded_tree enabled_target rollback_bundle
  require_root
  require_control "$1" "$2"
  require_backup "$3"
  recorded_sha="$(sed -n '1p' "$3/application-provenance.txt")"
  recorded_tree="$(sed -n '2p' "$3/application-provenance.txt")"
  rollback_bundle="$(mktemp -p "$APPLICATION_ROOT/.git" tu1nz-s10-rollback.XXXXXXXX.bundle)" \
    || fail "ROLLBACK_APPLICATION_BUNDLE_STAGE_RED"
  install -o chatops -g chatops -m 0400 "$3/application.bundle" "$rollback_bundle" \
    || { unlink "$rollback_bundle" 2>/dev/null || true; fail "ROLLBACK_APPLICATION_BUNDLE_STAGE_RED"; }
  if ! runuser -u chatops -- git -C "$APPLICATION_ROOT" bundle verify "$rollback_bundle" >/dev/null; then
    unlink "$rollback_bundle" 2>/dev/null || true
    fail "ROLLBACK_APPLICATION_BUNDLE_VERIFY_RED"
  fi
  if ! runuser -u chatops -- git -C "$APPLICATION_ROOT" bundle unbundle "$rollback_bundle" >/dev/null; then
    unlink "$rollback_bundle" 2>/dev/null || true
    fail "ROLLBACK_APPLICATION_BUNDLE_IMPORT_RED"
  fi
  unlink "$rollback_bundle" || fail "ROLLBACK_APPLICATION_BUNDLE_CLEANUP_RED"
  runuser -u chatops -- git -C "$APPLICATION_ROOT" cat-file -e "${recorded_sha}^{commit}" \
    || fail "ROLLBACK_APPLICATION_COMMIT_MISSING"
  [ "$(git_value "$APPLICATION_ROOT" "${recorded_sha}^{tree}")" = "$recorded_tree" ] \
    || fail "ROLLBACK_APPLICATION_TREE_DIVERGED"
  stop_growth
  systemctl stop "$S8_SERVICE" "$S8_LANDING_SERVICE" "$S7_SERVICE" \
    || fail "ROLLBACK_LEGACY_SERVICE_STOP_RED"
  case "$(service_value "$HEALTH_TIMER" LoadState)" in
    not-found|"") ;;
    *) systemctl disable --now "$HEALTH_TIMER" || fail "ROLLBACK_HEALTH_TIMER_STOP_RED" ;;
  esac
  case "$(service_value "$WMS_SERVICE" LoadState)" in
    not-found|"") ;;
    *) systemctl disable --now "$WMS_SERVICE" || fail "ROLLBACK_WMS_STOP_RED" ;;
  esac
  unlink /etc/nginx/sites-enabled/wantmeseen.conf 2>/dev/null || true
  unlink /etc/nginx/sites-available/wantmeseen.conf 2>/dev/null || true
  unlink "/etc/systemd/system/$WMS_SERVICE" 2>/dev/null || true
  unlink "/etc/systemd/system/$LOCAL_HEALTH_SERVICE" 2>/dev/null || true
  unlink "/etc/systemd/system/$PRE_GROWTH_HEALTH_SERVICE" 2>/dev/null || true
  unlink "/etc/systemd/system/$HEALTH_SERVICE" 2>/dev/null || true
  unlink "/etc/systemd/system/$HEALTH_TIMER" 2>/dev/null || true
  unlink /etc/systemd/system/tu1nz-adult-public-s9-seed.service.d/s10-wms.conf 2>/dev/null || true
  unlink /etc/systemd/system/tu1nz-adult-public-s9-audience.service.d/s10-wms.conf 2>/dev/null || true
  unlink /etc/systemd/system/tu1nz-adult-public-s9-nurture.service.d/s10-wms.conf 2>/dev/null || true
  unlink /etc/systemd/system/tu1nz-adult-public-s9-report.service.d/s10-wms.conf 2>/dev/null || true
  unlink /etc/systemd/system/tu1nz-adult-public-s8-telegram.service.d/s10-wms.conf 2>/dev/null || true
  unlink /etc/tu1nz/adult-commercial-s10-wms.json 2>/dev/null || true
  unlink /etc/tu1nz/adult-commercial-s10-wms-copy.json 2>/dev/null || true
  unlink /etc/tu1nz/adult-commercial-s10-wms-bot-identity.json 2>/dev/null || true
  unlink "$ACTIVATION_STATE" 2>/dev/null || true
  unlink /usr/local/bin/tu1nz_adult_public_s10_1_health.py 2>/dev/null || true
  unlink "$OBSERVER" 2>/dev/null || true
  tar -xpf "$3/public-configuration-before.tar" -C /etc/tu1nz
  tar -xpf "$3/public-units-before.tar" -C /etc/systemd/system
  tar -xpf "$3/s10-configuration-before.tar" -C /etc/tu1nz
  tar -xpf "$3/s10-units-before.tar" -C /etc/systemd/system
  cp --archive "$3/nginx-enabled-before.conf" /etc/nginx/sites-enabled/tu1nz.conf
  cp --archive "$3/nginx-available-before.conf" /etc/nginx/sites-available/tu1nz.conf
  if grep -qx 'available=present' "$3/s10-nginx-state-before.txt"; then
    cp --archive "$3/s10-nginx-available-before.conf" /etc/nginx/sites-available/wantmeseen.conf
  fi
  case "$(sed -n 's/^enabled=//p' "$3/s10-nginx-state-before.txt")" in
    symlink)
      enabled_target="$(cat "$3/s10-nginx-enabled-link-before.txt")"
      case "$enabled_target" in
        /etc/nginx/sites-available/wantmeseen.conf|../sites-available/wantmeseen.conf) ;;
        *) fail "ROLLBACK_NGINX_ENABLED_LINK_UNSAFE" ;;
      esac
      ln -s "$enabled_target" /etc/nginx/sites-enabled/wantmeseen.conf
      ;;
    file)
      cp --archive "$3/s10-nginx-enabled-before.conf" /etc/nginx/sites-enabled/wantmeseen.conf
      ;;
    absent) ;;
    *) fail "ROLLBACK_NGINX_ENABLED_STATE_DIVERGED" ;;
  esac
  runuser -u chatops -- git -C "$APPLICATION_ROOT" switch --detach "$recorded_sha"
  require_application_clean
  systemctl daemon-reload
  nginx -t || fail "ROLLBACK_NGINX_VERIFY_RED"
  systemctl reload nginx.service
  systemctl start "$S7_SERVICE" || fail "ROLLBACK_S7_RED"
  systemctl start "$S8_LANDING_SERVICE" || fail "ROLLBACK_S8_LANDING_RED"
  systemctl start "$S8_SERVICE" || fail "ROLLBACK_S8_RED"
  require_s9_restored_green
  run_health_gate "$LEGACY_PREARM_SERVICE" "ROLLBACK_S9_PREARM_HEALTH_RED"
  unlink "/etc/systemd/system/$LEGACY_PREARM_SERVICE" || fail "ROLLBACK_PREARM_UNIT_CLEANUP_RED"
  unlink "$LEGACY_PREARM" || fail "ROLLBACK_PREARM_SCRIPT_CLEANUP_RED"
  systemctl daemon-reload
  restore_s9_timer_state "$3/s10-s9-timer-state-before.txt"
  if [ "$(awk -F'|' '$2=="enabled" && $3=="active" {count++} END {print count+0}' "$3/s10-s9-timer-state-before.txt")" = "4" ]; then
    systemctl start tu1nz-adult-public-s9-health.service || fail "ROLLBACK_S9_HEALTH_RED"
  fi
  printf '{"ok":true,"safe_code":"S10_1_WMS_ROLLBACK_TO_LEGACY_SFW_GREEN","database_evidence_preserved":true}\n'
}

case "${1:-}" in
  preflight) [ "$#" -eq 3 ] || fail "USAGE"; preflight "$2" "$3" ;;
  install-local) [ "$#" -eq 4 ] || fail "USAGE"; install_local "$2" "$3" "$4" ;;
  dns-preflight) [ "$#" -eq 3 ] || fail "USAGE"; dns_preflight "$2" "$3" ;;
  prepare-acme) [ "$#" -eq 3 ] || fail "USAGE"; prepare_acme "$2" "$3" ;;
  issue-tls) [ "$#" -eq 3 ] || fail "USAGE"; issue_tls "$2" "$3" ;;
  activate-public) [ "$#" -eq 4 ] || fail "USAGE"; activate_public "$2" "$3" "$4" ;;
  verify-public) [ "$#" -eq 3 ] || fail "USAGE"; verify_public "$2" "$3" ;;
  start-observation) [ "$#" -eq 4 ] || fail "USAGE"; start_observation "$2" "$3" "$4" ;;
  observation-status) [ "$#" -eq 2 ] || fail "USAGE"; observation_status "$2" ;;
  finalize-de-redirect) [ "$#" -eq 4 ] || fail "USAGE"; finalize_de_redirect "$2" "$3" "$4" ;;
  rollback) [ "$#" -eq 4 ] || fail "USAGE"; rollback "$2" "$3" "$4" ;;
  *) fail "USAGE" ;;
esac
