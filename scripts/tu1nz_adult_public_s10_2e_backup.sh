#!/usr/bin/env bash
set -euo pipefail
umask 0007

readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly BASE_BACKUP="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_1_backup.sh"
readonly EVIDENCE_TOOL="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_2e_evidence.py"
readonly AGGREGATE_PATH="/var/lib/tu1nz-adult-public-s9/landing-aggregates.json"
readonly BACKUP_PREFIX="/opt/tu1nz_repos/backups/commercial-s8-public-telegram/"
readonly SNAPSHOT_NAME="s10-2e-acquisition-baseline.json"
readonly HEALTH_NAME="s10-2e-public-health-before.json"
readonly AGGREGATE_HASH_NAME="s10-2e-aggregate-before.sha256"

fail() {
  printf 'S10_2E_BACKUP_RED %s\n' "$1" >&2
  exit 2
}

require_boundary() {
  local canonical
  canonical="$(readlink -m -- "$1")"
  [ "$canonical" = "$1" ] || fail "BACKUP_PATH_NOT_CANONICAL"
  case "$canonical" in
    "${BACKUP_PREFIX}"[0-9]*-pre-s10-2d-community) ;;
    *) fail "BACKUP_PATH_OUTSIDE_BOUNDARY" ;;
  esac
}

database_snapshot() {
  runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --dbname="$DATABASE" --command="SELECT json_build_object(
      'schema_version',1,
      'collected_at',to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
      'state',json_build_object(
        'pre_acquisition_readiness',c.pre_acquisition_readiness,
        'real_acquisition_active',c.wms_real_acquisition_ready,
        'real_acquisition_baseline_start',CASE WHEN c.real_acquisition_baseline_start IS NULL THEN NULL ELSE to_char(c.real_acquisition_baseline_start AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END,
        'community_enabled',c.community_enabled,
        'community_posting_enabled',c.community_posting_enabled,
        'community_media_publishing_enabled',c.community_media_publishing_enabled,
        'community_automod_enabled',c.community_automod_enabled,
        'community_welcome_enabled',c.community_welcome_enabled,
        'controlled_beta',s9.controlled_beta,
        'public_sfw_growth_enabled',s9.public_sfw_growth_enabled,
        'audience_seeding_enabled',s9.audience_seeding_enabled,
        'organic_discovery_enabled',s9.organic_discovery_enabled,
        'nurture_enabled',s9.nurture_enabled
      ),
      'counts',json_build_object(
        'waitlist_total',(SELECT count(*) FROM commercial_s8_users WHERE waitlist_status='WAITLISTED'),
        'waitlist_joined_events',(SELECT count(*) FROM commercial_s8_analytics_events WHERE event_type='WAITLIST_JOINED'),
        'bot_starts',(SELECT count(*) FROM commercial_s8_analytics_events WHERE event_type='BOT_START'),
        'referral_bot_starts',(SELECT count(*) FROM commercial_s8_analytics_events WHERE event_type='BOT_START' AND source='referral'),
        's8_analytics_total',(SELECT count(*) FROM commercial_s8_analytics_events),
        'community_members',(SELECT count(*) FROM commercial_s10_2d_community_members),
        'community_active',(SELECT count(*) FROM commercial_s10_2d_community_members WHERE community_state='ACTIVE'),
        'community_events',(SELECT count(*) FROM commercial_s10_2d_community_events),
        'moderation_events',(SELECT count(*) FROM commercial_s10_2d_moderation_events),
        'pending_moderation',(SELECT count(*) FROM commercial_s10_2d_moderation_outbox WHERE delivery_state='PENDING'),
        'stuck_restrictions',(SELECT count(*) FROM commercial_s10_2d_community_members WHERE community_state='RESTRICTED' AND restriction_until<CURRENT_TIMESTAMP)
      )
    )::text FROM commercial_s10_2d_runtime_control c CROSS JOIN commercial_s9_runtime_control s9 WHERE c.singleton AND s9.singleton;"
}

refresh_index() {
  (
    cd "$1"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
      | sort -z | xargs -0 sha256sum >SHA256SUMS
    chmod 0600 SHA256SUMS
  )
}

verify_acquisition_backup() {
  local path="$1" expected actual
  "$BASE_BACKUP" verify-existing "$path" >/dev/null || fail "BASE_BACKUP_VERIFY_RED"
  [ -f "$path/$SNAPSHOT_NAME" ] && [ ! -L "$path/$SNAPSHOT_NAME" ] || fail "BASELINE_SNAPSHOT_MISSING"
  [ -f "$path/$HEALTH_NAME" ] && [ ! -L "$path/$HEALTH_NAME" ] || fail "PUBLIC_HEALTH_SNAPSHOT_MISSING"
  [ -f "$path/$AGGREGATE_HASH_NAME" ] && [ ! -L "$path/$AGGREGATE_HASH_NAME" ] || fail "AGGREGATE_HASH_MISSING"
  "$EVIDENCE_TOOL" verify-snapshot --snapshot "$path/$SNAPSHOT_NAME" >/dev/null \
    || fail "BASELINE_SNAPSHOT_RED"
  /usr/bin/python3 -c 'import json,sys; value=json.load(open(sys.argv[1],encoding="ascii")); raise SystemExit(0 if value.get("ok") is True else 2)' \
    "$path/$HEALTH_NAME" || fail "PUBLIC_HEALTH_SNAPSHOT_RED"
  "$EVIDENCE_TOOL" verify-aggregate --snapshot "$path/s10-2d-aggregate-before.json" >/dev/null \
    || fail "AGGREGATE_SNAPSHOT_RED"
  read -r expected _ <"$path/$AGGREGATE_HASH_NAME"
  actual="$(sha256sum "$path/s10-2d-aggregate-before.json" | awk '{print $1}')"
  [ "$actual" = "$expected" ] || fail "AGGREGATE_HASH_RED"
  (
    cd "$path"
    sha256sum --check --strict SHA256SUMS >/dev/null
  ) || fail "BACKUP_INDEX_RED"
}

[ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
[ "$#" -eq 2 ] || fail "USAGE"
readonly ACTION="$1"
readonly BACKUP_PATH="$2"
require_boundary "$BACKUP_PATH"

case "$ACTION" in
  verify-existing)
    verify_acquisition_backup "$BACKUP_PATH"
    printf '{"ok":true,"safe_code":"S10_2E_BACKUP_EXISTING_GREEN","restore_path":"%s"}\n' "$BACKUP_PATH"
    ;;
  create)
    [ ! -e "$BACKUP_PATH" ] || fail "BACKUP_PATH_EXISTS"
    "$BASE_BACKUP" create "$BACKUP_PATH" >/dev/null || fail "BASE_BACKUP_CREATE_RED"
    "$EVIDENCE_TOOL" snapshot-aggregate \
      --source "$AGGREGATE_PATH" \
      --destination "$BACKUP_PATH/s10-2d-aggregate-before.json" >/dev/null \
      || fail "AGGREGATE_SNAPSHOT_CREATE_RED"
    database_snapshot >"$BACKUP_PATH/$SNAPSHOT_NAME"
    curl --fail --silent --show-error --max-time 10 https://wantmeseen.com/health \
      | /usr/bin/python3 -c 'import json,sys; value=json.load(sys.stdin); keys=("adult_content","media_intake","identity_documents","real_avs","payments","external_publishing","controlled_beta","production"); assert value.get("ok") is True and all(value.get(k) is False for k in keys); print("{\"ok\":true,\"product_boundaries_closed\":true}")' \
      >"$BACKUP_PATH/$HEALTH_NAME" || fail "PUBLIC_HEALTH_RED"
    sha256sum "$BACKUP_PATH/s10-2d-aggregate-before.json" >"$BACKUP_PATH/$AGGREGATE_HASH_NAME"
    printf '%s\n' \
      "S10.2E pause keeps REAL_ACQUISITION_BASELINE_START immutable and sets only REAL_ACQUISITION_ACTIVE=false." \
      "Verify SHA256SUMS, the S10.1 base restore contract, and the S10.2E aggregate snapshot before any destructive database restore." \
      >>"$BACKUP_PATH/RESTORE.txt"
    find "$BACKUP_PATH" -maxdepth 1 -type f -exec chmod 0600 {} +
    refresh_index "$BACKUP_PATH"
    verify_acquisition_backup "$BACKUP_PATH"
    printf '{"ok":true,"safe_code":"S10_2E_BACKUP_GREEN","restore_path":"%s","index_sha256":"%s"}\n' \
      "$BACKUP_PATH" "$(sha256sum "$BACKUP_PATH/SHA256SUMS" | awk '{print $1}')"
    ;;
  *) fail "USAGE" ;;
esac
