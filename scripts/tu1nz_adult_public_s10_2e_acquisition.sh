#!/usr/bin/env bash
set -euo pipefail
umask 0027

readonly APPLICATION_ROOT="/opt/tu1nz_repos/adult-publishing-core"
readonly CONTROL_ROOT="/opt/tu1nz_repos/control"
readonly DATABASE="tu1nz_adult_commercial_s3"
readonly APPLICATION_SHA="312db84d5db6d76c9d6bb448459c9404b1dfcbe4"
readonly APPLICATION_TREE="ac4f8bca1fd796626742a8ef6c6afcdda482fc68"
readonly FREEZE_TAG="s10-2d-r8-3-technical-readiness-freeze-r1"
readonly COMMUNITY_CONTROLLER="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_2d_control.sh"
readonly BACKUP_TOOL="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_2e_backup.sh"
readonly EVIDENCE_TOOL="$CONTROL_ROOT/scripts/tu1nz_adult_public_s10_2e_evidence.py"
readonly AGGREGATE_PATH="/var/lib/tu1nz-adult-public-s9/landing-aggregates.json"
readonly SNAPSHOT_NAME="s10-2e-acquisition-baseline.json"

fail() {
  printf 'S10_2E_ACQUISITION_RED %s\n' "$1" >&2
  exit 2
}

database_scalar() {
  runuser -u postgres -- psql --no-psqlrc --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --dbname="$DATABASE" --command="$1" | tr -d '[:space:]'
}

git_value() {
  runuser -u chatops -- git -C "$1" rev-parse "$2"
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "ROOT_REQUIRED"
}

require_release() {
  local control_sha="$1" control_tree="$2"
  [[ "$control_sha" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_SHA_INVALID"
  [[ "$control_tree" =~ ^[0-9a-f]{40}$ ]] || fail "CONTROL_TREE_INVALID"
  [ -z "$(runuser -u chatops -- git -C "$APPLICATION_ROOT" status --porcelain=v1)" ] || fail "APPLICATION_DIRTY"
  [ -z "$(runuser -u chatops -- git -C "$CONTROL_ROOT" status --porcelain=v1)" ] || fail "CONTROL_DIRTY"
  [ "$(git_value "$APPLICATION_ROOT" HEAD):$(git_value "$APPLICATION_ROOT" 'HEAD^{tree}')" = "$APPLICATION_SHA:$APPLICATION_TREE" ] \
    || fail "APPLICATION_RELEASE_RED"
  [ "$(git_value "$CONTROL_ROOT" HEAD):$(git_value "$CONTROL_ROOT" 'HEAD^{tree}')" = "$control_sha:$control_tree" ] \
    || fail "CONTROL_RELEASE_RED"
  [ "$(runuser -u chatops -- git -C "$CONTROL_ROOT" rev-parse "$FREEZE_TAG^{}")" = "d41b7695061136f7449d27e38e6adf1be0df219c" ] \
    || fail "R8_3_FREEZE_RED"
}

require_inactive_state() {
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_runtime_control WHERE singleton AND pre_acquisition_readiness='GREEN' AND NOT wms_real_acquisition_ready AND real_acquisition_baseline_start IS NULL;")" = "1" ] \
    || fail "ACQUISITION_INITIAL_STATE_RED"
}

require_active_state() {
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_runtime_control WHERE singleton AND pre_acquisition_readiness='GREEN' AND wms_real_acquisition_ready AND real_acquisition_baseline_start IS NOT NULL;")" = "1" ] \
    || fail "ACQUISITION_ACTIVE_STATE_RED"
}

require_distribution_and_boundaries() {
  [ "$(database_scalar "SELECT count(*) FROM commercial_s8_runtime_control WHERE singleton AND public_telegram_early_access_enabled AND new_waitlist_joins_enabled AND notifications_enabled AND NOT invite_automation_enabled;")" = "1" ] \
    || fail "S8_DISTRIBUTION_RED"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s9_runtime_control WHERE singleton AND public_sfw_growth_enabled AND audience_seeding_enabled AND telegram_channel_enabled AND organic_discovery_enabled AND nurture_enabled AND NOT x_enabled AND NOT reddit_enabled AND NOT invite_automation_enabled AND NOT controlled_beta AND pricing_mode='FREE_EARLY_ACCESS';")" = "1" ] \
    || fail "OWNED_ORGANIC_DISTRIBUTION_RED"
  [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_runtime_control WHERE singleton AND community_enabled AND community_posting_enabled AND NOT community_media_publishing_enabled AND community_automod_enabled AND community_welcome_enabled;")" = "1" ] \
    || fail "COMMUNITY_BOUNDARY_RED"
}

validate_observation() {
  /usr/bin/python3 -c 'import json,sys; value=json.load(sys.stdin); valid=value.get("ok") is True and value.get("WMS_REAL_ACQUISITION_TECHNICALLY_READY") is True and value.get("REAL_ACQUISITION_ACTIVE") is False and value.get("REAL_ACQUISITION_BASELINE_START_PRESENT") is False and value.get("business_loop_state")=="WAITING_OPERATOR_ACQUISITION_GO"; raise SystemExit(0 if valid else 2)' \
    || fail "R8_3_OBSERVATION_RED"
}

preflight() {
  local control_sha="$1" control_tree="$2" backup="$3"
  require_root
  require_release "$control_sha" "$control_tree"
  "$BACKUP_TOOL" verify-existing "$backup" >/dev/null || fail "BACKUP_VERIFY_RED"
  "$COMMUNITY_CONTROLLER" verify "$control_sha" "$control_tree" >/dev/null \
    || fail "COMMUNITY_RUNTIME_RED"
  "$COMMUNITY_CONTROLLER" observe "$control_sha" "$control_tree" | validate_observation
  require_inactive_state
  require_distribution_and_boundaries
  printf '{"ok":true,"safe_code":"S10_2E_PREFLIGHT_GREEN","technical_readiness":true,"real_acquisition_active":false,"baseline_start":null,"owned_organic_distribution":true,"human_acceptance":"DEFERRED","adult_media":false,"avs":false,"payments":false,"publishing":false}\n'
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

pause_database() {
  database_scalar "WITH updated AS (UPDATE commercial_s10_2d_runtime_control SET wms_real_acquisition_ready=false,updated_at=CURRENT_TIMESTAMP WHERE singleton AND pre_acquisition_readiness='GREEN' AND wms_real_acquisition_ready AND real_acquisition_baseline_start IS NOT NULL RETURNING 1) SELECT count(*) FROM updated;"
}

activate() {
  local control_sha="$1" control_tree="$2" backup="$3" baseline evidence_file
  preflight "$control_sha" "$control_tree" "$backup" >/dev/null
  baseline="$(database_scalar "WITH updated AS (UPDATE commercial_s10_2d_runtime_control SET real_acquisition_baseline_start=CURRENT_TIMESTAMP,wms_real_acquisition_ready=true,updated_at=CURRENT_TIMESTAMP WHERE singleton AND pre_acquisition_readiness='GREEN' AND NOT wms_real_acquisition_ready AND real_acquisition_baseline_start IS NULL RETURNING to_char(real_acquisition_baseline_start AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')) SELECT coalesce((SELECT * FROM updated),'');")"
  if [[ ! "$baseline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$ ]]; then
    fail "ACTIVATION_STATE_DIVERGED"
  fi
  require_active_state
  evidence_file="$backup/s10-2e-acquisition-activation.json"
  if ! printf '{"ok":true,"safe_code":"S10_2E_ACQUISITION_ACTIVATED","baseline_start":"%s","activation_timestamp":"%s","real_acquisition_active":true,"owned_organic_distribution":true,"human_acceptance":"DEFERRED","adult_media":false,"avs":false,"payments":false,"publishing":false}\n' \
    "$baseline" "$baseline" >"$evidence_file"; then
    pause_database >/dev/null || true
    fail "ACTIVATION_EVIDENCE_WRITE_RED"
  fi
  chmod 0600 "$evidence_file"
  refresh_index "$backup"
  "$BACKUP_TOOL" verify-existing "$backup" >/dev/null || {
    pause_database >/dev/null || true
    fail "POST_ACTIVATION_BACKUP_VERIFY_RED"
  }
  printf '{"ok":true,"safe_code":"S10_2E_ACQUISITION_ACTIVATED","REAL_ACQUISITION_ACTIVE":true,"REAL_ACQUISITION_BASELINE_START":"%s","owned_organic_distribution":true,"human_acceptance":"DEFERRED","adult_media":false,"avs":false,"payments":false,"publishing":false}\n' "$baseline"
}

pause() {
  local control_sha="$1" control_tree="$2" backup="$3" reason="$4" rows
  require_root
  require_release "$control_sha" "$control_tree"
  "$BACKUP_TOOL" verify-existing "$backup" >/dev/null || fail "BACKUP_VERIFY_RED"
  [[ "$reason" =~ ^[A-Z][A-Z0-9_]{2,95}$ ]] || fail "PAUSE_REASON_INVALID"
  rows="$(pause_database)"
  if [ "$rows" = "0" ]; then
    [ "$(database_scalar "SELECT count(*) FROM commercial_s10_2d_runtime_control WHERE singleton AND pre_acquisition_readiness='GREEN' AND NOT wms_real_acquisition_ready AND real_acquisition_baseline_start IS NOT NULL;")" = "1" ] \
      || fail "PAUSE_STATE_DIVERGED"
  elif [ "$rows" != "1" ]; then
    fail "PAUSE_STATE_DIVERGED"
  fi
  printf '{"ok":true,"safe_code":"S10_2E_ACQUISITION_PAUSED","reason":"%s","REAL_ACQUISITION_ACTIVE":false,"baseline_preserved":true}\n' "$reason"
}

report() {
  local backup="$1" current
  "$BACKUP_TOOL" verify-existing "$backup" >/dev/null || fail "BACKUP_VERIFY_RED"
  current="$(mktemp /run/tu1nz-s10-2e-current.XXXXXX.json)"
  trap 'find "$current" -maxdepth 0 -type f -delete' RETURN
  database_snapshot >"$current"
  chmod 0600 "$current"
  "$EVIDENCE_TOOL" report \
    --baseline "$backup/$SNAPSHOT_NAME" \
    --current "$current" \
    --baseline-aggregate "$backup/s10-2d-aggregate-before.json" \
    --current-aggregate "$AGGREGATE_PATH" \
    || fail "REPORT_RED"
  find "$current" -maxdepth 0 -type f -delete
  trap - RETURN
}

verify_active() {
  local control_sha="$1" control_tree="$2" backup="$3"
  require_root
  require_release "$control_sha" "$control_tree"
  "$BACKUP_TOOL" verify-existing "$backup" >/dev/null || fail "BACKUP_VERIFY_RED"
  "$COMMUNITY_CONTROLLER" verify "$control_sha" "$control_tree" >/dev/null || fail "COMMUNITY_RUNTIME_RED"
  require_active_state
  require_distribution_and_boundaries
  report "$backup"
}

case "${1:-}" in
  preflight) [ "$#" -eq 4 ] || fail "USAGE"; preflight "$2" "$3" "$4" ;;
  activate) [ "$#" -eq 4 ] || fail "USAGE"; activate "$2" "$3" "$4" ;;
  verify-active) [ "$#" -eq 4 ] || fail "USAGE"; verify_active "$2" "$3" "$4" ;;
  report) [ "$#" -eq 2 ] || fail "USAGE"; report "$2" ;;
  pause) [ "$#" -eq 5 ] || fail "USAGE"; pause "$2" "$3" "$4" "$5" ;;
  *) fail "USAGE" ;;
esac
