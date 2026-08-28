#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-}"
[[ "$MODE" == preflight || "$MODE" == prepare || "$MODE" == partial-preflight || "$MODE" == recover-partial || "$MODE" == resume-prepare || "$MODE" == verify-prepared || "$MODE" == install-unit ]] || {
  echo "usage: $0 preflight|prepare|partial-preflight|recover-partial|resume-prepare|verify-prepared|install-unit [arguments]" >&2
  exit 2
}
shift

APPLICATION_SHA=""
CONTROL_SHA=""
PREINSTALL_ARCHIVE=""
PREINSTALL_SHA256=""
RELEASE_ARCHIVE=""
APPLICATION_BUNDLE=""
APPLICATION_BUNDLE_SHA256=""

while (( $# > 0 )); do
  case "$1" in
    --application-sha) APPLICATION_SHA="${2:-}"; shift 2 ;;
    --control-sha) CONTROL_SHA="${2:-}"; shift 2 ;;
    --preinstall-archive) PREINSTALL_ARCHIVE="${2:-}"; shift 2 ;;
    --preinstall-sha256) PREINSTALL_SHA256="${2:-}"; shift 2 ;;
    --release-archive) RELEASE_ARCHIVE="${2:-}"; shift 2 ;;
    --application-bundle) APPLICATION_BUNDLE="${2:-}"; shift 2 ;;
    --application-bundle-sha256) APPLICATION_BUNDLE_SHA256="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

readonly EXPECTED_APPLICATION_SHA="52494d6121660ead53774deb8616701f14bb7a8f"
readonly EXPECTED_APPLICATION_TREE="b2820945c52ffdf77c2f5fbdd227c03ee6b245ab"
readonly EXPECTED_PREINSTALL_ARCHIVE="/opt/tu1nz_repos/backups/encrypted-system/tu1nz_system_backup_20260828T14-39-46Z.tar.gz"
readonly EXPECTED_PREINSTALL_SHA256="011856113239a94c83104e9156336dfc0cfbae8208f6cfdc0cee8f68d4316887"
readonly PREVIOUS_BACKUP_SHA256="068eccb256b4f5f9d3abed8bcc58b03145bdb2745b003ca60616daf4c07d0f78"
readonly EXPECTED_HBA_SHA256="ad0df9635890926d79a12d5627b68af6b85b6254fa23cace2bbe077838969c9e"
readonly EXPECTED_IDENT_SHA256="b4dfef08731a7d20a3bb724ad4cf3e1cd91ec01fbe51349c6a3acc5704072965"
readonly RUNTIME_USER="tu1nz-adult-commercial-s0"
readonly RUNTIME_GROUP="tu1nz-adult-commercial-s0"
readonly MIGRATOR_ROLE="tu1nz_adult_commercial_s0_migrator"
readonly RUNTIME_ROLE="tu1nz_adult_commercial_s0_runtime"
readonly DATABASE="tu1nz_adult_commercial_s0"
readonly UNIT="tu1nz-adult-commercial-s0.service"
readonly RELEASE_ROOT="/opt/tu1nz_repos/releases/adult-publishing/staging-s0-commercial"
readonly CONFIG_ROOT="/etc/tu1nz/adult-publishing/staging-s0-commercial"
readonly STATE_ROOT="/var/lib/tausendunde1nz/adult-publishing/staging-s0-commercial"
readonly CONTROL_REPOSITORY="/opt/tu1nz_repos/control"
readonly CONTROL_REMOTE="git@github.com-infra:Tausendunde1nz/infra.git"
readonly AUTHORIZATION="$CONTROL_REPOSITORY/manifests/adult-publishing-commercial-installation-authorization.m4-22.json"
readonly INSTALLED_BACKUP="/usr/local/bin/tu1nz_encrypted_backup.sh"
readonly INSTALLED_UNIT="/etc/systemd/system/$UNIT"
readonly PARTIAL_STAGE_ROOT="/opt/tu1nz_repos/.m4-23-commercial-s0-stage-30b4531449ec05b30afe0097eb69e1cb569590da"
BACKUP_TIMER_PAUSED=0

fail() {
  echo "M4_23_STOPPED_INSTALLATION_BLOCKED $*" >&2
  exit 1
}

resume_backup_timer() {
  if (( BACKUP_TIMER_PAUSED == 1 )); then
    /bin/systemctl start tu1nz_encrypted_backup.timer
  fi
}

require_root() {
  [[ "$EUID" -eq 0 ]] || fail "root identity required"
}

sha256() {
  /usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}'
}

postgres() {
  /usr/sbin/runuser -u postgres -- /usr/bin/psql --no-psqlrc --tuples-only --no-align --set=ON_ERROR_STOP=1 "$@"
}

git_read() {
  local repository="$1"
  shift
  /usr/bin/git -c "safe.directory=$repository" -C "$repository" "$@"
}

verify_clean_release() {
  local repository="$1"
  local expected_sha="$2"
  local expected_tree="$3"
  [[ ! -L "$repository" && -d "$repository/.git" ]] || fail "unsafe release repository: $repository"
  [[ "$(git_read "$repository" rev-parse HEAD)" == "$expected_sha" ]] || fail "release SHA mismatch: $repository"
  [[ "$(git_read "$repository" rev-parse 'HEAD^{tree}')" == "$expected_tree" ]] || fail "release tree mismatch: $repository"
  [[ -z "$(git_read "$repository" status --porcelain=v1)" ]] || fail "dirty release repository: $repository"
  [[ -z "$(git_read "$repository" clean -ndx)" ]] || fail "untracked or ignored release material: $repository"
  git_read "$repository" fsck --full >/dev/null
}

resolve_postgres_files() {
  HBA_FILE="$(postgres --dbname=postgres --command='SHOW hba_file')"
  IDENT_FILE="$(postgres --dbname=postgres --command='SHOW ident_file')"
  [[ "$HBA_FILE" == /* && "$IDENT_FILE" == /* ]] || fail "PostgreSQL configuration paths are invalid"
  [[ -f "$HBA_FILE" && ! -L "$HBA_FILE" && -f "$IDENT_FILE" && ! -L "$IDENT_FILE" ]] || fail "PostgreSQL configuration files are unsafe"
}

verify_common_inputs() {
  require_root
  [[ "$APPLICATION_SHA" == "$EXPECTED_APPLICATION_SHA" ]] || fail "final application SHA required"
  [[ "$CONTROL_SHA" =~ ^[0-9a-f]{40}$ ]] || fail "exact Control SHA required"
  [[ "$PREINSTALL_SHA256" == "$EXPECTED_PREINSTALL_SHA256" ]] || fail "exact approved pre-install archive SHA-256 required"
  [[ "$PREINSTALL_ARCHIVE" == "$EXPECTED_PREINSTALL_ARCHIVE" ]] || fail "exact approved pre-install archive path required"
  [[ -f "$PREINSTALL_ARCHIVE" && ! -L "$PREINSTALL_ARCHIVE" ]] || fail "safe pre-install archive required"
  [[ "$(sha256 "$PREINSTALL_ARCHIVE")" == "$PREINSTALL_SHA256" ]] || fail "pre-install archive digest mismatch"
  [[ "$(readlink -f "$CONTROL_REPOSITORY")" == "$CONTROL_REPOSITORY" ]] || fail "canonical Control path required"
  [[ "$(git_read "$CONTROL_REPOSITORY" rev-parse HEAD)" == "$CONTROL_SHA" ]] || fail "canonical Control SHA mismatch"
  [[ -z "$(git_read "$CONTROL_REPOSITORY" status --porcelain=v1)" ]] || fail "canonical Control checkout is dirty"
  "$CONTROL_REPOSITORY/scripts/tu1nz_adult_commercial_installation_authorization_gate.py" --contract "$AUTHORIZATION" >/dev/null
}

preflight_absent() {
  verify_common_inputs
  [[ "$(sha256 "$INSTALLED_BACKUP")" == "$PREVIOUS_BACKUP_SHA256" ]] || fail "installed backup baseline drift"
  for path in "$RELEASE_ROOT" "$CONFIG_ROOT" "$STATE_ROOT" "$INSTALLED_UNIT"; do
    [[ ! -e "$path" && ! -L "$path" ]] || fail "commercial target must be absent: $path"
  done
  ! /usr/bin/getent passwd "$RUNTIME_USER" >/dev/null || fail "commercial operating-system user already exists"
  ! /usr/bin/getent group "$RUNTIME_GROUP" >/dev/null || fail "commercial operating-system group already exists"
  [[ "$(postgres --dbname=postgres --command="SELECT count(*) FROM pg_roles WHERE rolname IN ('$MIGRATOR_ROLE','$RUNTIME_ROLE')")" == 0 ]] || fail "commercial PostgreSQL role already exists"
  [[ "$(postgres --dbname=postgres --command="SELECT count(*) FROM pg_database WHERE datname='$DATABASE'")" == 0 ]] || fail "commercial PostgreSQL database already exists"
  /bin/systemctl is-active --quiet postgresql.service || fail "PostgreSQL is not active"
  /bin/systemctl is-active --quiet tu1nz-adult-publishing-s1.service || fail "STAGING-S1 is not active"
  ! /bin/systemctl is-active --quiet tu1nz_encrypted_backup.service || fail "backup service is currently active"
  /bin/systemctl is-active --quiet tu1nz_encrypted_backup.timer || fail "backup timer is not active before the installation window"
  ! /bin/systemctl is-active --quiet "$UNIT" || fail "commercial unit is unexpectedly active"
  resolve_postgres_files
  [[ "$(sha256 "$HBA_FILE")" == "$EXPECTED_HBA_SHA256" ]] || fail "pg_hba baseline drift"
  [[ "$(sha256 "$IDENT_FILE")" == "$EXPECTED_IDENT_SHA256" ]] || fail "pg_ident baseline drift"
  [[ "$(/usr/bin/df --output=avail -B1 / | /usr/bin/tail -1 | /usr/bin/tr -d ' ')" -ge 1073741824 ]] || fail "less than one GiB is available"
  echo "M4_23_STOPPED_INSTALLATION_PREFLIGHT_OK"
}

install_postgres_mapping() {
  local evidence_root="$1"
  local hba_temp ident_temp
  /usr/bin/install -o root -g root -m 0600 "$HBA_FILE" "$evidence_root/pg_hba.conf.before"
  /usr/bin/install -o root -g root -m 0600 "$IDENT_FILE" "$evidence_root/pg_ident.conf.before"
  hba_temp="$(/usr/bin/mktemp "${HBA_FILE}.m4-23.XXXXXX")"
  ident_temp="$(/usr/bin/mktemp "${IDENT_FILE}.m4-23.XXXXXX")"
  /usr/bin/awk '
    BEGIN { inserted=0 }
    /^[[:space:]]*local[[:space:]]+all[[:space:]]+all[[:space:]]+peer([[:space:]]|$)/ && inserted == 0 {
      print "local tu1nz_adult_commercial_s0 tu1nz_adult_commercial_s0_runtime peer map=tu1nz_adult_commercial_s0"
      inserted=1
    }
    { print }
    END { if (inserted != 1) exit 42 }
  ' "$HBA_FILE" >"$hba_temp" || fail "generic PostgreSQL peer anchor missing or ambiguous"
  /usr/bin/awk '
    { print }
    END { print "tu1nz_adult_commercial_s0 tu1nz-adult-commercial-s0 tu1nz_adult_commercial_s0_runtime" }
  ' "$IDENT_FILE" >"$ident_temp"
  /usr/bin/chown --reference="$HBA_FILE" "$hba_temp"
  /usr/bin/chmod --reference="$HBA_FILE" "$hba_temp"
  /usr/bin/chown --reference="$IDENT_FILE" "$ident_temp"
  /usr/bin/chmod --reference="$IDENT_FILE" "$ident_temp"
  /usr/bin/mv -- "$hba_temp" "$HBA_FILE"
  /usr/bin/mv -- "$ident_temp" "$IDENT_FILE"
  "$CONTROL_REPOSITORY/scripts/tu1nz_adult_commercial_host_access_gate.py" \
    --contract "$CONTROL_REPOSITORY/manifests/adult-publishing-commercial-host-access.m4-21.json" \
    --control-repository "$CONTROL_REPOSITORY" --phase installed \
    --pg-hba "$HBA_FILE" --pg-ident "$IDENT_FILE" >/dev/null
  /bin/systemctl reload postgresql.service
  [[ "$(postgres --dbname=postgres --command='SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL')" == 0 ]] || fail "PostgreSQL HBA parser reports an error"
  [[ "$(postgres --dbname=postgres --command='SELECT count(*) FROM pg_ident_file_mappings WHERE error IS NOT NULL')" == 0 ]] || fail "PostgreSQL ident parser reports an error"
}

create_database() {
  postgres --dbname=postgres --command="CREATE ROLE $MIGRATOR_ROLE NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT"
  postgres --dbname=postgres --command="CREATE ROLE $RUNTIME_ROLE LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD NULL"
  postgres --dbname=postgres --command="CREATE DATABASE $DATABASE OWNER $MIGRATOR_ROLE TEMPLATE template0 ENCODING 'UTF8'"
}

clone_release() {
  local remote="$1"
  local target="$2"
  local sha="$3"
  [[ ! -e "$target" && ! -L "$target" ]] || fail "release target already exists: $target"
  /usr/sbin/runuser -u chatops -- /usr/bin/git clone --no-checkout --filter=blob:none "$remote" "$target"
  /usr/sbin/runuser -u chatops -- /usr/bin/git -C "$target" checkout --detach "$sha"
}

clone_bundle_release() {
  local bundle="$1"
  local target="$2"
  local sha="$3"
  [[ ! -e "$target" && ! -L "$target" ]] || fail "release target already exists: $target"
  /usr/bin/git clone --no-checkout "$bundle" "$target"
  /usr/bin/git -C "$target" checkout --detach "$sha"
}

verify_application_bundle() {
  local expected_path="/opt/tu1nz_repos/backups/m4-23-input/adult-publishing-core-$APPLICATION_SHA.bundle"
  [[ "$APPLICATION_BUNDLE" == "$expected_path" ]] || fail "exact application bundle path required"
  [[ "$APPLICATION_BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "application bundle SHA-256 required"
  [[ -f "$APPLICATION_BUNDLE" && ! -L "$APPLICATION_BUNDLE" && "$(stat -c '%a:%U:%G:%h' "$APPLICATION_BUNDLE")" == "600:root:root:1" ]] || fail "safe root-private application bundle required"
  [[ "$(sha256 "$APPLICATION_BUNDLE")" == "$APPLICATION_BUNDLE_SHA256" ]] || fail "application bundle digest mismatch"
  /usr/bin/git bundle verify "$APPLICATION_BUNDLE" >/dev/null
}

prepare_release_and_database() {
  local source_mode="${1:-bundle-new}"
  local app_target="$RELEASE_ROOT/application/$APPLICATION_SHA"
  local control_target="$RELEASE_ROOT/control/$CONTROL_SHA"
  local venv_target="$RELEASE_ROOT/venv/$APPLICATION_SHA"
  local stage_root=""
  local app_stage=""
  local control_stage=""
  local migration
  if [[ "$source_mode" == bundle-new ]]; then
    stage_root="/opt/tu1nz_repos/.m4-23-commercial-s0-stage-$CONTROL_SHA"
    app_stage="$stage_root/application-$APPLICATION_SHA"
    control_stage="$stage_root/control-$CONTROL_SHA"
    [[ ! -e "$stage_root" && ! -L "$stage_root" ]] || fail "staging root already exists"
    /usr/bin/install -d -o chatops -g chatops -m 0700 "$stage_root"
    verify_application_bundle
    clone_bundle_release "$APPLICATION_BUNDLE" "$app_stage" "$APPLICATION_SHA"
  elif [[ "$source_mode" == bundle-resume ]]; then
    stage_root="$PARTIAL_STAGE_ROOT"
    app_stage="$stage_root/application-$APPLICATION_SHA"
    control_stage="$stage_root/control-$CONTROL_SHA"
    [[ -d "$stage_root" && ! -L "$stage_root" && "$(stat -c '%a:%U:%G' "$stage_root")" == "2700:chatops:chatops" ]] || fail "exact empty partial staging root required"
    [[ -z "$(/usr/bin/find "$stage_root" -mindepth 1 -print -quit)" ]] || fail "partial staging root is not empty"
    verify_application_bundle
    clone_bundle_release "$APPLICATION_BUNDLE" "$app_stage" "$APPLICATION_SHA"
  else
    fail "invalid release source mode"
  fi
  clone_release "$CONTROL_REMOTE" "$control_stage" "$CONTROL_SHA"
  verify_clean_release "$app_stage" "$APPLICATION_SHA" "$EXPECTED_APPLICATION_TREE"
  verify_clean_release "$control_stage" "$CONTROL_SHA" "$(git_read "$CONTROL_REPOSITORY" rev-parse 'HEAD^{tree}')"
  /usr/bin/chown -R root:"$RUNTIME_GROUP" "$app_stage" "$control_stage"
  /usr/bin/chmod 0750 "$app_stage" "$control_stage"
  /usr/bin/install -d -o root -g "$RUNTIME_GROUP" -m 0750 \
    "$RELEASE_ROOT" "$RELEASE_ROOT/application" "$RELEASE_ROOT/control" "$RELEASE_ROOT/venv"
  /usr/bin/mv -- "$app_stage" "$app_target"
  /usr/bin/mv -- "$control_stage" "$control_target"
  /usr/bin/rmdir -- "$stage_root"
  verify_clean_release "$app_target" "$APPLICATION_SHA" "$EXPECTED_APPLICATION_TREE"
  verify_clean_release "$control_target" "$CONTROL_SHA" "$(git_read "$CONTROL_REPOSITORY" rev-parse 'HEAD^{tree}')"

  /usr/bin/python3 -m venv "$venv_target"
  "$venv_target/bin/python" -m pip install --require-hashes --no-deps --requirement "$app_target/requirements-m2.lock"
  "$venv_target/bin/python" -m pip install --no-deps --no-build-isolation "$app_target"
  /usr/bin/chown -R root:"$RUNTIME_GROUP" "$venv_target"
  /usr/bin/chmod 0750 "$venv_target"
  [[ "$(PYTHONDONTWRITEBYTECODE=1 "$venv_target/bin/python" -c "import importlib.metadata,psycopg,tu1nz_sandbox;print(psycopg.__version__+'|'+importlib.metadata.version('tu1nz-adult-publishing-core'))")" == "3.3.4|0.1.0" ]] || fail "virtual environment contract mismatch"
  verify_clean_release "$app_target" "$APPLICATION_SHA" "$EXPECTED_APPLICATION_TREE"

  mapfile -t migrations < <(/usr/bin/find "$app_target/migrations" -maxdepth 1 -type f -name '*.sql' ! -name '*.down.sql' -printf '%f\n' | /usr/bin/sort)
  [[ "${#migrations[@]}" -eq 14 && "${migrations[0]}" == 0001_m1_core.sql && "${migrations[13]}" == 0014_m4_15_durable_commercial_persistence.sql ]] || fail "exact migration sequence required"
  for migration in "${migrations[@]}"; do
    /usr/sbin/runuser -u postgres -- /usr/bin/env PGOPTIONS="-c role=$MIGRATOR_ROLE" \
      /usr/bin/psql --no-psqlrc --dbname="$DATABASE" --set=ON_ERROR_STOP=1 --file="$app_target/migrations/$migration" >/dev/null
  done
  /usr/sbin/runuser -u postgres -- /usr/bin/env PGOPTIONS="-c role=$MIGRATOR_ROLE" \
    /usr/bin/psql --no-psqlrc --dbname="$DATABASE" --set=ON_ERROR_STOP=1 \
      --file="$control_target/config/adult-publishing/staging-s0-commercial/bootstrap.sql" >/dev/null

  /usr/bin/install -d -o root -g "$RUNTIME_GROUP" -m 0750 "$CONFIG_ROOT"
  /usr/bin/install -o root -g "$RUNTIME_GROUP" -m 0640 \
    "$control_target/config/adult-publishing/staging-s0-commercial/runtime.env.example" "$CONFIG_ROOT/runtime.env"
  /usr/bin/install -o "$RUNTIME_USER" -g "$RUNTIME_GROUP" -m 0600 \
    "$control_target/config/adult-publishing/staging-s0-commercial/core-identities.synthetic.json" "$CONFIG_ROOT/core-identities.json"
  /usr/bin/install -d -o "$RUNTIME_USER" -g "$RUNTIME_GROUP" -m 0700 "$STATE_ROOT"
  /usr/bin/install -o "$RUNTIME_USER" -g "$RUNTIME_GROUP" -m 0600 \
    "$control_target/config/adult-publishing/staging-s0-commercial/state.empty.json" "$STATE_ROOT/state.json"
  /usr/bin/ln -s "application/$APPLICATION_SHA" "$RELEASE_ROOT/application-current"
  /usr/bin/ln -s "control/$CONTROL_SHA" "$RELEASE_ROOT/control-current"
  /usr/bin/ln -s "venv/$APPLICATION_SHA" "$RELEASE_ROOT/venv-current"

  /usr/sbin/runuser -u "$RUNTIME_USER" -- /usr/bin/psql --no-psqlrc --dbname="$DATABASE" --set=ON_ERROR_STOP=1 \
    --file="$app_target/tests/postgres/m4_15_durable_commercial_persistence_schema_acceptance.sql" >/dev/null
}

verify_partial() {
  local timer_phase="${1:-paused}"
  local stage_root="$PARTIAL_STAGE_ROOT"
  local evidence_root="/opt/tu1nz_repos/backups/m4-23-commercial-s0-stopped-installation/20260828T15-39-59Z"
  verify_common_inputs
  [[ "$(sha256 "$INSTALLED_BACKUP")" == "$(sha256 "$CONTROL_REPOSITORY/scripts/tu1nz_encrypted_backup.sh")" ]] || fail "commercial-aware backup script is not installed"
  /usr/bin/getent passwd "$RUNTIME_USER" >/dev/null || fail "commercial operating-system user is absent"
  /usr/bin/getent group "$RUNTIME_GROUP" >/dev/null || fail "commercial operating-system group is absent"
  [[ -z "$(/usr/bin/id -nG "$RUNTIME_USER" | /usr/bin/tr ' ' '\n' | /usr/bin/grep -Fx chatops || true)" ]] || fail "runtime identity belongs to forbidden chatops group"
  "$CONTROL_REPOSITORY/scripts/tu1nz_adult_commercial_path_access.sh" verify >/dev/null
  resolve_postgres_files
  "$CONTROL_REPOSITORY/scripts/tu1nz_adult_commercial_host_access_gate.py" \
    --contract "$CONTROL_REPOSITORY/manifests/adult-publishing-commercial-host-access.m4-21.json" \
    --control-repository "$CONTROL_REPOSITORY" --phase installed \
    --pg-hba "$HBA_FILE" --pg-ident "$IDENT_FILE" >/dev/null
  [[ "$(postgres --dbname=postgres --command="SELECT string_agg(rolname || ':' || rolcanlogin, ',' ORDER BY rolname) FROM pg_roles WHERE rolname IN ('$MIGRATOR_ROLE','$RUNTIME_ROLE')")" == "$MIGRATOR_ROLE:false,$RUNTIME_ROLE:true" ]] || fail "commercial PostgreSQL role boundary mismatch"
  [[ "$(postgres --dbname=postgres --command="SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='$DATABASE'")" == "$MIGRATOR_ROLE" ]] || fail "commercial PostgreSQL database boundary mismatch"
  [[ "$(postgres --dbname="$DATABASE" --command="SELECT count(*) FROM pg_tables WHERE schemaname='public'")" == 0 ]] || fail "partial commercial database is not empty"
  for path in "$RELEASE_ROOT" "$CONFIG_ROOT" "$STATE_ROOT" "$INSTALLED_UNIT"; do
    [[ ! -e "$path" && ! -L "$path" ]] || fail "partial boundary target must be absent: $path"
  done
  [[ -d "$stage_root" && ! -L "$stage_root" && "$(stat -c '%a:%U:%G' "$stage_root")" == "2700:chatops:chatops" ]] || fail "partial staging root mismatch"
  [[ -z "$(/usr/bin/find "$stage_root" -mindepth 1 -print -quit)" ]] || fail "partial staging root is not empty"
  for evidence in tu1nz_encrypted_backup.sh.before pg_hba.conf.before pg_ident.conf.before; do
    [[ -f "$evidence_root/$evidence" && ! -L "$evidence_root/$evidence" && "$(stat -c '%a:%U:%G:%h' "$evidence_root/$evidence")" == "600:root:root:1" ]] || fail "rollback evidence mismatch: $evidence"
  done
  /bin/systemctl is-active --quiet tu1nz-adult-publishing-s1.service || fail "STAGING-S1 is not active"
  ! /bin/systemctl is-active --quiet tu1nz_encrypted_backup.service || fail "backup service is active during partial recovery"
  if [[ "$timer_phase" == paused ]]; then
    ! /bin/systemctl is-active --quiet tu1nz_encrypted_backup.timer || fail "backup timer is unexpectedly active"
  elif [[ "$timer_phase" == active ]]; then
    /bin/systemctl is-active --quiet tu1nz_encrypted_backup.timer || fail "backup timer is not active"
  else
    fail "invalid partial timer phase"
  fi
  ! /bin/systemctl is-active --quiet "$UNIT" || fail "commercial unit is active"
  echo "M4_23_PARTIAL_BOUNDARY_OK timer=$timer_phase"
}

recover_partial() {
  verify_partial paused >/dev/null
  /bin/systemctl start tu1nz_encrypted_backup.timer
  verify_partial active >/dev/null
  echo "M4_23_PARTIAL_TIMER_RECOVERED_OK"
}

resume_prepare() {
  verify_partial active >/dev/null
  verify_application_bundle
  trap resume_backup_timer EXIT
  /bin/systemctl stop tu1nz_encrypted_backup.timer
  BACKUP_TIMER_PAUSED=1
  prepare_release_and_database bundle-resume
  verify_prepared absent paused >/dev/null
  /bin/systemctl start tu1nz_encrypted_backup.timer
  BACKUP_TIMER_PAUSED=0
  /bin/systemctl is-active --quiet tu1nz_encrypted_backup.timer || fail "backup timer did not resume"
  trap - EXIT
  echo "M4_23_STOPPED_CANDIDATE_PREPARED_OK resumed_from_exact_partial_state"
}

verify_prepared() {
  local manifest_phase="${1:-absent}"
  local timer_phase="${2:-active}"
  local app_target="$RELEASE_ROOT/application/$APPLICATION_SHA"
  local control_target="$RELEASE_ROOT/control/$CONTROL_SHA"
  local venv_target="$RELEASE_ROOT/venv/$APPLICATION_SHA"
  verify_common_inputs
  [[ "$(sha256 "$INSTALLED_BACKUP")" == "$(sha256 "$CONTROL_REPOSITORY/scripts/tu1nz_encrypted_backup.sh")" ]] || fail "commercial-aware backup script is not installed"
  /usr/bin/getent passwd "$RUNTIME_USER" >/dev/null || fail "commercial operating-system user is absent"
  /usr/bin/getent group "$RUNTIME_GROUP" >/dev/null || fail "commercial operating-system group is absent"
  [[ -z "$(/usr/bin/id -nG "$RUNTIME_USER" | /usr/bin/tr ' ' '\n' | /usr/bin/grep -Fx chatops || true)" ]] || fail "runtime identity belongs to forbidden chatops group"
  "$CONTROL_REPOSITORY/scripts/tu1nz_adult_commercial_path_access.sh" verify >/dev/null
  resolve_postgres_files
  "$CONTROL_REPOSITORY/scripts/tu1nz_adult_commercial_host_access_gate.py" \
    --contract "$CONTROL_REPOSITORY/manifests/adult-publishing-commercial-host-access.m4-21.json" \
    --control-repository "$CONTROL_REPOSITORY" --phase installed \
    --pg-hba "$HBA_FILE" --pg-ident "$IDENT_FILE" >/dev/null
  [[ "$(postgres --dbname=postgres --command="SELECT count(*) FROM pg_roles WHERE rolname IN ('$MIGRATOR_ROLE','$RUNTIME_ROLE')")" == 2 ]] || fail "commercial PostgreSQL roles are incomplete"
  [[ "$(postgres --dbname=postgres --command="SELECT count(*) FROM pg_database WHERE datname='$DATABASE'")" == 1 ]] || fail "commercial PostgreSQL database is absent"
  verify_clean_release "$app_target" "$APPLICATION_SHA" "$EXPECTED_APPLICATION_TREE"
  verify_clean_release "$control_target" "$CONTROL_SHA" "$(git_read "$CONTROL_REPOSITORY" rev-parse 'HEAD^{tree}')"
  [[ "$(stat -c '%a:%U:%G' "$app_target")" == "750:root:$RUNTIME_GROUP" ]] || fail "application release metadata mismatch"
  [[ "$(stat -c '%a:%U:%G' "$control_target")" == "750:root:$RUNTIME_GROUP" ]] || fail "Control release metadata mismatch"
  [[ "$(stat -c '%a:%U:%G' "$venv_target")" == "750:root:$RUNTIME_GROUP" ]] || fail "venv metadata mismatch"
  [[ "$(PYTHONDONTWRITEBYTECODE=1 "$venv_target/bin/python" -c "import importlib.metadata,psycopg,tu1nz_sandbox;print(psycopg.__version__+'|'+importlib.metadata.version('tu1nz-adult-publishing-core'))")" == "3.3.4|0.1.0" ]] || fail "venv dependency or application import mismatch"
  [[ "$(readlink "$RELEASE_ROOT/application-current")" == "application/$APPLICATION_SHA" ]] || fail "application active link mismatch"
  [[ "$(readlink "$RELEASE_ROOT/control-current")" == "control/$CONTROL_SHA" ]] || fail "Control active link mismatch"
  [[ "$(readlink "$RELEASE_ROOT/venv-current")" == "venv/$APPLICATION_SHA" ]] || fail "venv active link mismatch"
  [[ "$(stat -c '%a:%U:%G' "$CONFIG_ROOT")" == "750:root:$RUNTIME_GROUP" ]] || fail "configuration metadata mismatch"
  [[ "$(stat -c '%a:%U:%G' "$CONFIG_ROOT/runtime.env")" == "640:root:$RUNTIME_GROUP" ]] || fail "runtime environment metadata mismatch"
  /usr/bin/cmp --silent "$CONFIG_ROOT/runtime.env" "$control_target/config/adult-publishing/staging-s0-commercial/runtime.env.example" || fail "runtime environment drift"
  [[ "$(stat -c '%a:%U:%G' "$CONFIG_ROOT/core-identities.json")" == "600:$RUNTIME_USER:$RUNTIME_GROUP" ]] || fail "identity registry metadata mismatch"
  /usr/bin/cmp --silent "$CONFIG_ROOT/core-identities.json" "$control_target/config/adult-publishing/staging-s0-commercial/core-identities.synthetic.json" || fail "identity registry drift"
  [[ "$(stat -c '%a:%U:%G' "$STATE_ROOT")" == "700:$RUNTIME_USER:$RUNTIME_GROUP" ]] || fail "state metadata mismatch"
  [[ "$(stat -c '%a:%U:%G' "$STATE_ROOT/state.json")" == "600:$RUNTIME_USER:$RUNTIME_GROUP" ]] || fail "state file metadata mismatch"
  /usr/bin/cmp --silent "$STATE_ROOT/state.json" "$control_target/config/adult-publishing/staging-s0-commercial/state.empty.json" || fail "initial state drift"
  [[ ! -e "$STATE_ROOT/runtime-status.json" && ! -L "$STATE_ROOT/runtime-status.json" ]] || fail "runtime status exists before first start"
  [[ ! -e "$STATE_ROOT/runtime.lock" && ! -L "$STATE_ROOT/runtime.lock" ]] || fail "runtime lock exists before first start"
  /usr/sbin/runuser -u "$RUNTIME_USER" -- /usr/bin/psql --no-psqlrc --dbname="$DATABASE" --set=ON_ERROR_STOP=1 \
    --file="$app_target/tests/postgres/m4_15_durable_commercial_persistence_schema_acceptance.sql" >/dev/null
  if [[ "$manifest_phase" == absent ]]; then
    [[ ! -e "$CONFIG_ROOT/release-manifest.json" && ! -L "$CONFIG_ROOT/release-manifest.json" ]] || fail "release manifest must await post-backup approval"
  elif [[ "$manifest_phase" == present ]]; then
    [[ -f "$CONFIG_ROOT/release-manifest.json" && ! -L "$CONFIG_ROOT/release-manifest.json" ]] || fail "post-backup approved release manifest required"
  else
    fail "invalid manifest verification phase"
  fi
  [[ ! -e "$INSTALLED_UNIT" && ! -L "$INSTALLED_UNIT" ]] || fail "unit must remain uninstalled before post-backup approval"
  /bin/systemctl is-active --quiet tu1nz-adult-publishing-s1.service || fail "STAGING-S1 is not active after preparation"
  if [[ "$timer_phase" == active ]]; then
    /bin/systemctl is-active --quiet tu1nz_encrypted_backup.timer || fail "backup timer is not active after preparation"
  elif [[ "$timer_phase" == paused ]]; then
    ! /bin/systemctl is-active --quiet tu1nz_encrypted_backup.timer || fail "backup timer is active inside the transition window"
  else
    fail "invalid backup timer verification phase"
  fi
  ! /bin/systemctl is-active --quiet "$UNIT" || fail "commercial unit is active"
  echo "M4_23_STOPPED_CANDIDATE_PREPARED_OK"
}

prepare() {
  preflight_absent >/dev/null
  verify_application_bundle
  local evidence_root="/opt/tu1nz_repos/backups/m4-23-commercial-s0-stopped-installation/$(/usr/bin/date -u +%Y%m%dT%H-%M-%SZ)"
  trap resume_backup_timer EXIT
  /bin/systemctl stop tu1nz_encrypted_backup.timer
  BACKUP_TIMER_PAUSED=1
  /usr/bin/install -d -o root -g root -m 0700 "$evidence_root"
  /usr/bin/install -o root -g root -m 0600 "$INSTALLED_BACKUP" "$evidence_root/tu1nz_encrypted_backup.sh.before"
  /usr/bin/install -o root -g root -m 0755 "$CONTROL_REPOSITORY/scripts/tu1nz_encrypted_backup.sh" "$INSTALLED_BACKUP"
  [[ "$(sha256 "$INSTALLED_BACKUP")" == "$(sha256 "$CONTROL_REPOSITORY/scripts/tu1nz_encrypted_backup.sh")" ]] || fail "backup script installation drift"

  /usr/sbin/groupadd --system "$RUNTIME_GROUP"
  /usr/sbin/useradd --system --gid "$RUNTIME_GROUP" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$RUNTIME_USER"
  "$CONTROL_REPOSITORY/scripts/tu1nz_adult_commercial_path_access.sh" apply >/dev/null
  resolve_postgres_files
  install_postgres_mapping "$evidence_root"
  create_database
  prepare_release_and_database bundle-new
  verify_prepared absent paused >/dev/null
  /bin/systemctl start tu1nz_encrypted_backup.timer
  BACKUP_TIMER_PAUSED=0
  /bin/systemctl is-active --quiet tu1nz_encrypted_backup.timer || fail "backup timer did not resume"
  trap - EXIT
  echo "M4_23_STOPPED_CANDIDATE_PREPARED_OK evidence=$evidence_root"
}

install_unit() {
  verify_prepared present >/dev/null
  [[ "$RELEASE_ARCHIVE" == /opt/tu1nz_repos/backups/encrypted-system/tu1nz_system_backup_*.tar.gz ]] || fail "qualifying commercial release archive required"
  [[ -f "$RELEASE_ARCHIVE" && ! -L "$RELEASE_ARCHIVE" ]] || fail "safe commercial release archive required"
  [[ -f "$CONFIG_ROOT/release-manifest.json" && ! -L "$CONFIG_ROOT/release-manifest.json" ]] || fail "post-backup approved release manifest required"
  /usr/bin/chown root:"$RUNTIME_GROUP" "$CONFIG_ROOT/release-manifest.json"
  /usr/bin/chmod 0640 "$CONFIG_ROOT/release-manifest.json"
  /usr/bin/install -o root -g root -m 0644 "$RELEASE_ROOT/control/$CONTROL_SHA/systemd/$UNIT" "$INSTALLED_UNIT"
  /bin/systemctl daemon-reload
  ! /bin/systemctl is-active --quiet "$UNIT" || fail "commercial unit became active"
  [[ "$(/bin/systemctl is-enabled "$UNIT" 2>/dev/null || true)" != enabled ]] || fail "commercial unit became enabled"
  /usr/bin/systemd-analyze verify "$INSTALLED_UNIT"
  "$RELEASE_ROOT/control/$CONTROL_SHA/scripts/tu1nz_adult_commercial_s0_release_gate.py" \
    --manifest "$CONFIG_ROOT/release-manifest.json" \
    --application-repository "$RELEASE_ROOT/application-current" \
    --control-repository "$RELEASE_ROOT/control-current" \
    --application-release-root "$RELEASE_ROOT/application" \
    --control-release-root "$RELEASE_ROOT/control" \
    --venv "$RELEASE_ROOT/venv-current" \
    --configuration-root "$CONFIG_ROOT" --state-root "$STATE_ROOT" \
    --installed-unit "$INSTALLED_UNIT" --archive "$RELEASE_ARCHIVE" \
    --runtime-user "$RUNTIME_USER" --runtime-group "$RUNTIME_GROUP" \
    --release-user root --configuration-user root --unit-user root --unit-group root \
    --require-active >/dev/null
  ! /bin/systemctl is-active --quiet "$UNIT" || fail "commercial unit is active after verification"
  echo "M4_23_STOPPED_UNIT_INSTALLED_OK"
}

case "$MODE" in
  preflight) preflight_absent ;;
  prepare) prepare ;;
  partial-preflight) verify_partial paused ;;
  recover-partial) recover_partial ;;
  resume-prepare) resume_prepare ;;
  verify-prepared) verify_prepared ;;
  install-unit) install_unit ;;
esac
