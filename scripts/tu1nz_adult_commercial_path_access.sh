#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-verify}"
RUNTIME_USER="tu1nz-adult-commercial-s0"
FORBIDDEN_GROUP="chatops"
PATHS=(
  /opt/tu1nz_repos
  /opt/tu1nz_repos/releases
  /opt/tu1nz_repos/releases/adult-publishing
  /etc/tu1nz
  /var/lib/tausendunde1nz/adult-publishing
)
EXPECTED=(
  2770:chatops:chatops
  2750:root:chatops
  2750:root:chatops
  750:root:chatops
  2750:root:chatops
)
MASKS=(
  rwx
  r-x
  r-x
  r-x
  r-x
)

[[ "$MODE" == apply || "$MODE" == verify || "$MODE" == rollback ]] || {
  echo "usage: $0 [apply|verify|rollback]" >&2
  exit 2
}

[[ "$EUID" -eq 0 ]] || {
  echo "root identity required" >&2
  exit 3
}
id "$RUNTIME_USER" >/dev/null
command -v getfacl >/dev/null
command -v setfacl >/dev/null
command -v runuser >/dev/null

if id -nG "$RUNTIME_USER" | tr ' ' '\n' | grep -Fx "$FORBIDDEN_GROUP" >/dev/null; then
  echo "runtime identity must not belong to $FORBIDDEN_GROUP" >&2
  exit 4
fi

# Validate the entire transaction before the first mutation. Apply requires a
# clean pre-state; rollback accepts a clean or exactly applied partial state.
for index in "${!PATHS[@]}"; do
  path="${PATHS[$index]}"
  [[ -d "$path" && ! -L "$path" ]]
  [[ "$(stat -c '%a:%U:%G' "$path")" == "${EXPECTED[$index]}" ]]
  acl="$(getfacl -cp -- "$path")"
  entry="$(printf '%s\n' "$acl" | grep -E "^user:${RUNTIME_USER}:" || true)"
  [[ "$(printf '%s\n' "$acl" | grep -Fxc "mask::${MASKS[$index]}")" -eq 1 ]]
  case "$MODE" in
    apply)
      [[ -z "$entry" ]]
      ;;
    verify)
      [[ "$entry" == "user:${RUNTIME_USER}:--x" ]]
      ;;
    rollback)
      [[ -z "$entry" || "$entry" == "user:${RUNTIME_USER}:--x" ]]
      ;;
  esac
done

if [[ "$MODE" == apply ]]; then
  for path in "${PATHS[@]}"; do
    setfacl --no-mask -m "user:${RUNTIME_USER}:--x" -- "$path"
  done
elif [[ "$MODE" == rollback ]]; then
  for path in "${PATHS[@]}"; do
    if getfacl -cp -- "$path" | grep -Fx "user:${RUNTIME_USER}:--x" >/dev/null; then
      setfacl --no-mask -x "user:${RUNTIME_USER}" -- "$path"
    fi
  done
fi

for index in "${!PATHS[@]}"; do
  path="${PATHS[$index]}"
  acl="$(getfacl -cp -- "$path")"
  [[ "$(stat -c '%a:%U:%G' "$path")" == "${EXPECTED[$index]}" ]]
  [[ "$(printf '%s\n' "$acl" | grep -Fxc "mask::${MASKS[$index]}")" -eq 1 ]]
  if [[ "$MODE" == rollback ]]; then
    ! printf '%s\n' "$acl" | grep -E "^user:${RUNTIME_USER}:" >/dev/null
    ! runuser -u "$RUNTIME_USER" -- test -x "$path"
  else
    [[ "$(printf '%s\n' "$acl" | grep -Fxc "user:${RUNTIME_USER}:--x")" -eq 1 ]]
    runuser -u "$RUNTIME_USER" -- test -x "$path"
    runuser -u "$RUNTIME_USER" -- test ! -r "$path"
    runuser -u "$RUNTIME_USER" -- test ! -w "$path"
  fi
done

echo "COMMERCIAL_PATH_ACCESS_OK mode=$MODE"
