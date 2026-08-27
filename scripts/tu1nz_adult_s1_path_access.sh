#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-verify}"
RUNTIME_USER="tu1nz-adult-s1"
PATHS=(
  /opt/tu1nz_repos
  /opt/tu1nz_repos/releases
  /opt/tu1nz_repos/releases/adult-publishing
  /opt/tu1nz_repos/backups
  /opt/tu1nz_repos/backups/encrypted-system
  /etc/tu1nz
  /var/lib/tausendunde1nz/adult-publishing
)
EXPECTED=(
  2770:chatops:chatops
  2750:root:chatops
  2750:root:chatops
  2770:chatops:chatops
  2750:root:chatops
  750:root:chatops
  2750:root:chatops
)
MASKS=(
  rwx
  r-x
  r-x
  rwx
  r-x
  r-x
  r-x
)

[[ "$MODE" == apply || "$MODE" == verify ]] || {
  echo "usage: $0 [apply|verify]" >&2
  exit 2
}

id "$RUNTIME_USER" >/dev/null
command -v getfacl >/dev/null
command -v setfacl >/dev/null

for index in "${!PATHS[@]}"; do
  path="${PATHS[$index]}"
  [[ -d "$path" && ! -L "$path" ]]
  [[ "$(stat -c '%a:%U:%G' "$path")" == "${EXPECTED[$index]}" ]]
  if [[ "$MODE" == apply ]]; then
    setfacl -m "user:${RUNTIME_USER}:--x,mask::${MASKS[$index]}" -- "$path"
  fi
  getfacl -cp -- "$path" | grep -Fx "user:${RUNTIME_USER}:--x" >/dev/null
  getfacl -cp -- "$path" | grep -Fx "mask::${MASKS[$index]}" >/dev/null
  [[ "$(stat -c '%a:%U:%G' "$path")" == "${EXPECTED[$index]}" ]]
  runuser -u "$RUNTIME_USER" -- test -x "$path"
done

echo "S1_PATH_ACCESS_OK mode=$MODE"
