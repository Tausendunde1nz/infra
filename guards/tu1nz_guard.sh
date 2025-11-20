#!/usr/bin/env bash
source /etc/tu1nz/paths.env
set -euo pipefail

# Auto-Detection des Repos
if [ -d "/opt/tu1nz_repos/.git" ]; then
  REPO_ROOT="/opt/tu1nz_repos"
elif [ -d "/tausendunde1nz/.git" ]; then
  REPO_ROOT="/tausendunde1nz"
else
  echo "[SKIP] Kein Git-Repository gefunden – Guard übersprungen."
  exit 0
fi

# Prüfen auf Änderungen im Repo
cd "$REPO_ROOT"
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "[WARN] Uncommittete Änderungen im Repo ($REPO_ROOT)"
  exit 2
fi

# Prüfen auf Dateien außerhalb des Repos, die in den letzten 10 Minuten verändert wurden
find /opt /var/lib/tausendunde1nz -type f -mmin -10 ! -path "$REPO_ROOT/*" 2>/dev/null \
  | grep -vE '(\.log|\.json|\.tmp)$' && {
  echo "[WARN] Änderungen außerhalb des Repos entdeckt!"
  exit 3
}

echo "[OK] Tu1nz Guard Check – keine Abweichungen erkannt."
exit 0
