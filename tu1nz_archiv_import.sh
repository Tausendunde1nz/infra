#!/usr/bin/env bash
set -uo pipefail

ARCH_SRC="/opt/tu1nz_repos/docs"
ARCH_DST="/opt/tu1nz_repos/archive"
LOG_DIR="/var/log/tausendunde1nz"
LOG_FILE="$LOG_DIR/archiv_latest.log"

mkdir -p "$ARCH_DST"
mkdir -p "$LOG_DIR"

declare -A MAP=(
  # System-Dokumentation / Status
  ["System_Dokumentation_"]="system/dokumentation"
  ["TU1NZ_Hauptdokumentation_"]="system/dokumentation"
  ["System_StatusReport_"]="system/statusberichte"
  ["TU1NZ_Systemzustand_"]="system/statusberichte"
  ["TU1NZ_HealthCheck_"]="system/healthmonitor"

  # Regeln / Policies / Systemordnung
  ["TU1NZ_Systembetriebsordnung"]="system/regeln"
  ["TU1NZ_Systemregeln_"]="system/regeln"

  # Sicherheit / Hardening / Integrität
  ["T1NZ_Integrity_"]="system/sicherheit"
  ["T1NZ_SSH_Hardening_"]="system/sicherheit"
  ["T1NZ_Lockclean_"]="system/sicherheit"

  # Infrastruktur / Backup / Restore
  ["TU1NZ_Server_Struktur_"]="infrastruktur/backup"
  ["T1NZ_Restore_Smoke_"]="infrastruktur/backup"

  # Roadmaps / Systementwicklung
  ["TU1NZ_Roadmap_"]="roadmaps/systementwicklung"
  ["TU1NZ_3Tage_TurboRoadmap"]="roadmaps/systementwicklung"
  ["TU1NZ_Phase5"]="roadmaps/systementwicklung"
  ["TU1NZ_Agentmodus_Offline_Strategie_"]="roadmaps/systementwicklung"

  # Monetarisierung / Finance
  ["TU1NZ_Monetarisierungsstart_"]="finance/monetarisierung"
  ["Finanzplan_"]="finance/monetarisierung"

  # Bots / Trendwatch
  ["Trendwatch_"]="bots/trendwatch"
  ["TW_Status_"]="bots/trendwatch"

  # Meta / Logs / Reports
  ["upload_log"]="meta/logs"
  ["TU1NZ_Implementierungsvermerk_"]="meta/logs"
)

log() {
  echo "$@" | tee -a "$LOG_FILE"
}

log "=== TU1NZ ARCHIV IMPORT v1.1 START ==="
log "Quelle:    $ARCH_SRC"
log "Zielroot:  $ARCH_DST"
log ""

shopt -s nullglob

for f in "$ARCH_SRC"/*; do
  [ -f "$f" ] || continue
  file=$(basename "$f")
  target=""

  for key in "${!MAP[@]}"; do
    if [[ "$file" == $key* ]]; then
      target="${MAP[$key]}"
      break
    fi
  done

  if [[ -z "$target" ]]; then
    log "⛔ $file -> UNBEKANNT (nicht verschoben)"
    continue
  fi

  dest_dir="$ARCH_DST/$target"
  mkdir -p "$dest_dir"

  log "📁 Verschiebe: $file -> $target"
  /bin/mv -n "$f" "$dest_dir"/
done

log ""
log "=== TU1NZ ARCHIV IMPORT v1.1 ENDE ==="
