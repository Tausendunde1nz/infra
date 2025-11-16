# TU1NZ – Infra Audit v7.1
# Klassifikation aller relevanten Dateien (A–E)
# Stand: $(date +"%Y-%m-%d")

## A — Produktiv, versioniert, gehört ins Repo
- README.md
- docker-compose.trendwatch.yml
- t1nz_create_golden.sh
- trends_fetcher.js
- TRENDWATCH_DOC_LINKS.txt

### Blueprint & Template
- bot-factory/ACTIVE_BLUEPRINT.conf
- bot-factory/trendwatch_blueprint_v6/
  - docker-compose.yml
  - Dockerfile
  - package.json, package-lock.json
  - README_BLUEPRINT.md
  - README_TRENDWATCH_v6.md
  - src/
- bot-template-src/
  - package.json, package-lock.json
  - src/
- trendwatch-src/
  - Dockerfile
  - package.json, package-lock.json
  - README_TRENDWATCH_v6.md
  - src/index.js
  - src/trends_fetcher.js

## B — Test / temporär / kann langfristig entfernt werden
- bot-factory/test_blueprint_bot_min/
- bot-factory/test_blueprint_run/
- *alle* node_modules/ (in allen Projekten)

## C — Sensibel, bleibt lokal (niemals ins Git)
- trendwatch.env
- notify.conf
- alle Tokens/Chat-IDs (BOT_TOKEN, ALERT_BOT_TOKEN, ALERT_CHAT_ID)

## D — Archiv / Snapshots / Baselines
- snapshots/
  - bot_blueprint_v6.4_2025-11-16.tar.gz
  - trendwatch_v6.3_2025-11-16.tar.gz
  - trendwatch_v6.4_2025-11-16.tar.gz
- control_backup_v6/
- trendwatch-src/src/index_vanilla_backup.js
- bot-factory/test_blueprint_bot_min/src/index_vanilla_backup.js
- trendwatch_api_v6_baseline.js

## E — Unklar / später entscheiden
- api_patch.js
- trendwatch_api_patch.js
- weitere Patch-/Helper-Skripte

## Hinweis
Dies ist ausschließlich die Audit-Dokumentation.
Noch **keine** Änderungen, Löschungen oder Commits.
