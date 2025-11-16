# T1NZ – Infra Audit v7.2
# Klassifikation aller relevanten Dateien (A–E)
# Stand: 2025-11-16

---

## A – Produktiv, versioniert, gehört ins Repo

- .gitignore
- README.md
- docker-compose.trendwatch.yml
- tu1nz_create_golden.sh
- TRENDWATCH_DOC_LINKS.txt
- trends_fetcher.js

### A.1 – Trendwatch Blueprint (Template, aber produktiv relevant)

- bot-factory/ACTIVE_BLUEPRINT.conf
- bot-factory/trendwatch_blueprint_v6/Dockerfile
- bot-factory/trendwatch_blueprint_v6/docker-compose.yml
- bot-factory/trendwatch_blueprint_v6/package.json
- bot-factory/trendwatch_blueprint_v6/package-lock.json
- bot-factory/trendwatch_blueprint_v6/README_BLUEPRINT.md
- bot-factory/trendwatch_blueprint_v6/README_TRENDWATCH_v6.md
- bot-factory/trendwatch_blueprint_v6/src/index.js
- bot-factory/trendwatch_blueprint_v6/src/trends_fetcher.js

### A.2 – Bot-Template (allgemeine Basis)

- bot-template-src/package.json
- bot-template-src/package-lock.json
- bot-template-src/src/index.js
- bot-template-src/src/trends_fetcher.js

---

## B – Test / temporär / kann langfristig entfernt werden

- bot-factory/test_blueprint_bot_min/Dockerfile
- bot-factory/test_blueprint_bot_min/docker-compose.yml
- bot-factory/test_blueprint_bot_min/package.json
- bot-factory/test_blueprint_bot_min/package-lock.json
- bot-factory/test_blueprint_bot_min/src/index.js
- bot-factory/test_blueprint_run/docker-compose.yml
- bot-factory/test_blueprint_run/package.json
- bot-factory/test_blueprint_run/package-lock.json

### B.1 – Generische Test-Artefakte

- node_modules/  (alle Projekte – NICHT tracken, nur Hinweis)

---

## C – Sensibel, bleibt lokal (niemals ins Git)

- trendwatch.env
- notify.conf
- bot-factory/trendwatch_blueprint_v6/.env
- bot-factory/test_blueprint_bot_min/.env
- bot-factory/test_blueprint_run/.env

### C.1 – Tokens / Chat-IDs (nur als Kategorie, keine echten Werte)

- BOT_TOKEN
- ALERT_BOT_TOKEN
- ALERT_CHAT_ID
- weitere Zugangsdaten (API-Keys, Secrets etc.)

---

## D – Archiv / Snapshots / Baselines

### D.1 – Snapshots / Tarballs

- snapshots/bot_blueprint_v6_2025-11-16.tar.gz
- snapshots/trendwatch_v6.3_2025-11-16.tar.gz
- snapshots/trendwatch_v6.4_2025-11-16.tar.gz

### D.2 – Baseline-Dateien

- trendwatch_api_v6_baseline.js
- bot-factory/test_blueprint_bot_min/src/index_vanilla_backup.js
- trendwatch-src/index_vanilla_backup.js

### D.3 – Backup-Verzeichnisse und -Dateien

- control_backup_v6/INTEGRITY_REFERENCE.txt
- control_backup_v6/INTEGRITY_REFERENCE.sha256
- control_backup_v6/LAST_SYNC_OK
- notify.conf.backup
- tu1nz_archiv_import.sh.bak_2025-11-15

---

## E – Unklar / später entscheiden (Patch/Helper)

- api_patch.js
- trendwatch_api_patch.js
- tu1nz_archiv_import.sh
- weitere Patch-/Helper-Skripte (zukünftige Varianten)

---

## Hinweis

Dieses Dokument ist eine **reine Bestandsaufnahme (Audit)** der aktuellen Infra-Struktur
unter `/opt/tu1nz_repos/infra`.

- Noch KEINE Änderungen, Löschungen oder Commits.
- Grundlage für das geplante „Clean Infra Commit“ im Rahmen von v7.1 / v7.2.

---

## E-Set Entscheidung v7.2 (2025-11-16)

- **api_patch.js**
  - Status: Legacy-Patch, wird aktuell nicht produktiv verwendet.
  - Klassifikation: **D – Archiv / Snapshots / Baselines**
  - Begründung: Aktive Patch-Logik liegt in `trendwatch_api_patch.js` (A-Set).
- Weitere Patch-/Helper-Skripte:
  - Aktuell **keine** weiteren Dateien im E-Set.

Damit ist das E-Set zum Stand v7.2 leer; alle Dateien sind A–D eindeutig zugeordnet.
