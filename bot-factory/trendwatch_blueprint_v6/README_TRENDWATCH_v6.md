# Trendwatch Bot v6 – Blueprint

## Zweck
- Dient als Blueprint für die Bot-Fabrik (TU1NZ Bot-Template).
- Bietet:
  - Telegram-Bot mit Basis-Kommandos
  - HTTP-API für Health-/Status-Checks und Trend-Daten
  - Trennung von Hauptbot und Alert-/Status-Bot

## Telegram-Bot

**Kommandos:**
- `/start` – Begrüßung / kurze Erklärung
- `/ping` – einfacher Lebenszeichen-Check
- `/whoami` – zeigt Telegram-Userinfo
- `/trends` – ruft aktuelle Trends über den Fetcher ab und formatiert sie als Liste

**Env-Variablen (kommen aus \`trendwatch.env\`):**
- \`BOT_TOKEN\` – Hauptbot (Trendwatch / User-Interaktion)
- \`ALERT_BOT_TOKEN\` – Alert-/Systemstatus-Bot
- \`ALERT_CHAT_ID\` – Admin-/Status-Channel
- \`PORT\` – HTTP-Port im Container (Standard: 3000)

## HTTP-API

Läuft im Container auf Port **3000**, von außen über Host-Port **3011** erreichbar (siehe \`docker-compose.trendwatch.yml\`).

Wichtige Endpoints:
- `GET /healthz` – einfacher Healthcheck (Antwort: `ok`)
- `GET /api/status` – Status der API (`{"ok": true, "msg": "API Skeleton online"}`)
- `GET /api/fetch/test` – Test-Endpunkt für Fetch-Layer
- `GET /api/trends/test` – Test-Endpunkt für Trends-Layer
- `GET /api/trends/live` – nutzt den echten \`trends_fetcher.js\`

## Trends-Fetcher

Datei: \`src/trends_fetcher.js\`

- Exportiert `fetchTrends()`
- Liefert aktuell Demo-Daten (TikTok/Instagram/YouTube Trends mit Score).
- Später hier Anbindung an echte Quellen (TikTok/IG/YT APIs, Scraper, Trend-APIs).

## Build & Run (Docker)

Ausführen im Ordner \`/opt/tu1nz_repos/infra\`:

1. Image bauen:
   \`docker build -t tu1nz/bot-template:latest trendwatch-src\`

2. Container starten:
   \`docker compose -f docker-compose.trendwatch.yml up -d\`

3. Logs prüfen:
   \`docker logs trendwatch-bot --tail 60\`

## Schnelltests

Auf dem Server:

- Health:
  \`curl -s http://localhost:3011/healthz\`
- API-Status:
  \`curl -s http://localhost:3011/api/status\`
- Live-Trends:
  \`curl -s http://localhost:3011/api/trends/live\`

Im Telegram-Chat mit dem Bot:

- \`/ping\` → `pong ✅`
- \`Hallo\` → `Echo: Hallo`
- \`/trends\` → formatierte Liste der Demo-Trends

## Snapshot / Version

Aktuelle stabile Version:
- Snapshot: \`snapshots/trendwatch_v6.4_2025-11-16.tar.gz\`
- Enthält:
  - \`trendwatch-src\`
  - \`docker-compose.trendwatch.yml\`
  - \`trendwatch.env\`

