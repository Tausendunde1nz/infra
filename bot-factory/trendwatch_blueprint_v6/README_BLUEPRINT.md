# Trendwatch Blueprint v6

Dieser Ordner ist der *Blueprint* für Bots der TU1NZ Bot-Fabrik.

- Basis: Trendwatch v6.4 (stabiler Stand vom 16.11.2025)
- Enthält: NodeJS-Bot mit HTTP-API, Healthchecks und /trends-Command
- Zweck: Vorlage zum Klonen für neue Bots (z.B. Nischen-Bots, Kanal-Bots)

WICHTIG:
- Diesen Ordner NICHT direkt für produktive Bots verändern.
- Für neue Bots immer eine Kopie erstellen (z.B. `cp -r trendwatch_blueprint_v6 my_new_bot`).
- Bot-spezifische ENV-Dateien (Tokens, Chat-IDs) liegen IMMER außerhalb des Repos.

Im Telegram-Chat mit dem Blueprint-Stand:
- `/ping`  → `pong ✅`
- `/trends` → gibt Beispiel-Trends zurück (Demo-Daten oder Test-Fetcher).

Stand: v6.4 – Bot läuft stabil in Docker (`trendwatch-bot`).
