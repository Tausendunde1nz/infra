# infra

---

## 🧩 Bot-Fabrik Blueprint (Stand v6.4)

Der zentrale Blueprint für alle zukünftigen Bots befindet sich hier:

- `bot-factory/trendwatch_blueprint_v6/`

Dieser Blueprint enthält:
- fertige NodeJS-Bot-Struktur  
- integrierte API (Health, Ready, Trends)  
- Telegraf-Bot inkl. Command-Handler  
- Platzhalter-Trend-Fetcher  
- Docker-Setup, das sofort läuft  

⚠️ **Wichtig:**  
Der Blueprint wird *niemals direkt verändert*.  
Für neue Bots IMMER zuerst kopieren, z. B.:

```bash
cp -r bot-factory/trendwatch_blueprint_v6 my_new_bot
