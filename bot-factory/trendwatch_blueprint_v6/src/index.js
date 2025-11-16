// src/index.js
const { Telegraf } = require('telegraf');
const express = require('express');

// === ENV VARS ===
// Hauptbot: chattet mit Usern (tu1nz_test_bot)
const BOT_TOKEN = process.env.BOT_TOKEN;

// Alarm-Bot: schickt dir System-Status (SystemStatusTausendundE1NZ_Bot)
const ALERT_BOT_TOKEN = process.env.ALERT_BOT_TOKEN;
const ALERT_CHAT_ID = process.env.ALERT_CHAT_ID;

// HTTP Port für Healthcheck
const PORT = process.env.PORT || 3000;

// --- Sanity Check Logs (nur zur Kontrolle) ---
console.log("Loaded env:");
console.log("BOT_TOKEN present? ", !!BOT_TOKEN);
console.log("ALERT_BOT_TOKEN present? ", !!ALERT_BOT_TOKEN);
console.log("ALERT_CHAT_ID: ", ALERT_CHAT_ID);

// === 1. Hauptbot initialisieren ===
if (!BOT_TOKEN) {
  console.error("❌ BOT_TOKEN fehlt. Kann Hauptbot nicht starten.");
  process.exit(1);
}
const bot = new Telegraf(BOT_TOKEN);

// /start -> Begrüßung
bot.start((ctx) => {
  ctx.reply('👋 Hallo! Ich bin dein TU1NZ Test Bot und laufe gerade live.');
});

// /ping -> simple check
bot.command('ping', (ctx) => {
  ctx.reply('pong ✅');
});

// /whoami -> Userdaten
bot.command('whoami', (ctx) => {
  const u = ctx.from;
  ctx.reply(`Du bist ${u.username || u.first_name || u.id}`);
});

// Fallback: jede Textnachricht
bot.on('text', async (ctx, next) => {
  const text = ctx.message.text;
  console.log(`[message] ${ctx.from.username || ctx.from.id} said: ${text}`);
  if (text && text.startsWith('/')) {
    // Slash-Commands wie /trends an die Command-Handler durchreichen
    return next();
  }
  ctx.reply(`Echo: ${text}`);
});


// === 2. Alarm-/Status-Bot vorbereiten ===
// (eigener Telegraf-Client NUR für Notify, kein Polling nötig)
let alertBot = null;
if (ALERT_BOT_TOKEN && ALERT_CHAT_ID) {
  alertBot = new Telegraf(ALERT_BOT_TOKEN);

  // Helper-Funktion für Statusmeldungen
  const sendStatus = async (msg) => {
    try {
      await alertBot.telegram.sendMessage(ALERT_CHAT_ID, `🔔 Systemstatus:\n${msg}`);
      console.log("[alert] status message sent to admin chat");
    } catch (err) {
      console.error("[alert] failed to send status message:", err.message);
    }
  };

  // Wir schicken beim Start direkt einen Ping
  sendStatus("✅ Bot gestartet und bereit.");
} else {
  console.log("⚠️ Kein ALERT_BOT_TOKEN/ALERT_CHAT_ID gesetzt. Status-Pings deaktiviert.");
}

// === 3. HTTP Server (Health, Ready) ===
const app = express();

app.get('/healthz', (req, res) => {
  console.log("[http] /healthz check");
  res.send('ok');
});

app.get('/ready', (req, res) => {
  res.send('ready');
});

// Start HTTP server
app.listen(PORT, () => {
  console.log(`HTTP server listening on ${PORT}`);
});

// === 4. Hauptbot starten (Long Polling)
bot.launch()
  .then(() => {
    console.log('🤖 Hauptbot (tu1nz_test_bot) läuft jetzt im Polling-Modus');
  })
  .catch(err => {
    console.error('❌ Hauptbot konnte nicht starten:', err);
    process.exit(1);
  });

// Clean shutdown
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));

// === API v1 – simple JSON endpoints (non-breaking) ===
app.get('/api/v1/ping', (req, res) => {
  res.json({ ok: true, pong: true, ts: Date.now() });
});

app.get('/api/v1/health', (req, res) => {
  res.json({ ok: true, status: 'api alive' });
});

app.get('/api/status', (req, res) => {
  res.json({ ok: true, msg: 'API Skeleton online' });
});

app.get('/api/fetch/test', (req, res) => {
  res.json({ ok: true, test: 'fetch-test working' });
});

app.get('/api/trends/test', (req, res) => {
  res.json({ ok: true, test: 'trends-test working' });
});

// === LIVE TRENDS ENDPOINT ===
const { fetchTrends } = require('./trends_fetcher');

app.get('/api/trends/live', async (req, res) => {
  try {
    const data = await fetchTrends();
    res.json({
      ok: true,
      source: 'live-fetcher',
      data
    });
  } catch (err) {
    console.error('Error in /api/trends/live:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// === TELEGRAM COMMAND: /trends ===
bot.command('trends', async (ctx) => {
  try {
    const { fetchTrends } = require('./trends_fetcher');
    const data = await fetchTrends();

    if (!data || !data.items || data.items.length === 0) {
      return ctx.reply("⚠️ Keine Trends verfügbar.");
    }

    let msg = "🔥 *Aktuelle Trends* 🔥\n\n";
    for (const t of data.items) {
      msg += `• *${t.title}* (platform: ${t.platform}, score: ${t.score})\n`;
    }

    ctx.replyWithMarkdown(msg);

  } catch (err) {
    console.error("Error in /trends command:", err);
    ctx.reply("❌ Fehler beim Abrufen der Trends.");
  }
});
