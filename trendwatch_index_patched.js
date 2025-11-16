// src/index.js
const { Telegraf } = require('telegraf');
const express = require('express');
const registerApi = require('./api_patch.js');

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
bot.on('text', (ctx) => {
  const text = ctx.message.text;
  console.log(`[message] ${ctx.from.username || ctx.from.id} said: ${text}`);
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
registerApi(app);

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
