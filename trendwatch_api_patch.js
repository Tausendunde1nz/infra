module.exports = function registerApi(app) {
  // --- API v1 basic endpoints ---
  app.get("/api/v1/ping", (req, res) => {
    res.json({ ok: true, pong: true, ts: Date.now() });
  });

  app.get("/api/v1/health", (req, res) => {
    res.json({ ok: true, status: "api alive" });
  });

  // --- Main API ---
  app.get("/api/status", (req, res) => {
    res.json({ ok: true, msg: "API Skeleton online" });
  });

  app.get("/api/fetch/test", (req, res) => {
    res.json({ ok: true, test: "fetch-test working" });
  });

  app.post("/api/fetch", (req, res) => {
    res.json({ ok: true, msg: "fetch POST endpoint reached", body: req.body || null });
  });

  app.get("/api/trends/test", (req, res) => {
    res.json({ ok: true, test: "trends-test working" });
  });
};
