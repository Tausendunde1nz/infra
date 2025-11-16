module.exports = {
  fetchTrends: async () => {
    return {
      ok: true,
      fetched_at: Date.now(),
      items: [
        { id: 1, title: "Testtrend 1" },
        { id: 2, title: "Testtrend 2" }
      ]
    };
  }
};
