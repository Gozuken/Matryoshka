const express = require("express");
const app = express();

app.use(express.json());

app.post("/heartbeat", (req, res) => {
  console.log(">>> /heartbeat HIT, body =", req.body);
  return res.json({ ok: true, body: req.body });
});

const PORT = 5600;
app.listen(PORT, () => {
  console.log("TEST server listening on port", PORT);
});
