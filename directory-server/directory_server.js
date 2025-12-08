console.log(">>> Matryoshka Directory Server v2 (with heartbeat) starting...");

const express = require("express");
const fs = require("fs");
const path = require("path");
const DATA_FILE = path.join(__dirname, "relays.json");

const app = express();

app.use(express.json());

// Basit request logger (log için)
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});

// -------- Validation Helpers --------
function isValidIp(ip) {
  // Basit IPv4 kontrolü: 4 parça, hepsi 0-255 arası sayı
  const parts = ip.split(".");
  if (parts.length !== 4) return false;

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) return false; // sadece rakam
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

function isValidPort(port) {
  const n = Number(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}
function saveRelaysToFile() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(relays, null, 2));
    console.log(">>> Saved relays to relays.json");
  } catch (err) {
    console.error(">>> Failed to save relays.json:", err);
  }
}

// In-memory relay storage
// relays: { [id]: { ip, port, public_key, last_seen } }
let relays = {};

// Sunucu açılırken dosyayı yükle
if (fs.existsSync(DATA_FILE)) {
  try {
    const raw = fs.readFileSync(DATA_FILE);
    relays = JSON.parse(raw);
    console.log(">>> Loaded relays from JSON file:", Object.keys(relays));
  } catch (err) {
    console.error(">>> Error loading relays.json:", err);
  }
} else {
  console.log(">>> No relays.json file found, starting fresh.");
}

// ROOT
app.get("/", (req, res) => {
  res.send("Matryoshka Directory Server is alive 🚀");
});

// REGISTER  (POST /register)
app.post("/register", (req, res) => {
  const { id, ip, port, public_key } = req.body;

  console.log("[REGISTER]", req.body);

  // Eksik alan kontrolü
  if (!id || !ip || !port || !public_key) {
    return res.status(400).json({
      success: false,
      error: "Missing required fields (id, ip, port, public_key)",
    });
  }

  // IP format kontrolü
  if (!isValidIp(ip)) {
    return res.status(400).json({
      success: false,
      error: "Invalid IP address format",
    });
  }

  // Port aralık kontrolü
  if (!isValidPort(port)) {
    return res.status(400).json({
      success: false,
      error: "Invalid port (must be integer between 1 and 65535)",
    });
  }

  // Duplicate ID kontrolü
  if (relays[id]) {
    return res.status(400).json({
      success: false,
      error: "Relay with this ID already exists",
    });
  }

  // Relay’i kaydet
  relays[id] = {
    ip,
    port,
    public_key,
    last_seen: Date.now(),
  };
  saveRelaysToFile();

  return res.status(201).json({
    success: true,
    message: "Relay registered successfully",
  });
});

// GET RELAYS  (GET /relays)
app.get("/relays", (req, res) => {
  const relayList = Object.entries(relays).map(([id, info]) => ({
    id,
    ip: info.ip,
    port: info.port,
    public_key: info.public_key,
    // last_seen'i response'a koymuyoruz, sadece içerde kullanıyoruz
  }));

  return res.status(200).json({
    relays: relayList,
    count: relayList.length,
  });
});

// DELETE /relay/:id
app.delete("/relay/:id", (req, res) => {
  const { id } = req.params;

  console.log("[DELETE]", id);

  if (!relays[id]) {
    return res.status(404).json({
      success: false,
      error: "Relay not found",
    });
  }

  delete relays[id];
  saveRelaysToFile();

  return res.json({
    success: true,
    message: "Relay removed successfully",
    relay_id: id,
  });
});

// GET /health
app.get("/health", (req, res) => {
  const now = Date.now();
  const TIMEOUT = 5 * 60 * 1000; // 5 dakika

  const relayIds = Object.keys(relays);
  const totalRelays = relayIds.length;

  let activeRelays = 0;

  for (const id of relayIds) {
    const relay = relays[id];
    if (now - relay.last_seen <= TIMEOUT) {
      activeRelays++;
    }
  }

  const inactiveRelays = totalRelays - activeRelays;

  return res.json({
    status: "ok",
    relayCount: totalRelays,
    activeRelays,
    inactiveRelays,
    uptime_seconds: Math.floor(process.uptime()),
  });
});

// HEARTBEAT  (POST /heartbeat)
app.post("/heartbeat", (req, res) => {
  const { id } = req.body;

  console.log("[HEARTBEAT]", req.body);

  if (!id) {
    return res.status(400).json({ success: false, error: "Missing relay ID" });
  }

  if (!relays[id]) {
    return res.status(404).json({ success: false, error: "Relay not found" });
  }

  relays[id].last_seen = Date.now();

  return res.json({
    success: true,
    message: "Heartbeat received",
    relay_id: id,
    last_seen: relays[id].last_seen,
  });
});

// CLEANUP: 5 dakika heartbeat gelmeyen relay'i sil
setInterval(() => {
  const now = Date.now();

  for (const [id, relay] of Object.entries(relays)) {
    if (now - relay.last_seen > 5 * 60 * 1000) {
      console.log(`[CLEANUP] Removing inactive relay: ${id}`);
      delete relays[id];
      saveRelaysToFile();
    }
  }
}, 10 * 1000); // her 10 saniyede bir kontrol

// START SERVER
// Not: Dökümanda 5000 yazıyor ama sende 5000 AirPlay tarafından işgal edildiği için 5600 kullanıyoruz.
const PORT = 5600;

app.listen(PORT, () => {
  console.log(`Matryoshka Directory Server running on port ${PORT}`);
});
