// ============================================================
// CHILD — PERSISTENT ENCRYPTED RELAY SERVER
// Using sqlite3 (works on Node 18–25 + Render)
// ============================================================

const WebSocket = require("ws");
const sqlite3 = require("sqlite3").verbose();
const { v4: uuidv4 } = require("uuid");

// ============================================================
// DATABASE INIT
// ============================================================

const db = new sqlite3.Database("./child.db", (err) => {
  if (err) {
    console.error("DATABASE ERROR:", err);
  } else {
    console.log("[DB] Connected");
  }
});

// Create tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      vaultId TEXT,
      fromUser TEXT,
      messageBlob TEXT,
      timestamp INTEGER
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS vaultMembers (
      vaultId TEXT,
      userId TEXT
    );
  `);
});

// Promisified DB helpers
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// ============================================================
// ACTIVE CLIENTS
// ============================================================
// userId → ws
const clients = new Map();

// vaultId → Set of connected user ids
const liveVaultMap = new Map();

function addToLiveVault(vaultId, userId) {
  if (!liveVaultMap.has(vaultId)) liveVaultMap.set(vaultId, new Set());
  liveVaultMap.get(vaultId).add(userId);
}

function removeFromLiveVault(userId) {
  for (const v of liveVaultMap.values()) {
    v.delete(userId);
  }
}

// ============================================================
// WEBSOCKET SERVER
// ============================================================
const wss = new WebSocket.Server({ port: 8080 }, () => {
  console.log("WS Server running on port 8080");
});

// ============================================================
// SEND TO MEMBER (if connected)
// ============================================================
function sendToUser(userId, packet) {
  const sock = clients.get(userId);
  if (sock && sock.readyState === WebSocket.OPEN) {
    sock.send(JSON.stringify(packet));
    return true;
  }
  return false;
}

// ============================================================
// BROADCAST WITHIN VAULT
// ============================================================
function broadcastToVault(vaultId, packet, exceptUser = null) {
  const members = liveVaultMap.get(vaultId);
  if (!members) return;

  for (const uid of members) {
    if (uid === exceptUser) continue;
    sendToUser(uid, packet);
  }
}

// ============================================================
// STORE OFFLINE MESSAGE
// ============================================================
async function storeMessage(vaultId, fromUser, messageBlob) {
  const id = uuidv4();
  const timestamp = Date.now();

  await dbRun(
    `INSERT INTO messages (id, vaultId, fromUser, messageBlob, timestamp)
     VALUES (?, ?, ?, ?, ?)`,
    [
      id,
      vaultId,
      fromUser,
      JSON.stringify(messageBlob),
      timestamp
    ]
  );
}

// ============================================================
// DELIVER STORED MESSAGES ON LOGIN
// ============================================================
async function deliverOfflineMessages(userId, userVaults) {
  const rows = await dbAll(
    `SELECT * FROM messages WHERE vaultId IN (${userVaults.map(()=>"?").join(",")})
     ORDER BY timestamp ASC`,
    userVaults
  );

  for (const row of rows) {
    const payload = {
      type: "message",
      vaultId: row.vaultId,
      from: row.fromUser,
      blob: JSON.parse(row.messageBlob),
      ts: row.timestamp
    };

    sendToUser(userId, payload);
  }
}

// ============================================================
// HANDLE CLIENT CONNECTION
// ============================================================
wss.on("connection", (ws) => {

  let userId = null;

  ws.on("message", async (data) => {
    let msg;
    try { msg = JSON.parse(data); }
    catch { return; }

    switch (msg.type) {

      // --------------------------------------------------------
      // IDENTIFY
      // --------------------------------------------------------
      case "identify":
        userId = msg.userHash;
        clients.set(userId, ws);

        // Join vaults the client says they belong to
        for (const v of msg.vaults) {
          addToLiveVault(v, userId);
          await dbRun(
            `INSERT INTO vaultMembers (vaultId, userId) VALUES (?, ?)`,
            [v, userId]
          ).catch(()=>{});
        }

        // Deliver offline messages
        await deliverOfflineMessages(userId, msg.vaults);

        sendToUser(userId, { type: "identify-ack" });
        break;


      // --------------------------------------------------------
      // JOIN VAULT
      // --------------------------------------------------------
      case "join-vault":
        if (!userId) return;

        addToLiveVault(msg.vaultId, userId);

        await dbRun(
          `INSERT INTO vaultMembers (vaultId, userId) VALUES (?, ?)`,
          [msg.vaultId, userId]
        ).catch(()=>{});

        sendToUser(userId, { type: "join-ack", vaultId: msg.vaultId });
        break;


      // --------------------------------------------------------
      // SEND MESSAGE
      // --------------------------------------------------------
      case "send":
        if (!userId) return;

        const packet = {
          type: "message",
          vaultId: msg.vaultId,
          from: msg.from,
          blob: msg.blob,
          ts: msg.ts
        };

        // Store persistently
        await storeMessage(msg.vaultId, msg.from, msg.blob);

        // Broadcast to live members
        broadcastToVault(msg.vaultId, packet, msg.from);

        sendToUser(msg.from, { type: "send-ack", id: msg.id });
        break;


      // --------------------------------------------------------
      // NUKE ACCOUNT (delete all stored messages)
      // --------------------------------------------------------
      case "nuke":
        if (!userId) return;
        await dbRun(`DELETE FROM messages WHERE fromUser = ?`, [userId]);
        break;


      // --------------------------------------------------------
      // KEEPALIVE
      // --------------------------------------------------------
      case "ping":
        sendToUser(userId, { type: "pong" });
        break;
    }
  });

  // --------------------------------------------------------------
  // ON CLOSE
  // --------------------------------------------------------------
  ws.on("close", () => {
    if (userId) {
      clients.delete(userId);
      removeFromLiveVault(userId);
    }
  });
});

