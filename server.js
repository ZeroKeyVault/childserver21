// ============================================================
// CHILD v2 — SECURE ENCRYPTED MESSAGING SERVER (PERSISTENT)
// Using SQLite (better-sqlite3) for persistent storage
// Supports:
//   - Private vaults (2-user only)
//   - Public/group vaults (unlimited)
//   - Offline message queues
//   - Chunked encrypted file relaying
//   - SenderKey distribution messages
//   - No key storage (zero-knowledge server)
// ============================================================

const WebSocket = require("ws");
const http = require("http");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const { v4: uuidv4 } = require("uuid");

const PORT = process.env.PORT || 8080;

// ============================================================
// DATABASE INITIALIZATION
// ============================================================

const db = new Database("child.db");

// Create tables if not exist
db.exec(`
CREATE TABLE IF NOT EXISTS vaults (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL CHECK (type IN ('private','public')),
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_members (
  vault_id TEXT NOT NULL,
  user_id  TEXT NOT NULL,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (vault_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  json TEXT NOT NULL,       -- encrypted blob
  delivered INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  last_seen INTEGER NOT NULL
);
`);

// ============================================================
// HELPER FUNCTIONS
// ============================================================

function now() {
  return Date.now();
}

function vaultExists(vaultId) {
  return !!db
    .prepare("SELECT id FROM vaults WHERE id = ?")
    .get(vaultId);
}

function getVaultType(vaultId) {
  const row = db
    .prepare("SELECT type FROM vaults WHERE id = ?")
    .get(vaultId);
  return row ? row.type : null;
}

function getVaultMemberCount(vaultId) {
  const row = db
    .prepare("SELECT COUNT(*) c FROM vault_members WHERE vault_id = ?")
    .get(vaultId);
  return row.c;
}

function addVaultIfNotExists(vaultId, type) {
  if (!vaultExists(vaultId)) {
    db.prepare(
      "INSERT INTO vaults (id,type,created_at) VALUES (?,?,?)"
    ).run(vaultId, type, now());
  }
}

function addUserIfNotExists(userId) {
  db.prepare(
    "INSERT OR IGNORE INTO users (user_id,last_seen) VALUES (?,?)"
  ).run(userId, now());
}

function updateUserLastSeen(userId) {
  db.prepare("UPDATE users SET last_seen = ? WHERE user_id = ?")
    .run(now(), userId);
}

function addMemberToVault(vaultId, userId) {
  db.prepare(
    "INSERT OR IGNORE INTO vault_members (vault_id,user_id,joined_at) VALUES (?,?,?)"
  ).run(vaultId, userId, now());
}

function removeMemberFromVault(vaultId, userId) {
  db.prepare(
    "DELETE FROM vault_members WHERE vault_id = ? AND user_id = ?"
  ).run(vaultId, userId);
}

function getVaultMembers(vaultId) {
  return db.prepare(
    "SELECT user_id FROM vault_members WHERE vault_id = ?"
  ).all(vaultId).map(r => r.user_id);
}

function queueMessage(vaultId, senderId, blob, ts) {
  const id = uuidv4();
  const json = JSON.stringify(blob);

  db.prepare(`
    INSERT INTO messages (id,vault_id,sender_id,ts,json,delivered)
    VALUES (?,?,?,?,?,0)
  `).run(id, vaultId, senderId, ts, json);

  return id;
}

function getUndeliveredMessagesForUser(userId) {
  return db.prepare(`
    SELECT m.*
    FROM messages m
    JOIN vault_members v ON m.vault_id = v.vault_id
    WHERE v.user_id = ? AND m.delivered = 0
    ORDER BY m.ts ASC
  `).all(userId);
}

function markMessageDelivered(id) {
  db.prepare(
    "UPDATE messages SET delivered = 1 WHERE id = ?"
  ).run(id);
}

// ============================================================
// SERVER
// ============================================================

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("Child relay server active");
});

const wss = new WebSocket.Server({ server });

// Track connected clients in memory
const connections = new Map(); // userId -> ws

// ============================================================
// BROADCAST/RELAY LOGIC
// ============================================================

function deliverMessageToVaultMembers(senderId, vaultId, blob, ts) {
  const members = getVaultMembers(vaultId);
  const msgId = queueMessage(vaultId, senderId, blob, ts);

  for (const m of members) {
    if (m === senderId) continue;

    const ws = connections.get(m);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(
        JSON.stringify({
          type: "message",
          vaultId,
          blob,
          from: senderId,
          id: msgId,
          ts
        })
      );
      markMessageDelivered(msgId);
    }
  }
}

// ============================================================
// CONNECTION HANDLER
// ============================================================

wss.on("connection", ws => {
  let currentUserId = null;

  ws.on("message", data => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch (_) {
      return;
    }

    switch (msg.type) {

      // --------------------------------------------
      // IDENTIFY USER
      // --------------------------------------------
      case "identify": {
        currentUserId = msg.userHash;
        addUserIfNotExists(currentUserId);
        updateUserLastSeen(currentUserId);
        connections.set(currentUserId, ws);

        // Send offline messages
        const undelivered = getUndeliveredMessagesForUser(currentUserId);
        for (const m of undelivered) {
          ws.send(
            JSON.stringify({
              type: "message",
              vaultId: m.vault_id,
              blob: JSON.parse(m.json),
              from: m.sender_id,
              id: m.id,
              ts: m.ts
            })
          );
          markMessageDelivered(m.id);
        }

        ws.send(JSON.stringify({ type: "identify-ack", userId: currentUserId }));
        break;
      }

      // --------------------------------------------
      // JOIN VAULT
      // --------------------------------------------
      case "join-vault": {
        const { vaultId, isPrivate, userHash } = msg;
        const type = isPrivate ? "private" : "public";

        addVaultIfNotExists(vaultId, type);

        // Enforce private vault rules
        if (type === "private") {
          const count = getVaultMemberCount(vaultId);
          if (count >= 2) {
            ws.send(JSON.stringify({
              type: "error",
              message: "Private vault already has 2 members."
            }));
            return;
          }
        }

        addMemberToVault(vaultId, userHash);

        ws.send(JSON.stringify({
          type: "join-ack",
          vaultId
        }));
        break;
      }

      // --------------------------------------------
      // LEAVE VAULT
      // --------------------------------------------
      case "leave-vault": {
        const { vaultId, userHash } = msg;
        removeMemberFromVault(vaultId, userHash);
        ws.send(JSON.stringify({ type: "leave-ack", vaultId }));
        break;
      }

      // --------------------------------------------
      // RECEIVE ENCRYPTED MESSAGE (TEXT / FILE / CHUNKS)
      // --------------------------------------------
      case "send": {
        const { vaultId, blob, from, ts } = msg;
        deliverMessageToVaultMembers(from, vaultId, blob, ts);
        ws.send(JSON.stringify({ type: "send-ack" }));
        break;
      }

      // --------------------------------------------
      // USER WIPES EVERYTHING
      // --------------------------------------------
      case "nuke": {
        const userId = msg.userHash;

        // Remove from all vaults
        db.prepare("DELETE FROM vault_members WHERE user_id = ?")
          .run(userId);

        // Delete queued messages
        db.prepare(`
          UPDATE messages m
          SET delivered = 1
          WHERE m.id IN (
            SELECT m.id
            FROM messages m
            JOIN vault_members v ON m.vault_id = v.vault_id
            WHERE v.user_id = ?
          )
        `).run(userId);

        ws.send(JSON.stringify({ type: "nuked" }));
        break;
      }

      case "ping":
        ws.send(JSON.stringify({ type: "pong", ts: now() }));
        break;
    }
  });

  ws.on("close", () => {
    if (currentUserId) {
      connections.delete(currentUserId);
      updateUserLastSeen(currentUserId);
    }
  });

  ws.send(JSON.stringify({ type: "connected" }));
});

// ============================================================
// START SERVER
// ============================================================

server.listen(PORT, () => {
  console.log("Child server running on port", PORT);
});
