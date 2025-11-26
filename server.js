// server2.js
// Persistent WebSocket relay + PreKey registry for simplified X3DH + file chunk relay
//
// Usage: node server2.js
// Requires: npm i express ws body-parser
//
// Security note: Server only stores encrypted blobs and key metadata (prekeys). It does not
// attempt to decrypt messages. The server persists DB to disk (db.json). For production,
// use a proper DB and rotate encryption keys at rest.

const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const bodyParser = require('body-parser');
const WebSocket = require('ws');

const DB_PATH = path.join(__dirname, 'db.json');
const PORT = process.env.PORT || 8080;

// Load or initialize DB
let DB = {
  users: {},          // userId -> { identityPub (base64url), signPub (base64url), lastSeen }
  prekeys: {},        // userId -> { prekeys: [pub1, pub2...], oneTimePrekeys: [pub...] }
  vaults: {},         // vaultId -> { creator, members: Set([...]), createdAt }
  queues: {},         // userId -> [ message objects ... ]
  messagesRetentionMs: 7 * 24 * 60 * 60 * 1000
};

function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      DB = JSON.parse(raw);
      // convert members arrays back to sets if needed
      for (const v of Object.values(DB.vaults)) {
        if (Array.isArray(v.members)) v.members = new Set(v.members);
        else if (!v.members) v.members = new Set();
      }
      console.log('DB loaded');
    } else {
      persistDB();
    }
  } catch (e) {
    console.error('Failed to load DB:', e);
  }
}

function persistDB() {
  // convert Sets to arrays for JSON
  const copy = JSON.parse(JSON.stringify(DB, (k, v) => {
    if (v instanceof Set) return Array.from(v);
    return v;
  }));
  fs.writeFileSync(DB_PATH, JSON.stringify(copy, null, 2), 'utf8');
}

// periodic DB persist
setInterval(() => persistDB(), 5000);

loadDB();

const app = express();
app.use(bodyParser.json({ limit: '5mb' }));

// Simple health
app.get('/', (req, res) => res.send('Child relay persistent server'));

// Register or update a user's prekey bundle
// Body: { userId, identityPub, signPub (optional), prekeys: [pub...], oneTimePrekeys: [pub...] }
app.post('/register_prekeys', (req, res) => {
  const body = req.body;
  if (!body || !body.userId || !body.identityPub || !Array.isArray(body.prekeys)) {
    return res.status(400).json({ error: 'invalid' });
  }
  const uid = body.userId;
  DB.users[uid] = DB.users[uid] || {};
  DB.users[uid].identityPub = body.identityPub;
  if (body.signPub) DB.users[uid].signPub = body.signPub;
  DB.users[uid].lastSeen = Date.now();

  DB.prekeys[uid] = DB.prekeys[uid] || { prekeys: [], oneTimePrekeys: [] };

  // Overwrite current prekeys (rotate)
  DB.prekeys[uid].prekeys = body.prekeys.slice(0, 50); // limit to 50 stored
  if (Array.isArray(body.oneTimePrekeys)) {
    DB.prekeys[uid].oneTimePrekeys = body.oneTimePrekeys.slice(0, 200);
  }

  persistDB();

  return res.json({ ok: true });
});

// Fetch prekey bundle for a user
// GET /get_prekeys/:userId
// returns { identityPub, prekeys: [...], oneTimePrekey? }
app.get('/get_prekeys/:userId', (req, res) => {
  const uid = req.params.userId;
  if (!DB.prekeys[uid] || !DB.users[uid]) {
    return res.status(404).json({ error: 'not_found' });
  }
  const pk = DB.prekeys[uid];
  const one = pk.oneTimePrekeys && pk.oneTimePrekeys.length > 0 ? pk.oneTimePrekeys.shift() : null;
  persistDB();
  return res.json({
    identityPub: DB.users[uid].identityPub,
    prekeys: pk.prekeys,
    oneTimePrekey: one || null,
    signPub: DB.users[uid].signPub || null
  });
});

// Fetch user metadata (for listing vault members etc.)
app.get('/user/:userId', (req, res) => {
  const uid = req.params.userId;
  if (!DB.users[uid]) return res.status(404).json({ error: 'not_found' });
  return res.json(DB.users[uid]);
});

// WebSocket server for relaying encrypted messages and handling identify/join/send/leave/nuke, file chunks, and x3dh handshake messages
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const connections = new Map(); // userId -> ws

// helper: queue message for offline user
function queueMessage(userId, msg) {
  DB.queues[userId] = DB.queues[userId] || [];
  DB.queues[userId].push(msg);
  persistDB();
}

function deliverQueued(userId) {
  if (!connections.has(userId)) return;
  const ws = connections.get(userId);
  const list = DB.queues[userId] || [];
  for (const m of list) {
    try {
      ws.send(JSON.stringify(m));
    } catch (e) {
      console.error('deliverQueued send error', e);
    }
  }
  DB.queues[userId] = [];
  persistDB();
}

// remove old queued messages older than retention
setInterval(() => {
  const now = Date.now();
  for (const uid of Object.keys(DB.queues)) {
    DB.queues[uid] = (DB.queues[uid] || []).filter(m => {
      if (!m.ts) return true;
      return (now - m.ts) < DB.messagesRetentionMs;
    });
  }
  persistDB();
}, 60 * 60 * 1000);

wss.on('connection', (ws) => {
  let userId = null;
  ws.send(JSON.stringify({ type: 'connected', ts: Date.now() }));

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }

    switch (msg.type) {
      case 'identify':
        // { type:'identify', userId, vaults: [] }
        if (!msg.userId) return;
        userId = msg.userId;
        connections.set(userId, ws);
        DB.users[userId] = DB.users[userId] || { lastSeen: Date.now() };
        DB.users[userId].lastSeen = Date.now();
        // add to vault membership if provided
        if (Array.isArray(msg.vaults)) {
          for (const vId of msg.vaults) {
            DB.vaults[vId] = DB.vaults[vId] || { creator: userId, members: new Set(), createdAt: Date.now() };
            DB.vaults[vId].members.add(userId);
          }
          persistDB();
        }
        // deliver queued messages
        deliverQueued(userId);
        ws.send(JSON.stringify({ type: 'identify-ack', userId }));
        break;

      case 'join-vault':
        // { type:'join-vault', vaultId, userId }
        if (!msg.vaultId || !msg.userId) return;
        DB.vaults[msg.vaultId] = DB.vaults[msg.vaultId] || { creator: msg.userId, members: new Set(), createdAt: Date.now() };
        DB.vaults[msg.vaultId].members.add(msg.userId);
        persistDB();

        // notify vault creator (if online)
        const creator = DB.vaults[msg.vaultId].creator;
        if (creator && connections.has(creator)) {
          connections.get(creator).send(JSON.stringify({
            type: 'vault-join-request',
            vaultId: msg.vaultId,
            userId: msg.userId,
            ts: Date.now()
          }));
        }
        ws.send(JSON.stringify({ type: 'join-ack', vaultId: msg.vaultId }));
        break;

      case 'leave-vault':
        if (!msg.vaultId || !msg.userId) return;
        if (DB.vaults[msg.vaultId]) {
          DB.vaults[msg.vaultId].members.delete(msg.userId);
          persistDB();
        }
        // ack
        ws.send(JSON.stringify({ type: 'leave-ack', vaultId: msg.vaultId }));
        break;

      case 'send':
        // Encrypted send to vault
        // { type:'send', vaultId, from, header, blob, ts, meta }
        if (!msg.vaultId || !msg.from) return;
        const v = DB.vaults[msg.vaultId];
        if (!v) {
          // queue to creator? just ack with error
          ws.send(JSON.stringify({ type: 'send-ack', ok: false, error: 'unknown-vault' }));
          return;
        }
        const members = Array.from(v.members || []);
        let delivered = false;
        for (const member of members) {
          if (member === msg.from) continue;
          const envelope = Object.assign({}, msg, { target: member });
          if (connections.has(member)) {
            try {
              connections.get(member).send(JSON.stringify(envelope));
              delivered = true;
            } catch (e) {
              console.error('ws send error', e);
              queueMessage(member, envelope);
            }
          } else {
            queueMessage(member, envelope);
          }
        }
        ws.send(JSON.stringify({ type: 'send-ack', ok: true, delivered }));
        break;

      case 'x3dh-init':
      case 'x3dh-response':
        // Relay X3DH handshake messages between users (server does not inspect keys)
        // { type:'x3dh-init', to, from, payload }
        if (!msg.to) return;
        if (connections.has(msg.to)) {
          connections.get(msg.to).send(JSON.stringify(msg));
        } else {
          queueMessage(msg.to, msg); // queued for offline
        }
        break;

      case 'file-chunk':
      case 'file-complete':
        // File chunk relay: server only relays encrypted chunk blobs
        // { type:'file-chunk', to, from, vaultId, chunkIndex, chunkData (base64), fileId, ts }
        if (!msg.to) return;
        if (connections.has(msg.to)) {
          connections.get(msg.to).send(JSON.stringify(msg));
        } else {
          queueMessage(msg.to, msg);
        }
        break;

      case 'nuke':
        // { type:'nuke', userId }
        if (!msg.userId) return;
        // remove queues, vault membership
        delete DB.queues[msg.userId];
        for (const vId of Object.keys(DB.vaults)) {
          DB.vaults[vId].members.delete(msg.userId);
        }
        persistDB();
        ws.send(JSON.stringify({ type: 'nuked' }));
        break;

      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
        break;

      default:
        // unknown type - ignore silently
        break;
    }
  });

  ws.on('close', () => {
    if (userId) {
      connections.delete(userId);
      // We do not remove from vault membership; they can rejoin.
    }
  });

  ws.on('error', (err) => {
    console.error('ws error', err);
  });
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received: persisting DB and shutting down');
  persistDB();
  wss.close(() => {
    server.close(() => process.exit(0));
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
