// server.js - WebSocket relay server for Child messaging app
// Deploy on Render as a Web Service
// Start command: node server.js

const WebSocket = require('ws');
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;

// In-memory message queue: userId -> [{vaultId, blob, id, from, ts}]
const messageQueue = new Map();
// Active connections: userId -> WebSocket
const connections = new Map();
// Vault membership tracking: vaultId -> Set of userIds
const vaultMembers = new Map();

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Child relay server running');
});

const wss = new WebSocket.Server({ server });

// Clean up old messages periodically (messages older than 7 days)
const MESSAGE_RETENTION = 7 * 24 * 60 * 60 * 1000; // 7 days
setInterval(() => {
  const now = Date.now();
  for (const [userId, messages] of messageQueue.entries()) {
    const filtered = messages.filter(m => (now - m.ts) < MESSAGE_RETENTION);
    if (filtered.length === 0) {
      messageQueue.delete(userId);
    } else {
      messageQueue.set(userId, filtered);
    }
  }
}, 60 * 60 * 1000); // Run every hour

function generateMessageId() {
  return crypto.randomBytes(16).toString('base64url');
}

function addToQueue(userId, messageData) {
  if (!messageQueue.has(userId)) {
    messageQueue.set(userId, []);
  }
  messageQueue.get(userId).push(messageData);
}

function getAndClearQueue(userId) {
  const messages = messageQueue.get(userId) || [];
  messageQueue.delete(userId);
  return messages;
}

function addVaultMember(vaultId, userId) {
  if (!vaultMembers.has(vaultId)) {
    vaultMembers.set(vaultId, new Set());
  }
  vaultMembers.get(vaultId).add(userId);
}

function removeVaultMember(vaultId, userId) {
  if (vaultMembers.has(vaultId)) {
    vaultMembers.get(vaultId).delete(userId);
    if (vaultMembers.get(vaultId).size === 0) {
      vaultMembers.delete(vaultId);
    }
  }
}

function getVaultMembers(vaultId) {
  return vaultMembers.get(vaultId) || new Set();
}

wss.on('connection', (ws) => {
  let currentUserId = null;
  let userVaults = new Set();

  ws.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch (e) {
      return;
    }

    switch (msg.type) {
      case 'identify':
        // User identifies with their userHash and current vaults
        currentUserId = msg.userHash;
        connections.set(currentUserId, ws);
        
        // Register user to their vaults
        if (Array.isArray(msg.vaults)) {
          msg.vaults.forEach(vaultId => {
            userVaults.add(vaultId);
            addVaultMember(vaultId, currentUserId);
          });
        }

        // Send queued messages
        const queued = getAndClearQueue(currentUserId);
        queued.forEach(qMsg => {
          ws.send(JSON.stringify({
            type: 'message',
            vaultId: qMsg.vaultId,
            blob: qMsg.blob,
            from: qMsg.from,
            id: qMsg.id,
            ts: qMsg.ts
          }));
        });

        ws.send(JSON.stringify({ type: 'identify-ack', userId: currentUserId }));
        break;

      case 'join-vault':
        // User joins a vault
        if (!currentUserId) break;
        const joinVaultId = msg.vaultId;
        userVaults.add(joinVaultId);
        addVaultMember(joinVaultId, currentUserId);
        ws.send(JSON.stringify({ type: 'join-ack', vaultId: joinVaultId }));
        break;

      case 'send':
        // User sends encrypted message to vault
        if (!currentUserId) break;
        const vaultId = msg.vaultId;
        const blob = msg.blob; // {iv, ct, fileData?}
        const from = msg.from || currentUserId;
        const ts = msg.ts || Date.now();
        const msgId = generateMessageId();

        const messageData = {
          vaultId,
          blob,
          from,
          id: msgId,
          ts
        };

        // Relay to all vault members
        const members = getVaultMembers(vaultId);
        let delivered = false;

        members.forEach(memberId => {
          if (memberId === currentUserId) return; // Don't send to self
          
          const memberWs = connections.get(memberId);
          if (memberWs && memberWs.readyState === WebSocket.OPEN) {
            memberWs.send(JSON.stringify({
              type: 'message',
              vaultId,
              blob,
              from,
              id: msgId,
              ts
            }));
            delivered = true;
          } else {
            // Queue for offline user
            addToQueue(memberId, messageData);
          }
        });

        // Send ack to sender
        ws.send(JSON.stringify({ type: 'send-ack', id: msgId, delivered }));
        break;

      case 'nuke':
        // User requests complete data deletion
        if (!currentUserId) break;
        
        // Clear message queue
        messageQueue.delete(currentUserId);
        
        // Remove from all vaults
        userVaults.forEach(vId => {
          removeVaultMember(vId, currentUserId);
        });
        
        // Clear connection
        connections.delete(currentUserId);
        
        ws.send(JSON.stringify({ type: 'nuked' }));
        
        currentUserId = null;
        userVaults.clear();
        break;

      case 'leave-vault':
        if (!currentUserId) break;
        const leaveVaultId = msg.vaultId;
        userVaults.delete(leaveVaultId);
        removeVaultMember(leaveVaultId, currentUserId);
        ws.send(JSON.stringify({ type: 'leave-ack', vaultId: leaveVaultId }));
        break;

      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
        break;
    }
  });

  ws.on('close', () => {
    if (currentUserId) {
      connections.delete(currentUserId);
      // Keep vault memberships - user may reconnect
    }
  });

  ws.on('error', (err) => {
    console.error('WebSocket error:', err);
  });

  // Send initial connection ack
  ws.send(JSON.stringify({ type: 'connected' }));
});

server.listen(PORT, () => {
  console.log(`Child relay server listening on port ${PORT}`);
  console.log(`WebSocket endpoint: ws://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  wss.close(() => {
    server.close(() => {
      console.log('Server closed');
      process.exit(0);
    });
  });
});
