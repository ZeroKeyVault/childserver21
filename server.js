// server2.js - Persistent WebSocket Relay with File Storage
// Dependencies: npm install ws

const WebSocket = require('ws');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;
const DB_FILE = path.join(__dirname, 'child_data.json');

// --- PERSISTENCE LAYER ---

let db = {
  users: {}, // userId -> { identityKey, signedPreKey, oneTimeKeys: [] }
  messages: {}, // userId -> [ { ...msg } ]
  vaults: {}, // vaultId -> { members: [userId, ...], type: 'private'|'public' }
};

function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = fs.readFileSync(DB_FILE, 'utf8');
      db = JSON.parse(data);
      console.log('Database loaded.');
    } else {
      saveDB();
    }
  } catch (e) {
    console.error('Failed to load DB:', e);
  }
}

function saveDB() {
  try {
    // Atomic write to prevent corruption
    const tempFile = DB_FILE + '.tmp';
    fs.writeFileSync(tempFile, JSON.stringify(db, null, 2));
    fs.renameSync(tempFile, DB_FILE);
  } catch (e) {
    console.error('Failed to save DB:', e);
  }
}

// Save periodically (every 5 seconds if dirty)
setInterval(saveDB, 5000);

// --- SERVER SETUP ---

const server = http.createServer((req, res) => {
  res.writeHead(200);
  res.end('Child Secure Relay Active');
});

const wss = new WebSocket.Server({ server });
const connections = new Map(); // userId -> ws

loadDB();

// --- HELPER FUNCTIONS ---

function pruneOldMessages() {
  const ONE_WEEK = 7 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  let changed = false;
  
  for (const uid in db.messages) {
    const originalLen = db.messages[uid].length;
    db.messages[uid] = db.messages[uid].filter(m => (now - m.ts) < ONE_WEEK);
    if (db.messages[uid].length !== originalLen) changed = true;
  }
  if (changed) saveDB();
}
setInterval(pruneOldMessages, 3600000); // Hourly

wss.on('connection', (ws) => {
  let authenticatedUser = null;

  ws.on('message', (message) => {
    let msg;
    try { msg = JSON.parse(message); } catch (e) { return; }

    try {
      switch (msg.type) {
        case 'identify':
          handleIdentify(ws, msg);
          break;
        case 'publish-keys':
          handlePublishKeys(ws, msg, authenticatedUser);
          break;
        case 'fetch-keys':
          handleFetchKeys(ws, msg);
          break;
        case 'join-vault':
          handleJoinVault(ws, msg, authenticatedUser);
          break;
        case 'send-message':
        case 'send-file-chunk':
          handleRelay(ws, msg, authenticatedUser);
          break;
        case 'leave-vault':
          handleLeaveVault(ws, msg, authenticatedUser);
          break;
        case 'nuke':
          handleNuke(ws, msg, authenticatedUser);
          break;
        case 'ping':
          ws.send(JSON.stringify({ type: 'pong' }));
          break;
      }
    } catch (err) {
      console.error('Error handling message:', err);
    }
  });

  ws.on('close', () => {
    if (authenticatedUser) {
      connections.delete(authenticatedUser);
    }
  });

  function handleIdentify(ws, msg) {
    authenticatedUser = msg.userHash;
    connections.set(authenticatedUser, ws);
    
    // Create user entry if not exists
    if (!db.users[authenticatedUser]) {
      db.users[authenticatedUser] = { identityKey: null, signedPreKey: null };
    }

    // Send queued messages
    const queue = db.messages[authenticatedUser] || [];
    if (queue.length > 0) {
      queue.forEach(m => ws.send(JSON.stringify(m)));
      db.messages[authenticatedUser] = []; // Clear queue after sending
      saveDB();
    }
    
    ws.send(JSON.stringify({ type: 'identified', userHash: authenticatedUser }));
  }

  function handlePublishKeys(ws, msg, user) {
    if (!user) return;
    db.users[user].identityKey = msg.identityKey;
    db.users[user].signedPreKey = msg.signedPreKey;
    saveDB();
  }

  function handleFetchKeys(ws, msg) {
    const target = msg.targetUser;
    const userData = db.users[target];
    if (userData) {
      ws.send(JSON.stringify({
        type: 'keys-found',
        user: target,
        identityKey: userData.identityKey,
        signedPreKey: userData.signedPreKey,
        reqId: msg.reqId
      }));
    } else {
      ws.send(JSON.stringify({ type: 'keys-missing', user: target, reqId: msg.reqId }));
    }
  }

  function handleJoinVault(ws, msg, user) {
    if (!user) return;
    const vId = msg.vaultId;
    
    if (!db.vaults[vId]) {
      db.vaults[vId] = { members: [], type: msg.isPrivate ? 'private' : 'public' };
    }
    
    if (!db.vaults[vId].members.includes(user)) {
      // For private vaults, strict 2 person limit
      if (db.vaults[vId].type === 'private' && db.vaults[vId].members.length >= 2) {
        ws.send(JSON.stringify({ type: 'error', message: 'Private vault full' }));
        return;
      }
      db.vaults[vId].members.push(user);
      saveDB();
    }
    
    // Notify about other members (vital for private vault key exchange)
    const others = db.vaults[vId].members.filter(m => m !== user);
    ws.send(JSON.stringify({ type: 'vault-joined', vaultId: vId, members: others, isPrivate: db.vaults[vId].type === 'private' }));
    
    // Notify others that I joined
    others.forEach(m => {
      const sock = connections.get(m);
      if (sock && sock.readyState === WebSocket.OPEN) {
        sock.send(JSON.stringify({ type: 'member-joined', vaultId: vId, newUser: user }));
      }
    });
  }

  function handleRelay(ws, msg, sender) {
    if (!sender) return;
    const vId = msg.vaultId;
    if (!db.vaults[vId]) return;

    const members = db.vaults[vId].members;
    const timestamp = Date.now();
    
    // Enhance message with server metadata
    const packet = {
      ...msg,
      from: sender,
      ts: timestamp
    };

    members.forEach(m => {
      if (m === sender) return;
      
      const socket = connections.get(m);
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify(packet));
      } else {
        // Queue message for offline user
        // Note: For file chunks, we generally don't queue them to save DB space, 
        // but for text we do.
        if (msg.type === 'send-message') {
           if (!db.messages[m]) db.messages[m] = [];
           db.messages[m].push(packet);
        }
      }
    });
    
    // If it's a message, acknowledge persistence
    if (msg.type === 'send-message') saveDB();
  }

  function handleLeaveVault(ws, msg, user) {
    if (!user || !db.vaults[msg.vaultId]) return;
    const v = db.vaults[msg.vaultId];
    v.members = v.members.filter(m => m !== user);
    if (v.members.length === 0) {
      delete db.vaults[msg.vaultId];
    }
    saveDB();
  }

  function handleNuke(ws, msg, user) {
    if (!user) return;
    
    // Remove from all vaults
    for (const vid in db.vaults) {
      db.vaults[vid].members = db.vaults[vid].members.filter(m => m !== user);
    }
    
    // Remove messages
    delete db.messages[user];
    
    // Remove user keys
    delete db.users[user];
    
    saveDB();
    ws.send(JSON.stringify({ type: 'nuked' }));
    connections.delete(user);
  }
});

server.listen(PORT, () => {
  console.log(`Child Persistent Server running on port ${PORT}`);
});
