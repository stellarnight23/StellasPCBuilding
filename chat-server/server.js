const { WebSocketServer } = require('ws');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const chatPort = Number(process.env.CHAT_PORT) || 8080;
const chatSecret = process.env.CHAT_SECRET || 'development-chat-secret-change-me';
const wss = new WebSocketServer({ port: chatPort });
const rooms = new Map();
const historyFile = path.join(__dirname, 'chat-history.json');
const historyRetentionMs = 14 * 24 * 60 * 60 * 1000;
const dashboardClients = new Set();

if (!fs.existsSync(historyFile)) fs.writeFileSync(historyFile, '{}');

function readHistory() {
  try {
    return JSON.parse(fs.readFileSync(historyFile, 'utf8'));
  } catch (error) {
    console.error('Could not read chat history:', error);
    return {};
  }
}

function pruneHistory(history) {
  const cutoff = Date.now() - historyRetentionMs;
  let changed = false;

  Object.keys(history).forEach((roomId) => {
    const messages = Array.isArray(history[roomId]) ? history[roomId] : [];
    const recentMessages = messages.filter((message) => message.timestamp > cutoff);
    if (recentMessages.length !== messages.length) changed = true;

    if (recentMessages.length) {
      history[roomId] = recentMessages;
    } else {
      delete history[roomId];
      if (messages.length) changed = true;
    }
  });

  if (changed) fs.writeFileSync(historyFile, JSON.stringify(history, null, 2));
  return history;
}

const history = pruneHistory(readHistory());

function saveHistory() {
  fs.writeFileSync(historyFile, JSON.stringify(history, null, 2));
}

function getRoomMessages(roomId) {
  const cutoff = Date.now() - historyRetentionMs;
  const storedMessages = history[roomId] || [];
  const messages = storedMessages.filter((message) => message.timestamp > cutoff);
  history[roomId] = messages;
  if (messages.length !== storedMessages.length) saveHistory();
  return messages;
}

console.log(`Multi-room chat server started on ws://localhost:${chatPort}`);

function verifyChatToken(token) {
  if (!token) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;

  const expectedSignature = crypto.createHmac('sha256', chatSecret).update(payload).digest('base64url');
  if (signature.length !== expectedSignature.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) return null;

  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.expiresAt > Date.now() ? data : null;
  } catch {
    return null;
  }
}

function sendJson(ws, data) {
  if (ws.readyState === 1) {
    ws.send(JSON.stringify(data));
  }
}

function getOpenRooms() {
  return Array.from(rooms, ([roomId, room]) => ({
    roomId,
    participants: room.clients.size,
    customerName: room.customerName,
    lastMessage: getRoomMessages(roomId).at(-1)?.text || null
  }));
}

function broadcastRooms() {
  const data = { type: 'rooms', rooms: getOpenRooms() };
  dashboardClients.forEach((client) => sendJson(client, data));
}

function leaveRoom(ws) {
  if (!ws.currentRoomId) return;

  const room = rooms.get(ws.currentRoomId);
  if (room) {
    room.clients.delete(ws);
    if (room.clients.size === 0) {
      rooms.delete(ws.currentRoomId);
    }
  }

  console.log(`User has left ${ws.currentRoomId}.`);
  ws.currentRoomId = null;
  broadcastRooms();
}

wss.on('connection', (ws, request) => {
  const requestUrl = new URL(request.url, `http://${request.headers.host}`);
  const token = requestUrl.searchParams.get('token');
  const isDashboardConnection = requestUrl.searchParams.get('dashboard') === '1';
  const user = isDashboardConnection ? { userId: 'owner', name: 'Ash' } : verifyChatToken(token);
  if (!user) {
    ws.close(1008, 'Login required');
    return;
  }

  ws.user = user;
  ws.currentRoomId = null;
  ws.isDashboard = false;

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());

      if (data.type === 'dashboard') {
        ws.isDashboard = true;
        dashboardClients.add(ws);
        sendJson(ws, { type: 'rooms', rooms: getOpenRooms() });
        return;
      }

      if (data.type === 'listRooms' && ws.isDashboard) {
        sendJson(ws, { type: 'rooms', rooms: getOpenRooms() });
        return;
      }

      if (data.type === 'join' && data.roomId) {
        leaveRoom(ws);

        if (!rooms.has(data.roomId)) {
          rooms.set(data.roomId, { clients: new Set(), customerName: data.roomId.startsWith('account-') ? ws.user.name : 'Customer' });
        }

        const room = rooms.get(data.roomId);
        ws.currentRoomId = data.roomId;
        room.clients.add(ws);
        console.log(`User ${ws.user.name} joined room: ${data.roomId}`);

        getRoomMessages(data.roomId).forEach((chatMessage) => {
          sendJson(ws, chatMessage);
        });
        broadcastRooms();
        return;
      }

      if (data.type === 'message' && ws.currentRoomId && data.text) {
        const room = rooms.get(ws.currentRoomId);
        if (!room) return;

        const chatMessage = {
          type: 'message',
          senderId: ws.user.userId,
          senderName: ws.user.name,
          text: data.text,
          timestamp: Date.now()
        };
        getRoomMessages(ws.currentRoomId).push(chatMessage);
        history[ws.currentRoomId] = history[ws.currentRoomId].slice(-100);
        saveHistory();
        room.clients.forEach((client) => sendJson(client, chatMessage));
        broadcastRooms();
      }
    } catch (err) {
      console.error('Error while processing message:', err);
    }
  });

  ws.on('close', () => {
    dashboardClients.delete(ws);
    leaveRoom(ws);
  });
});
