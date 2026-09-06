const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const nodemailer = require('nodemailer');
const { promisify } = require('node:util');

const rootDirectory = path.resolve(__dirname, '..');
const dataDirectory = path.join(__dirname, 'data');
const usersFile = path.join(dataDirectory, 'users.json');
const resetTokensFile = path.join(dataDirectory, 'reset-tokens.json');
const port = Number(process.env.PORT) || 3000;
const sessions = new Map();
const scrypt = promisify(crypto.scrypt);
const chatSecret = process.env.CHAT_SECRET || 'development-chat-secret-change-me';
const resetTokenLifetimeMs = 30 * 60 * 1000;
const publicUrl = process.env.PUBLIC_URL || `http://localhost:${port}`;
const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
}) : null;

fs.mkdirSync(dataDirectory, { recursive: true });
if (!fs.existsSync(usersFile)) fs.writeFileSync(usersFile, '[]');
if (!fs.existsSync(resetTokensFile)) fs.writeFileSync(resetTokensFile, '{}');

function readUsers() {
  return JSON.parse(fs.readFileSync(usersFile, 'utf8'));
}

function writeUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function readResetTokens() {
  return JSON.parse(fs.readFileSync(resetTokensFile, 'utf8'));
}

function writeResetTokens(tokens) {
  fs.writeFileSync(resetTokensFile, JSON.stringify(tokens, null, 2));
}

function hashResetToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function sendResetEmail(user, token) {
  if (!mailer) throw new Error('SMTP is not configured');
  const resetUrl = `${publicUrl}/reset-password.html?token=${encodeURIComponent(token)}`;
  await mailer.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: user.email,
    subject: "Reset your Ash's PC Building password",
    text: `Use this link to reset your password. It expires in 30 minutes:\n\n${resetUrl}`,
    html: `<p>Use this link to reset your password. It expires in 30 minutes:</p><p><a href="${resetUrl}">Reset your password</a></p>`
  });
}

function parseCookies(request) {
  return Object.fromEntries((request.headers.cookie || '').split(';').filter(Boolean).map((cookie) => {
    const [name, ...value] = cookie.trim().split('=');
    return [name, decodeURIComponent(value.join('='))];
  }));
}

function sendJson(response, statusCode, body, headers = {}) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers
  });
  response.end(JSON.stringify(body));
}

function setSessionCookie(response, sessionId) {
  response.setHeader('Set-Cookie', `session=${sessionId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`);
}

function clearSessionCookie(response) {
  response.setHeader('Set-Cookie', 'session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
}

function getSessionUser(request) {
  const sessionId = parseCookies(request).session;
  const userId = sessions.get(sessionId);
  return readUsers().find((user) => user.id === userId) || null;
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', (chunk) => {
      body += chunk;
      if (body.length > 10000) request.destroy();
    });
    request.on('end', () => {
      try {
        resolve(JSON.parse(body || '{}'));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    request.on('error', reject);
  });
}

async function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derivedKey = await scrypt(password, salt, 64);
  return { salt, hash: derivedKey.toString('hex') };
}

async function passwordsMatch(password, user) {
  const { hash } = await hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.passwordHash, 'hex'));
}

function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email };
}

function createChatToken(user) {
  const payload = Buffer.from(JSON.stringify({
    userId: user.id,
    name: user.name,
    expiresAt: Date.now() + 5 * 60 * 1000
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', chatSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

async function handleApi(request, response) {
  try {
    if (request.method === 'GET' && request.url === '/api/me') {
      const user = getSessionUser(request);
      return sendJson(response, 200, { user: user ? publicUser(user) : null });
    }

    if (request.method === 'GET' && request.url === '/api/chat-token') {
      const user = getSessionUser(request);
      if (!user) return sendJson(response, 401, { error: 'You must be logged in to use chat.' });
      return sendJson(response, 200, { token: createChatToken(user) });
    }

    if (request.method === 'POST' && request.url === '/api/forgot-password') {
      const body = await readBody(request);
      const email = String(body.email || '').trim().toLowerCase();
      const user = readUsers().find((candidate) => candidate.email === email);
      const genericMessage = 'If an account exists for that email, a password reset link has been sent.';
      if (!user) return sendJson(response, 200, { message: genericMessage });
      if (!mailer) return sendJson(response, 503, { error: 'Password reset email is not configured on the server yet.' });

      const rawToken = crypto.randomBytes(32).toString('hex');
      const tokens = readResetTokens();
      tokens[hashResetToken(rawToken)] = { userId: user.id, expiresAt: Date.now() + resetTokenLifetimeMs };
      writeResetTokens(tokens);
      await sendResetEmail(user, rawToken);
      return sendJson(response, 200, { message: genericMessage });
    }

    if (request.method === 'POST' && request.url === '/api/reset-password') {
      const body = await readBody(request);
      const tokenHash = hashResetToken(String(body.token || ''));
      const tokens = readResetTokens();
      const reset = tokens[tokenHash];
      const password = String(body.password || '');
      if (!reset || reset.expiresAt < Date.now() || password.length < 8) {
        return sendJson(response, 400, { error: 'This reset link is invalid or expired.' });
      }

      const users = readUsers();
      const user = users.find((candidate) => candidate.id === reset.userId);
      if (!user) return sendJson(response, 400, { error: 'This reset link is invalid or expired.' });
      const { salt, hash } = await hashPassword(password);
      user.salt = salt;
      user.passwordHash = hash;
      writeUsers(users);
      delete tokens[tokenHash];
      writeResetTokens(tokens);
      return sendJson(response, 200, { ok: true });
    }

    if (request.method === 'POST' && ['/api/register', '/api/login'].includes(request.url)) {
      const body = await readBody(request);
      const users = readUsers();
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');

      if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 8) {
        return sendJson(response, 400, { error: 'Enter a valid email and a password of at least 8 characters.' });
      }

      if (request.url === '/api/register') {
        const name = String(body.name || '').trim();
        if (name.length < 2) return sendJson(response, 400, { error: 'Enter your full name.' });
        if (users.some((user) => user.email === email)) return sendJson(response, 409, { error: 'An account with that email already exists.' });

        const { salt, hash } = await hashPassword(password);
        const user = { id: crypto.randomUUID(), name, email, salt, passwordHash: hash, createdAt: new Date().toISOString() };
        users.push(user);
        writeUsers(users);
        const sessionId = crypto.randomBytes(32).toString('hex');
        sessions.set(sessionId, user.id);
        setSessionCookie(response, sessionId);
        return sendJson(response, 201, { user: publicUser(user) });
      }

      const user = users.find((candidate) => candidate.email === email);
      if (!user || !(await passwordsMatch(password, user))) return sendJson(response, 401, { error: 'Email or password is incorrect.' });
      const sessionId = crypto.randomBytes(32).toString('hex');
      sessions.set(sessionId, user.id);
      setSessionCookie(response, sessionId);
      return sendJson(response, 200, { user: publicUser(user) });
    }

    if (request.method === 'POST' && request.url === '/api/logout') {
      const sessionId = parseCookies(request).session;
      sessions.delete(sessionId);
      clearSessionCookie(response);
      return sendJson(response, 200, { ok: true });
    }

    sendJson(response, 404, { error: 'Not found' });
  } catch (error) {
    console.error(error);
    sendJson(response, 500, { error: 'Something went wrong. Please try again.' });
  }
}

const server = http.createServer((request, response) => {
  if (request.url.startsWith('/api/')) return handleApi(request, response);

  const requestedPath = request.url === '/' ? '/index.html' : request.url.split('?')[0];
  const filePath = path.normalize(path.join(rootDirectory, requestedPath));
  const privateDirectory = path.join(rootDirectory, 'auth-server');
  if (!filePath.startsWith(rootDirectory) || filePath.startsWith(privateDirectory) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    response.writeHead(404);
    return response.end('Not found');
  }

  const contentTypes = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg' };
  response.writeHead(200, { 'Content-Type': contentTypes[path.extname(filePath)] || 'application/octet-stream' });
  fs.createReadStream(filePath).pipe(response);
});

server.listen(port, () => console.log(`Website and account server running at http://localhost:${port}`));
