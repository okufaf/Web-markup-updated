import path from 'node:path';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import express from 'express';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import { createProxyMiddleware } from 'http-proxy-middleware';
import pg from 'pg';
import {
  resolveWmtsCapabilitiesUrl,
  parseWmtsCapabilities,
  pickSuggestedWmts,
  fillWmtsSampleTileUrl,
  isBlockedWmtsHost,
  buildWmtsRestUrl,
} from './wmts.js';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT ? Number(process.env.PORT) : 5173;
// Локально: localhost:8000. В Docker задайте ML_BACKEND_URL=http://backend:8000
const ML_BACKEND_URL = process.env.ML_BACKEND_URL || 'http://localhost:8000';
const DATABASE_URL = process.env.DATABASE_URL || '';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const DZZ_SESSIONS_FILE = path.join(DATA_DIR, 'dzz-sessions.enc');

const pool = DATABASE_URL
  ? new pg.Pool({ connectionString: DATABASE_URL })
  : null;

function isStrongPassword(password) {
  const p = String(password || '');
  if (p.length < 8) return false;
  if (!/[a-zа-яё]/.test(p)) return false;
  if (!/[A-ZА-ЯЁ]/.test(p)) return false;
  if (!/[^a-zA-Zа-яА-ЯёЁ0-9]/.test(p)) return false;
  return true;
}

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

const mlProxy = (mountPath) =>
  createProxyMiddleware({
    target: ML_BACKEND_URL,
    changeOrigin: true,
    logLevel: 'warn',
    pathRewrite: (p) => `${mountPath}${p}`,
  });

app.use('/api/v1/segmentation', mlProxy('/api/v1/segmentation'));
app.use('/api/v1/classification', mlProxy('/api/v1/classification'));

function rowToUser(row) {
  if (!row) return null;
  return {
    email: row.email,
    firstName: row.first_name ?? row.firstName,
    lastName: row.last_name ?? row.lastName,
    organization: row.organization,
    role: row.role,
    passwordHash: row.password_hash ?? row.passwordHash,
    lastLogin: row.last_login ?? row.lastLogin ?? null,
  };
}

async function ensureDataFiles() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(USERS_FILE);
  } catch {
    await fs.writeFile(USERS_FILE, JSON.stringify({ users: [] }, null, 2), 'utf8');
  }
}

async function waitForDb(retries = 30) {
  if (!pool) return;
  for (let i = 0; i < retries; i++) {
    try {
      await pool.query('SELECT 1');
      console.log('[auth] Postgres OK');
      return;
    } catch (e) {
      console.log(`[auth] waiting for Postgres… (${i + 1}/${retries})`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw new Error('Postgres unavailable');
}

async function findUserByEmail(email) {
  if (pool) {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return rowToUser(rows[0]);
  }
  await ensureDataFiles();
  const raw = await fs.readFile(USERS_FILE, 'utf8');
  const parsed = JSON.parse(raw);
  const users = Array.isArray(parsed.users) ? parsed.users : [];
  return users.find((u) => u.email === email) || null;
}

async function insertUser(user) {
  if (pool) {
    await pool.query(
      `INSERT INTO users (email, first_name, last_name, organization, role, password_hash, last_login)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [
        user.email,
        user.firstName,
        user.lastName,
        user.organization,
        user.role,
        user.passwordHash,
        user.lastLogin,
      ],
    );
    return;
  }
  await ensureDataFiles();
  const raw = await fs.readFile(USERS_FILE, 'utf8');
  const parsed = JSON.parse(raw);
  const users = Array.isArray(parsed.users) ? parsed.users : [];
  users.push(user);
  await fs.writeFile(USERS_FILE, JSON.stringify({ users }, null, 2), 'utf8');
}

async function updateUser(user) {
  if (pool) {
    await pool.query(
      `UPDATE users SET first_name=$2, last_name=$3, organization=$4, role=$5,
        password_hash=$6, last_login=$7 WHERE email=$1`,
      [
        user.email,
        user.firstName,
        user.lastName,
        user.organization,
        user.role,
        user.passwordHash,
        user.lastLogin,
      ],
    );
    return;
  }
  await ensureDataFiles();
  const raw = await fs.readFile(USERS_FILE, 'utf8');
  const parsed = JSON.parse(raw);
  const users = Array.isArray(parsed.users) ? parsed.users : [];
  const idx = users.findIndex((u) => u.email === user.email);
  if (idx === -1) throw new Error('NOT_FOUND');
  users[idx] = user;
  await fs.writeFile(USERS_FILE, JSON.stringify({ users }, null, 2), 'utf8');
}

async function deleteUser(email) {
  if (pool) {
    await pool.query('DELETE FROM users WHERE email = $1', [email]);
    return;
  }
  await ensureDataFiles();
  const raw = await fs.readFile(USERS_FILE, 'utf8');
  const parsed = JSON.parse(raw);
  const users = Array.isArray(parsed.users) ? parsed.users : [];
  const next = users.filter((u) => u.email !== email);
  await fs.writeFile(USERS_FILE, JSON.stringify({ users: next }, null, 2), 'utf8');
}

function publicUser(row) {
  return {
    email: row.email,
    firstName: row.firstName,
    lastName: row.lastName,
    organization: row.organization,
    role: row.role,
    lastLogin: row.lastLogin || null,
  };
}

function setAuthCookie(res, payload, remember) {
  const token = jwt.sign(payload, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: remember ? '30d' : '2h',
  });
  res.cookie('av_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: remember ? 1000 * 60 * 60 * 24 * 30 : 1000 * 60 * 60 * 2,
  });
}

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.av_session;
    if (!token) return res.status(401).json({ error: 'UNAUTHORIZED' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await findUserByEmail(decoded.email);
    if (!user) return res.status(401).json({ error: 'UNAUTHORIZED' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'UNAUTHORIZED' });
  }
}

app.get('/api/health', async (req, res) => {
  let db = 'file';
  if (pool) {
    try {
      await pool.query('SELECT 1');
      db = 'ok';
    } catch {
      db = 'down';
    }
  }
  let dzz = { available: false, connected: false };
  try {
    dzz = await probeDzzAvailability(req);
  } catch {
    dzz = { available: false, connected: false };
  }
  res.json({
    ok: true,
    db,
    ml: ML_BACKEND_URL,
    dzz: {
      available: Boolean(dzz.available),
      connected: Boolean(dzz.connected),
      status: dzz.available ? 'online' : 'unavailable',
    },
  });
});

app.post('/api/register', async (req, res) => {
  try {
    const { firstName, lastName, email, organization, role, password } = req.body || {};
    const cleanEmail = String(email || '').trim().toLowerCase();

    if (!cleanEmail || !cleanEmail.includes('@')) return res.status(400).json({ error: 'INVALID_EMAIL' });
    if (!firstName || !lastName || !organization || !role) return res.status(400).json({ error: 'INVALID_PROFILE' });
    if (!isStrongPassword(password)) return res.status(400).json({ error: 'WEAK_PASSWORD' });

    const existing = await findUserByEmail(cleanEmail);
    if (existing) return res.status(409).json({ error: 'EMAIL_EXISTS' });

    const passwordHash = await bcrypt.hash(String(password), 12);
    const lastLogin = new Date().toLocaleString('ru-RU');
    const user = {
      email: cleanEmail,
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      organization: organization.trim(),
      role: role.trim(),
      passwordHash,
      lastLogin,
    };
    await insertUser(user);
    setAuthCookie(res, { email: user.email }, true);
    res.json({ user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password, remember } = req.body || {};
    const cleanEmail = String(email || '').trim().toLowerCase();
    const user = await findUserByEmail(cleanEmail);
    if (!user) return res.status(401).json({ error: 'INVALID_CREDENTIALS' });

    const ok = await bcrypt.compare(String(password || ''), user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'INVALID_CREDENTIALS' });

    user.lastLogin = new Date().toLocaleString('ru-RU');
    await updateUser(user);

    setAuthCookie(res, { email: user.email }, !!remember);
    res.json({ user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.post('/api/logout', async (_req, res) => {
  res.clearCookie('av_session');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post('/api/profile', requireAuth, async (req, res) => {
  try {
    const { firstName, lastName, organization, role, newPassword } = req.body || {};
    const user = { ...req.user };

    if (typeof firstName === 'string') user.firstName = firstName.trim();
    if (typeof lastName === 'string') user.lastName = lastName.trim();
    if (typeof organization === 'string') user.organization = organization.trim();
    if (typeof role === 'string') user.role = role.trim();
    if (typeof newPassword === 'string' && newPassword.length) {
      if (!isStrongPassword(newPassword)) return res.status(400).json({ error: 'WEAK_PASSWORD' });
      user.passwordHash = await bcrypt.hash(newPassword, 12);
    }

    await updateUser(user);
    res.json({ user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.delete('/api/account', requireAuth, async (req, res) => {
  try {
    await deleteUser(req.user.email);
    res.clearCookie('av_session');
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

const DZZ_UPSTREAM = 'https://www.dzz.by';
const DZZ_DEFAULT_SERVICE = `${DZZ_UPSTREAM}/arcgis/rest/services/georesursDDZ/Polya_all/ImageServer`;
const DZZ_SESSION_TTL_MS = 1000 * 60 * 60 * 8;
const dzzSessions = new Map();
let dzzPersistTimer = null;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function dzzSessionKey() {
  return crypto.createHash('sha256').update(String(JWT_SECRET)).digest();
}

function encryptDzzSessionsPayload(obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', dzzSessionKey(), iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  return JSON.stringify({
    v: 1,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: enc.toString('base64'),
  });
}

function decryptDzzSessionsPayload(raw) {
  const parsed = JSON.parse(raw);
  if (parsed?.v !== 1 || !parsed.iv || !parsed.tag || !parsed.data) throw new Error('format');
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    dzzSessionKey(),
    Buffer.from(parsed.iv, 'base64'),
  );
  decipher.setAuthTag(Buffer.from(parsed.tag, 'base64'));
  const json = Buffer.concat([
    decipher.update(Buffer.from(parsed.data, 'base64')),
    decipher.final(),
  ]).toString('utf8');
  return JSON.parse(json);
}

async function persistDzzSessions() {
  pruneDzzSessions(false);
  const sessions = [];
  for (const [sid, sess] of dzzSessions) {
    sessions.push({
      sid,
      login: sess.login,
      password: sess.password,
      url: sess.url,
      expiresAt: sess.expiresAt,
    });
  }
  await fs.mkdir(DATA_DIR, { recursive: true });
  const tmp = `${DZZ_SESSIONS_FILE}.tmp`;
  await fs.writeFile(tmp, encryptDzzSessionsPayload({ sessions }), 'utf8');
  try {
    await fs.rename(tmp, DZZ_SESSIONS_FILE);
  } catch {
    await fs.unlink(DZZ_SESSIONS_FILE).catch(() => {});
    await fs.rename(tmp, DZZ_SESSIONS_FILE);
  }
}

function persistDzzSessionsSoon() {
  if (dzzPersistTimer) return;
  dzzPersistTimer = setTimeout(() => {
    dzzPersistTimer = null;
    persistDzzSessions().catch((e) => console.error('[dzz] persist failed', e?.message || e));
  }, 250);
}

async function loadDzzSessions() {
  try {
    const raw = await fs.readFile(DZZ_SESSIONS_FILE, 'utf8');
    const parsed = decryptDzzSessionsPayload(raw);
    const now = Date.now();
    let n = 0;
    for (const rec of parsed.sessions || []) {
      if (!rec?.sid || !rec.login || !rec.password || !rec.url) continue;
      if (rec.expiresAt && rec.expiresAt < now) continue;
      dzzSessions.set(rec.sid, {
        login: rec.login,
        password: rec.password,
        url: rec.url,
        expiresAt: rec.expiresAt || now + DZZ_SESSION_TTL_MS,
      });
      n += 1;
    }
    if (n) console.log(`[dzz] restored ${n} session(s) after restart`);
  } catch (e) {
    if (e?.code !== 'ENOENT') console.warn('[dzz] could not restore sessions', e.message || e);
  }
}

async function fetchDzzUpstream(target, headers, attempts = 3) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      const upstream = await fetch(target, {
        method: 'GET',
        headers,
        signal: AbortSignal.timeout(20000),
      });
      if (upstream.status >= 500 && upstream.status !== 501 && i < attempts - 1) {
        await sleep(400 * (i + 1));
        continue;
      }
      return upstream;
    } catch (e) {
      lastErr = e;
      if (i < attempts - 1) await sleep(400 * (i + 1));
    }
  }
  throw lastErr;
}

function dzzCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: DZZ_SESSION_TTL_MS,
  };
}

function dzzBasicHeader(login, password) {
  return `Basic ${Buffer.from(`${login}:${password}`, 'utf8').toString('base64')}`;
}

function resolveDzzServiceRoot(raw) {
  let value = String(raw || '').trim() || DZZ_DEFAULT_SERVICE;
  value = value.replace(/^http:\/\//i, 'https://');
  value = value.replace(/\/WMTS(?:\/1\.0\.0\/WMTSCapabilities\.xml)?\/?$/i, '');
  value = value.replace(/\/tile\/\{z\}\/\{y\}\/\{x\}\/?$/i, '');
  value = value.replace(/\/+$/, '');
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:') return null;
  if (!/^(www\.)?dzz\.by$/i.test(parsed.hostname)) return null;
  const match = parsed.href.match(
    /^(https:\/\/(?:www\.)?dzz\.by\/arcgis\/rest\/services\/[^/]+\/[^/]+\/ImageServer)/i,
  );
  return match ? match[1] : null;
}

function publicDzzUrl(serviceRoot) {
  return `${serviceRoot}/tile/{z}/{y}/{x}`;
}

function getDzzSession(req) {
  const sid = req?.cookies?.dzz_sid;
  if (!sid) return null;
  const sess = dzzSessions.get(sid);
  if (!sess || sess.expiresAt < Date.now()) {
    if (dzzSessions.delete(sid)) persistDzzSessionsSoon();
    return null;
  }
  return { sid, ...sess };
}

function pruneDzzSessions(persist = true) {
  const now = Date.now();
  let changed = false;
  for (const [sid, sess] of dzzSessions) {
    if (!sess || sess.expiresAt < now) {
      dzzSessions.delete(sid);
      changed = true;
    }
  }
  if (changed && persist) persistDzzSessionsSoon();
}

function dzzError(res, status, error, message) {
  return res.status(status).json({ error, message });
}

async function probeDzzService(login, password, serviceRoot) {
  try {
    const upstream = await fetch(`${serviceRoot}?f=json`, {
      headers: { Authorization: dzzBasicHeader(login, password) },
      signal: AbortSignal.timeout(15000),
    });
    if (upstream.status === 401 || upstream.status === 403) {
      return { ok: false, code: 'INVALID_CREDENTIALS' };
    }
    if (upstream.status >= 500 || upstream.status === 502 || upstream.status === 503) {
      return { ok: false, code: 'SERVICE_UNAVAILABLE' };
    }
    if (!upstream.ok) {
      return { ok: false, code: upstream.status === 404 ? 'INVALID_URL' : 'SERVICE_UNAVAILABLE' };
    }
    let data;
    try {
      data = JSON.parse(await upstream.text());
    } catch {
      return { ok: false, code: 'SERVICE_UNAVAILABLE' };
    }
    if (data?.error) {
      const code = Number(data.error.code);
      if (code === 498 || code === 499 || code === 401 || /token|unauthorized|password|credential|login/i.test(String(data.error.message || ''))) {
        return { ok: false, code: 'INVALID_CREDENTIALS' };
      }
      return { ok: false, code: 'SERVICE_UNAVAILABLE' };
    }
    if (!data?.name) return { ok: false, code: 'SERVICE_UNAVAILABLE' };
    return { ok: true };
  } catch (e) {
    const code = e?.cause?.code || e?.code || e?.name;
    if (code === 'TimeoutError' || e?.name === 'TimeoutError' || e?.name === 'AbortError') {
      return { ok: false, code: 'SERVICE_UNAVAILABLE' };
    }
    if (String(code).includes('UNABLE_TO_VERIFY') || String(code).includes('CERT')) {
      return { ok: false, code: 'TLS_ERROR' };
    }
    return { ok: false, code: 'SERVICE_UNAVAILABLE' };
  }
}

async function probeDzzAvailability(req) {
  pruneDzzSessions();
  const sess = getDzzSession(req);
  const root = sess?.url || DZZ_DEFAULT_SERVICE;
  if (sess) {
    const probe = await probeDzzService(sess.login, sess.password, root);
    if (probe.ok) return { available: true, connected: true, reason: 'ok' };
    if (probe.code === 'INVALID_CREDENTIALS') {
      return { available: true, connected: false, reason: 'unauthorized' };
    }
    return { available: false, connected: false, reason: probe.code === 'TLS_ERROR' ? 'tls' : 'unavailable' };
  }
  try {
    const upstream = await fetch(`${root}?f=json`, { signal: AbortSignal.timeout(8000) });
    if (upstream.status === 401 || upstream.status === 403 || upstream.ok) {
      return { available: true, connected: false, reason: 'reachable' };
    }
    return { available: false, connected: false, reason: 'unavailable' };
  } catch {
    return { available: false, connected: false, reason: 'unavailable' };
  }
}

app.get('/api/dzz/health', async (req, res) => {
  try {
    const dzz = await probeDzzAvailability(req);
    res.json({
      ok: dzz.available,
      available: dzz.available,
      connected: dzz.connected,
      status: dzz.available ? 'online' : 'unavailable',
      message: dzz.available
        ? (dzz.connected ? 'Сервис dzz.by доступен, сессия активна' : 'Сервис dzz.by доступен')
        : 'Сервис dzz.by недоступен',
    });
  } catch {
    res.json({
      ok: false,
      available: false,
      connected: false,
      status: 'unavailable',
      message: 'Сервис dzz.by недоступен',
    });
  }
});

app.post('/api/dzz/connect', async (req, res) => {
  pruneDzzSessions();
  const login = String(req.body?.login || '').trim();
  const password = String(req.body?.password || '');
  const serviceRoot = resolveDzzServiceRoot(req.body?.url);
  if (!login || !password) {
    return dzzError(res, 400, 'MISSING_CREDENTIALS', 'Укажите логин, пароль и адрес подключения');
  }
  if (!serviceRoot) {
    return dzzError(res, 400, 'INVALID_URL', 'Некорректный адрес подключения. Укажите URL ImageServer dzz.by');
  }

  const probe = await probeDzzService(login, password, serviceRoot);
  if (!probe.ok) {
    if (probe.code === 'INVALID_CREDENTIALS') {
      return dzzError(res, 401, 'INVALID_CREDENTIALS', 'Неверные логин или пароль dzz.by');
    }
    if (probe.code === 'INVALID_URL') {
      return dzzError(res, 400, 'INVALID_URL', 'Некорректный адрес подключения. Укажите URL ImageServer dzz.by');
    }
    if (probe.code === 'TLS_ERROR') {
      return dzzError(res, 503, 'TLS_ERROR', 'Не удалось проверить сертификат dzz.by. Перезапустите сервер командой npm start.');
    }
    return dzzError(res, 503, 'SERVICE_UNAVAILABLE', 'Сервис dzz.by недоступен. Попробуйте позже.');
  }

  const prev = req.cookies?.dzz_sid;
  if (prev) dzzSessions.delete(prev);
  const sid = crypto.randomBytes(32).toString('hex');
  dzzSessions.set(sid, {
    login,
    password,
    url: serviceRoot,
    expiresAt: Date.now() + DZZ_SESSION_TTL_MS,
  });
  try {
    await persistDzzSessions();
  } catch (e) {
    console.error('[dzz] persist failed', e?.message || e);
  }
  res.cookie('dzz_sid', sid, dzzCookieOptions());
  res.json({ ok: true, connected: true, url: publicDzzUrl(serviceRoot) });
});

app.get('/api/dzz/status', (req, res) => {
  const sess = getDzzSession(req);
  if (!sess) {
    return res.json({ connected: false });
  }
  res.json({ connected: true, url: publicDzzUrl(sess.url) });
});

async function annotateWmtsReachable(parsed, headers) {
  const layer = parsed.layers?.[0];
  if (!layer) return;
  const gmc = parsed.tileMatrixSets.find((item) => item.wellKnown === 'GoogleMapsCompatible');
  const targets = gmc ? [gmc] : parsed.tileMatrixSets.filter((item) => item.supported).slice(0, 1);
  for (const matrixSet of targets) {
    const tileUrl = buildWmtsRestUrl(layer, matrixSet, layer.defaultStyle);
    const sample = fillWmtsSampleTileUrl(tileUrl, matrixSet.zoomOffset);
    if (!sample || /\{[A-Za-z]+\}/.test(sample)) {
      matrixSet.reachable = null;
      continue;
    }
    try {
      const upstream = await fetch(sample, {
        method: 'GET',
        headers,
        signal: AbortSignal.timeout(8000),
        redirect: 'follow',
      });
      matrixSet.reachable = upstream.ok;
      matrixSet.httpStatus = upstream.status;
    } catch {
      matrixSet.reachable = false;
      matrixSet.httpStatus = 0;
    }
  }
}

app.post('/api/wmts/capabilities', async (req, res) => {
  const rawUrl = String(req.body?.url || '').trim();
  const login = String(req.body?.login || '').trim();
  const password = String(req.body?.password || '');
  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl.replace(/^http:\/\//i, 'https://'));
  } catch {
    return dzzError(res, 400, 'INVALID_URL', 'Укажите адрес WMTS или ImageServer');
  }
  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    return dzzError(res, 400, 'INVALID_URL', 'Нужен http(s) адрес WMTSCapabilities.xml');
  }

  const isDzz = /^(www\.)?dzz\.by$/i.test(parsedUrl.hostname);
  if (!isDzz && isBlockedWmtsHost(parsedUrl.hostname)) {
    return dzzError(res, 400, 'INVALID_URL', 'Этот хост нельзя запрашивать как WMTS');
  }

  try {
    let headers = {};
    let capabilitiesUrl = '';
    let xml = '';
    if (isDzz) {
      const sess = getDzzSession(req);
      if (!sess) {
        return dzzError(res, 401, 'DZZ_NOT_CONNECTED', 'Сначала проверьте подключение к dzz.by');
      }
      capabilitiesUrl = resolveWmtsCapabilitiesUrl(rawUrl, sess.url);
      const target = new URL(capabilitiesUrl);
      if (target.origin !== DZZ_UPSTREAM) {
        return dzzError(res, 400, 'INVALID_DZZ_HOST', 'WMTS dzz.by должен быть на www.dzz.by');
      }
      headers = { Authorization: dzzBasicHeader(sess.login, sess.password) };
      const upstream = await fetchDzzUpstream(target, headers);
      if (upstream.status === 401 || upstream.status === 403) {
        return dzzError(res, 401, 'INVALID_CREDENTIALS', 'Неверные логин или пароль dzz.by');
      }
      if (!upstream.ok) {
        return dzzError(res, 502, 'WMTS_FETCH_FAILED', `WMTSCapabilities.xml недоступен (${upstream.status})`);
      }
      const buf = Buffer.from(await upstream.arrayBuffer());
      if (buf.length > 2_500_000) {
        return dzzError(res, 413, 'WMTS_TOO_LARGE', 'WMTSCapabilities.xml слишком большой');
      }
      xml = buf.toString('utf8');
    } else {
      capabilitiesUrl = resolveWmtsCapabilitiesUrl(rawUrl);
      if (login) headers.Authorization = dzzBasicHeader(login, password);
      const upstream = await fetch(capabilitiesUrl, {
        headers,
        signal: AbortSignal.timeout(20000),
        redirect: 'follow',
      });
      if (upstream.status === 401 || upstream.status === 403) {
        return dzzError(res, 401, 'INVALID_CREDENTIALS', 'WMTS требует логин и пароль');
      }
      if (!upstream.ok) {
        return dzzError(res, 502, 'WMTS_FETCH_FAILED', `WMTSCapabilities.xml недоступен (${upstream.status})`);
      }
      const buf = Buffer.from(await upstream.arrayBuffer());
      if (buf.length > 2_500_000) {
        return dzzError(res, 413, 'WMTS_TOO_LARGE', 'WMTSCapabilities.xml слишком большой');
      }
      xml = buf.toString('utf8');
    }

    const parsed = parseWmtsCapabilities(xml, capabilitiesUrl);
    if (!parsed.ok) {
      return dzzError(res, 400, parsed.error || 'WMTS_PARSE', parsed.message || 'Не удалось разобрать WMTS');
    }
    await annotateWmtsReachable(parsed, headers);
    const suggested = pickSuggestedWmts(parsed, { preferNotGoogleMapsCompatible: isDzz });
    const gmc = parsed.tileMatrixSets.find((item) => item.wellKnown === 'GoogleMapsCompatible');
    if (isDzz && gmc && gmc.httpStatus === 520 && suggested) {
      suggested.warning = 'Матрица GoogleMapsCompatible есть в capabilities, но dzz.by отвечает 520 — слоя нет. Выбран запасной набор REST {z}/{y}/{x}.';
    }
    return res.json({ ...parsed, suggested, source: isDzz ? 'dzz' : 'custom' });
  } catch (e) {
    console.error('[wmts] fetch failed', e?.name || e);
    return dzzError(res, 503, 'WMTS_FETCH_FAILED', 'Не удалось загрузить WMTSCapabilities.xml');
  }
});

app.post('/api/dzz/disconnect', async (req, res) => {
  const sid = req.cookies?.dzz_sid;
  if (sid) dzzSessions.delete(sid);
  try {
    await persistDzzSessions();
  } catch (e) {
    console.error('[dzz] persist failed', e?.message || e);
  }
  res.clearCookie('dzz_sid', { path: '/' });
  res.json({ ok: true, connected: false });
});

app.use('/api/dzz', async (req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED', message: 'Метод не поддерживается' });
  }

  const sess = getDzzSession(req);
  if (!sess) {
    return dzzError(res, 401, 'DZZ_NOT_CONNECTED', 'Сначала проверьте подключение к dzz.by');
  }

  const suffix = req.originalUrl.replace(/^\/api\/dzz/, '');
  if (!suffix.startsWith('/arcgis/')) {
    return dzzError(res, 400, 'INVALID_DZZ_PATH', 'Некорректный путь запроса к dzz.by');
  }

  let target;
  try {
    target = new URL(suffix, DZZ_UPSTREAM);
  } catch {
    return dzzError(res, 400, 'INVALID_DZZ_URL', 'Некорректный адрес подключения');
  }
  if (target.origin !== DZZ_UPSTREAM) {
    return dzzError(res, 400, 'INVALID_DZZ_HOST', 'Некорректный адрес подключения');
  }

  try {
    const upstream = await fetchDzzUpstream(target, {
      Authorization: dzzBasicHeader(sess.login, sess.password),
    });
    if (upstream.status === 401 || upstream.status === 403) {
      return dzzError(res, 401, 'INVALID_CREDENTIALS', 'Неверные логин или пароль dzz.by');
    }
    res.status(upstream.status);
    const contentType = upstream.headers.get('content-type');
    if (contentType) res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'private, no-store');
    const buf = Buffer.from(await upstream.arrayBuffer());
    res.send(buf);
  } catch (e) {
    console.error('[dzz] proxy error', e?.name || e);
    return dzzError(res, 503, 'SERVICE_UNAVAILABLE', 'Сервис dzz.by недоступен. Попробуйте позже.');
  }
});

app.use(express.static(__dirname));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

await waitForDb();
await loadDzzSessions();
app.listen(PORT, () => {
  console.log(`Web UI: http://0.0.0.0:${PORT}`);
  console.log(`ML API proxy → ${ML_BACKEND_URL}`);
  console.log(`Auth store: ${pool ? 'Postgres' : 'JSON file'}`);
});
