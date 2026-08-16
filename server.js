import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import express from 'express';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import { createProxyMiddleware } from 'http-proxy-middleware';
import pg from 'pg';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT ? Number(process.env.PORT) : 5173;
// Локально: localhost:8000. В Docker задайте ML_BACKEND_URL=http://backend:8000
const ML_BACKEND_URL = process.env.ML_BACKEND_URL || 'http://localhost:8000';
const DATABASE_URL = process.env.DATABASE_URL || '';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

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

app.get('/api/health', async (_req, res) => {
  let db = 'file';
  if (pool) {
    try {
      await pool.query('SELECT 1');
      db = 'ok';
    } catch {
      db = 'down';
    }
  }
  res.json({ ok: true, db, ml: ML_BACKEND_URL });
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

app.use(express.static(__dirname));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

await waitForDb();
app.listen(PORT, () => {
  console.log(`Web UI: http://0.0.0.0:${PORT}`);
  console.log(`ML API proxy → ${ML_BACKEND_URL}`);
  console.log(`Auth store: ${pool ? 'Postgres' : 'JSON file'}`);
});
