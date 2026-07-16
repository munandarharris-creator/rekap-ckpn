import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createClient } from '@libsql/client';
import crypto from 'node:crypto';

const required = ['TURSO_DATABASE_URL', 'TURSO_AUTH_TOKEN'];
const missing = required.filter((name) => !process.env[name]);
if (missing.length) throw new Error(`Konfigurasi belum lengkap: ${missing.join(', ')}`);

const db = createClient({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });
await db.execute(`CREATE TABLE IF NOT EXISTS app_state (
  state_key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);
await db.execute(`CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('Admin', 'User')),
  kode_reg TEXT NOT NULL DEFAULT '0000',
  expiry_date TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);

const sessions = new Map();
const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => new Promise((resolve, reject) =>
  crypto.scrypt(password, salt, 64, (error, key) => error ? reject(error) : resolve(`${salt}:${key.toString('hex')}`))
);
async function verifyPassword(password, stored) {
  const [salt, key] = stored.split(':');
  const candidate = await hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(`${salt}:${key}`));
}
const publicUser = (user) => ({ username: user.username, name: user.name, role: user.role, kodeReg: user.kode_reg, expiryDate: user.expiry_date });
async function seedAdmin() {
  const result = await db.execute('SELECT COUNT(*) AS count FROM users');
  if (Number(result.rows[0].count) > 0) return;
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;
  if (!username || !password) throw new Error('ADMIN_USERNAME dan ADMIN_PASSWORD wajib diisi untuk membuat akun pertama.');
  await db.execute({ sql: 'INSERT INTO users (username, name, password_hash, role, kode_reg) VALUES (?, ?, ?, ?, ?)', args: [username.toLowerCase(), process.env.ADMIN_NAME || 'Administrator', await hashPassword(password), 'Admin', process.env.ADMIN_KODE_REG || '0000'] });
}
await seedAdmin();

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(express.json({ limit: '25mb' }));
const requireAuth = async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const session = token && sessions.get(token);
  if (!session || session.expires < Date.now()) return res.status(401).json({ error: 'Sesi tidak valid atau telah berakhir.' });
  req.user = session.user;
  next();
};
const requireAdmin = (req, res, next) => req.user.role === 'Admin' ? next() : res.status(403).json({ error: 'Khusus Administrator.' });

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const result = await db.execute({ sql: 'SELECT * FROM users WHERE username = ?', args: [username] });
    const user = result.rows[0];
    if (!user || !(await verifyPassword(password, user.password_hash)) || (user.expiry_date && new Date(user.expiry_date) <= new Date())) return res.status(401).json({ error: 'Username atau kata sandi tidak valid.' });
    const token = crypto.randomBytes(32).toString('hex');
    const safeUser = publicUser(user);
    sessions.set(token, { user: safeUser, expires: Date.now() + 8 * 60 * 60 * 1000 });
    res.json({ token, user: safeUser });
  } catch (error) { next(error); }
});
app.post('/api/auth/logout', requireAuth, (req, res) => { sessions.delete(req.headers.authorization.replace('Bearer ', '')); res.status(204).end(); });
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: req.user }));

app.get('/api/health', async (_req, res) => {
  try { await db.execute('SELECT 1'); res.json({ ok: true }); }
  catch { res.status(503).json({ ok: false }); }
});

app.get('/api/state', requireAuth, async (_req, res, next) => {
  try {
    const result = await db.execute({ sql: 'SELECT value, updated_at FROM app_state WHERE state_key = ?', args: ['dashboard'] });
    if (!result.rows.length) return res.json({ state: null });
    res.json({ state: JSON.parse(result.rows[0].value), updatedAt: result.rows[0].updated_at });
  } catch (error) { next(error); }
});

app.put('/api/state', requireAuth, async (req, res, next) => {
  try {
    if (!req.body?.state || typeof req.body.state !== 'object') return res.status(400).json({ error: 'state harus berupa objek' });
    const value = JSON.stringify(req.body.state);
    await db.execute({
      sql: `INSERT INTO app_state (state_key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(state_key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
      args: ['dashboard', value]
    });
    res.json({ ok: true });
  } catch (error) { next(error); }
});

app.get('/api/users', requireAuth, requireAdmin, async (_req, res, next) => {
  try { const result = await db.execute('SELECT username, name, role, kode_reg, expiry_date FROM users ORDER BY name'); res.json({ users: result.rows.map(publicUser) }); }
  catch (error) { next(error); }
});
app.post('/api/users', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const { username, name, password, role, kodeReg, expiryDate } = req.body || {};
    if (!username || !name || !password || !['Admin', 'User'].includes(role)) return res.status(400).json({ error: 'Data pengguna belum lengkap.' });
    await db.execute({ sql: 'INSERT INTO users (username, name, password_hash, role, kode_reg, expiry_date) VALUES (?, ?, ?, ?, ?, ?)', args: [String(username).toLowerCase(), name, await hashPassword(password), role, kodeReg || '0000', expiryDate || null] });
    res.status(201).json({ ok: true });
  } catch (error) { next(error); }
});
app.put('/api/users/:username', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const { name, password, role, kodeReg, expiryDate } = req.body || {};
    if (!name || !['Admin', 'User'].includes(role)) return res.status(400).json({ error: 'Data pengguna belum lengkap.' });
    const params = [name, role, kodeReg || '0000', expiryDate || null];
    let sql = 'UPDATE users SET name = ?, role = ?, kode_reg = ?, expiry_date = ?';
    if (password) { sql += ', password_hash = ?'; params.push(await hashPassword(password)); }
    sql += ' WHERE username = ?'; params.push(req.params.username.toLowerCase());
    await db.execute({ sql, args: params }); res.json({ ok: true });
  } catch (error) { next(error); }
});
app.delete('/api/users/:username', requireAuth, requireAdmin, async (req, res, next) => {
  try { await db.execute({ sql: 'DELETE FROM users WHERE username = ?', args: [req.params.username.toLowerCase()] }); res.status(204).end(); }
  catch (error) { next(error); }
});

app.use(express.static(path.join(__dirname, 'public')));
app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({ error: 'Gagal memproses data.' });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Aplikasi siap di http://localhost:${port}`));
