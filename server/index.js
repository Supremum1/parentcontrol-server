import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import pkg from 'pg';
const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  host: process.env.PGHOST,
  port: Number(process.env.PGPORT),
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
});

// Инициализация схемы
import fs from 'fs';
const schema = fs.readFileSync(new URL('./schema.sql', import.meta.url));
await pool.query(schema.toString());

const SESSION_TTL_DAYS = Number(process.env.SESSION_TTL_DAYS || 7);
const PAIR_CODE_TTL_MIN = Number(process.env.PAIR_CODE_TTL_MIN || 10);

function addDays(date, d) {
  const copy = new Date(date);
  copy.setDate(copy.getDate() + d);
  return copy;
}

function addMinutes(date, m) {
  return new Date(date.getTime() + m * 60000);
}

async function authMiddleware(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token' });
  }
  const token = auth.substring('Bearer '.length);
  const { rows } = await pool.query(
    'SELECT user_id, expires_at FROM sessions WHERE token=$1',
    [token]
  );
  if (rows.length === 0) return res.status(401).json({ error: 'Invalid token' });
  const session = rows[0];
  if (new Date(session.expires_at) < new Date()) {
    await pool.query('DELETE FROM sessions WHERE token=$1', [token]);
    return res.status(401).json({ error: 'Expired token' });
  }
  // Подгрузим пользователя
  const ures = await pool.query('SELECT id, email, role FROM users WHERE id=$1', [session.user_id]);
  if (ures.rows.length === 0) return res.status(401).json({ error: 'User not found' });
  req.user = ures.rows[0];
  req.token = token;
  next();
}

// Регистрация
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password || !role || !['parent','child'].includes(role)) {
      return res.status(400).json({ error: 'email, password, role=parent|child required' });
    }
    const hash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    await pool.query(
      'INSERT INTO users(id, email, password_hash, role) VALUES($1,$2,$3,$4)',
      [id, email, hash, role]
    );
    // Автовход
    const token = uuidv4();
    const exp = addDays(new Date(), SESSION_TTL_DAYS);
    await pool.query(
      'INSERT INTO sessions(token, user_id, expires_at) VALUES($1,$2,$3)',
      [token, id, exp]
    );
    res.json({ token, user: { id, email, role } });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Email already exists' });
    }
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Логин
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email, password required' });
  const { rows } = await pool.query('SELECT id, email, password_hash, role FROM users WHERE email=$1', [email]);
  if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
  const user = rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = uuidv4();
  const exp = addDays(new Date(), SESSION_TTL_DAYS);
  await pool.query('INSERT INTO sessions(token, user_id, expires_at) VALUES($1,$2,$3)', [token, user.id, exp]);
  res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
});

// Выпуск кода (только child)
app.post('/api/child/create-code', authMiddleware, async (req, res) => {
  if (req.user.role !== 'child') return res.status(403).json({ error: 'Forbidden' });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = addMinutes(new Date(), PAIR_CODE_TTL_MIN);
  await pool.query('DELETE FROM pairing_codes WHERE child_user_id=$1 OR expires_at < NOW()', [req.user.id]);
  await pool.query('INSERT INTO pairing_codes(code, child_user_id, expires_at) VALUES($1,$2,$3)', [code, req.user.id, expires]);
  res.json({ code, expiresAt: expires.toISOString() });
});

// Привязка по коду (только parent)
app.post('/api/parent/pair', authMiddleware, async (req, res) => {
  if (req.user.role !== 'parent') return res.status(403).json({ error: 'Forbidden' });
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'code required' });
  const { rows } = await pool.query('SELECT child_user_id, used, expires_at FROM pairing_codes WHERE code=$1', [code]);
  if (rows.length === 0) return res.status(404).json({ error: 'Code not found' });
  const pc = rows[0];
  if (pc.used) return res.status(400).json({ error: 'Code already used' });
  if (new Date(pc.expires_at) < new Date()) return res.status(400).json({ error: 'Code expired' });
  // Создать связь, если нет
  const childId = pc.child_user_id;
  // Один ребёнок — одна связь (демо)
  const exist = await pool.query('SELECT id FROM connections WHERE child_user_id=$1', [childId]);
  if (exist.rows.length === 0) {
    const id = uuidv4();
    await pool.query(
      'INSERT INTO connections(id, parent_user_id, child_user_id) VALUES($1,$2,$3)',
      [id, req.user.id, childId]
    );
  }
  await pool.query('UPDATE pairing_codes SET used=TRUE WHERE code=$1', [code]);
  res.json({ ok: true });
});

// Статус для ребёнка
app.get('/api/child/pair-status', authMiddleware, async (req, res) => {
  if (req.user.role !== 'child') return res.status(403).json({ error: 'Forbidden' });
  const { rows } = await pool.query('SELECT id FROM connections WHERE child_user_id=$1', [req.user.id]);
  res.json({ connected: rows.length > 0 });
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

const port = Number(process.env.PORT || 8080);
app.listen(port, () => console.log(`ParentControl server listening on http://localhost:${port}`));