const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'iamwithyou-secret-key-change-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

app.use(cors());
app.use(express.json());

const db = new Database(process.env.DB_PATH || './data.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT,
    is_active INTEGER DEFAULT 1,
    deepgram_key TEXT DEFAULT '',
    groq_key TEXT DEFAULT '',
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    question TEXT,
    answer TEXT,
    ts INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY,
    password TEXT NOT NULL
  );
`);

const adminExists = db.prepare('SELECT id FROM admin WHERE id = 1').get();
if (!adminExists) {
  const hashed = bcrypt.hashSync(ADMIN_PASSWORD, 10);
  db.prepare('INSERT INTO admin(id, password) VALUES(1, ?)').run(hashed);
}

function verifyAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Not admin' });
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function verifyUser(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// Admin routes
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  const admin = db.prepare('SELECT * FROM admin WHERE id = 1').get();
  if (!admin || !bcrypt.compareSync(password, admin.password))
    return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

app.get('/admin/users', verifyAdmin, (req, res) => {
  const users = db.prepare('SELECT id, email, name, is_active, deepgram_key, groq_key, created_at FROM users').all();
  res.json(users);
});

app.post('/admin/users', verifyAdmin, (req, res) => {
  const { email, password, name, deepgram_key, groq_key } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const id = uuidv4();
    const hashed = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users(id, email, password, name, deepgram_key, groq_key) VALUES(?,?,?,?,?,?)')
      .run(id, email, hashed, name || '', deepgram_key || '', groq_key || '');
    res.json({ success: true, id });
  } catch { res.status(400).json({ error: 'Email already exists' }); }
});

app.put('/admin/users/:id', verifyAdmin, (req, res) => {
  const { name, is_active, deepgram_key, groq_key, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const newPass = password ? bcrypt.hashSync(password, 10) : user.password;
  db.prepare('UPDATE users SET name=?, is_active=?, deepgram_key=?, groq_key=?, password=? WHERE id=?')
    .run(name ?? user.name, is_active ?? user.is_active, deepgram_key ?? user.deepgram_key, groq_key ?? user.groq_key, newPass, req.params.id);
  res.json({ success: true });
});

app.delete('/admin/users/:id', verifyAdmin, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.get('/admin/users/:id/history', verifyAdmin, (req, res) => {
  const history = db.prepare('SELECT * FROM history WHERE user_id = ? ORDER BY ts DESC LIMIT 100').all(req.params.id);
  res.json(history);
});

app.put('/admin/password', verifyAdmin, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  db.prepare('UPDATE admin SET password = ? WHERE id = 1').run(bcrypt.hashSync(password, 10));
  res.json({ success: true });
});

// User routes
app.post('/user/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Invalid email or password' });
  if (!user.is_active)
    return res.status(403).json({ error: 'Account deactivated. Contact admin.' });
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, name: user.name, deepgram_key: user.deepgram_key, groq_key: user.groq_key });
});

app.get('/user/verify', verifyUser, (req, res) => {
  const user = db.prepare('SELECT id, email, name, is_active, deepgram_key, groq_key FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!user.is_active) return res.status(403).json({ error: 'Account deactivated' });
  res.json(user);
});

app.post('/user/history', verifyUser, (req, res) => {
  const { question, answer } = req.body;
  db.prepare('INSERT INTO history(user_id, question, answer) VALUES(?,?,?)').run(req.userId, question, answer);
  res.json({ success: true });
});

app.get('/', (req, res) => res.json({ status: 'IAmWithYou Backend Running' }));
app.listen(PORT, () => console.log('Server on port', PORT));
