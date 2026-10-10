const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'change-me-in-production-please';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- Помощники ---------- */
function sign(user) {
  return jwt.sign({ id: user.id, is_admin: user.is_admin }, SECRET, { expiresIn: '30d' });
}
function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Не авторизован' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Неверный токен' });
  }
}
function adminOnly(req, res, next) {
  auth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Только админ' });
    next();
  });
}

/* ---------- Авторизация ---------- */
app.post('/api/auth/register', (req, res) => {
  const { email, password, name, phone } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Заполни email и пароль' });
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (exists) return res.status(400).json({ error: 'Email уже занят' });
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(
    'INSERT INTO users (email, password, name, phone) VALUES (?, ?, ?, ?)'
  ).run(email, hash, name || '', phone || '');
  const user = { id: info.lastInsertRowid, is_admin: 0 };
  res.cookie('token', sign(user), { httpOnly: true, maxAge: 30*24*3600*1000 });
  res.json({ id: user.id, email, name, phone, is_admin: 0 });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(400).json({ error: 'Неверный email или пароль' });
  res.cookie('token', sign(user), { httpOnly: true, maxAge: 30*24*3600*1000 });
  res.json({ id: user.id, email: user.email, name: user.name, phone: user.phone, is_admin: user.is_admin });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, email, name, phone, is_admin FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(401).json({ error: 'Нет пользователя' });
  res.json(user);
});

/* ---------- Товары ---------- */
app.get('/api/products', (req, res) => {
  const { brand } = req.query;
  const rows = brand
    ? db.prepare('SELECT * FROM products WHERE brand = ? ORDER BY id DESC').all(brand)
    : db.prepare('SELECT * FROM products ORDER BY id DESC').all();
  res.json(rows);
});

app.post('/api/products', adminOnly, (req, res) => {
  const { brand, name, price, image, sizes } = req.body;
  if (!brand || !name || !price) return res.status(400).json({ error: 'Заполни поля' });
  const info = db.prepare(
    'INSERT INTO products (brand, name, price, image, sizes) VALUES (?, ?, ?, ?, ?)'
  ).run(brand, name, price, image || '', sizes || 'S,M,L,XL');
  res.json(db.prepare('SELECT * FROM products WHERE id = ?').get(info.lastInsertRowid));
});

app.put('/api/products/:id', adminOnly, (req, res) => {
  const { brand, name, price, image, sizes } = req.body;
  db.prepare(
    'UPDATE products SET brand=?, name=?, price=?, image=?, sizes=? WHERE id=?'
  ).run(brand, name, price, image, sizes, req.params.id);
  res.json(db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id));
});

app.delete('/api/products/:id', adminOnly, (req, res) => {
  db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

/* ---------- Заказы ---------- */
app.post('/api/orders', (req, res) => {
  const { name, phone, email, comment, items, total, payment_method } = req.body;
  if (!name || !phone || !items || !items.length)
    return res.status(400).json({ error: 'Заполни обязательные поля' });

  let userId = null;
  try {
    const token = req.cookies.token;
    if (token) userId = jwt.verify(token, SECRET).id;
  } catch {}

  const info = db.prepare(
    `INSERT INTO orders (user_id, name, phone, email, comment, items, total, payment_method)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(userId, name, phone, email || '', comment || '', JSON.stringify(items), total, payment_method || 'cash');

  // Здесь позже вставим вызов платёжной системы
  // if (payment_method === 'card') return res.json({ payUrl: '...' });

  res.json({ id: info.lastInsertRowid, ok: true });
});

app.get('/api/orders/my', auth, (req, res) => {
  const orders = db.prepare(
    'SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC'
  ).all(req.user.id);
  orders.forEach(o => o.items = JSON.parse(o.items));
  res.json(orders);
});

app.get('/api/orders', adminOnly, (req, res) => {
  const orders = db.prepare('SELECT * FROM orders ORDER BY id DESC').all();
  orders.forEach(o => o.items = JSON.parse(o.items));
  res.json(orders);
});

app.patch('/api/orders/:id', adminOnly, (req, res) => {
  db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(req.body.status, req.params.id);
  res.json({ ok: true });
});

/* ---------- Запуск ---------- */
app.listen(PORT, () => {
  console.log(`🚀 Сайт: http://localhost:${PORT}`);
  console.log(`🔧 Админка: http://localhost:${PORT}/admin.html`);
});