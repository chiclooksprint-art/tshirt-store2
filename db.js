const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const db = new Database('store.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT,
    phone TEXT,
    is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    brand TEXT NOT NULL,
    name TEXT NOT NULL,
    price INTEGER NOT NULL,
    image TEXT,
    sizes TEXT DEFAULT 'S,M,L,XL',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT,
    phone TEXT,
    email TEXT,
    comment TEXT,
    items TEXT,
    total INTEGER,
    payment_method TEXT DEFAULT 'cash',
    status TEXT DEFAULT 'new',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Создаём админа при первом запуске
const adminExists = db.prepare('SELECT id FROM users WHERE is_admin = 1').get();
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare(
    'INSERT INTO users (email, password, name, is_admin) VALUES (?, ?, ?, 1)'
  ).run('admin@store.local', hash, 'Администратор');
  console.log('✅ Создан админ: admin@store.local / admin123 — СМЕНИ ПАРОЛЬ!');
}

// Стартовые товары (можно удалить позже через админку)
const prodCount = db.prepare('SELECT COUNT(*) as c FROM products').get().c;
if (prodCount === 0) {
  const insert = db.prepare(
    'INSERT INTO products (brand, name, price, image) VALUES (?, ?, ?, ?)'
  );
  const seed = [
    ['brand1', 'Футболка White Classic', 2500, 'https://picsum.photos/seed/tshirt1/600/750'],
    ['brand1', 'Футболка Black Basic',   2500, 'https://picsum.photos/seed/tshirt2/600/750'],
    ['brand2', 'Street Tee Grey',        3200, 'https://picsum.photos/seed/street1/600/750'],
    ['brand2', 'Urban Drop Acid',        3500, 'https://picsum.photos/seed/street3/600/750'],
    ['brand3', 'Sport Dry-Fit Blue',     2200, 'https://picsum.photos/seed/sport1/600/750'],
    ['brand3', 'Training Tee Graphite',  2400, 'https://picsum.photos/seed/sport3/600/750'],
  ];
  seed.forEach(s => insert.run(...s));
}

module.exports = db;