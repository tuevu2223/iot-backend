// db.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./kholanh.db');

// Tạo bảng chứa danh sách tài khoản
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'user',      -- 'admin' hoặc 'user'
      canViewData INTEGER DEFAULT 0  -- 0: Chưa được xem, 1: Được xem nhiệt độ
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      token TEXT PRIMARY KEY,
      userId INTEGER NOT NULL,
      FOREIGN KEY (userId) REFERENCES users (id) ON DELETE CASCADE
    )
  `);
});

module.exports = db;