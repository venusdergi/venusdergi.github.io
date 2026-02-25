const path = require('path');
const sqlite3 = require('sqlite3');

const dbPath = path.join(__dirname, '..', '..', 'reelspdf.sqlite');
const db = new sqlite3.Database(dbPath);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function init() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS reels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      pdf_path TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  await run(`ALTER TABLE reels ADD COLUMN pdf_url TEXT;`).catch(() => {});
  await run(`UPDATE reels SET pdf_url = '/uploads/' || pdf_path WHERE pdf_url IS NULL OR pdf_url = '';`).catch(() => {});
}

module.exports = { db, run, get, all, init };
