import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import path from 'path';

const DB_PATH = process.env.DB_PATH || path.resolve('server', 'data.db');

export async function initDb() {
  const db = await open({
    filename: DB_PATH,
    driver: sqlite3.Database
  });

  // enable foreign keys
  await db.exec('PRAGMA foreign_keys = ON');

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      wallet TEXT UNIQUE NOT NULL,
      nonce TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS campaigns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      color TEXT,
      prize_pool REAL DEFAULT 0,
      questions_json TEXT NOT NULL,
      owner_wallet TEXT NOT NULL,
      prize_pool_contract TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS participants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id INTEGER NOT NULL,
      wallet TEXT NOT NULL,
      encrypted_input TEXT,
      input_proof TEXT,
      score INTEGER,
      passed INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
    );
  `);

  return db;
}