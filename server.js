// server.js — resilient startup for DigitalOcean App Platform (CommonJS)

const express = require('express');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL || '';
const APP_SCHEMA = process.env.APP_SCHEMA || 'public';

// Create PG pool if DATABASE_URL is set; require verified SSL on DO
let pool = null;
if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL, // e.g., ...:25060/dbname?sslmode=require
    ssl: { rejectUnauthorized: true },
  });
  pool.on('connect', (client) => {
    client.query(`SET search_path TO ${APP_SCHEMA}, public`).catch(() => {});
  });
}

// Health endpoints
app.get('/', (_req, res) => res.status(200).send('ok')); // fast 200 for readiness
app.get('/healthz', async (_req, res) => {
  if (!pool) return res.status(200).send('ok (no db)');
  try { await pool.query('SELECT 1'); return res.status(200).send('ok'); }
  catch { return res.status(500).send('db down'); }
});

// Minimal idempotent bootstrap to test write perms; won't crash on failure
async function runBootstrap() {
  if (!pool) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_bootstrap (
        id SERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    console.log('[startup] bootstrap/migrations ok');
  } catch (e) {
    console.error('[migrations] failed (will not crash):', e.code || e.message);
  }
}

async function start() {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[startup] listening on ${PORT}`);
  });
  await runBootstrap();
}

start();

