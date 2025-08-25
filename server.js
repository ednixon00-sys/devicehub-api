'use strict';

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const { Pool } = require('pg');

const PORT = process.env.PORT || 8080;

// ---------- Postgres SSL config ----------
let ssl;
if (process.env.PG_CA_PEM) {
  // Use trusted CA (base64-encoded). Fixes “self-signed certificate in chain”
  ssl = { ca: Buffer.from(process.env.PG_CA_PEM, 'base64').toString('utf8') };
} else {
  // Fallback to require TLS without strict verification (still encrypted)
  ssl = { rejectUnauthorized: false };
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl,
});

// ---------- Express app ----------
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('tiny'));

// ---------- Helpers ----------
function mapDevice(r) {
  return {
    deviceId: r.device_id,
    appVersion: r.app_version,
    tauriVersion: r.tauri_version,
    osName: r.os_name,
    osVersion: r.os_version,
    arch: r.arch,
    hostname: r.hostname,
    username: r.username,
    ipLast: r.ip_last,
    status: r.status,
    firstSeenAt: r.first_seen_at,
    lastSeenAt: r.last_seen_at,
    updatedAt: r.updated_at,
  };
}

function adminAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (!process.env.ADMIN_TOKEN || token === process.env.ADMIN_TOKEN) return next();
  return res.status(401).json({ ok: false, error: 'unauthorized' });
}

// ---------- Auto-migrations (idempotent) ----------
async function ensureMigrations() {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`);

  // devices
  await pool.query(`
    CREATE TABLE IF NOT EXISTS devices (
      device_id    TEXT PRIMARY KEY,
      app_version  TEXT,
      tauri_version TEXT,
      os_name      TEXT,
      os_version   TEXT,
      arch         TEXT,
      hostname     TEXT,
      username     TEXT,
      device_secret TEXT,
      status       TEXT NOT NULL DEFAULT 'active',
      first_seen_at TIMESTAMPTZ,
      last_seen_at  TIMESTAMPTZ,
      updated_at    TIMESTAMPTZ DEFAULT now(),
      ip_last       TEXT
    );
  `);
  await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_secret TEXT;`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_devices_updated ON devices(updated_at DESC);`);

  // device_events
  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_events (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      device_id   TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
      event_type  TEXT NOT NULL,
      payload     JSONB NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_device_events_device_time
      ON device_events (device_id, created_at DESC);
  `);

  // device_notes
  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_notes (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      device_id   TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
      note        TEXT NOT NULL,
      created_by  TEXT,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_device_notes_device_time
      ON device_notes (device_id, created_at DESC);
  `);

  // device_commands
  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_commands (
      id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      device_id   TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
      kind        TEXT NOT NULL,
      payload     JSONB NOT NULL,
      status      TEXT NOT NULL DEFAULT 'queued',
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      sent_at     TIMESTAMPTZ,
      done_at     TIMESTAMPTZ,
      error       TEXT
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_device_commands_device_status
      ON device_commands (device_id, status, created_at);
  `);

  console.log('[migrations] ok');
}

// ---------- Health ----------
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/db-ping', async (_req, res) => {
  try {
    await pool.query('select 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------- Device: register ----------
app.post('/v1/devices/register', async (req, res) => {
  try {
    const {
      deviceId, deviceSecret,
      appVersion, tauriVersion,
      osName, osVersion, arch,
      hostname, username,
    } = req.body || {};

    if (!deviceId || !deviceSecret) {
      return res.status(400).json({ ok: false, error: 'missing deviceId/deviceSecret' });
    }

    await pool.query(`
      INSERT INTO devices
        (device_id, app_version, tauri_version, os_name, os_version, arch, hostname, username, device_secret,
         status, first_seen_at, last_seen_at, ip_last, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'active', now(), now(), $10, now())
      ON CONFLICT (device_id) DO UPDATE SET
        app_version = EXCLUDED.app_version,
        tauri_version = EXCLUDED.tauri_version,
        os_name = EXCLUDED.os_name,
        os_version = EXCLUDED.os_version,
        arch = EXCLUDED.arch,
        hostname = EXCLUDED.hostname,
        username = EXCLUDED.username,
        device_secret = COALESCE(EXCLUDED.device_secret, devices.device_secret),
        last_seen_at = now(),
        ip_last = EXCLUDED.ip_last,
        updated_at = now();
    `, [deviceId, appVersion, tauriVersion, osName, osVersion, arch, hostname, username, deviceSecret, req.ip]);

    // event
    await pool.query(`
      INSERT INTO device_events (device_id, event_type, payload)
      VALUES ($1,'register', $2)
    `, [deviceId, req.body]);

    res.json({ ok: true });
  } catch (e) {
    console.error('register error', e);
    res.status(500).json({ ok: false, error: 'server' });
  }
});

// ---------- Device: poll for commands & ACK results ----------
async function findDeviceForAuth(deviceId, deviceSecret) {
  const { rows } = await pool.query(
    `SELECT device_id, device_secret FROM devices WHERE device_id=$1 LIMIT 1`, [deviceId]
  );
  if (!rows.length) return null;
  const d = rows[0];
  if (d.device_secret && d.device_secret === deviceSecret) return d;
  if (!d.device_secret && deviceSecret && deviceSecret.length > 8) {
    await pool.query(`UPDATE devices SET device_secret=$1 WHERE device_id=$2`, [deviceSecret, deviceId]);
    return { device_id: deviceId, device_secret: deviceSecret };
  }
  return null;
}

app.post('/v1/devices/poll', async (req, res) => {
  try {
    const { deviceId, deviceSecret, max = 5, results = [] } = req.body || {};
    if (!deviceId || !deviceSecret) return res.status(400).json({ ok: false, error: 'missing deviceId/deviceSecret' });

    const dev = await findDeviceForAuth(deviceId, deviceSecret);
    if (!dev) return res.status(401).json({ ok: false, error: 'unauthorized' });

    // record results
    for (const r of results) {
      if (!r || !r.id) continue;
      const ok = !!r.ok;
      await pool.query(
        `UPDATE device_commands
           SET status=$2, done_at=now(), error=$3
         WHERE id=$1 AND device_id=$4`,
        [r.id, ok ? 'done' : 'failed', ok ? null : (r.error || 'error'), deviceId]
      );
    }

    // fetch next queued
    const { rows } = await pool.query(
      `UPDATE device_commands
          SET status='sent', sent_at=now()
        WHERE id IN (
          SELECT id FROM device_commands
          WHERE device_id=$1 AND status='queued'
          ORDER BY created_at ASC
          LIMIT $2
        )
        RETURNING id, kind, payload`,
      [deviceId, Math.max(1, Math.min(20, max))]
    );

    res.json({ ok: true, commands: rows || [] });
  } catch (e) {
    console.error('poll error', e);
    res.status(500).json({ ok: false, error: 'server' });
  }
});

// ---------- (Optional) Public device list ----------
app.get('/v1/devices', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM devices ORDER BY updated_at DESC LIMIT 50`
    );
    res.json({ ok: true, devices: rows.map(mapDevice), limit: 50, offset: 0 });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'server' });
  }
});

// ---------- Admin APIs ----------
app.get('/admin/api/devices', adminAuth, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const limit = Math.max(1, Math.min(200, parseInt(req.query.limit || '25', 10)));
    const offset = (page - 1) * limit;
    const q = (req.query.q || '').toString().trim();
    const status = (req.query.status || '').toString().trim();

    const where = [];
    const params = [];
    let idx = 1;

    if (q) {
      where.push(`(
        device_id ILIKE $${idx} OR
        hostname  ILIKE $${idx} OR
        username  ILIKE $${idx} OR
        os_name   ILIKE $${idx} OR
        os_version ILIKE $${idx} OR
        ip_last   ILIKE $${idx}
      )`);
      params.push(`%${q}%`); idx++;
    }
    if (status) { where.push(`status = $${idx}`); params.push(status); idx++; }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const total = await pool.query(`SELECT COUNT(*)::int AS n FROM devices ${whereSql}`, params);
    const items = await pool.query(
      `SELECT * FROM devices ${whereSql} ORDER BY updated_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...params, limit, offset]
    );

    res.json({
      ok: true,
      page,
      limit,
      total: total.rows[0].n,
      items: items.rows.map(mapDevice),
    });
  } catch (e) {
    console.error('admin/devices list error', e);
    res.status(500).json({ ok: false, error: 'server' });
  }
});

app.get('/admin/api/devices/:id', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const { rows } = await pool.query(`SELECT * FROM devices WHERE device_id=$1 LIMIT 1`, [id]);
    if (!rows.length) return res.status(404).json({ ok: false, error: 'not found' });
    res.json({ ok: true, device: mapDevice(rows[0]) });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'server' });
  }
});

app.get('/admin/api/devices/:id/events', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const limit = Math.max(1, Math.min(200, parseInt(req.query.limit || '50', 10)));
    const { rows } = await pool.query(
      `SELECT id, event_type AS "eventType", payload, created_at AS "createdAt"
       FROM device_events
       WHERE device_id=$1
       ORDER BY created_at DESC
       LIMIT $2`,
      [id, limit]
    );
    res.json({ ok: true, events: rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'server' });
  }
});

app.get('/admin/api/devices/:id/notes', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const { rows } = await pool.query(
      `SELECT id, note, created_by AS "createdBy", created_at AS "createdAt"
       FROM device_notes
       WHERE device_id=$1
       ORDER BY created_at DESC`,
      [id]
    );
    res.json({ ok: true, notes: rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'server' });
  }
});

app.post('/admin/api/devices/:id/notes', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const { note, createdBy } = req.body || {};
    if (!note || !note.trim()) return res.status(400).json({ ok: false, error: 'note required' });
    await pool.query(
      `INSERT INTO device_notes (device_id, note, created_by) VALUES ($1,$2,$3)`,
      [id, note.trim(), createdBy || 'admin']
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'server' });
  }
});

app.post('/admin/api/devices/:id/status', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const { status } = req.body || {};
    if (!status) return res.status(400).json({ ok: false, error: 'status required' });
    await pool.query(
      `UPDATE devices SET status=$2, updated_at=now() WHERE device_id=$1`,
      [id, status]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'server' });
  }
});

// enqueue command
app.post('/admin/api/devices/:id/commands', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const { kind, payload } = req.body || {};
    if (!kind || typeof payload !== 'object') return res.status(400).json({ ok: false, error: 'kind/payload required' });
    await pool.query(
      `INSERT INTO device_commands (device_id, kind, payload) VALUES ($1,$2,$3)`,
      [id, String(kind), payload]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('enqueue cmd error', e);
    res.status(500).json({ ok: false, error: 'server' });
  }
});

// ---------- Static admin UI ----------
app.use('/admin', express.static(path.join(__dirname, 'admin'), { index: ['index.html'] }));

// ---------- Root ----------
app.get('/', (_req, res) => res.json({ ok: true, service: 'devicehub-api' }));

// ---------- Boot ----------
ensureMigrations()
  .then(() => {
    app.listen(PORT, () => console.log('API listening on', PORT));
  })
  .catch((e) => {
    console.error('[migrations] failed', e);
    process.exit(1);
  });
