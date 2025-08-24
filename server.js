// server.js — API + Admin UI

require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const crypto = require('crypto');
const { Pool } = require('pg');

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || ''; // set in DO App Platform

function sha256(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }
function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf && typeof xf === 'string') return xf.split(',')[0].trim();
  return (req.socket?.remoteAddress || '').replace('::ffff:', '');
}

// Postgres (TLS verify disabled; you also set NODE_TLS_REJECT_UNAUTHORIZED=0)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(helmet());
app.use(cors());
app.use(morgan('tiny'));

// --------- public health ----------
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/db-ping', async (_req, res) => {
  try {
    const { rows } = await pool.query('SELECT 1 AS ok');
    return res.json({ ok: rows[0].ok === 1 });
  } catch (e) {
    console.error('db-ping error:', e);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// --------- device registration ----------
app.post('/v1/devices/register', async (req, res) => {
  try {
    const {
      deviceId, deviceSecret,
      appVersion, tauriVersion,
      osName, osVersion, arch,
      hostname, username
    } = req.body || {};
    if (!deviceId || !deviceSecret || !appVersion || !osName || !osVersion || !arch || !hostname) {
      return res.status(400).json({ ok: false, error: 'missing_required_fields' });
    }
    const hash = sha256(deviceSecret);
    const ip = getClientIp(req);

    await pool.query(`
      INSERT INTO devices (
        device_id, device_secret_hash, app_version, tauri_version,
        os_name, os_version, arch, hostname, username, ip_last, status
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::inet,'active')
      ON CONFLICT (device_id) DO UPDATE SET
        device_secret_hash = EXCLUDED.device_secret_hash,
        app_version        = EXCLUDED.app_version,
        tauri_version      = EXCLUDED.tauri_version,
        os_name            = EXCLUDED.os_name,
        os_version         = EXCLUDED.os_version,
        arch               = EXCLUDED.arch,
        hostname           = EXCLUDED.hostname,
        username           = EXCLUDED.username,
        ip_last            = EXCLUDED.ip_last,
        status             = 'active',
        last_seen_at       = now(),
        updated_at         = now()
    `, [deviceId, hash, appVersion, tauriVersion || null,
        osName, osVersion, arch, hostname, username || null, ip || null]);

    await pool.query(
      `INSERT INTO device_events (device_id, event_type, payload)
       VALUES ($1,'register',$2::jsonb)`,
      [deviceId, JSON.stringify({ ip, appVersion, tauriVersion, osName, osVersion, arch, hostname, username })]
    );

    return res.json({ ok: true, deviceId });
  } catch (e) {
    console.error('register error:', e);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// --------- heartbeat ----------
app.post('/v1/devices/heartbeat', async (req, res) => {
  try {
    const { deviceId, deviceSecret } = req.body || {};
    if (!deviceId || !deviceSecret) return res.status(400).json({ ok:false, error:'missing_required_fields' });

    const hash = sha256(deviceSecret);
    const ip = getClientIp(req);

    const { rowCount } = await pool.query(
      `UPDATE devices
         SET last_seen_at = now(),
             updated_at   = now(),
             ip_last      = $3::inet,
             status       = 'active'
       WHERE device_id = $1 AND device_secret_hash = $2`,
      [deviceId, hash, ip || null]
    );
    if (rowCount === 0) return res.status(403).json({ ok:false, error:'invalid_device_or_secret' });

    await pool.query(
      `INSERT INTO device_events (device_id, event_type, payload)
       VALUES ($1,'heartbeat',$2::jsonb)`,
      [deviceId, JSON.stringify({ ip, ts: new Date().toISOString() })]
    );

    res.json({ ok:true });
  } catch (e) {
    console.error('heartbeat error:', e);
    res.status(500).json({ ok:false, error: e.message });
  }
});

// ---------- public list ----------
app.get('/v1/devices', async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(200, parseInt(req.query.limit) || 50));
    const offset = Math.max(0, parseInt(req.query.offset) || 0);

    const { rows } = await pool.query(
      `SELECT
         device_id      AS "deviceId",
         app_version    AS "appVersion",
         tauri_version  AS "tauriVersion",
         os_name        AS "osName",
         os_version     AS "osVersion",
         arch,
         hostname,
         username,
         ip_last        AS "ipLast",
         status,
         first_seen_at  AS "firstSeenAt",
         last_seen_at   AS "lastSeenAt",
         updated_at     AS "updatedAt"
       FROM devices
       ORDER BY last_seen_at DESC NULLS LAST, updated_at DESC NULLS LAST
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    res.json({ ok: true, devices: rows, limit, offset });
  } catch (e) {
    console.error('list devices error:', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// =====================================================
//               ADMIN (CRM-style) BACKEND
// =====================================================
function adminAuth(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(503).json({ ok:false, error:'admin_not_configured' });
  const h = req.headers.authorization || '';
  if (h === `Bearer ${ADMIN_TOKEN}`) return next();
  return res.status(401).json({ ok:false, error:'unauthorized' });
}

// List/search (admin)
app.get('/admin/api/devices', adminAuth, async (req, res) => {
  try {
    const q = (req.query.q || '').toString().trim();
    const status = (req.query.status || '').toString().trim();
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit) || 25));
    const offset = (page - 1) * limit;

    const where = [];
    const vals = [];
    let i = 1;

    if (q) {
      where.push(`(
        device_id ILIKE $${i} OR
        hostname  ILIKE $${i} OR
        username  ILIKE $${i} OR
        os_name   ILIKE $${i} OR
        os_version ILIKE $${i} OR
        arch      ILIKE $${i} OR
        ip_last::text ILIKE $${i}
      )`);
      vals.push(`%${q}%`); i++;
    }
    if (status) { where.push(`status = $${i}`); vals.push(status); i++; }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const { rows } = await pool.query(
      `SELECT
         device_id      AS "deviceId",
         app_version    AS "appVersion",
         tauri_version  AS "tauriVersion",
         os_name        AS "osName",
         os_version     AS "osVersion",
         arch,
         hostname,
         username,
         ip_last        AS "ipLast",
         status,
         first_seen_at  AS "firstSeenAt",
         last_seen_at   AS "lastSeenAt",
         updated_at     AS "updatedAt"
       FROM devices
       ${whereSql}
       ORDER BY last_seen_at DESC NULLS LAST, updated_at DESC NULLS LAST
       LIMIT $${i} OFFSET $${i+1}`,
       [...vals, limit, offset]
    );

    const { rows: c } = await pool.query(
      `SELECT COUNT(*)::int AS count FROM devices ${whereSql}`, vals
    );

    res.json({ ok:true, items: rows, page, limit, total: c[0].count });
  } catch (e) {
    console.error('admin list error:', e);
    res.status(500).json({ ok:false, error: e.message });
  }
});

// Device detail (admin)
app.get('/admin/api/devices/:id', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const { rows } = await pool.query(
      `SELECT
         device_id      AS "deviceId",
         app_version    AS "appVersion",
         tauri_version  AS "tauriVersion",
         os_name        AS "osName",
         os_version     AS "osVersion",
         arch,
         hostname,
         username,
         ip_last        AS "ipLast",
         status,
         first_seen_at  AS "firstSeenAt",
         last_seen_at   AS "lastSeenAt",
         updated_at     AS "updatedAt"
       FROM devices WHERE device_id = $1`, [id]
    );
    if (!rows.length) return res.status(404).json({ ok:false, error:'not_found' });
    res.json({ ok:true, device: rows[0] });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});

// Device events (admin)
app.get('/admin/api/devices/:id/events', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const limit = Math.max(1, Math.min(500, parseInt(req.query.limit) || 100));
    const { rows } = await pool.query(
      `SELECT id, event_type AS "eventType", payload, created_at AS "createdAt"
         FROM device_events
        WHERE device_id = $1
        ORDER BY created_at DESC
        LIMIT $2`, [id, limit]
    );
    res.json({ ok:true, events: rows });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});

// Notes add/get (admin)
app.post('/admin/api/devices/:id/notes', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const note = (req.body?.note || '').toString().trim();
    const createdBy = (req.body?.createdBy || 'admin').toString().trim() || 'admin';
    if (!note) return res.status(400).json({ ok:false, error:'note_required' });

    await pool.query(
      `INSERT INTO device_notes (device_id, note, created_by)
       VALUES ($1,$2,$3)`, [id, note, createdBy]
    );
    res.json({ ok:true });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});
app.get('/admin/api/devices/:id/notes', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const { rows } = await pool.query(
      `SELECT id, note, created_by AS "createdBy", created_at AS "createdAt"
         FROM device_notes
        WHERE device_id = $1
        ORDER BY created_at DESC`, [id]
    );
    res.json({ ok:true, notes: rows });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});

// Status update (admin)
app.post('/admin/api/devices/:id/status', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const status = (req.body?.status || '').toString().trim();
    if (!['active','disabled','retired'].includes(status)) {
      return res.status(400).json({ ok:false, error:'invalid_status' });
    }
    await pool.query(
      `UPDATE devices SET status = $2, updated_at = now() WHERE device_id = $1`,
      [id, status]
    );
    res.json({ ok:true });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});

// --------- serve the Admin UI (static; file added next step) ----------
app.use('/admin', express.static(path.join(__dirname, 'admin')));

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});

