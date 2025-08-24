// server.js (final, copy-paste all of this)

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const crypto = require('crypto');
const { Pool } = require('pg');

// ---------- helpers ----------
function sha256(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }
function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf && typeof xf === 'string') return xf.split(',')[0].trim();
  return (req.socket?.remoteAddress || '').replace('::ffff:', '');
}

// ---------- DB pool (TLS cert checks disabled on purpose) ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // final nail: bypass CA validation
});

// ---------- app ----------
const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors());
app.use(morgan('tiny'));

// ---------- health ----------
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

// ---------- POST /v1/devices/register ----------
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

    const device_secret_hash = sha256(deviceSecret);
    const ip = getClientIp(req);

    await pool.query(`
      INSERT INTO devices (
        device_id, device_secret_hash, app_version, tauri_version,
        os_name, os_version, arch, hostname, username, ip_last
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::inet)
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
        last_seen_at       = now(),
        updated_at         = now()
    `, [deviceId, device_secret_hash, appVersion, tauriVersion || null,
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

// ---------- GET /v1/devices ----------
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
       ORDER BY last_seen_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    res.json({ ok: true, devices: rows, limit, offset });
  } catch (e) {
    console.error('list devices error:', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});

