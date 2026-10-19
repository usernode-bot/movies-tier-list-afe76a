const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// The platform signs user-identity tokens with an RSA private key it never
// shares. Containers get only the PUBLIC half, so this app can verify who a
// user is but cannot mint an identity — and neither can any other app.
const JWT_PUBLIC_KEY = (process.env.USERNODE_JWT_PUBLIC_KEY || '')
  .replace(/\\n/g, '\n');

// Tokens are minted for one app: the audience is this app's numeric id, so a
// token issued for a different app is rejected below rather than accepted as
// a valid user.
const APP_AUDIENCE = process.env.USERNODE_APP_ID
  ? 'usernode:app:' + process.env.USERNODE_APP_ID
  : null;

// Visitors with no Homeroom account ("guests") may look around this app at
// its own address, read-only (every public app). The platform marks
// them with a token of their own: ES256, signed by a key of its own (its
// public half is USERNODE_GUEST_JWT_PUBLIC_KEY), this audience, `pur:
// 'guest'`, `guest: true`, and no id or username. Such a visitor is
// `req.guest`, never `req.user`, and every write they try is answered 401
// `account_required`, which the bridge turns into "Make an account to
// continue".
const GUEST_AUDIENCE = APP_AUDIENCE ? APP_AUDIENCE + ':guest' : null;
const GUEST_PUBLIC_KEY = (process.env.USERNODE_GUEST_JWT_PUBLIC_KEY || '')
  .replace(/\\n/g, '\n');

// Paths that stay open without authentication. Add a path here (and add it
// with `app.get`/`app.post` below) if you deliberately want it public.
// Everything else requires a valid platform-issued JWT.
const PUBLIC_API_PATHS = new Set(['/health']);

app.use(express.json());

// The platform's three centrally hosted files — the bridge, the native UI
// kit and the Tailwind runtime — are reachable at these paths on this app's
// OWN origin, so index.html can load them with a RELATIVE path and never
// name the platform's hostname. A hostname baked into an app is what breaks
// every app at once when the platform's domain moves.
//
// In production and on a staging preview the platform's edge answers these
// before the request ever reaches this process (a per-app Ingress rule on
// Kubernetes, the wildcard site's matcher on the docker runtime). This
// handler is what makes the same relative paths work under a plain
// `node server.js`, where there is no edge in front of the app at all.
//
// Registered BEFORE the auth middleware because these three files are
// public: the platform serves them anonymously from any app origin, and a
// login redirect arriving where a <script> was expected is exactly the
// failure a relative path is meant to avoid.
// The platform's origin, at RUNTIME, and ONLY from the variable the platform
// injects. No hostname is written into this file: a baked-in one is what left
// the whole fleet pointing at a domain the platform had moved away from.
// Unset only outside the platform (a plain local `node server.js`) — set
// USERNODE_PLATFORM_ORIGIN there too if you want the hosted assets locally.
const PLATFORM_ORIGIN = (process.env.USERNODE_PLATFORM_ORIGIN || '')
  .replace(/\/+$/, '');

app.get(/^\/usernode-(?:bridge|native|tailwind)\//, async (req, res) => {
  try {
    if (!PLATFORM_ORIGIN) return res.sendStatus(503);
    const upstream = await fetch(PLATFORM_ORIGIN + req.path);
    if (!upstream.ok) return res.sendStatus(upstream.status);
    const type = upstream.headers.get('content-type');
    if (type) res.type(type);
    // max-age=0 with revalidation, never a long TTL: the whole point of
    // central hosting is that a platform-side fix lands on the next load.
    res.set('Cache-Control', 'public, max-age=0, must-revalidate');
    return res.send(Buffer.from(await upstream.arrayBuffer()));
  } catch (err) {
    console.warn('hosted asset fetch failed: ' + err.message);
    return res.sendStatus(502);
  }
});

// "Now" for this request, as a Date: `req.now`, set for every request by
// the middleware below. Read the day and the time through it (and
// `usernode.now()` in the page), never `new Date()` or SQL's NOW(),
// wherever they decide what shows: a reminder, a rota, a deadline.
// Production always gets the real time. A staging preview may be shown as of
// a chosen moment: the platform opens it with `?un-now=<ISO time>`, and the
// page sends `usernode.now()` on as the `x-usernode-now` header. Only a
// staging container reads either. See "Time-dependent features" in the
// platform conventions.
const IS_STAGING = process.env.USERNODE_ENV === 'staging';
const PREVIEW_NOW = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/;
function requestNow(req) {
  const raw = IS_STAGING ? (req.headers['x-usernode-now'] || req.query['un-now']) : null;
  return typeof raw === 'string' && PREVIEW_NOW.test(raw) ? new Date(raw) : new Date();
}

// Verify platform-issued JWT if one was passed, then enforce auth on
// anything not explicitly marked public. The iframe adds `?token=…`
// on load; the frontend script forwards the token via `x-usernode-token`
// on subsequent fetches.
app.use((req, res, next) => {
  req.now = requestNow(req);
  const token = req.query.token || req.headers['x-usernode-token'];
  if (token && JWT_PUBLIC_KEY && APP_AUDIENCE) {
    try {
      // Pin the algorithm, issuer and audience. Without `algorithms` a
      // caller could hand us an HS256 token signed with the public PEM
      // (which every app knows) and forge any user.
      const claims = jwt.verify(token, JWT_PUBLIC_KEY, {
        algorithms: ['RS256'],
        issuer: 'usernode',
        audience: APP_AUDIENCE,
      });
      // `pur` names what the token is for. Only user-identity tokens
      // authenticate a person here.
      if (claims && claims.pur === 'iframe') req.user = claims;
    } catch {}
  }
  if (!req.user && token && GUEST_PUBLIC_KEY && GUEST_AUDIENCE) {
    try {
      const guest = jwt.verify(token, GUEST_PUBLIC_KEY, {
        algorithms: ['ES256'],
        issuer: 'usernode',
        audience: GUEST_AUDIENCE,
      });
      if (guest && guest.pur === 'guest' && guest.guest === true) req.guest = true;
    } catch {}
  }

  // Static assets (CSS/JS/images) are always served; the API and the HTML
  // shell are gated so direct hits to the staging/prod subdomain don't
  // leak app data to the public internet. A guest may READ: every GET,
  // `/api/*` included, so read routes must not assume req.user (use
  // `req.user ? req.user.id : null`). Every write needs an account.
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    if (!req.user && req.guest) {
      if (req.method === 'GET' || req.method === 'HEAD') return next();
      return res.status(401).json({ error: 'account_required' });
    }
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// The template ships no favicon file; index.html carries an inline SVG
// icon instead. Answer 204 here so anything that still probes
// /favicon.ico (older browsers, direct visits) doesn't fall through to
// the auth-gated catch-all and surface a 401 in the console on every
// fresh load.
app.get('/favicon.ico', (_req, res) => res.status(204).end());

// ── The movie tier list ──────────────────────────────────────────────────
// One shared list: anyone in the project adds a movie by name, anyone moves
// it into one of five fixed tiers (S best to D worst), and a movie with no
// tier is "Waiting to be sorted". Only the person who added a movie can
// remove it. Demo rows are staging only and never appear without ?demo=1.
const TIERS = new Set(['S', 'A', 'B', 'C', 'D']);

function isDemoRequest(req) {
  return IS_STAGING && req.query.demo === '1';
}

function viewerIdOf(req) {
  return req.user ? String(req.user.id || req.user.sub || '') : null;
}

function viewerNameOf(req) {
  return (req.user && req.user.username) || 'Someone';
}

// Staging mock data: fifteen made-up picks from four made-up friends, so the
// populated screen can be seen. Fixed ids keep it idempotent, and is_demo
// keeps every row out of the plain list.
const DEMO_FRIENDS = [
  // tier, title, added by, moved by, minutes ago placed
  ['S', 'Spirited Away', 'Maya', 'Maya', 600],
  ['S', 'Parasite', 'Priya', 'Priya', 590],
  ['S', 'The Godfather', 'Sam', 'Sam', 580],
  ['A', 'Inception', 'Theo', 'Theo', 570],
  ['A', 'Mad Max: Fury Road', 'Maya', 'Maya', 560],
  ['A', 'Knives Out', 'Priya', 'Priya', 550],
  ['A', 'Coco', 'Sam', 'Sam', 540],
  ['A', 'Heat', 'Theo', 'Theo', 530],
  ['B', 'Top Gun: Maverick', 'Sam', 'Sam', 520],
  ['B', 'The Martian', 'Priya', 'Priya', 510],
  ['B', 'Barbie', 'Maya', 'Maya', 500],
  ['C', 'Jurassic World', 'Theo', 'Theo', 490],
  ['C', 'Cats', 'Sam', 'Sam', 480],
  [null, 'Everything Everywhere All at Once', 'Theo', null, 470],
  [null, 'The Holdovers', 'Maya', null, 460],
];

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS movies (
      id serial PRIMARY KEY,
      title text NOT NULL,
      tier text CHECK (tier IS NULL OR tier IN ('S', 'A', 'B', 'C', 'D')),
      added_by_id text NOT NULL,
      added_by_name text NOT NULL,
      moved_by_name text,
      created_at timestamptz NOT NULL DEFAULT now(),
      placed_at timestamptz,
      is_demo boolean NOT NULL DEFAULT false,
      demo_key text
    );
    CREATE UNIQUE INDEX IF NOT EXISTS movies_title_demo_uidx
      ON movies (lower(title), is_demo);
    CREATE UNIQUE INDEX IF NOT EXISTS movies_demo_key_uidx
      ON movies (demo_key, added_by_id);
    CREATE TABLE IF NOT EXISTS movie_reports (
      id serial PRIMARY KEY,
      movie_id integer NOT NULL REFERENCES movies (id) ON DELETE CASCADE,
      reporter_id text NOT NULL,
      reporter_name text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (movie_id, reporter_id)
    );
    COMMENT ON TABLE movie_reports IS 'staging:private';
  `);

  if (!IS_STAGING) return;

  // One marker per viewer, so the demo's own rows are written once and a
  // removed one is not put back by the next demo load.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS demo_seeded (
      viewer_id text PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  const base = Date.parse('2026-01-05T18:00:00Z');
  const values = [];
  const params = [];
  DEMO_FRIENDS.forEach(([tier, title, friend, movedBy, minutesAgo], i) => {
    const at = new Date(base - minutesAgo * 60000);
    const offset = i * 8;
    params.push(900001 + i, title, tier, 'demo-' + friend.toLowerCase(), friend,
      movedBy, at.toISOString(), tier ? at.toISOString() : null);
    values.push(`($${offset + 1}::integer, $${offset + 2}::text, $${offset + 3}::text,
      $${offset + 4}::text, $${offset + 5}::text, $${offset + 6}::text,
      $${offset + 7}::timestamptz, $${offset + 8}::timestamptz, true)`);
  });
  await pool.query(
    `INSERT INTO movies (id, title, tier, added_by_id, added_by_name,
       moved_by_name, created_at, placed_at, is_demo)
     VALUES ${values.join(', ')}
     ON CONFLICT DO NOTHING`,
    params
  );
}

// The viewer's own two demo rows: one already sorted, one waiting, so
// Remove works in the populated preview. Written on the first ?demo=1 load
// by that viewer, never on a plain route.
async function ensureViewerDemoRows(req) {
  if (!req.user) return;
  const viewerId = viewerIdOf(req);
  const now = req.now.toISOString();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const seeded = await client.query(
      `INSERT INTO demo_seeded (viewer_id, created_at) VALUES ($1::text, $2::timestamptz)
       ON CONFLICT (viewer_id) DO NOTHING
       RETURNING viewer_id`,
      [viewerId, now]
    );
    if (seeded.rowCount) {
      await client.query(
        `INSERT INTO movies (title, tier, added_by_id, added_by_name,
           moved_by_name, created_at, placed_at, is_demo, demo_key)
         VALUES ('Paddington 2', 'S', $1::text, $2::text, 'Maya', $3::timestamptz, $3::timestamptz, true, 'paddington'),
                ('Dune: Part Two', NULL, $1::text, $2::text, NULL, $3::timestamptz, NULL, true, 'dune')
         ON CONFLICT DO NOTHING`,
        [viewerId, viewerNameOf(req), now]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

const MOVIE_SELECT = `
  SELECT m.id, m.title, m.tier, m.added_by_id, m.added_by_name,
         m.moved_by_name, m.created_at, m.placed_at, m.is_demo,
         EXISTS (
           SELECT 1 FROM movie_reports r
           WHERE r.movie_id = m.id AND r.reporter_id = $1
         ) AS reported_by_viewer
  FROM movies m`;

const MOVIE_ORDER = `
  ORDER BY CASE m.tier
             WHEN 'S' THEN 1 WHEN 'A' THEN 2 WHEN 'B' THEN 3
             WHEN 'C' THEN 4 WHEN 'D' THEN 5 ELSE 6 END,
           CASE WHEN m.tier IS NULL THEN m.created_at END DESC NULLS LAST,
           m.placed_at ASC NULLS FIRST,
           m.id ASC`;

function serializeMovie(row, viewerId) {
  return {
    id: row.id,
    title: row.title,
    tier: row.tier,
    addedById: row.added_by_id,
    addedByName: row.added_by_name,
    movedByName: row.moved_by_name,
    createdAt: row.created_at,
    placedAt: row.placed_at,
    isMine: viewerId !== null && String(row.added_by_id) === viewerId,
    reported: row.reported_by_viewer === true,
  };
}

app.get('/api/movies', async (req, res) => {
  try {
    const demo = isDemoRequest(req);
    if (demo) await ensureViewerDemoRows(req);
    const viewerId = viewerIdOf(req);
    const { rows } = await pool.query(
      MOVIE_SELECT + (demo ? ' WHERE m.is_demo = true' : ' WHERE m.is_demo = false') +
        MOVIE_ORDER,
      [viewerId]
    );
    res.json({ movies: rows.map((row) => serializeMovie(row, viewerId)), viewerId });
  } catch (err) {
    console.error('list movies failed: ' + err.message);
    res.status(500).json({ error: 'list_failed' });
  }
});

app.post('/api/movies', async (req, res) => {
  const raw = req.body && req.body.title;
  const title = typeof raw === 'string' ? raw.trim() : '';
  if (!title || title.length > 120) {
    return res.status(400).json({ error: 'invalid_title' });
  }
  const demo = isDemoRequest(req);
  const viewerId = viewerIdOf(req);
  const addedByName = viewerNameOf(req);
  try {
    const existing = await pool.query(
      'SELECT tier FROM movies WHERE lower(title) = lower($1) AND is_demo = $2 LIMIT 1',
      [title, demo]
    );
    if (existing.rows.length) {
      return res.status(409).json({ error: 'duplicate', tier: existing.rows[0].tier });
    }
    const { rows } = await pool.query(
      `INSERT INTO movies (title, tier, added_by_id, added_by_name,
         created_at, is_demo)
       VALUES ($1, NULL, $2, $3, $4, $5)
       RETURNING id, title, tier, added_by_id, added_by_name, moved_by_name,
                 created_at, placed_at, false AS reported_by_viewer`,
      [title, viewerId, addedByName, req.now.toISOString(), demo]
    );
    res.status(201).json({ movie: serializeMovie(rows[0], viewerId) });
  } catch (err) {
    if (err.code === '23505') {
      const existing = await pool.query(
        'SELECT tier FROM movies WHERE lower(title) = lower($1) AND is_demo = $2 LIMIT 1',
        [title, demo]
      );
      return res.status(409).json({ error: 'duplicate', tier: existing.rows[0] ? existing.rows[0].tier : null });
    }
    console.error('add movie failed: ' + err.message);
    res.status(500).json({ error: 'add_failed' });
  }
});

// Load one row the viewer is allowed to write to, or answer 404. Demo rows
// exist only in the demo view, so a write without ?demo=1 cannot reach them.
async function writableMovie(req, res) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) {
    res.status(404).json({ error: 'not_found' });
    return null;
  }
  const { rows } = await pool.query(
    `SELECT id, title, tier, added_by_id, added_by_name, is_demo
     FROM movies WHERE id = $1`,
    [id]
  );
  if (!rows.length || (rows[0].is_demo && !isDemoRequest(req))) {
    res.status(404).json({ error: 'not_found' });
    return null;
  }
  return rows[0];
}

app.patch('/api/movies/:id', async (req, res) => {
  const body = req.body || {};
  if (!Object.prototype.hasOwnProperty.call(body, 'tier')) {
    return res.status(400).json({ error: 'invalid_tier' });
  }
  const tier = body.tier === null ? null : body.tier;
  if (tier !== null && !TIERS.has(tier)) {
    return res.status(400).json({ error: 'invalid_tier' });
  }
  try {
    const movie = await writableMovie(req, res);
    if (!movie) return;
    const { rows } = await pool.query(
      `UPDATE movies
       SET tier = $1, moved_by_name = $2, placed_at = $3
       WHERE id = $4
       RETURNING id, title, tier, added_by_id, added_by_name, moved_by_name,
                 created_at, placed_at, false AS reported_by_viewer`,
      [tier, viewerNameOf(req), tier ? req.now.toISOString() : null, movie.id]
    );
    res.json({ movie: serializeMovie(rows[0], viewerIdOf(req)) });
  } catch (err) {
    console.error('move movie failed: ' + err.message);
    res.status(500).json({ error: 'move_failed' });
  }
});

app.delete('/api/movies/:id', async (req, res) => {
  try {
    const movie = await writableMovie(req, res);
    if (!movie) return;
    if (String(movie.added_by_id) !== viewerIdOf(req)) {
      return res.status(403).json({ error: 'not_your_movie' });
    }
    await pool.query('DELETE FROM movies WHERE id = $1', [movie.id]);
    res.json({ removed: true });
  } catch (err) {
    console.error('remove movie failed: ' + err.message);
    res.status(500).json({ error: 'remove_failed' });
  }
});

app.post('/api/movies/:id/report', async (req, res) => {
  try {
    const movie = await writableMovie(req, res);
    if (!movie) return;
    const viewerId = viewerIdOf(req);
    if (String(movie.added_by_id) === viewerId) {
      return res.status(400).json({ error: 'own_movie' });
    }
    await pool.query(
      `INSERT INTO movie_reports (movie_id, reporter_id, reporter_name, created_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (movie_id, reporter_id) DO NOTHING`,
      [movie.id, viewerId, viewerNameOf(req), req.now.toISOString()]
    );
    res.json({ reported: true });
  } catch (err) {
    console.error('report movie failed: ' + err.message);
    res.status(500).json({ error: 'report_failed' });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

// HTML shell: serve the app if authenticated. Unauthenticated top-level
// visits (share links pasted into a browser — Sec-Fetch-Dest: document)
// are sent to the platform's chromeless view of this app, where the shell
// embeds it with a real token so the link just works. Every other
// tokenless case (iframe loads with an expired token, old browsers
// without Sec-Fetch-*) gets the "open in Homeroom" landing page instead
// of a redirect, so the platform shell is never loaded INSIDE its own
// app iframe and stray visits still don't reveal the app.
app.get('*', (req, res) => {
  if (!req.user && !req.guest) {
    // Deep-link pass-through (platform #743): carry the visited
    // path+query into the chromeless view so share links land on the
    // shared screen, not Home. The clean platform route stores `path`
    // as one encoded query value so an inner ?, &, or = survives. The
    // shell decodes and validates it as relative-only before use. The
    // character test keeps the
    // value attribute-safe for the landing anchor below — anything
    // unusual falls back to the bare link.
    const deepPath = /^\/[A-Za-z0-9\-._~!$&()*+,;=:@\/%?]*$/.test(req.originalUrl)
      ? '?path=' + encodeURIComponent(req.originalUrl) : '';
    if (PLATFORM_ORIGIN && req.get('sec-fetch-dest') === 'document') {
      return res.redirect(302, PLATFORM_ORIGIN + '/app/movies-tier-list-afe76a/full' + deepPath);
    }
    return res.status(401).send(`<!doctype html><meta charset=utf-8><title>Open in Homeroom</title>
<body style="font-family:system-ui;background:#09090b;color:#e4e4e7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="max-width:24rem;padding:2rem;text-align:center">
    <h1 style="font-size:1.25rem;margin:0 0 0.5rem">Open this app inside Homeroom</h1>
    <p style="color:#a1a1aa;font-size:0.9rem;margin:0 0 1.25rem">This page is served via the platform; direct visits aren't authenticated.</p>
    <a href="${PLATFORM_ORIGIN}/app/movies-tier-list-afe76a/full${deepPath}" style="display:inline-block;padding:0.5rem 1rem;background:#7c3aed;color:white;border-radius:0.5rem;text-decoration:none;font-size:0.9rem">Open in Homeroom</a>
  </div>
</body>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

let server = null;
let closing = false;

async function start() {
  await initDb();
  server = app.listen(port, () => console.log(`Listening on :${port}`));
  // Let Envoy retire idle upstream connections at 60s, with a 15s margin.
  server.keepAliveTimeout = 75_000;
}

// Stop accepting connections, give in-flight requests ~3 seconds to finish,
// close the pool and exit.
function shutdown(signal) {
  if (closing) return;
  closing = true;
  console.log(`${signal} received, shutting down`);
  const finish = () => {
    pool.end().catch(() => {}).finally(() => process.exit(0));
  };
  if (!server) return finish();
  server.close(finish);
  setTimeout(finish, 3000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

start().catch(err => { console.error(err); process.exit(1); });
