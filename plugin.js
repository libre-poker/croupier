// plugin.js — the croupier as a JSS loader plugin (the globs pattern).
//
//   plugins: [{ id: 'croupier', module: 'croupier/plugin.js', prefix: '/croupier' }]
//
// Routes (all under {prefix}):
//   POST /create    make a session (SPEC §3); any verifiable agent may create
//   POST /consent   submit a consent op (SPEC §4)
//   GET  /state     public session view (SPEC §5)
//   GET  /events    per-party SSE channel (replay + live)
//   GET  /health    liveness
//
// Identity, two doors (both per SPEC §6):
//   - real: any credential getAgent understands (bearer/DPoP/NIP-98) on the
//     request; the agent string is the party id.
//   - test/invite: the per-party bearer tokens minted at create — the
//     friend-link flow. Disable with config { tokens: false }.
//
// The croupier deals, proves, and forgets. It never plays.
import { getAgent } from 'javascript-solid-server/auth.js';
import { createCroupier } from './core.js';

export async function activate(api) {
  const prefix = api.prefix || '/croupier';
  const allowTokens = api.config?.tokens !== false;
  const C = createCroupier(api.config?.limits || {});

  const CORS = {
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'authorization, content-type',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
  };
  const cors = (reply) => { for (const [k, v] of Object.entries(CORS)) reply.header(k, v); };

  async function partyOf(request, sid) {
    if (allowTokens) {
      const tok = (request.headers.authorization || '').replace(/^Bearer /, '')
        || request.query?.token;
      const pk = tok && C.partyFromToken(sid, tok);
      if (pk) return pk;
    }
    try {
      const agent = await getAgent(request);
      if (agent) return agent;
    } catch { /* unauthenticated */ }
    return null;
  }

  api.fastify.options(`${prefix}/*`, async (request, reply) => {
    cors(reply);
    return reply.code(204).send();
  });

  api.fastify.post(`${prefix}/create`, async (request, reply) => {
    cors(reply);
    const out = C.create(request.body || {});
    return reply.code(out.error ? 400 : 200).send(out);
  });

  api.fastify.post(`${prefix}/claim`, async (request, reply) => {
    cors(reply);
    const b = request.body || {};
    const out = C.claim(b.sid, b.party, b.code);
    return reply.code(out.error ? (out.error === 'unknown-sid' ? 404 : 403) : 200).send(out);
  });

  // ------------------------------------------------------------ rooms
  // A generic, game-blind message relay: join by code, post, listen.
  // No auth, no inspection, capped and expiring — the "fully generic"
  // half of the two-player architecture. The croupier's consent rules
  // carry the security; the room only carries the chatter.
  const rooms = new Map();       // code -> {log:[], channels:Set<fn>, createdAt}
  const ROOM_TTL = 24 * 3600 * 1000, ROOM_MAX = 2000, ROOM_LOG_MAX = 500, MSG_MAX = 8192;
  setInterval(() => {
    const now = Date.now();
    for (const [code, r] of rooms) if (now - r.createdAt > ROOM_TTL) {
      for (const fn of r.channels) fn(null);
      rooms.delete(code);
    }
  }, 60000).unref?.();

  // a room named by a well-formed code exists whenever someone uses it —
  // server restarts lose the log, never the address
  const resurrect = (codeRaw) => {
    const code = String(codeRaw || '').toUpperCase();
    let r = rooms.get(code);
    if (!r && /^[A-Z0-9]{6}$/.test(code) && rooms.size < ROOM_MAX) {
      // ids seed from the clock so no incarnation ever reuses one — the
      // listeners' replay-dedup sets survive resurrection
      r = { log: [], channels: new Set(), createdAt: Date.now(), name: 'table', game: '', unlisted: false, nextId: Date.now() };
      rooms.set(code, r);
    }
    return r;
  };

  api.fastify.post(`${prefix}/room/create`, async (request, reply) => {
    cors(reply);
    if (rooms.size >= ROOM_MAX) return reply.code(503).send({ error: 'full' });
    const b = request.body || {};
    const code = Array.from({ length: 6 }, () =>
      'ABCDEFGHJKMNPQRSTVWXYZ23456789'[Math.floor(Math.random() * 30)]).join('');
    rooms.set(code, {
      log: [], channels: new Set(), createdAt: Date.now(), nextId: Date.now(),
      name: String(b.name || '').slice(0, 40),
      game: String(b.game || '').slice(0, 24),
      unlisted: b.unlisted === true,
    });
    return { room: code };
  });

  // the directory: public by default; {unlisted:true} at create opts out
  api.fastify.get(`${prefix}/room/list`, async (request, reply) => {
    cors(reply);
    const now = Date.now();
    const list = [...rooms.entries()]
      .filter(([, r]) => !r.unlisted && now - r.createdAt < ROOM_TTL)
      .sort((a, b) => b[1].createdAt - a[1].createdAt)
      .slice(0, 100)
      .map(([code, r]) => ({
        room: code, name: r.name, game: r.game,
        createdAt: r.createdAt, listeners: r.channels.size, msgs: r.log.length,
      }));
    return { rooms: list };
  });

  api.fastify.post(`${prefix}/room/send`, async (request, reply) => {
    cors(reply);
    const b = request.body || {};
    const r = resurrect(b.room);
    if (!r) return reply.code(404).send({ error: 'unknown-room' });
    const msg = b.msg;
    if (msg == null || JSON.stringify(msg).length > MSG_MAX) return reply.code(400).send({ error: 'bad-msg' });
    if (r.nextId === undefined) {
      const base = Date.now();
      r.log.forEach((e, i) => { if (e.id === undefined) e.id = base + i; });
      r.nextId = r.log.length ? r.log[r.log.length - 1].id + 1 : base;
    }
    const entry = { id: r.nextId++, t: Date.now(), msg };
    r.log.push(entry);
    if (r.log.length > ROOM_LOG_MAX) r.log.shift();
    for (const fn of r.channels) fn(entry);
    return { ok: true };
  });

  api.fastify.get(`${prefix}/room/events`, async (request, reply) => {
    const r = resurrect(request.query?.room);
    const raw = reply.raw;
    reply.hijack();
    if (!r) {
      raw.writeHead(404, { 'content-type': 'application/json', ...CORS });
      return raw.end(JSON.stringify({ error: 'unknown-room' }));
    }
    raw.writeHead(200, {
      'content-type': 'text/event-stream', 'cache-control': 'no-cache',
      connection: 'keep-alive', ...CORS,
    });
    raw.write('retry: 1500\n\n');
    // Last-Event-ID: the browser's own resume cursor — replay only the tail
    const since = Number(request.headers['last-event-id'] ?? -1);
    const frame = (e) => `${e.id !== undefined ? 'id: ' + e.id + '\n' : ''}data: ${JSON.stringify(e)}\n\n`;
    for (const e of r.log) { if (!(e.id !== undefined && e.id <= since)) raw.write(frame(e)); }
    const fn = (e) => { if (e === null) return raw.end(); raw.write(frame(e)); };
    r.channels.add(fn);
    const ping = setInterval(() => { try { raw.write(': ping\n\n'); } catch { /* gone */ } }, 25000);
    request.raw.on('close', () => { clearInterval(ping); r.channels.delete(fn); });
  });

  api.fastify.post(`${prefix}/consent`, async (request, reply) => {
    cors(reply);
    const b = request.body || {};
    const party = await partyOf(request, b.sid);
    if (!party) return reply.code(403).send({ error: 'not-a-party' });
    const out = C.consent(b.sid, party, b.op);
    return reply.code(out.error ? (out.error === 'unknown-sid' ? 404 : 400) : 200).send(out);
  });

  api.fastify.get(`${prefix}/state`, async (request, reply) => {
    cors(reply);
    const out = C.state(request.query?.sid);
    return reply.code(out.error ? 404 : 200).send(out);
  });

  // ---- the archive: finished hands live forever, queryable ----------
  // Mongo is the index; the signed document is the truth. The plugin is
  // a mailbox, not a judge: verification stays client-side, always.
  let archiveCol = null;
  async function archive() {
    if (archiveCol) return archiveCol;
    const { MongoClient } = await import('mongodb');
    const client = new MongoClient(process.env.LP_MONGO || 'mongodb://127.0.0.1:27017');
    await client.connect();
    archiveCol = client.db('librepoker').collection('hands');
    await archiveCol.createIndex({ key: 1, submitter: 1 }, { unique: true });
    await archiveCol.createIndex({ t: -1 });
    return archiveCol;
  }

  api.fastify.post(`${prefix}/archive`, async (request, reply) => {
    cors(reply);
    const b = request.body || {};
    const doc = b.doc;
    const key = doc && (doc.root || doc.seed);
    if (!key || typeof key !== 'string' || JSON.stringify(doc).length > 32768) {
      return reply.code(400).send({ error: 'bad-doc' });
    }
    const submitter = String(b.submitter || 'anon').slice(0, 64);
    try {
      const col = await archive();
      await col.updateOne(
        { key, submitter },
        { $setOnInsert: { key, submitter, t: Date.now(), doc, attest: b.attest ?? null } },
        { upsert: true },
      );
      return { ok: true };
    } catch (e) {
      return reply.code(503).send({ error: 'archive-unavailable' });
    }
  });

  api.fastify.get(`${prefix}/archive`, async (request, reply) => {
    cors(reply);
    try {
      const col = await archive();
      const q = {};
      if (request.query?.submitter) q.submitter = String(request.query.submitter);
      const limit = Math.min(200, Math.max(1, Number(request.query?.limit || 50)));
      const rows = await col.find(q).sort({ t: -1 }).limit(limit).toArray();
      return { hands: rows.map(({ _id, ...r }) => r) };
    } catch (e) {
      return reply.code(503).send({ error: 'archive-unavailable' });
    }
  });

  api.fastify.get(`${prefix}/health`, async (request, reply) => {
    cors(reply);
    return C.health();
  });

  // SSE: hijack the reply and speak raw http on the socket
  api.fastify.get(`${prefix}/events`, async (request, reply) => {
    const sid = request.query?.sid;
    const party = await partyOf(request, sid);
    const raw = reply.raw;
    if (!party) {
      reply.hijack();
      raw.writeHead(403, { 'content-type': 'application/json', ...CORS });
      return raw.end(JSON.stringify({ error: 'not-a-party' }));
    }
    const write = (ev) => {
      if (ev === null) return raw.end();
      raw.write(`data: ${JSON.stringify(ev)}\n\n`);
    };
    const at = C.attach(sid, party, write);
    reply.hijack();
    if (at.error) {
      raw.writeHead(404, { 'content-type': 'application/json', ...CORS });
      return raw.end(JSON.stringify(at));
    }
    raw.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
      ...CORS,
    });
    raw.write(': croupier\n\n');
    for (const ev of at.replay) raw.write(`data: ${JSON.stringify(ev)}\n\n`);
    const ping = setInterval(() => { try { raw.write(': ping\n\n'); } catch { /* gone */ } }, 25000);
    request.raw.on('close', () => { clearInterval(ping); at.unsubscribe(); });
  });

  api.log.info?.(`croupier: dealing at ${prefix} (lp-croupier-v0${allowTokens ? ', invite tokens on' : ''})`);
  return { deactivate() { C.stop(); } };
}
