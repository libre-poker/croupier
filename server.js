// server.js — the croupier, reference implementation of SPEC.md v0.
// Zero dependencies: node http + SSE channels. One process, in-memory
// sessions. The test binding issues per-party bearer tokens at create
// (the creator distributes them — fine for friends and tests; a
// production binding exchanges xlogin credentials instead, per SPEC §6).
//
//   node server.js [--port 8477]
//
// The croupier deals, proves, and forgets. It never plays.
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import {
  permFromSeed, saltFor, leafFor, merkle, merklePath,
} from './verify.js';

const PORT = Number(process.argv.includes('--port')
  ? process.argv[process.argv.indexOf('--port') + 1]
  : process.env.PORT || 8477);

const SESSION_TTL = 24 * 3600 * 1000;
const CONSENT_TTL = 300 * 1000;
const MAX_N = 4096, MAX_PARTIES = 32, MAX_SESSIONS = 10000;

const sessions = new Map();     // sid -> S
const hex = (n) => randomBytes(n).toString('hex');

function makeSession({ n, parties, openPolicy, expiry, meta }) {
  const seed = hex(32);
  const perm = permFromSeed(seed, n);
  const salts = Array.from({ length: n }, (_, i) => saltFor(seed, i));
  const leaves = perm.map((v, i) => leafFor(salts[i], v));
  const { root, levels } = merkle(leaves);
  const S = {
    sid: hex(16), createdAt: Date.now(),
    expiresAt: Date.now() + Math.min(expiry ? expiry * 1000 : SESSION_TTL, SESSION_TTL),
    n, parties, openPolicy, meta: meta ?? null,
    seed, perm, salts, levels, root,
    tokens: Object.fromEntries(parties.map((p) => [p, hex(16)])),
    envelopes: Array.from({ length: n }, () => ({ status: 'sealed' })),
    pending: new Map(),          // opKey -> {op, consents:Set, expiresAt}
    log: [],                     // {ev, ..., vis: 'all'|pubkey}
    channels: new Map(),         // pubkey -> Set(res)
    opened: false,
  };
  sessions.set(S.sid, S);
  return S;
}

// ---- events
function emit(S, ev, vis) {
  const entry = { ...ev, vis };
  S.log.push(entry);
  const payload = JSON.stringify(ev);
  for (const [pk, resSet] of S.channels) {
    const visible = vis === 'all' || vis === pk
      || (vis.startsWith('all-but:') && vis !== 'all-but:' + pk);
    if (visible) for (const res of resSet) res.write(`data: ${payload}\n\n`);
  }
}
function revealEventFor(S, index, to) {
  return {
    sid: S.sid, ev: 'reveal', index,
    value: S.perm[index], salt: S.salts[index],
    path: merklePath(S.levels, index), to,
  };
}

// ---- ops
function executeOp(S, op) {
  if (op.kind === 'reveal') {
    const env = S.envelopes[op.index];
    if (op.to === 'all') {
      env.status = 'public'; env.value = S.perm[op.index];
      emit(S, revealEventFor(S, op.index, 'all'), 'all');
    } else {
      env.status = 'private'; env.to = op.to;
      emit(S, revealEventFor(S, op.index, op.to), op.to);
      emit(S, { sid: S.sid, ev: 'reveal', index: op.index, to: op.to }, 'all-but:' + op.to);
    }
  } else if (op.kind === 'open') {
    S.opened = true;
    for (const env of S.envelopes) if (env.status === 'sealed') env.status = 'opened';
    emit(S, { sid: S.sid, ev: 'open', seed: S.seed }, 'all');
  }
}
function opError(S, op) {
  if (op.kind === 'reveal') {
    if (!Number.isInteger(op.index) || op.index < 0 || op.index >= S.n) return 'bad-index';
    const env = S.envelopes[op.index];
    if (env.status === 'public' || env.status === 'opened') return 'already-public';
    if (env.status === 'private') {
      if (op.to !== 'all') return 'already-held';
      // private -> public allowed via fresh unanimous reveal-to-all
    }
    if (op.to !== 'all' && !S.parties.includes(op.to)) return 'not-a-party';
    return null;
  }
  if (op.kind === 'open') {
    if (S.openPolicy === 'none') return 'policy-forbids-open';
    if (S.opened) return 'already-public';
    return null;
  }
  return 'bad-op';
}
const opKey = (op) => op.kind === 'reveal' ? `r|${op.index}|${op.to}` : 'open';

// ---- http plumbing
const json = (res, code, obj) => {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
};
const readBody = (req) => new Promise((resolve, reject) => {
  let buf = '';
  req.on('data', (c) => { buf += c; if (buf.length > 65536) reject(new Error('too-big')); });
  req.on('end', () => { try { resolve(buf ? JSON.parse(buf) : {}); } catch { reject(new Error('bad-json')); } });
});
function auth(S, req, url) {
  const tok = (req.headers.authorization || '').replace(/^Bearer /, '') || url.searchParams.get('token');
  for (const [pk, t] of Object.entries(S.tokens)) if (t === tok) return pk;
  return null;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'authorization, content-type',
      'access-control-allow-methods': 'GET, POST, OPTIONS',
    });
    return res.end();
  }
  try {
    // ---------------------------------------------------------- create
    if (req.method === 'POST' && url.pathname === '/croupier/create') {
      if (sessions.size >= MAX_SESSIONS) return json(res, 503, { error: 'full' });
      const b = await readBody(req);
      const n = b.n | 0;
      const parties = Array.isArray(b.parties) ? b.parties.map(String) : [];
      if (n < 1 || n > MAX_N) return json(res, 400, { error: 'bad-n' });
      if (parties.length < 2 || parties.length > MAX_PARTIES || parties.length > n
        || new Set(parties).size !== parties.length) return json(res, 400, { error: 'bad-parties' });
      const openPolicy = ['none', 'unanimous', 'any'].includes(b.openPolicy) ? b.openPolicy : 'none';
      const S = makeSession({ n, parties, openPolicy, expiry: b.expiry, meta: b.meta });
      return json(res, 200, {
        sid: S.sid, root: S.root, algo: 'lp-croupier-v0', n: S.n,
        parties: S.parties, openPolicy: S.openPolicy, createdAt: S.createdAt,
        meta: S.meta, tokens: S.tokens,          // test binding: creator distributes
      });
    }
    // ---------------------------------------------------------- consent
    if (req.method === 'POST' && url.pathname === '/croupier/consent') {
      const b = await readBody(req);
      const S = sessions.get(b.sid);
      if (!S || Date.now() > S.expiresAt) return json(res, 404, { error: 'unknown-sid' });
      const pk = auth(S, req, url);
      if (!pk) return json(res, 403, { error: 'not-a-party' });
      const op = b.op || {};
      if (op.kind === 'open' && S.openPolicy === 'any') {
        const err = opError(S, op);
        if (err) return json(res, 400, { error: err });
        executeOp(S, op);
        return json(res, 200, { sid: S.sid, op, pending: [] });
      }
      const err = opError(S, op);
      if (err) return json(res, 400, { error: err });
      const key = opKey(op);
      let p = S.pending.get(key);
      if (!p || Date.now() > p.expiresAt) {
        p = { op, consents: new Set(), expiresAt: Date.now() + CONSENT_TTL };
        S.pending.set(key, p);
      }
      p.consents.add(pk);
      const pendingParties = S.parties.filter((x) => !p.consents.has(x));
      if (pendingParties.length === 0) {
        S.pending.delete(key);
        const err2 = opError(S, op);            // state may have moved
        if (err2) return json(res, 409, { error: err2 });
        executeOp(S, op);
      }
      return json(res, 200, { sid: S.sid, op, pending: pendingParties });
    }
    // ---------------------------------------------------------- state
    if (req.method === 'GET' && url.pathname === '/croupier/state') {
      const S = sessions.get(url.searchParams.get('sid'));
      if (!S || Date.now() > S.expiresAt) return json(res, 404, { error: 'unknown-sid' });
      return json(res, 200, {
        sid: S.sid, root: S.root, algo: 'lp-croupier-v0', n: S.n,
        parties: S.parties, openPolicy: S.openPolicy, opened: S.opened, meta: S.meta,
        envelopes: S.envelopes.map((e) =>
          e.status === 'sealed' ? 'sealed'
            : e.status === 'public' ? { to: 'public', value: e.value }
              : e.status === 'opened' ? 'opened' : { to: e.to }),
        pendingOps: [...S.pending.values()]
          .filter((p) => Date.now() <= p.expiresAt)
          .map((p) => ({ op: p.op, consented: [...p.consents] })),
      });
    }
    // ---------------------------------------------------------- events (SSE)
    if (req.method === 'GET' && url.pathname === '/croupier/events') {
      const S = sessions.get(url.searchParams.get('sid'));
      if (!S || Date.now() > S.expiresAt) return json(res, 404, { error: 'unknown-sid' });
      const pk = auth(S, req, url);
      if (!pk) return json(res, 403, { error: 'not-a-party' });
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache',
        'access-control-allow-origin': '*',
        connection: 'keep-alive',
      });
      res.write(': croupier\n\n');
      // replay everything this party may see
      for (const e of S.log) {
        const { vis, ...ev } = e;
        const visible = vis === 'all' || vis === pk
          || (typeof vis === 'string' && vis.startsWith('all-but:') && vis !== 'all-but:' + pk);
        if (visible) res.write(`data: ${JSON.stringify(ev)}\n\n`);
      }
      if (!S.channels.has(pk)) S.channels.set(pk, new Set());
      S.channels.get(pk).add(res);
      const ping = setInterval(() => res.write(': ping\n\n'), 25000);
      req.on('close', () => { clearInterval(ping); S.channels.get(pk)?.delete(res); });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/croupier/health') {
      return json(res, 200, { ok: true, sessions: sessions.size, algo: 'lp-croupier-v0' });
    }
    json(res, 404, { error: 'not-found' });
  } catch (e) {
    json(res, 400, { error: String(e.message || e) });
  }
});

setInterval(() => {
  const now = Date.now();
  for (const [sid, S] of sessions) {
    if (now > S.expiresAt) {
      for (const set of S.channels.values()) for (const res of set) res.end();
      sessions.delete(sid);
    }
    for (const [k, p] of S.pending) if (now > p.expiresAt) S.pending.delete(k);
  }
}, 30000).unref();

server.listen(PORT, () => console.log(`croupier dealing on :${PORT} (lp-croupier-v0)`));
