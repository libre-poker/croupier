// core.js — the croupier's brain, binding-agnostic. server.js (standalone
// http) and plugin.js (JSS) are thin IO wrappers around this. All state in
// memory; all rules of SPEC.md §3–§5 live here and only here.
import { randomBytes } from 'node:crypto';
import { permFromSeed, saltFor, leafFor, merkle, merklePath } from './verify.js';

const hex = (n) => randomBytes(n).toString('hex');

export function createCroupier({
  sessionTtlMs = 24 * 3600 * 1000,
  consentTtlMs = 300 * 1000,
  maxN = 4096, maxParties = 32, maxSessions = 10000,
} = {}) {
  const sessions = new Map();

  function reap() {
    const now = Date.now();
    for (const [sid, S] of sessions) {
      if (now > S.expiresAt) {
        for (const set of S.channels.values()) for (const fn of set) fn(null);   // close signal
        sessions.delete(sid);
        continue;
      }
      for (const [k, p] of S.pending) if (now > p.expiresAt) S.pending.delete(k);
    }
  }
  const reaper = setInterval(reap, 30000);
  reaper.unref?.();

  function emit(S, ev, vis) {
    S.log.push({ ...ev, vis });
    for (const [pk, fnSet] of S.channels) {
      if (visibleTo(vis, pk)) for (const fn of fnSet) fn(ev);
    }
  }
  const visibleTo = (vis, pk) => vis === 'all' || vis === pk
    || (vis.startsWith('all-but:') && vis !== 'all-but:' + pk);

  const revealEventFor = (S, index, to) => ({
    sid: S.sid, ev: 'reveal', index,
    value: S.perm[index], salt: S.salts[index],
    path: merklePath(S.levels, index), to,
  });

  function executeOp(S, op) {
    if (op.kind === 'reveal') {
      const env = S.envelopes[op.index];
      if (op.to === 'all') {
        env.status = 'public'; env.value = S.perm[op.index]; delete env.to;
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
      if (env.status === 'private' && op.to !== 'all') return 'already-held';
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

  return {
    create({ n, parties, openPolicy, expiry, meta }) {
      if (sessions.size >= maxSessions) return { error: 'full' };
      n = n | 0;
      parties = Array.isArray(parties) ? parties.map(String) : [];
      if (n < 1 || n > maxN) return { error: 'bad-n' };
      if (parties.length < 2 || parties.length > maxParties || parties.length > n
        || new Set(parties).size !== parties.length) return { error: 'bad-parties' };
      openPolicy = ['none', 'unanimous', 'any'].includes(openPolicy) ? openPolicy : 'none';
      const seed = hex(32);
      const perm = permFromSeed(seed, n);
      const salts = Array.from({ length: n }, (_, i) => saltFor(seed, i));
      const { root, levels } = merkle(perm.map((v, i) => leafFor(salts[i], v)));
      const S = {
        sid: hex(16), createdAt: Date.now(),
        expiresAt: Date.now() + Math.min(expiry ? expiry * 1000 : sessionTtlMs, sessionTtlMs),
        n, parties, openPolicy, meta: meta ?? null,
        seed, perm, salts, levels, root,
        tokens: Object.fromEntries(parties.map((p) => [p, hex(16)])),
        envelopes: Array.from({ length: n }, () => ({ status: 'sealed' })),
        pending: new Map(), log: [], channels: new Map(), opened: false,
      };
      sessions.set(S.sid, S);
      return {
        sid: S.sid, root: S.root, algo: 'lp-croupier-v0', n: S.n,
        parties: S.parties, openPolicy: S.openPolicy, createdAt: S.createdAt,
        meta: S.meta, tokens: S.tokens,
      };
    },

    // party: an already-authenticated party id (binding's job to establish)
    consent(sid, party, op) {
      const S = sessions.get(sid);
      if (!S || Date.now() > S.expiresAt) return { error: 'unknown-sid' };
      if (!S.parties.includes(party)) return { error: 'not-a-party' };
      op = op || {};
      const err = opError(S, op);
      if (err) return { error: err };
      if (op.kind === 'open' && S.openPolicy === 'any') {
        executeOp(S, op);
        return { sid, op, pending: [] };
      }
      const key = opKey(op);
      let p = S.pending.get(key);
      if (!p || Date.now() > p.expiresAt) {
        p = { op, consents: new Set(), expiresAt: Date.now() + consentTtlMs };
        S.pending.set(key, p);
      }
      p.consents.add(party);
      const pending = S.parties.filter((x) => !p.consents.has(x));
      if (pending.length === 0) {
        S.pending.delete(key);
        const err2 = opError(S, op);
        if (err2) return { error: err2 };
        executeOp(S, op);
      }
      return { sid, op, pending };
    },

    state(sid) {
      const S = sessions.get(sid);
      if (!S || Date.now() > S.expiresAt) return { error: 'unknown-sid' };
      return {
        sid: S.sid, root: S.root, algo: 'lp-croupier-v0', n: S.n,
        parties: S.parties, openPolicy: S.openPolicy, opened: S.opened, meta: S.meta,
        envelopes: S.envelopes.map((e) =>
          e.status === 'sealed' ? 'sealed'
            : e.status === 'public' ? { to: 'public', value: e.value }
              : e.status === 'opened' ? 'opened' : { to: e.to }),
        pendingOps: [...S.pending.values()]
          .filter((p) => Date.now() <= p.expiresAt)
          .map((p) => ({ op: p.op, consented: [...p.consents] })),
      };
    },

    // binding resolves party auth; fn(ev) receives events, fn(null) = closed.
    // Returns {replay, unsubscribe} or {error}.
    attach(sid, party, fn) {
      const S = sessions.get(sid);
      if (!S || Date.now() > S.expiresAt) return { error: 'unknown-sid' };
      if (!S.parties.includes(party)) return { error: 'not-a-party' };
      const replay = S.log.filter((e) => visibleTo(e.vis, party))
        .map(({ vis, ...ev }) => ev);
      if (!S.channels.has(party)) S.channels.set(party, new Set());
      S.channels.get(party).add(fn);
      return { replay, unsubscribe: () => S.channels.get(party)?.delete(fn) };
    },

    // test binding only: bearer token -> party id
    partyFromToken(sid, token) {
      const S = sessions.get(sid);
      if (!S) return null;
      for (const [pk, t] of Object.entries(S.tokens)) if (t === token) return pk;
      return null;
    },

    health: () => ({ ok: true, sessions: sessions.size, algo: 'lp-croupier-v0' }),
    stop: () => clearInterval(reaper),
  };
}
