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
