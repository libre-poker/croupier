// server.js — standalone http binding for the croupier core (SPEC §6 test
// binding: per-party bearer tokens issued at create). Zero dependencies.
//
//   node server.js [--port 8477]
//
// The croupier deals, proves, and forgets. It never plays.
import { createServer } from 'node:http';
import { createCroupier } from './core.js';

const PORT = Number(process.argv.includes('--port')
  ? process.argv[process.argv.indexOf('--port') + 1]
  : process.env.PORT || 8477);

const C = createCroupier();

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
const tokenOf = (req, url) =>
  (req.headers.authorization || '').replace(/^Bearer /, '') || url.searchParams.get('token');

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
    if (req.method === 'POST' && url.pathname === '/croupier/create') {
      const out = C.create(await readBody(req));
      return json(res, out.error ? 400 : 200, out);
    }
    if (req.method === 'POST' && url.pathname === '/croupier/consent') {
      const b = await readBody(req);
      const party = C.partyFromToken(b.sid, tokenOf(req, url));
      if (!party) return json(res, 403, { error: 'not-a-party' });
      const out = C.consent(b.sid, party, b.op);
      return json(res, out.error ? (out.error === 'unknown-sid' ? 404 : 400) : 200, out);
    }
    if (req.method === 'GET' && url.pathname === '/croupier/state') {
      const out = C.state(url.searchParams.get('sid'));
      return json(res, out.error ? 404 : 200, out);
    }
    if (req.method === 'GET' && url.pathname === '/croupier/events') {
      const sid = url.searchParams.get('sid');
      const party = C.partyFromToken(sid, tokenOf(req, url));
      if (!party) return json(res, 403, { error: 'not-a-party' });
      const write = (ev) => {
        if (ev === null) return res.end();
        res.write(`data: ${JSON.stringify(ev)}\n\n`);
      };
      const at = C.attach(sid, party, write);
      if (at.error) return json(res, 404, at);
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache',
        'access-control-allow-origin': '*',
        connection: 'keep-alive',
      });
      res.write(': croupier\n\n');
      for (const ev of at.replay) res.write(`data: ${JSON.stringify(ev)}\n\n`);
      const ping = setInterval(() => res.write(': ping\n\n'), 25000);
      req.on('close', () => { clearInterval(ping); at.unsubscribe(); });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/croupier/health') {
      return json(res, 200, C.health());
    }
    json(res, 404, { error: 'not-found' });
  } catch (e) {
    json(res, 400, { error: String(e.message || e) });
  }
});

server.listen(PORT, () => console.log(`croupier dealing on :${PORT} (lp-croupier-v0)`));
