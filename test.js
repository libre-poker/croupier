// test.js — the croupier dealt a full heads-up hand to two suspicious
// clients over real HTTP, and both verified every proof. run: node test.js
import { spawn } from 'node:child_process';
import { verifyReveal, verifyOpen } from './verify.js';

const PORT = 8990 + (Date.now() % 100);
const BASE = `http://127.0.0.1:${PORT}/croupier`;
let fails = 0;
const ok = (c, m) => { if (c) console.log('  ok ', m); else { fails++; console.error('  FAIL', m); } };
const post = (path, body, token) => fetch(BASE + path, {
  method: 'POST',
  headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) },
  body: JSON.stringify(body),
}).then((r) => r.json());

// a tiny SSE client: collects events, resolves waiters
function listen(sid, token) {
  const events = [];
  const waiters = [];
  const push = (ev) => {
    events.push(ev);
    for (let i = waiters.length - 1; i >= 0; i--) {
      if (waiters[i].pred(ev)) { waiters[i].resolve(ev); waiters.splice(i, 1); }
    }
  };
  fetch(`${BASE}/events?sid=${sid}&token=${token}`).then(async (res) => {
    const reader = res.body.getReader();
    let buf = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += new TextDecoder().decode(value);
      let idx;
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        const chunk = buf.slice(0, idx); buf = buf.slice(idx + 2);
        const m = chunk.match(/^data: (.*)$/m);
        if (m) push(JSON.parse(m[1]));
      }
    }
  }).catch(() => { /* server going down at test end */ });
  return {
    events,
    next: (pred, ms = 3000) => new Promise((resolve, reject) => {
      const found = events.find(pred);
      if (found) return resolve(found);
      const w = { pred, resolve };
      waiters.push(w);
      setTimeout(() => reject(new Error('event timeout')), ms);
    }),
  };
}

const srv = spawn(process.execPath, ['server.js', '--port', String(PORT)], { stdio: 'inherit' });
await new Promise((r) => setTimeout(r, 600));

try {
  const A = 'a'.repeat(64), B = 'b'.repeat(64);

  // ---- create: 52 envelopes for two players, muck stays sealed forever
  const S = await post('/create', { n: 52, parties: [A, B], openPolicy: 'none', meta: { game: 'holdem-hu' } });
  ok(!!S.sid && /^[0-9a-f]{64}$/.test(S.root), `session created, root ${S.root.slice(0, 8)}…`);
  const tA = S.tokens[A], tB = S.tokens[B];
  const chA = listen(S.sid, tA), chB = listen(S.sid, tB);

  // ---- one-sided consent does nothing
  let r = await post('/consent', { sid: S.sid, op: { kind: 'reveal', index: 0, to: A } }, tA);
  ok(r.pending.length === 1 && r.pending[0] === B, 'half a consent stays pending');

  // ---- the deal: both consent, A's holes arrive privately, B sees facts only
  const deal = [[0, A], [1, A], [2, B], [3, B]];
  for (const [idx, to] of deal) {
    await post('/consent', { sid: S.sid, op: { kind: 'reveal', index: idx, to } }, tA);
    await post('/consent', { sid: S.sid, op: { kind: 'reveal', index: idx, to } }, tB);
  }
  const a0 = await chA.next((e) => e.ev === 'reveal' && e.index === 0 && e.value !== undefined);
  const a1 = await chA.next((e) => e.ev === 'reveal' && e.index === 1 && e.value !== undefined);
  ok(verifyReveal(S.root, a0) && verifyReveal(S.root, a1), `A's holes verify against the root (${a0.value}, ${a1.value})`);
  const bFact = await chB.next((e) => e.ev === 'reveal' && e.index === 0);
  ok(bFact.value === undefined, "B sees the fact of A's card, never the value");
  const b2 = await chB.next((e) => e.ev === 'reveal' && e.index === 2 && e.value !== undefined);
  ok(verifyReveal(S.root, b2), 'B\'s hole verifies too');

  // ---- flop to all
  for (const idx of [4, 5, 6]) {
    await post('/consent', { sid: S.sid, op: { kind: 'reveal', index: idx, to: 'all' } }, tA);
    await post('/consent', { sid: S.sid, op: { kind: 'reveal', index: idx, to: 'all' } }, tB);
  }
  const flopA = await Promise.all([4, 5, 6].map((i) => chA.next((e) => e.ev === 'reveal' && e.index === i && e.value !== undefined)));
  const flopB = await Promise.all([4, 5, 6].map((i) => chB.next((e) => e.ev === 'reveal' && e.index === i && e.value !== undefined)));
  ok(flopA.every((e) => verifyReveal(S.root, e)), 'flop public to A, proofs good');
  ok(flopB.every((e) => verifyReveal(S.root, e)) && flopB.map((e) => e.value).join() === flopA.map((e) => e.value).join(),
    'flop identical for B');

  // ---- showdown: A publicizes an already-private card (sealed→private→public)
  await post('/consent', { sid: S.sid, op: { kind: 'reveal', index: 0, to: 'all' } }, tA);
  await post('/consent', { sid: S.sid, op: { kind: 'reveal', index: 0, to: 'all' } }, tB);
  const shown = await chB.next((e) => e.ev === 'reveal' && e.index === 0 && e.value !== undefined);
  ok(verifyReveal(S.root, shown) && shown.value === a0.value, 'showdown: private card publicized, same value, proof holds');

  // ---- errors: steal attempt, double-public, forbidden open
  r = await post('/consent', { sid: S.sid, op: { kind: 'reveal', index: 2, to: A } }, tA);
  ok(r.error === 'already-held', "cannot re-route B's private card to A");
  r = await post('/consent', { sid: S.sid, op: { kind: 'reveal', index: 4, to: 'all' } }, tA);
  ok(r.error === 'already-public', 'cannot re-reveal a public card');
  r = await post('/consent', { sid: S.sid, op: { kind: 'open' } }, tA);
  ok(r.error === 'policy-forbids-open', 'openPolicy none holds: the muck stays mucked');
  r = await post('/consent', { sid: S.sid, op: { kind: 'reveal', index: 9, to: 'all' } }, 'wrong-token');
  ok(r.error === 'not-a-party', 'strangers are not dealt in');

  // ---- no duplicates among everything revealed
  const seen = [a0, a1, b2, ...flopB].map((e) => e.value);
  ok(new Set(seen).size === seen.length, 'no duplicate values among reveals');

  // ---- state view keeps secrets
  const st = await (await fetch(`${BASE}/state?sid=${S.sid}`)).json();
  ok(st.envelopes[1].to === A && st.envelopes[1].value === undefined, 'state shows who holds, never what');
  ok(st.envelopes[10] === 'sealed', 'unsold envelopes sealed');

  // ---- audit mode: a second session with openPolicy any, full verification
  const S2 = await post('/create', { n: 8, parties: [A, B], openPolicy: 'any' });
  const ch2 = listen(S2.sid, S2.tokens[A]);
  await post('/consent', { sid: S2.sid, op: { kind: 'open' } }, S2.tokens[B]);
  const opened = await ch2.next((e) => e.ev === 'open');
  const perm = verifyOpen(S2.root, opened.seed, 8);
  ok(Array.isArray(perm) && new Set(perm).size === 8, 'open: seed reproduces root; permutation is complete');
  // ---- claims mode: nobody gets tokens up front; redeems are one-time
  const S3 = await post('/create', { n: 8, parties: [A, B], claims: true });
  ok(S3.tokens === undefined && S3.claims && S3.claims[A] && S3.claims[B], 'claims mode: no tokens in create response');
  const cA = await post('/claim', { sid: S3.sid, party: A, code: S3.claims[A] });
  ok(!!cA.token, 'A redeems own claim for a token');
  const cAgain = await post('/claim', { sid: S3.sid, party: A, code: S3.claims[A] });
  ok(cAgain.error === 'already-claimed', 'claims are one-time');
  const cBad = await post('/claim', { sid: S3.sid, party: B, code: 'nope' });
  ok(cBad.error === 'bad-claim', 'wrong code refused');
  r = await post('/consent', { sid: S3.sid, op: { kind: 'reveal', index: 0, to: 'all' } }, cA.token);
  ok(Array.isArray(r.pending) && r.pending[0] === B, 'claimed token works for consent');
} finally {
  srv.kill();
}
if (fails) { console.error(`\n${fails} FAILURE(S)`); process.exit(1); }
console.log('\nthe croupier deals, proves, and forgets — verified');
process.exit(0);
