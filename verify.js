// verify.js — the croupier's mathematics, shared by server, tests, and any
// client. Pure JavaScript, zero dependencies, no node:crypto, no Buffer:
// the same file runs in node and in every player's browser, because the
// distrust has to travel. Normative reference for lp-croupier-v0 alongside
// SPEC.md; test.js proves the primitives bit-identical to node's crypto.

// ---------------------------------------------------------------- bytes
export const hexToBytes = (h) => {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
};
export const bytesToHex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
export const asciiBytes = (s) => {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
};
export const concatBytes = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((a, x) => a + x.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};

// ---------------------------------------------------------------- sha256
// compact synchronous SHA-256 over Uint8Array (FIPS 180-4)
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
export function sha256bytes(msg) {
  const len = msg.length;
  const bitLen = len * 8;
  const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(msg);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
      const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i]);
  return out;
}
export const sha256hex = (bytes) => bytesToHex(sha256bytes(bytes));

// HMAC-SHA256 (RFC 2104)
export function hmacSha256(keyBytes, msgBytes) {
  let k = keyBytes.length > 64 ? sha256bytes(keyBytes) : keyBytes;
  const ipad = new Uint8Array(64).fill(0x36);
  const opad = new Uint8Array(64).fill(0x5c);
  for (let i = 0; i < k.length; i++) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
  return sha256bytes(concatBytes(opad, sha256bytes(concatBytes(ipad, msgBytes))));
}

// ---- the pinned shuffle: vendored bit-for-bit from libre-poker/engine
// poker.js (rngFromSeed + Fisher–Yates as shuffledDeck applies it).
export function rngFromSeed(seedHex) {
  if (!/^[0-9a-f]{64}$/.test(seedHex)) throw new Error('seed must be 64 hex chars');
  let a = parseInt(seedHex.slice(0, 8), 16) >>> 0;
  let b = parseInt(seedHex.slice(8, 16), 16) >>> 0;
  let c = parseInt(seedHex.slice(16, 24), 16) >>> 0;
  let d = parseInt(seedHex.slice(24, 32), 16) >>> 0;
  if (!(a | b | c | d)) a = 0x9e3779b9;
  return function () {
    const t = a ^ (a << 11);
    a = b; b = c; c = d;
    d = (d ^ (d >>> 19)) ^ (t ^ (t >>> 8));
    return (d >>> 0) / 4294967296;
  };
}
export function permFromSeed(seedHex, n) {
  const rng = rngFromSeed(seedHex);
  const p = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = (rng() * (i + 1)) | 0;
    [p[i], p[j]] = [p[j], p[i]];
  }
  return p;
}

// ---- commitments
export const saltFor = (seedHex, i) =>
  bytesToHex(hmacSha256(hexToBytes(seedHex), asciiBytes('lp-croupier-salt' + i)));
export const leafFor = (saltHex, value) =>
  sha256hex(concatBytes(hexToBytes(saltHex), asciiBytes(String(value))));

// binary Merkle tree, sha256(left||right) over hex leaves; odd node promotes
export function merkle(leaves) {
  let level = leaves.slice();
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length
        ? sha256hex(hexToBytes(level[i] + level[i + 1]))
        : level[i]);
    }
    level = next;
    levels.push(level);
  }
  return { root: level[0], levels };
}
export function merklePath(levels, index) {
  const path = [];
  let i = index;
  for (let d = 0; d < levels.length - 1; d++) {
    const level = levels[d];
    const sib = i ^ 1;
    if (sib < level.length) path.push({ h: level[sib], right: sib > i });
    i = Math.floor(i / 2);
  }
  return path;
}
export function verifyPath(root, leaf, path) {
  let h = leaf;
  for (const step of path) {
    h = step.right
      ? sha256hex(hexToBytes(h + step.h))
      : sha256hex(hexToBytes(step.h + h));
  }
  return h === root;
}

// ---- client duties (SPEC §5)
export function verifyReveal(root, { index, value, salt, path }) {
  return verifyPath(root, leafFor(salt, value), path);
}
export function verifyOpen(root, seedHex, n) {
  const perm = permFromSeed(seedHex, n);
  const leaves = perm.map((v, i) => leafFor(saltFor(seedHex, i), v));
  return merkle(leaves).root === root ? perm : null;
}
