// verify.js — the croupier's mathematics, shared by server, tests, and any
// client. Zero dependencies; runs in node and the browser (pass a webcrypto
// subtle-less path: everything here is synchronous over Uint8Array via a
// tiny SHA-256 when crypto.createHash is absent? No — node/browsers both
// expose what we need; node gets createHash/createHmac, browsers can import
// this in a worker with crypto.subtle wrappers later. This file is the
// normative reference for lp-croupier-v0 alongside SPEC.md).
import { createHash, createHmac } from 'node:crypto';

export const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex');

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
  createHmac('sha256', Buffer.from(seedHex, 'hex')).update('lp-croupier-salt' + i).digest('hex');
export const leafFor = (saltHex, value) =>
  sha256hex(Buffer.concat([Buffer.from(saltHex, 'hex'), Buffer.from(String(value))]));

// binary Merkle tree, sha256(left||right) over hex leaves; odd node promotes
export function merkle(leaves) {
  let level = leaves.slice();
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length
        ? sha256hex(Buffer.from(level[i] + level[i + 1], 'hex'))
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
      ? sha256hex(Buffer.from(h + step.h, 'hex'))
      : sha256hex(Buffer.from(step.h + h, 'hex'));
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
