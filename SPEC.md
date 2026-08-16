# The Croupier — a game-blind dealing service

*Version 0 (draft). The croupier seals a shuffled deck of envelopes, proves
it sealed them before anyone looked, opens them only by the players'
unanimous consent, and never learns what game is being played. It is the
one trusted component of casual online play under the Libre Poker
constitution — trusted for exactly two things, accountable for both, and
designed to be replaced by cryptography without changing its interface.*

## 1. What it is, and is not

A croupier session is `n` sealed envelopes containing a uniformly shuffled
permutation of `0..n-1`, created for a fixed set of parties. Parties ask
for envelopes to be revealed — privately to one of them, or publicly to
all — and a reveal happens only when **every** party has asked for the
identical reveal. That is the whole service.

The croupier does not know poker. It does not know that envelopes 0 and 1
are someone's hole cards, that 4 through 8 will become a board, or that a
game ended. All game semantics live in the clients, encoded in *what they
consent to reveal, to whom, in what order*. The same service deals hold'em,
hanabi, dominoes, or conclave ballots.

**The trust statement, plainly:** the croupier is trusted for
(a) **privacy** — it sees every value and must not leak them, and
(b) **uniformity** — it must shuffle fairly. It is *accountable* (not
trusted) for **consistency**: commitments make it impossible to change an
envelope after creation without detection, and any revealed duplicate is a
publishable fraud proof. Rated play must never rest on a croupier; this is
a casual-play component, and the constitution's §6 blocker stands until
mental poker replaces it. The interface below is deliberately implementable
by a future trustless (mental-poker) backend, so clients built today
survive the croupier's own abolition.

## 2. Cryptographic construction

All hashes are SHA-256. `||` is byte concatenation. Integers serialize as
decimal ASCII unless stated.

On `create(n, parties)`:

1. `seed` ← 32 random bytes (hex-encoded lowercase; never reused).
2. The permutation `P` of `0..n-1` is produced by the **pinned shuffle**:
   the Fisher–Yates implementation of the Libre Poker engine
   (`rngFromSeed(seedHex)` — the xorshift128 construction seeded from the
   first 32 hex chars — driving `shuffledDeck`-style descending swaps).
   The engine's `poker.js` is normative; a croupier MUST produce
   bit-identical permutations to it for a given seed and `n`.
3. Per-envelope salts: `salt_i = HMAC-SHA256(seed, "lp-croupier-salt" || i)`.
4. Per-envelope leaves: `leaf_i = SHA256(salt_i || P[i])` (value as decimal
   ASCII).
5. `root` = binary Merkle root over `leaf_0..leaf_{n-1}` (SHA-256 of
   `left || right`; odd nodes promote unpaired).

`root` is published to all parties at creation. Every reveal of envelope
`i` carries `(value, salt_i, merkle_path_i)` and is **self-verifying
against the root** — no end-of-session ceremony is required, and envelopes
never revealed stay sealed forever (a mucked hand stays mucked).

An optional `open` (policy-gated, below) reveals `seed` itself, letting
anyone re-derive the entire permutation and audit uniformity. Note the
trade openly: `open` proves the deck was a true permutation but exposes
every envelope, mucked cards included. Games choose their policy at
creation.

## 3. Sessions

```
create:
  → { n, parties: [pubkey…], openPolicy: "none"|"unanimous"|"any",
      expiry?: seconds, meta?: opaque }
  ← { sid, root, algo: "lp-croupier-v0", n, parties, openPolicy, createdAt }
```

- `parties` are nostr public keys (hex). 2 ≤ parties ≤ n. Any
  authenticated party-to-be may create; all parties learn `{sid, root,…}`
  on their channels.
- `sid` is unguessable (≥128 bits). Sessions expire (default 24h);
  expiry destroys the seed and all unrevealed values.
- `meta` is opaque to the croupier; clients may bind a game id, a room
  code, or a Hand document reference. It is echoed, never inspected.
- `openPolicy`: `none` — the seed is never revealed (maximum muck
  privacy); `unanimous` — `open` executes on unanimous consent;
  `any` — any single party may open (audit-first games).

## 4. Consent and reveals

Every mutation after creation is a **consent op**. A party submits an op;
the croupier records the submission; when the set of submitting parties
equals the full party list and the ops are byte-identical, the op
executes. Pending ops expire (default 300 s) to prevent deadlock.

```
consent:
  → { sid, op }
    op := { kind: "reveal", index, to: pubkey | "all" }
        | { kind: "open" }
  ← { sid, op, pending: [pubkey…] }        # who has not yet consented

executed reveal (delivered on channels):
  { sid, ev: "reveal", index, value, salt, path: [hex…],
    to: "all" | pubkey }
  # to = "all": delivered to every party, and thereafter public
  # to = pubkey: delivered ONLY on that party's channel; others receive
  #   { sid, ev: "reveal", index, to: pubkey }   — fact, not value

executed open:
  { sid, ev: "open", seed }
```

Rules:

- `index` must be in range and **still sealed**. Re-revealing a public
  envelope errors (`already-public`); revealing privately an envelope
  already privately held by another party errors (`already-held`) —
  a value moves only sealed → private(one party) → (optionally, by a
  fresh consented reveal-to-all) public. Sealed → public directly is
  allowed.
- Consent is per-exact-op: `reveal(3, to: A)` and `reveal(3, to: all)`
  are different ops. Clients automate consent from their game script —
  in hold'em both clients consent "0,1 → seat A; 2,3 → seat B" at the
  deal, "4,5,6 → all" at the flop, and a showdown is each player
  consenting to publicize their own two.
- The croupier never initiates. No consensus, no motion.

## 5. State and verification

```
state:
  → { sid }
  ← { sid, root, algo, n, parties, openPolicy,
      envelopes: [ "sealed" | {to: "public", value} | {to: pubkey} … ],
      pendingOps: [...] }
```

Client duties (normative):

1. Record `root` at creation; verify every reveal's `(value, salt, path)`
   against it. A failed proof is fraud; publish `{sid, root, reveal}`.
2. Track revealed values; **two identical values are fraud** — publish
   both proofs. (The Merkle construction makes the croupier unable to
   deny having committed to both.)
3. On `open`: re-derive the permutation from the seed via the pinned
   shuffle; verify it reproduces the root and every prior reveal.
4. Treat `state` as advisory; proofs and events are the record.

## 6. Transport binding (reference)

The reference implementation is a JSS plugin at prefix `/croupier`
(the neonglobs pattern):

- `POST /croupier/session` — xlogin (nostr / Solid OIDC) credential →
  24 h HMAC session, exactly as the globs plugin does it.
- `WS /croupier/ws` — `hello {session}` then the messages of §3–§5,
  JSON, one per frame; each party's WS connection is their private
  channel. Reconnection replays undelivered events for live sessions.

The message layer, not the binding, is normative: an implementation may
serve HTTP-polling, or a nostr-relay binding where consent ops are
ephemeral events and private reveals are NIP-44-encrypted DMs — the
croupier holding a nostr key of its own. (That binding is attractive:
rooms and transport then need no server of ours at all.)

## 7. Errors

`unknown-sid` · `not-a-party` · `bad-index` · `already-public` ·
`already-held` · `policy-forbids-open` · `consent-expired` ·
`session-expired` · `bad-op`.

## 8. The poker mapping (non-normative appendix)

Heads-up hold'em, engine card order (`value = suit*13 + rank` per
`poker.js`): `n = 52`; envelopes `0,1 → seat 0 private`, `2,3 → seat 1
private`, `4..6` flop, `7` turn, `8` river, all-to-all; showdown =
each player consenting `reveal(own, to: all)`; muck = simply never
consenting; `openPolicy: "none"`. Betting, legality, and settlement run
entirely in the two clients' engines; actions travel peer-to-peer as
signed Hand-document entries over the room channel, and the finished
hand co-signs into a transcript whose `seed` field is replaced by
`{croupier: sid, root}` — a Hand dealt by commitment rather than by a
revealed seed, which the schema will learn as `variant` metadata when
the implementation lands (extracted, not invented).

## 9. Lineage

The commit-reveal discipline is the fleet's (tideholm's trails, the
Wardroom's committed shuffles); the session/auth pattern is neonglobs'
globs plugin; the unanimous-consent reveal rule is what makes one
service game-blind — the game is whatever the players agree to unveil.

*The croupier deals, proves, and forgets. It never plays.*
