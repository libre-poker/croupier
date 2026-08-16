# Libre Poker · croupier

**A game-blind dealing service.** The croupier seals a shuffled deck of
envelopes behind a Merkle commitment, reveals them only by the players'
unanimous consent — privately or publicly — and never learns what game
is being played. Every reveal is self-verifying; every duplicate is a
publishable fraud proof; unmucked secrets stay sealed forever.

**[Read the spec →](SPEC.md)**

It is the one trusted component of casual online play under the
[constitution](https://librepoker.org/constitution.html), trusted for
privacy and uniformity, accountable for consistency — and its interface
is designed so a future mental-poker backend can replace it without
clients noticing.

Status: **spec v0**. Implementation (a JSS plugin, the neonglobs
pattern) follows in this repo.

License: AGPL-3.0 (the spec text itself may be reused freely).
