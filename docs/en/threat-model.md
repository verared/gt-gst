# Threat model — Gerarion Time `v3.4.0` (GUS v3.0.0)

This document defines **what the system protects, against whom, and what it
does NOT protect**. Without an explicit threat model, any claim of
"unforgeable" is marketing. Spanish mirror:
[`../spec/threat-model.md`](../spec/threat-model.md) (EN > ES). Disclosure
policy: [`SECURITY.md`](../../SECURITY.md).

## 1. Assets

| Asset | Definition |
|---|---|
| Temporal value (instant) | Continuous count `ins` + canonical timestamp `ts` |
| Historical order | The total ordering of instants and its anchoring sequence |
| Attribution | Verifiable attribution of which authorized key asserted an instant |

## 2. Adversaries and assumed capabilities

| Adversary | Capabilities |
|---|---|
| A-Local | Controls its own clock, logs and system; can deny facts |
| A-Impersonator | Generates its own valid hybrid keys and claims another `issuer` / `kid` |
| A-Replayer | Captures valid envelopes and resubmits them, concurrently or later |
| A-Insider | Holds a signing or notarial key from a past epoch |
| A-Root | Has `root` on the signing host (no `TPM` / `HSM` in place) |
| A-Persistent | Compromises a complete notary (keys, state, disk) |
| A-Jurisdictional | Watches, censors and legally coerces a notary within its domain |
| A-Quantum | Quantum computer with millions of logical qubits (2035+ horizon) |
| A-Social | Disinformation campaign about what time it "was" |

## 3. Normative profile and verification levels

`GST v2` signs `b"GUS3-GST-V2\x00" + JCS(payload)` (RFC 8785, integers within
`±(2^53 - 1)`) with **Ed25519 + ML-DSA**; the algorithm/key descriptor is
inside the signed payload. Verification (`gerarion.gst.v2.verify`) returns a
`VerificationResult` with three independent levels:

1. **`crypto`** — mathematical validity, JCS, `event_hash`, anti-downgrade,
   dual signatures.
2. **`identity`** — `KeyRegistry` authorization of `(issuer, kid)` and
   transactional anti-replay (`ReplayStore`).
3. **`temporal`** — clock provenance/quality from `gt-gts`; `UNKNOWN` when no
   authenticated reading is supplied.

`sealed` covers levels 1 and 2. `overall_trusted` additionally requires bound
temporal evidence accepted by the host and a `VERIFIED` clock reading.

## 4. Guarantees and their premises

### G1 — Any alteration of a signed envelope is detected

Alter one bit of the signed payload and verification fails (deterministic
tamper detection, not physical impossibility). **Premise:** SHA-256 is
collision- and preimage-resistant; Ed25519 and ML-DSA are unbroken.

### G2 — A valid signature from an unauthorized key is rejected

A self-signed envelope claiming another `issuer` / `kid` passes level 1 but
fails level 2 (`KEY_MISMATCH` / `UNKNOWN_KEY`). Keys are compared in constant
time (`hmac.compare_digest`) against the `KeyRegistry`, which also enforces
validity windows (`KEY_EXPIRED`), revocation (`KEY_REVOKED`) and keeps rotated
keys auditable (`HISTORICAL_VALID`). A rejected key never mutates the replay
state of the legitimate issuer. **Premise:** the integrator distributes the
`KeyRegistry` through a trusted channel.

### G3 — Replay and rollback are rejected atomically

`SQLiteReplayStore` (`PRAGMA journal_mode=WAL`, `synchronous=FULL`,
`busy_timeout=5000`, `BEGIN IMMEDIATE`) checks and records
`(issuer, kid, nonce)` uniqueness and strictly increasing `seq` in one
transaction, removing the TOCTOU window under multi-thread / multi-worker
load (tested with 16 concurrent threads: exactly one accepted). Corrupted or
foreign state puts the store in fail-closed mode instead of resetting `seq`.
**Premise:** the database is not rolled back from an old backup; if it must be
restored, rotate to a fresh `kid`.

### G4 — The notary's past is immutable without detection

The `day_root` of day n includes the `day_root` of n-1. Altering a day
requires recomputing the entire subsequent chain **and** publishing it
consistently on every replica a verifier consults. **Premise:** at least one
independent replica remains honest and accessible.

### G5 — Clock rollback is detected

`gt-gts` evaluates readings with the full `(instant, nanos)` tuple against a
persisted anchor: a sub-second regression is `REJECTED`, and `VERIFIED`
requires an explicitly authenticated source (`require_authenticated`).
**Premise:** the anchor store is not rolled back by the attacker.

### G6 — Quantum compatibility and agility

The signature layer combines a classical and a post-quantum (lattice)
algorithm; the hash layer faces only Grover's quadratic speedup (2^128
margin). `alg` is a first-class field, so a future break is handled by signing
with a new algorithm and re-anchoring old evidence, never by rewriting the
past. **Premise:** the hybrid scheme is all-or-nothing; a classical-only or
PQ-only signature is rejected.

## 5. Concrete attacks and mitigations

| Attack | Outcome |
|---|---|
| Forge an individual envelope | Requires breaking Ed25519 **and** ML-DSA (G1) |
| Self-signed envelope impersonating an issuer | Level 2 `KEY_MISMATCH` / `UNKNOWN_KEY`; `overall_trusted = False` (G2) |
| Downgrade by stripping one signature branch | Descriptor is inside signed bytes; envelope invalid (G1) |
| Replay of a valid envelope (sequential or concurrent) | `REPLAY` / `SEQ_ROLLBACK` from the atomic `ReplayStore` (G3) |
| Verification without a replay store | Level 2 invalid unless `allow_unchecked_replay=True`; reported as `SKIPPED` |
| Use of an expired or revoked key | `KEY_EXPIRED` / `KEY_REVOKED`; earlier events remain `HISTORICAL` |
| Corrupted / truncated replay database | Fail-closed: everything rejected, `seq` never silently reset |
| Local clock stepped backwards | Sub-second rollback anchor → `REJECTED` (G5) |
| Retro-edit the notary log | Requires breaking G4 (all replicas) |
| Notarial key compromise | Published `day_root` values cannot be retracted; damage limited to future signatures; signed rotation |
| Quantum attack on the signature | Both branches would have to fall (G6) |
| Conversion bug | Normative vectors in CI; spec and code cannot diverge silently |
| Attacker with `root` on the signing host | **Not mitigated** without `TPM` / `HSM` (see §6) |

## 6. What this system does NOT guarantee (limits, in honesty)

1. **No independent cryptographic audit yet.** `gt-gst` and the notary have
   not been reviewed by an independent third party.
2. **No hardware key custody yet (`TPM` / `HSM`).** An attacker with `root`
   on the signing host can use the private keys to sign arbitrary events with
   the authorized `(issuer, kid)`; key theft is detected only after the fact
   through revocation. Do not use `gt-gst` for critical production decisions
   until both this point and the previous one are closed.
3. **A seal is not a physical-time certificate.** A signer holding an authorized
   key can still sign a false time. Check the uncertainty and the independent
   anchor's scope before treating an anchored envelope as evidence of time.
4. **It does not guarantee the wall-clock accuracy of a device.** NTP, PTP and
   GNSS are external layers; `gt-gts` classifies readings, it does not
   discipline the clock.
5. **It does not survive a conspirator controlling all replicas from the
   origin.** This is the constitutive limit of *any* notarization.
6. **It does not define which civil time to display to humans.** Presentation,
   time zone and language are application layers.
7. **It does not replace OS, hardware or network controls.** `gt-tslr`,
   `gt-gcerts`, the Roughtime profile and the RFC 3161 profile are
   EXPERIMENTAL and kept separate from the core.
8. **Legacy code is out of scope.** `WOTS+`
   (`src/gerarion/deprecated/hashots.py`) and the `GST v1` API are
   deprecated educational artifacts.

## 7. Forgery cost budget (summary)

| Attacker objective | Minimum cost |
|---|---|
| Alter 1 bit of a signed envelope | Break Ed25519 and ML-DSA, or find a SHA-256 preimage (2^256; 2^128 under Grover) |
| Impersonate an issuer | Obtain the registered private keys (see §6.2) |
| Rewrite 1 day with R honest replicas | Rewrite R logs coherently and neutralize the external memory of R communities |
| Forge unanchored past time | Only produces "assertions"; no notary accredits them as facts |

The thesis: **the cost of lying about time MUST exceed the value of any
temporal lie.** Replication, chained roots and key authorization are the
mechanism — not faith, not decree.
