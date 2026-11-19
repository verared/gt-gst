# Threat model — GUS 2.0

This document defines **what the system protects, against whom, and what it
does NOT protect**. It is the basis of any serious security evaluation:
without an explicit threat model, any claim of "unforgeable" is marketing.

## 1. Assets

| Asset | Definition |
|---|---|
| Temporal value (instant) | Continuous count `ins` + canonical timestamp `ts` |
| Historical order | The total ordering of instants and its anchoring sequence |
| Non-repudiation | Verifiable attribution of who asserted an instant, and when |

## 2. Adversaries and assumed capabilities

| Adversary | Capabilities |
|---|---|
| A-Local | Controls its own clock, logs and system; can deny facts |
| A-Insider | Holds a notarial or signing key from a past epoch |
| A-Persistent | Compromises a complete notary (keys, state, disk) |
| A-Jurisdictional | Watches, censors and legally coerces a notary within its domain |
| A-Quantum | Quantum computer with millions of logical qubits (2035+ horizon) |
| A-Social | Disinformation campaign about what time it "was" |

## 3. Guarantees and their premises

### G1 — Any alteration of a signed GST is detected

Alter one bit of `ts`, `ins`, `sig` or `pub` and verification fails: the
guarantee is deterministic tamper detection, not physical impossibility
(an absolute claim is not a verifiable guarantee).
**Premise:** SHA-256 is collision- and preimage-resistant. The cost of
forgery: 2^256 of serial work (or 2^128 in the quantum Grover case).
Both exceed, by orders of magnitude, any defensible temporal value.

### G2 — The notary's past is immutable without detection

The `day_root` of day n includes the `day_root` of n-1. Altering any day
requires recomputing the entire subsequent chain **and** publishing it
consistently on every replica a verifier consults.
**Premise:** at least one independent replica remains honest and
accessible. This is the only social requirement of the entire system, and
it is satisfied with replicas that are organizationally and
jurisdictionally separated.

### G3 — Quantum compatibility

The reference signatures and the recommended algorithms (SLH-DSA, ML-DSA,
LMS, XMSS) are hash-only or lattice-based; against them, the quantum
attacker only obtains Grover's quadratic speedup over the hash.
**Premise:** a 2^128 post-Grover margin is considered adequate at a
100+ year horizon. The specification additionally allows migrating to
SHA-384 or SHAKE256 via the `alg` field if the margin is judged
insufficient.

### G4 — Cryptographic agility

`alg` is a first-class field. A future break (of SHA-256 or of the
signature scheme) does not invalidate the format: one signs with a new
algorithm and old timestamps are re-anchored (re-timestamping: the old
roots are included as leaves of the modern notary). Time is not
rewritten: it is re-protected, and that operation is public in the log.

### G5 — A local signer cannot assert its own clock

A malicious issuer can sign *any timestamp* with its own key: that is an
assertion, not a time. Objective verifiability exists only with respect to
the notary log: a timestamp without anchoring is an *assertion*
(status "unsigned"); with anchoring, it is a *notarized fact*. Consumers
decide the degree of trust according to the anchoring.
**Premise explicitly accepted:** no cryptography prevents a system from
lying about its internal clock; the notary prevents that lie from being
sustained against third parties.

### G6 — Post-quantum migration plan (phased, no promised dates)

Actual state in 2.5.0b1 and candidate path to RC/1.0:

- **Today:** Ed25519 only in the network-anchoring profile (Roughtime);
  SLH-DSA (FIPS 205) optional adapter (`gerarion[slh]`); ML-DSA (FIPS 204)
  optional adapter (`gerarion[pqc]`, `cryptography>=47`). The hash-only
  reference signature remains deprecated and blocked by default.
- **Phase 1 (IMPLEMENTED in 3.0.0, GST v2 scheme):** simultaneous hybrid
  signing (Ed25519 + ML-DSA) over the same JCS-canonical bytes
  (RFC 8785), with the algorithm descriptor inside the signed payload:
  removing or downgrading the post-quantum branch also invalidates the
  classical one (structural anti-downgrade). Hybrid verification is
  all-or-nothing.
- **Phase 2 (goal):** high-level verifiers require the post-quantum
  component; a classical-only signature is reported as degraded.
- **Phase 3 (goal):** new anchoring exclusively post-quantum; Ed25519
  remains only for reading historical evidence (re-signing with chain
  preservation, without rewriting the past — see G4).

**Premise:** the migration is a signing-layer change (minor version; G4),
not a kernel change; the normative calendar vectors do not change.

## 4. Concrete attacks and mitigations

| Attack | Outcome |
|---|---|
| Forge an individual GST | Requires breaking G1 |
| Retro-edit the notary log | Requires breaking G2 (all replicas) |
| Roll back the notary to a past state | Detectable by divergence with published replicas; strict-order sealing leaves no hidden window |
| OTS leaf reuse | State audited; the daily anchoring records the index used; repeated leaf = public alarm |
| Notarial key compromise | Already-published `day_root` values cannot be retracted; damage is limited to future signatures; signed rotation (spec §7.1) |
| Quantum attack on the signature | G3: hash-only degrades no further than Grover |
| Blocking or censorship of a notary | The system requires N notaries; timestamps survive individual loss |
| Long-range (insider signs "30 years back") | Not provable as a fact: inclusion requires the `day_root` of that day, which already exists and is published. It can only produce *detectable assertions* |
| Conversion bug | Normative vector suite in CI; the spec and the code cannot diverge silently |

## 5. What this system does NOT guarantee (limits, in honesty)

1. **It does not guarantee the wall-clock accuracy of a device.** Civil
   synchronization (NTP, GNSS) is an external layer. GUS guarantees
   *order* and *notarization*, not the fine tuning of the local clock.
2. **It does not survive a conspirator controlling all replicas from the
   origin.** This is the constitutive limit of *any* notarization.
   Structural mitigation: public keys published in advance cannot be
   changed retroactively without leaving an observable discontinuity.
3. **It does not define which civil time to display to humans.**
   Presentation, time zone and language are application layers.
4. **GUS does not replace OS, hardware or network controls.** Operating
   system security controls, hardware isolation and network mitigations
   are OUT OF SCOPE for GUS: this system complements them, never
   replaces them. TSLR and GCERTS are EXPERIMENTAL profiles kept separate
   from the core.
5. **The reference implementation is NOT production code.** It is
   executable, exact and verified for *vectors*; deployment requires
   audited libraries (FIPS 204, FIPS 205, RFC 8554). The reference's
   `slh-dsa` adapter is an open-source library with **no verified FIPS
   validation or external audit** (useful for interoperability and
   vectors, not a certified module).

## 6. Forgery cost budget (summary)

| Attacker objective | Minimum cost |
|---|---|
| Alter 1 bit of a GST | 2^256 (SHA-256 preimage) |
| Break a signature (quantum attacker) | 2^128 (Grover) |
| Rewrite 1 day with R honest replicas | Rewrite R logs coherently and neutralize the external memory of R communities |
| Forge unanchored past time | Only produces "assertions" without anchoring; no notary accredits them as facts |

The GUS thesis: **the cost of lying about time MUST exceed the value of
any temporal lie.** Replication and the chains of roots are the mechanism
that sustains it — not faith, not decree.
