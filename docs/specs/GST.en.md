# GST Specification — Cryptographic Event Sealing

- **Status:** Stable (`GST v2`, external cryptographic audit & TPM/HSM custody required before production security decisions); TSA/notary profiles **Experimental in deployment** ·
  **Version:** 1.1.0 · **Baseline:** GUS v3.0.0 / suite `v3.3.0`
- **Consolidated edition:** [`../en/gus-3.0.0.md`](../en/gus-3.0.0.md) (§7–§8) ·
  Profile: [`../en/profiles/gus-3161-profile.md`](../en/profiles/gus-3161-profile.md)
- **License:** CC-BY-4.0 · Maintained by: verared contributors

## 1. Scope

The signed **GST v2** envelope (*Gerarion Signed Timestamp*): deterministic
JSON canonicalisation (RFC 8785), event binding, simultaneous hybrid
signing Ed25519 + ML-DSA with anti-downgrade protection, anti-replay /
anti-rollback protection, and the external anchors (Merkle notary and
RFC 3161). It does not cover prior clock quality (GTS domain) nor the
stamp format (GUS domain).

### Normative Cryptographic Profile

| Aspect | Normative declaration |
|---|---|
| **Normative algorithm (`GST v2`)** | Hybrid **Ed25519 + ML-DSA** over **RFC 8785 (JCS)** canonicalised payload (integers strictly within IEEE-754 `binary64` `±(2^53 - 1)`), domain separation `GUS3-GST-V2`, algorithm and key descriptors included inside the signed bytes (**anti-downgrade**), monotonic counter `seq` + `nonce` with fail-closed `ReplayGuard`, and optional daily Merkle notary. |
| **Deprecated / educational algorithm** | `WOTS+` / `WotsMerkleSigner`, isolated in `src/gerarion/deprecated/hashots.py` with explicit `DeprecationWarning`; **outside** the normative `GST v2` profile and not for production. |
| **Test coverage & audit boundary** | **Covered by tests:** core arithmetic, RFC 8785 JCS (hostile inputs and `> 2^53 - 1` rejection), dual hybrid verification, anti-downgrade rejection, fail-closed `ReplayGuard`, sub-second anchors, and assembled satellite integration. **Pending:** independent external third-party cryptographic audit and hardware key custody (TPM/HSM) before production security decisions. |

## 2. Normative rules

1. **Canonicalisation RFC 8785 (JCS):** every signature and verification
   operates on the exact UTF-8 bytes of `jcs.dumps(payload)` (keys sorted
   by UTF-16 code units, minimal escaping, IEEE 754 numbers in
   ECMAScript text, `NaN`/`Infinity` rejected, integers outside
   ±(2⁵³−1) rejected — they must travel as decimal strings).
2. **Domain separation:** signed bytes are
   `b"GUS3-GST-V2\x00" + canonical_bytes`.
3. **Mandatory v2 envelope fields:** `gst_version: "2.0"`, `ts`
   (canonical GUS stamp), `ins` (int64 seconds), `nanos`
   (0..999,999,999), `scale: "TCJ"` (or explicit `"TAI"`), `event_hash`
   (mandatory, `sha256:<hex>` or `sha512:<hex>`), `kid` and `issuer`,
   `nonce` (cryptographically random) and `seq` (monotonic counter),
   `policy_version`. A `v2` envelope without a valid `event_hash` is
   rejected.
4. **Hybrid signing:** the complete algorithm descriptors (`alg`,
   `kid_classical`, `kid_pqc`) live **inside the canonicalised payload
   before signing**; removing or downgrading the post-quantum signature
   also invalidates the classical one. Hybrid verification requires
   **both** signatures valid; a missing or failing one → `REJECTED`.
5. **Persistent anti-replay:** `ReplayGuard` records seen `(kid, nonce)`
   pairs and the last trusted `(seq, ins)`; it rejects exact replays and
   counter/clock regressions. Corrupt persisted state → *fail-closed*
   (`seq` is never silently reset).
6. **Content traceability:** `event_hash` anchors the external data; the
   seal attests the existence and ordering of the event, not its truth.
7. **Daily Merkle notary:** `day_root(n) = SHA-256("GUS2-DAY" || n ||
   tree_root(n) || day_root(n-1))`; days sealed in strict order, no
   gaps; roots published to independent replicas. Quorum requires
   distinct signers: duplicated responses from the same node do not
   count.
8. **RFC 3161 profile (GUS-3161):** the TSA certifies the existence of
   the canonical GST bytes at its `genTime`; the notary certifies the
   ordering. Complementary seals; offline verification against the
   declared trust root.
9. **Reference adapter maturity notice:** the hash-only family
   (WOTS16-Merkle, `hashots.py`) is EDUCATIONAL and unaudited;
   production requires FIPS 203/204/205 with audited implementations.

## 3. Sources of truth

| Component | Implementation |
|---|---|
| Envelope and verification | `src/gerarion/gst/envelope.py` |
| JCS | `src/gerarion/gst/jcs.py` |
| Hybrid signers | `src/gerarion/gst/adapters.py` |
| Notary and quorum | `src/gerarion/gst/notary.py`, `notary_cluster.py` |
| Verification CLI | `tools/verify_gus.py` |

## 4. Applicable vectors

- Dedicated test vectors in `tests/test_jcs_gstv2.py`,
  `tests/test_adversarial_security.py`, `tests/test_notary_cluster.py`
  (positive, replay, rollback, downgrade, hostile JCS).
- The notary signs the current day: vectors cover structure, not dated
  seals.

## 5. Maturity and limits

- GST v2 format + JCS + hybrid: **stable** (hardened in v3.0.1/v3.1.1).
- TSLR and GCERTS are separate experimental profiles (see their sheets).
- Signing does not make the value unforgable: it binds content to a key
  and enables deterministic tamper detection and post-quantum
  cryptographic traceability; historical objectivity requires
  independent notary replicas and previously established trust.

## 6. References

- `docs/en/threat-model.md`, `docs/notary-runbook.md`,
  `docs/en/audit/AUDIT-REPORT-v3.0.0.md` (A-*, B-* findings).
