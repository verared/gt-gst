# Cryptographic event sealing

Part of the **Gerarion** reference suite (verared/gerarion `v3.4.0`,
Gerarion Universal Standard). This directory is an **export package**
ready to be published (or consumed) as the `verared/gt-gst` satellite
repository; it keeps the base repository's relative layout so modules
compose cleanly.

## The unique problem it solves

The signed GST v2 envelope: RFC 8785 canonicalisation (JCS), hybrid Ed25519 + ML-DSA signing with anti-downgrade protection, persistent ReplayGuard, and the daily Merkle notary with quorum.

## Normative status

- **Estable (GST v2; auditoría criptográfica externa requerida para producción)** (`maturity: stable`) — baseline `v3.4.0` (frozen arithmetic and vectors:
  GUS v3.0.0).
- Included specification(s): `docs/specs/GST.es.md`, `docs/specs/GST.en.md`, `docs/spec/threat-model.md`, `docs/en/threat-model.md`
- Verifiable integrity manifest: [`EXPORT-MANIFEST.json`](EXPORT-MANIFEST.json)
- Official compatibility matrix: [`COMPATIBILITY.md`](https://github.com/verared/gerarion/blob/v3.4.0/COMPATIBILITY.md)

### Normative Cryptographic Profile (`GST v2`)

| Aspect | Normative declaration |
|---|---|
| **Normative algorithm (`GST v2`)** | Hybrid **Ed25519 + ML-DSA** over **RFC 8785 (JCS)** canonicalised payload (integers strictly within IEEE-754 `binary64` `±(2^53 - 1)`), domain separation `GUS3-GST-V2`, algorithm and key descriptors included in signed bytes (**anti-downgrade**), `KeyRegistry` with validity/rotation/revocation, monotonic counter `seq` + `nonce` with fail-closed `SQLiteReplayStore` / `ReplayGuard`, and optional daily Merkle notary. |
| **Deprecated / educational algorithm** | `WOTS+` / `WotsMerkleSigner`, isolated in `src/gerarion/deprecated/hashots.py` of `verared/gerarion` with explicit `DeprecationWarning`; **outside** the normative `GST v2` profile. |
| **Test coverage & audit boundary** | Covered by vectors and tests (JCS, dual verification, anti-downgrade, `KeyRegistry`, concurrent `SQLiteReplayStore`, satellite integration). **Independent third-party cryptographic audit** and **TPM/HSM key custody** are required before production security decisions. |

## Integrate `gt-core` + `gt-gst` in 1 Minute (CMS / API Quickstart)

```python
import hashlib
from gerarion.core import format as fmt
from gerarion.gst import HybridSigner, v2

# 1. Initialize hybrid signer (Ed25519 + ML-DSA-65), key trust registry, and SQLite ReplayStore
signer = HybridSigner(seed_classical=bytes(range(32)), seed_pqc=bytes(range(32, 64)))
registry = v2.KeyRegistry()
registry.register_signer(issuer="cms.example.org", kid="cms-2026-k1", signer=signer)
replay_store = v2.SQLiteReplayStore(":memory:")  # In production: "/var/lib/cms/gst_replay.sqlite3"

# 2. Seal a business event on a canonical GUS coordinate
event_bytes = b'{"action":"post.publish","object_id":"art-42","version":1}'
event_hash = "sha256:" + hashlib.sha256(event_bytes).hexdigest()
envelope = v2.create(
    fmt.parse("2031DY-03-08-T-09:30:00-SC-TCJ+0"),
    signer,
    event_hash=event_hash,
    issuer="cms.example.org",
    kid="cms-2026-k1",
    seq=1,
)

# 3. Verify across 3 independent levels (Cryptography, Identity/Replay, Temporal Assurance)
res = v2.verify(envelope, expected_event_hash=event_hash, trust_store=registry, replay_store=replay_store)
assert res.crypto.valid is True
assert res.identity.valid is True and res.identity.key_status == "ACTIVE"
assert res.identity.replay_status == "OK"
assert res.temporal.clock_state == "UNKNOWN"  # Or "VERIFIED" when passing a gt-gts ClockReading
assert res.sealed and not res.overall_trusted
```

## The 5 Distribution Guarantees

| # | Guarantee | Verifiable mechanism |
|---|---|---|
| 1 | **SHA-256 Integrity** | `files` map in [`EXPORT-MANIFEST.json`](EXPORT-MANIFEST.json) checked via `--verify-existing`. |
| 2 | **Declared Provenance** | `source_repo`, `source_tag` (`v3.4.0`), and 40-char `source_commit` fields. |
| 3 | **Publication Authenticity** | Detached Ed25519 signature `EXPORT-MANIFEST.json.sig` verified via `--trusted-pub-key` (zero self-reference). |
| 4 | **Reproducibility** | Bit-for-bit deterministic re-export from the same `--source-commit`. |
| 5 | **Functional Conformance** | Shared CC0 normative vectors and cross-satellite integration tests in C11, Python, and JavaScript. |

## Dependencies

- `gt-core` (*verared/gt-core*): base types and core services.
Common base: `verared/gerarion` `v3.4.0`.

## Contents

- `EXPORT-MANIFEST.json`
- `LICENSE`
- `NOTICE`
- `docs/en/threat-model.md`
- `docs/spec/threat-model.md`
- `docs/specs/GST.en.md`
- `docs/specs/GST.es.md`
- `src/gerarion/gst/` (9 archivos)

## Offline usage

No network, accounts, package registries, or frameworks required:

```bash
python3 -c 'import sys; sys.path.insert(0, "src"); import gerarion'
```

## Verification

With Python ≥ 3.9 and `reuse` installed:

```bash
reuse lint                                    # licensing 100 %
# (las pruebas viven en la suite de verared/gerarion)
```

From `verared/gerarion`, full integrity and (optionally) detached-signature authenticity are verified with:

```bash
python3 tools/export_module.py --verify-existing /path/to/gt-gst
# With cryptographic verification of EXPORT-MANIFEST.json.sig:
python3 tools/export_module.py --verify-existing /path/to/gt-gst --trusted-pub-key /path/to/release-pub.pem
```

## Synchronisation contract with `verared/gerarion`

This package is **generated, never hand-edited**: it is regenerated
byte for byte from `verared/gerarion v3.4.0` with
`python3 tools/export_module.py --module gt-gst --out <dir>`. The
normative source of truth (specifications, CC0 vectors, reference
cores for the three platforms, and the full test suite) stays in
`verared/gerarion`; `verared/gt-gst` satellites consume it and never fork the
arithmetic. Updates flow by regenerating the export from a tag of the
base repository — never by editing exported files.
