# Cryptographic event sealing

Part of the **Gerarion** reference suite (verared/gerarion `v3.2.2`,
Gerarion Universal Standard). This directory is an **export package**
ready to be published (or consumed) as the `verared/gt-gst` satellite
repository; it keeps the base repository's relative layout so modules
compose cleanly.

## The unique problem it solves

The signed GST v2 envelope: RFC 8785 canonicalisation (JCS), hybrid Ed25519 + ML-DSA signing with anti-downgrade protection, persistent ReplayGuard, and the daily Merkle notary with quorum.

## Normative status

- **Estable (GST v2; auditoría criptográfica externa requerida para producción)** (`maturity: stable`) — baseline `v3.2.2` (frozen arithmetic and vectors:
  GUS v3.0.0).
- Included specification(s): `docs/specs/GST.es.md`, `docs/specs/GST.en.md`, `docs/spec/threat-model.md`, `docs/en/threat-model.md`
- Verifiable integrity manifest: [`EXPORT-MANIFEST.json`](EXPORT-MANIFEST.json)
- Official compatibility matrix: [`COMPATIBILITY.md`](https://github.com/verared/gerarion/blob/v3.2.2/COMPATIBILITY.md)

### Normative Cryptographic Profile (`GST v2`)

| Aspect | Normative declaration |
|---|---|
| **Normative algorithm (`GST v2`)** | Hybrid **Ed25519 + ML-DSA** over **RFC 8785 (JCS)** canonicalised payload (integers strictly within IEEE-754 `binary64` `±(2^53 - 1)`), domain separation `GUS3-GST-V2`, algorithm and key descriptors included in signed bytes (**anti-downgrade**), monotonic counter `seq` + `nonce` with fail-closed `ReplayGuard`, and optional daily Merkle notary. |
| **Deprecated / educational algorithm** | `WOTS+` / `WotsMerkleSigner`, isolated in `src/gerarion/deprecated/hashots.py` of `verared/gerarion` with explicit `DeprecationWarning`; **outside** the normative `GST v2` profile. |
| **Test coverage & audit boundary** | Covered by vectors and tests (JCS, dual verification, anti-downgrade, `ReplayGuard`, satellite integration). **Independent third-party cryptographic audit** and **TPM/HSM key custody** are required before production security decisions. |

## Dependencies

- `gt-core` (*verared/gt-core*): tipos base y servicios del núcleo.
Common base: `verared/gerarion` `3.2.2`.

## Contents

- `EXPORT-MANIFEST.json`
- `LICENSE`
- `NOTICE`
- `docs/en/threat-model.md`
- `docs/spec/threat-model.md`
- `docs/specs/GST.en.md`
- `docs/specs/GST.es.md`
- `src/gerarion/gst/` (6 archivos)

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

From `verared/gerarion`, full integrity against `EXPORT-MANIFEST.json` is verified with:

```bash
python3 tools/export_module.py --verify-existing /path/to/gt-gst
```

## Synchronisation contract with `verared/gerarion`

This package is **generated, never hand-edited**: it is regenerated
byte for byte from `verared/gerarion v3.2.2` with
`python3 tools/export_module.py --module gt-gst --out <dir>`. The
normative source of truth (specifications, CC0 vectors, reference
cores for the three platforms, and the full test suite) stays in
`verared/gerarion`; `verared/gt-gst` satellites consume it and never fork the
arithmetic. Updates flow by regenerating the export from a tag of the
base repository — never by editing exported files.
