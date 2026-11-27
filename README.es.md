# Sellado criptográfico de eventos

Parte de la suite de referencia **Gerarion** (verared/gerarion `v3.4.0`,
Gerarion Universal Standard). Este directorio es un **paquete de
exportación** listo para publicarse (o consumirse) como repositorio
satélite `verared/gt-gst`; conserva las rutas relativas del repositorio
base para componer módulos.

## El problema único que resuelve

El sobre firmado GST v2: canonicalización RFC 8785 (JCS), firma híbrida Ed25519 + ML-DSA con protección anti-downgrade, ReplayGuard persistente y notario Merkle diario con quórum.

## Estado normativo

- **Estable (GST v2; auditoría criptográfica externa requerida para producción)** (`maturity: stable`) — línea base `v3.4.0` (aritmética y vectores
  congelados: GUS v3.0.0).
- Especificación(es) incluida(s): `docs/specs/GST.es.md`, `docs/specs/GST.en.md`, `docs/spec/threat-model.md`, `docs/en/threat-model.md`
- Manifiesto de integridad verificable: [`EXPORT-MANIFEST.json`](EXPORT-MANIFEST.json)
- Matriz oficial de compatibilidad: [`COMPATIBILITY.md`](https://github.com/verared/gerarion/blob/v3.4.0/COMPATIBILITY.md)

### Perfil criptográfico normativo (`GST v2`)

| Aspecto | Declaración normativa |
|---|---|
| **Algoritmo normativo (`GST v2`)** | Firma híbrida **Ed25519 + ML-DSA** sobre payload canonicalizado con **RFC 8785 (JCS)** (enteros estrictamente dentro de IEEE-754 `binary64` `±(2^53 - 1)`), separación de dominio `GUS3-GST-V2`, descriptor de algoritmos y claves incluido en los bytes firmados (protección **anti-downgrade**), `KeyRegistry` con vigencia/rotación/revocación, contador monotónico `seq` + `nonce` con `SQLiteReplayStore` / `ReplayGuard` *fail-closed* y notario Merkle diario opcional. |
| **Algoritmo deprecado / educativo** | `WOTS+` / `WotsMerkleSigner`, aislado en `src/gerarion/deprecated/hashots.py` de `verared/gerarion` con `DeprecationWarning` explícito; **fuera** del perfil normativo `GST v2`. |
| **Cobertura y límite de auditoría** | Cubierto por vectores y pruebas (JCS, verificación dual, anti-downgrade, `KeyRegistry`, `SQLiteReplayStore` concurrente, integración de satélites). Pendiente de **auditoría criptográfica externa independiente** y **custodia TPM/HSM** antes de producción. |

## Integra `gt-core` + `gt-gst` en 1 minuto (Guía rápida CMS / API)

```python
import hashlib
from gerarion.core import format as fmt
from gerarion.gst import HybridSigner, v2

# 1. Inicializar firmante híbrido (Ed25519 + ML-DSA-65), registro de claves y ReplayStore SQLite
signer = HybridSigner(seed_classical=bytes(range(32)), seed_pqc=bytes(range(32, 64)))
registry = v2.KeyRegistry()
registry.register_signer(issuer="cms.example.org", kid="cms-2026-k1", signer=signer)
replay_store = v2.SQLiteReplayStore(":memory:")  # En producción: "/var/lib/cms/gst_replay.sqlite3"

# 2. Sellar un evento de negocio sobre coordenada canónica GUS
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

# 3. Verificar en 3 niveles independientes (Criptografía, Identidad/Replay, Aseguramiento Temporal)
res = v2.verify(envelope, expected_event_hash=event_hash, trust_store=registry, replay_store=replay_store)
assert res.crypto.valid is True
assert res.identity.valid is True and res.identity.key_status == "ACTIVE"
assert res.identity.replay_status == "OK"
assert res.temporal.clock_state == "UNKNOWN"  # O "VERIFIED" al pasar una lectura de gt-gts
assert res.sealed and not res.overall_trusted
```

## Las 5 Garantías de Distribución

| # | Garantía | Mecanismo verificable |
|---|---|---|
| 1 | **Integridad SHA-256** | Mapa `files` en [`EXPORT-MANIFEST.json`](EXPORT-MANIFEST.json) verificado con `--verify-existing`. |
| 2 | **Procedencia declarada** | Campos `source_repo`, `source_tag` (`v3.4.0`) y `source_commit` (SHA-1 de 40 caracteres). |
| 3 | **Autenticidad de publicación** | Firma Ed25519 separada `EXPORT-MANIFEST.json.sig` verificable con `--trusted-pub-key` (sin autorreferencia). |
| 4 | **Reproducibilidad** | Re-exportación determinista bit a bit desde el mismo `--source-commit`. |
| 5 | **Conformidad funcional** | Suite de vectores normativos CC0 e integración cruzada en C11, Python y JavaScript. |

## Dependencias

- `gt-core` (*verared/gt-core*): tipos base y servicios del núcleo.
Base común: `verared/gerarion` `v3.4.0`.

## Contenido

- `EXPORT-MANIFEST.json`
- `LICENSE`
- `NOTICE`
- `docs/en/threat-model.md`
- `docs/spec/threat-model.md`
- `docs/specs/GST.en.md`
- `docs/specs/GST.es.md`
- `src/gerarion/gst/` (9 archivos)

## Uso offline

No requiere red, cuentas, registro de paquetes ni frameworks:

```bash
python3 -c 'import sys; sys.path.insert(0, "src"); import gerarion'
```

## Verificación

Con Python ≥ 3.9 y `reuse` instalado:

```bash
reuse lint                                    # licencias al 100 %
# (las pruebas viven en la suite de verared/gerarion)
```

Desde `verared/gerarion`, la integridad y (opcionalmente) la autenticidad de firma separada se verifican con:

```bash
python3 tools/export_module.py --verify-existing /ruta/a/gt-gst
# Con verificación criptográfica de EXPORT-MANIFEST.json.sig:
python3 tools/export_module.py --verify-existing /ruta/a/gt-gst --trusted-pub-key /ruta/a/release-pub.pem
```

## Contrato de sincronización con `verared/gerarion`

Este paquete es **generado, no editado a mano**: se regenera byte a
byte desde `verared/gerarion v3.4.0` con
`python3 tools/export_module.py --module gt-gst --out <dir>`. La fuente
de verdad normativa (especificaciones, vectores CC0, núcleos de
referencia de las tres plataformas y la batería completa) permanece en
`verared/gerarion`; los satélites `verared/gt-gst` la consumen y no forkean la
aritmética. Las actualizaciones fluyen regenerando la exportación desde
un tag del repositorio base; nunca editando los archivos exportados.
