# Sellado criptográfico de eventos

Parte de la suite de referencia **Gerarion** (verared/gerarion `v3.2.2`,
Gerarion Universal Standard). Este directorio es un **paquete de
exportación** listo para publicarse (o consumirse) como repositorio
satélite `verared/gt-gst`; conserva las rutas relativas del repositorio
base para componer módulos.

## El problema único que resuelve

El sobre firmado GST v2: canonicalización RFC 8785 (JCS), firma híbrida Ed25519 + ML-DSA con protección anti-downgrade, ReplayGuard persistente y notario Merkle diario con quórum.

## Estado normativo

- **Estable (GST v2; auditoría criptográfica externa requerida para producción)** (`maturity: stable`) — línea base `v3.2.2` (aritmética y vectores
  congelados: GUS v3.0.0).
- Especificación(es) incluida(s): `docs/specs/GST.es.md`, `docs/specs/GST.en.md`, `docs/spec/threat-model.md`, `docs/en/threat-model.md`
- Manifiesto de integridad verificable: [`EXPORT-MANIFEST.json`](EXPORT-MANIFEST.json)
- Matriz oficial de compatibilidad: [`COMPATIBILITY.md`](https://github.com/verared/gerarion/blob/v3.2.2/COMPATIBILITY.md)

### Perfil criptográfico normativo (`GST v2`)

| Aspecto | Declaración normativa |
|---|---|
| **Algoritmo normativo (`GST v2`)** | Firma híbrida **Ed25519 + ML-DSA** sobre payload canonicalizado con **RFC 8785 (JCS)** (enteros estrictamente dentro de IEEE-754 `binary64` `±(2^53 - 1)`), separación de dominio `GUS3-GST-V2`, descriptor de algoritmos y claves incluido en los bytes firmados (protección **anti-downgrade**), contador monotónico `seq` + `nonce` con `ReplayGuard` *fail-closed* y notario Merkle diario opcional. |
| **Algoritmo deprecado / educativo** | `WOTS+` / `WotsMerkleSigner`, aislado en `src/gerarion/deprecated/hashots.py` de `verared/gerarion` con `DeprecationWarning` explícito; **fuera** del perfil normativo `GST v2`. |
| **Cobertura y límite de auditoría** | Cubierto por vectores y pruebas (JCS, verificación dual, anti-downgrade, `ReplayGuard`, integración de satélites). Pendiente de **auditoría criptográfica externa independiente** y **custodia TPM/HSM** antes de producción. |

## Dependencias

- `gt-core` (*verared/gt-core*): tipos base y servicios del núcleo.
Base común: `verared/gerarion` `v3.2.2`.

## Contenido

- `EXPORT-MANIFEST.json`
- `LICENSE`
- `NOTICE`
- `docs/en/threat-model.md`
- `docs/spec/threat-model.md`
- `docs/specs/GST.en.md`
- `docs/specs/GST.es.md`
- `src/gerarion/gst/` (6 archivos)

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

Desde `verared/gerarion`, la integridad completa contra `EXPORT-MANIFEST.json` se verifica con:

```bash
python3 tools/export_module.py --verify-existing /ruta/a/gt-gst
```

## Contrato de sincronización con `verared/gerarion`

Este paquete es **generado, no editado a mano**: se regenera byte a
byte desde `verared/gerarion v3.2.2` con
`python3 tools/export_module.py --module gt-gst --out <dir>`. La fuente
de verdad normativa (especificaciones, vectores CC0, núcleos de
referencia de las tres plataformas y la batería completa) permanece en
`verared/gerarion`; los satélites `verared/gt-gst` la consumen y no forkean la
aritmética. Las actualizaciones fluyen regenerando la exportación desde
un tag del repositorio base; nunca editando los archivos exportados.
